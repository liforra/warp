// Package client drives the protocol x address fallback loop that connects
// to a host using ssh, mosh, et, tailscale ssh, or tsh.
package client

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/liforra/warp/internal/config"
	"github.com/liforra/warp/internal/detect"
)

// connectFailureCode is ssh's conventional exit code for a connection-level
// failure (as opposed to the remote command's own exit status): 255 means
// "try the next thing," anything else means a real session happened and its
// exit code should propagate.
//
// et and mosh both bootstrap over ssh, so a failure before that bootstrap
// completes (server unreachable, port closed, auth rejected) reliably exits
// 255 too, and warp falls through to the next protocol without having
// prompted for credentials at all. If the bootstrap succeeds (you've already
// authenticated once) but the session fails afterward -- mosh-server missing,
// a firewalled UDP range -- the client's own exit code is generally *not*
// 255, so warp deliberately stops and reports the failure rather than
// silently opening a second, separately-authenticated session. tailscale and
// tsh don't share ssh's 255 convention at all; treat their fallback behavior
// here as unverified until tested against a real deployment.
const connectFailureCode = 255

var protoBinary = map[string]detect.Binary{
	"ssh":       detect.SSH,
	"mosh":      detect.Mosh,
	"et":        detect.ET,
	"tailscale": detect.Tailscale,
	"tsh":       detect.Tsh,
}

// Executor runs a fully-built argv (argv[0] is the resolved binary path) and
// reports its exit code. It's an interface so tests can substitute a fake
// without spawning real processes.
type Executor interface {
	Run(argv []string) (exitCode int, err error)
}

// ExecExecutor is the real Executor: it runs the command with the current
// process's stdio wired through, so interactive sessions behave normally.
type ExecExecutor struct{}

func (ExecExecutor) Run(argv []string) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), nil
	}
	// The process never started (binary vanished, permissions, etc.).
	return -1, err
}

// Attempt records the outcome of trying one (protocol, address) pair, for
// the failure summary shown when every combination fails.
type Attempt struct {
	Protocol string
	Address  string // empty if Skipped before an address was chosen
	Skipped  bool
	Reason   string // populated when Skipped
	ExitCode int    // populated when !Skipped
}

// ConnectFailedErr is returned when every (protocol, address) combination
// failed to connect.
type ConnectFailedErr struct {
	Attempts []Attempt
}

func (e *ConnectFailedErr) Error() string {
	var b strings.Builder
	b.WriteString("could not connect using any configured protocol/address:\n")
	for _, a := range e.Attempts {
		if a.Skipped {
			if a.Address != "" {
				fmt.Fprintf(&b, "  %s@%s: %s\n", a.Protocol, a.Address, a.Reason)
			} else {
				fmt.Fprintf(&b, "  %s: %s\n", a.Protocol, a.Reason)
			}
			continue
		}
		fmt.Fprintf(&b, "  %s@%s: exit %d\n", a.Protocol, a.Address, a.ExitCode)
	}
	return b.String()
}

// Connector drives the nested protocol(outer) x address(inner) fallback
// loop for a resolved host.
type Connector struct {
	Resolver *detect.Resolver
	Exec     Executor
}

// NewConnector builds a Connector that executes real processes.
func NewConnector(resolver *detect.Resolver) *Connector {
	return &Connector{Resolver: resolver, Exec: ExecExecutor{}}
}

// Connect tries each protocol in host.Protocols, in order; for each
// protocol it tries every address in host.Addresses before moving on to the
// next protocol. It returns the exit code of the first session that
// actually ran (any exit code other than 255 counts as "a session
// happened"), or a *ConnectFailedErr if nothing connected.
func (c *Connector) Connect(host *config.ResolvedHost) (int, error) {
	var attempts []Attempt

	for _, proto := range host.Protocols {
		bin, ok := protoBinary[proto]
		if !ok {
			attempts = append(attempts, Attempt{Protocol: proto, Skipped: true, Reason: fmt.Sprintf("unknown protocol %q", proto)})
			continue
		}

		res := c.Resolver.Resolve(bin)
		if res.Err != nil {
			attempts = append(attempts, Attempt{Protocol: proto, Skipped: true, Reason: res.Err.Error()})
			continue
		}

		for _, addr := range host.Addresses {
			argv, err := buildArgv(proto, res.Path, addr, host)
			if err != nil {
				attempts = append(attempts, Attempt{Protocol: proto, Address: addr, Skipped: true, Reason: err.Error()})
				continue
			}

			code, err := c.Exec.Run(argv)
			if err != nil {
				attempts = append(attempts, Attempt{Protocol: proto, Address: addr, Skipped: true, Reason: err.Error()})
				continue
			}

			if code == connectFailureCode {
				attempts = append(attempts, Attempt{Protocol: proto, Address: addr, ExitCode: code})
				continue
			}

			return code, nil
		}
	}

	return -1, &ConnectFailedErr{Attempts: attempts}
}

func buildArgv(proto, binPath, addr string, host *config.ResolvedHost) ([]string, error) {
	switch proto {
	case "ssh":
		return buildSSHArgv(binPath, addr, host.SSH), nil
	case "mosh":
		return buildMoshArgv(binPath, addr, host.Mosh), nil
	case "et":
		return buildETArgv(binPath, addr, host.ET), nil
	case "tailscale":
		return buildTailscaleArgv(binPath, addr, host.Tailscale), nil
	case "tsh":
		return buildTshArgv(binPath, addr, host.Tsh), nil
	default:
		return nil, fmt.Errorf("unknown protocol %q", proto)
	}
}
