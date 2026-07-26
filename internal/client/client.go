// Package client drives the protocol x address fallback loop that connects
// to a host using ssh, mosh, et, tailscale ssh, tsh, or telnet.
package client

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/liforra/warp/internal/config"
	"github.com/liforra/warp/internal/detect"
)

// connectFailureCode is ssh's conventional exit code for a connection-level
// failure (as opposed to the remote command's own exit status): 255 means
// "try the next thing," anything else means a real session happened and its
// exit code should propagate.
//
// This convention is NOT universal, though -- et, confirmed by testing,
// exits 1 on a connection failure ("Could not reach the ET server"), not
// 255, and would otherwise be misread as "a session happened, stop" instead
// of falling through to the next protocol. Rather than guess at (and
// maintain) each binary's own exit-code convention, preflightPort checks
// TCP reachability directly before ever invoking the binary, for any
// protocol with a well-defined port -- the same idea `warp --scan` uses.
// That resolves the common case (nothing listening at all) generically,
// across every protocol, without relying on exit codes at all. It can't
// help with a failure *after* the port answers (wrong credentials, a
// firewall that answers SYN but drops later packets, a protocol-level
// handshake failure) -- those still fall back to the exit-255 heuristic
// below, which remains ssh-specific and unverified for tailscale/tsh.
const connectFailureCode = 255

// preflightTimeout bounds the TCP reachability check done before invoking
// a protocol's binary at all.
const preflightTimeout = 3 * time.Second

// dial is overridden in tests to avoid touching the network.
var dial = net.DialTimeout

// preflightPort returns the port to reachability-check for proto before
// invoking its binary, and whether such a check applies at all. mosh
// bootstraps over ssh, so its bootstrap ssh port is checked. tailscale and
// tsh have no fixed, meaningfully-checkable port from here (tailscale ssh
// runs over the tailnet's own transport; tsh goes through a central
// proxy), so they're always attempted directly.
func preflightPort(proto string, host *config.ResolvedHost) (port int, ok bool) {
	switch proto {
	case "ssh":
		if p := host.SSH.Port; p != 0 {
			return p, true
		}
		return 22, true
	case "mosh":
		if p := host.Mosh.SSHPort; p != 0 {
			return p, true
		}
		if p := host.Mosh.Port; p != 0 {
			return p, true
		}
		return 22, true
	case "et":
		if p := host.ET.Port; p != 0 {
			return p, true
		}
		return 2022, true
	case "telnet":
		if p := host.Telnet.Port; p != 0 {
			return p, true
		}
		return 23, true
	default:
		return 0, false
	}
}

var protoBinary = map[string]detect.Binary{
	"ssh":       detect.SSH,
	"mosh":      detect.Mosh,
	"et":        detect.ET,
	"tailscale": detect.Tailscale,
	"tsh":       detect.Tsh,
	"telnet":    detect.Telnet,
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
// next protocol. Before invoking a protocol's binary at all, it does a TCP
// reachability preflight on that protocol's port (see preflightPort) and
// skips straight to the next address/protocol if nothing answers there --
// this is what actually handles "nothing is listening," generically,
// rather than relying on the binary's own exit code. It returns the exit
// code of the first session that actually ran (any exit code other than
// 255 counts as "a session happened," for protocols that get that far --
// see connectFailureCode), or a *ConnectFailedErr if nothing connected.
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
			if port, ok := preflightPort(proto, host); ok {
				addrPort := net.JoinHostPort(addr, strconv.Itoa(port))
				conn, dialErr := dial("tcp", addrPort, preflightTimeout)
				if dialErr != nil {
					attempts = append(attempts, Attempt{Protocol: proto, Address: addr, Skipped: true, Reason: fmt.Sprintf("port %d unreachable: %v", port, dialErr)})
					continue
				}
				conn.Close()
			}

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
	case "telnet":
		return buildTelnetArgv(binPath, addr, host.Telnet), nil
	default:
		return nil, fmt.Errorf("unknown protocol %q", proto)
	}
}
