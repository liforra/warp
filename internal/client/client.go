// Package client drives the protocol x address fallback loop that connects
// to a host using ssh, mosh, et, tailscale ssh, tsh, or telnet.
package client

import (
	"bytes"
	"fmt"
	"io"
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

// protoLabel is the human-friendly name printed in the "Connecting with
// ..." announcement just before a protocol is actually invoked.
var protoLabel = map[string]string{
	"ssh":       "SSH",
	"mosh":      "Mosh",
	"et":        "ET",
	"tailscale": "Tailscale SSH",
	"tsh":       "Teleport (tsh)",
	"telnet":    "Telnet",
}

func labelFor(proto string) string {
	if l, ok := protoLabel[proto]; ok {
		return l
	}
	return proto
}

// Executor runs a fully-built argv (argv[0] is the resolved binary path)
// and reports its exit code, plus a copy of what it wrote to stderr (used
// to detect known non-255 connection-failure signatures -- see
// knownFailureMarkers). It's an interface so tests can substitute a fake
// without spawning real processes.
type Executor interface {
	Run(argv []string) (exitCode int, stderr string, err error)
}

// ExecExecutor is the real Executor: it runs the command with the current
// process's stdio wired through, so interactive sessions behave normally.
// stderr is additionally captured (via io.MultiWriter) for the caller to
// inspect, without changing what the user actually sees on their terminal.
type ExecExecutor struct{}

func (ExecExecutor) Run(argv []string) (int, string, error) {
	var stderrBuf bytes.Buffer

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)

	err := cmd.Run()
	if err == nil {
		return 0, stderrBuf.String(), nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), stderrBuf.String(), nil
	}
	// The process never started (binary vanished, permissions, etc.).
	return -1, stderrBuf.String(), err
}

// knownFailureMarkers are stable, protocol-specific stderr substrings that
// indicate a connection-level failure even though the binary's own exit
// code doesn't follow ssh's 255 convention. Confirmed by real-world
// testing: mosh's ssh bootstrap can succeed (you've already authenticated)
// while mosh itself still fails because mosh-server isn't installed on the
// remote -- mosh's exit code for that isn't 255, so without this it would
// be misread as "a session happened, stop" instead of falling through to
// the next protocol. This is deliberately narrow (an exact, stable message)
// rather than "treat any non-zero mosh exit as retriable," which would
// risk misreading a real interactive session's own non-zero exit status
// (e.g. the user's last command failed) as a connection failure.
var knownFailureMarkers = map[string][]string{
	"mosh": {"Did not find mosh server startup message"},
}

func isKnownConnectFailure(proto, stderr string) bool {
	for _, marker := range knownFailureMarkers[proto] {
		if strings.Contains(stderr, marker) {
			return true
		}
	}
	return false
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
// protocol it tries every address in host.Addresses (the last address that
// got far enough to actually attempt a connection is tried first for each
// subsequent protocol -- see prioritizeAddr) before moving on to the next
// protocol. Before invoking a protocol's binary at all, it does a TCP
// reachability preflight on that protocol's port (see preflightPort) and
// skips straight to the next address/protocol if nothing answers there --
// this is what actually handles "nothing is listening," generically,
// rather than relying on the binary's own exit code. It returns the exit
// code of the first session that actually ran (any exit code other than
// 255 counts as "a session happened," for protocols that get that far --
// see connectFailureCode), or a *ConnectFailedErr if nothing connected.
func (c *Connector) Connect(host *config.ResolvedHost) (int, error) {
	var attempts []Attempt

	// preferredAddr is the last address that got far enough to actually
	// invoke a binary (regardless of outcome). ssh's ControlMaster/
	// ControlPath keys its multiplexed connection by the *literal* address
	// string given to it, so falling through to the next protocol against
	// a *different* address -- even one that reaches the same physical
	// host -- would never reuse a connection an earlier attempt just
	// authenticated. Trying preferredAddr first for each subsequent
	// protocol maximizes the chance ControlMaster (if configured) can
	// reuse that connection instead of prompting for auth again.
	var preferredAddr string

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

		for _, addr := range prioritizeAddr(host.Addresses, preferredAddr) {
			if port, ok := preflightPort(proto, host); ok {
				addrPort := net.JoinHostPort(addr, strconv.Itoa(port))
				conn, dialErr := dial("tcp", addrPort, preflightTimeout)
				if dialErr != nil {
					attempts = append(attempts, Attempt{Protocol: proto, Address: addr, Skipped: true, Reason: fmt.Sprintf("port %d unreachable: %v", port, dialErr)})
					continue
				}
				conn.Close()
			}

			// Only announced once we've confirmed (via preflight, where
			// applicable) that this attempt is actually worth making --
			// tailscale/tsh have no preflight check, so for those it's
			// printed right before invoking regardless, since there's no
			// way to verify in advance.
			fmt.Fprintf(os.Stderr, "Connecting with %s (%s)...\n", labelFor(proto), addr)
			preferredAddr = addr

			argv, err := buildArgv(proto, res.Path, addr, host)
			if err != nil {
				attempts = append(attempts, Attempt{Protocol: proto, Address: addr, Skipped: true, Reason: err.Error()})
				continue
			}

			code, stderr, err := c.Exec.Run(argv)
			if err != nil {
				attempts = append(attempts, Attempt{Protocol: proto, Address: addr, Skipped: true, Reason: err.Error()})
				continue
			}

			if isKnownConnectFailure(proto, stderr) {
				// A known failure marker describes a property of the
				// remote host itself (e.g. mosh-server isn't installed
				// there), not of this specific address -- retrying the
				// other addresses for the same protocol would just repeat
				// the same failure (and the same auth prompt) pointlessly.
				// Abandon this protocol entirely and move on to the next.
				attempts = append(attempts, Attempt{Protocol: proto, Address: addr, ExitCode: code})
				break
			}

			if code == connectFailureCode {
				// A plain transport-level failure, which can legitimately
				// vary per address (different network path), so still
				// worth retrying the other addresses for this protocol.
				attempts = append(attempts, Attempt{Protocol: proto, Address: addr, ExitCode: code})
				continue
			}

			return code, nil
		}
	}

	return -1, &ConnectFailedErr{Attempts: attempts}
}

// prioritizeAddr returns addrs with preferred moved to the front, if it's
// present at all (preferred == "" or not found just returns addrs as-is).
func prioritizeAddr(addrs []string, preferred string) []string {
	if preferred == "" {
		return addrs
	}
	out := make([]string, 0, len(addrs))
	out = append(out, preferred)
	for _, a := range addrs {
		if a != preferred {
			out = append(out, a)
		}
	}
	return out
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
