package client

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// safetyNetPersist bounds how long a warp-established master connection
// can live even if warp's own explicit teardown never runs (e.g. a crash),
// when the user hasn't configured a longer multiplex_persist themselves.
const safetyNetPersist = 30 * time.Second

// runSSHCommand is overridden in tests to avoid spawning real ssh
// processes (establishing or tearing down a master connection).
var runSSHCommand = func(sshPath string, args ...string) error {
	cmd := exec.Command(sshPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// master is one warp-established ControlMaster connection.
type master struct {
	controlPath string
	target      string // "[user@]addr", as passed to ssh
}

// multiplexer establishes and tracks warp-owned ssh ControlMaster
// connections for the lifetime of one Connect call, so ssh and mosh's
// bootstrap can share a single real authenticated connection per (user,
// address, port) instead of prompting separately. This exists because
// real-world testing showed mosh's own aborted bootstrap doesn't reliably
// leave a usable ControlMaster socket behind for a subsequent ssh fallback
// to reuse, even with ControlMaster configured in ~/.ssh/config.
//
// It's deliberately best-effort: establishing a master can fail (ssh not
// resolvable, unsupported platform, the connection itself failing) without
// that being a hard error -- callers just get "" back and proceed without
// a shared ControlPath, falling back to whatever the user's own ssh_config
// provides (i.e. today's behavior).
type multiplexer struct {
	sshPath string
	persist time.Duration // <=0 means "tear down explicitly in closeAll"
	masters map[string]master
}

func newMultiplexer(sshPath string, persist time.Duration) *multiplexer {
	return &multiplexer{sshPath: sshPath, persist: persist, masters: make(map[string]master)}
}

// controlPath returns the ControlPath to use for (user, addr, port),
// establishing a new master connection if one for this exact combination
// doesn't already exist yet in this Connect call. Returns "" if
// multiplexing isn't usable here; callers should treat that as "proceed
// without one," not an error.
func (m *multiplexer) controlPath(user, addr string, port int, identityFile string) string {
	if m == nil || m.sshPath == "" || runtime.GOOS == "windows" {
		// ControlMaster's unix-domain-socket approach isn't reliably
		// supported on Windows across ssh implementations.
		return ""
	}

	key := fmt.Sprintf("%s@%s:%d", user, addr, port)
	if existing, ok := m.masters[key]; ok {
		return existing.controlPath
	}

	dir, err := os.MkdirTemp("", "warp-ssh-cm")
	if err != nil {
		return ""
	}
	controlPath := filepath.Join(dir, "socket")
	tgt := target(user, addr)

	persist := m.persist
	if persist <= 0 {
		persist = safetyNetPersist
	}

	args := []string{
		"-o", "ControlMaster=auto",
		"-o", "ControlPath=" + controlPath,
		"-o", "ControlPersist=" + persist.String(),
		"-N", "-f",
	}
	if identityFile != "" {
		args = append(args, "-i", identityFile)
	}
	if port != 0 {
		args = append(args, "-p", strconv.Itoa(port))
	}
	args = append(args, tgt)

	if err := runSSHCommand(m.sshPath, args...); err != nil {
		os.RemoveAll(dir)
		return ""
	}

	m.masters[key] = master{controlPath: controlPath, target: tgt}
	return controlPath
}

// closeAll tears down every master this multiplexer established, unless a
// persist duration was configured (in which case ControlPersist's own
// timeout governs cleanup instead, per the user's own multiplex_persist
// setting).
func (m *multiplexer) closeAll() {
	if m == nil || m.persist > 0 {
		return
	}
	for _, mst := range m.masters {
		runSSHCommand(m.sshPath, "-O", "exit", "-o", "ControlPath="+mst.controlPath, mst.target)
		os.RemoveAll(filepath.Dir(mst.controlPath))
	}
}
