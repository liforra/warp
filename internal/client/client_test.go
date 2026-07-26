package client

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/liforra/warp/internal/config"
	"github.com/liforra/warp/internal/detect"
)

// fakeConn is a minimal net.Conn stand-in so the preflight check can call
// Close() on it without touching a real socket.
type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

// stubDialAlwaysReachable makes the preflight port check always succeed, so
// tests that exercise the exit-code fallback behavior (not the preflight
// itself) reach the fake Executor as before.
func stubDialAlwaysReachable(t *testing.T) {
	t.Helper()
	orig := dial
	dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return fakeConn{}, nil
	}
	t.Cleanup(func() { dial = orig })
}

// fakeExecutor returns exit codes (and, optionally, stderr text) from
// queues, in call order, so tests can script a sequence of connection
// outcomes without spawning real processes.
type fakeExecutor struct {
	codes   []int
	stderrs []string
	calls   [][]string
}

func (f *fakeExecutor) Run(argv []string) (int, string, error) {
	f.calls = append(f.calls, argv)

	code := 0
	if len(f.codes) > 0 {
		code = f.codes[0]
		f.codes = f.codes[1:]
	}

	stderr := ""
	if len(f.stderrs) > 0 {
		stderr = f.stderrs[0]
		f.stderrs = f.stderrs[1:]
	}

	return code, stderr, nil
}

// selfPath returns a path that is guaranteed to exist and be executable, so
// detect.Resolver can "find" a fake binary deterministically in tests.
func selfPath(t *testing.T) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return p
}

func TestConnectAddressFallbackThenProtocolFallback(t *testing.T) {
	stubDialAlwaysReachable(t)
	self := selfPath(t)
	resolver := detect.NewResolver(map[detect.Binary]string{
		detect.Mosh: self,
		detect.SSH:  self,
	})

	host := &config.ResolvedHost{
		Addresses: []string{"addr1", "addr2"},
		Protocols: []string{"mosh", "ssh"},
	}

	// mosh fails to connect on both addresses (255), ssh succeeds on the
	// first address it tries.
	exec := &fakeExecutor{codes: []int{255, 255, 0}}
	conn := &Connector{Resolver: resolver, Exec: exec}

	code, err := conn.Connect(host)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if len(exec.calls) != 3 {
		t.Fatalf("calls = %d, want 3 (mosh@addr1, mosh@addr2, ssh@addr1)", len(exec.calls))
	}
}

func TestConnectNonConnectFailureStopsImmediately(t *testing.T) {
	stubDialAlwaysReachable(t)
	self := selfPath(t)
	resolver := detect.NewResolver(map[detect.Binary]string{detect.SSH: self})

	host := &config.ResolvedHost{
		Addresses: []string{"addr1", "addr2"},
		Protocols: []string{"ssh"},
	}

	// A real session: connected, then the remote command exited 1. Should
	// not be treated as a connection failure, and address2 must not be tried.
	exec := &fakeExecutor{codes: []int{1}}
	conn := &Connector{Resolver: resolver, Exec: exec}

	code, err := conn.Connect(host)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if len(exec.calls) != 1 {
		t.Fatalf("calls = %d, want 1 (should not try addr2)", len(exec.calls))
	}
}

// TestConnectPreflightSkipsUnreachablePortWithoutInvokingBinary reproduces
// the real bug this preflight check fixes: et exits 1 (not ssh's 255) on a
// connection failure, so relying on exit codes alone would misread that as
// "a session happened" and stop instead of falling through to ssh. The
// preflight check must skip et before ever invoking it, based on port
// reachability alone, regardless of what its exit code would have been.
func TestConnectPreflightSkipsUnreachablePortWithoutInvokingBinary(t *testing.T) {
	origDial := dial
	dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if addr == "myhost:22" {
			return fakeConn{}, nil // ssh's port is reachable
		}
		return nil, errRefused{} // et's port (2022) is not
	}
	defer func() { dial = origDial }()

	self := selfPath(t)
	resolver := detect.NewResolver(map[detect.Binary]string{
		detect.ET:  self,
		detect.SSH: self,
	})

	host := &config.ResolvedHost{
		Addresses: []string{"myhost"},
		Protocols: []string{"et", "ssh"},
	}

	// et should never actually be invoked (preflight skips it), so ssh gets
	// the only exec call and should succeed.
	exec := &fakeExecutor{codes: []int{0}}
	conn := &Connector{Resolver: resolver, Exec: exec}

	code, err := conn.Connect(host)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0 (ssh should have succeeded)", code)
	}
	if len(exec.calls) != 1 {
		t.Fatalf("calls = %d, want 1 -- et should never have been invoked (port unreachable), only ssh", len(exec.calls))
	}
}

// TestConnectRetriesMoshAfterNoMoshServerMarker reproduces the second
// real-world bug: mosh's own ssh bootstrap succeeds (port reachable, so
// preflight passes) but mosh-server isn't installed on the remote, so mosh
// exits non-255 anyway. That must still be treated as retriable -- ssh
// should get a chance -- based on mosh's stable stderr message, not by
// treating every non-zero mosh exit as retriable (which risks misreading a
// real session's own non-zero exit as a connection failure).
func TestConnectRetriesMoshAfterNoMoshServerMarker(t *testing.T) {
	stubDialAlwaysReachable(t)
	self := selfPath(t)
	resolver := detect.NewResolver(map[detect.Binary]string{
		detect.Mosh: self,
		detect.SSH:  self,
	})

	host := &config.ResolvedHost{
		Addresses: []string{"myhost"},
		Protocols: []string{"mosh", "ssh"},
	}

	exec := &fakeExecutor{
		codes:   []int{10, 0},
		stderrs: []string{"/usr/bin/mosh: Did not find mosh server startup message. (Have you installed mosh on your server?)"},
	}
	conn := &Connector{Resolver: resolver, Exec: exec}

	code, err := conn.Connect(host)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0 (ssh should have been tried and succeeded)", code)
	}
	if len(exec.calls) != 2 {
		t.Fatalf("calls = %d, want 2 (mosh, then ssh)", len(exec.calls))
	}
}

// TestConnectDoesNotRetryMoshOnUnrelatedNonZeroExit guards against
// over-broadening the mosh check to "any non-zero exit": a real session
// that happens to end with a non-zero exit status (e.g. the user's last
// remote command failed) must NOT be treated as a connection failure.
func TestConnectDoesNotRetryMoshOnUnrelatedNonZeroExit(t *testing.T) {
	stubDialAlwaysReachable(t)
	self := selfPath(t)
	resolver := detect.NewResolver(map[detect.Binary]string{
		detect.Mosh: self,
		detect.SSH:  self,
	})

	host := &config.ResolvedHost{
		Addresses: []string{"myhost"},
		Protocols: []string{"mosh", "ssh"},
	}

	exec := &fakeExecutor{codes: []int{1}} // no matching stderr marker
	conn := &Connector{Resolver: resolver, Exec: exec}

	code, err := conn.Connect(host)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if code != 1 {
		t.Errorf("code = %d, want 1 (a real session's own exit code, propagated)", code)
	}
	if len(exec.calls) != 1 {
		t.Fatalf("calls = %d, want 1 (should not have fallen through to ssh)", len(exec.calls))
	}
}

// TestConnectPrioritizesLastAttemptedAddressForNextProtocol reproduces the
// third real-world issue: with ControlMaster configured, ssh's multiplexed
// connection is keyed by the *literal* address string. If mosh's failed
// attempt authenticated against addr2, falling through to ssh should retry
// addr2 first too -- not restart from addr1 -- so a real ControlMaster
// setup gets a chance to reuse that connection instead of prompting again.
func TestConnectPrioritizesLastAttemptedAddressForNextProtocol(t *testing.T) {
	stubDialAlwaysReachable(t)
	self := selfPath(t)
	resolver := detect.NewResolver(map[detect.Binary]string{
		detect.Mosh: self,
		detect.SSH:  self,
	})

	host := &config.ResolvedHost{
		Addresses: []string{"addr1", "addr2"},
		Protocols: []string{"mosh", "ssh"},
	}

	exec := &fakeExecutor{
		codes: []int{255, 10, 0},
		stderrs: []string{
			"", // addr1: plain connection failure, keep trying other addresses
			"/usr/bin/mosh: Did not find mosh server startup message. (Have you installed mosh on your server?)", // addr2: host-level failure, abandon mosh
		},
	}
	conn := &Connector{Resolver: resolver, Exec: exec}

	code, err := conn.Connect(host)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if len(exec.calls) != 3 {
		t.Fatalf("calls = %d, want 3 (mosh@addr1, mosh@addr2, ssh@addr2)", len(exec.calls))
	}

	sshCall := exec.calls[2]
	found := false
	for _, arg := range sshCall {
		if arg == "addr2" || strings.HasSuffix(arg, "@addr2") {
			found = true
		}
	}
	if !found {
		t.Errorf("ssh call = %v, want it to target addr2 (mosh's last attempted address), not restart from addr1", sshCall)
	}
}

type errRefused struct{}

func (errRefused) Error() string { return "connection refused" }

func TestConnectAllFailReturnsConnectFailedErr(t *testing.T) {
	resolver := detect.NewResolver(map[detect.Binary]string{
		detect.SSH: "/definitely-not-a-real-binary-warp-test",
	})

	host := &config.ResolvedHost{
		Addresses: []string{"addr1"},
		Protocols: []string{"ssh"},
	}

	exec := &fakeExecutor{}
	conn := &Connector{Resolver: resolver, Exec: exec}

	_, err := conn.Connect(host)
	var failErr *ConnectFailedErr
	if !errors.As(err, &failErr) {
		t.Fatalf("err = %v, want *ConnectFailedErr", err)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("calls = %d, want 0 (binary unresolvable, should never exec)", len(exec.calls))
	}
	if len(failErr.Attempts) != 1 || !failErr.Attempts[0].Skipped {
		t.Fatalf("Attempts = %+v, want one skipped attempt", failErr.Attempts)
	}
}
