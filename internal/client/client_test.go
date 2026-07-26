package client

import (
	"errors"
	"net"
	"os"
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

// fakeExecutor returns exit codes from a queue, in call order, so tests can
// script a sequence of connection outcomes without spawning real processes.
type fakeExecutor struct {
	codes []int
	calls [][]string
}

func (f *fakeExecutor) Run(argv []string) (int, error) {
	f.calls = append(f.calls, argv)
	if len(f.codes) == 0 {
		return 0, nil
	}
	code := f.codes[0]
	f.codes = f.codes[1:]
	return code, nil
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
