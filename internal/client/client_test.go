package client

import (
	"errors"
	"os"
	"testing"

	"github.com/liforra/warp/internal/config"
	"github.com/liforra/warp/internal/detect"
)

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
