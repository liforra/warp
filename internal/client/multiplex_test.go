package client

import (
	"errors"
	"testing"
	"time"
)

func TestMultiplexerControlPathCachesPerKey(t *testing.T) {
	orig := runSSHCommand
	calls := 0
	runSSHCommand = func(sshPath string, args ...string) error {
		calls++
		return nil
	}
	defer func() { runSSHCommand = orig }()

	m := newMultiplexer("/usr/bin/ssh", 0)

	p1 := m.controlPath("alice", "host1", 22, "/key")
	if p1 == "" {
		t.Fatal("controlPath returned empty on success")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 after first controlPath call", calls)
	}

	p2 := m.controlPath("alice", "host1", 22, "/key")
	if p2 != p1 {
		t.Errorf("controlPath = %q, want same path %q as first call (cached)", p2, p1)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want still 1 -- same (user,addr,port) should reuse, not re-establish", calls)
	}

	p3 := m.controlPath("alice", "host2", 22, "/key")
	if p3 == p1 {
		t.Error("controlPath for a different address should not reuse host1's socket path")
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2 after a genuinely new (user,addr,port)", calls)
	}
}

func TestMultiplexerControlPathFailureReturnsEmpty(t *testing.T) {
	orig := runSSHCommand
	runSSHCommand = func(sshPath string, args ...string) error {
		return errors.New("connection failed")
	}
	defer func() { runSSHCommand = orig }()

	m := newMultiplexer("/usr/bin/ssh", 0)
	if p := m.controlPath("alice", "host1", 22, "/key"); p != "" {
		t.Errorf("controlPath = %q, want empty when establishing the master fails", p)
	}
}

func TestMultiplexerControlPathEmptyWithoutSSHPath(t *testing.T) {
	m := newMultiplexer("", 0)
	if p := m.controlPath("alice", "host1", 22, "/key"); p != "" {
		t.Errorf("controlPath = %q, want empty when sshPath is unresolved", p)
	}
}

func TestMultiplexerCloseAllTearsDownWhenNotPersisting(t *testing.T) {
	orig := runSSHCommand
	var teardownCalls [][]string
	runSSHCommand = func(sshPath string, args ...string) error {
		if len(args) > 0 && args[0] == "-O" {
			teardownCalls = append(teardownCalls, args)
		}
		return nil
	}
	defer func() { runSSHCommand = orig }()

	m := newMultiplexer("/usr/bin/ssh", 0) // persist <= 0: should tear down
	m.controlPath("alice", "host1", 22, "/key")
	m.closeAll()

	if len(teardownCalls) != 1 {
		t.Fatalf("teardown calls = %d, want 1", len(teardownCalls))
	}
}

func TestMultiplexerCloseAllSkipsTeardownWhenPersisting(t *testing.T) {
	orig := runSSHCommand
	var teardownCalls int
	runSSHCommand = func(sshPath string, args ...string) error {
		if len(args) > 0 && args[0] == "-O" {
			teardownCalls++
		}
		return nil
	}
	defer func() { runSSHCommand = orig }()

	m := newMultiplexer("/usr/bin/ssh", 5*time.Minute) // persist > 0: leave it running
	m.controlPath("alice", "host1", 22, "/key")
	m.closeAll()

	if teardownCalls != 0 {
		t.Errorf("teardown calls = %d, want 0 when a persist duration is configured", teardownCalls)
	}
}

func TestParseMultiplexPersist(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"not-a-duration", 0},
		{"5m", 5 * time.Minute},
		{"30s", 30 * time.Second},
	}
	for _, c := range cases {
		if got := parseMultiplexPersist(c.in); got != c.want {
			t.Errorf("parseMultiplexPersist(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
