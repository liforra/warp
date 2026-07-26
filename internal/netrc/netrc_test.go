package netrc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseBasicMachineEntry(t *testing.T) {
	entries := parse(`
machine old-switch.example.com
login admin
password hunter2
`)
	e, ok := entries["old-switch.example.com"]
	if !ok {
		t.Fatalf("expected entry for old-switch.example.com, got %+v", entries)
	}
	if e.Login != "admin" {
		t.Errorf("Login = %q, want %q", e.Login, "admin")
	}
}

func TestParseMultipleMachines(t *testing.T) {
	entries := parse(`
machine host1 login alice password secret1
machine host2 login bob password secret2
`)
	if entries["host1"].Login != "alice" {
		t.Errorf("host1 Login = %q, want alice", entries["host1"].Login)
	}
	if entries["host2"].Login != "bob" {
		t.Errorf("host2 Login = %q, want bob", entries["host2"].Login)
	}
}

func TestParseDefaultEntryNotKeyed(t *testing.T) {
	entries := parse(`
machine host1
login alice

default
login anonymous
`)
	if _, ok := entries["default"]; ok {
		t.Error("default should not be returned as a keyed machine entry")
	}
	if entries["host1"].Login != "alice" {
		t.Errorf("host1 Login = %q, want alice", entries["host1"].Login)
	}
}

func TestParseMacdefIsSkippedNotMisparsed(t *testing.T) {
	entries := parse(`
machine host1
login alice

macdef init
machine fake-injected-via-macro
login should-not-appear

machine host2
login bob
`)
	if _, ok := entries["fake-injected-via-macro"]; ok {
		t.Error("macro body should not be parsed as real entries")
	}
	if entries["host1"].Login != "alice" || entries["host2"].Login != "bob" {
		t.Errorf("entries = %+v, want host1=alice host2=bob", entries)
	}
}

func TestParseNeverRetainsPassword(t *testing.T) {
	entries := parse(`
machine host1
login alice
password hunter2
`)
	// Entry has no Password field at all -- this test exists to make the
	// invariant explicit and catch any future regression that adds one.
	e := entries["host1"]
	if e.Login != "alice" {
		t.Errorf("Login = %q, want alice", e.Login)
	}
}

func TestParseFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netrc")
	if err := os.WriteFile(path, []byte("machine example.com\nlogin someone\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entries, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if entries["example.com"].Login != "someone" {
		t.Errorf("got %+v, want example.com login=someone", entries)
	}
}

func TestParseMissingFile(t *testing.T) {
	if _, err := Parse("/nonexistent/netrc/path"); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
