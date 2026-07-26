package sshconfig

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
	return path
}

func TestParseBasicHostBlock(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config", `
Host myserver
  HostName 10.0.0.5
  User bob
  Port 2222
  IdentityFile ~/.ssh/id_work
  ProxyJump bastion
`)

	hosts, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1: %+v", len(hosts), hosts)
	}
	h := hosts[0]
	if h.Name != "myserver" || h.HostName != "10.0.0.5" || h.User != "bob" ||
		h.Port != 2222 || h.IdentityFile != "~/.ssh/id_work" || h.ProxyJump != "bastion" {
		t.Errorf("got %+v, want fully populated myserver host", h)
	}
}

func TestParseSkipsWildcardHosts(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config", `
Host *
  User globaluser

Host *.example.com
  Port 2200

Host real-host
  HostName 192.168.1.1
`)

	hosts, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Name != "real-host" {
		t.Fatalf("got %+v, want only real-host", hosts)
	}
}

func TestParseEqualsSyntax(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config", `
Host eq-style
  HostName=10.0.0.9
  Port=2022
`)

	hosts, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(hosts) != 1 || hosts[0].HostName != "10.0.0.9" || hosts[0].Port != 2022 {
		t.Fatalf("got %+v, want HostName=10.0.0.9 Port=2022", hosts)
	}
}

func TestParseFollowsInclude(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "included", `
Host included-host
  HostName 10.0.0.20
`)
	main := writeFile(t, dir, "config", `
Include included

Host main-host
  HostName 10.0.0.10
`)

	hosts, err := Parse(main)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	names := map[string]bool{}
	for _, h := range hosts {
		names[h.Name] = true
	}
	if !names["included-host"] || !names["main-host"] {
		t.Fatalf("got %+v, want both included-host and main-host", hosts)
	}
}

func TestParseIncludeCycleDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a", "Include b\n")
	writeFile(t, dir, "b", "Include a\n")

	// Should return (possibly with an error, possibly empty), but must not
	// hang or stack-overflow.
	done := make(chan struct{})
	go func() {
		Parse(a)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Parse did not return -- likely an infinite include loop")
	}
}

func TestParseMissingFile(t *testing.T) {
	if _, err := Parse("/nonexistent/path/that/should/not/exist"); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
