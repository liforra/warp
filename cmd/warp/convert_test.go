package main

import (
	"strings"
	"testing"

	"github.com/liforra/warp/internal/config"
	"github.com/liforra/warp/internal/sshconfig"
)

func TestRenderWarpTomlBasic(t *testing.T) {
	hosts := []sshconfig.Host{
		{Name: "myserver", HostName: "10.0.0.5", User: "bob", Port: 2222, ProxyJump: "bastion"},
		{Name: "bare-host"},
	}

	out := renderWarpToml("~/.ssh/config", hosts)

	if !strings.Contains(out, "[host.myserver]") {
		t.Errorf("missing [host.myserver] block:\n%s", out)
	}
	if !strings.Contains(out, `addresses = "10.0.0.5"`) {
		t.Errorf("missing addresses line:\n%s", out)
	}
	if !strings.Contains(out, `user = "bob"`) {
		t.Errorf("missing user line:\n%s", out)
	}
	if !strings.Contains(out, "port = 2222") {
		t.Errorf("missing port line:\n%s", out)
	}
	if !strings.Contains(out, "[host.myserver.ssh]") || !strings.Contains(out, `proxy_jump = "bastion"`) {
		t.Errorf("missing proxy_jump block:\n%s", out)
	}
	// bare-host has no HostName, so its own literal name is used as the address.
	if !strings.Contains(out, "[host.bare-host]") || !strings.Contains(out, `addresses = "bare-host"`) {
		t.Errorf("missing bare-host block using its own name as address:\n%s", out)
	}
}

func TestRenderWarpTomlEmpty(t *testing.T) {
	out := renderWarpToml("~/.ssh/config", nil)
	if !strings.Contains(out, "No literal") {
		t.Errorf("expected a note about no importable hosts, got:\n%s", out)
	}
}

// TestRenderWarpTomlRoundTrips confirms the generated document is actually
// valid input to config.Parse, not just plausible-looking text.
func TestRenderWarpTomlRoundTrips(t *testing.T) {
	hosts := []sshconfig.Host{
		{Name: "myserver", HostName: "10.0.0.5", User: "bob", Port: 2222, IdentityFile: "~/.ssh/id_ed25519", ProxyJump: "bastion"},
	}
	out := renderWarpToml("~/.ssh/config", hosts)

	// Disable auto-sourcing for this parse: it's on by default in real use,
	// but this test only cares about the generated [host.*] blocks
	// themselves, not the (unrelated to --convert) sourcing feature -- and
	// this package has no equivalent to internal/config's test-only
	// userHomeDir override, so leaving it on would read this machine's
	// actual ~/.ssh/config and ~/.netrc.
	out += "\n[sources.ssh_config]\nenabled = false\n[sources.netrc]\nenabled = false\n"

	cfg, err := config.Parse([]byte(out))
	if err != nil {
		t.Fatalf("generated TOML failed to parse: %v\n%s", err, out)
	}
	resolved, err := cfg.Resolve("myserver")
	if err != nil {
		t.Fatalf("Resolve(myserver): %v", err)
	}
	if resolved.SSH.User != "bob" || resolved.SSH.Port != 2222 || resolved.SSH.ProxyJump != "bastion" {
		t.Errorf("resolved.SSH = %+v, want User=bob Port=2222 ProxyJump=bastion", resolved.SSH)
	}
}
