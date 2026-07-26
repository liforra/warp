package config

import (
	"testing"
)

const testConfig = `
[defaults]
user = "alice"
port = 22

[host.myserver]
addresses = ["myserver.example.com", "10.0.0.5"]
aliases = ["ms", "myserver-prod"]
protocol = ["mosh", "ssh"]

[host.myserver.ssh]
port = 2200
proxy_jump = "bastion"

[host.sshonly]
addresses = "sshonly.example.com"
protocol = "ssh"
`

func TestMergePrecedence(t *testing.T) {
	cfg, err := Parse([]byte(testConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	resolved, err := cfg.Resolve("myserver")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if resolved.Mosh.Port != 22 {
		t.Errorf("Mosh.Port = %d, want 22 (inherited from defaults)", resolved.Mosh.Port)
	}
	if resolved.SSH.Port != 2200 {
		t.Errorf("SSH.Port = %d, want 2200 (host.ssh override)", resolved.SSH.Port)
	}
	if resolved.SSH.User != "alice" {
		t.Errorf("SSH.User = %q, want %q (inherited from defaults)", resolved.SSH.User, "alice")
	}
	if resolved.SSH.ProxyJump != "bastion" {
		t.Errorf("SSH.ProxyJump = %q, want %q", resolved.SSH.ProxyJump, "bastion")
	}
}

func TestStringOrSliceBareStringAndArray(t *testing.T) {
	cfg, err := Parse([]byte(testConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	multi, _, ok := cfg.FindHost("myserver")
	if !ok {
		t.Fatalf("FindHost(myserver) not found")
	}
	resolved, err := cfg.Resolve(multi)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	wantAddrs := []string{"myserver.example.com", "10.0.0.5"}
	if !slicesEqual(resolved.Addresses, wantAddrs) {
		t.Errorf("Addresses = %v, want %v", resolved.Addresses, wantAddrs)
	}
	wantProtos := []string{"mosh", "ssh"}
	if !slicesEqual(resolved.Protocols, wantProtos) {
		t.Errorf("Protocols = %v, want %v", resolved.Protocols, wantProtos)
	}

	solo, err := cfg.Resolve("sshonly")
	if err != nil {
		t.Fatalf("Resolve(sshonly): %v", err)
	}
	if !slicesEqual(solo.Addresses, []string{"sshonly.example.com"}) {
		t.Errorf("Addresses = %v, want single-element slice from bare string", solo.Addresses)
	}
	if !slicesEqual(solo.Protocols, []string{"ssh"}) {
		t.Errorf("Protocols = %v, want single-element slice from bare string", solo.Protocols)
	}
}

func TestAliasResolution(t *testing.T) {
	cfg, err := Parse([]byte(testConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	canon, _, ok := cfg.FindHost("ms")
	if !ok || canon != "myserver" {
		t.Fatalf("FindHost(ms) = (%q, %v), want (myserver, true)", canon, ok)
	}

	canon, _, ok = cfg.FindHost("myserver")
	if !ok || canon != "myserver" {
		t.Fatalf("FindHost(myserver) = (%q, %v), want (myserver, true)", canon, ok)
	}

	if _, _, ok := cfg.FindHost("nope"); ok {
		t.Fatalf("FindHost(nope) should not resolve")
	}
}

func TestResolveDefaultsProtocolOrderWhenUnset(t *testing.T) {
	const noProtocolConfig = `
[host.bare]
addresses = "bare.example.com"
`
	cfg, err := Parse([]byte(noProtocolConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	resolved, err := cfg.Resolve("bare")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !slicesEqual(resolved.Protocols, DefaultProtocolOrder) {
		t.Errorf("Protocols = %v, want DefaultProtocolOrder %v", resolved.Protocols, DefaultProtocolOrder)
	}
}

func TestAliasCollisionErrors(t *testing.T) {
	const collidingConfig = `
[host.a]
addresses = "a.example.com"
protocol = "ssh"
aliases = ["shared"]

[host.b]
addresses = "b.example.com"
protocol = "ssh"
aliases = ["shared"]
`
	if _, err := Parse([]byte(collidingConfig)); err == nil {
		t.Fatal("expected error on alias collision, got nil")
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
