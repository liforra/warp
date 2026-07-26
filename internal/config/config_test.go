package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain isolates every test in this package from the real machine's
// ~/.ssh/config and ~/.netrc: applySources runs by default on every Parse,
// and without this, test behavior would depend on whatever the developer's
// or CI runner's actual dotfiles happen to contain.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "warp-config-test-home")
	if err != nil {
		panic(err)
	}

	orig := userHomeDir
	userHomeDir = func() (string, error) { return dir, nil }

	// Note: os.Exit below skips any deferred cleanup, so restore/remove
	// happen explicitly before it rather than via defer.
	code := m.Run()
	userHomeDir = orig
	os.RemoveAll(dir)

	os.Exit(code)
}

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

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
	t.Cleanup(func() { os.Remove(path) })
}

func TestImportSSHConfigAddsLowerPriorityHost(t *testing.T) {
	dir := t.TempDir()
	sshConfigPath := filepath.Join(dir, "ssh_config")
	writeTestFile(t, sshConfigPath, `
Host imported-host
  HostName 10.0.0.42
  User carol
  Port 2200
`)

	toml := `
[sources.ssh_config]
paths = ["` + sshConfigPath + `"]
[sources.netrc]
enabled = false
`
	cfg, err := Parse([]byte(toml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	resolved, err := cfg.Resolve("imported-host")
	if err != nil {
		t.Fatalf("Resolve(imported-host): %v", err)
	}
	if !slicesEqual(resolved.Addresses, []string{"10.0.0.42"}) {
		t.Errorf("Addresses = %v, want [10.0.0.42]", resolved.Addresses)
	}
	if resolved.SSH.User != "carol" || resolved.SSH.Port != 2200 {
		t.Errorf("SSH = %+v, want User=carol Port=2200", resolved.SSH)
	}
	if !slicesEqual(resolved.Protocols, DefaultProtocolOrder) {
		t.Errorf("Protocols = %v, want DefaultProtocolOrder (no protocol info in ssh_config)", resolved.Protocols)
	}
}

func TestImportSSHConfigExplicitHostWins(t *testing.T) {
	dir := t.TempDir()
	sshConfigPath := filepath.Join(dir, "ssh_config")
	writeTestFile(t, sshConfigPath, `
Host myserver
  HostName 10.9.9.9
  User from-ssh-config
`)

	toml := `
[sources.ssh_config]
paths = ["` + sshConfigPath + `"]
[sources.netrc]
enabled = false

[host.myserver]
addresses = "myserver.explicit.example.com"
protocol = "ssh"
user = "explicit-user"
`
	cfg, err := Parse([]byte(toml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	resolved, err := cfg.Resolve("myserver")
	if err != nil {
		t.Fatalf("Resolve(myserver): %v", err)
	}
	if resolved.Addresses[0] != "myserver.explicit.example.com" {
		t.Errorf("Addresses = %v, explicit warp.toml host should win entirely over sourced ssh_config entry", resolved.Addresses)
	}
	if resolved.SSH.User != "explicit-user" {
		t.Errorf("SSH.User = %q, want explicit-user (explicit config wins)", resolved.SSH.User)
	}
}

func TestImportSSHConfigSkipsAliasCollision(t *testing.T) {
	dir := t.TempDir()
	sshConfigPath := filepath.Join(dir, "ssh_config")
	writeTestFile(t, sshConfigPath, `
Host ms
  HostName 10.9.9.9
`)

	toml := `
[sources.ssh_config]
paths = ["` + sshConfigPath + `"]
[sources.netrc]
enabled = false

[host.myserver]
addresses = "myserver.example.com"
protocol = "ssh"
aliases = ["ms"]
`
	cfg, err := Parse([]byte(toml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	canon, _, ok := cfg.FindHost("ms")
	if !ok || canon != "myserver" {
		t.Fatalf("FindHost(ms) = (%q, %v), want (myserver, true) -- alias should win over sourced host of the same name", canon, ok)
	}
}

func TestNetrcEnablesTelnetAutologin(t *testing.T) {
	dir := t.TempDir()
	netrcPath := filepath.Join(dir, "netrc")
	writeTestFile(t, netrcPath, `
machine old-switch.example.com
login admin
password hunter2
`)

	toml := `
[sources.ssh_config]
enabled = false
[sources.netrc]
paths = ["` + netrcPath + `"]

[host.oldswitch]
addresses = "old-switch.example.com"
protocol = "telnet"
`
	cfg, err := Parse([]byte(toml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	resolved, err := cfg.Resolve("oldswitch")
	if err != nil {
		t.Fatalf("Resolve(oldswitch): %v", err)
	}
	if !resolved.Telnet.NetrcAutologin {
		t.Error("Telnet.NetrcAutologin = false, want true (matching .netrc machine entry)")
	}
	if resolved.Telnet.User != "admin" {
		t.Errorf("Telnet.User = %q, want admin (from .netrc login, since not set explicitly)", resolved.Telnet.User)
	}
}

func TestNetrcDoesNotOverrideExplicitUser(t *testing.T) {
	dir := t.TempDir()
	netrcPath := filepath.Join(dir, "netrc")
	writeTestFile(t, netrcPath, `
machine old-switch.example.com
login admin
password hunter2
`)

	toml := `
[sources.ssh_config]
enabled = false
[sources.netrc]
paths = ["` + netrcPath + `"]

[host.oldswitch]
addresses = "old-switch.example.com"
protocol = "telnet"

[host.oldswitch.telnet]
user = "explicit-telnet-user"
`
	cfg, err := Parse([]byte(toml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	resolved, err := cfg.Resolve("oldswitch")
	if err != nil {
		t.Fatalf("Resolve(oldswitch): %v", err)
	}
	if resolved.Telnet.User != "explicit-telnet-user" {
		t.Errorf("Telnet.User = %q, want explicit-telnet-user (explicit config wins)", resolved.Telnet.User)
	}
	if !resolved.Telnet.NetrcAutologin {
		t.Error("Telnet.NetrcAutologin = false, want true even though User was already explicit")
	}
}

func TestSourcesCanBeDisabled(t *testing.T) {
	dir := t.TempDir()
	sshConfigPath := filepath.Join(dir, "ssh_config")
	writeTestFile(t, sshConfigPath, `
Host should-not-appear
  HostName 10.0.0.1
`)

	toml := `
[sources.ssh_config]
enabled = false
paths = ["` + sshConfigPath + `"]
`
	cfg, err := Parse([]byte(toml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, _, ok := cfg.FindHost("should-not-appear"); ok {
		t.Error("should-not-appear was imported despite sources.ssh_config.enabled = false")
	}
}

func TestDefaultSourcePathsUseHomeDir(t *testing.T) {
	home, err := userHomeDir()
	if err != nil {
		t.Fatalf("userHomeDir: %v", err)
	}
	writeTestFile(t, filepath.Join(home, ".ssh", "config"), `
Host default-path-host
  HostName 10.0.0.77
`)

	cfg, err := Parse([]byte(`[sources.netrc]
enabled = false
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, _, ok := cfg.FindHost("default-path-host"); !ok {
		t.Error("expected default ~/.ssh/config path to be sourced automatically")
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
