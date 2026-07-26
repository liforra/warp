package client

import (
	"testing"

	"github.com/liforra/warp/internal/config"
)

func TestBuildTailscaleArgvWithSocket(t *testing.T) {
	opts := config.TailscaleOptions{Socket: "/var/run/tailscale/tailscaled.sock"}
	opts.User = "alice"

	got := buildTailscaleArgv("/usr/bin/tailscale", "myhost", opts)
	want := []string{"/usr/bin/tailscale", "--socket=/var/run/tailscale/tailscaled.sock", "ssh", "alice@myhost"}
	if !stringSlicesEqual(got, want) {
		t.Errorf("argv = %v, want %v", got, want)
	}
}

func TestBuildTailscaleArgvWithoutSocket(t *testing.T) {
	got := buildTailscaleArgv("/usr/bin/tailscale", "myhost", config.TailscaleOptions{})
	want := []string{"/usr/bin/tailscale", "ssh", "myhost"}
	if !stringSlicesEqual(got, want) {
		t.Errorf("argv = %v, want %v (no --socket when unset)", got, want)
	}
}

func stringSlicesEqual(a, b []string) bool {
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
