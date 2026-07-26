package client

import (
	"testing"

	"github.com/liforra/warp/internal/config"
)

func TestBuildTelnetArgvWithNetrcAutologin(t *testing.T) {
	opts := config.TelnetOptions{NetrcAutologin: true}
	opts.User = "admin"

	got := buildTelnetArgv("/usr/bin/telnet", "old-switch.example.com", opts)
	want := []string{"/usr/bin/telnet", "-l", "admin", "-a", "old-switch.example.com"}
	if !stringSlicesEqual(got, want) {
		t.Errorf("argv = %v, want %v", got, want)
	}
}

func TestBuildTelnetArgvNoUserNoAutologin(t *testing.T) {
	got := buildTelnetArgv("/usr/bin/telnet", "plainhost", config.TelnetOptions{})
	want := []string{"/usr/bin/telnet", "plainhost"}
	if !stringSlicesEqual(got, want) {
		t.Errorf("argv = %v, want %v (no -l/-a when neither applies)", got, want)
	}
}

func TestBuildTelnetArgvWithPort(t *testing.T) {
	opts := config.TelnetOptions{}
	opts.Port = 2323

	got := buildTelnetArgv("/usr/bin/telnet", "plainhost", opts)
	want := []string{"/usr/bin/telnet", "plainhost", "2323"}
	if !stringSlicesEqual(got, want) {
		t.Errorf("argv = %v, want %v", got, want)
	}
}
