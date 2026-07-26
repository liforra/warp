package scan

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// fakeConn is a minimal net.Conn stand-in so matchesFor can call Close() on
// it without touching a real socket.
type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

type errRefused struct{}

func (errRefused) Error() string { return "connection refused" }

func TestExpandCIDRDropsNetworkAndBroadcast(t *testing.T) {
	ips, err := expandCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("expandCIDR: %v", err)
	}
	want := []string{"192.168.1.1", "192.168.1.2"}
	if len(ips) != len(want) {
		t.Fatalf("got %d IPs, want %d: %v", len(ips), len(want), ips)
	}
	for i, ip := range ips {
		if ip.String() != want[i] {
			t.Errorf("ips[%d] = %s, want %s", i, ip, want[i])
		}
	}
}

func TestExpandCIDRRejectsTooLarge(t *testing.T) {
	if _, err := expandCIDR("10.0.0.0/8"); err == nil {
		t.Fatal("expected error for /8 subnet, got nil")
	}
}

func TestExpandCIDRRejectsIPv6(t *testing.T) {
	if _, err := expandCIDR("2001:db8::/120"); err == nil {
		t.Fatal("expected error for IPv6 subnet, got nil")
	}
}

// fakeDial simulates: ssh(22) open on 10.0.0.5; et(2022) open on 10.0.0.6;
// ssh(2222), an alternate port, open on 10.0.0.7 (nothing on 22); ssh(22)
// open on the tailscale peer 10.0.0.9; nothing open anywhere else.
func fakeDial(network, addr string, timeout time.Duration) (net.Conn, error) {
	switch addr {
	case "10.0.0.5:22", "10.0.0.6:2022", "10.0.0.7:2222", "10.0.0.9:22":
		return fakeConn{}, nil
	default:
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	}
}

func hasMatch(matches []Match, protocol string, port int) bool {
	for _, m := range matches {
		if m.Protocol == protocol && m.Port == port {
			return true
		}
	}
	return false
}

// stubReverseLookup makes reverseLookup deterministic and network-free for
// tests: known IPs return a fixed name, everything else returns "" (as a
// real PTR-less LAN device would).
func stubReverseLookup(t *testing.T, known map[string]string) {
	t.Helper()
	orig := reverseLookup
	reverseLookup = func(ip net.IP) string { return known[ip.String()] }
	t.Cleanup(func() { reverseLookup = orig })
}

// stubTailscaleUnavailable simulates "tailscale isn't installed/logged in"
// so tests that don't care about Tailscale integration aren't affected by
// (or dependent on) a real local tailscale installation.
func stubTailscaleUnavailable(t *testing.T) {
	t.Helper()
	orig := tailscaleStatus
	tailscaleStatus = func() ([]byte, error) { return nil, fmt.Errorf("tailscale not available in test") }
	t.Cleanup(func() { tailscaleStatus = orig })
}

func TestRunProbesSubnetAndTailscalePeers(t *testing.T) {
	origDial := dial
	origStatus := tailscaleStatus
	dial = fakeDial
	tailscaleStatus = func() ([]byte, error) {
		return []byte(`{
			"Peer": {
				"node1": {"TailscaleIPs": ["10.0.0.9"], "Online": true, "DNSName": "peer9.tailnet-abc.ts.net."},
				"node2": {"TailscaleIPs": ["10.0.0.99"], "Online": false},
				"node3": {"TailscaleIPs": ["10.0.0.50"], "Online": true, "HostName": "peer50"}
			}
		}`), nil
	}
	stubReverseLookup(t, map[string]string{"10.0.0.5": "host5.lan"})
	defer func() {
		dial = origDial
		tailscaleStatus = origStatus
	}()

	results, err := Run(Options{Subnets: []string{"10.0.0.0/28"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	byIP := make(map[string]Result)
	for _, r := range results {
		byIP[r.IP.String()] = r
	}

	ssh, ok := byIP["10.0.0.5"]
	if !ok || len(ssh.Matches) != 1 || !hasMatch(ssh.Matches, "ssh", 22) {
		t.Errorf("10.0.0.5 matches = %+v, want [{ssh 22}]", ssh.Matches)
	}
	if ssh.Hostname != "host5.lan" {
		t.Errorf("10.0.0.5 Hostname = %q, want %q (via reverse DNS)", ssh.Hostname, "host5.lan")
	}

	et, ok := byIP["10.0.0.6"]
	if !ok || len(et.Matches) != 1 || !hasMatch(et.Matches, "et", 2022) {
		t.Errorf("10.0.0.6 matches = %+v, want [{et 2022}]", et.Matches)
	}

	altSSH, ok := byIP["10.0.0.7"]
	if !ok || len(altSSH.Matches) != 1 || !hasMatch(altSSH.Matches, "ssh", 2222) {
		t.Errorf("10.0.0.7 matches = %+v, want [{ssh 2222}] (alt ssh port)", altSSH.Matches)
	}

	peer, ok := byIP["10.0.0.9"]
	if !ok {
		t.Fatalf("expected tailscale peer 10.0.0.9 in results, got %+v", results)
	}
	if !peer.Tailscale {
		t.Errorf("10.0.0.9 Tailscale = false, want true")
	}
	if !hasMatch(peer.Matches, "ssh", 22) {
		t.Errorf("10.0.0.9 matches = %+v, want to include {ssh 22}", peer.Matches)
	}
	if peer.Hostname != "peer9.tailnet-abc.ts.net" {
		t.Errorf("10.0.0.9 Hostname = %q, want %q (DNSName, trailing dot trimmed)", peer.Hostname, "peer9.tailnet-abc.ts.net")
	}

	quietPeer, ok := byIP["10.0.0.50"]
	if !ok {
		t.Fatalf("expected tailscale peer 10.0.0.50 in results even with nothing open, got %+v", results)
	}
	if !quietPeer.Tailscale || len(quietPeer.Matches) != 0 {
		t.Errorf("10.0.0.50 = %+v, want Tailscale=true, Matches=empty", quietPeer)
	}
	if quietPeer.Hostname != "peer50" {
		t.Errorf("10.0.0.50 Hostname = %q, want %q (HostName fallback, no DNSName)", quietPeer.Hostname, "peer50")
	}

	if _, ok := byIP["10.0.0.99"]; ok {
		t.Error("offline peer 10.0.0.99 should not appear in results")
	}
	if _, ok := byIP["10.0.0.1"]; ok {
		t.Error("10.0.0.1 (plain subnet IP, nothing open) should not appear in results")
	}
}

func TestAutoDetectSubnetsDoesNotError(t *testing.T) {
	if _, err := AutoDetectSubnets(); err != nil {
		t.Fatalf("AutoDetectSubnets: %v", err)
	}
}

func TestScanHostReportsPortsForIPLiteral(t *testing.T) {
	origDial := dial
	dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if addr == "203.0.113.5:22" {
			return fakeConn{}, nil
		}
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	}
	stubReverseLookup(t, map[string]string{"203.0.113.5": "reverse.example.com"})
	stubTailscaleUnavailable(t)
	defer func() { dial = origDial }()

	results, err := ScanHost("203.0.113.5")
	if err != nil {
		t.Fatalf("ScanHost: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}
	if !hasMatch(results[0].Matches, "ssh", 22) {
		t.Errorf("matches = %+v, want to include {ssh 22}", results[0].Matches)
	}
	if results[0].Hostname != "reverse.example.com" {
		t.Errorf("Hostname = %q, want %q (IP literal input, so reverse DNS)", results[0].Hostname, "reverse.example.com")
	}
}

func TestScanHostUsesQueriedNameNotReverseDNS(t *testing.T) {
	origDial := dial
	origLookup := lookupHost
	dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if addr == "203.0.113.7:22" {
			return fakeConn{}, nil
		}
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	}
	lookupHost = func(host string) ([]string, error) {
		if host != "myhost.example.com" {
			t.Fatalf("lookupHost called with %q, want myhost.example.com", host)
		}
		return []string{"203.0.113.7"}, nil
	}
	// If either of these gets consulted, the queried DNS name wasn't
	// preferred over it as it should be.
	stubReverseLookup(t, map[string]string{"203.0.113.7": "should-not-be-used"})
	stubTailscaleUnavailable(t)
	defer func() {
		dial = origDial
		lookupHost = origLookup
	}()

	results, err := ScanHost("myhost.example.com")
	if err != nil {
		t.Fatalf("ScanHost: %v", err)
	}
	if len(results) != 1 || results[0].Hostname != "myhost.example.com" {
		t.Fatalf("results = %+v, want one result with Hostname %q", results, "myhost.example.com")
	}
}

func TestScanHostPrefersTailscaleHostnameOverReverseDNS(t *testing.T) {
	origDial := dial
	origStatus := tailscaleStatus
	dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if addr == "100.64.0.5:22" {
			return fakeConn{}, nil
		}
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	}
	tailscaleStatus = func() ([]byte, error) {
		return []byte(`{
			"Peer": {
				"node1": {"TailscaleIPs": ["100.64.0.5"], "Online": true, "DNSName": "mybox.tailnet-abc.ts.net."}
			}
		}`), nil
	}
	// If this gets called, the Tailscale hostname wasn't preferred over it
	// -- CGNAT addresses like 100.64.0.5 have no real public PTR record, so
	// falling through to reverse DNS would normally yield nothing anyway.
	stubReverseLookup(t, map[string]string{"100.64.0.5": "should-not-be-used"})
	defer func() {
		dial = origDial
		tailscaleStatus = origStatus
	}()

	results, err := ScanHost("100.64.0.5")
	if err != nil {
		t.Fatalf("ScanHost: %v", err)
	}
	if len(results) != 1 || results[0].Hostname != "mybox.tailnet-abc.ts.net" {
		t.Fatalf("results = %+v, want one result with Hostname %q", results, "mybox.tailnet-abc.ts.net")
	}
}

func TestScanHostReportsEmptyMatchesRatherThanDropping(t *testing.T) {
	origDial := dial
	dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	}
	stubReverseLookup(t, nil)
	stubTailscaleUnavailable(t)
	defer func() { dial = origDial }()

	results, err := ScanHost("203.0.113.9")
	if err != nil {
		t.Fatalf("ScanHost: %v", err)
	}
	if len(results) != 1 || len(results[0].Matches) != 0 {
		t.Fatalf("results = %+v, want one result with empty Matches", results)
	}
}

func TestScanHostRejectsIPv6(t *testing.T) {
	if _, err := ScanHost("2001:db8::1"); err == nil {
		t.Fatal("expected error for IPv6 literal, got nil")
	}
}
