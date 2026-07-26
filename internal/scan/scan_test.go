package scan

import (
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

func TestRunProbesSubnetAndTailscalePeers(t *testing.T) {
	origDial := dial
	origStatus := tailscaleStatus
	dial = fakeDial
	tailscaleStatus = func() ([]byte, error) {
		return []byte(`{
			"Peer": {
				"node1": {"TailscaleIPs": ["10.0.0.9"], "Online": true},
				"node2": {"TailscaleIPs": ["10.0.0.99"], "Online": false},
				"node3": {"TailscaleIPs": ["10.0.0.50"], "Online": true}
			}
		}`), nil
	}
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

	quietPeer, ok := byIP["10.0.0.50"]
	if !ok {
		t.Fatalf("expected tailscale peer 10.0.0.50 in results even with nothing open, got %+v", results)
	}
	if !quietPeer.Tailscale || len(quietPeer.Matches) != 0 {
		t.Errorf("10.0.0.50 = %+v, want Tailscale=true, Matches=empty", quietPeer)
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
}

func TestScanHostReportsEmptyMatchesRatherThanDropping(t *testing.T) {
	origDial := dial
	dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	}
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
