package scan

import (
	"net"
	"testing"
	"time"
)

// fakeConn is a minimal net.Conn stand-in so probe() can call Close() on it
// without touching a real socket.
type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

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

// fakeDial simulates ssh (port 22) open on 10.0.0.5 and et (port 2022) open
// on 10.0.0.6; everything else refuses.
func fakeDial(network, addr string, timeout time.Duration) (net.Conn, error) {
	switch addr {
	case "10.0.0.5:22", "10.0.0.9:22":
		return fakeConn{}, nil
	case "10.0.0.6:2022":
		return fakeConn{}, nil
	default:
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	}
}

type errRefused struct{}

func (errRefused) Error() string { return "connection refused" }

func TestRunProbesSubnetAndTailscalePeers(t *testing.T) {
	origDial := dial
	origStatus := tailscaleStatus
	dial = fakeDial
	tailscaleStatus = func() ([]byte, error) {
		return []byte(`{
			"Peer": {
				"node1": {"TailscaleIPs": ["10.0.0.9"], "Online": true},
				"node2": {"TailscaleIPs": ["10.0.0.99"], "Online": false}
			}
		}`), nil
	}
	defer func() {
		dial = origDial
		tailscaleStatus = origStatus
	}()

	results, err := Run(Options{Subnets: []string{"10.0.0.0/29"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	byIP := make(map[string]Result)
	for _, r := range results {
		byIP[r.IP.String()] = r
	}

	ssh, ok := byIP["10.0.0.5"]
	if !ok {
		t.Fatalf("expected a result for 10.0.0.5, got %+v", results)
	}
	if len(ssh.Protocols) != 1 || ssh.Protocols[0] != "ssh" {
		t.Errorf("10.0.0.5 protocols = %v, want [ssh]", ssh.Protocols)
	}

	et, ok := byIP["10.0.0.6"]
	if !ok || len(et.Protocols) != 1 || et.Protocols[0] != "et" {
		t.Errorf("10.0.0.6 result = %+v, want protocols [et]", et)
	}

	peer, ok := byIP["10.0.0.9"]
	if !ok {
		t.Fatalf("expected tailscale peer 10.0.0.9 in results, got %+v", results)
	}
	if !peer.Tailscale {
		t.Errorf("10.0.0.9 Tailscale = false, want true")
	}
	found := false
	for _, p := range peer.Protocols {
		if p == "ssh" {
			found = true
		}
	}
	if !found {
		t.Errorf("10.0.0.9 protocols = %v, want to include ssh", peer.Protocols)
	}

	if _, ok := byIP["10.0.0.99"]; ok {
		t.Error("offline peer 10.0.0.99 should not appear in results")
	}
	if _, ok := byIP["10.0.0.1"]; ok {
		t.Error("10.0.0.1 (nothing open) should not appear in results")
	}
}

func TestAutoDetectSubnetsDoesNotError(t *testing.T) {
	if _, err := AutoDetectSubnets(); err != nil {
		t.Fatalf("AutoDetectSubnets: %v", err)
	}
}
