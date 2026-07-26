// Package scan implements `warp --scan`: concurrently probing a set of IPv4
// subnets (auto-detected, config-supplied, or given via --subnet) for hosts
// speaking any of warp's scannable protocols, plus discovering Tailscale
// peers directly through the local tailscale client rather than by probing
// a subnet (Tailscale doesn't expose a walkable CIDR the way a LAN does).
package scan

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"sync"
	"time"
)

// tcpProbes lists the protocols that have a fixed, meaningfully scannable
// TCP port. mosh isn't probed separately: it bootstraps over the same ssh
// port, and there's no static port to test for the mosh-server side without
// actually authenticating, so an open ssh port is the closest available
// signal for both. tsh (Teleport) is fronted by a central proxy rather than
// a per-host port, so it isn't scannable this way either -- neither shows
// up in Result.Protocols on its own; only tailscale peers (found via
// tailscale status, not a port probe) are reported outside of this list.
var tcpProbes = []struct {
	Protocol string
	Port     int
}{
	{"ssh", 22},
	{"et", 2022},
	{"telnet", 23},
}

const (
	defaultWorkers = 256
	dialTimeout    = 800 * time.Millisecond
	// maxHostBits caps how large a single CIDR we'll expand and probe (16
	// host bits = a /16, 65536 addresses), so a mistyped or unexpectedly
	// huge subnet (e.g. a corporate /8) doesn't turn into an hours-long scan.
	maxHostBits = 16
)

// dial is overridden in tests to avoid touching the network.
var dial = net.DialTimeout

// tailscaleStatus is overridden in tests to avoid depending on a real
// tailscale installation.
var tailscaleStatus = func() ([]byte, error) {
	path, err := exec.LookPath("tailscale")
	if err != nil {
		return nil, err
	}
	return exec.Command(path, "status", "--json").Output()
}

// Result is one IP where at least one protocol answered.
type Result struct {
	IP        net.IP
	Protocols []string // e.g. {"ssh", "et"}; may include "tailscale"
	Tailscale bool     // true if this IP came from the tailnet peer list
}

// Options configures a scan run.
type Options struct {
	// Subnets are IPv4 CIDRs to expand and probe, e.g. "192.168.1.0/24".
	Subnets []string
	// Workers caps scan concurrency; <= 0 uses a sane default.
	Workers int
}

type candidate struct {
	ip        net.IP
	tailscale bool
}

// Run expands Options.Subnets into individual host IPs, adds any online
// Tailscale peers (regardless of Subnets), probes every candidate
// concurrently for each protocol in tcpProbes, and returns only the IPs
// that answered, sorted.
func Run(opts Options) ([]Result, error) {
	workers := opts.Workers
	if workers <= 0 {
		workers = defaultWorkers
	}

	candidates := make(map[string]*candidate)

	for _, cidr := range opts.Subnets {
		ips, err := expandCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("subnet %q: %w", cidr, err)
		}
		for _, ip := range ips {
			addCandidate(candidates, ip, false)
		}
	}

	if peers, err := tailscalePeers(); err == nil {
		for _, ip := range peers {
			addCandidate(candidates, ip, true)
		}
	}
	// A failure here (tailscale not installed, not logged in, not running)
	// is expected and not fatal -- scanning should work fine without it.

	jobs := make(chan *candidate)
	results := make(chan Result, len(candidates))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				if r := probe(c); r != nil {
					results <- *r
				}
			}
		}()
	}

	go func() {
		for _, c := range candidates {
			jobs <- c
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]Result, 0, len(candidates))
	for r := range results {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].IP.String() < out[j].IP.String()
	})

	return out, nil
}

func addCandidate(m map[string]*candidate, ip net.IP, tailscale bool) {
	key := ip.String()
	if existing, ok := m[key]; ok {
		if tailscale {
			existing.tailscale = true
		}
		return
	}
	m[key] = &candidate{ip: ip, tailscale: tailscale}
}

func probe(c *candidate) *Result {
	var protocols []string
	for _, p := range tcpProbes {
		addr := net.JoinHostPort(c.ip.String(), fmt.Sprintf("%d", p.Port))
		conn, err := dial("tcp", addr, dialTimeout)
		if err != nil {
			continue
		}
		conn.Close()
		protocols = append(protocols, p.Protocol)
	}
	if c.tailscale {
		protocols = append(protocols, "tailscale")
	}

	if len(protocols) == 0 {
		return nil
	}
	return &Result{IP: c.ip, Protocols: protocols, Tailscale: c.tailscale}
}

// expandCIDR returns every usable host address in cidr (network and
// broadcast addresses excluded for subnets larger than /31).
func expandCIDR(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("only IPv4 subnets are supported")
	}

	ones, bits := ipnet.Mask.Size()
	if bits-ones > maxHostBits {
		return nil, fmt.Errorf("too large to scan (max /16 / 65536 addresses); narrow it down")
	}

	var ips []net.IP
	for cur := cloneIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(cur); incIP(cur) {
		ips = append(ips, cloneIP(cur))
	}
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1] // drop network/broadcast addresses
	}

	return ips, nil
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

// AutoDetectSubnets derives CIDR subnets from this machine's non-loopback,
// up, IPv4 network interfaces. A /32 address (typical of a Tailscale
// interface, which routes its whole tailnet rather than exposing a walkable
// subnet) is skipped here; use tailscalePeers for that instead. Subnets
// larger than maxHostBits are skipped too, since they're unlikely to
// be a real scannable LAN (e.g. a misconfigured default route).
func AutoDetectSubnets() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing network interfaces: %w", err)
	}

	seen := make(map[string]bool)
	var subnets []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			ones, bits := ipnet.Mask.Size()
			if ones == 32 || bits-ones > maxHostBits {
				continue
			}
			cidr := fmt.Sprintf("%s/%d", ipnet.IP.Mask(ipnet.Mask), ones)
			if !seen[cidr] {
				seen[cidr] = true
				subnets = append(subnets, cidr)
			}
		}
	}
	return subnets, nil
}

// tailscaleStatusJSON is the subset of `tailscale status --json` warp reads.
type tailscaleStatusJSON struct {
	Peer map[string]struct {
		TailscaleIPs []string `json:"TailscaleIPs"`
		Online       bool     `json:"Online"`
	} `json:"Peer"`
}

// tailscalePeers asks the local tailscale client for the tailnet's online
// peers. Returning an error just means tailscale isn't installed, isn't
// logged in, or isn't running -- callers should treat that as "no peers
// to add," not a scan failure.
func tailscalePeers() ([]net.IP, error) {
	out, err := tailscaleStatus()
	if err != nil {
		return nil, err
	}

	var status tailscaleStatusJSON
	if err := json.Unmarshal(out, &status); err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, peer := range status.Peer {
		if !peer.Online {
			continue
		}
		for _, s := range peer.TailscaleIPs {
			if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}
