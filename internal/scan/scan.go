// Package scan implements `warp --scan`: concurrently probing a set of IPv4
// subnets (auto-detected, config-supplied, or given via --subnet) for hosts
// speaking any of warp's scannable protocols, plus discovering Tailscale
// peers directly through the local tailscale client rather than by probing
// a subnet (Tailscale doesn't expose a walkable CIDR the way a LAN does).
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// tcpProbes lists the (protocol, port) pairs actually dialed. A protocol
// only ever appears in a Result if one of these answered. ssh is checked on
// its default port plus 5 commonly-used alternative ports (hardening guides
// often suggest moving sshd off 22 to cut down on automated scan noise).
// mosh isn't probed separately: it bootstraps over the same ssh port, and
// there's no static port to test for the mosh-server side without actually
// authenticating, so an open ssh port is the closest available signal for
// both. tsh (Teleport) is fronted by a central proxy rather than a per-host
// port, so it isn't scannable this way either. tailscale isn't here either,
// but for a different reason: it's not that there's no port, it's that
// there's no way to tell "sshd is open" apart from "Tailscale SSH is open"
// via a bare TCP probe, and Tailscale SSH being enabled is a policy setting
// we can't observe from outside. See the Result doc comment.
var tcpProbes = []struct {
	Protocol string
	Port     int
}{
	{"ssh", 22},
	{"ssh", 2222},
	{"ssh", 22222},
	{"ssh", 2200},
	{"ssh", 22022},
	{"ssh", 222},
	{"et", 2022},
	{"telnet", 23},
}

const (
	defaultWorkers = 256
	dialTimeout    = 800 * time.Millisecond
	// reverseDNSTimeout bounds a best-effort PTR lookup for a plain subnet
	// IP. Most home/LAN devices have no PTR record at all, and the system
	// resolver's handling of that (immediate NXDOMAIN vs. waiting out a
	// retry) varies, so this is capped rather than left to hang the scan.
	reverseDNSTimeout = 1 * time.Second
	// maxHostBits caps how large a single CIDR we'll expand and probe (16
	// host bits = a /16, 65536 addresses), so a mistyped or unexpectedly
	// huge subnet (e.g. a corporate /8) doesn't turn into an hours-long scan.
	maxHostBits = 16
)

// dial is overridden in tests to avoid touching the network.
var dial = net.DialTimeout

// tailscaleStatus is overridden in tests to avoid depending on a real
// tailscale installation. socket is passed as --socket when non-empty, for
// machines where tailscaled listens on a non-default control socket.
var tailscaleStatus = func(socket string) ([]byte, error) {
	path, err := exec.LookPath("tailscale")
	if err != nil {
		return nil, err
	}
	args := []string{}
	if socket != "" {
		args = append(args, "--socket="+socket)
	}
	args = append(args, "status", "--json")
	return exec.Command(path, args...).Output()
}

// lookupHost is overridden in tests to avoid depending on real DNS.
var lookupHost = net.LookupHost

// reverseLookup is overridden in tests. It's best-effort: most LAN devices
// have no PTR record, so a failure just means an empty hostname, not an
// error -- callers should never treat this as fatal.
var reverseLookup = func(ip net.IP) string {
	ctx, cancel := context.WithTimeout(context.Background(), reverseDNSTimeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// Match is one (protocol, port) pair confirmed open on a host.
type Match struct {
	Protocol string
	Port     int
}

// Result is one IP worth reporting: either a probed protocol answered, or
// it's a Tailscale peer (reported regardless, since it's a real, known host
// even if nothing else confirmed it).
//
// Matches only ever contains protocol/port pairs actually confirmed by a TCP
// probe (ssh/et/telnet) -- it does NOT include "tailscale". There's no
// reliable way to verify Tailscale SSH is enabled on a peer from the
// outside: it's a per-node ACL/policy setting, not a distinct open port, so
// a peer with plain sshd running (common) would be indistinguishable from
// one with Tailscale SSH enabled if we just claimed "tailscale" as a match
// here. Tailscale is reported as an origin (Result.Tailscale), not a
// verified capability; whether `tailscale ssh` itself works on a given peer
// is unverified.
//
// Hostname is filled in best-effort: for a Tailscale peer, from its tailnet
// DNS/host name (already known via `tailscale status`, no extra lookup
// needed); otherwise via a reverse DNS (PTR) lookup, which many LAN/home
// devices simply don't have, in which case it's left empty.
type Result struct {
	IP        net.IP
	Hostname  string // best-effort; empty if none was found
	Matches   []Match
	Tailscale bool // true if this IP came from the tailnet peer list
}

// Options configures a scan run.
type Options struct {
	// Subnets are IPv4 CIDRs to expand and probe, e.g. "192.168.1.0/24".
	Subnets []string
	// Workers caps scan concurrency; <= 0 uses a sane default.
	Workers int
	// TailscaleSocket is passed to `tailscale status --json` as --socket
	// when non-empty, for machines where tailscaled isn't on the default
	// control socket.
	TailscaleSocket string
}

type candidate struct {
	ip        net.IP
	tailscale bool
	hostname  string // known display name (e.g. from tailscale status); may be empty
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
			addCandidate(candidates, ip, false, "")
		}
	}

	if peers, err := tailscalePeers(opts.TailscaleSocket); err == nil {
		for _, p := range peers {
			addCandidate(candidates, p.IP, true, p.Hostname)
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
				matches := matchesFor(c.ip)
				// A Tailscale peer is worth reporting even with nothing
				// confirmed -- it's a real, known host, and `tailscale ssh`
				// may still work even though we can't verify that from here
				// (see Result docs). A plain-subnet candidate with nothing
				// open, though, is just noise.
				if len(matches) == 0 && !c.tailscale {
					continue
				}
				hostname := c.hostname
				if hostname == "" {
					hostname = reverseLookup(c.ip)
				}
				results <- Result{IP: c.ip, Hostname: hostname, Matches: matches, Tailscale: c.tailscale}
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

func addCandidate(m map[string]*candidate, ip net.IP, tailscale bool, hostname string) {
	key := ip.String()
	if existing, ok := m[key]; ok {
		if tailscale {
			existing.tailscale = true
		}
		if hostname != "" {
			existing.hostname = hostname
		}
		return
	}
	m[key] = &candidate{ip: ip, tailscale: tailscale, hostname: hostname}
}

// matchesFor dials every (protocol, port) pair in tcpProbes against ip and
// returns the ones that answered.
func matchesFor(ip net.IP) []Match {
	var matches []Match
	for _, p := range tcpProbes {
		addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", p.Port))
		conn, err := dial("tcp", addr, dialTimeout)
		if err != nil {
			continue
		}
		conn.Close()
		matches = append(matches, Match{Protocol: p.Protocol, Port: p.Port})
	}
	return matches
}

// ScanHost probes a single host (IP literal or DNS name) for every
// (protocol, port) pair in tcpProbes, without subnet expansion or size
// limits -- just "what does this one host answer on." A DNS name resolving
// to multiple IPv4 addresses is probed and reported once per address.
// Unlike Run, a host with nothing open is still returned (with an empty
// Matches) rather than dropped, since an explicit, single-host scan asked
// about exactly this host.
func ScanHost(hostOrIP string, tailscaleSocket string) ([]Result, error) {
	ips, queriedName, err := resolveHost(hostOrIP)
	if err != nil {
		return nil, err
	}

	// Best-effort: if the target happens to be a Tailscale peer, its
	// tailnet hostname is usually more useful than a CGNAT address's
	// (nonexistent) public PTR record. A lookup failure (tailscale not
	// installed/logged in) just means an empty map, not an error here.
	tsHostnames := tailscaleHostnameByIP(tailscaleSocket)

	out := make([]Result, 0, len(ips))
	for _, ip := range ips {
		// Preference order: the DNS name the user actually typed (best --
		// and skips a redundant PTR query) > a matching Tailscale peer's
		// known hostname > a bare reverse DNS (PTR) lookup as a last resort.
		hostname := queriedName
		if hostname == "" {
			hostname = tsHostnames[ip.String()]
		}
		if hostname == "" {
			hostname = reverseLookup(ip)
		}
		out = append(out, Result{IP: ip, Hostname: hostname, Matches: matchesFor(ip)})
	}
	return out, nil
}

// tailscaleHostnameByIP returns a best-effort {IP: hostname} map built from
// the local tailscale client's peer list. A failure (not installed, not
// logged in) just yields an empty map, not an error.
func tailscaleHostnameByIP(socket string) map[string]string {
	peers, err := tailscalePeers(socket)
	if err != nil {
		return nil
	}
	m := make(map[string]string, len(peers))
	for _, p := range peers {
		if p.Hostname != "" {
			m[p.IP.String()] = p.Hostname
		}
	}
	return m
}

// resolveHost returns the IPv4 addresses for hostOrIP, plus the DNS name
// that was queried (empty if hostOrIP was already an IP literal).
func resolveHost(hostOrIP string) (ips []net.IP, queriedName string, err error) {
	if ip := net.ParseIP(hostOrIP); ip != nil {
		if ip.To4() == nil {
			return nil, "", fmt.Errorf("only IPv4 addresses are supported")
		}
		return []net.IP{ip}, "", nil
	}

	addrs, err := lookupHost(hostOrIP)
	if err != nil {
		return nil, "", fmt.Errorf("resolving %q: %w", hostOrIP, err)
	}

	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, "", fmt.Errorf("%q did not resolve to any IPv4 address", hostOrIP)
	}
	return ips, hostOrIP, nil
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
		HostName     string   `json:"HostName"`
		DNSName      string   `json:"DNSName"`
	} `json:"Peer"`
}

// tailscalePeer is one online peer discovered via `tailscale status`.
type tailscalePeer struct {
	IP       net.IP
	Hostname string
}

// tailscalePeers asks the local tailscale client for the tailnet's online
// peers, including whatever hostname it already knows for each (so we don't
// need a separate reverse DNS lookup for these). Returning an error just
// means tailscale isn't installed, isn't logged in, or isn't running --
// callers should treat that as "no peers to add," not a scan failure.
func tailscalePeers(socket string) ([]tailscalePeer, error) {
	out, err := tailscaleStatus(socket)
	if err != nil {
		return nil, err
	}

	var status tailscaleStatusJSON
	if err := json.Unmarshal(out, &status); err != nil {
		return nil, err
	}

	var peers []tailscalePeer
	for _, peer := range status.Peer {
		if !peer.Online {
			continue
		}
		// DNSName is the fully-qualified tailnet name (e.g.
		// "host.tailXXXX.ts.net."); HostName is just the OS hostname.
		// Prefer the former, trimmed of its trailing dot, when present.
		name := strings.TrimSuffix(peer.DNSName, ".")
		if name == "" {
			name = peer.HostName
		}
		for _, s := range peer.TailscaleIPs {
			if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
				peers = append(peers, tailscalePeer{IP: ip, Hostname: name})
			}
		}
	}
	return peers, nil
}
