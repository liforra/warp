package main

import (
	"fmt"
	"strings"

	"github.com/liforra/warp/internal/scan"
)

// formatMatches renders a Result's confirmed (protocol, port) pairs as
// "ssh:22, et:2022", falling back to a caveat line for a Tailscale peer
// where nothing was confirmed (see scan.Result docs on why "tailscale"
// itself is never a confirmed match).
func formatMatches(r scan.Result) string {
	if len(r.Matches) == 0 {
		if r.Tailscale {
			return "(none confirmed; tailscale ssh may still work, unverified)"
		}
		return "(none)"
	}
	parts := make([]string, len(r.Matches))
	for i, m := range r.Matches {
		parts[i] = fmt.Sprintf("%s:%d", m.Protocol, m.Port)
	}
	return strings.Join(parts, ", ")
}

// formatHostname renders a Result's best-effort hostname, or "-" when none
// was found (e.g. no PTR record).
func formatHostname(r scan.Result) string {
	if r.Hostname == "" {
		return "-"
	}
	return r.Hostname
}

// runScanHost implements `warp --scan --host=<name/ip/domain>`: probes just
// that one host for every supported protocol/port, skipping subnet
// expansion and Tailscale peer discovery entirely.
func runScanHost(host string) error {
	fmt.Printf("scanning host %s\n", host)

	cfg, cfgErr := loadConfig()
	socket := ""
	if cfgErr == nil {
		socket = cfg.Tailscale.Socket
	}

	results, err := scan.ScanHost(host, socket)
	if err != nil {
		return err
	}

	for _, r := range results {
		fmt.Printf("%-15s  %-30s  %s\n", r.IP, formatHostname(r), formatMatches(r))
	}
	return nil
}

// runScan implements `warp --scan`. Subnet sources are tried in order --
// --subnet flags, then [scan].subnets in config, then auto-detection from
// local network interfaces -- the first non-empty one wins; they are not
// merged. Tailscale peers are always additionally probed regardless of
// which subnet source was used, since discovering them isn't subnet-based
// (see internal/scan).
func runScan() error {
	cfg, err := loadConfig()

	subnets := scanSubnets
	source := "--subnet"

	if len(subnets) == 0 && err == nil {
		subnets = cfg.Scan.Subnets
		source = "[scan].subnets"
	}

	if len(subnets) == 0 {
		auto, autoErr := scan.AutoDetectSubnets()
		if autoErr != nil {
			return fmt.Errorf("auto-detecting subnets: %w", autoErr)
		}
		subnets = auto
		source = "auto-detected"
	}

	if len(subnets) == 0 {
		return fmt.Errorf("no subnets to scan: pass --subnet, set [scan].subnets in config, or ensure a network interface has a routable address")
	}

	workers := 0
	socket := ""
	if err == nil {
		workers = cfg.Scan.Workers
		socket = cfg.Tailscale.Socket
	}

	fmt.Printf("scanning %d subnet(s) (%s): %s\n", len(subnets), source, strings.Join(subnets, ", "))

	results, scanErr := scan.Run(scan.Options{Subnets: subnets, Workers: workers, TailscaleSocket: socket})
	if scanErr != nil {
		return scanErr
	}

	if len(results) == 0 {
		fmt.Println("no hosts found")
		return nil
	}

	for _, r := range results {
		origin := ""
		if r.Tailscale && len(r.Matches) > 0 {
			origin = "  (tailscale peer)"
		}
		fmt.Printf("%-15s  %-30s  %s%s\n", r.IP, formatHostname(r), formatMatches(r), origin)
	}
	return nil
}
