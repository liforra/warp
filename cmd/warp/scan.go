package main

import (
	"fmt"
	"strings"

	"github.com/liforra/warp/internal/scan"
)

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
	if err == nil {
		workers = cfg.Scan.Workers
	}

	fmt.Printf("scanning %d subnet(s) (%s): %s\n", len(subnets), source, strings.Join(subnets, ", "))

	results, scanErr := scan.Run(scan.Options{Subnets: subnets, Workers: workers})
	if scanErr != nil {
		return scanErr
	}

	if len(results) == 0 {
		fmt.Println("no hosts found")
		return nil
	}

	for _, r := range results {
		origin := ""
		if r.Tailscale {
			origin = "  (tailscale peer)"
		}
		fmt.Printf("%-15s  %s%s\n", r.IP, strings.Join(r.Protocols, ", "), origin)
	}
	return nil
}
