package client

import (
	"fmt"

	"github.com/liforra/warp/internal/config"
)

// buildETArgv maps merged et options + a chosen address to an et argv.
// et's own flag names vary across versions/forks; extra_args is the
// escape hatch for anything not modeled here.
func buildETArgv(binPath, addr string, opts config.ETOptions) []string {
	dest := target(opts.User, addr)
	if opts.Port != 0 {
		dest = fmt.Sprintf("%s:%d", dest, opts.Port)
	}

	argv := []string{binPath, dest}

	if opts.Jumphost != "" {
		argv = append(argv, "--jumphost="+opts.Jumphost)
	}
	if opts.SSHForwarding != nil && !*opts.SSHForwarding {
		argv = append(argv, "--forwardssh=false")
	}
	if opts.Keepalive != nil && *opts.Keepalive {
		argv = append(argv, "--keepalive")
	}
	argv = append(argv, opts.ExtraArgs...)

	return argv
}
