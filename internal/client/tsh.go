package client

import "github.com/liforra/warp/internal/config"

// buildTshArgv maps merged Teleport options + a chosen address to a
// `tsh ssh` argv.
func buildTshArgv(binPath, addr string, opts config.TshOptions) []string {
	argv := []string{binPath, "ssh"}

	if opts.Proxy != "" {
		argv = append(argv, "--proxy="+opts.Proxy)
	}
	if opts.Cluster != "" {
		argv = append(argv, "--cluster="+opts.Cluster)
	}
	argv = append(argv, opts.ExtraArgs...)
	argv = append(argv, target(opts.User, addr))

	return argv
}
