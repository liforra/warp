package client

import "github.com/liforra/warp/internal/config"

// buildTailscaleArgv maps merged tailscale options + a chosen address to a
// `tailscale ssh` argv. Tailscale SSH authenticates via the tailnet
// identity, not a key or port, so there's little to map beyond the
// username and the escape hatch.
func buildTailscaleArgv(binPath, addr string, opts config.TailscaleOptions) []string {
	argv := []string{binPath, "ssh"}
	argv = append(argv, opts.ExtraArgs...)
	argv = append(argv, target(opts.User, addr))
	return argv
}
