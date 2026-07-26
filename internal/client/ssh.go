package client

import (
	"fmt"

	"github.com/liforra/warp/internal/config"
)

// buildSSHArgv maps merged ssh options + a chosen address to an ssh argv.
// controlPath, if non-empty, is warp's own pre-established ControlMaster
// socket for this (user, addr, port) (see multiplexer) -- passing it here
// lets this ssh invocation transparently reuse a connection an earlier
// mosh/ssh attempt in the same Connect call already authenticated.
func buildSSHArgv(binPath, addr string, opts config.SSHOptions, controlPath string) []string {
	argv := []string{binPath}

	if opts.Port != 0 {
		argv = append(argv, "-p", fmt.Sprintf("%d", opts.Port))
	}
	if opts.IdentityFile != "" {
		argv = append(argv, "-i", opts.IdentityFile)
	}
	if opts.Compression != nil && *opts.Compression {
		argv = append(argv, "-C")
	}
	if opts.ProxyJump != "" {
		argv = append(argv, "-J", opts.ProxyJump)
	}
	if opts.ControlMaster != nil && *opts.ControlMaster {
		argv = append(argv, "-o", "ControlMaster=auto", "-o", "ControlPersist=10m")
	}
	if controlPath != "" {
		argv = append(argv, "-o", "ControlPath="+controlPath)
	}
	for _, fwd := range opts.PortForwarding {
		argv = append(argv, "-L", fwd)
	}
	argv = append(argv, opts.ExtraArgs...)
	argv = append(argv, target(opts.User, addr))

	return argv
}

func target(user, addr string) string {
	if user == "" {
		return addr
	}
	return user + "@" + addr
}
