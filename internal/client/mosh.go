package client

import (
	"fmt"
	"strings"

	"github.com/liforra/warp/internal/config"
)

// buildMoshArgv maps merged mosh options + a chosen address to a mosh argv.
// mosh bootstraps over ssh internally, so the identity file / bootstrap port
// are passed through its --ssh flag rather than as direct mosh flags.
// controlPath, if non-empty, is injected into that same --ssh flag so
// mosh's bootstrap can reuse warp's own pre-established ControlMaster
// connection instead of negotiating a fresh one (see multiplexer).
func buildMoshArgv(binPath, addr string, opts config.MoshOptions, controlPath string) []string {
	argv := []string{binPath}

	if opts.Predict != "" {
		argv = append(argv, "--predict="+opts.Predict)
	}
	if opts.UDPPortRange != "" {
		argv = append(argv, "-p", opts.UDPPortRange)
	}

	var sshOpts []string
	switch {
	case opts.SSHPort != 0:
		sshOpts = append(sshOpts, "-p", fmt.Sprintf("%d", opts.SSHPort))
	case opts.Port != 0:
		sshOpts = append(sshOpts, "-p", fmt.Sprintf("%d", opts.Port))
	}
	if opts.IdentityFile != "" {
		sshOpts = append(sshOpts, "-i", opts.IdentityFile)
	}
	if controlPath != "" {
		sshOpts = append(sshOpts, "-o", "ControlPath="+controlPath)
	}
	if len(sshOpts) > 0 {
		argv = append(argv, "--ssh=ssh "+strings.Join(sshOpts, " "))
	}

	argv = append(argv, opts.ExtraArgs...)
	argv = append(argv, target(opts.User, addr))

	return argv
}
