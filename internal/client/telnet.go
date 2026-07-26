package client

import (
	"fmt"

	"github.com/liforra/warp/internal/config"
)

// buildTelnetArgv maps merged telnet options + a chosen address to a telnet
// argv. -l sets the login name most telnet implementations understand;
// -a triggers the client's own .netrc-based autologin (which reads the
// file itself at connection time) when applySources found a matching
// machine entry -- warp never reads or passes a password itself.
func buildTelnetArgv(binPath, addr string, opts config.TelnetOptions) []string {
	argv := []string{binPath}

	if opts.User != "" {
		argv = append(argv, "-l", opts.User)
	}
	if opts.NetrcAutologin {
		argv = append(argv, "-a")
	}
	argv = append(argv, opts.ExtraArgs...)

	if opts.Port != 0 {
		argv = append(argv, addr, fmt.Sprintf("%d", opts.Port))
	} else {
		argv = append(argv, addr)
	}

	return argv
}
