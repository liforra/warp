package client

import (
	"fmt"

	"github.com/liforra/warp/internal/config"
)

// buildTelnetArgv maps merged telnet options + a chosen address to a telnet
// argv. telnet has no login step of its own at the connection level (auth
// happens inside the session, if at all), so User isn't applied here.
func buildTelnetArgv(binPath, addr string, opts config.TelnetOptions) []string {
	argv := []string{binPath}
	argv = append(argv, opts.ExtraArgs...)

	if opts.Port != 0 {
		argv = append(argv, addr, fmt.Sprintf("%d", opts.Port))
	} else {
		argv = append(argv, addr)
	}

	return argv
}
