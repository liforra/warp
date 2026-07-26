// Command warp connects to configured hosts over ssh, mosh, et, tailscale
// ssh, tsh, or telnet, choosing binaries and options from a shared TOML
// config. See internal/cli for the actual command tree and logic.
package main

import (
	"os"

	"github.com/liforra/warp/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
