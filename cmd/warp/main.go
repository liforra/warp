// Command warp connects to configured hosts over ssh, mosh, or et,
// choosing binaries and options from a shared TOML config.
package main

import (
	"os"
	"strings"

	"github.com/liforra/warp/internal/client"
	"github.com/liforra/warp/internal/config"
	"github.com/liforra/warp/internal/detect"
	"github.com/spf13/cobra"
)

var (
	configPath    string
	protoOverride string
	scanFlag      bool
	scanSubnets   []string
	scanHost      string
	convertFlag   bool
	outputPath    string

	// version and commit are set via -ldflags at release build time
	// (see .goreleaser.yaml); "dev"/"unknown" are the go build/go run defaults.
	version = "dev"
	commit  = "unknown"
)

func main() {
	root := &cobra.Command{
		Use:   "warp [host-or-alias]",
		Short: "Connect to hosts over ssh, mosh, or et using a shared TOML config",
		// Bare `warp <host>` is shorthand for `warp connect <host>`. It only
		// takes effect when the argument doesn't match a subcommand name
		// below (list/detect/config/init/connect), since cobra routes
		// matching subcommands first.
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if convertFlag {
				return runConvert()
			}
			if scanFlag {
				if scanHost != "" {
					return runScanHost(scanHost)
				}
				return runScan()
			}
			if len(args) == 0 {
				return cmd.Help()
			}
			return runConnect(args[0])
		},
		// A failed connection is a runtime outcome, not a usage error --
		// don't dump a usage blob after it.
		SilenceUsage: true,
	}
	root.PersistentFlags().StringVar(&configPath, "config", "", "path to config.toml (default: ~/.config/warp/config.toml); with --convert, the ssh_config-style file to convert FROM instead (default: ~/.ssh/config)")
	root.Flags().StringVar(&protoOverride, "proto", "", "comma-separated protocol chain override for this invocation, e.g. ssh or mosh,ssh")
	root.Flags().BoolVar(&scanFlag, "scan", false, "scan for hosts speaking any supported protocol, instead of connecting")
	root.Flags().StringArrayVar(&scanSubnets, "subnet", nil, "CIDR subnet to scan (repeatable); overrides [scan].subnets and auto-detection when given")
	root.Flags().StringVar(&scanHost, "host", "", "with --scan, probe just this one host (name, IP, or domain) instead of a subnet")
	root.Flags().BoolVar(&convertFlag, "convert", false, "convert an ssh_config-style file into warp.toml [host] blocks, instead of connecting")
	root.Flags().StringVar(&outputPath, "output", "", "with --convert, destination path for the generated warp.toml (default: stdout)")

	connectCmd := &cobra.Command{
		Use:          "connect <host-or-alias>",
		Short:        "Connect to a configured host",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConnect(args[0])
		},
	}
	connectCmd.Flags().StringVar(&protoOverride, "proto", "", "comma-separated protocol chain override for this invocation, e.g. ssh or mosh,ssh")

	root.AddCommand(connectCmd, listCmd(), detectCmd(), configRootCmd(), initCmd(), versionCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadConfig() (*config.Config, error) {
	path := configPath
	if path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	return config.Load(path)
}

// binaryOverrides adapts the config's [binaries] table (string keys) to the
// detect.Binary-keyed map the resolver expects.
func binaryOverrides(cfg *config.Config) map[detect.Binary]string {
	out := make(map[detect.Binary]string, len(cfg.Binaries))
	for name, path := range cfg.Binaries {
		out[detect.Binary(name)] = path
	}
	return out
}

func runConnect(hostArg string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	resolved, err := cfg.Resolve(hostArg)
	if err != nil {
		return err
	}
	if protoOverride != "" {
		resolved.Protocols = strings.Split(protoOverride, ",")
	}

	resolver := detect.NewResolver(binaryOverrides(cfg))
	conn := client.NewConnector(resolver)

	code, err := conn.Connect(resolved)
	if err != nil {
		return err
	}

	os.Exit(code)
	return nil
}
