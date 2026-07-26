package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/liforra/warp/internal/config"
	"github.com/liforra/warp/internal/detect"
	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the warp version and commit",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("warp %s (%s)\n", version, commit)
			return nil
		},
	}
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured hosts with their aliases, addresses, and protocol chain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}

			names := make([]string, 0, len(cfg.Hosts))
			for name := range cfg.Hosts {
				names = append(names, name)
			}
			sort.Strings(names)

			for _, name := range names {
				h := cfg.Hosts[name]
				// Resolve rather than reading h.Protocol/h.Addresses
				// directly, so a host that relies on DefaultProtocolOrder
				// (no `protocol` set at all) shows the chain it will
				// actually use instead of an empty list.
				resolved, err := cfg.Resolve(name)
				if err != nil {
					return fmt.Errorf("host %q: %w", name, err)
				}

				fmt.Println(name)
				if len(h.Aliases) > 0 {
					fmt.Printf("  aliases:    %s\n", strings.Join(h.Aliases, ", "))
				}
				fmt.Printf("  addresses:  %s\n", strings.Join(resolved.Addresses, ", "))
				fmt.Printf("  protocols:  %s\n", strings.Join(resolved.Protocols, ", "))
			}
			return nil
		},
	}
}

func detectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detect",
		Short: "Show resolved paths for each supported client binary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Detection is useful even without a config file yet (e.g.
			// before `warp init`), so a missing/unparsable config just
			// means no [binaries] overrides rather than a hard error.
			cfg, err := loadConfig()
			var overrides map[detect.Binary]string
			if err == nil {
				overrides = binaryOverrides(cfg)
			}

			resolver := detect.NewResolver(overrides)
			for _, res := range resolver.ResolveAll() {
				if res.Err != nil {
					fmt.Printf("%-9s not found: %v\n", res.Binary, res.Err)
					continue
				}
				fmt.Printf("%-9s %s\n", res.Binary, res.Path)
			}
			return nil
		},
	}
}

func configRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Config file utilities",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Parse and sanity-check the config without connecting",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			for name := range cfg.Hosts {
				if _, err := cfg.Resolve(name); err != nil {
					return fmt.Errorf("host %q: %w", name, err)
				}
			}
			fmt.Println("config OK")
			return nil
		},
	})
	return cmd
}

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Scaffold ~/.config/warp/config.toml with example content",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := configPath
			if path == "" {
				p, err := config.DefaultPath()
				if err != nil {
					return err
				}
				path = p
			}

			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("config already exists at %s", path)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return fmt.Errorf("creating config dir: %w", err)
			}
			if err := os.WriteFile(path, config.ExampleTOML, 0o644); err != nil {
				return fmt.Errorf("writing config: %w", err)
			}

			fmt.Printf("wrote example config to %s\n", path)
			return nil
		},
	}
}
