// Package config loads and resolves warp's TOML configuration: binary path
// overrides, global defaults, and per-host / per-host-per-protocol option
// layering (including address and protocol fallback chains).
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// toStringSlice normalizes a decoded TOML value that may be either a bare
// string or an array of strings into a []string. Used for `protocol` and
// `addresses`, where a single value means "no fallback" and multiple means
// "try in order". go-toml/v2's plain Unmarshal decodes untyped fields into
// string or []any, so this is done as a post-processing pass rather than via
// a custom unmarshaler (which requires its unstable raw-bytes API).
func toStringSlice(v any, field string) ([]string, error) {
	switch val := v.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{val}, nil
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s: expected string element, got %T", field, item)
			}
			out = append(out, str)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s: expected string or array of strings, got %T", field, v)
	}
}

// Options holds the fields shared across all three protocols: [defaults],
// a host's generic overrides, and each host.<protocol> table's overrides of
// those same shared fields.
type Options struct {
	User         string `toml:"user"`
	IdentityFile string `toml:"identity_file"`
	Port         int    `toml:"port"`
	Compression  *bool  `toml:"compression"`
}

// mergeOptions layers override on top of base: any field override sets
// (non-empty string, non-zero port, non-nil pointer) replaces base's value.
func mergeOptions(base, override Options) Options {
	if override.User != "" {
		base.User = override.User
	}
	if override.IdentityFile != "" {
		base.IdentityFile = override.IdentityFile
	}
	if override.Port != 0 {
		base.Port = override.Port
	}
	if override.Compression != nil {
		base.Compression = override.Compression
	}
	return base
}

// SSHOptions is ssh-specific config, layered under host.<name>.ssh.
type SSHOptions struct {
	Options
	PortForwarding []string `toml:"port_forwarding"`
	ProxyJump      string   `toml:"proxy_jump"`
	ControlMaster  *bool    `toml:"control_master"`
	ExtraArgs      []string `toml:"extra_args"`
}

// MoshOptions is mosh-specific config, layered under host.<name>.mosh.
type MoshOptions struct {
	Options
	Predict      string   `toml:"predict"`
	UDPPortRange string   `toml:"udp_port_range"`
	SSHPort      int      `toml:"ssh_port"`
	ExtraArgs    []string `toml:"extra_args"`
}

// ETOptions is et-specific config, layered under host.<name>.et.
type ETOptions struct {
	Options
	Jumphost      string   `toml:"jumphost"`
	SSHForwarding *bool    `toml:"ssh_forwarding"`
	Keepalive     *bool    `toml:"keepalive"`
	ExtraArgs     []string `toml:"extra_args"`
}

// HostConfig is one [host.X] table.
type HostConfig struct {
	RawAddresses any      `toml:"addresses"`
	Aliases      []string `toml:"aliases"`
	RawProtocol  any      `toml:"protocol"`
	Options

	SSH  SSHOptions  `toml:"ssh"`
	Mosh MoshOptions `toml:"mosh"`
	ET   ETOptions   `toml:"et"`

	// Addresses and Protocol are populated from RawAddresses/RawProtocol by
	// normalize() after unmarshaling; use these, not the Raw* fields.
	Addresses []string `toml:"-"`
	Protocol  []string `toml:"-"`
}

// normalize fills in Addresses/Protocol from their raw decoded values.
func (h *HostConfig) normalize(name string) error {
	addrs, err := toStringSlice(h.RawAddresses, "addresses")
	if err != nil {
		return fmt.Errorf("host %q: %w", name, err)
	}
	h.Addresses = addrs

	protos, err := toStringSlice(h.RawProtocol, "protocol")
	if err != nil {
		return fmt.Errorf("host %q: %w", name, err)
	}
	h.Protocol = protos

	return nil
}

// Config is the root of ~/.config/warp/config.toml.
type Config struct {
	Binaries map[string]string      `toml:"binaries"`
	Defaults Options                `toml:"defaults"`
	Hosts    map[string]*HostConfig `toml:"host"`

	// index maps every host key and alias to its canonical host key.
	// Built by buildIndex after unmarshaling; not part of the TOML itself.
	index map[string]string
}

// DefaultPath returns the XDG-conventional config location,
// ~/.config/warp/config.toml.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolving config dir: %w", err)
	}
	return filepath.Join(dir, "warp", "config.toml"), nil
}

// Load reads and parses the config file at path, then builds the
// name/alias index. It errors if any alias collides with a host name or
// another alias.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	return Parse(data)
}

// Parse decodes raw TOML bytes into a Config and builds its index.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	for name, h := range cfg.Hosts {
		if err := h.normalize(name); err != nil {
			return nil, err
		}
	}
	if err := cfg.buildIndex(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) buildIndex() error {
	c.index = make(map[string]string, len(c.Hosts))
	for name := range c.Hosts {
		c.index[name] = name
	}
	for name, h := range c.Hosts {
		for _, alias := range h.Aliases {
			if existing, ok := c.index[alias]; ok && existing != name {
				return fmt.Errorf("alias %q for host %q collides with %q", alias, name, existing)
			}
			c.index[alias] = name
		}
	}
	return nil
}

// FindHost resolves a host name or alias to its canonical name and config.
func (c *Config) FindHost(nameOrAlias string) (canonical string, host *HostConfig, ok bool) {
	canon, found := c.index[nameOrAlias]
	if !found {
		return "", nil, false
	}
	return canon, c.Hosts[canon], true
}

// ResolvedHost is a host's fully merged, ready-to-execute configuration:
// defaults -> host -> host.<protocol> have already been layered for each
// protocol, leaving only the chosen address to be injected at connect time.
type ResolvedHost struct {
	Name      string
	Addresses []string
	Protocols []string
	SSH       SSHOptions
	Mosh      MoshOptions
	ET        ETOptions
}

// Resolve looks up nameOrAlias and merges [defaults] -> host generic
// options -> host.<protocol> options for each of the three protocols.
func (c *Config) Resolve(nameOrAlias string) (*ResolvedHost, error) {
	canon, h, ok := c.FindHost(nameOrAlias)
	if !ok {
		return nil, fmt.Errorf("no host or alias named %q", nameOrAlias)
	}
	if len(h.Addresses) == 0 {
		return nil, fmt.Errorf("host %q has no addresses configured", canon)
	}
	if len(h.Protocol) == 0 {
		return nil, fmt.Errorf("host %q has no protocol configured", canon)
	}

	base := mergeOptions(c.Defaults, h.Options)

	ssh := h.SSH
	ssh.Options = mergeOptions(base, h.SSH.Options)

	mosh := h.Mosh
	mosh.Options = mergeOptions(base, h.Mosh.Options)

	et := h.ET
	et.Options = mergeOptions(base, h.ET.Options)

	return &ResolvedHost{
		Name:      canon,
		Addresses: h.Addresses,
		Protocols: h.Protocol,
		SSH:       ssh,
		Mosh:      mosh,
		ET:        et,
	}, nil
}
