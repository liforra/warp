// Package config loads and resolves warp's TOML configuration: binary path
// overrides, global defaults, and per-host / per-host-per-protocol option
// layering (including address and protocol fallback chains).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/liforra/warp/internal/netrc"
	"github.com/liforra/warp/internal/sshconfig"
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

// TailscaleOptions is `tailscale ssh`-specific config, layered under
// host.<name>.tailscale. Tailscale SSH authenticates via the tailnet
// identity rather than a key/port, so it shares little with Options beyond
// the username.
type TailscaleOptions struct {
	Options
	// Socket is the tailscaled control socket to talk to, for machines
	// where it's not the default (e.g. a non-standard install, a
	// container, or multiple tailscaled instances). Falls back to
	// Config.Tailscale.Socket when unset; passed as `tailscale --socket=`.
	Socket    string   `toml:"socket"`
	ExtraArgs []string `toml:"extra_args"`
}

// TshOptions is Teleport's `tsh ssh`-specific config, layered under
// host.<name>.tsh.
type TshOptions struct {
	Options
	Cluster   string   `toml:"cluster"`
	Proxy     string   `toml:"proxy"`
	ExtraArgs []string `toml:"extra_args"`
}

// TelnetOptions is telnet-specific config, layered under host.<name>.telnet.
// telnet predates ssh's exit-255 convention, so its fallback behavior in the
// exit-code heuristic (see internal/client) is unverified.
type TelnetOptions struct {
	Options
	ExtraArgs []string `toml:"extra_args"`

	// NetrcAutologin is set by applySources (not user-configurable) when
	// this host's address matched a ~/.netrc machine entry. It signals
	// the telnet client to use its own -a autologin (which reads .netrc
	// itself at connection time) -- warp never reads the password.
	NetrcAutologin bool `toml:"-"`
}

// HostConfig is one [host.X] table.
type HostConfig struct {
	RawAddresses any      `toml:"addresses"`
	Aliases      []string `toml:"aliases"`
	RawProtocol  any      `toml:"protocol"`
	Options

	SSH       SSHOptions       `toml:"ssh"`
	Mosh      MoshOptions      `toml:"mosh"`
	ET        ETOptions        `toml:"et"`
	Tailscale TailscaleOptions `toml:"tailscale"`
	Tsh       TshOptions       `toml:"tsh"`
	Telnet    TelnetOptions    `toml:"telnet"`

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

// DefaultProtocolOrder is the fallback chain used when a host doesn't set
// `protocol` at all: try the most capable/resilient options first, falling
// back toward plain ssh, then toward the identity-based tools, and finally
// telnet as the last resort (unencrypted, and its fallback behavior under
// the exit-255 heuristic is unverified -- see internal/client).
var DefaultProtocolOrder = []string{"et", "mosh", "ssh", "tailscale", "tsh", "telnet"}

// ScanConfig configures `warp --scan`. Subnets is used whenever no --subnet
// flag is given on the CLI; if that's also empty, warp falls back to
// auto-detecting local subnets from network interfaces.
type ScanConfig struct {
	RawSubnets any `toml:"subnets"`
	Workers    int `toml:"workers"`

	// Subnets is populated from RawSubnets by normalize() after unmarshaling.
	Subnets []string `toml:"-"`
}

func (s *ScanConfig) normalize() error {
	subnets, err := toStringSlice(s.RawSubnets, "scan.subnets")
	if err != nil {
		return err
	}
	s.Subnets = subnets
	return nil
}

// SourceOption configures one auto-sourced external config file (an
// ssh_config-style file, or a .netrc): whether to source it at all, and
// which path(s) to read. Both default to enabled, reading their tool's
// standard location, if the section is omitted entirely.
type SourceOption struct {
	EnabledOpt *bool `toml:"enabled"`
	RawPaths   any   `toml:"paths"`

	// Paths is populated from RawPaths by normalize() after unmarshaling.
	Paths []string `toml:"-"`
}

func (s *SourceOption) enabled() bool {
	return s.EnabledOpt == nil || *s.EnabledOpt
}

func (s *SourceOption) normalize(field string) error {
	paths, err := toStringSlice(s.RawPaths, field)
	if err != nil {
		return err
	}
	s.Paths = paths
	return nil
}

// SourcesConfig configures auto-importing hosts and credentials from
// external config files that ssh/mosh/et/telnet already understand, so
// entries don't need to be duplicated into warp.toml. A host name (or
// alias) already present under [host.*] always wins outright over anything
// sourced -- sourced hosts are strictly lower priority, never merged in.
type SourcesConfig struct {
	// SSHConfig sources ~/.ssh/config (default) as additional warp hosts:
	// each literal (non-wildcard) Host block becomes a host with that
	// block's HostName/User/Port/IdentityFile/ProxyJump. mosh and et both
	// benefit from this too -- mosh bootstraps over ssh, and et parses
	// ssh_config itself for the same fields.
	SSHConfig SourceOption `toml:"ssh_config"`
	// Netrc sources ~/.netrc (default) to enable telnet's own -a autologin
	// for hosts with a matching machine entry, and to fill in a host's
	// telnet username from its login field when not already set. The
	// password itself is never read by warp (see internal/netrc).
	Netrc SourceOption `toml:"netrc"`
}

// TailscaleConfig is the top-level [tailscale] table: machine-wide
// defaults for `tailscale ssh`, e.g. when tailscaled listens on a
// non-default control socket. Host.<name>.tailscale.socket overrides this
// per host.
type TailscaleConfig struct {
	Socket string `toml:"socket"`
}

// Config is the root of ~/.config/warp/config.toml.
type Config struct {
	Binaries  map[string]string      `toml:"binaries"`
	Defaults  Options                `toml:"defaults"`
	Hosts     map[string]*HostConfig `toml:"host"`
	Scan      ScanConfig             `toml:"scan"`
	Sources   SourcesConfig          `toml:"sources"`
	Tailscale TailscaleConfig        `toml:"tailscale"`

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
	if err := cfg.Scan.normalize(); err != nil {
		return nil, err
	}
	if err := cfg.Sources.SSHConfig.normalize("sources.ssh_config.paths"); err != nil {
		return nil, err
	}
	if err := cfg.Sources.Netrc.normalize("sources.netrc.paths"); err != nil {
		return nil, err
	}
	if err := cfg.buildIndex(); err != nil {
		return nil, err
	}
	if err := cfg.applySources(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applySources auto-imports hosts from ~/.ssh/config (or configured paths)
// as lower-priority warp hosts, then enriches telnet options from ~/.netrc.
// Both are best-effort: a missing default file is expected and not an
// error; only real read/parse failures on an explicitly configured path
// are surfaced.
func (c *Config) applySources() error {
	if c.Hosts == nil {
		c.Hosts = make(map[string]*HostConfig)
	}

	if c.Sources.SSHConfig.enabled() {
		paths := c.Sources.SSHConfig.Paths
		usingDefault := len(paths) == 0
		if usingDefault {
			paths = []string{"~/.ssh/config"}
		}
		for _, p := range paths {
			if err := c.importSSHConfig(p, usingDefault); err != nil {
				return fmt.Errorf("sources.ssh_config %q: %w", p, err)
			}
		}
	}

	if c.Sources.Netrc.enabled() {
		paths := c.Sources.Netrc.Paths
		usingDefault := len(paths) == 0
		if usingDefault {
			paths = defaultNetrcPaths()
		}
		for _, p := range paths {
			if err := c.applyNetrc(p, usingDefault); err != nil {
				return fmt.Errorf("sources.netrc %q: %w", p, err)
			}
		}
	}

	return nil
}

// importSSHConfig adds one host per literal Host block in the ssh_config
// file at path, skipping any name that collides with an existing host or
// alias (explicit config always wins) or that was already imported from an
// earlier source path. missingOK suppresses a not-found error for the
// default path, which usually just doesn't exist.
func (c *Config) importSSHConfig(path string, missingOK bool) error {
	abs, err := expandUserPath(path)
	if err != nil {
		return err
	}

	hosts, err := sshconfig.Parse(abs)
	if err != nil {
		if missingOK && os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, sh := range hosts {
		if _, exists := c.index[sh.Name]; exists {
			continue
		}

		hc := &HostConfig{
			Addresses: []string{firstNonEmpty(sh.HostName, sh.Name)},
		}
		hc.Options.User = sh.User
		hc.Options.Port = sh.Port
		hc.Options.IdentityFile = sh.IdentityFile
		if sh.ProxyJump != "" {
			hc.SSH.ProxyJump = sh.ProxyJump
		}

		c.Hosts[sh.Name] = hc
		c.index[sh.Name] = sh.Name
	}
	return nil
}

// applyNetrc marks NetrcAutologin (and fills in an unset telnet username)
// for any host whose first address matches a .netrc machine entry.
// missingOK suppresses a not-found error for the default path.
func (c *Config) applyNetrc(path string, missingOK bool) error {
	abs, err := expandUserPath(path)
	if err != nil {
		return err
	}

	entries, err := netrc.Parse(abs)
	if err != nil {
		if missingOK && os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, h := range c.Hosts {
		if len(h.Addresses) == 0 {
			continue
		}
		entry, ok := entries[h.Addresses[0]]
		if !ok {
			continue
		}
		h.Telnet.NetrcAutologin = true
		if h.Telnet.Options.User == "" {
			h.Telnet.Options.User = entry.Login
		}
	}
	return nil
}

func defaultNetrcPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{"~/_netrc", "~/.netrc"}
	}
	return []string{"~/.netrc"}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// userHomeDir is overridden in tests so default source paths (~/.ssh/config,
// ~/.netrc) resolve inside an isolated temp directory instead of the actual
// machine's real dotfiles -- otherwise test behavior would depend on
// whatever happens to be in the developer's or CI runner's home directory.
var userHomeDir = os.UserHomeDir

func expandUserPath(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	home, err := userHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~")), nil
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
	Tailscale TailscaleOptions
	Tsh       TshOptions
	Telnet    TelnetOptions
}

// Resolve looks up nameOrAlias and merges [defaults] -> host generic
// options -> host.<protocol> options for each protocol. If the host doesn't
// set `protocol`, DefaultProtocolOrder is used instead of erroring.
func (c *Config) Resolve(nameOrAlias string) (*ResolvedHost, error) {
	canon, h, ok := c.FindHost(nameOrAlias)
	if !ok {
		return nil, fmt.Errorf("no host or alias named %q", nameOrAlias)
	}
	if len(h.Addresses) == 0 {
		return nil, fmt.Errorf("host %q has no addresses configured", canon)
	}

	protocols := h.Protocol
	if len(protocols) == 0 {
		protocols = DefaultProtocolOrder
	}

	base := mergeOptions(c.Defaults, h.Options)

	ssh := h.SSH
	ssh.Options = mergeOptions(base, h.SSH.Options)

	mosh := h.Mosh
	mosh.Options = mergeOptions(base, h.Mosh.Options)

	et := h.ET
	et.Options = mergeOptions(base, h.ET.Options)

	tailscale := h.Tailscale
	tailscale.Options = mergeOptions(base, h.Tailscale.Options)
	if tailscale.Socket == "" {
		tailscale.Socket = c.Tailscale.Socket
	}

	tsh := h.Tsh
	tsh.Options = mergeOptions(base, h.Tsh.Options)

	telnet := h.Telnet
	telnet.Options = mergeOptions(base, h.Telnet.Options)

	return &ResolvedHost{
		Name:      canon,
		Addresses: h.Addresses,
		Protocols: protocols,
		SSH:       ssh,
		Mosh:      mosh,
		ET:        et,
		Tailscale: tailscale,
		Tsh:       tsh,
		Telnet:    telnet,
	}, nil
}
