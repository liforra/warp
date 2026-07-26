# warp

A single CLI that connects to hosts over **ssh**, **mosh**, **et** (Eternal Terminal), **tailscale ssh**, **tsh** (Teleport), or **telnet** — all driven by one shared TOML config, instead of juggling each tool's own flags and config files.

- **Protocol fallback chains** per host (e.g. try `mosh`, fall back to `ssh`), or a global default order if you don't set one.
- **Address fallback** too — multiple IPs/hostnames per host, tried in order.
- **Layered config**: global defaults → per-host → per-host-per-protocol overrides.
- **Auto-sources** hosts from your existing `~/.ssh/config` and credentials from `~/.netrc`, at lower priority than anything explicit in `warp.toml`.
- **`warp --scan`** — concurrently probes subnets (auto-detected, or given via `--subnet`) for reachable hosts, plus your Tailscale peers.
- **`warp --convert`** — turns an existing `ssh_config`-style file into real `warp.toml` host entries.

## Installation

Pick whichever matches how you install CLI tools. All of these install the `warp` binary; none require Go unless you build from source.

### Quick install script (Linux / macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/liforra/warp/master/install.sh | sh
```

Installs to `~/.local/bin` by default. Override with `WARP_INSTALL_DIR=/some/other/dir`.

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/liforra/warp/master/install.ps1 | iex
```

Installs to `%LOCALAPPDATA%\warp` by default. Override with the `WARP_INSTALL_DIR` environment variable.

### Debian / Ubuntu (.deb)

Download the `.deb` for your architecture from the [latest release](https://github.com/liforra/warp/releases/latest), then:

```sh
sudo apt install ./warp_<version>_linux_amd64.deb   # or _arm64 on ARM
```

This also installs man pages (`man warp`, `man warp-connect`, etc.).

### Fedora / RHEL / openSUSE (.rpm)

Download the `.rpm` for your architecture from the [latest release](https://github.com/liforra/warp/releases/latest), then:

```sh
sudo rpm -i warp_<version>_linux_amd64.rpm           # or _arm64 on ARM
# or, if you prefer dnf to resolve/track it:
sudo dnf install ./warp_<version>_linux_amd64.rpm
```

### Manual download (any OS/arch)

Grab the right archive from the [latest release](https://github.com/liforra/warp/releases/latest):

| OS      | Arch    | Archive                                  |
|---------|---------|-------------------------------------------|
| Linux   | amd64   | `warp_<version>_linux_amd64.tar.gz`       |
| Linux   | arm64   | `warp_<version>_linux_arm64.tar.gz`       |
| macOS   | amd64   | `warp_<version>_darwin_amd64.tar.gz`      |
| macOS   | arm64   | `warp_<version>_darwin_arm64.tar.gz`      |
| Windows | amd64   | `warp_<version>_windows_amd64.zip`        |
| Windows | arm64   | `warp_<version>_windows_arm64.zip`        |

Extract it and put the `warp` (or `warp.exe`) binary somewhere on your `$PATH`. A `checksums.txt` is published alongside every release if you want to verify the download.

### Homebrew / Scoop

Not published yet — the `.goreleaser.yaml` config has these ready to go (commented out) but they need a separate tap/bucket repo and a cross-repo token first. If you want these, ask for them to be set up.

### Build from source

Requires Go 1.24+.

```sh
git clone https://github.com/liforra/warp.git
cd warp
go build -o warp ./cmd/warp
```

Or without cloning:

```sh
go install github.com/liforra/warp/cmd/warp@latest
```

(This installs to `$(go env GOPATH)/bin` — make sure that's on your `$PATH`.)

## Getting started

```sh
warp init                 # scaffolds ~/.config/warp/config.toml with a commented example
$EDITOR ~/.config/warp/config.toml
warp connect myserver     # or just: warp myserver
```

See [`config.example.toml`](config.example.toml) for every option, or run `warp --convert` to generate a starting point from your existing `~/.ssh/config`.

## Usage

```
warp [host-or-alias]                 connect (bare shorthand for `warp connect`)
warp connect <host-or-alias>         connect to a configured host
warp list                            list configured hosts, aliases, addresses, protocol chains
warp detect                          show resolved paths for each supported client binary
warp config validate                 parse and sanity-check the config without connecting
warp init                            scaffold ~/.config/warp/config.toml
warp version                         print version/commit
warp --scan                          scan for reachable hosts (auto-detected subnets + Tailscale peers)
warp --scan --subnet <cidr>          scan a specific subnet (repeatable)
warp --scan --host <name/ip/domain>  scan a single host for every supported protocol/port
warp --convert --config <ssh_config> --output <warp.toml>
                                      convert an ssh_config-style file into warp.toml host blocks
```

Every command has a generated man page (`man warp`, `man warp-connect`, ...) once installed via `.deb`/`.rpm`, and a [tldr page](docs/tldr/warp.md) for quick examples.

## License

[GNU Affero General Public License v3.0](LICENSE.md).
