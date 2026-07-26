# warp

> Connect to hosts over ssh, mosh, et, tailscale ssh, tsh, or telnet, chosen and configured from one shared TOML file.
> Falls back through your configured protocol chain automatically (e.g. mosh, then ssh).
> More information: <https://github.com/liforra/warp>.

- Connect to a configured host (protocol chosen by its config, or the built-in default order):

`warp {{host_or_alias}}`

- Connect using an explicit subcommand instead of the bare shorthand:

`warp connect {{host_or_alias}}`

- Connect, overriding the configured protocol chain for this one run:

`warp {{host_or_alias}} --proto {{ssh}}`

- List every configured host with its resolved aliases, addresses, and protocol chain:

`warp list`

- Show which of ssh/mosh/et/tailscale/tsh/telnet are installed, and where:

`warp detect`

- Scan a subnet for hosts speaking any supported protocol (auto-detects subnets, and Tailscale peers, if none are given):

`warp --scan`

- Scan a specific subnet (repeatable for multiple subnets):

`warp --scan --subnet {{192.168.1.0/24}}`

- Scan a single host for every protocol/port it answers on:

`warp --scan --host {{hostname_or_ip}}`

- Convert an existing ssh_config file into warp.toml [host] blocks:

`warp --convert --config {{path/to/ssh_config}} --output {{path/to/warp.toml}}`

- Create a starter config at the default location (~/.config/warp/config.toml):

`warp init`

- Validate the config file without connecting to anything:

`warp config validate`
