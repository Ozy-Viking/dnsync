# dnsync

A Rust CLI + MCP server for [Technitium DNS Server](https://technitium.com/dns/).

Use it interactively from the terminal, or run it as an MCP server so Claude can manage your DNS.

## Build

```bash
cargo build --release
# Binary: ./target/release/dns
```

## Configuration

Auth can be read from a config file, flags, or environment variables. Release
builds read the default config file from `$XDG_CONFIG_HOME/dnsync/config.toml`,
falling back to `~/.config/dnsync/config.toml` on Linux. Debug builds use
`./.config/dnsync/config.toml` under the repository root so development changes
do not affect your real user config. If the selected config file does not
exist, `dnsync` creates it with safe defaults and no embedded secrets.

The config file must be readable only by its owner (`chmod 600`); the
containing directory must be owner-only as well (`chmod 700`). `dnsync`
sets these permissions automatically when it creates the file, and
refuses to start if it finds a config that is group- or world-readable.

Use `--config /path/to/config.toml` or `DNSYNC_CONFIG=/path/to/config.toml` to
load a custom config file. When a config contains multiple DNS servers, select
one with `--server <id>` or `DNSYNC_SERVER=<id>`.

Set `DNSYNC_TECHNITIUM_API_TOKEN` in the environment, pass `--token`, or edit
the config to use a different `token_env`.

To preview the starter config without writing any files:

```bash
dns config print
```

To create the config file without starting the DNS client or requiring an API
token:

```bash
dns config init
dns --config ./dnsync.toml config init
dns config init --force   # overwrite an existing file
```

```toml
[[servers]]
id = "home"
vendor = "technitium"
base_url = "http://192.168.1.10:5380"
token_env = "DNSYNC_HOME_API_TOKEN"

[servers.mcp]
readonly = true
allowed_zones = ["example.com", "internal.lan"]

[[servers]]
id = "lab"
vendor = "technitium"
base_url = "http://192.168.1.20:5380"
token_env = "DNSYNC_LAB_API_TOKEN"

[servers.mcp]
readonly = false
allowed_zones = ["lab.example.com"]
```

MCP permissions are applied per selected server. `readonly = true` blocks all
mutating MCP tools for that server, and `allowed_zones` restricts zone-targeting
MCP tools to the listed zones and their subdomains. `--allow-zone` /
`DNS_ALLOWED_ZONES` can further narrow configured zones for a launch, but cannot
broaden a server's configured allow-list.

Flags and environment variables override config values:

| Flag | Env var | Default |
|---|---|---|
| `--config` | `DNSYNC_CONFIG` | release: `$XDG_CONFIG_HOME/dnsync/config.toml`; debug: `./.config/dnsync/config.toml` |
| `--server` | `DNSYNC_SERVER` | only server in config |
| `--base-url` | `TECHNITIUM_BASE_URL` | config `base_url`, then `http://localhost:5380` |
| `--token` | `TECHNITIUM_API_TOKEN` | config `token_env` → env lookup, then `token` |
| `--readonly` | `DNS_READONLY` | config `readonly` |
| `--allow-zone` | `DNS_ALLOWED_ZONES` | config `allowed_zones` |

Token resolution per server: `--token` / `TECHNITIUM_API_TOKEN` → `token_env` (env var named in config) → `token` (literal in config).

---

## CLI Usage

```
dns [OPTIONS] <COMMAND>

Commands:
  config    Manage the config file (init, print)
  mcp       Start as MCP stdio server
  zone      Manage DNS zones
  record    Manage DNS records
  cache     Manage the DNS cache
  stats     View server statistics
  blocked   Manage blocked domains
  allowed   Manage allowed (whitelist) domains
  settings  Show server settings
```

### Zones

```bash
dns zone list
dns zone list --page 2 --per-page 20
dns zone create example.com
dns zone create internal.lan --type Forwarder
dns zone enable example.com
dns zone disable example.com
dns zone delete example.com
```

### Records

```bash
dns record list example.com
dns record add --zone example.com --domain www.example.com --type A --value 93.184.216.34
dns record add --zone example.com --domain example.com --type MX --value mail.example.com
dns record add --zone example.com --domain example.com --type TXT --value "v=spf1 ~all"
dns record delete --zone example.com --domain www.example.com --type A --value 93.184.216.34
```

### Cache

```bash
dns cache list
dns cache list example.com
dns cache delete example.com
dns cache flush
```

### Stats

```bash
dns stats
dns stats --type LastHour
dns stats --type LastWeek
```

### Blocked / Allowed

```bash
dns blocked list
dns blocked add doubleclick.net
dns blocked delete doubleclick.net

dns allowed list
dns allowed add myapp.internal
```

---

## MCP Server

### Claude

```json
{
  "mcpServers": {
    "technitium-dns": {
      "command": "/path/to/dns",
      "args": ["mcp"],
      "env": {
        "TECHNITIUM_BASE_URL": "http://192.168.1.10:5380",
        "TECHNITIUM_API_TOKEN": "your-token-here"
      }
    }
  }
}
```
