# dnsync

A Rust CLI + MCP server for managing DNS servers.

Use it interactively from the terminal, or run it as an MCP server so Claude can manage your DNS.

**Supported vendors:** Technitium · Pangolin · Cloudflare

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

`--token` and `--base-url` are explicit CLI overrides. Without them, credentials
are resolved from vendor-specific environment variables and the selected server's
config entry (see the resolution chain below).

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

To add a server entry interactively:

```bash
dns config add           # interactive wizard
```

Or non-interactively with flags:

```bash
dns config add --id home --vendor technitium --base-url-env HOME_DNS_URL --token-env HOME_DNS_TOKEN
dns config add --id cf   --vendor cloudflare  --token-env CLOUDFLARE_API_TOKEN
dns config add --id pg   --vendor pangolin    --org-id my-org --token-env PANGOLIN_API_TOKEN
```

### Example config

```toml
[[servers]]
id = "home"
vendor = "technitium"
base_url = "http://192.168.1.10:5380"   # or use base_url_env to read from an env var
token_env = "DNSYNC_HOME_API_TOKEN"

[[servers.validation_endpoints]]
name = "home-router"
transport = "dns"
address = "192.168.1.1"
port = 53

[[servers.validation_endpoints]]
name = "cloudflare-doh"
transport = "doh"
url = "https://cloudflare-dns.com/dns-query"
timeout_ms = 2000

[[servers.validation_endpoints]]
name = "quad9-dot"
transport = "dot"
address = "9.9.9.9"
port = 853
tls_server_name = "dns.quad9.net"

[servers.mcp]
access = "read"
allowed_zones = ["example.com", "internal.lan"]

[[servers]]
id = "lab"
vendor = "technitium"
base_url = "http://192.168.1.20:5380"
token_env = "DNSYNC_LAB_API_TOKEN"

[servers.mcp]
access = "delete"
allowed_zones = ["lab.example.com"]

[[servers]]
id = "cf"
vendor = "cloudflare"
token_env = "CLOUDFLARE_API_TOKEN"

[[servers]]
id = "pg"
vendor = "pangolin"
org_id = "my-org"
token_env = "PANGOLIN_API_TOKEN"

# Named record-sync profile — see the Sync section above.
[[sync]]
name = "home"          # invoked as `dns sync home`
from = "cf"            # source server id
to = "home"            # destination server id
zones = ["example.com"]  # optional; omit to sync every zone on the source

[sync.ip_map]
"203.0.113.10" = "192.168.1.10"
"203.0.113.11" = "192.168.1.11"
```

Each `[[sync]]` profile names a `from`/`to` pair of server ids and an optional
`ip_map` of `external = internal` address rewrites. Both sides of a mapping
must be valid IP addresses of the same family (IPv4↔IPv4 or IPv6↔IPv6).

Vendor defaults when no `base_url` is set:
- `technitium` → `http://localhost:5380`
- `pangolin` → `https://api.pangolin.net/v1`
- `cloudflare` → `https://api.cloudflare.com/client/v4`

Validation endpoints are optional per-server DNS resolvers used by endpoint
validation. Configure them with `[[servers.validation_endpoints]]`. Supported
transports are `dns`, `doh`, and `dot`; DNS/DoT endpoints require `address`,
while DoH endpoints require `url`. If no validation endpoints are configured,
validation remains enabled but is skipped with reason
`no_validation_endpoints_configured`.

MCP permissions are applied per selected server. `access` controls the maximum
permitted operation level (`read` = read-only, `write` = no deletes, `delete` =
full access), and `allowed_zones` restricts zone-targeting MCP tools to the
listed zones and their subdomains. `--allow-zone` / `DNS_ALLOWED_ZONES` can
further narrow configured zones for a launch, but cannot broaden a server's
configured allow-list.

Flags and environment variables override config values:

| Flag | Env var | Default |
|---|---|---|
| `--config` | `DNSYNC_CONFIG` | release: `$XDG_CONFIG_HOME/dnsync/config.toml`; debug: `./.config/dnsync/config.toml` |
| `--server` | `DNSYNC_SERVER` | only server in config |
| `--base-url` | — | vendor env var → config `base_url_env` → `base_url` → vendor default |
| `--token` | — | vendor env var → config `token_env` → `token` |
| `--access` | `DNS_ACCESS` | config `access` |
| `--allow-zone` | `DNS_ALLOWED_ZONES` | config `allowed_zones` |

Credential resolution chain (highest priority first):

| Step | Base URL | Token |
|---|---|---|
| 1 | `--base-url` flag | `--token` flag |
| 2 | vendor env var (`DNSYNC_TECHNITIUM_BASE_URL`, `DNSYNC_PANGOLIN_BASE_URL`, `DNSYNC_CLOUDFLARE_BASE_URL`) | vendor env var (`DNSYNC_TECHNITIUM_API_TOKEN`, `DNSYNC_PANGOLIN_API_TOKEN`, `DNSYNC_CLOUDFLARE_API_TOKEN`) |
| 3 | config `base_url_env` → env lookup | config `token_env` → env lookup |
| 4 | config `base_url` literal | config `token` literal |
| 5 | vendor default URL | — |

Technitium also accepts legacy `TECHNITIUM_BASE_URL` / `TECHNITIUM_API_TOKEN` at step 2 (checked after `DNSYNC_TECHNITIUM_*`).

Pangolin additionally requires `org_id` — resolved from `DNSYNC_PANGOLIN_ORG_ID` then config `org_id`.

---

## CLI Usage

```
dns [OPTIONS] <COMMAND>

Commands:
  config      Manage the config file (init, print, add)
  mcp         Start as MCP stdio server
  zone        Manage DNS zones
  record      Manage DNS records
  sync        Sync records between two configured servers, remapping IPs
  cache       Manage the DNS cache
  stats       View server statistics
  blocked     Manage blocked domains
  allowed     Manage allowed (whitelist) domains
  settings    Show server settings
  completions Print a shell completion script to stdout
```

### Config

```bash
dns config init               # write the starter config file
dns config init --force       # overwrite an existing file
dns config print              # show current config (tokens redacted)
dns config add                # interactive wizard — add a server entry
dns config add --id home --vendor technitium --base-url http://192.168.1.10:5380 --token-env MY_TOKEN
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
dns zone import example.com ./example.com.zone
dns zone import example.com ./example.com.zone --overwrite-zone   # delete all records first
dns zone export example.com                                       # prints BIND zone file to stdout
dns zone export example.com --output ./example.com.zone          # write to file
dns zone transfer example.com --from home --to lab               # copy zone between configured servers
```

### Records

`record list` accepts an optional domain argument. Without a domain it lists all
records across all configured servers. Supply `--zone` to qualify a bare label
(e.g. `huly` + `--zone hankin.io` → `huly.hankin.io`); without `--zone`, the
domain is matched against all zones.

```bash
dns record list                         # all records from all configured servers
dns record list --json                  # JSON array with serverName, zone, and records
dns record list example.com
dns record list example.com --zone example.com
dns record list www --zone example.com
dns record list example.com --all-subdomains   # include all subdomain records
dns record list example.com --json             # raw JSON output
dns record list example.com --use-local-ip     # prefer private/local IP for A/AAAA
dns --all record list example.com              # query all configured servers
dns --server home --server lab record list example.com  # query specific servers
```

`record add` and `record delete` take the record type as a subcommand with
type-specific positional arguments:

```bash
# Add records
dns record add --zone example.com --domain www.example.com a 93.184.216.34
dns record add --zone example.com --domain example.com    aaaa 2001:db8::1
dns record add --zone example.com --domain example.com    mx mail.example.com --preference 10
dns record add --zone example.com --domain example.com    txt "v=spf1 ~all"
dns record add --zone example.com --domain example.com    cname alias.example.com
dns record add --zone example.com --domain example.com    ns ns1.example.com
dns record add --zone example.com --domain _dmarc.example.com txt "v=DMARC1; p=none"
dns record add --zone example.com --domain example.com    caa letsencrypt.org --tag issue
dns record add --zone example.com --domain _sip._tcp.example.com srv sip.example.com --port 5060 --priority 10 --weight 20
dns record add --zone example.com --domain example.com    sshfp RSA SHA256 abcdef...
dns record add --zone example.com --domain example.com    tlsa DANE-EE SPKI SHA2-256 abcdef...
dns record add --zone example.com --ttl 300 --domain example.com txt "short-lived"

# Delete specific record
dns record delete --zone example.com --domain www.example.com a 93.184.216.34

# Delete all records of a type for a domain
dns record delete --zone example.com --domain www.example.com a
```

Supported record types for `add` and `delete`: `a`, `aaaa`, `aname`, `app`,
`caa`, `cname`, `dname`, `ds`, `fwd`, `https`, `mx`, `naptr`, `ns`, `ptr`,
`sshfp`, `srv`, `svcb`, `tlsa`, `txt`, `uri`, `unknown`.

For Pangolin servers, `record list` reads records from Pangolin's DNS API and
normalizes them into the same shape used by other vendors. `--use-local-ip`
optionally resolves A/AAAA record names with Hickory and prefers a
private/local address when one is visible; without the flag, provider API
values are preserved exactly.

### Sync

`record sync` copies records from one configured server to another, optionally
rewriting IP addresses on A/AAAA records — for example, mapping a public
address to its internal LAN equivalent ("split-horizon" DNS).

```bash
dns sync home                                   # run the "home" profile (dry run)
dns sync home --apply                           # commit the changes
dns sync home --json                            # emit the plan as JSON
dns sync --from cf --to home --zone example.com # ad-hoc, no profile
dns sync --from cf --to home --zone example.com --map 203.0.113.10=192.168.1.10
```

Sync is **dry-run by default** — it prints the planned changes and writes
nothing until `--apply` is passed. It is **additive**: it adds records the
destination is missing and updates record sets whose values differ, but never
prunes whole names that exist only on the destination. Server-managed records
(SOA, DNSSEC) and disabled records are skipped; source TTLs are preserved.

Because it reads and writes individual records through the vendor-neutral API,
`sync` works between any pair of supported vendors — including Pangolin, which
cannot participate in `zone transfer`.

Sync pairs and their IP-mapping tables can be stored as named `[[sync]]`
profiles in the config file (see below). CLI flags override the profile, and
`--map SRC=DST` entries merge into and override the profile's `ip_map`.

### Cache

```bash
dns cache list
dns cache list example.com
dns cache delete example.com
dns cache flush
```

### Stats

```bash
dns stats                       # defaults to LastDay
dns stats --type LastHour
dns stats --type LastDay
dns stats --type LastWeek
dns stats --type LastMonth
dns stats --type LastYear
```

### Blocked / Allowed

```bash
dns blocked list
dns blocked add doubleclick.net
dns blocked delete doubleclick.net

dns allowed list
dns allowed add myapp.internal
dns allowed delete myapp.internal
```

### Shell completions

```bash
dns completions fish > ~/.config/fish/completions/dns.fish
dns completions bash > ~/.local/share/bash-completion/completions/dns
dns completions zsh  > ~/.zsh/completions/_dns
```

---

## MCP Server

### Claude Desktop

Use a config file with a named server entry — credentials are resolved via `token_env` and `base_url` in the config:

```json
{
  "mcpServers": {
    "dnsync": {
      "command": "/path/to/dns",
      "args": ["mcp"],
      "env": {
        "DNSYNC_CONFIG": "/home/user/.config/dnsync/config.toml",
        "DNSYNC_SERVER": "home",
        "MY_DNS_TOKEN": "your-token-here"
      }
    }
  }
}
```

Where the config entry for `home` sets `token_env = "MY_DNS_TOKEN"`. For a one-off setup without a config file, pass credentials as flags:

```json
{
  "mcpServers": {
    "dnsync": {
      "command": "/path/to/dns",
      "args": ["mcp", "--base-url", "http://192.168.1.10:5380", "--token", "your-token-here"],
      "env": {}
    }
  }
}
```
