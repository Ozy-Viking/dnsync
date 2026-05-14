# technitium-dns-mcp

A Rust CLI + MCP server for [Technitium DNS Server](https://technitium.com/dns/).

Use it interactively from the terminal, or run it as an MCP server so Claude can manage your DNS.

## Build

```bash
cargo build --release
# Binary: ./target/release/dns
```

## Configuration

Auth is read from flags or environment variables:

| Flag | Env var | Default |
|---|---|---|
| `--base-url` | `TECHNITIUM_BASE_URL` | `http://localhost:5380` |
| `--token` | `TECHNITIUM_API_TOKEN` | *(required)* |

Get a token from the Technitium web console: **Settings → Users → your user → API Tokens → Create Token**

---

## CLI Usage

```
dns [OPTIONS] <COMMAND>

Commands:
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

## MCP Server (Claude Desktop)

Add to `claude_desktop_config.json`:

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
