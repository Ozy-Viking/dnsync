# `dns query` — direct DNS lookups (dig-style)

This document is the design record for `dns query`, a vendor-neutral DNS
lookup subcommand that lets `dns` itself resolve names — by default through
the local system resolver, optionally through a named or ad-hoc nameserver,
across plain DNS, DoT, DoH, and (behind the opt-in `doq` Cargo feature)
DoQ transports.

## Background — gap analysis

`dns` today is an API client (Technitium / Pangolin / Cloudflare) and a
sync tool. It can *list records as the provider sees them*
(`dns record list`), but it cannot answer "what does this nameserver
actually return for huly.hankin.io right now?" without leaving the tool.
Two pieces of in-tree machinery are already close to that answer:

- `core::dns::validation` wraps `hickory-resolver` for DNS / DoT / DoH
  endpoint probes, but the builders are locked inside the validation
  pipeline. The cluster-config work (PR #27) explicitly notes the
  validation layer "is not used at runtime" today
  (`docs/validation_endpoint_analysis.md`).
- The cluster-config work added first-class **per-server transport
  blocks**: `[servers.dns]`, `[servers.dot]`, `[servers.doh]` on each
  `[[servers]]` entry — exactly the shape needed to answer "where does
  dns1 listen for DNS queries?".

Three gaps remain:

1. **No user-facing resolver.** Users reach for `dig`, `kdig`, or
   `nslookup` to verify what a server publishes. `dns` should answer
   that question itself, reusing the resolver machinery already in-tree.
2. **No transport coverage for DoQ.** Neither the validation layer nor
   the new transport blocks know about QUIC. The user explicitly asked
   for DoQ.
3. **No way to address an arbitrary resolver from the CLI.** Today every
   configured DNS target is bound to a `[[servers]]` entry; ad-hoc
   `@1.1.1.1`-style lookups have no path.

## `dns query`

A new vendor-neutral subcommand. Reads the answer from a DNS resolver and
prints it; never touches a vendor API.

```bash
dns query huly.hankin.io                          # system resolver, all supported types
dns query huly.hankin.io -t AAAA                  # specific record type
dns q huly.hankin.io                              # short alias
dns query huly.hankin.io --server dns1            # configured server entry
dns query huly.hankin.io --server dns1 --dot      # force DoT
dns query huly.hankin.io --server dns1 --dot --doh # fan out across two
dns query huly.hankin.io --server dns1 --all-transports # every enabled block
dns query huly.hankin.io --server dns1 --server dns2    # several servers
dns query huly.hankin.io --all-servers            # every configured server
dns query huly.hankin.io --all                    # all servers × types × transports
dns query huly.hankin.io @1.1.1.1                 # ad-hoc plain DNS
dns query huly.hankin.io --at tls://9.9.9.9       # ad-hoc DoT
dns query huly.hankin.io --at https://cloudflare-dns.com/dns-query
dns query huly.hankin.io --at quic://dns.adguard.com
dns query huly.hankin.io @9.9.9.9 --dot --port 853
dns query huly.hankin.io --json
```

### Behaviour

- **Defaults to the host's resolver.** No `--server`, no `--at`, no
  `@host` → `Resolver::builder_tokio()` is used. This reads
  `/etc/resolv.conf` on Unix and the platform resolver elsewhere. No
  config file is required.
- **Read-only.** No vendor API call, no token, no network policy.
- **One *kind* of target per invocation.** Named servers
  (`--server`/`--all-servers`) and ad-hoc (`@host`/`--at`) are mutually
  exclusive; supplying both is a parse error. `--server` is repeatable
  and `--all-servers` fans out across every configured server.
- **`--server <ID>` selects a configured `[[servers]]` entry** and
  queries it over its `[servers.dns|dot|doh|doq]` blocks. Without any
  transport flag, the server's default transport (the first enabled
  block in the precedence order `dns → dot → doh → doq`, or its sole
  configured block) is used. Pass one or more of `--dns`, `--dot`,
  `--doh`, `--doq` to pick specific transports; pass `--all-transports`
  to fan out across every enabled block.
- **`--all-transports` is best-effort.** It runs against whatever
  transport blocks are configured and `enabled = true` on the target. If
  only two are enabled, only those two are queried — no error.
- **Transport is auto-detected from the URL scheme** for ad-hoc targets.
  Any single transport flag (`--dns`/`--dot`/`--doh`/`--doq`) overrides
  it. Schemes recognised: `udp://`, `tcp://`, `dns://` (plain),
  `tls://`, `dot://` (DoT), `https://`, `doh://` (DoH), `quic://`,
  `doq://` (DoQ).
- **Output is dig-flavoured.** Default is a compact table: name, type,
  TTL, data. Multiple-transport runs print one header+answer block per
  transport, separated by blank lines, in precedence order. `--json`
  emits a stable JSON shape with an `answers` array per transport.
  `--short` prints only the data column.
- **TTL preserved as observed.** Unlike validation, this command shows
  the resolver's TTL.

### Flags

| Flag | Meaning |
|---|---|
| `<DOMAIN>` | Required. Name to resolve. Bare labels are not auto-qualified — the user passes the FQDN. |
| `-t, --type <RR>` | Record type, repeatable (default: all supported standard types). Accepts standard mnemonics: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SRV`, `CAA`, `PTR`, `SOA`, `ANY`. |
| `--all-types` | Query every supported record type, overriding any `-t`/`--type`. Same as the default when no `-t` is given. |
| `--server <ID>` | A configured `[[servers]]` entry, **repeatable**. Matched case-insensitively against `server.id` (existing rule). Pass more than once to fan out across several servers. |
| `--all-servers` | Query every configured `[[servers]]` entry. Mutually exclusive with `--at`/`@ADDR` and with explicit `--server`. |
| `--at <ADDR>` | Ad-hoc resolver. `host[:port]` or `scheme://host[:port][/path]`. |
| `@ADDR` (positional) | Sugar for `--at ADDR`. Following dig convention; can appear before or after the domain. |
| `--dns` | Use the `[servers.dns]` block (plain DNS, UDP+TCP). With `--at`, forces plain DNS. Combine with other transport flags to fan out. |
| `--dot` | Use the `[servers.dot]` block. With `--at`, forces DoT. |
| `--doh` | Use the `[servers.doh]` block. With `--at`, forces DoH. |
| `--doq` | Use the `[servers.doq]` block. With `--at`, forces DoQ. Requires the `doq` Cargo feature. |
| `--all-transports` | Query every transport block present and `enabled = true` on the target; missing/disabled transports are skipped silently. Requires a server target (`--server`/`--all-servers`); not valid with ad-hoc or the system resolver. Mutually exclusive with the individual transport flags. |
| `--all` | Shorthand for `--all-servers --all-types --all-transports`: every server, every record type, every enabled transport. |
| `--port <u16>` | Override the port. Defaults: DNS 53, DoT 853, DoH 443, DoQ 853. |
| `--tls-server-name <NAME>` | SNI / certificate name override for DoT, DoH, DoQ. |
| `--timeout <MS>` | Per-attempt timeout (default 5000, overrides the block's `timeout_ms`). |
| `--tcp` | With `--dns`, force TCP for the plain-DNS query (skip UDP). Ignored for other transports. |
| `--short` | Print only the data column. Mirrors `dig +short`. |
| `--json` | Emit structured output (see §Output). |

`--transport <X>` from earlier drafts is removed; the boolean flags
above subsume it. Mapping for users converting scripts:
`--transport dns` → `--dns`, `--transport doh` → `--doh`, etc.

### CLI rules

- `--server`/`--all-servers` and (`--at` or `@addr`) are mutually
  exclusive.
- `--all-servers` and explicit `--server` are mutually exclusive
  (`--all-servers` already covers every server).
- `--at` and `@addr` are mutually exclusive (use one).
- `--port`, `--tls-server-name`, `--tcp` only apply with an ad-hoc
  resolver. With `--server`/`--all-servers` they are an error (the
  transport block owns those values).
- **Transport flags require a resolver target.** `--dns`/`--dot`/
  `--doh`/`--doq`/`--all-transports` with neither a server target nor
  `--at`/`@` (i.e. trying to influence the system resolver) is an error
  — the OS resolver picks the transport itself.
- **With `--at`/`@ADDR`, at most one** of `--dns`/`--dot`/`--doh`/
  `--doq` is accepted; combining multiple (or `--all-transports`) is an
  error — ad-hoc names a single endpoint with one transport. Use
  `--server` for fan-out.
- **`--all-transports` is mutually exclusive** with the individual
  transport flags; supplying both is an error.
- **`--all-transports` requires a server target.** With ad-hoc or the
  system resolver it errors with a fix-it hint.
- **`--all` expands** to `--all-servers --all-types --all-transports`
  before the rules above are applied, so `--all` with `@addr` errors the
  same way `--all-servers` with `@addr` does.
- `--server <id>` where `<id>` resolves to a cluster, not a server,
  errors with "use `--server <member>` to pick one of <listed
  members>". Cluster fan-out is a future feature.
- The top-level `--token`, `--base-url`, `--config` flags are accepted
  but unused; pass-through, no parse error (matches the existing
  `record list` behaviour).
- The top-level `--server` is shadowed by the subcommand-level
  `--server` for `query` (same pattern as `record list`).

### Output

The header line starts with `@` (the resolver target), then transport,
then any transport-specific key=value extras, then the elapsed wall-clock
time. No BIND-style `;;` prefix; trailing dots on names are stripped.
Columns are space-padded to fit the widest cell.

**Default table** (one row per answer record, blank line between header
and answers):

```
@ 10.5.0.53:853  dot  sni=dns1.hankin.io  9ms

huly.hankin.io  A  300  10.5.0.42
huly.hankin.io  A  300  10.5.0.43
```

For the system-resolver default the header line names the OS resolver
the platform actually picked:

```
@ 127.0.0.53  dns  system  3ms

huly.hankin.io  A  300  10.5.0.42
```

Non-`noerror` results render as a single row in the answer table —
queried name on the left, status where the data would go — so the
user can see what was actually asked:

```
$ dns q nope.hankin.io
@ 127.0.0.53  dns  system  3ms

nope.hankin.io  NXDOMAIN
```

```
$ dns q huly.hankin.io --server dns1 --dot
@ 10.5.0.53:853  dot  sni=dns1.hankin.io  5004ms

huly.hankin.io  TIMEOUT
```

In a `--type A -t AAAA` query where the type matters, the type column
is preserved on the status row:

```
nope.hankin.io  A     NXDOMAIN
nope.hankin.io  AAAA  NXDOMAIN
```

**Multiple transports** (`--all-transports`, or combinations of
`--dns`/`--dot`/`--doh`/`--doq`) — one header+answer block per transport,
separated by blank lines, in precedence order `dns → dot → doh → doq`:

```
$ dns q huly.hankin.io --server dns1 --all-transports

@ 10.5.0.53:53  dns  4ms
huly.hankin.io  A  300  10.5.0.42

@ 10.5.0.53:853  dot  sni=dns1.hankin.io  9ms
huly.hankin.io  A  300  10.5.0.42

@ dns1.hankin.io/dns-query  doh  22ms
huly.hankin.io  A  300  10.5.0.42
```

**Multiple servers** (`--all-servers`, or repeated `--server`) — each
header gains a `server=<id>` tag so blocks are attributable:

```
$ dns q huly.hankin.io --server dns1 --server dns2

@ 10.5.0.53:53  dns  server=dns1  4ms
huly.hankin.io  A  300  10.5.0.42

@ 10.6.0.53:53  dns  server=dns2  5ms
huly.hankin.io  A  300  10.5.0.42
```

If a transport is requested explicitly (`--doq`) but the block is
absent or disabled, that transport gets a header line marking the
skip; other transports continue:

```
@ dns1.hankin.io/dns-query  doh  22ms
huly.hankin.io  A  300  10.5.0.42

@ —  doq  skipped (no [servers.doq] block on dns1)
```

`--all-transports` skips silently — only blocks that exist and are
enabled produce output, matching the expectation that `--all-transports`
on a server with two configured transports prints two blocks.

The process exit code is the worst across transports (see §Errors).

**`--short`** — answers only, one per line:

```
10.5.0.42
10.5.0.43
```

**`--json`** (stable shape, suitable for piping). One JSON object per
invocation, with a `results` array — one entry per (server, transport)
pair used. A single-transport query produces a single-element `results`
array; `--all-transports` produces one entry per enabled block, and
multiple servers add more entries. Each result carries a `"server"`
field when it came from a named server (omitted for system/ad-hoc).
The top-level `target.server`/`target.cluster` are populated only for a
single named server; for a multi-server fan-out they are `null`.

```json
{
  "query":   { "name": "huly.hankin.io", "types": ["A"] },
  "target":  {
    "kind": "named",                  // "system" | "named" | "ad_hoc"
    "server": "dns1",                  // null when kind != "named" or multi-server
    "cluster": "home-dns"              // server's cluster, when set
  },
  "results": [
    {
      "server": "dns1",                // present for named results
      "resolver": {
        "transport": "doh",
        "address": null,
        "port": 443,
        "url": "https://dns1.hankin.io/dns-query",
        "server_name": "dns1.hankin.io"
      },
      "elapsed_ms": 22,
      "status": "noerror",             // "noerror" | "nxdomain" | "servfail" | "refused" | "timeout" | "skipped" | "unsupported_transport"
      "skip_reason": null,             // set when status == "skipped"
      "answers": [
        { "name": "huly.hankin.io", "type": "A", "ttl": 300, "data": "10.5.0.42" }
      ]
    },
    {
      "resolver": {
        "transport": "dot",
        "address": "10.5.0.53",
        "port": 853,
        "url": null,
        "server_name": "dns1.hankin.io"
      },
      "elapsed_ms": 9,
      "status": "noerror",
      "answers": [
        { "name": "huly.hankin.io", "type": "A", "ttl": 300, "data": "10.5.0.42" }
      ]
    }
  ]
}
```

### Errors and exit codes

| Condition | Status | Exit |
|---|---|---|
| Answer returned | `noerror` | `0` |
| NXDOMAIN | `nxdomain` | `1` |
| SERVFAIL | `servfail` | `2` |
| REFUSED | `refused` | `2` |
| Timeout | `timeout` | `2` |
| TLS / HTTPS / QUIC handshake failure | `tls_failure` / `doh_http_failure` / `doq_failure` | `2` |
| `--doq` requested on a non-DoQ build, or block disabled | `unsupported_transport` | `2` |
| Explicit `--<transport>` whose block is missing/disabled (skipped) | `skipped` | per per-transport status of the others; if every requested transport skipped, `2` |
| Parse / config error (bad scheme, unknown `--server`, `--all` with ad-hoc, etc.) | n/a | `64` |

For multi-transport runs (`--all` or several transport flags), the
process exit code is the **worst** across the per-transport results, in
the order `noerror < skipped < nxdomain < servfail/refused/timeout/...`.
Implicit `--all` skips do not affect the exit code; they are best-effort.
Mapped through the existing `core::error::Error::exit_code()`.

## Config — `[servers.dns|dot|doh|doq]` blocks

The cluster-config work (PR #27) already added `[servers.dns]`,
`[servers.dot]`, and `[servers.doh]` blocks to each `[[servers]]` entry.
`dns query --server <ID>` reads those blocks directly — no new
`[[servers.validation_endpoints]]` plumbing, no cross-server name lookup,
no name-uniqueness invariant to add. Server IDs are already required
unique (case-insensitive) by `AppConfig::validate`, so `--server dns1`
is unambiguous.

A new `[servers.doq]` block, modelled on `[servers.dot]`, adds the DoQ
slot. Example (from `README.md`, with the new `doq` block added):

```toml
[[servers]]
id = "dns1"
vendor = "technitium"
location = "local"
cluster = "home-dns"
base_url = "https://dns1-ui.hankin.io"
token_env = "DNSYNC_DNS1_API_TOKEN"

[servers.dns]
enabled = true
addr = "10.5.0.53:53"

[servers.dot]
enabled = true
addr = "10.5.0.53:853"
server_name = "dns1.hankin.io"

[servers.doh]
enabled = true
url = "https://dns1.hankin.io/dns-query"

[servers.doq]                       # new — opt-in `doq` build only
enabled = true
addr = "10.5.0.53:853"
server_name = "dns1.hankin.io"

[servers.mcp]
access = ["read"]
allowed_zones = ["example.com"]
```

### Selection precedence

Each server has a **default transport**, derived from its configured
transport blocks — no extra config field is needed:

- If a server has exactly one transport block (say only `[servers.dot]`),
  that block is its default, regardless of where it sits in the order
  below.
- If a server has several enabled blocks, the first enabled block in this
  precedence order is the default:

  `dns` → `dot` → `doh` → `doq`

Plain DNS is first because it is the universally-available baseline; DoQ
is last because it is not in default builds. Users with `--features doq`
who want it first can pass `--doq` explicitly.

For `--server <ID>` with **one or more** transport flags
(`--dns`/`--dot`/`--doh`/`--doq`), only those transports run. If an
explicitly-requested transport's block is missing or disabled on that
server, the command emits a `skipped` result for it and continues with
the others; the exit code reflects that. `--all-transports` is equivalent
to passing every transport flag, except that missing/disabled blocks are
silently dropped rather than reported as `skipped`.

The output order is always `dns → dot → doh → doq`, regardless of the
order the flags were supplied on the command line.

### Querying multiple servers

`--server <ID>` is repeatable, and `--all-servers` fans out across every
configured `[[servers]]` entry. Each selected server is queried over its
own transport set (its default transport, the explicit transport flags,
or — with `--all-transports` — every enabled block). The output prints one
header+answer block per (server, transport) pair; when more than one
server is involved, each header gains a `server=<id>` tag and each `--json`
result carries a `"server"` field. The top-level `target.server` /
`target.cluster` fields stay populated only for the single-server case;
for a multi-server fan-out they are `null`.

`--all` is shorthand for `--all-servers --all-types --all-transports`:
every server, every supported record type, every enabled transport.

### Field mapping → resolver

| Block | Required | Optional | Default port |
|---|---|---|---|
| `[servers.dns]` | `addr` (`host:port` or `host`) | `timeout_ms` | 53 |
| `[servers.dot]` | `addr` | `server_name`, `timeout_ms` | 853 |
| `[servers.doh]` | `url` | `addr` (IP override), `server_name`, `timeout_ms` | 443 |
| `[servers.doq]` | `addr` | `server_name`, `timeout_ms` | 853 |

`addr` is `host[:port]`. The query path parses host and port itself; the
existing `validate_server_transports` only checks non-empty
`addr`/`url`, which still applies.

### Config changes required

1. **Add `DoqTransportConfig`** to `src/control_plane/config.rs`,
   mirroring `DotTransportConfig` (fields: `enabled`, `addr`,
   `server_name`, `timeout_ms`). Always compiled in — only the resolver
   wiring is feature-gated. See §DoQ feature gating below.
2. **Add `pub doq: Option<DoqTransportConfig>`** to `DnsServerConfig`
   and to its raw deserialization counterpart `DnsServerConfigRaw`, and
   wire it through the `From<DnsServerConfigRaw>` impl. Add the same
   `#[serde(skip_serializing_if = "Option::is_none")]` decoration the
   other transport fields use.
3. **Extend `validate_server_transports`** with a `doq` arm: enabled +
   missing `addr` is an error, matching the `dot` arm exactly.
4. **Extend `append_server_entry`** to round-trip `[servers.doq]`
   through `render_toml` (copy the `dot` branch, swap the field set).
5. **Update `cli::interactive::run_add_wizard`** if it prompts for
   transport blocks — append a DoQ prompt with the same shape as DoT.
   (Verify in code: as of the cluster PR, the wizard does not appear to
   prompt for these blocks yet; if so, no change.)
6. **`[[servers.validation_endpoints]]` remains on the legacy pipeline.**
   `ValidationTransport` gains a `Doq` variant for the new `[servers.doq]`
   blocks and `ValidationEndpointConfig::from_str` also accepts `doq` so TOML
   and CLI-style validation endpoint shorthands stay consistent. The resolver
   path still feature-gates DoQ and reports unsupported transport when the
   `doq` Cargo feature is disabled.

## Code layout

The resolver-building code currently lives inline in
`core/dns/validation.rs` (`resolver_config`, `plain_dns_name_server`,
`dot_name_server`, `doh_name_server`, `classify_hickory_error`). It is
keyed on `ValidationEndpointConfig` — the legacy validation type, not
the new per-server transport blocks. The query path needs to work from
the new blocks, so the builders are extracted onto a small neutral
target type.

**Refactor first, add second.**

1. **Introduce `ResolverTarget`** in a new module
   `src/core/dns/resolver.rs`:

   ```rust
   pub struct ResolverTarget {
       pub transport: ValidationTransport,   // re-used; gains a Doq variant
       pub addr: Option<String>,             // "host:port" or "host"
       pub url: Option<String>,              // DoH only
       pub server_name: Option<String>,      // SNI for DoT/DoH/DoQ
       pub timeout: Duration,
   }
   ```

   Two `From`-impls (or factory fns) populate it:
   - `ResolverTarget::from_server_transport(&DnsServerConfig,
     ValidationTransport)` — pulls `addr`/`url`/`server_name`/`timeout_ms`
     out of the matching `[servers.*]` block.
   - `ResolverTarget::from_endpoint(&ValidationEndpointConfig)` — the
     legacy path, preserves today's validation behaviour bit-for-bit.

2. **Extract** the resolver builders and the error classifier into
   `resolver.rs` and re-key them on `ResolverTarget`. Move:
   - `resolver_config` → takes `&ResolverTarget`
   - `plain_dns_name_server`, `dot_name_server`, `doh_name_server`
   - `endpoint_ip`, `tls_server_name`, `doh_url_parts` (operate on the
     new target's `addr`/`url`/`server_name`)
   - `classify_hickory_error`
   - `HickoryDnsEndpointResolver` (the trait stays in `validation.rs`
     because it owns the `ObservedRecord` type)

   `validation.rs` keeps its public surface; internally it builds a
   `ResolverTarget::from_endpoint(...)` before delegating. Behaviour and
   tests unchanged.

3. **Extend `ValidationTransport` with a `Doq` variant.** Always
   compiled in (so the enum is total and pattern matches on it stay
   exhaustive). It is reused as the target-side enum in step 1; the
   legacy `[[servers.validation_endpoints]]` `FromStr` parser also learns
   `doq` so serialized configs and shorthand inputs agree.

4. **Add `doq_name_server`** in `resolver.rs`, **gated behind
   `#[cfg(feature = "doq")]`**. Hickory 0.26 exposes
   `ConnectionConfig::quic(server_name: Arc<str>) -> Self`
   (`hickory-resolver` `src/config.rs`, behind the internal `__quic`
   feature). Default port is 853 — RFC 9250 registers ALPN `doq` on the
   same port as DoT. Function mirrors `dot_name_server`:

   ```rust
   #[cfg(feature = "doq")]
   fn doq_name_server(
       target: &ResolverTarget,
   ) -> DnsEndpointResolverResult<NameServerConfig> {
       let (ip, port) = parse_host_port(target.addr.as_deref(), 853)?;
       let server_name = tls_server_name(target)?.into();
       let mut quic = ConnectionConfig::quic(server_name);
       quic.port = port;
       Ok(NameServerConfig::new(ip, true, vec![quic]))
   }
   ```

5. **Add a project Cargo feature `doq`** (non-default) and wire it to
   the hickory `quic-ring` feature. See §DoQ feature gating below.

6. **Add `src/cli/query.rs`** with:
   - `QueryArgs` (clap struct, see §Flags above).
   - `AdHocTarget` value-parser: turns `@addr` / `--at addr` into a
     `ResolverTarget` with scheme→transport mapping.
   - `pub async fn run_query(config: Option<&AppConfig>, args: QueryArgs) -> Result<i32>`
     that:
     1. Builds an effective `ResolverTarget` from the source
        (system / `--server <ID>` / ad-hoc), or `None` for system.
     2. For the system case, calls `Resolver::builder_tokio()` directly.
     3. For `--server <ID>`: looks up
        `app_config.selected_server(Some(id))`, then either uses
        `--transport` to pick the block or runs the precedence
        (`dns → dot → doh → doq`) over enabled blocks. Errors with a
        helpful message if the picked block is disabled or absent.
        Refuses if `<ID>` matches a cluster key
        (`app_config.clusters.contains_key`).
     4. For ad-hoc: parses scheme/host/port and applies
        `--transport`/`--port`/`--tls-server-name`/`--timeout` overrides.
     5. Calls `HickoryDnsEndpointResolver::resolver_for_target(&target,
        timeout)` (renamed from `resolver_for_endpoint`).
     6. Iterates the requested record types, collecting
        `ObservedRecord`s plus the wall-clock elapsed time.
     7. Prints table / `--short` / `--json` per the flags.

7. **Wire in `src/cli/mod.rs`**: new `Command::Query(QueryArgs)`
   variant with `#[command(alias = "q")]`.

8. **Wire in `src/main.rs`**: dispatch `Command::Query` early — before
   the `AppConfig::load` call that creates a starter config — so that
   `dns query 1.1.1.1.in-addr.arpa @1.1.1.1` works on a machine with no
   config file. Pass `AppConfig::load_if_exists(...)` so `--server <ID>`
   lookup still works when a config does exist.

9. **Shell completions**: extend `cli/completions.rs` so `--server` on
   `query` reuses the existing hidden `_servers` listing (server IDs,
   same source the top-level `--server` already completes against). No
   new hidden subcommand needed.

## Resolver selection logic

```text
        no flags                  --server <ID>                @ADDR / --at ADDR
            │                            │                              │
            ▼                            ▼                              ▼
  Resolver::builder_tokio()    cfg.selected_server(Some(id))   parse scheme → transport
  (system resolver)            → DnsServerConfig               parse addr / url / port
                               build the transport set:        apply --dns/--dot/--doh/--doq
                                 no flags   → first enabled    /--port / --tls-server-name
                                              block in         overrides
                                              precedence       → ResolverTarget
                                 flags      → those blocks     (single-target only;
                                              (skip if         --all rejected here)
                                              missing/disabled)
                                 --all      → every enabled
                                              block
                               → Vec<ResolverTarget>
                                  (length 1 for no-flag /
                                   ad-hoc; ≥1 for fan-out)
            │                            │                              │
            └────────────┬───────────────┴──────────────────────────────┘
                         ▼
            For each ResolverTarget:
              HickoryDnsEndpointResolver::resolver_for_target(&target, timeout)
              (system path skips this and uses the platform resolver directly)
                         ▼
            For each --type × target, call resolver.lookup(fqdn, RR)
                         ▼
            Render output (one block per target, precedence order)
                         ▼
            Exit code = worst over per-target results
```

## Tests

Mostly mirror the `validation.rs` test layout.

- **Pure config parsing** (synchronous, no network):
  - `query` URL scheme parsing → transport mapping (table-driven via
    `rstest::rstest`).
  - `--server <ID>` resolves against a multi-server config: picks the
    `[servers.doh]` block when present, falls back through DoT and DNS.
  - `--server <ID> --transport doh` against a server with `doh.enabled
    = false` errors with the list of enabled blocks.
  - `--server <CLUSTER_ID>` (matches `app_config.clusters`) errors with
    a "use a cluster member" message that lists `cluster.members`.
  - Conflict detection for `--server` vs `--at`/`@`, and for `--port` /
    `--tls-server-name` / `--tcp` supplied alongside `--server`.

- **Resolver wiring** (unit-level, no sockets):
  - Reuse / extend `FakeDnsEndpointResolver` to back a `run_query` that
    accepts an injected resolver in tests.
  - Cover `noerror`, `nxdomain`, `servfail`, `timeout`, `tls_failure`,
    `doh_http_failure`, `unsupported_transport` → exit code mapping.
  - `#[cfg(not(feature = "doq"))]` test asserts that a `[servers.doq]`
    block selected by `--transport doq` (or the precedence fallback)
    yields `UnsupportedTransport`.
  - `#[cfg(feature = "doq")]` test asserts the resolver-config branch
    chooses `doq_name_server` and returns a `NameServerConfig` whose
    connection uses port 853.

- **Output**:
  - JSON shape snapshot test (`serde_json::to_value`, asserts on stable
    field names: `query.name`, `resolver.kind`, `answers[].ttl`, …).
  - `--short` returns one line per answer.

- **Round-trip**:
  - Extend the existing `server_transport_blocks_roundtrip` test to
    include `[servers.doq]` and assert the field set parses, renders,
    and reparses identically.
  - Add a `validate_rejects_doq_without_addr` test mirroring the
    existing DoT/DoH negative-validation tests.

- **Integration** (opt-in / `#[ignore]` by default): one live test
  against `1.1.1.1` for plain DNS and `https://cloudflare-dns.com/dns-query`
  for DoH, gated by an env var so CI does not require outbound traffic.

## DoQ feature gating

DoQ (DNS-over-QUIC, RFC 9250) is opt-in. It depends on `quinn`, `rustls`,
and a handful of QUIC-only crates that materially grow build time and
binary size; users who only need `dns`/`dot`/`doh` should not pay for
them. **The `doq` Cargo feature is not enabled by default.**

### What hickory 0.26.1 actually requires

Confirmed against
[`hickory-resolver` 0.26.1 `Cargo.toml`](https://github.com/hickory-dns/hickory-dns/blob/v0.26.1/crates/resolver/Cargo.toml)
and `crates/net/Cargo.toml`:

| Need | Feature to enable | What it pulls in |
|---|---|---|
| DoT (already on)  | `tls-ring` | `__tls`, `rustls`, `tokio-rustls` |
| DoH (already on)  | `https-ring` | `__https` (→ `__tls`) |
| **DoQ (new)** | `quic-ring` | `__quic` (→ `__tls`), `quinn` with `runtime-tokio`, `rustls-ring` backend |
| DoH3 (future) | `h3-ring` | `__h3` (→ `__quic`) |

The constructor is `ConnectionConfig::quic(server_name: Arc<str>) -> Self`,
verified present in 0.26.1. Defaults: ALPN `"doq"`, port 853 (RFC 9250 §6).
No additional ALPN or `rustls::ClientConfig` plumbing is required — the
`quic-ring` feature wires `quinn` to `rustls` with the right defaults.

### `Cargo.toml` changes

```toml
[features]
default = ["technitium", "pangolin", "cloudflare"]
technitium = []
pangolin = []
cloudflare = []
doq = ["hickory-resolver/quic-ring"]   # ← new, non-default

[dependencies]
hickory-resolver = { version = "0.26", features = [
    "tls-ring",
    "https-ring",
    "rustls-platform-verifier",
] }
```

No new direct dependencies. `quinn` arrives transitively through
`hickory-net`'s `quic-ring` feature. Confirm with
`cargo tree --features doq -e features | rg quinn` after wiring.

### Source-level gating

| Symbol | Gate |
|---|---|
| `DoqTransportConfig` struct in `control_plane/config.rs` | always present (configs round-trip on every build) |
| `pub doq: Option<DoqTransportConfig>` on `DnsServerConfig` and `DnsServerConfigRaw` | always present |
| `[servers.doq]` round-trip in `append_server_entry` | always present |
| `validate_server_transports` arm requiring `addr` when `doq.enabled` | always present |
| `ValidationTransport::Doq` enum variant (used as the target-side transport tag in `ResolverTarget`) | always present |
| `--transport doq` CLI parsing | always present |
| `fn doq_name_server` in `core/dns/resolver.rs` | `#[cfg(feature = "doq")]` |
| Match arm `ValidationTransport::Doq => doq_name_server(target)?` in `resolver_config` | `#[cfg(feature = "doq")]` |
| Match arm on `#[cfg(not(feature = "doq"))]` returning `ValidationFailureKind::UnsupportedTransport` with a `tracing::warn!` recommending the `doq` build flag | `#[cfg(not(feature = "doq"))]` |
| Default-port table (`853` for DoQ) | always present |
| Test `resolver_doq_succeeds` (live or fake-backed) | `#[cfg(feature = "doq")]` |
| Test `resolver_doq_unsupported_without_feature` | `#[cfg(not(feature = "doq"))]` |

### Runtime behaviour without the feature

A config file containing a `[servers.doq]` block parses and validates on
every build. Issuing a `dns query --server <id> --transport doq` (or
selecting that block through the precedence fallback) on a build without
`doq` returns `ValidationFailureKind::UnsupportedTransport` (already in
the enum, no new variant). The CLI maps that to exit code `2` with the
message:

```
DoQ transport is not enabled in this build of dns.
Rebuild with `--features doq` to enable DNS-over-QUIC.
```

### CI / release implications

- `cargo build` and `cargo test` continue to run with default features —
  no QUIC dependencies pulled in.
- Add `cargo build --features doq` and `cargo test --features doq` jobs
  to CI alongside the existing default-features run. The fake-backed
  tests cover the gated code paths so neither job needs network access.
- The release pipeline produces two artefacts when DoQ matters: the
  default build, and a `doq` variant. Document the choice in `README.md`.

## Open questions / deferred

- **`ANY` queries.** Most public resolvers RFC8482-refuse `ANY`. Document
  this; do not special-case in the first cut.
- **Reverse lookups.** `dns query 1.2.3.4` could auto-convert to
  `4.3.2.1.in-addr.arpa` `PTR`. Out of scope for v1; tracked in *Future
  features*.
- **`dig`-style bare-domain top-level** (`dns huly.hankin.io` with no
  subcommand). Rejected for v1 because it conflicts with future
  subcommand additions; users get `dns q huly.hankin.io` as the short
  form.
- **DoH3 (HTTP/3 transport for DoH).** Hickory has `h3-ring`; the same
  feature-gate pattern would apply. Out of scope for v1; revisit once DoQ
  is shipped and the gating template is proven.

## Future features

- Reverse-lookup sugar (`dns query 1.2.3.4` ⇒ PTR on the in-addr arpa
  name).
- `+trace`-style iterative resolution from the roots.
- `dns query --compare home cloudflare huly.hankin.io` — fan out to a
  set of resolvers and diff the answers (a natural fit alongside the
  existing `record list --all`).
- DNSSEC validation toggle (`--dnssec` / `+dnssec`).
- EDNS Client Subnet (`--subnet 203.0.113.0/24`).
- A `dns query --watch` mode that re-queries on a TTL-aware schedule.
- MCP exposure: a vendor-neutral `dns_resolve` tool reusing the same
  builder.
