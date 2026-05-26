# `dns query` — direct DNS lookups (dig-style)

This document is the design record for `dns query`, a vendor-neutral DNS
lookup subcommand that lets `dns` itself resolve names — by default through
the local system resolver, optionally through a named or ad-hoc nameserver,
across plain DNS, DoT, DoH, and (behind the opt-in `doq` Cargo feature)
DoQ transports.

## Background — gap analysis

`dns` today is an API client (Technitium / Pangolin / Cloudflare) and a sync
tool. It can *list records as the provider sees them* (`dns record list`),
but it cannot answer "what does this nameserver actually return for
huly.hankin.io right now?" without leaving the tool. The closest existing
machinery is `core::dns::validation`, which already wraps `hickory-resolver`
for DNS / DoT / DoH endpoint probes — but it is locked inside the validation
pipeline.

Three gaps:

1. **No user-facing resolver.** Users reach for `dig`, `kdig`, or `nslookup`
   to verify what a server publishes. `dns` should answer that question
   itself, reusing the resolver machinery already in-tree.
2. **No transport coverage for DoQ.** `validation.rs` supports
   `dns | doh | dot`. The user explicitly asked for DoQ.
3. **No way to address an arbitrary resolver from the CLI.** Validation
   endpoints are config-bound and tied to a specific API server.

## `dns query`

A new vendor-neutral subcommand. Reads the answer from a DNS resolver and
prints it; never touches a vendor API.

```bash
dns query huly.hankin.io                          # system resolver, A
dns query huly.hankin.io -t AAAA                  # specific record type
dns q huly.hankin.io                              # short alias
dns query huly.hankin.io --server dns1            # named validation endpoint
dns query huly.hankin.io @1.1.1.1                 # ad-hoc plain DNS
dns query huly.hankin.io --at tls://9.9.9.9       # ad-hoc DoT
dns query huly.hankin.io --at https://cloudflare-dns.com/dns-query
dns query huly.hankin.io --at quic://dns.adguard.com
dns query huly.hankin.io @9.9.9.9 --transport dot --port 853
dns query huly.hankin.io --json
```

### Behaviour

- **Defaults to the host's resolver.** No `--server`, no `--at`, no `@host`
  → `Resolver::builder_tokio()` is used. This reads `/etc/resolv.conf` on
  Unix and the platform resolver elsewhere. No config file is required.
- **Read-only.** No vendor API call, no token, no network policy.
- **One target per invocation.** `--server` and `@host`/`--at` are mutually
  exclusive; supplying both is a parse error.
- **Transport is auto-detected from the URL scheme.** `--transport` overrides
  it. Schemes recognised: `udp://`, `tcp://`, `dns://` (plain), `tls://`,
  `dot://` (DoT), `https://`, `doh://` (DoH), `quic://`, `doq://` (DoQ).
- **Output is dig-flavoured.** Default is a compact table: name, type, TTL,
  data. `--json` emits a stable JSON shape, `--short` prints only the data
  column (one per line).
- **TTL preserved as observed.** Unlike validation, this command shows the
  resolver's TTL.

### Flags

| Flag | Meaning |
|---|---|
| `<DOMAIN>` | Required. Name to resolve. Bare labels are not auto-qualified — the user passes the FQDN. |
| `-t, --type <RR>` | Record type, repeatable (default `A`). Accepts standard mnemonics: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SRV`, `CAA`, `PTR`, `SOA`, `ANY`. |
| `--server <NAME>` | Named entry from `[[servers.validation_endpoints]]`. Searched across all configured servers; name must be globally unique (loader validates this — see §Config below). |
| `--at <ADDR>` | Ad-hoc resolver. `host[:port]` or `scheme://host[:port][/path]`. |
| `@ADDR` (positional) | Sugar for `--at ADDR`. Following dig convention; can appear before or after the domain. |
| `--transport <dns\|dot\|doh\|doq>` | Force the transport. Overrides scheme inference. Required when only an IP/host is given and a non-default transport is desired. |
| `--port <u16>` | Override the port. Defaults: DNS 53, DoT 853, DoH 443, DoQ 853. |
| `--tls-server-name <NAME>` | SNI / certificate name override for DoT, DoH, DoQ. |
| `--timeout <MS>` | Per-attempt timeout (default 5000). |
| `--tcp` | Force TCP for plain DNS; ignored for other transports. |
| `--short` | Print only the data column. Mirrors `dig +short`. |
| `--json` | Emit structured output (see §Output). |

### CLI rules

- `--server` and (`--at` or `@addr`) are mutually exclusive (`clap`
  `conflicts_with_all`).
- `--at` and `@addr` are mutually exclusive (use one).
- `--transport`, `--port`, `--tls-server-name`, `--tcp` only apply with an
  ad-hoc resolver. With `--server <NAME>` they are an error (the named entry
  already specifies these).
- The top-level `--token`, `--base-url`, `--config` flags are accepted but
  unused; pass-through, no parse error (matches the existing
  `record list` behaviour).
- The top-level `--server` is shadowed by the subcommand-level `--server`
  for `query` (same pattern as `record list`).

### Output

**Default table** (one row per answer record, header per type):

```
;; @ 1.1.1.1 (dns)  in 14 ms

huly.hankin.io.   A    300   192.168.1.42
huly.hankin.io.   A    300   192.168.1.43
```

**`--short`**:

```
192.168.1.42
192.168.1.43
```

**`--json`** (stable shape, suitable for piping):

```json
{
  "query": { "name": "huly.hankin.io", "types": ["A"] },
  "resolver": {
    "kind": "ad_hoc",            // "system" | "named" | "ad_hoc"
    "name": null,                 // set when kind == "named"
    "transport": "dns",
    "address": "1.1.1.1",
    "port": 53
  },
  "elapsed_ms": 14,
  "answers": [
    { "name": "huly.hankin.io.", "type": "A", "ttl": 300, "data": "192.168.1.42" },
    { "name": "huly.hankin.io.", "type": "A", "ttl": 300, "data": "192.168.1.43" }
  ],
  "status": "noerror"             // "noerror" | "nxdomain" | "servfail" | "refused" | "timeout"
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
| Parse / config error (bad scheme, unknown `--server`, etc.) | n/a | `64` |

Mapped through the existing `core::error::Error::exit_code()`.

## Config — reusing `[[servers.validation_endpoints]]`

The named-resolver list is not duplicated. Entries already configured for
validation are queryable by `--server <NAME>`. Example, unchanged from
today:

```toml
[[servers]]
id = "home"
vendor = "technitium"
token_env = "DNSYNC_HOME_TOKEN"

[[servers.validation_endpoints]]
name = "dns1"                       # dns query foo.com --server dns1
transport = "dns"
address = "192.168.1.1"
port = 53

[[servers.validation_endpoints]]
name = "cloudflare-doh"
transport = "doh"
url = "https://cloudflare-dns.com/dns-query"

[[servers.validation_endpoints]]
name = "quad9-dot"
transport = "dot"
address = "9.9.9.9"
port = 853
tls_server_name = "dns.quad9.net"

[[servers.validation_endpoints]]
name = "adguard-doq"                # new: DoQ
transport = "doq"
address = "94.140.14.140"
port = 853
tls_server_name = "dns.adguard.com"
```

### Config changes required

1. Extend `ValidationTransport` with a `Doq` variant (`#[serde(rename =
   "doq")]`). **The variant is always compiled in**, even on builds without
   the `doq` Cargo feature — so configs that mention `transport = "doq"`
   parse cleanly everywhere, and `--transport doq` is recognised by clap on
   every build. Only the resolver-wiring path is feature-gated; see §DoQ
   feature gating below. Update the `FromStr` parser in
   `control_plane/config.rs` to accept `doq`. Update the validation error
   message to list `doq`.
2. Update `validate_validation_endpoints` so `doq` requires an `address`
   (same as `dot`).
3. Add a cross-server uniqueness check for `validation_endpoints[*].name`
   in `AppConfig::validate`. Today names are not required unique across
   servers; for `--server <NAME>` to be unambiguous, they must be. If a
   conflict already exists in user configs, the error message should name
   both servers so the user can rename one.
4. Update `append_server_entry` in `control_plane/config.rs` to round-trip
   the new `doq` value through `render_toml`.

## Code layout

The resolver-building code currently lives inline in
`core/dns/validation.rs` (`resolver_config`, `plain_dns_name_server`,
`dot_name_server`, `doh_name_server`, `classify_hickory_error`). It is
already trait-shaped (`DnsEndpointResolver`).

**Refactor first, add second.**

1. **Extract** the resolver builders and the error classifier into a new
   module `src/core/dns/resolver.rs`. Move:
   - `resolver_config`
   - `plain_dns_name_server`, `dot_name_server`, `doh_name_server`
   - `endpoint_ip`, `tls_server_name`, `doh_url_parts`
   - `classify_hickory_error`
   - `HickoryDnsEndpointResolver` (the trait stays in `validation.rs`
     because it owns the `ObservedRecord` type)

   `validation.rs` re-exports / uses them; behaviour and tests unchanged.

2. **Add `doq_name_server`** in the new module, **gated behind `#[cfg(feature
   = "doq")]`**. Hickory 0.26 exposes
   `ConnectionConfig::quic(server_name: Arc<str>) -> Self`
   (`hickory-resolver` `src/config.rs`, behind the internal `__quic`
   feature). Default port is 853 — RFC 9250 registers ALPN `doq` on the
   same port as DoT. The function mirrors `dot_name_server`:

   ```rust
   #[cfg(feature = "doq")]
   fn doq_name_server(
       endpoint: &ValidationEndpointConfig,
   ) -> DnsEndpointResolverResult<NameServerConfig> {
       let ip = endpoint_ip(endpoint)?;
       let server_name = tls_server_name(endpoint)?.into();
       let mut quic = ConnectionConfig::quic(server_name);
       quic.port = endpoint.port.unwrap_or(853);
       Ok(NameServerConfig::new(ip, true, vec![quic]))
   }
   ```

3. **Add a project Cargo feature `doq`** (non-default) and wire it to the
   hickory `quic-ring` feature. See §DoQ feature gating below for the full
   plumbing.

4. **Add `src/cli/query.rs`** with:
   - `QueryArgs` (clap struct, see §Flags above)
   - `AdHocResolver` value-parser: turns `@addr` / `--at addr` into a
     `ValidationEndpointConfig`-shaped struct with scheme→transport
     mapping.
   - `pub async fn run_query(config: Option<&AppConfig>, args: QueryArgs) -> Result<i32>`
     that:
     1. Builds an effective `ValidationEndpointConfig` from the source
        (system / named / ad-hoc).
     2. For the `system` case, calls `Resolver::builder_tokio()` directly
        (no `ValidationEndpointConfig`).
     3. For named / ad-hoc, calls
        `HickoryDnsEndpointResolver::resolver_for_endpoint`.
     4. Iterates the requested record types, collecting
        `ObservedRecord`s plus the wall-clock elapsed time.
     5. Prints table / `--short` / `--json` per the flags.

5. **Wire in `src/cli/mod.rs`**: new `Command::Query(QueryArgs)` variant
   with `#[command(alias = "q")]`.

6. **Wire in `src/main.rs`**: dispatch `Command::Query` early — before the
   `AppConfig::load` call that creates a starter config — so that
   `dns query 1.1.1.1.in-addr.arpa @1.1.1.1` works on a machine with no
   config file. Pass `AppConfig::load_if_exists(...)` so named-resolver
   lookup still works when a config does exist.

7. **Shell completions**: add a hidden `_resolvers` subcommand parallel to
   `_servers`, printing each `validation_endpoints[*].name`. Update
   `cli/completions.rs` to teach Bash / Zsh / Fish about
   `--server <named>` for `query`.

## Resolver selection logic

```text
            no flags                          --server NAME                  --at ADDR / @ADDR
                │                                  │                                  │
                ▼                                  ▼                                  ▼
   Resolver::builder_tokio()          search config.servers[*].             parse scheme → transport
   (system resolver)                  validation_endpoints by name          parse addr / url / port
                                      → ValidationEndpointConfig            apply --transport / --port /
                                                                            --tls-server-name overrides
                                                                            → ValidationEndpointConfig
                │                                  │                                  │
                └──────────────┬───────────────────┴──────────────────────────────────┘
                               ▼
                  HickoryDnsEndpointResolver::resolver_for_endpoint(ep, timeout)
                  (system path skips this and uses the platform resolver directly)
                               ▼
                  For each --type, call resolver.lookup(fqdn, RR)
                               ▼
                          Render output
```

## Tests

Mostly mirror the `validation.rs` test layout.

- **Pure config parsing** (synchronous, no network):
  - `query` URL scheme parsing → transport mapping (table-driven via
    `rstest::rstest`).
  - `--server NAME` resolves against a multi-server config, error path
    for unknown name and for ambiguous name (cross-server duplicate).
  - Conflict detection for `--server` vs `--at`/`@`, and for transport
    flags supplied alongside `--server`.

- **Resolver wiring** (unit-level, no sockets):
  - Reuse / extend `FakeDnsEndpointResolver` to back a `run_query` that
    accepts an injected resolver in tests.
  - Cover `noerror`, `nxdomain`, `servfail`, `timeout`, `tls_failure`,
    `doh_http_failure`, `unsupported_transport` → exit code mapping.
  - `#[cfg(not(feature = "doq"))]` test asserts that a `doq` endpoint
    yields `UnsupportedTransport`.
  - `#[cfg(feature = "doq")]` test asserts the resolver-config branch
    chooses `doq_name_server` and returns a `NameServerConfig` whose
    connection uses port 853.

- **Output**:
  - JSON shape snapshot test (`serde_json::to_value`, asserts on stable
    field names: `query.name`, `resolver.kind`, `answers[].ttl`, …).
  - `--short` returns one line per answer.

- **Round-trip**: TOML config containing a `doq` endpoint serialises and
  re-parses identically (extend `config_validation_endpoint_roundtrip`).

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
| `ValidationTransport::Doq` enum variant | always present (parses in configs and clap on every build) |
| `ValidationTransport`'s clap `ValueEnum`/serde mapping for `doq` | always present |
| `fn doq_name_server` in `core/dns/resolver.rs` | `#[cfg(feature = "doq")]` |
| Match arm `ValidationTransport::Doq => doq_name_server(endpoint)?` in `resolver_config` | `#[cfg(feature = "doq")]` |
| Match arm on `#[cfg(not(feature = "doq"))]` returning `ValidationFailureKind::UnsupportedTransport` with a `tracing::warn!` recommending the `doq` build flag | `#[cfg(not(feature = "doq"))]` |
| Default-port table (`853` for DoQ) | always present |
| `validate_validation_endpoints` requirement that `doq` endpoints have an `address` | always present (configs validate the same on either build) |
| `--transport doq` CLI parsing | always present |
| Test `validation_resolver_doq_succeeds` (live or fake-backed) | `#[cfg(feature = "doq")]` |
| Test `validation_resolver_doq_unsupported_without_feature` | `#[cfg(not(feature = "doq"))]` |

### Runtime behaviour without the feature

A config file containing a `transport = "doq"` endpoint parses and
validates on every build. Issuing a query that uses it on a build without
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
