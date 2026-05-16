# dnsync Vendor Adapter Requirements

This document defines what must be added when introducing a new DNS/vendor backend to `dnsync`.
It is the authoritative reference for code reviewers and implementors.

## Summary

Every production-ready vendor must provide:

- Cargo feature wiring
- inclusion in default features
- a `VendorKind` entry
- default endpoint/auth configuration
- credential resolution
- a vendor client
- vendor-neutral service trait implementations
- declared capabilities
- normalized record output
- runtime dispatch
- module exports
- tests and documentation

---

## Project layout relevant to a new vendor

```
src/
  core/dns/service.rs       ← vendor-neutral trait contracts  (do not modify)
  core/dns/records.rs       ← DNS record types                (do not modify)
  core/dns/responses.rs     ← ListRecordsResponse etc.        (do not modify)
  core/dns/capabilities.rs  ← VendorCapabilities struct       (do not modify)
  core/error.rs             ← Error enum and Result alias     (do not modify)
  core/secret.rs            ← ApiToken wrapper                (do not modify)
  control_plane/config.rs   ← VendorKind enum + DnsServerConfig  (YOU ADD HERE)
  vendors/mod.rs            ← feature-gated vendor modules       (YOU ADD HERE)
  vendors/<yourvendor>/
    mod.rs                  ← module declarations  (YOU CREATE)
    client.rs               ← HTTP transport       (YOU CREATE)
    service.rs              ← trait implementations (YOU CREATE)
  main.rs                   ← credential resolution + dispatch  (YOU ADD HERE)
Cargo.toml                  ← feature flag                       (YOU ADD HERE)
```

---

## 1. Cargo Feature

Add a feature for the vendor in `Cargo.toml`. `reqwest` is a direct dependency and does not
need to be listed per-feature.

```toml
[features]
default = ["technitium", "pangolin", "newvendor"]

technitium = []
pangolin = []
newvendor = []
```

New production-ready vendors should be added to `default` so normal builds include them automatically.

Only omit a vendor from default features if it is experimental, requires unusually heavy dependencies, or has platform-specific constraints.

---

## 2. VendorKind Entry

Add the vendor to the central vendor enum in `control_plane/config.rs`.

```rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum VendorKind {
    #[default]
    Technitium,
    Pangolin,
    NewVendor,
}
```

The enum must support:

- config deserialization (`serde(rename_all = "lowercase")`)
- CLI selection (`clap::ValueEnum`)
- runtime dispatch (match arms in `main.rs`)
- case-insensitive user-facing naming
- interactive setup wizard (see section 13)

---

## 3. Vendor Defaults

Vendor defaults are implemented as constants and match arms — there is no `VendorDefaults` struct.

Add a default base URL constant alongside the existing ones:

```rust
pub const NEWVENDOR_DEFAULT_BASE_URL: &str = "https://api.newvendor.com/v1";
```

Add match arms in `resolved_base_url()` and `resolved_location()` on `DnsServerConfig`:

```rust
// resolved_base_url
.unwrap_or_else(|| match self.vendor {
    VendorKind::Technitium => TECHNITIUM_DEFAULT_BASE_URL.to_string(),
    VendorKind::Pangolin   => PANGOLIN_DEFAULT_BASE_URL.to_string(),
    VendorKind::NewVendor  => NEWVENDOR_DEFAULT_BASE_URL.to_string(),
})

// resolved_location — used to infer local vs external from the default URL
let url = self.base_url.as_deref().unwrap_or(match self.vendor {
    VendorKind::Technitium => TECHNITIUM_DEFAULT_BASE_URL,
    VendorKind::Pangolin   => PANGOLIN_DEFAULT_BASE_URL,
    VendorKind::NewVendor  => NEWVENDOR_DEFAULT_BASE_URL,
});
```

Add a match arm in `append_server_entry()` for TOML serialisation:

```rust
tbl["vendor"] = value(match server.vendor {
    VendorKind::Technitium => "technitium",
    VendorKind::Pangolin   => "pangolin",
    VendorKind::NewVendor  => "newvendor",
});
```

Required defaults:

- default API base URL, where safe and known
- vendor-specific base URL environment variable (`DNSYNC_NEWVENDOR_BASE_URL`)
- vendor-specific token environment variable (`DNSYNC_NEWVENDOR_API_TOKEN`)
- whether the vendor requires an organisation/account ID

### Pangolin default

Pangolin defaults to the hosted cloud API root:

```text
https://api.pangolin.net/v1
```

Resolution order:

```text
--base-url
→ DNSYNC_PANGOLIN_BASE_URL
→ config base_url
→ https://api.pangolin.net/v1
```

`org_id` is required because Pangolin routes are org-scoped. `DnsServerConfig.org_id` already exists for this purpose.

---

## 4. Credential Resolution

Each vendor needs a `resolve_<vendor>_credentials` function in `main.rs`, gated with
`#[cfg(feature = "newvendor")]`. Follow the existing Technitium or Pangolin pattern exactly.

Resolution order for the token:

```text
CLI --token
→ DNSYNC_NEWVENDOR_API_TOKEN env var
→ config token_env lookup (reads the named env var)
→ config literal token
→ Error::parse(...)
```

For base URLs:

```text
CLI --base-url
→ DNSYNC_NEWVENDOR_BASE_URL env var
→ config base_url
→ vendor default base URL
```

For organisation/account IDs where required (`DnsServerConfig.org_id`):

```text
DNSYNC_NEWVENDOR_ORG_ID env var
→ config org_id
→ Error::parse(...)
```

---

## 5. Vendor Client

Create `src/vendors/<vendor>/client.rs`. Model it on the Technitium or Pangolin client.

Key rules:

1. Build a `reqwest::Client` with a 30-second timeout in `new()`.
2. Always use bearer auth: `.bearer_auth(self.token.expose_for_auth())`.
3. Never log the token. `ApiToken` has a `Debug` impl that prints `[REDACTED]`.
4. Every HTTP method must follow this tracing template exactly:

```rust
use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;
use reqwest::{Client, Response};
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct NewVendorClient {
    pub http: Client,
    pub base_url: String,
    token: ApiToken,
    // add vendor-specific fields (org_id, etc.)
}

impl NewVendorClient {
    pub fn new(base_url: String, token: ApiToken) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(Error::Network)?;
        Ok(Self { http, base_url, token })
    }

    pub async fn get(&self, path: &str, params: &[(&str, String)]) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let span = tracing::debug_span!("http.get", path, http.status = tracing::field::Empty);
        let _enter = span.enter();
        tracing::debug!("sending GET");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.token.expose_for_auth())
            .query(params)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "GET failed");
                Error::Network(e)
            })?;
        span.record("http.status", resp.status().as_u16());
        tracing::debug!("received response");
        parse_response(resp).await
    }

    // Add post(), delete(), patch() etc. following the same span pattern.
    // For post_file, extract the zone from params and add it to the span:
    //   let zone = params.iter().find(|(k,_)| *k == "zone").map(|(_,v)| v.as_str()).unwrap_or("");
    //   let span = tracing::debug_span!("http.post_file", path, zone, http.status = ...);
}

async fn parse_response(resp: Response) -> Result<Value> {
    // Inspect status, parse JSON, map vendor-specific errors to:
    //   Error::Api { message }       — vendor returned an error payload
    //   Error::Http { status, body } — non-2xx without a structured error
    //   Error::Forbidden { .. }      — HTTP 403; use Error::forbidden(msg)
    //   Error::InvalidJson(e)        — JSON decode failure
    //   Error::Network(e)            — transport failure
    // Do NOT add tracing inside parse_response — it is pure sync parsing.
}
```

Tracing field rules:

| Field | Value |
|---|---|
| Span name | `"http.get"`, `"http.post"`, `"http.post_file"`, etc. |
| `path` | the API path string |
| `http.status` | `tracing::field::Empty` as placeholder; recorded via `span.record(...)` after response |
| On network error | `tracing::warn!(error = %e, "GET failed")` inside the closure, then propagate |

Do **not** add tracing inside `parse_response`.

Typical file structure:

```text
src/vendors/<vendor>/
├── mod.rs
├── client.rs
└── service.rs
```

Larger vendors may also add:

```text
api.rs
mapping.rs
responses.rs
config.rs
```

---

## 6. Service Trait Implementations

Create `src/vendors/<vendor>/service.rs`. Implement **all** of the following traits on your
client struct. This is mandatory even for unsupported operations.

Required traits (all in `crate::core::dns::service`):

- `DnsVendor`
- `ZoneRead`
- `ZoneWrite`
- `RecordWrite`
- `CacheRead`
- `CacheWrite`
- `StatsRead`
- `AccessListRead`
- `AccessListWrite`
- `ZoneImport`
- `SettingsRead`

`DnsService` is a blanket impl — do not implement it directly.

Unsupported operations must return explicit unsupported errors:

```rust
Err(Error::unsupported("VendorName", "zone import"))
```

Full trait signatures for reference:

```rust
// DnsVendor
fn kind(&self) -> VendorKind;
fn capabilities(&self) -> VendorCapabilities;

// ZoneRead
async fn list_zones(&self, page: u32, per_page: u32) -> Result<Value>;
async fn list_records<'a>(&'a self, domain: &'a str, zone: Option<&'a str>,
    options: ListRecordsOptions) -> Result<ListRecordsResponse>;

// ZoneWrite
async fn create_zone<'a>(&'a self, zone: &'a str, zone_type: &'a str) -> Result<Value>;
async fn delete_zone<'a>(&'a self, zone: &'a str) -> Result<Value>;
async fn enable_zone<'a>(&'a self, zone: &'a str) -> Result<Value>;
async fn disable_zone<'a>(&'a self, zone: &'a str) -> Result<Value>;

// RecordWrite
async fn add_record<'a>(&'a self, zone: &'a str, domain: &'a str,
    ttl: u32, record: &'a RecordData) -> Result<Value>;
async fn delete_record<'a>(&'a self, zone: &'a str, domain: &'a str,
    type_params: &'a [(&'a str, String)]) -> Result<Value>;

// CacheRead
async fn list_cache<'a>(&'a self, domain: &'a str) -> Result<Value>;

// CacheWrite
async fn delete_cache_zone<'a>(&'a self, domain: &'a str) -> Result<Value>;
async fn flush_cache(&self) -> Result<Value>;

// StatsRead
async fn get_stats<'a>(&'a self, stats_type: &'a str) -> Result<Value>;

// AccessListRead
async fn list_blocked(&self) -> Result<Value>;
async fn list_allowed(&self) -> Result<Value>;

// AccessListWrite
async fn add_blocked<'a>(&'a self, domain: &'a str) -> Result<Value>;
async fn delete_blocked<'a>(&'a self, domain: &'a str) -> Result<Value>;
async fn add_allowed<'a>(&'a self, domain: &'a str) -> Result<Value>;
async fn delete_allowed<'a>(&'a self, domain: &'a str) -> Result<Value>;

// ZoneImport
async fn import_zone_file<'a>(&'a self, zone: &'a str, file_name: String,
    file_bytes: Vec<u8>, overwrite: bool, overwrite_zone: bool,
    overwrite_soa_serial: bool) -> Result<Value>;

// SettingsRead
async fn get_settings(&self) -> Result<Value>;
```

### Tracing standard for service.rs

Apply `#[instrument]` to every method that performs real I/O. Do **not** annotate methods that
return `Error::unsupported` immediately.

```rust
use tracing::instrument;

// Supported methods: #[instrument] with vendor and operation fields.
// Parameters (zone, domain, etc.) are captured automatically from function arguments.
// Always skip(self). Skip non-Debug params: record, file_bytes, type_params.

#[instrument(skip(self), fields(vendor = "newvendor", operation = "list_zones"))]
async fn list_zones(&self, page: u32, per_page: u32) -> Result<Value> { ... }

#[instrument(skip(self), fields(vendor = "newvendor", operation = "create_zone"))]
async fn create_zone(&self, zone: &str, zone_type: &str) -> Result<Value> { ... }

#[instrument(skip(self, record), fields(vendor = "newvendor", operation = "add_record"))]
async fn add_record(&self, zone: &str, domain: &str, ttl: u32, record: &RecordData)
    -> Result<Value> { ... }

#[instrument(skip(self, file_bytes), fields(vendor = "newvendor", operation = "import_zone_file"))]
async fn import_zone_file(&self, zone: &str, file_name: String, file_bytes: Vec<u8>, ...)
    -> Result<Value> { ... }

// Unsupported methods: NO #[instrument], return immediately.
async fn flush_cache(&self) -> Result<Value> {
    Err(Error::unsupported("NewVendor", "cache flush"))
}
```

Field naming rules:

- `vendor` — lowercase string literal matching your vendor name
- `operation` — snake_case trait method name
- `zone`, `domain`, `stats_type` — captured automatically from params; do not re-list in `fields()`
- `skip(self, record)` — skip `self` always; skip `&RecordData`, `Vec<u8>`, and `&[(&str, String)]` (not Debug)

---

## 7. Logging and Tracing

### Runtime setup

Logging is initialized in `main.rs` using `tracing-subscriber` with an `EnvFilter`:

```rust
fmt()
    .with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
    )
    .with_writer(std::io::stderr)
    .init();
```

Key points:
- Default level is `warn`. Users raise it with `RUST_LOG=debug` (or `RUST_LOG=dnslib=debug`).
- **All log output goes to stderr.** Stdout is reserved for structured JSON/table output. Vendor code must never write diagnostics to stdout.

### Log levels

| Level | Use for |
|---|---|
| `error!` | Rarely used directly — prefer returning `Err(...)`. Only for fatal process-level failures. |
| `warn!` | Transport/network failures inside an HTTP method closure, before propagating the error. |
| `info!` | Significant lifecycle events (server start, mode). Not used in vendor HTTP code. |
| `debug!` | Request lifecycle (before send, after response), soft non-fatal resolution failures. |

### Patterns used in the codebase

Inside HTTP method closures (network failure):
```rust
.map_err(|e| {
    tracing::warn!(error = %e, "GET failed");
    Error::Network(e)
})?;
```

Request lifecycle around an HTTP call:
```rust
tracing::debug!("sending GET");
// ... .send().await ...
tracing::debug!("received response");
```

Soft diagnostic failures (non-fatal, should not block the operation):
```rust
tracing::debug!(%error, "failed to build DNS resolver for local IP lookup");
```

Lifecycle events (main.rs only):
```rust
tracing::info!("MCP server starting in read-only mode");
```

### What not to log

- Never log the token value. `ApiToken::Debug` prints `[REDACTED]`; `expose_for_auth()` must only appear in `.bearer_auth(...)`.
- Do not add `tracing::` calls inside `parse_response` — it is pure sync parsing with no I/O.
- Do not log successful record data or zone contents at any level; that is user data and belongs in the return value, not in logs.

---

## 8. Capabilities

Every vendor must declare its supported functionality in `DnsVendor::capabilities()`.

```rust
pub struct VendorCapabilities {
    pub zones: bool,
    pub records: bool,
    pub cache: bool,
    pub access_lists: bool,
    pub settings: bool,
    pub zone_import: bool,
}
```

Set each boolean to `true` only for operations you fully implement. Capabilities must reflect
actual behaviour, not aspirational support.

Example for Pangolin (read-only):

```rust
VendorCapabilities {
    zones: true,
    records: true,
    cache: false,
    access_lists: false,
    settings: true,
    zone_import: false,
}
```

---

## 9. Records Must Be Normalized by Default

`list_records` must return `Result<ListRecordsResponse>`. Map vendor-specific data to the
vendor-neutral types before returning.

```text
vendor API response
→ vendor-specific parser
→ normalized ZoneRecord / ListRecordsResponse
→ CLI/MCP output
```

### Key types

**`ListRecordsResponse`** — wraps one or more zones. Construct with:

```rust
ListRecordsResponse::single(zone_info, records)  // most vendors: one zone per call
```

**`ZoneInfo`** fields:

| Field | Type | Notes |
|---|---|---|
| `name` | `String` | zone FQDN |
| `zone_type` | `String` | e.g. `"Primary"` |
| `disabled` | `bool` | |
| `dnssec_status` | `Option<String>` | `None` if not applicable |

**`ZoneRecord`** fields:

| Field | Type | Notes |
|---|---|---|
| `name` | `String` | relative name or `"@"` for apex |
| `record_type` | `String` | uppercase, e.g. `"A"`, `"MX"` |
| `ttl` | `u32` | 0 if unavailable |
| `disabled` | `bool` | |
| `comments` | `String` | empty string if unavailable |
| `expiry_ttl` | `u64` | 0 if unavailable |
| `data` | `serde_json::Value` | serialized as `rData`; vendor-neutral shape |
| `parsed` | `Option<AnyRecordData>` | typed form; set to `None` if you don't populate it |

### rData shape

The `data` field should contain a JSON object whose keys match what `RecordData`'s serde
deserialisation expects, so that typed `parsed` can be populated by callers. Standard shapes:

| Type | rData keys |
|---|---|
| A / AAAA | `{"ipAddress": "1.2.3.4"}` |
| CNAME | `{"cname": "target.example.com"}` |
| DNAME | `{"dname": "target.example.com"}` |
| MX | `{"preference": 10, "exchange": "mail.example.com"}` |
| TXT | `{"text": "v=spf1 ~all", "splitText": false}` |
| NS | `{"nameServer": "ns1.example.com", "glue": null}` |
| PTR | `{"ptrName": "host.example.com"}` |
| SRV | `{"priority": 10, "weight": 20, "port": 5060, "target": "sip.example.com"}` |
| CAA | `{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}` |
| SSHFP | `{"sshfpAlgorithm": "RSA", "sshfpFingerprintType": "SHA256", "sshfpFingerprint": "abcdef"}` |
| TLSA | `{"tlsaCertificateUsage": "DANE-EE", "tlsaSelector": "SPKI", "tlsaMatchingType": "SHA2-256", "tlsaCertificateAssociationData": "deadbeef"}` |
| DS | `{"keyTag": 1234, "algorithm": "ECDSAP256SHA256", "digestType": "SHA256", "digest": "abcdef"}` |
| HTTPS / SVCB | `{"svcPriority": 1, "svcTargetName": ".", "svcParams": "alpn=h2", "autoIpv4Hint": false, "autoIpv6Hint": false}` |
| NAPTR | `{"naptrOrder": 100, "naptrPreference": 10, "naptrFlags": "U", "naptrServices": "E2U+sip", "naptrRegexp": "!^.*$!", "naptrReplacement": "."}` |
| URI | `{"uriPriority": 10, "uriWeight": 1, "uri": "https://example.com"}` |
| unknown | `{"value": "<raw content>"}` |

Additional vendor metadata (IDs, proxied state, health, etc.) can be added as extra keys in the
same `data` object.

### Vendors that use numeric enum values

Some vendors (e.g. Cloudflare) encode SSHFP, TLSA, DS, and similar types using IANA numeric
values in their `data` objects, while `RecordData` uses string enum names (e.g. `"RSA"`,
`"DANE-EE"`, `"SHA256"`). Both directions need conversion helpers.

Numeric → string (for `normalize_rdata`, Cloudflare → internal):

| Enum | Numeric → string |
|---|---|
| SSHFP algorithm | 1→RSA, 2→DSA, 3→ECDSA, 4→Ed25519, 6→Ed448 |
| SSHFP fingerprint type | 1→SHA1, 2→SHA256 |
| TLSA cert usage | 0→PKIX-TA, 1→PKIX-EE, 2→DANE-TA, 3→DANE-EE |
| TLSA selector | 0→Cert, 1→SPKI |
| TLSA matching type | 0→Full, 1→SHA2-256, 2→SHA2-512 |
| DS algorithm (IANA) | 1→RSAMD5, 3→DSA, 5→RSASHA1, 6→DSA-NSEC3-SHA1, 7→RSASHA1-NSEC3-SHA1, 8→RSASHA256, 10→RSASHA512, 12→ECC-GOST, 13→ECDSAP256SHA256, 14→ECDSAP384SHA384, 15→ED25519, 16→ED448 |
| DS digest type | 1→SHA1, 2→SHA256, 3→GOST-R-34-11-94, 4→SHA384 |

String → numeric (for `record_data_to_<vendor>_body`, internal → Cloudflare):
The reverse of the table above. Implement as separate helper functions, one per enum type.

Cloudflare API shapes for structured record types:

| Type | Cloudflare `data` keys |
|---|---|
| SRV | `{priority, weight, port, target}` |
| CAA | `{flags, tag, value}` |
| SSHFP | `{algorithm: u8, type: u8, fingerprint: hex_string}` |
| TLSA | `{usage: u8, selector: u8, matching_type: u8, certificate: hex_string}` |
| DS | `{key_tag: u16, algorithm: u8, digest_type: u8, digest: hex_string}` |
| HTTPS / SVCB | `{priority: u16, target: string, value: params_string}` |
| NAPTR | `{order, preference, flags, service, regexp, replacement}` |
| URI | `{priority: u16, weight: u16, content: string}` |

Rules:

- Standard DNS records (`A`, `AAAA`, `CNAME`, `DNAME`, `MX`, `TXT`, `NS`, `SRV`, `CAA`, `PTR`, `SSHFP`, `TLSA`, `DS`, `HTTPS`, `SVCB`, `NAPTR`, `URI`) should map to typed normalized records where possible.
- Vendor-specific or non-DNS-native resources should still return as normalized records.
- Raw vendor API shapes should not be the primary output format.
- If a field is unavailable, use a safe neutral default and preserve useful original vendor data in `data`.

### Pangolin normalization

```text
Pangolin domain      → ZoneInfo
Pangolin resource    → ZoneRecord
resource.fullDomain  → FQDN / record name
resource.http        → HTTP-like record type
resource.protocol    → TCP/UDP/etc. for non-HTTP resources
resource.enabled     → disabled = !enabled
targets/sites/health → vendor metadata in data
```

---

## 10. Runtime Dispatch

Add credential resolution and a dispatch branch in `main.rs`.

Update every `#[cfg(any(feature = "technitium", feature = "pangolin"))]` guard to include
the new feature:

```rust
#[cfg(any(feature = "technitium", feature = "pangolin", feature = "newvendor"))]
```

Update the `compile_error!` guard:

```rust
#[cfg(not(any(feature = "technitium", feature = "pangolin", feature = "newvendor")))]
compile_error!("No DNS vendor feature is enabled...");
```

Add a dispatch branch in `run()`:

```rust
#[cfg(feature = "newvendor")]
config::VendorKind::NewVendor => {
    use dnslib::vendors::newvendor::client::NewVendorClient;
    let (base_url, token) = match resolve_newvendor_credentials(&cli, app_config.as_ref()) {
        Ok(v) => v,
        Err(e) => return render_error(e),
    };
    let client = match NewVendorClient::new(base_url, token) {
        Ok(c) => c,
        Err(e) => return render_error(e),
    };
    run_with_client(cli, client, policy).await
}
```

---

## 11. Module Exports

Expose the vendor module from `src/vendors/mod.rs`:

```rust
#[cfg(feature = "newvendor")]
pub mod newvendor;
```

`src/lib.rs` only needs updating if the new vendor warrants a dedicated re-export in the
`pub mod client` block (currently only Technitium has one). The `compile_error!` at the top
of `lib.rs` must include the new feature.

---

## 12. Error Types

Use the existing `Error` variants — do not define new error types:

| Variant | Constructor / usage |
|---|---|
| `Error::Network(reqwest::Error)` | transport/timeout failure |
| `Error::InvalidJson(reqwest::Error)` | JSON decode failure |
| `Error::Api { message }` | vendor returned error payload |
| `Error::Http { status, body }` | non-2xx without structured error |
| `Error::Forbidden { .. }` | `Error::forbidden(msg)` |
| `Error::Unsupported { .. }` | `Error::unsupported("VendorName", "operation")` |
| `Error::Parse { .. }` | `Error::parse("description")` |
| `Error::Io { .. }` | `Error::io("context", io_error)` |

---

## 13. CLI and Documentation

For every vendor, update:

- CLI help text
- README examples
- config examples
- environment variable table
- MCP examples
- supported/unsupported operation notes
- interactive setup wizard (`src/cli/interactive.rs`)

### Interactive setup wizard

`dns config add` (run with no flags) prompts the user through each field. The vendor
selection list and the `org_id` prompt are hardcoded in `src/cli/interactive.rs` and
**must be updated by hand** for each new vendor.

**Vendor selection** — add a `VendorChoice` entry to `run_add_wizard()`:

```rust
let choices = vec![
    VendorChoice { kind: VendorKind::Technitium, label: "technitium" },
    VendorChoice { kind: VendorKind::Pangolin,   label: "pangolin" },
    VendorChoice { kind: VendorKind::Cloudflare, label: "cloudflare" },
    VendorChoice { kind: VendorKind::NewVendor,  label: "newvendor" },
];
```

The default base URL shown to the user is derived from the match arm in `optional_text`
for `base_url`, which uses `NEWVENDOR_DEFAULT_BASE_URL` — that constant is already added
in step 3, so no extra change is needed there.

**Organisation / account ID** — the `org_id` prompt is currently gated on Pangolin.
If your vendor also requires an org or account ID, extend the condition:

```rust
let org_id = if matches!(vendor, VendorKind::Pangolin | VendorKind::NewVendor) {
    optional_text("Organisation ID:", "Leave empty to skip", None)?
} else {
    None
};
```

If your vendor does not use `org_id`, no change is needed.

Prefer generic naming for shared env vars:

```text
DNSYNC_BASE_URL
DNSYNC_API_TOKEN
DNSYNC_SERVER
```

Keep vendor-specific aliases where useful:

```text
DNSYNC_TECHNITIUM_API_TOKEN
DNSYNC_PANGOLIN_API_TOKEN
DNSYNC_NEWVENDOR_API_TOKEN
```

---

## 14. Tests

Each vendor must include tests for:

- default base URL constant value
- token resolution order (CLI > env > config)
- required org/account ID error when missing
- config round-trip (`VendorKind` serde: `"newvendor"` → enum → `"newvendor"`)
- response envelope parsing (success, API error, forbidden, empty errors)
- capability declaration matches `VendorCapabilities` struct exactly
- normalized record conversion (A, AAAA, MX, TXT, SRV, CAA, SSHFP, TLSA, DS, HTTPS, NAPTR, URI, DNAME, unknown type, proxied flag, vendor ID)
- supported read operations
- all unsupported operations return `Error::Unsupported` with correct vendor name
- feature-gated compilation (`cargo build --features newvendor`)

For read-only vendors, tests should prove write operations fail clearly and safely.

---

## New Vendor Checklist

```text
[ ] Add Cargo feature (empty: `newvendor = []`)
[ ] Add vendor to default features if production-ready
[ ] Add VendorKind enum variant
[ ] Add default base URL constant
[ ] Add match arm in resolved_base_url()
[ ] Add match arm in resolved_location()
[ ] Add match arm in append_server_entry()
[ ] Add vendor-specific env vars (DNSYNC_NEWVENDOR_API_TOKEN, DNSYNC_NEWVENDOR_BASE_URL)
[ ] Add credential resolver function in main.rs (feature-gated)
[ ] Update all cfg(any(...)) guards in main.rs
[ ] Update compile_error! guards in main.rs and lib.rs
[ ] Add vendor module declaration in vendors/mod.rs (feature-gated)
[ ] Create vendors/newvendor/mod.rs
[ ] Create vendors/newvendor/client.rs with tracing template
[ ] Create vendors/newvendor/service.rs with all 12 traits
[ ] Apply #[instrument] to I/O methods; Error::unsupported on unsupported methods
[ ] Use tracing::warn! inside HTTP error closures; tracing::debug! for request lifecycle
[ ] Never log token values; never write diagnostics to stdout
[ ] Set VendorCapabilities correctly
[ ] Normalize records by default (ZoneRecord with correct rData shape)
[ ] Preserve vendor metadata in normalized output data field
[ ] Add runtime dispatch branch in main.rs
[ ] Update CLI help text
[ ] Add VendorChoice entry in src/cli/interactive.rs run_add_wizard()
[ ] Extend org_id prompt condition in interactive.rs if the vendor requires an org/account ID
[ ] Update README/config examples
[ ] Add tests (credential resolution, envelope parsing, normalization, unsupported ops)
[ ] Verify vendor-only feature build: cargo build --features newvendor
[ ] Verify default-feature build: cargo build
[ ] Verify all tests pass: cargo test
```
