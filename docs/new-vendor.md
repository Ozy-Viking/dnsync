# dnsync Vendor Adapter Requirements

This document defines what must be added when introducing a new DNS/vendor backend to `dnsync`.

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

## 1. Cargo Feature

Add a feature for the vendor in `Cargo.toml`.

```toml
[features]
default = ["technitium", "pangolin", "newvendor"]

technitium = []
pangolin = []
newvendor = []
```

New production-ready vendors should be added to `default` so normal builds include them automatically.

Only omit a vendor from default features if it is experimental, requires unusually heavy dependencies, or has platform-specific constraints.

## 2. VendorKind Entry

Add the vendor to the central vendor enum.

```rust
pub enum VendorKind {
    Technitium,
    Pangolin,
    NewVendor,
}
```

The enum must support:

- config deserialization
- CLI selection
- runtime dispatch
- case-insensitive or predictable user-facing naming

## 3. Vendor Defaults

Every vendor must define default metadata and configuration values.

Recommended shape:

```rust
pub struct VendorDefaults {
    pub kind: VendorKind,
    pub display_name: &'static str,
    pub default_base_url: Option<&'static str>,
    pub base_url_env: &'static str,
    pub token_env: &'static str,
    pub requires_org_id: bool,
    pub org_id_env: Option<&'static str>,
}
```

Required defaults:

- display name
- default API base URL, where safe and known
- vendor-specific base URL environment variable
- vendor-specific token environment variable
- whether the vendor requires an organisation/account ID
- organisation/account ID environment variable, if applicable

### Pangolin Default

Pangolin should default to the hosted cloud API root:

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

`org_id` should remain required because Pangolin routes are org-scoped.

## 4. Credential Resolution

Each vendor must resolve credentials consistently.

Recommended order:

```text
CLI override
→ vendor-specific environment variable
→ config token_env lookup
→ config literal token
→ error
```

For base URLs:

```text
CLI override
→ vendor-specific environment variable
→ config base_url
→ vendor default base_url
→ error
```

For organisation/account IDs, where required:

```text
CLI/env override
→ config org_id/account_id
→ error
```

## 5. Vendor Client

Each vendor needs a client module responsible for:

- HTTP client construction
- base URL storage
- authentication injection
- request helpers
- response parsing
- vendor-specific error mapping
- safe handling of secrets
- timeout configuration

Typical structure:

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

## 6. Service Trait Implementations

Every vendor must implement the full vendor-neutral DNS service contract.

Required traits:

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

Unsupported operations must return explicit unsupported errors.

Example:

```rust
Err(Error::unsupported("VendorName", "zone import"))
```

This keeps CLI and MCP behaviour predictable even when a vendor is read-only or only partially DNS-compatible.

## 7. Capabilities

Every vendor must declare its supported functionality.

Current capability fields:

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

Capabilities must reflect actual behaviour, not aspirational support.

Example for Pangolin:

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

## 8. Records Must Be Normalized by Default

Every vendor adapter must normalize vendor-specific DNS/resource data into dnsync's vendor-neutral record model before returning it to CLI or MCP callers.

Default flow:

```text
vendor API response
→ vendor-specific parser
→ normalized ZoneRecord / RecordData / ListRecordsResponse
→ CLI/MCP output
```

Normalized records should consistently expose:

- zone
- record name
- fully qualified domain name, where available
- record type
- TTL, where meaningful
- enabled/disabled state
- comments or description, where available
- parsed typed record data, where possible
- vendor metadata in `data`

Rules:

- Standard DNS records such as `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SRV`, `CAA`, `PTR`, `HTTPS`, and `SVCB` should map to typed normalized records where possible.
- Vendor-specific or non-DNS-native resources should still return as normalized records.
- Raw vendor API shapes should not be the primary output format.
- If a field is unavailable, use a safe neutral default and preserve useful original vendor data in `data`.

### Pangolin Normalization

Pangolin should normalize resources as DNS-like records:

```text
Pangolin domain      → ZoneInfo
Pangolin resource    → ZoneRecord
resource.fullDomain  → FQDN / record name
resource.http        → HTTP-like record type
resource.protocol    → TCP/UDP/etc. for non-HTTP resources
resource.enabled     → disabled = !enabled
targets/sites/health → vendor metadata in data
```

## 9. Runtime Dispatch

Add a runtime dispatch branch in `main.rs` for the new vendor.

Pattern:

```rust
match vendor {
    VendorKind::Technitium => { /* construct TechnitiumClient */ }
    VendorKind::Pangolin => { /* construct PangolinClient */ }
    VendorKind::NewVendor => { /* construct NewVendorClient */ }
}
```

The dispatch branch must:

- resolve credentials
- construct the vendor client
- pass the client into the shared CLI/MCP runner

## 10. Module Exports

Expose the vendor module from `src/vendors/mod.rs`.

```rust
#[cfg(feature = "newvendor")]
pub mod newvendor;
```

Also ensure `src/lib.rs` and `src/main.rs` feature gates include the new vendor where required.

## 11. CLI and Documentation

For every vendor, update:

- CLI help text
- README examples
- config examples
- environment variable table
- MCP examples
- supported/unsupported operation notes

Avoid hard-coding one vendor's name in generic CLI/MCP descriptions.

Prefer generic naming:

```text
dnsync
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

## 12. Tests

Each vendor must include tests for:

- default base URL resolution
- token resolution
- required org/account ID handling
- config round-trip
- response-envelope parsing
- error parsing
- capability declaration
- normalized record conversion
- supported read operations
- unsupported write/non-DNS operations
- feature-gated compilation

For read-only vendors, tests should prove write operations fail clearly and safely.

## New Vendor Checklist

Use this checklist when adding a vendor.

```text
[ ] Add Cargo feature
[ ] Add vendor to default features if production-ready
[ ] Add VendorKind enum variant
[ ] Add vendor defaults
[ ] Add default base URL, if known and safe
[ ] Add vendor-specific env vars
[ ] Add credential resolver
[ ] Add client module
[ ] Add service trait implementations
[ ] Add unsupported-operation behaviour
[ ] Add capabilities
[ ] Normalize records by default
[ ] Preserve vendor metadata in normalized output
[ ] Add runtime dispatch
[ ] Export vendor module
[ ] Update CLI help text
[ ] Update README/config examples
[ ] Add tests
[ ] Verify vendor-only feature build
[ ] Verify default-feature build
```
