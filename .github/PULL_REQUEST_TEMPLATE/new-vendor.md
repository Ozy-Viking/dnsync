## New Vendor: `<VendorName>`

> Replace `<VendorName>` with the name of the vendor being added (e.g. `Cloudflare`, `Route53`).

### Naming conventions

| Usage | Convention | Example |
|---|---|---|
| Rust enum variant | `PascalCase` | `NewVendor` |
| Cargo feature, module directory | lowercase, no separator | `newvendor` |
| Serde / TOML / CLI value | lowercase, no separator (derived from `rename_all = "lowercase"`) | `"newvendor"` |

For multi-word names, concatenate without separator: `newvendor`, not `new-vendor` or `new_vendor`.

### Summary

<!-- One paragraph: what this vendor is, what DNS operations it supports, and any notable constraints. -->

### API reference

<!-- Link to the vendor's API documentation. -->

---

## Checklist

Complete every item before requesting review. Check the box once it is done, or strike it through and explain in **Notes / exceptions** below if it does not apply.

### 1. Cargo feature (`Cargo.toml`)

- [ ] Feature flag added; if this vendor requires additional crates, list them as dependencies under the feature — do not leave it empty in that case
- [ ] Vendor added to `default` features (omit only if experimental, requires heavy dependencies, or has platform-specific constraints — explain in Notes)

### 2. `VendorKind` entry (`control_plane/config.rs`)

- [ ] New variant added to `VendorKind` enum
- [ ] Enum still derives `Debug`, `Clone`, `Copy`, `Default`*, `PartialEq`, `Eq`, `Serialize`, `Deserialize`, `clap::ValueEnum`
- [ ] `serde(rename_all = "lowercase")` remains on the enum

*`Default` is only required if this vendor becomes the new default — otherwise leave the existing default unchanged.

### 3. Vendor defaults (`control_plane/config.rs`)

- [ ] `NEWVENDOR_DEFAULT_BASE_URL` constant added alongside existing constants
- [ ] Match arm added in `resolved_base_url()`
- [ ] Match arm added in `resolved_location()`
- [ ] Match arm added in `append_server_entry()` for TOML serialisation

### 4. Credential resolution (`src/vendors/<vendor>/mod.rs`)

Resolution order implemented and verified:

- [ ] Token: CLI `--token` → `token_env` config lookup (reads the named env var) → literal config token → `Error::parse(...)`
- [ ] Base URL: CLI `--base-url` → `base_url_env` config lookup (reads the named env var) → config `base_url` → vendor default constant
- [ ] Any vendor-specific fields required by this provider (e.g. org ID, account ID, region) are captured in `DnsServerConfig` and resolved from config with a clear error if missing
- [ ] Credential logic is **in the vendor module**, not in `main.rs` or `vendors/runtime.rs`

### 5. Vendor client (`src/vendors/<vendor>/client.rs`)

- [ ] `reqwest::Client` built with a 30-second timeout in `new()`
- [ ] Vendor is correctly authenticated per its API requirements
- [ ] Credentials are **never logged**; `ApiToken` debug prints `[REDACTED]` and the raw value must not appear in any log output
- [ ] Tracing is implemented following the same patterns as existing vendors (see `src/vendors/technitium/client.rs` or `src/vendors/pangolin/client.rs`)
- [ ] `parse_response` contains no tracing calls
- [ ] `parse_response` maps all responses to the appropriate error variants in `src/core/error.rs`
- [ ] No diagnostics written to stdout — all log output goes to stderr

### 6. Service trait implementations (`src/vendors/<vendor>/service.rs`)

All 11 traits implemented (even for unsupported operations):

- [ ] `DnsVendor` (`kind`, `capabilities`)
- [ ] `ZoneRead` (`list_zones`, `list_records`)
- [ ] `ZoneWrite` (`create_zone`, `delete_zone`, `enable_zone`, `disable_zone`)
- [ ] `RecordWrite` (`add_record`, `delete_record`)
- [ ] `CacheRead` (`list_cache`)
- [ ] `CacheWrite` (`delete_cache_zone`, `flush_cache`)
- [ ] `StatsRead` (`get_stats`)
- [ ] `AccessListRead` (`list_blocked`, `list_allowed`)
- [ ] `AccessListWrite` (`add_blocked`, `delete_blocked`, `add_allowed`, `delete_allowed`)
- [ ] `ZoneImport` (`import_zone_file`)
- [ ] `SettingsRead` (`get_settings`)
- [ ] `DnsService` is **not** implemented directly (it is a blanket impl)
- [ ] Unsupported methods return `Err(Error::unsupported("VendorName", "operation name"))` immediately

### 7. Tracing in `service.rs`

Follow the same tracing patterns as existing vendors (see `src/vendors/technitium/service.rs` or `src/vendors/pangolin/service.rs`):

- [ ] Methods that perform real I/O are instrumented; methods that return `Error::unsupported` immediately are not
- [ ] Log output goes to stderr only; no diagnostics written to stdout

### 8. Capabilities (`DnsVendor::capabilities`)

- [ ] `VendorCapabilities` returned with accurate boolean values
- [ ] Every `true` capability is actually implemented (no aspirational `true`)
- [ ] Every unsupported operation in the service impl is `false` in capabilities

### 9. Normalized records

- [ ] `list_records` returns `Result<ListRecordsResponse>`
- [ ] `ListRecordsResponse::single(zone_info, records)` used for single-zone responses
- [ ] `ZoneInfo` fields populated: `name`, `zone_type`, `disabled`, `dnssec_status`
- [ ] `ZoneRecord` fields populated with correct defaults where unavailable: `ttl = 0`, `comments = ""`, `expiry_ttl = 0`, `parsed = None` if not populated
- [ ] `data` field uses the standard `rData` key shapes (see `docs/new-vendor.md` §9)
- [ ] Vendor metadata (IDs, proxied state, health, etc.) preserved as extra keys in `data`
- [ ] If vendor uses numeric values for SSHFP, TLSA, DS, or similar types: conversion helpers implemented in both directions (see `docs/new-vendor.md` §9)
- [ ] Raw vendor API shapes are **not** the primary output format

### 10. Runtime dispatch (`src/vendors/runtime.rs` and `src/vendors/<vendor>/mod.rs`)

- [ ] `VendorClient` enum has a new feature-gated variant for this vendor
- [ ] Dispatch branch added in `VendorClient::from_selected_server()`
- [ ] `client_from_server()` constructor helper added in `src/vendors/<vendor>/mod.rs`
- [ ] All `#[cfg(any(feature = "technitium", feature = "pangolin", ...))]` guards updated to include the new feature
- [ ] `compile_error!` guard in `vendors/runtime.rs` updated
- [ ] Zone import/export: explicit branches added if supported; `Error::unsupported(...)` returned before credential resolution if not

### 11. Module exports (`src/vendors/mod.rs` and `src/lib.rs`)

- [ ] Feature-gated `pub mod <vendor>;` added in `src/vendors/mod.rs`
- [ ] `compile_error!` guard at the top of `src/lib.rs` updated to include the new feature
- [ ] `src/lib.rs` public re-export added only if warranted (currently only Technitium has one)

### 12. Error handling

- [ ] No new error types defined; only existing variants in `src/core/error.rs` are used
- [ ] `parse_response` maps every response outcome to the correct variant (refer to `src/core/error.rs` for the full set)

### 13. CLI and documentation

- [ ] CLI help text updated
- [ ] `VendorChoice` entry added in `run_add_wizard()` in `src/cli/interactive.rs`
- [ ] `interactive.rs` updated if this vendor requires any extra config fields (e.g. org ID prompt)
- [ ] README examples updated
- [ ] Config file examples updated
- [ ] Environment variable table updated
- [ ] MCP examples updated
- [ ] Supported / unsupported operations documented

### 14. Tests

- [ ] Default base URL constant value tested
- [ ] Token resolution order tested (CLI > `token_env` env lookup > literal config token)
- [ ] Base URL resolution order tested (CLI > `base_url_env` env lookup > config `base_url` > default)
- [ ] Error when required vendor-specific fields are missing (if applicable)
- [ ] `VendorKind` serde round-trip: `"<vendor>"` → enum → `"<vendor>"`
- [ ] Response envelope parsing: success, API error, forbidden, empty errors
- [ ] Capability declaration matches `VendorCapabilities` struct exactly
- [ ] Normalized record conversion tested for each record type this vendor supports
- [ ] Supported read operations tested
- [ ] All unsupported operations return `Error::Unsupported` with the correct vendor name
- [ ] Feature-gated compilation passes: `cargo build --no-default-features --features <vendor>`

### Build verification

- [ ] `cargo build --no-default-features --features <vendor>` — vendor-only build passes
- [ ] `cargo build` — default-features build passes
- [ ] `cargo test` — all tests pass

---

## Notes / exceptions

<!-- Document here any checklist items that were deliberately skipped, deferred, or handled differently.
     Examples: a capability left as `false` because the vendor API doesn't expose it; vendor omitted
     from `default` due to extra dependencies; a departure from the standard credential resolution
     order; record types excluded from normalization tests because the vendor doesn't support them. -->
