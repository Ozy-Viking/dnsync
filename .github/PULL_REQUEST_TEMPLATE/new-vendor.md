## New Vendor: `<VendorName>`

> Replace `<VendorName>` with the name of the vendor being added (e.g. `Cloudflare`, `Route53`).

### Summary

<!-- One paragraph: what this vendor is, what DNS operations it supports, and any notable constraints. -->

### API reference

<!-- Link to the vendor's API documentation. -->

---

## Checklist

Complete every item before requesting review. Check the box once it is done, or strike it through and explain below if it does not apply.

### 1. Cargo feature (`Cargo.toml`)

- [ ] Empty feature flag added: `newvendor = []`
- [ ] Vendor added to `default` features (omit only if experimental, heavy-dependency, or platform-specific — explain below)

### 2. `VendorKind` entry (`control_plane/config.rs`)

- [ ] New variant added to `VendorKind` enum
- [ ] Enum still derives `Debug`, `Clone`, `Copy`, `Default`*, `PartialEq`, `Eq`, `Serialize`, `Deserialize`, `clap::ValueEnum`
- [ ] `serde(rename_all = "lowercase")` remains on the enum

*`Default` is only required if this vendor becomes the new default — otherwise leave the existing default.

### 3. Vendor defaults (`control_plane/config.rs`)

- [ ] `NEWVENDOR_DEFAULT_BASE_URL` constant added alongside existing constants
- [ ] Match arm added in `resolved_base_url()`
- [ ] Match arm added in `resolved_location()`
- [ ] Match arm added in `append_server_entry()` for TOML serialisation
- [ ] Vendor-specific env var `DNSYNC_<VENDOR>_BASE_URL` documented / wired up
- [ ] Vendor-specific env var `DNSYNC_<VENDOR>_API_TOKEN` documented / wired up
- [ ] If `org_id` / account ID is required: noted here and handled in credential resolution

### 4. Credential resolution (`src/vendors/<vendor>/mod.rs`)

Resolution order implemented and verified:

- [ ] Token: CLI `--token` → `DNSYNC_<VENDOR>_API_TOKEN` env var → `token_env` config lookup → literal config token → `Error::parse(...)`
- [ ] Base URL: CLI `--base-url` → `DNSYNC_<VENDOR>_BASE_URL` env var → config `base_url` → vendor default constant
- [ ] Org/account ID (if required): `DNSYNC_<VENDOR>_ORG_ID` env var → config `org_id` → `Error::parse(...)`
- [ ] Credential logic is **in the vendor module**, not in `main.rs` or `vendors/runtime.rs`

### 5. Vendor client (`src/vendors/<vendor>/client.rs`)

- [ ] `reqwest::Client` built with a 30-second timeout in `new()`
- [ ] Bearer auth used on every request: `.bearer_auth(self.token.expose_for_auth())`
- [ ] Token value is **never logged**; `ApiToken` debug prints `[REDACTED]`
- [ ] Every HTTP method follows the tracing span template:
  - Span named `"http.get"` / `"http.post"` / etc.
  - `http.status = tracing::field::Empty` placeholder, recorded after response via `span.record(...)`
  - `tracing::debug!("sending GET")` before send, `tracing::debug!("received response")` after
  - Network error closure calls `tracing::warn!(error = %e, "<method> failed")` before propagating `Error::Network(e)`
- [ ] `parse_response` contains **no tracing calls**
- [ ] `parse_response` maps errors to correct variants: `Error::Api`, `Error::Http`, `Error::Forbidden`, `Error::InvalidJson`, `Error::Network`
- [ ] No diagnostics written to stdout (all log output goes to stderr)

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
- [ ] Unsupported methods return `Err(Error::unsupported("VendorName", "operation name"))` and have **no** `#[instrument]`

### 7. Tracing in `service.rs`

- [ ] `#[instrument]` applied to every method that performs real I/O
- [ ] All `#[instrument]` attrs include `skip(self)` and `fields(vendor = "...", operation = "...")`
- [ ] `record: &RecordData`, `file_bytes: Vec<u8>`, and `type_params: &[(&str, String)]` are listed in `skip(...)` (not `Debug`)
- [ ] Field naming follows the spec: `vendor` = lowercase vendor string, `operation` = snake_case method name
- [ ] Log output to stderr only; no diagnostics written to stdout

### 8. Capabilities (`DnsVendor::capabilities`)

- [ ] `VendorCapabilities` returned with accurate boolean values
- [ ] Every `true` capability is actually implemented (no aspirational `true`)
- [ ] Every unsupported operation in the service impl is `false` in capabilities

### 9. Normalized records

- [ ] `list_records` returns `Result<ListRecordsResponse>`
- [ ] `ListRecordsResponse::single(zone_info, records)` used for single-zone responses
- [ ] `ZoneInfo` fields populated: `name`, `zone_type`, `disabled`, `dnssec_status`
- [ ] `ZoneRecord` fields populated with correct defaults where unavailable: `ttl = 0`, `comments = ""`, `expiry_ttl = 0`, `parsed = None` if not populated
- [ ] `data` field uses the standard `rData` key shapes (see docs/new-vendor.md §9)
- [ ] Vendor metadata (IDs, proxied state, health) preserved as extra keys in `data`
- [ ] If vendor uses **numeric enum values** (SSHFP, TLSA, DS): conversion helpers implemented in both directions (numeric→string and string→numeric)
- [ ] Raw vendor API shapes are **not** the primary output format

### 10. Runtime dispatch (`src/vendors/runtime.rs` and `src/vendors/<vendor>/mod.rs`)

- [ ] `VendorClient` enum has a new feature-gated variant: `#[cfg(feature = "newvendor")] NewVendor(...)`
- [ ] Dispatch branch added in `VendorClient::from_selected_server()`
- [ ] `client_from_server()` constructor helper added in `src/vendors/newvendor/mod.rs`
- [ ] All `#[cfg(any(feature = "technitium", feature = "pangolin", ...))]` guards updated to include new feature
- [ ] `compile_error!` guard in `vendors/runtime.rs` updated
- [ ] If zone import/export supported: explicit branches added in `export_zone_for_server()` / `import_zone_for_server()`; otherwise `Error::unsupported(...)` returned before credential resolution

### 11. Module exports (`src/vendors/mod.rs` and `src/lib.rs`)

- [ ] `#[cfg(feature = "newvendor")] pub mod newvendor;` added in `src/vendors/mod.rs`
- [ ] `compile_error!` guard at the top of `src/lib.rs` updated to include the new feature
- [ ] `src/lib.rs` public re-export added only if warranted (currently only Technitium has one)

### 12. Error types

- [ ] Only existing `Error` variants used; no new error types defined
- [ ] Correct variant used in each context (see docs/new-vendor.md §12 for the full table)

### 13. CLI and documentation

- [ ] CLI help text updated
- [ ] `VendorChoice` entry added in `run_add_wizard()` in `src/cli/interactive.rs`
- [ ] `org_id` prompt condition in `interactive.rs` extended (only if vendor requires org/account ID)
- [ ] README examples updated
- [ ] Config file examples updated
- [ ] Environment variable table updated (generic + vendor-specific aliases)
- [ ] MCP examples updated
- [ ] Supported / unsupported operations documented

### 14. Tests

- [ ] Default base URL constant value tested
- [ ] Token resolution order tested (CLI > env > config)
- [ ] Required org/account ID error tested when missing (if applicable)
- [ ] `VendorKind` serde round-trip: `"newvendor"` → enum → `"newvendor"`
- [ ] Response envelope parsing: success, API error, forbidden, empty errors
- [ ] Capability declaration matches `VendorCapabilities` struct exactly
- [ ] Normalized record conversion tested for: A, AAAA, MX, TXT, SRV, CAA, SSHFP, TLSA, DS, HTTPS, NAPTR, URI, DNAME, unknown type, proxied flag, vendor ID
- [ ] Supported read operations tested
- [ ] All unsupported operations return `Error::Unsupported` with the correct vendor name
- [ ] Feature-gated compilation passes: `cargo build --no-default-features --features newvendor`

### Build verification

- [ ] `cargo build --no-default-features --features newvendor` — vendor-only build passes
- [ ] `cargo build` — default-features build passes
- [ ] `cargo test` — all tests pass

---

## Notes / exceptions

<!-- Document here any checklist items that were deliberately skipped, deferred, or handled differently, with a brief justification. -->
