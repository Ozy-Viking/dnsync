# DNS Validation Endpoint Runtime Usage Analysis

## Executive Summary

Legacy `[[servers.validation_endpoints]]` entries are mostly **configuration-time constructs**.
The newer per-server transport blocks (`[servers.dns]`, `[servers.dot]`,
`[servers.doh]`, `[servers.doq]`) are used by direct query and MCP resolution.

Validation endpoints are **not used at runtime** for:

- Record listing/query operations
- Zone import/export operations
- Zone transfer operations

The validation endpoint layer exists purely for:

1. Configuration validation at startup/add time
2. Resolver-target validation/reporting paths
3. Backward-compatible config shape while per-server transport blocks become
   the preferred model

## Detailed Findings

### Configuration Flow (Where Validation Endpoints Are Used)

```text
CLI Add / Interactive Wizard
    → main.rs:ConfigCmd::Add
    → control_plane/config.rs:add_server()
    → AppConfig::validate()
        → validate_validation_endpoints()  ← VALIDATION HAPPENS HERE
    → config::append_server_entry()  ← WRITES TO TOML
```

**Files involved:**

- `src/control_plane/config.rs` - Defines `ValidationEndpointConfig`, TOML deserialization, config validation
- `src/main.rs` - Wires CLI config-add flows
- `src/cli/mod.rs` - Declares `--validation-endpoint` CLI flag
- `src/cli/interactive.rs` - Interactive wizard path

### Runtime Call Graphs (Where Validation Endpoints Are NOT Used)

#### Record Listing/Query Path

> **Note on `cli::runner`:** the call graphs below describe the **pre-refactor**
> dispatch via `cli::runner::run()`. Per `docs/function-placement-guide.md`,
> `runner` is slated for removal and command dispatch is moving into per-command
> modules; once that lands, replace `cli::runner::run()` in these graphs with
> the new dispatcher entry points.

```text
CLI: dns record list example.com
    → main.rs → cli::runner::run()  (pre-refactor; runner slated for removal)
    → mcp::tools::records::handle_list_records()  (MCP path)
    OR
    → core::dns::records::query::list_records_for_query()
        → list_records_for_all_zones() 
        OR search_bare_label_in_zones()
        OR direct client.list_records()  ← VENDOR API CALL
            → Vendors: Technitium/Pangolin/Cloudflare/UniFi/Pi-hole HTTP APIs
```

**Files involved:**

- `src/core/dns/records/query.rs` - Record-list/query routing
- `src/mcp/tools/records.rs` - MCP record-list handler
- `src/vendors/*/service.rs` - Vendor-specific implementations

#### Zone Import Path

```text
CLI: dns zone import example.com zone.file
    → main.rs → cli::runner::run()  (pre-refactor; runner slated for removal)
    → mcp::tools::zones::handle_import_zone_file()  (MCP path)
    OR
    → core::dns::zones::import_zone_file()
        → ZoneImport impl on vendor client
        → vendor HTTP import endpoint  ← VENDOR API CALL
```

**Files involved:**

- `src/core/dns/zones.rs` - Zone import/export logic
- `src/mcp/tools/zones.rs` - MCP zone-import handler
- `src/vendors/*/service.rs` - Vendor-specific implementations

#### Zone Transfer Path

```text
CLI: dns zone transfer example.com
    → main.rs
        → VendorClient::export_zone_for_server()  ← EXPORT
        → VendorClient::import_zone_for_server()  ← IMPORT
```

### Validation Endpoint Layer (Currently Unused at Runtime)

Defined in `src/core/dns/validation.rs`:

- shared resolver builders construct Hickory resolvers for validation and
  direct query paths
- transport-specific builders, one per supported transport:
  - `plain_dns_name_server()` (UDP+TCP, port 53)
  - `dot_name_server()` (TLS, port 853)
  - `doh_name_server()` (HTTPS, port 443, path `/dns-query`)
  - `doq_name_server()` (QUIC, port 853) — available only when compiled with
    the `doq` Cargo feature; default builds report `unsupported_transport`
- `ValidationReport` types - `disabled()`, `skipped_no_endpoints()`, success/failure reports

Per the project mandate (`agents.md`), all **four** transports — DNS, DoT, DoH,
and DoQ — are first-class config/CLI tags. DoQ execution is feature-gated.

**Key observation:** No CLI/MCP/vendor code calls `HickoryDnsEndpointResolver::query_endpoint()` or related validation functions.

## Assumptions & Defaults in Current Implementation

### Validation Endpoint Configuration Shape

- Required: `name`, `transport` (`dns`/`dot`/`doh`/`doq`)
- DNS/DoT/DoQ: require nonempty `address`
- DoH: require nonempty `url`
- Optional fields: `port`, `tls_server_name`, `timeout_ms`
- CLI shorthand: `name:transport:address` (DoH treats 3rd segment as `url`, others as `address`)
- `enabled` field defaults to `true` (but currently unused)

### Transport-Specific Defaults

- **DNS**: UDP+TCP name servers, port 53
- **DoT**: TLS only, port 853, server name from `tls_server_name` or `address`
- **DoH**: HTTPS only, port 443, default path `/dns-query`, server name from `tls_server_name` or URL host
- **DoQ**: QUIC, port 853, server name from `tls_server_name` or `address`;
  requires `--features doq` to execute
- **Validation timeout**: Defaults to 5000 ms

### Enabled Flag Behavior

- `ValidationEndpointConfig.enabled`: Defaults `true`, serialized to TOML, but **not consulted** by any runtime logic
- `ValidationOptions.enabled`: Defaults `true` (validation layer enable switch)
- Disabled paths:
  - `ValidationReport::disabled()` - Explicit skip by caller (`validation_disabled` reason)
  - `ValidationReport::skipped_no_endpoints()` - Enabled but no endpoints configured (`no_validation_endpoints_configured` reason)

## Assumptions That Would Need Changing for Grouped Targets

If implementing grouped targets (multiple transports per target) for validation endpoints, these assumptions would need modification:

### 1. Configuration Data Model

**Current:** One transport per endpoint

```toml
[[servers.validation_endpoints]]
name = "example"
transport = "doh"
url = "https://1.1.1.1/dns-query"
```

**Needed:** Multiple transports per logical target

```toml
[[servers.validation_targets]]
name = "example"
# Either:
transports = [
  {type = "doh", url = "https://1.1.1.1/dns-query"},
  {type = "dot", address = "1.1.1.1", port = 853},
  {type = "dns", address = "1.1.1.1", port = 53}
]
# Or nested structure
```

### 2. Validation Logic Assumptions

**Current:**

- Single address/url validation per endpoint
- Transport determines validation method
- Enabled flag per endpoint

**Needed:**

- Validation succeeds if ANY transport in group succeeds
- Per-transport timeout/failure handling
- Group-level enabled flag vs per-transport flags
- Aggregated validation reporting (partial success?)

### 3. Resolver Construction Assumptions

**Current:**

- One resolver built per endpoint (single transport)
- Hickory resolver expects single upstream

**Needed:**

- Multi-transport resolver strategy (failover, load balancing, etc.)
- Either:
  - Build multiple Hickory resolvers and try sequentially
  - Or modify to use a custom resolver layer that handles multi-transport

### 4. CLI/API Assumptions

**Current:**

- `--validation-endpoint` accepts single `name:transport:address`
- Config validation validates single endpoint

**Needed:**

- New CLI syntax for grouped targets
- Config validation for transport groups
- MCP API changes if exposing validation configuration

### 5. Defaults & Fallback Assumptions

**Current:**

- Transport-specific defaults applied per endpoint

**Needed:**

- Group-level defaults that can be overridden per-transport
- Fallback behavior when some transports fail
- Consistent timeout handling across transports

## Recommendation for Clean Architectural Fit

Based on the analysis, **grouped targets would be a clean architectural fit** because:

1. **Clear separation of concerns**: Validation endpoint configuration is already isolated in `control_plane/config.rs` and `core/dns/validation.rs`

2. **Minimal runtime impact**: Since validation endpoints aren't used at runtime for DNS operations, changes would primarily affect:
   - Configuration parsing/validation
   - Potential future validation wiring
   - CLI/MCP interface for validation config

3. **Existing extension points**:
   - The `ValidationEndpointConfig` struct is already designed for extension
   - Transport-specific builder functions exist in `validation.rs`
   - Validation reporting infrastructure is in place

4. **Low risk of breaking changes**: Since the validation layer isn't currently wired into runtime DNS resolution, implementing grouped targets for validation wouldn't affect existing record listing/import/zone transfer functionality.

**Implementation approach**:

- Keep existing single-transport validation endpoints for backward compatibility
- Add new `validation_targets` configuration array that supports grouped transports
- Modify validation logic to iterate through transports in a group
- Maintain same validation reporting semantics (success if any transport works)

The primary architectural change would be in the configuration layer and validation logic, with no impact on the core DNS resolution paths used by record listing/query or zone import/export operations.
