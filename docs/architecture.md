# dnsync Architecture

`dnsync` is a general DNS control plane with a CLI, an MCP server, and
feature-gated vendor adapters. The binary is named `dns`; the importable library
crate is `dnslib`.

## Current Vendors

Default builds include these vendor features:

- `technitium`
- `pangolin`
- `cloudflare`
- `unifi`
- `pihole`

The central vendor enum is `VendorKind`. Runtime construction and dispatch live
in `vendors/runtime.rs`, which returns a `VendorClient` enum wrapping the
feature-gated concrete client.

## Module Boundaries

```text
src/
  core/
    dns/              vendor-neutral DNS records, responses, traits, resolver,
                      validation, and capability types
    error.rs          shared error type and Result alias
    secret.rs         redacted API token wrapper
  control_plane/
    config.rs         config model, default URLs, credential lookup inputs,
                      server/cluster/sync profile parsing
    policy.rs         MCP access and zone policy checks
    sync.rs           vendor-neutral record sync planning/execution
  cli/                command parsing and terminal-oriented presentation
  mcp/                MCP parameter parsing, policy enforcement, and tool
                      handlers
  vendors/
    runtime.rs        selects and delegates to vendor adapters
    http.rs           shared HTTP helpers
    technitium/       Technitium API client, response mapping, service impl
    pangolin/         Pangolin API client, response mapping, service impl
    cloudflare/       Cloudflare API client, response mapping, service impl
    unifi/            UniFi Network integration API adapter
    pihole/           Pi-hole adapter
```

## Control Plane Contract

CLI and MCP code should depend on traits from `core/dns/service.rs`, not on
concrete vendor clients. Vendor adapters implement the same trait set and return
`Error::unsupported(...)` for unavailable operations.

The shared traits currently cover:

- vendor identity and capabilities
- zone read/write
- record write
- cache read/write
- stats read
- access-list read/write
- zone import/export
- settings read
- logs read

Capabilities are descriptive and must match actual adapter behaviour. They are
not a permission system; MCP permissions are enforced separately through
`control_plane::policy`.

## DNS Query and Validation Transports

Direct DNS resolution uses a vendor-neutral resolver target model shared by the
`dns query` CLI path, the `dns_resolve` MCP tool, and endpoint validation.

Supported transport tags are DNS, DoT, DoH, and DoQ. DoQ config always parses
and round-trips, but the actual DNS-over-QUIC resolver is compiled only with the
`doq` Cargo feature. Default builds return `unsupported_transport` when asked to
execute a DoQ query.

## Vendor Adapter Rules

Vendor-specific code owns:

- credential construction for that vendor
- HTTP paths and request encoding
- vendor response parsing
- mapping vendor records into shared record/response types
- unsupported-operation errors

Vendor-neutral code owns:

- CLI/MCP command semantics
- sync planning
- record and zone response contracts
- resolver target construction
- policy enforcement
- output formatting

