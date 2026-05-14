# Technitium Vendor Mapping

## Purpose

This document maps the existing Technitium-focused implementation to the planned vendor-neutral DNS control plane.

The goal is to make explicit what belongs in shared core types and what must remain in `vendors/technitium/`.

## Vendor-Neutral Model

The core model should describe DNS operations in terms of shared concepts:

- zones
- records
- cache operations
- statistics
- access lists
- settings
- zone file import
- errors

The core model should not expose Technitium endpoint paths, form field names, response wrapper shapes, or auth mechanics.

## Technitium Adapter Responsibilities

The Technitium adapter should own:

- base URL and API token configuration
- bearer-auth HTTP requests
- Technitium `status: ok` and `status: error` response handling
- Technitium endpoint paths
- query parameter and form field names
- multipart zone file upload shape
- Technitium-specific record parameter mapping
- Technitium response normalization into core response types

## Operation Mapping

| Control-plane operation | Current Technitium path | Planned owner |
|---|---|---|
| List zones | `/api/zones/list` | `vendors/technitium/api/zones.rs` |
| Create zone | `/api/zones/create` | `vendors/technitium/api/zones.rs` |
| Delete zone | `/api/zones/delete` | `vendors/technitium/api/zones.rs` |
| Enable zone | `/api/zones/enable` | `vendors/technitium/api/zones.rs` |
| Disable zone | `/api/zones/disable` | `vendors/technitium/api/zones.rs` |
| List records | `/api/zones/records/get` | `vendors/technitium/api/records.rs` |
| Add record | `/api/zones/records/add` | `vendors/technitium/api/records.rs` |
| Delete record | `/api/zones/records/delete` | `vendors/technitium/api/records.rs` |
| List cache | `/api/cache/list` | `vendors/technitium/api/cache.rs` |
| Delete cache entry | `/api/cache/delete` | `vendors/technitium/api/cache.rs` |
| Flush cache | `/api/cache/flush` | `vendors/technitium/api/cache.rs` |
| Get stats | `/api/dashboard/stats/get` | `vendors/technitium/api/stats.rs` |
| List blocked domains | `/api/blocked/list` | `vendors/technitium/api/access_lists.rs` |
| Add blocked domain | `/api/blocked/add` | `vendors/technitium/api/access_lists.rs` |
| Delete blocked domain | `/api/blocked/delete` | `vendors/technitium/api/access_lists.rs` |
| List allowed domains | `/api/allowed/list` | `vendors/technitium/api/access_lists.rs` |
| Add allowed domain | `/api/allowed/add` | `vendors/technitium/api/access_lists.rs` |
| Delete allowed domain | `/api/allowed/delete` | `vendors/technitium/api/access_lists.rs` |
| Import zone file | `/api/zones/import` | `vendors/technitium/api/import.rs` |
| Get settings | `/api/settings/get` | `vendors/technitium/api/settings.rs` |

## Record Mapping

Shared record data should remain in core when the record type is a DNS concept used by the binary.

Technitium-specific encoding should move to vendor mapping. Examples include:

- `ipAddress` field names for A and AAAA records
- `nameServer` field names for NS records
- `svcPriority`, `svcTargetName`, and hint flags for HTTPS/SVCB records
- `forwarder`, `protocol`, `forwarderPriority`, and `dnssecValidation` for FWD records
- delete selector conversion into optional Technitium form parameters

Technitium-only record behavior should be documented explicitly instead of leaking silently into generic layers.

## Response Mapping

Technitium list-record responses currently include a response wrapper containing zone details and records.

The vendor adapter should parse and validate the Technitium response wrapper, then return core response models such as `ListRecordsResponse`, `ZoneInfo`, and `ZoneRecord`.

Read-only DNSSEC records such as DNSKEY, RRSIG, NSEC, and NSEC3 can remain in core response types if the binary exposes them as DNS-domain read models. Technitium-specific lifecycle notes should stay in documentation or vendor mapping.

## Error Mapping

Technitium errors should map into centralized core errors.

Expected mappings:

- network failure -> network error
- invalid JSON -> parse error
- non-success HTTP status -> HTTP error
- `status: error` response -> API error
- policy rejection -> policy error
- unexpected response shape -> parse error

## Unsupported Or Ambiguous Features

- Vendor capability detection is not defined yet.
- Technitium-specific record types such as ANAME, APP, and FWD need clear capability documentation.
- Zone type values such as Primary, Secondary, Stub, and Forwarder may not map cleanly to every future vendor.
- Settings responses may remain vendor-specific unless a generic settings model is defined.

## Test Fixtures And Golden Cases

Initial fixtures should cover:

- successful API response wrapper
- `status: error` response wrapper
- list records with writable records
- list records with read-only DNSSEC records
- record add form encoding
- record delete form encoding with optional selectors
- zone file multipart import
- bearer auth and query parameter handling
