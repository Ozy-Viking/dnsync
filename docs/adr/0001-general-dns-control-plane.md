# ADR 0001: General DNS Control Plane

## Status

Accepted.

## Context

`dnsync` began as a Technitium-oriented MCP and CLI tool. The project now needs
to manage multiple DNS backends through the same user-facing commands and MCP
tools. Current default vendors are Technitium, Pangolin, Cloudflare, UniFi, and
Pi-hole.

The project also needs direct DNS resolution across DNS, DoT, DoH, and DoQ
without tying resolver behaviour to a vendor API.

## Decision

Use a general DNS control-plane architecture:

- Keep shared DNS records, responses, capabilities, resolver targets, validation,
  and service traits under `core/dns`.
- Keep config, policy, sync, and app-level orchestration under `control_plane`.
- Keep terminal command parsing/output under `cli`.
- Keep MCP parameter handling and tool handlers under `mcp`.
- Keep all vendor API details under `vendors/<vendor>`.
- Construct concrete clients through `vendors/runtime.rs` and expose a
  vendor-neutral `VendorClient` delegating to the shared service traits.

Vendor adapters must implement the shared trait set and report unavailable
operations explicitly with `Error::unsupported(...)`.

DoQ is a first-class transport tag in config and command parsing, but executable
DNS-over-QUIC support remains gated by the `doq` Cargo feature.

## Consequences

CLI and MCP surfaces can share behaviour across vendors where the capability
exists. Vendor-specific differences are isolated in adapters and mapping code.

Adding a new vendor requires changes to feature flags, `VendorKind`, config
defaults, credential resolution, runtime dispatch, adapter modules, capability
declarations, tests, and documentation.

Some vendors do not model zones. Control-plane code must account for
record-capable but zone-less vendors such as UniFi and Pi-hole.

Transport configuration is independent from vendor API configuration. A
Cloudflare API server entry, for example, does not automatically imply public
resolver endpoints until provider-level resolver defaults are added.

