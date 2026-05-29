# Refactor To Do

Track the planned move from a Technitium-focused MCP server to a general DNS control plane with vendor-specific adapters.


## Docs First

- [x] Create `docs/architecture.md` to define module boundaries.
- [x] Create `docs/vendor-mapping.md` to document vendor mappings.
- [x] Create `docs/adr/0001-general-dns-control-plane.md` to record the architecture decision.
- [x] Use the docs as the source of truth for implementation phases.
- [x] Add initial `technitium` vendor feature flag.
- [x] Rename the importable library crate to `dnslib` while keeping the binary as `dns`.
- [x] Create the initial `core/`, `control_plane/`, `mcp/`, and `vendors/technitium/` module tree.
- [x] Document current vendor set: Technitium, Pangolin, Cloudflare, UniFi, and Pi-hole.

## Architecture

- [x] Finalize the planned directory tree before code changes.
- [x] Move centralized error handling into a shared core/control-plane error module.
- [x] Move MCP-specific code into its own `mcp/` module.
- [x] Define the shared DNS core types used inside the binary.
- [x] Define a vendor-neutral DNS operations interface.

## Control Plane

- [x] Keep MCP tool handling vendor-neutral where possible.
- [x] Keep CLI command handling vendor-neutral where possible.
- [x] Keep policy checks centralized and shared by control-plane surfaces.
- [x] Keep output/result formatting separate from vendor API calls.

## Vendor Areas

- [x] Create `vendors/technitium/` for the existing Technitium implementation.
- [x] Add `vendors/pangolin/`, `vendors/cloudflare/`, `vendors/unifi/`, and `vendors/pihole/`.
- [x] Move Technitium HTTP client/auth handling into the Technitium vendor area.
- [x] Move Technitium endpoint paths and request encoding into the Technitium vendor area.
- [x] Move Technitium response normalization/parsing into the Technitium vendor area.
- [x] Keep shared record/zone types outside the vendor area unless a type is truly vendor-specific.
- [ ] Add focused integration/fixture coverage for newer vendor adapters, especially write paths and unsupported-operation behaviour.

## Validation

- [x] Preserve current CLI behavior after restructuring.
- [x] Preserve current MCP tool behavior after restructuring.
- [x] Update tests to match the new module boundaries where code has moved.
- [x] Run formatting, tests, and build after each implementation phase.

## Direct DNS resolution (dns query / dns_resolve)

- [x] Plan the `dns query` subcommand (`docs/dns-query-command.md`).
- [x] Add the `doq` Cargo feature gating `hickory-resolver/quic-ring`.
- [x] Add `[servers.doq]` transport block; round-trip + validate.
- [x] Add provider-level default resolver transports for external providers
  such as Cloudflare, with DNS/DoT/DoH/DoQ defaults that can still be
  overridden per config. Future providers should be able to declare their
  transport defaults in one place instead of requiring every config to repeat
  standard public resolver endpoints.
- [x] Extract resolver builders onto a neutral `ResolverTarget` shared
  between validation and query paths; add DoQ behind `#[cfg]`.
- [x] Ship the `dns query` (alias `q`) CLI subcommand: system / named /
  ad-hoc targets, DoH bootstrap, dig-style table + `--short` + `--json`,
  fan-out with `--all` and per-transport flags.
- [x] Add public resolver shortcuts for Cloudflare, Google, Quad9, and
  AdGuard (`--cf`, `--google`, `--quad9`, `--adg`) across DNS/DoT/DoH/DoQ.
- [x] Ship the `dns_resolve` MCP tool with the same engine and JSON shape.
- [x] Document `dns query` in the README (examples + `[servers.doq]`).
- [x] Shell completion for `--server` on `dns query`; zsh output is patched
  to use the hidden `_servers` completion source.
- [ ] Optional: a future `dns query --compare` flag that diffs answers
  across multiple resolvers (extends the existing `record list --all`
  idea to the query side).
- [x] Wire DoQ (DNS-over-QUIC, port 853) into the shared resolver layer behind the `doq` Cargo feature.
- [x] Include DoQ in default Cargo features.
- [ ] Add end-to-end DoQ validation tests that run when built with `--features doq`.

## CLI / MCP Parity (bugs, per `agents.md`)

- [x] Add MCP `sync` tool that mirrors the `dns sync` CLI surface
      (profiles, `--from`/`--to`/`--zone`/`--map`, dry-run by default, `--apply`).
- [x] Add MCP `logs` tool mirroring the `dns logs` CLI surface.
- [x] Add MCP `transfer_zone` tool mirroring `dns zone transfer`.
- [x] Control `dns_get_settings` secret visibility through per-server config.
- [x] Add `dns config update` to materialize newly-known server defaults without overwriting existing values.
- [ ] Add MCP `diff` tool to ship alongside any future `dns diff` CLI command.
