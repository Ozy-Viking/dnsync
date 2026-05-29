# Vendor Mapping

This document summarizes how current vendor adapters map their APIs into
`dnsync`'s vendor-neutral control-plane traits.

## Capability Matrix

| Vendor | Zones | Records | Cache | Access lists | Settings | Zone import | Zone export | Logs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Technitium | yes | yes | yes | yes | yes | yes | yes | yes |
| Pangolin | yes | yes | no | no | yes | no | no | no |
| Cloudflare | yes | yes | no | no | yes | yes | yes | no |
| UniFi | no | yes | no | no | yes | no | no | no |
| Pi-hole | no | yes | yes | yes | yes | no | no | no |

Capabilities describe implemented adapter behaviour. Unsupported operations must
return `Error::unsupported(vendor, operation)` rather than faking empty results.

## Technitium

Technitium is the most complete adapter and maps closely to a full DNS server
control plane.

- Default base URL: `http://localhost:5380`
- Token env: `DNSYNC_TECHNITIUM_API_TOKEN`
- Legacy env accepted: `TECHNITIUM_API_TOKEN`
- Supports zones, records, cache, block/allow lists, settings, import/export,
  and logs.
- Supports zone transfer through export/import.
- Cluster write policy can use live primary discovery for `primary = "auto"`.

Technitium response mapping normalizes API payloads into
`ListRecordsResponse`, shared record shapes, and shared zone file strings where
the control plane expects them.

## Pangolin

Pangolin is a hosted, org-scoped DNS provider adapter.

- Default base URL: `https://api.pangolin.net/v1`
- Token env: `DNSYNC_PANGOLIN_API_TOKEN`
- Org env: `DNSYNC_PANGOLIN_ORG_ID`
- Requires `org_id`.
- Supports zone and record reads/writes where Pangolin exposes them.
- Does not support cache, access lists, zone import/export, or logs.

Because Pangolin has no zone import/export surface, it cannot participate in
`zone transfer`, but it can participate in `dns sync`, which operates through
vendor-neutral record reads and writes.

## Cloudflare

Cloudflare maps hosted zones and DNS records into the shared zone/record model.

- Default base URL: `https://api.cloudflare.com/client/v4`
- Token env: `DNSYNC_CLOUDFLARE_API_TOKEN`
- Supports zones, records, settings, zone import, and zone export.
- Does not support cache, access lists, or logs through the current adapter.

Cloudflare can participate in zone transfer where the import/export endpoints
cover the requested zone data, and it can be used as either side of `dns sync`.

## UniFi

UniFi uses the Network integration API and exposes local DNS records without a
true DNS zone abstraction.

- Default base URL: `https://192.168.1.1/proxy/network/integration/v1`
- Token env: `DNSYNC_UNIFI_API_TOKEN`
- Supports record operations.
- `settings` returns visible controller/site information for discovery.
- Zone operations, cache, access lists, import/export, and logs are unsupported.

Callers must not assume every record-capable vendor has zones. Use capability
checks or handle explicit unsupported errors.

## Pi-hole

Pi-hole exposes local DNS records plus cache and domain list operations.

- Default base URL: `http://pi.hole`
- Token env: `DNSYNC_PIHOLE_API_TOKEN`
- Supports record operations, cache operations, block/allow lists, and settings.
- Does not support zones, zone import/export, or logs.

Pi-hole record operations are mapped into shared record responses even though
Pi-hole itself does not model authoritative DNS zones.

## Query Transports

Vendor API support is separate from direct DNS query transport support. Per
server, `[servers.dns]`, `[servers.dot]`, `[servers.doh]`, and `[servers.doq]`
configure resolver endpoints used by `dns query`, `dns_resolve`, validation,
and future benchmarking.

DoQ means DNS-over-QUIC on port 853. Its config is portable across builds.
Default builds include the resolver implementation via the `doq` Cargo feature;
custom builds that disable default features can omit it.
