//! Pangolin-specific DNS record mapping and resolution helpers.
//!
//! Pangolin is a WireGuard reverse-proxy platform whose API returns JSON
//! shapes that differ from the vendor-neutral `core::dns` types. The functions
//! here translate Pangolin domains, resources, and DNS records into internal
//! zone-record representations, and resolve candidate IPs for `--use-local-ip`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_resolver::Resolver;
use serde_json::Value;

use crate::core::dns::{names::relative_to_zone, responses::ZoneRecord};
use crate::core::error::{Error, Result};
#[cfg(test)]
use crate::vendors::pangolin::responses::PangolinResource;
use crate::vendors::pangolin::responses::{PangolinDnsRecord, PangolinDomain};

// ─── Parsing helpers ──────────────────────────────────────────────────────────

pub fn parse_domains(data: &Value) -> Result<Vec<PangolinDomain>> {
    let arr = data
        .get("domains")
        .and_then(|d| d.as_array())
        .ok_or_else(|| Error::parse("Pangolin domains response missing 'domains' array"))?;

    arr.iter()
        .filter_map(|v| serde_json::from_value::<PangolinDomain>(v.clone()).ok())
        .collect::<Vec<_>>()
        .pipe(Ok)
}

#[cfg(test)]
pub fn parse_resources(data: &Value) -> Result<Vec<PangolinResource>> {
    let arr = data
        .get("resources")
        .and_then(|r| r.as_array())
        .ok_or_else(|| Error::parse("Pangolin resources response missing 'resources' array"))?;

    arr.iter()
        .filter_map(|v| serde_json::from_value::<PangolinResource>(v.clone()).ok())
        .collect::<Vec<_>>()
        .pipe(Ok)
}

pub fn parse_dns_records(data: &Value) -> Result<Vec<PangolinDnsRecord>> {
    let arr = data
        .as_array()
        .ok_or_else(|| Error::parse("Pangolin DNS records response missing data array"))?;

    arr.iter()
        .filter_map(|v| serde_json::from_value::<PangolinDnsRecord>(v.clone()).ok())
        .collect::<Vec<_>>()
        .pipe(Ok)
}

trait Pipe: Sized {
    fn pipe<R>(self, f: impl FnOnce(Self) -> R) -> R {
        f(self)
    }
}
impl<T> Pipe for T {}

// ─── Record conversion ────────────────────────────────────────────────────────

#[cfg(test)]
pub fn resource_to_zone_record(resource: &PangolinResource, base_domain: &str) -> ZoneRecord {
    let name = relative_to_zone(&resource.full_domain, base_domain);
    let record_type = if resource.http {
        "HTTP".to_string()
    } else {
        resource.protocol.to_uppercase()
    };

    let data = serde_json::json!({
        "resourceId": resource.resource_id,
        "name": resource.name,
        "fullDomain": resource.full_domain,
        "health": resource.health,
        "targets": resource.targets,
        "sites": resource.sites,
    });

    ZoneRecord {
        name,
        record_type,
        ttl: 0,
        disabled: !resource.enabled,
        comments: resource.name.clone(),
        expiry_ttl: 0,
        data,
        parsed: None,
    }
}

pub fn dns_record_to_zone_record(
    record: &PangolinDnsRecord,
    zone_name: &str,
    resolved_ips: &[IpAddr],
    use_local_ip: bool,
) -> ZoneRecord {
    let record_type = record.record_type.to_uppercase();
    let name = relative_to_zone(&record.base_domain, zone_name);
    let value = preferred_record_value(&record_type, &record.value, resolved_ips, use_local_ip);
    let data = dns_record_data(&record_type, &value);

    ZoneRecord {
        name,
        record_type,
        ttl: 0,
        disabled: !record.verified,
        comments: format!("Pangolin DNS record {}", record.id),
        expiry_ttl: 0,
        data,
        parsed: None,
    }
}

fn preferred_record_value(
    record_type: &str,
    value: &str,
    resolved_ips: &[IpAddr],
    use_local_ip: bool,
) -> String {
    if !use_local_ip {
        return value.to_string();
    }

    match record_type {
        "A" => resolved_ips
            .iter()
            .find_map(|ip| match ip {
                IpAddr::V4(ip) if is_local_ipv4(ip) => Some(ip.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| value.to_string()),
        "AAAA" => resolved_ips
            .iter()
            .find_map(|ip| match ip {
                IpAddr::V6(ip) if is_local_ipv6(ip) => Some(ip.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| value.to_string()),
        _ => value.to_string(),
    }
}

fn dns_record_data(record_type: &str, value: &str) -> Value {
    match record_type {
        "A" | "AAAA" => serde_json::json!({ "ipAddress": value }),
        "NS" => serde_json::json!({ "nameServer": value, "glue": null }),
        "CNAME" => serde_json::json!({ "cname": value }),
        "TXT" => serde_json::json!({ "text": value, "splitText": false }),
        _ => serde_json::json!({ "value": value }),
    }
}

fn is_local_ipv4(ip: &Ipv4Addr) -> bool {
    ip.is_private()
}

fn is_local_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

/// Check if an IP address is in a private/local range.
fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_local_ipv4(ip),
        IpAddr::V6(ip) => is_local_ipv6(ip),
    }
}

pub async fn resolve_local_candidates(names: &[String]) -> HashMap<String, Vec<IpAddr>> {
    let resolver = match Resolver::builder_tokio() {
        Ok(builder) => match builder.build() {
            Ok(resolver) => resolver,
            Err(error) => {
                tracing::debug!(%error, "failed to build DNS resolver for local IP lookup");
                return HashMap::new();
            }
        },
        Err(error) => {
            tracing::debug!(%error, "failed to load DNS resolver config for local IP lookup");
            return HashMap::new();
        }
    };

    let mut resolved = HashMap::new();
    for name in names {
        match resolver.lookup_ip(name.as_str()).await {
            Ok(lookup) => {
                let ips: Vec<IpAddr> = lookup.iter().filter(is_local_ip).collect();
                if !ips.is_empty() {
                    resolved.insert(name.clone(), ips);
                }
            }
            Err(error) => {
                tracing::debug!(%error, name, "local IP lookup failed");
            }
        }
    }
    resolved
}
