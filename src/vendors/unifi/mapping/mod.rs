//! UniFi DNS policy ↔ dnsync `ZoneRecord` / `RecordData` mapping.
//!
//! UniFi DNS policies are site-scoped, not zone-scoped, so dnsync derives
//! logical zones by domain suffix. `FORWARD_DOMAIN` is preserved in listings
//! as provider-specific metadata but is not treated as a normal DNS RRset
//! — `record_data_to_unifi_body` rejects it for create/update calls.

use serde_json::{Value, json};

use crate::core::dns::names::relative_to_zone;
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::ZoneRecord;
use crate::core::error::{Error, Result};

use super::responses::{UnifiDnsPolicy, UnifiDnsPolicyType};

/// Build the dnsync `rData` JSON for a UniFi policy.
///
/// Standard record types map to the shapes documented in
/// `docs/new-vendor.md`. `FORWARD_DOMAIN` produces a provider-specific
/// object (no equivalent `RecordData` variant) so consumers can still see
/// the metadata even though it is not a true RR.
pub fn policy_to_rdata(policy: &UnifiDnsPolicy) -> Value {
    match policy.policy_type {
        UnifiDnsPolicyType::ARecord => json!({
            "ipAddress": policy.ipv4_address.clone().unwrap_or_default(),
        }),
        UnifiDnsPolicyType::AaaaRecord => json!({
            "ipAddress": policy.ipv6_address.clone().unwrap_or_default(),
        }),
        UnifiDnsPolicyType::CnameRecord => json!({
            "cname": policy.target_domain.clone().unwrap_or_default(),
        }),
        UnifiDnsPolicyType::MxRecord => json!({
            "preference": policy.priority.unwrap_or(10),
            "exchange": policy.mail_server_domain.clone().unwrap_or_default(),
        }),
        UnifiDnsPolicyType::TxtRecord => json!({
            "text": policy.text.clone().unwrap_or_default(),
            "splitText": false,
        }),
        UnifiDnsPolicyType::SrvRecord => json!({
            "priority": policy.priority.unwrap_or(0),
            "weight": policy.weight.unwrap_or(0),
            "port": policy.port.unwrap_or(0),
            "target": policy.server_domain.clone().unwrap_or_default(),
        }),
        UnifiDnsPolicyType::ForwardDomain => json!({
            "forwardDomain": policy.domain.clone(),
            "ipAddress": policy.ip_address.clone().unwrap_or_default(),
            "providerType": "FORWARD_DOMAIN",
        }),
    }
}

/// Convert a UniFi DNS policy into a normalised `ZoneRecord` for display.
///
/// The UniFi policy `id` is preserved on `data["id"]` so callers can target
/// it for update/delete. The `enabled` flag is preserved via the standard
/// `ZoneRecord::disabled` field (`disabled = !enabled`).
pub fn policy_to_zone_record(policy: &UnifiDnsPolicy, zone: &str) -> ZoneRecord {
    let record_type = policy.policy_type.dnsync_record_type().to_string();
    let name = relative_to_zone(&policy.domain, zone);
    let ttl = policy.ttl_seconds.unwrap_or(0);

    let mut data = policy_to_rdata(policy);
    if let Some(obj) = data.as_object_mut() {
        obj.insert("id".into(), Value::String(policy.id.clone()));
        obj.insert("enabled".into(), Value::Bool(policy.enabled));
        obj.insert("fullDomain".into(), Value::String(policy.domain.clone()));
        obj.insert(
            "unifiType".into(),
            Value::String(policy.policy_type.as_str().to_string()),
        );
    }

    ZoneRecord {
        name,
        record_type,
        ttl,
        disabled: !policy.enabled,
        comments: String::new(),
        expiry_ttl: 0,
        data,
        parsed: None,
    }
}

/// Build the JSON body for `POST /sites/{siteId}/dns/policies` (create) or
/// `PUT /sites/{siteId}/dns/policies/{id}` (update).
///
/// FORWARD_DOMAIN, ANAME, APP, CAA, DS, FWD, HTTPS, NAPTR, NS, PTR, SVCB,
/// TLSA, URI, and unknown types return `Error::unsupported`. UniFi DNS
/// policies only model A/AAAA/CNAME/MX/TXT/SRV (and FORWARD_DOMAIN, which is
/// not a normal RRset and cannot be created through dnsync's record API).
pub fn record_data_to_unifi_body(
    domain: &str,
    ttl: u32,
    enabled: bool,
    record: &RecordData,
) -> Result<Value> {
    let body = match record {
        RecordData::A { ip } => json!({
            "type": "A_RECORD",
            "enabled": enabled,
            "domain": domain,
            "ipv4Address": ip.to_string(),
            "ttlSeconds": ttl,
        }),
        RecordData::Aaaa { ip } => json!({
            "type": "AAAA_RECORD",
            "enabled": enabled,
            "domain": domain,
            "ipv6Address": ip.to_string(),
            "ttlSeconds": ttl,
        }),
        RecordData::Cname { target } => json!({
            "type": "CNAME_RECORD",
            "enabled": enabled,
            "domain": domain,
            "targetDomain": target,
            "ttlSeconds": ttl,
        }),
        RecordData::Mx {
            exchange,
            preference,
        } => json!({
            "type": "MX_RECORD",
            "enabled": enabled,
            "domain": domain,
            "mailServerDomain": exchange,
            "priority": preference,
            "ttlSeconds": ttl,
        }),
        RecordData::Txt { text, .. } => json!({
            "type": "TXT_RECORD",
            "enabled": enabled,
            "domain": domain,
            "text": text,
            "ttlSeconds": ttl,
        }),
        RecordData::Srv {
            target,
            port,
            priority,
            weight,
        } => {
            let (service, protocol) = split_srv_labels(domain);
            json!({
                "type": "SRV_RECORD",
                "enabled": enabled,
                "domain": domain,
                "serverDomain": target,
                "service": service,
                "protocol": protocol,
                "port": port,
                "priority": priority,
                "weight": weight,
                "ttlSeconds": ttl,
            })
        }
        _ => {
            return Err(Error::unsupported(
                "UniFi",
                "record type (only A/AAAA/CNAME/MX/TXT/SRV are supported)",
            ));
        }
    };
    Ok(body)
}

/// Pull the `_service._protocol` labels out of an SRV-style domain.
///
/// `_sip._tcp.example.com` → `("_sip", "_tcp")`. Falls back to empty strings
/// when the leading labels do not match the SRV convention — UniFi will
/// reject the create call, surfacing a vendor error to the user.
fn split_srv_labels(domain: &str) -> (String, String) {
    let mut parts = domain.split('.');
    let service = parts.next().unwrap_or("").to_string();
    let protocol = parts.next().unwrap_or("").to_string();
    (service, protocol)
}

/// Compare a UniFi policy against a `type_params` payload used by
/// `RecordWrite::delete_record`. Returns true when the policy is the one the
/// caller wants to delete (matches type + the value-bearing field).
pub fn policy_matches_delete_params(
    policy: &UnifiDnsPolicy,
    domain: &str,
    type_params: &[(&str, String)],
) -> bool {
    if !policy.domain.eq_ignore_ascii_case(domain) {
        return false;
    }

    let target_type = type_params
        .iter()
        .find(|(k, _)| *k == "type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");

    if policy.policy_type.dnsync_record_type() != target_type.to_uppercase() {
        return false;
    }

    // Match the value-bearing field if the caller supplied one. Structured
    // types fall back to first-match by domain+type (rare for UniFi where
    // the same domain+type usually has at most one policy).
    let value_field = |key: &str| -> Option<&str> {
        type_params
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    };

    match policy.policy_type {
        UnifiDnsPolicyType::ARecord => value_field("ipAddress")
            .map(|want| policy.ipv4_address.as_deref() == Some(want))
            .unwrap_or(true),
        UnifiDnsPolicyType::AaaaRecord => value_field("ipAddress")
            .map(|want| policy.ipv6_address.as_deref() == Some(want))
            .unwrap_or(true),
        UnifiDnsPolicyType::CnameRecord => value_field("cname")
            .map(|want| policy.target_domain.as_deref() == Some(want))
            .unwrap_or(true),
        UnifiDnsPolicyType::TxtRecord => value_field("text")
            .map(|want| policy.text.as_deref() == Some(want))
            .unwrap_or(true),
        UnifiDnsPolicyType::MxRecord => {
            value_field("exchange")
                .map(|want| policy.mail_server_domain.as_deref() == Some(want))
                .unwrap_or(true)
                && value_field("preference")
                    .map(|want| policy.priority.map(|p| p.to_string()).as_deref() == Some(want))
                    .unwrap_or(true)
        }
        UnifiDnsPolicyType::SrvRecord => {
            value_field("target")
                .map(|want| policy.server_domain.as_deref() == Some(want))
                .unwrap_or(true)
                && value_field("port")
                    .map(|want| policy.port.map(|v| v.to_string()).as_deref() == Some(want))
                    .unwrap_or(true)
                && value_field("priority")
                    .map(|want| policy.priority.map(|v| v.to_string()).as_deref() == Some(want))
                    .unwrap_or(true)
                && value_field("weight")
                    .map(|want| policy.weight.map(|v| v.to_string()).as_deref() == Some(want))
                    .unwrap_or(true)
        }
        UnifiDnsPolicyType::ForwardDomain => false,
    }
}

#[cfg(test)]
mod tests;
