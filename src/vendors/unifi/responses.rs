//! UniFi Network Integration API DNS-policy DTOs.
//!
//! These mirror the `IntegrationDnsPolicyDto` / `IntegrationDnsPolicyPageDto`
//! schemas published in the UniFi Network OpenAPI spec (v10.3.58). Only the
//! fields needed by dnsync are captured; unknown fields are tolerated so we
//! survive minor UniFi schema additions.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// UniFi DNS policy types as published by the OpenAPI spec.
///
/// `FORWARD_DOMAIN` is intentionally kept distinct from RR types so dnsync
/// can treat it as a resolver forward rule rather than a DNS record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnifiDnsPolicyType {
    #[serde(rename = "A_RECORD")]
    ARecord,
    #[serde(rename = "AAAA_RECORD")]
    AaaaRecord,
    #[serde(rename = "CNAME_RECORD")]
    CnameRecord,
    #[serde(rename = "MX_RECORD")]
    MxRecord,
    #[serde(rename = "TXT_RECORD")]
    TxtRecord,
    #[serde(rename = "SRV_RECORD")]
    SrvRecord,
    #[serde(rename = "FORWARD_DOMAIN")]
    ForwardDomain,
}

impl UnifiDnsPolicyType {
    /// UniFi wire string for this policy type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ARecord => "A_RECORD",
            Self::AaaaRecord => "AAAA_RECORD",
            Self::CnameRecord => "CNAME_RECORD",
            Self::MxRecord => "MX_RECORD",
            Self::TxtRecord => "TXT_RECORD",
            Self::SrvRecord => "SRV_RECORD",
            Self::ForwardDomain => "FORWARD_DOMAIN",
        }
    }

    /// dnsync record_type label for this policy type. Returns `"FORWARD_DOMAIN"`
    /// for forward rules — callers can branch on this to skip them where DNS
    /// RRsets are expected.
    pub fn dnsync_record_type(&self) -> &'static str {
        match self {
            Self::ARecord => "A",
            Self::AaaaRecord => "AAAA",
            Self::CnameRecord => "CNAME",
            Self::MxRecord => "MX",
            Self::TxtRecord => "TXT",
            Self::SrvRecord => "SRV",
            Self::ForwardDomain => "FORWARD_DOMAIN",
        }
    }
}

/// One DNS policy returned by `GET /sites/{siteId}/dns/policies/...`.
///
/// All `Option` fields are populated only for the policy types they apply to
/// — e.g. `ipv4Address` is set for `A_RECORD` only. Extra fields not modelled
/// here are accepted and ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiDnsPolicy {
    pub id: String,
    #[serde(rename = "type")]
    pub policy_type: UnifiDnsPolicyType,
    pub enabled: bool,
    pub domain: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail_server_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
}

/// Paginated wrapper as returned by `GET /sites/{siteId}/dns/policies`.
///
/// UniFi documents the fields as `offset`, `limit`, `count`, `totalCount`,
/// `data`. Some firmware revisions omit `count`/`totalCount` for empty pages,
/// so both are `Option`-typed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiDnsPolicyPage {
    #[serde(default)]
    pub offset: u32,
    #[serde(default)]
    pub limit: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "totalCount")]
    pub total_count: Option<u32>,
    #[serde(default)]
    pub data: Vec<UnifiDnsPolicy>,
}

impl UnifiDnsPolicyPage {
    /// Number of items in this page. Falls back to `data.len()` when the
    /// controller omits the `count` field.
    pub fn page_count(&self) -> u32 {
        self.count.unwrap_or(self.data.len() as u32)
    }

    /// Total items across all pages, or `None` if the controller omits
    /// `totalCount`. Callers must rely on the empty-page sentinel instead.
    pub fn total(&self) -> Option<u32> {
        self.total_count
    }
}

/// Convert a raw JSON value (the parsed UniFi response body) into our
/// `UnifiDnsPolicyPage` shape. Falls back to a single-page wrapper when the
/// controller returns a bare array.
pub fn parse_page(value: Value) -> Result<UnifiDnsPolicyPage, serde_json::Error> {
    if value.is_array() {
        let data: Vec<UnifiDnsPolicy> = serde_json::from_value(value)?;
        let len = data.len() as u32;
        return Ok(UnifiDnsPolicyPage {
            offset: 0,
            limit: len,
            count: Some(len),
            total_count: Some(len),
            data,
        });
    }
    serde_json::from_value(value)
}

/// One UniFi site as returned by `GET /sites`.
///
/// Different controller firmwares expose slightly different shapes — most have
/// `id` + `name`, some also include `internalReference`. All non-`id` fields
/// are optional so we tolerate that variation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiSite {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_reference: Option<String>,
}

impl UnifiSite {
    /// Best human-readable label for this site — `name` if present, otherwise
    /// the internal reference, otherwise the UUID.
    pub fn display_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.internal_reference.as_deref())
            .unwrap_or(&self.id)
    }
}

/// Paginated wrapper around `GET /sites`. Mirrors `UnifiDnsPolicyPage` so the
/// same pagination loop in the client can drive both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiSitePage {
    #[serde(default)]
    pub offset: u32,
    #[serde(default)]
    pub limit: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "totalCount")]
    pub total_count: Option<u32>,
    #[serde(default)]
    pub data: Vec<UnifiSite>,
}

impl UnifiSitePage {
    pub fn total(&self) -> Option<u32> {
        self.total_count
    }
}

/// Parse a `GET /sites` response into `UnifiSitePage`, tolerating a bare
/// array (some firmware revisions skip the envelope).
pub fn parse_site_page(value: Value) -> Result<UnifiSitePage, serde_json::Error> {
    if value.is_array() {
        let data: Vec<UnifiSite> = serde_json::from_value(value)?;
        let len = data.len() as u32;
        return Ok(UnifiSitePage {
            offset: 0,
            limit: len,
            count: Some(len),
            total_count: Some(len),
            data,
        });
    }
    serde_json::from_value(value)
}

/// Find the site that matches `needle` against its UUID, `name`, or
/// `internalReference`. Comparisons are case-insensitive so configs can
/// store `"Default"` even when the controller reports `"default"`.
pub fn match_site<'a>(sites: &'a [UnifiSite], needle: &str) -> Option<&'a UnifiSite> {
    let needle = needle.trim();
    if needle.is_empty() {
        return None;
    }
    sites.iter().find(|s| {
        s.id.eq_ignore_ascii_case(needle)
            || s.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(needle))
            || s.internal_reference
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(needle))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_record_policy_round_trips() {
        let v = json!({
            "id": "policy-1",
            "type": "A_RECORD",
            "enabled": true,
            "domain": "www.example.com",
            "ipv4Address": "192.168.1.10",
            "ttlSeconds": 300
        });
        let p: UnifiDnsPolicy = serde_json::from_value(v).unwrap();
        assert_eq!(p.id, "policy-1");
        assert_eq!(p.policy_type, UnifiDnsPolicyType::ARecord);
        assert!(p.enabled);
        assert_eq!(p.ipv4_address.as_deref(), Some("192.168.1.10"));
        assert_eq!(p.ttl_seconds, Some(300));
    }

    #[test]
    fn forward_domain_policy_parses() {
        let v = json!({
            "id": "fwd-1",
            "type": "FORWARD_DOMAIN",
            "enabled": true,
            "domain": "lan.example.com",
            "ipAddress": "192.168.1.1"
        });
        let p: UnifiDnsPolicy = serde_json::from_value(v).unwrap();
        assert_eq!(p.policy_type, UnifiDnsPolicyType::ForwardDomain);
        assert_eq!(p.ip_address.as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn srv_policy_parses_all_fields() {
        let v = json!({
            "id": "srv-1",
            "type": "SRV_RECORD",
            "enabled": false,
            "domain": "_sip._tcp.example.com",
            "serverDomain": "sip.example.com",
            "service": "_sip",
            "protocol": "_tcp",
            "port": 5060,
            "priority": 10,
            "weight": 20,
            "ttlSeconds": 600
        });
        let p: UnifiDnsPolicy = serde_json::from_value(v).unwrap();
        assert_eq!(p.policy_type, UnifiDnsPolicyType::SrvRecord);
        assert!(!p.enabled);
        assert_eq!(p.server_domain.as_deref(), Some("sip.example.com"));
        assert_eq!(p.service.as_deref(), Some("_sip"));
        assert_eq!(p.protocol.as_deref(), Some("_tcp"));
        assert_eq!(p.port, Some(5060));
        assert_eq!(p.priority, Some(10));
        assert_eq!(p.weight, Some(20));
    }

    #[test]
    fn unknown_fields_are_tolerated() {
        let v = json!({
            "id": "p",
            "type": "TXT_RECORD",
            "enabled": true,
            "domain": "_acme.example.com",
            "text": "challenge",
            "futureField": 42
        });
        let p: UnifiDnsPolicy = serde_json::from_value(v).unwrap();
        assert_eq!(p.text.as_deref(), Some("challenge"));
    }

    #[test]
    fn page_parses_full_envelope() {
        let v = json!({
            "offset": 0,
            "limit": 25,
            "count": 1,
            "totalCount": 1,
            "data": [
                {"id": "p", "type": "A_RECORD", "enabled": true, "domain": "x", "ipv4Address": "1.1.1.1"}
            ]
        });
        let page = parse_page(v).unwrap();
        assert_eq!(page.limit, 25);
        assert_eq!(page.page_count(), 1);
        assert_eq!(page.total(), Some(1));
    }

    #[test]
    fn page_parses_bare_array_fallback() {
        let v = json!([
            {"id": "p", "type": "A_RECORD", "enabled": true, "domain": "x", "ipv4Address": "1.1.1.1"}
        ]);
        let page = parse_page(v).unwrap();
        assert_eq!(page.data.len(), 1);
        assert_eq!(page.page_count(), 1);
    }

    #[test]
    fn policy_type_dnsync_label_maps_correctly() {
        assert_eq!(UnifiDnsPolicyType::ARecord.dnsync_record_type(), "A");
        assert_eq!(UnifiDnsPolicyType::AaaaRecord.dnsync_record_type(), "AAAA");
        assert_eq!(
            UnifiDnsPolicyType::CnameRecord.dnsync_record_type(),
            "CNAME"
        );
        assert_eq!(UnifiDnsPolicyType::MxRecord.dnsync_record_type(), "MX");
        assert_eq!(UnifiDnsPolicyType::TxtRecord.dnsync_record_type(), "TXT");
        assert_eq!(UnifiDnsPolicyType::SrvRecord.dnsync_record_type(), "SRV");
        assert_eq!(
            UnifiDnsPolicyType::ForwardDomain.dnsync_record_type(),
            "FORWARD_DOMAIN"
        );
    }

    // ── Site listing ────────────────────────────────────────────────────────

    fn make_sites() -> Vec<UnifiSite> {
        vec![
            UnifiSite {
                id: "11111111-1111-1111-1111-111111111111".to_string(),
                name: Some("Default".to_string()),
                internal_reference: Some("default".to_string()),
            },
            UnifiSite {
                id: "22222222-2222-2222-2222-222222222222".to_string(),
                name: Some("Lab".to_string()),
                internal_reference: None,
            },
        ]
    }

    #[test]
    fn site_page_parses_full_envelope() {
        let v = json!({
            "offset": 0,
            "limit": 25,
            "count": 1,
            "totalCount": 1,
            "data": [
                {"id": "abc", "name": "Default", "internalReference": "default"}
            ]
        });
        let page = parse_site_page(v).unwrap();
        assert_eq!(page.data.len(), 1);
        assert_eq!(page.data[0].name.as_deref(), Some("Default"));
    }

    #[test]
    fn site_page_tolerates_bare_array() {
        let v = json!([{ "id": "abc", "name": "Default" }]);
        let page = parse_site_page(v).unwrap();
        assert_eq!(page.data.len(), 1);
    }

    #[test]
    fn site_page_tolerates_missing_optional_fields() {
        let v = json!({ "data": [{ "id": "minimal" }] });
        let page = parse_site_page(v).unwrap();
        assert!(page.data[0].name.is_none());
        assert_eq!(page.data[0].display_name(), "minimal");
    }

    #[test]
    fn match_site_finds_by_uuid() {
        let sites = make_sites();
        let found = match_site(&sites, "22222222-2222-2222-2222-222222222222").unwrap();
        assert_eq!(found.name.as_deref(), Some("Lab"));
    }

    #[test]
    fn match_site_finds_by_name_case_insensitively() {
        let sites = make_sites();
        let found = match_site(&sites, "default").unwrap();
        assert_eq!(found.id, "11111111-1111-1111-1111-111111111111");
    }

    #[test]
    fn match_site_finds_by_internal_reference() {
        let sites = make_sites();
        // The name is "Default" with capital D; internalReference is lowercase
        // "default". A configured value of "default" should still resolve.
        let found = match_site(&sites, "DEFAULT").unwrap();
        assert_eq!(found.id, "11111111-1111-1111-1111-111111111111");
    }

    #[test]
    fn match_site_returns_none_for_unknown() {
        let sites = make_sites();
        assert!(match_site(&sites, "Missing").is_none());
    }

    #[test]
    fn match_site_rejects_empty_needle() {
        let sites = make_sites();
        assert!(match_site(&sites, "   ").is_none());
        assert!(match_site(&sites, "").is_none());
    }

    #[test]
    fn site_display_name_prefers_name() {
        let s = UnifiSite {
            id: "id".into(),
            name: Some("Pretty".into()),
            internal_reference: Some("ref".into()),
        };
        assert_eq!(s.display_name(), "Pretty");
    }

    #[test]
    fn site_display_name_falls_back_to_internal_reference() {
        let s = UnifiSite {
            id: "id".into(),
            name: None,
            internal_reference: Some("ref".into()),
        };
        assert_eq!(s.display_name(), "ref");
    }

    #[test]
    fn site_display_name_falls_back_to_id() {
        let s = UnifiSite {
            id: "the-id".into(),
            name: None,
            internal_reference: None,
        };
        assert_eq!(s.display_name(), "the-id");
    }
}
