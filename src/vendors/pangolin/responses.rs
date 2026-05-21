//! Pangolin API response types.
//!
//! These structs model the JSON responses from Pangolin's API endpoints
//! (`/org/{orgId}/domains`, `/org/{orgId}/domain/{domainId}/dns-records`,
//! `/org/{orgId}/domain/{domainId}/resources`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PangolinDomain {
    pub domain_id: String,
    pub base_domain: String,
    #[serde(rename = "type")]
    pub domain_type: String,
    pub verified: bool,
    pub failed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PangolinTarget {
    pub target_id: u64,
    pub resource_id: u64,
    pub site_id: u64,
    pub ip: String,
    pub port: u16,
    pub enabled: bool,
    pub health_status: String,
    pub site_name: String,
    pub site_online: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PangolinSite {
    pub site_id: u64,
    pub site_name: String,
    pub online: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PangolinResource {
    pub resource_id: u64,
    pub name: String,
    pub full_domain: String,
    pub http: bool,
    pub protocol: String,
    pub enabled: bool,
    pub domain_id: String,
    pub health: String,
    #[serde(default)]
    pub targets: Vec<PangolinTarget>,
    #[serde(default)]
    pub sites: Vec<PangolinSite>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PangolinDnsRecord {
    pub id: u64,
    pub domain_id: String,
    pub record_type: String,
    pub base_domain: String,
    pub value: String,
    pub verified: bool,
}
