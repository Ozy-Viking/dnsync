use std::net::{Ipv4Addr, Ipv6Addr};

use clap::Subcommand;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{
    dns::{
        responses::ListRecordsResponse,
        service::{ListRecordsOptions, RecordWrite, ZoneRead},
    },
    error::Result,
};

pub mod query;

/// List DNS records through a vendor-neutral zone reader.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn list_records<C: ZoneRead + ?Sized>(
    client: &C,
    domain: &str,
    zone: Option<&str>,
    options: ListRecordsOptions,
) -> Result<ListRecordsResponse> {
    client.list_records(domain, zone, options).await
}

/// Create a DNS record through a vendor-neutral record writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn create_record<C: RecordWrite + ?Sized>(
    client: &C,
    zone: &str,
    domain: &str,
    ttl: u32,
    record: &RecordData,
) -> Result<Value> {
    client.add_record(zone, domain, ttl, record).await
}

/// Delete DNS records through a vendor-neutral record writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn delete_record<'a, C: RecordWrite + ?Sized>(
    client: &'a C,
    zone: &'a str,
    domain: &'a str,
    type_params: &'a [(&'a str, String)],
) -> Result<Value> {
    client.delete_record(zone, domain, type_params).await
}

// ─── Supporting enums ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum DsAlgorithm {
    #[serde(rename = "RSAMD5")]
    Rsamd5,
    #[serde(rename = "DSA")]
    Dsa,
    #[serde(rename = "RSASHA1")]
    Rsasha1,
    #[serde(rename = "DSA-NSEC3-SHA1")]
    DsaNsec3Sha1,
    #[serde(rename = "RSASHA1-NSEC3-SHA1")]
    Rsasha1Nsec3Sha1,
    #[serde(rename = "RSASHA256")]
    Rsasha256,
    #[serde(rename = "RSASHA512")]
    Rsasha512,
    #[serde(rename = "ECC-GOST")]
    EccGost,
    #[serde(rename = "ECDSAP256SHA256")]
    Ecdsap256sha256,
    #[serde(rename = "ECDSAP384SHA384")]
    Ecdsap384sha384,
    #[serde(rename = "ED25519")]
    Ed25519,
    #[serde(rename = "ED448")]
    Ed448,
}

impl DsAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rsamd5 => "RSAMD5",
            Self::Dsa => "DSA",
            Self::Rsasha1 => "RSASHA1",
            Self::DsaNsec3Sha1 => "DSA-NSEC3-SHA1",
            Self::Rsasha1Nsec3Sha1 => "RSASHA1-NSEC3-SHA1",
            Self::Rsasha256 => "RSASHA256",
            Self::Rsasha512 => "RSASHA512",
            Self::EccGost => "ECC-GOST",
            Self::Ecdsap256sha256 => "ECDSAP256SHA256",
            Self::Ecdsap384sha384 => "ECDSAP384SHA384",
            Self::Ed25519 => "ED25519",
            Self::Ed448 => "ED448",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum DigestType {
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "GOST-R-34-11-94")]
    GostR341194,
    #[serde(rename = "SHA384")]
    Sha384,
}

impl DigestType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::GostR341194 => "GOST-R-34-11-94",
            Self::Sha384 => "SHA384",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum SshfpAlgorithm {
    #[serde(rename = "RSA")]
    Rsa,
    #[serde(rename = "DSA")]
    Dsa,
    #[serde(rename = "ECDSA")]
    Ecdsa,
    #[serde(rename = "Ed25519")]
    Ed25519,
    #[serde(rename = "Ed448")]
    Ed448,
}

impl SshfpAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rsa => "RSA",
            Self::Dsa => "DSA",
            Self::Ecdsa => "ECDSA",
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum SshfpFingerprintType {
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
}

impl SshfpFingerprintType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum TlsaCertUsage {
    #[serde(rename = "PKIX-TA")]
    PkixTa,
    #[serde(rename = "PKIX-EE")]
    PkixEe,
    #[serde(rename = "DANE-TA")]
    DaneTa,
    #[serde(rename = "DANE-EE")]
    DaneEe,
}

impl TlsaCertUsage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PkixTa => "PKIX-TA",
            Self::PkixEe => "PKIX-EE",
            Self::DaneTa => "DANE-TA",
            Self::DaneEe => "DANE-EE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum TlsaSelector {
    #[serde(rename = "Cert")]
    Cert,
    #[serde(rename = "SPKI")]
    Spki,
}

impl TlsaSelector {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cert => "Cert",
            Self::Spki => "SPKI",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum TlsaMatchingType {
    #[serde(rename = "Full")]
    Full,
    #[serde(rename = "SHA2-256")]
    Sha2_256,
    #[serde(rename = "SHA2-512")]
    Sha2_512,
}

impl TlsaMatchingType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "Full",
            Self::Sha2_256 => "SHA2-256",
            Self::Sha2_512 => "SHA2-512",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum FwdProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
}

impl FwdProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Udp => "Udp",
            Self::Tcp => "Tcp",
            Self::Tls => "Tls",
            Self::Https => "Https",
            Self::Quic => "Quic",
        }
    }
}

// ─── RecordData ───────────────────────────────────────────────────────────────

/// Typed DNS record data. Each variant holds exactly the fields required for
/// that record type, mapping directly to Technitium API parameters.
///
/// Note: DNSKEY is intentionally absent — Technitium manages DNSKEY records
/// automatically via its DNSSEC key management API, not via record add/delete.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Subcommand)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
#[command(rename_all = "lower")]
pub enum RecordData {
    /// IPv4 address  e.g. `a 1.2.3.4`
    A {
        #[serde(rename = "ipAddress")]
        ip: Ipv4Addr,
    },
    /// IPv6 address  e.g. `aaaa 2001:db8::1`
    Aaaa {
        #[serde(rename = "ipAddress")]
        ip: Ipv6Addr,
    },
    /// Apex alias (Technitium-specific)  e.g. `aname target.example.net`
    Aname { aname: String },
    /// DNS App record  e.g. `app "Split Horizon" "SplitHorizon.SimpleAddress" '{}'`
    App {
        #[serde(rename = "appName")]
        app_name: String,
        #[serde(rename = "classPath")]
        class_path: String,
        /// JSON data string passed to the app
        #[serde(rename = "recordData")]
        record_data: String,
    },
    /// CA Authorization  e.g. `caa letsencrypt.org --tag issue`
    Caa {
        value: String,
        #[arg(long, default_value_t = 0)]
        flags: u8,
        /// issue, issuewild, or iodef
        #[arg(long, default_value = "issue")]
        tag: String,
    },
    /// Canonical name alias  e.g. `cname www.example.com`
    Cname {
        #[serde(rename = "cname")]
        target: String,
    },
    /// Subtree redirect  e.g. `dname target.example.com`
    Dname { dname: String },
    /// DNSSEC delegation signer  e.g. `ds 12345 RSASHA256 SHA256 abcdef...`
    Ds {
        #[serde(rename = "keyTag")]
        key_tag: u16,
        algorithm: DsAlgorithm,
        #[serde(rename = "digestType")]
        digest_type: DigestType,
        digest: String,
    },
    /// Conditional forwarder (Technitium-specific)  e.g. `fwd 1.1.1.1 --protocol Udp`
    Fwd {
        forwarder: String,
        #[arg(long, default_value = "Udp")]
        protocol: FwdProtocol,
        #[serde(rename = "forwarderPriority", default = "default_fwd_priority")]
        #[arg(long, default_value_t = 10)]
        priority: u16,
        #[serde(rename = "dnssecValidation", default)]
        #[arg(long, default_value_t = false)]
        dnssec_validation: bool,
    },
    /// HTTPS service binding  e.g. `https --svc-priority 1 svc.example.com`
    Https {
        #[serde(rename = "svcTargetName")]
        svc_target_name: String,
        #[serde(rename = "svcPriority")]
        #[arg(long, default_value_t = 1)]
        svc_priority: u16,
        #[serde(rename = "svcParams")]
        #[arg(long)]
        svc_params: Option<String>,
        #[serde(rename = "autoIpv4Hint", default)]
        #[arg(long, default_value_t = false)]
        auto_ipv4_hint: bool,
        #[serde(rename = "autoIpv6Hint", default)]
        #[arg(long, default_value_t = false)]
        auto_ipv6_hint: bool,
    },
    /// Mail exchange  e.g. `mx mail.example.com --preference 10`
    Mx {
        exchange: String,
        #[serde(default = "default_mx_preference")]
        #[arg(long, default_value_t = 10)]
        preference: u16,
    },
    /// Naming authority pointer  e.g. `naptr --order 10 --preference 20 ...`
    Naptr {
        #[serde(rename = "naptrOrder")]
        #[arg(long)]
        order: u16,
        #[serde(rename = "naptrPreference")]
        #[arg(long)]
        preference: u16,
        #[serde(rename = "naptrFlags")]
        #[arg(long, default_value = "")]
        flags: String,
        #[serde(rename = "naptrServices")]
        #[arg(long, default_value = "")]
        services: String,
        #[serde(rename = "naptrRegexp")]
        #[arg(long, default_value = "")]
        regexp: String,
        #[serde(rename = "naptrReplacement")]
        replacement: String,
    },
    /// Name server  e.g. `ns ns1.example.com` or `ns ns1.example.com --glue 1.2.3.4`
    Ns {
        #[serde(rename = "nameServer")]
        nameserver: String,
        #[arg(long)]
        glue: Option<String>,
    },
    /// Reverse DNS pointer  e.g. `ptr host.example.com`
    Ptr {
        #[serde(rename = "ptrName")]
        name: String,
    },
    /// SSH fingerprint  e.g. `sshfp RSA SHA256 abcdef...`
    Sshfp {
        #[serde(rename = "sshfpAlgorithm")]
        algorithm: SshfpAlgorithm,
        #[serde(rename = "sshfpFingerprintType")]
        fingerprint_type: SshfpFingerprintType,
        #[serde(rename = "sshfpFingerprint")]
        fingerprint: String,
    },
    /// Service locator  e.g. `srv sip.example.com --port 5060 --priority 10 --weight 20`
    Srv {
        target: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value_t = 0)]
        priority: u16,
        #[arg(long, default_value_t = 0)]
        weight: u16,
    },
    /// Service binding (generic)  e.g. `svcb --svc-priority 1 svc.example.com`
    Svcb {
        #[serde(rename = "svcTargetName")]
        svc_target_name: String,
        #[serde(rename = "svcPriority")]
        #[arg(long, default_value_t = 1)]
        svc_priority: u16,
        #[serde(rename = "svcParams")]
        #[arg(long)]
        svc_params: Option<String>,
        #[serde(rename = "autoIpv4Hint", default)]
        #[arg(long, default_value_t = false)]
        auto_ipv4_hint: bool,
        #[serde(rename = "autoIpv6Hint", default)]
        #[arg(long, default_value_t = false)]
        auto_ipv6_hint: bool,
    },
    /// DANE TLS authentication  e.g. `tlsa DANE-EE SPKI SHA2-256 abcdef...`
    Tlsa {
        #[serde(rename = "tlsaCertificateUsage")]
        cert_usage: TlsaCertUsage,
        #[serde(rename = "tlsaSelector")]
        selector: TlsaSelector,
        #[serde(rename = "tlsaMatchingType")]
        matching_type: TlsaMatchingType,
        #[serde(rename = "tlsaCertificateAssociationData")]
        cert_association_data: String,
    },
    /// Text record  e.g. `txt "v=spf1 ~all"` or `txt "long..." --split-text`
    Txt {
        text: String,
        #[serde(rename = "splitText", default)]
        #[arg(long, default_value_t = false)]
        split_text: bool,
    },
    /// URI record  e.g. `uri https://example.com --priority 10 --weight 1`
    Uri {
        uri: String,
        #[serde(rename = "uriPriority")]
        #[arg(long, default_value_t = 10)]
        priority: u16,
        #[serde(rename = "uriWeight")]
        #[arg(long, default_value_t = 1)]
        weight: u16,
    },
    /// Raw/unknown type — rdata as colon-separated hex string  e.g. `unknown 0a0b0c...`
    Unknown { rdata: String },
}

fn default_mx_preference() -> u16 {
    10
}
fn default_fwd_priority() -> u16 {
    10
}

impl RecordData {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::A { .. } => "A",
            Self::Aaaa { .. } => "AAAA",
            Self::Aname { .. } => "ANAME",
            Self::App { .. } => "APP",
            Self::Caa { .. } => "CAA",
            Self::Cname { .. } => "CNAME",
            Self::Dname { .. } => "DNAME",
            Self::Ds { .. } => "DS",
            Self::Fwd { .. } => "FWD",
            Self::Https { .. } => "HTTPS",
            Self::Mx { .. } => "MX",
            Self::Naptr { .. } => "NAPTR",
            Self::Ns { .. } => "NS",
            Self::Ptr { .. } => "PTR",
            Self::Sshfp { .. } => "SSHFP",
            Self::Srv { .. } => "SRV",
            Self::Svcb { .. } => "SVCB",
            Self::Tlsa { .. } => "TLSA",
            Self::Txt { .. } => "TXT",
            Self::Uri { .. } => "URI",
            Self::Unknown { .. } => "UNKNOWN",
        }
    }

    pub fn to_api_params(&self) -> Vec<(&'static str, String)> {
        let mut p = vec![("type", self.type_name().into())];
        match self {
            Self::A { ip } => p.push(("ipAddress", ip.to_string())),
            Self::Aaaa { ip } => p.push(("ipAddress", ip.to_string())),
            Self::Aname { aname } => p.push(("aname", aname.clone())),
            Self::App {
                app_name,
                class_path,
                record_data,
            } => {
                p.push(("appName", app_name.clone()));
                p.push(("classPath", class_path.clone()));
                p.push(("recordData", record_data.clone()));
            }
            Self::Caa { flags, tag, value } => {
                p.push(("flags", flags.to_string()));
                p.push(("tag", tag.clone()));
                p.push(("value", value.clone()));
            }
            Self::Cname { target } => p.push(("cname", target.clone())),
            Self::Dname { dname } => p.push(("dname", dname.clone())),
            Self::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                p.push(("keyTag", key_tag.to_string()));
                p.push(("algorithm", algorithm.as_str().into()));
                p.push(("digestType", digest_type.as_str().into()));
                p.push(("digest", digest.clone()));
            }
            Self::Fwd {
                forwarder,
                protocol,
                priority,
                dnssec_validation,
            } => {
                p.push(("forwarder", forwarder.clone()));
                p.push(("protocol", protocol.as_str().into()));
                p.push(("forwarderPriority", priority.to_string()));
                p.push(("dnssecValidation", dnssec_validation.to_string()));
            }
            Self::Https {
                svc_priority,
                svc_target_name,
                svc_params,
                auto_ipv4_hint,
                auto_ipv6_hint,
            }
            | Self::Svcb {
                svc_priority,
                svc_target_name,
                svc_params,
                auto_ipv4_hint,
                auto_ipv6_hint,
            } => {
                p.push(("svcPriority", svc_priority.to_string()));
                p.push(("svcTargetName", svc_target_name.clone()));
                if let Some(params) = svc_params {
                    p.push(("svcParams", params.clone()));
                }
                p.push(("autoIpv4Hint", auto_ipv4_hint.to_string()));
                p.push(("autoIpv6Hint", auto_ipv6_hint.to_string()));
            }
            Self::Mx {
                preference,
                exchange,
            } => {
                p.push(("preference", preference.to_string()));
                p.push(("exchange", exchange.clone()));
            }
            Self::Naptr {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => {
                p.push(("naptrOrder", order.to_string()));
                p.push(("naptrPreference", preference.to_string()));
                p.push(("naptrFlags", flags.clone()));
                p.push(("naptrServices", services.clone()));
                p.push(("naptrRegexp", regexp.clone()));
                p.push(("naptrReplacement", replacement.clone()));
            }
            Self::Ns { nameserver, glue } => {
                p.push(("nameServer", nameserver.clone()));
                if let Some(g) = glue {
                    p.push(("glue", g.clone()));
                }
            }
            Self::Ptr { name } => p.push(("ptrName", name.clone())),
            Self::Sshfp {
                algorithm,
                fingerprint_type,
                fingerprint,
            } => {
                p.push(("sshfpAlgorithm", algorithm.as_str().into()));
                p.push(("sshfpFingerprintType", fingerprint_type.as_str().into()));
                p.push(("sshfpFingerprint", fingerprint.clone()));
            }
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                p.push(("priority", priority.to_string()));
                p.push(("weight", weight.to_string()));
                p.push(("port", port.to_string()));
                p.push(("target", target.clone()));
            }
            Self::Tlsa {
                cert_usage,
                selector,
                matching_type,
                cert_association_data,
            } => {
                p.push(("tlsaCertificateUsage", cert_usage.as_str().into()));
                p.push(("tlsaSelector", selector.as_str().into()));
                p.push(("tlsaMatchingType", matching_type.as_str().into()));
                p.push((
                    "tlsaCertificateAssociationData",
                    cert_association_data.clone(),
                ));
            }
            Self::Txt { text, split_text } => {
                p.push(("text", text.clone()));
                p.push(("splitText", split_text.to_string()));
            }
            Self::Uri {
                priority,
                weight,
                uri,
            } => {
                p.push(("uriPriority", priority.to_string()));
                p.push(("uriWeight", weight.to_string()));
                p.push(("uri", uri.clone()));
            }
            Self::Unknown { rdata } => p.push(("rdata", rdata.clone())),
        }
        p
    }
}

/// Identifies one or more records for deletion. Similar to [`RecordData`] but
/// intentionally not identical — every value field is optional, and some variants
/// omit fields that are only meaningful at creation time (e.g. `Caa`, `Ds`,
/// `App`, `Https`). A missing field broadens the selector (e.g. `A { ip: None }`
/// matches every A record at the domain); compare [`RecordData`] to understand
/// which fields each variant actually exposes.
///
/// Derives both `Subcommand` (for clap-driven CLI parsing) and `Deserialize` +
/// `JsonSchema` (for MCP tool params), so the CLI and MCP share one type.
#[derive(Debug, Clone, Deserialize, JsonSchema, Subcommand)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
#[command(rename_all = "lower")]
pub enum RecordSelector {
    /// e.g. `a` (all A records) or `a 1.2.3.4` (specific)
    A {
        #[serde(rename = "ipAddress")]
        ip: Option<Ipv4Addr>,
    },
    /// e.g. `aaaa` or `aaaa 2001:db8::1`
    Aaaa {
        #[serde(rename = "ipAddress")]
        ip: Option<Ipv6Addr>,
    },
    Aname {
        aname: Option<String>,
    },
    App {
        #[serde(rename = "appName")]
        app_name: Option<String>,
        #[serde(rename = "classPath")]
        class_path: Option<String>,
    },
    Caa {
        value: Option<String>,
    },
    Cname {
        #[serde(rename = "cname")]
        target: Option<String>,
    },
    Dname {
        dname: Option<String>,
    },
    Ds {
        #[serde(rename = "keyTag")]
        key_tag: Option<u16>,
    },
    Fwd {
        forwarder: Option<String>,
    },
    Https {
        #[serde(rename = "svcTargetName")]
        svc_target_name: Option<String>,
    },
    Mx {
        exchange: Option<String>,
    },
    Naptr {
        #[serde(rename = "naptrReplacement")]
        replacement: Option<String>,
    },
    Ns {
        #[serde(rename = "nameServer")]
        nameserver: Option<String>,
    },
    Ptr {
        #[serde(rename = "ptrName")]
        name: Option<String>,
    },
    Sshfp {
        #[serde(rename = "sshfpFingerprint")]
        fingerprint: Option<String>,
    },
    Srv {
        target: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        priority: Option<u16>,
        #[arg(long)]
        weight: Option<u16>,
    },
    Svcb {
        #[serde(rename = "svcTargetName")]
        svc_target_name: Option<String>,
    },
    Tlsa {
        #[serde(rename = "tlsaCertificateAssociationData")]
        cert_association_data: Option<String>,
    },
    Txt {
        text: Option<String>,
    },
    Uri {
        uri: Option<String>,
    },
    Unknown {
        rdata: Option<String>,
    },
}

impl RecordSelector {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::A { .. } => "A",
            Self::Aaaa { .. } => "AAAA",
            Self::Aname { .. } => "ANAME",
            Self::App { .. } => "APP",
            Self::Caa { .. } => "CAA",
            Self::Cname { .. } => "CNAME",
            Self::Dname { .. } => "DNAME",
            Self::Ds { .. } => "DS",
            Self::Fwd { .. } => "FWD",
            Self::Https { .. } => "HTTPS",
            Self::Mx { .. } => "MX",
            Self::Naptr { .. } => "NAPTR",
            Self::Ns { .. } => "NS",
            Self::Ptr { .. } => "PTR",
            Self::Sshfp { .. } => "SSHFP",
            Self::Srv { .. } => "SRV",
            Self::Svcb { .. } => "SVCB",
            Self::Tlsa { .. } => "TLSA",
            Self::Txt { .. } => "TXT",
            Self::Uri { .. } => "URI",
            Self::Unknown { .. } => "UNKNOWN",
        }
    }

    pub fn to_api_params(&self) -> Vec<(&'static str, String)> {
        let mut p = vec![("type", self.type_name().into())];
        match self {
            Self::A { ip } => {
                if let Some(v) = ip {
                    p.push(("ipAddress", v.to_string()));
                }
            }
            Self::Aaaa { ip } => {
                if let Some(v) = ip {
                    p.push(("ipAddress", v.to_string()));
                }
            }
            Self::Aname { aname } => {
                if let Some(v) = aname {
                    p.push(("aname", v.clone()));
                }
            }
            Self::App {
                app_name,
                class_path,
            } => {
                if let Some(v) = app_name {
                    p.push(("appName", v.clone()));
                }
                if let Some(v) = class_path {
                    p.push(("classPath", v.clone()));
                }
            }
            Self::Caa { value } => {
                if let Some(v) = value {
                    p.push(("value", v.clone()));
                }
            }
            Self::Cname { target } => {
                if let Some(v) = target {
                    p.push(("cname", v.clone()));
                }
            }
            Self::Dname { dname } => {
                if let Some(v) = dname {
                    p.push(("dname", v.clone()));
                }
            }
            Self::Ds { key_tag } => {
                if let Some(v) = key_tag {
                    p.push(("keyTag", v.to_string()));
                }
            }
            Self::Fwd { forwarder } => {
                if let Some(v) = forwarder {
                    p.push(("forwarder", v.clone()));
                }
            }
            Self::Https { svc_target_name } | Self::Svcb { svc_target_name } => {
                if let Some(v) = svc_target_name {
                    p.push(("svcTargetName", v.clone()));
                }
            }
            Self::Mx { exchange } => {
                if let Some(v) = exchange {
                    p.push(("exchange", v.clone()));
                }
            }
            Self::Naptr { replacement } => {
                if let Some(v) = replacement {
                    p.push(("naptrReplacement", v.clone()));
                }
            }
            Self::Ns { nameserver } => {
                if let Some(v) = nameserver {
                    p.push(("nameServer", v.clone()));
                }
            }
            Self::Ptr { name } => {
                if let Some(v) = name {
                    p.push(("ptrName", v.clone()));
                }
            }
            Self::Sshfp { fingerprint } => {
                if let Some(v) = fingerprint {
                    p.push(("sshfpFingerprint", v.clone()));
                }
            }
            Self::Srv {
                target,
                port,
                priority,
                weight,
            } => {
                if let Some(v) = target {
                    p.push(("target", v.clone()));
                }
                if let Some(v) = port {
                    p.push(("port", v.to_string()));
                }
                if let Some(v) = priority {
                    p.push(("priority", v.to_string()));
                }
                if let Some(v) = weight {
                    p.push(("weight", v.to_string()));
                }
            }
            Self::Tlsa {
                cert_association_data,
            } => {
                if let Some(v) = cert_association_data {
                    p.push(("tlsaCertificateAssociationData", v.clone()));
                }
            }
            Self::Txt { text } => {
                if let Some(v) = text {
                    p.push(("text", v.clone()));
                }
            }
            Self::Uri { uri } => {
                if let Some(v) = uri {
                    p.push(("uri", v.clone()));
                }
            }
            Self::Unknown { rdata } => {
                if let Some(v) = rdata {
                    p.push(("rdata", v.clone()));
                }
            }
        }
        p
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};

    // ── Fixtures ──────────────────────────────────────────────────────────────

    #[fixture]
    fn a_record() -> RecordData {
        RecordData::A {
            ip: "1.2.3.4".parse().unwrap(),
        }
    }

    #[fixture]
    fn mx_record() -> RecordData {
        RecordData::Mx {
            preference: 10,
            exchange: "mail.example.com".into(),
        }
    }

    #[fixture]
    fn srv_record() -> RecordData {
        RecordData::Srv {
            priority: 10,
            weight: 20,
            port: 5060,
            target: "sip.example.com".into(),
        }
    }

    #[fixture]
    fn ns_with_glue() -> RecordData {
        RecordData::Ns {
            nameserver: "ns1.example.com".into(),
            glue: Some("1.2.3.4".into()),
        }
    }

    #[fixture]
    fn ns_without_glue() -> RecordData {
        RecordData::Ns {
            nameserver: "ns1.example.com".into(),
            glue: None,
        }
    }

    // ── type_name — every variant ─────────────────────────────────────────────

    #[rstest]
    #[case::a(RecordData::A { ip: "1.2.3.4".parse().unwrap() }, "A")]
    #[case::aaaa(RecordData::Aaaa { ip: "::1".parse().unwrap() }, "AAAA")]
    #[case::aname(RecordData::Aname { aname: "t.example.com".into() }, "ANAME")]
    #[case::app(RecordData::App { app_name: "App".into(), class_path: "C".into(), record_data: "{}".into() }, "APP")]
    #[case::caa(RecordData::Caa { flags: 0, tag: "issue".into(), value: "le.org".into() }, "CAA")]
    #[case::cname(RecordData::Cname { target: "www.example.com".into() }, "CNAME")]
    #[case::dname(RecordData::Dname { dname: "other.example.com".into() }, "DNAME")]
    #[case::ds(RecordData::Ds { key_tag: 1, algorithm: DsAlgorithm::Rsasha256, digest_type: DigestType::Sha256, digest: "ab".into() }, "DS")]
    #[case::fwd(RecordData::Fwd { forwarder: "1.1.1.1".into(), protocol: FwdProtocol::Udp, priority: 10, dnssec_validation: false }, "FWD")]
    #[case::https(RecordData::Https { svc_priority: 1, svc_target_name: "svc.example.com".into(), svc_params: None, auto_ipv4_hint: false, auto_ipv6_hint: false }, "HTTPS")]
    #[case::mx(RecordData::Mx { preference: 10, exchange: "mail.example.com".into() }, "MX")]
    #[case::naptr(RecordData::Naptr { order: 10, preference: 20, flags: "U".into(), services: "E2U+sip".into(), regexp: "".into(), replacement: ".".into() }, "NAPTR")]
    #[case::ns(RecordData::Ns { nameserver: "ns1.example.com".into(), glue: None }, "NS")]
    #[case::ptr(RecordData::Ptr { name: "host.example.com".into() }, "PTR")]
    #[case::sshfp(RecordData::Sshfp { algorithm: SshfpAlgorithm::Rsa, fingerprint_type: SshfpFingerprintType::Sha256, fingerprint: "abcd".into() }, "SSHFP")]
    #[case::srv(RecordData::Srv { priority: 0, weight: 0, port: 80, target: "t.example.com".into() }, "SRV")]
    #[case::svcb(RecordData::Svcb { svc_priority: 1, svc_target_name: "svc.example.com".into(), svc_params: None, auto_ipv4_hint: false, auto_ipv6_hint: false }, "SVCB")]
    #[case::tlsa(RecordData::Tlsa { cert_usage: TlsaCertUsage::DaneEe, selector: TlsaSelector::Spki, matching_type: TlsaMatchingType::Sha2_256, cert_association_data: "ab".into() }, "TLSA")]
    #[case::txt(RecordData::Txt { text: "v=spf1 ~all".into(), split_text: false }, "TXT")]
    #[case::uri(RecordData::Uri { priority: 1, weight: 1, uri: "https://example.com".into() }, "URI")]
    #[case::unknown(RecordData::Unknown { rdata: "0a0b".into() }, "UNKNOWN")]
    fn type_name_matches_variant(#[case] record: RecordData, #[case] expected: &str) {
        assert_eq!(record.type_name(), expected);
    }

    // ── to_api_params — correct field names ───────────────────────────────────

    fn params_map(record: &RecordData) -> std::collections::HashMap<&'static str, String> {
        record.to_api_params().into_iter().collect()
    }

    #[rstest]
    fn a_uses_ip_address_key(a_record: RecordData) {
        let p = params_map(&a_record);
        assert_eq!(p["type"], "A");
        assert_eq!(p["ipAddress"], "1.2.3.4");
        // Must NOT use "ip" — that's our internal field name
        assert!(!p.contains_key("ip"));
    }

    #[rstest]
    fn aaaa_uses_ip_address_key() {
        let r = RecordData::Aaaa {
            ip: "2001:db8::1".parse().unwrap(),
        };
        let p = params_map(&r);
        assert_eq!(p["type"], "AAAA");
        assert_eq!(p["ipAddress"], "2001:db8::1");
    }

    #[rstest]
    fn mx_uses_exchange_and_preference(mx_record: RecordData) {
        let p = params_map(&mx_record);
        assert_eq!(p["type"], "MX");
        assert_eq!(p["exchange"], "mail.example.com");
        assert_eq!(p["preference"], "10");
    }

    #[rstest]
    fn ns_uses_name_server_key(ns_without_glue: RecordData) {
        let p = params_map(&ns_without_glue);
        assert_eq!(p["type"], "NS");
        assert_eq!(p["nameServer"], "ns1.example.com"); // camelCase, not "nameserver"
        assert!(!p.contains_key("glue"));
    }

    #[rstest]
    fn ns_includes_glue_when_present(ns_with_glue: RecordData) {
        let p = params_map(&ns_with_glue);
        assert_eq!(p["glue"], "1.2.3.4");
    }

    #[rstest]
    fn ptr_uses_ptr_name_key() {
        let r = RecordData::Ptr {
            name: "host.example.com".into(),
        };
        let p = params_map(&r);
        assert_eq!(p["ptrName"], "host.example.com");
        assert!(!p.contains_key("name"));
    }

    #[rstest]
    fn cname_uses_cname_key() {
        let r = RecordData::Cname {
            target: "www.example.com".into(),
        };
        let p = params_map(&r);
        assert_eq!(p["cname"], "www.example.com");
        assert!(!p.contains_key("target"));
    }

    #[rstest]
    fn srv_uses_correct_keys(srv_record: RecordData) {
        let p = params_map(&srv_record);
        assert_eq!(p["type"], "SRV");
        assert_eq!(p["priority"], "10");
        assert_eq!(p["weight"], "20");
        assert_eq!(p["port"], "5060");
        assert_eq!(p["target"], "sip.example.com");
    }

    #[rstest]
    fn ds_uses_camel_case_keys() {
        let r = RecordData::Ds {
            key_tag: 12345,
            algorithm: DsAlgorithm::Ecdsap256sha256,
            digest_type: DigestType::Sha256,
            digest: "deadbeef".into(),
        };
        let p = params_map(&r);
        assert_eq!(p["keyTag"], "12345");
        assert_eq!(p["algorithm"], "ECDSAP256SHA256");
        assert_eq!(p["digestType"], "SHA256");
        assert_eq!(p["digest"], "deadbeef");
    }

    #[rstest]
    fn tlsa_uses_full_key_names() {
        let r = RecordData::Tlsa {
            cert_usage: TlsaCertUsage::DaneTa,
            selector: TlsaSelector::Cert,
            matching_type: TlsaMatchingType::Sha2_512,
            cert_association_data: "cafebabe".into(),
        };
        let p = params_map(&r);
        assert_eq!(p["tlsaCertificateUsage"], "DANE-TA");
        assert_eq!(p["tlsaSelector"], "Cert");
        assert_eq!(p["tlsaMatchingType"], "SHA2-512");
        assert_eq!(p["tlsaCertificateAssociationData"], "cafebabe");
    }

    #[rstest]
    fn fwd_uses_forwarder_priority_key() {
        let r = RecordData::Fwd {
            forwarder: "8.8.8.8".into(),
            protocol: FwdProtocol::Tls,
            priority: 5,
            dnssec_validation: true,
        };
        let p = params_map(&r);
        assert_eq!(p["forwarder"], "8.8.8.8");
        assert_eq!(p["protocol"], "Tls");
        assert_eq!(p["forwarderPriority"], "5"); // NOT "priority"
        assert_eq!(p["dnssecValidation"], "true");
    }

    #[rstest]
    fn https_and_svcb_use_svc_prefix() {
        let https = RecordData::Https {
            svc_priority: 1,
            svc_target_name: "svc.example.com".into(),
            svc_params: Some("alpn|h2".into()),
            auto_ipv4_hint: true,
            auto_ipv6_hint: false,
        };
        let svcb = RecordData::Svcb {
            svc_priority: 1,
            svc_target_name: "svc.example.com".into(),
            svc_params: Some("alpn|h2".into()),
            auto_ipv4_hint: true,
            auto_ipv6_hint: false,
        };
        for r in [&https, &svcb] {
            let p = params_map(r);
            assert_eq!(p["svcPriority"], "1");
            assert_eq!(p["svcTargetName"], "svc.example.com");
            assert_eq!(p["svcParams"], "alpn|h2");
            assert_eq!(p["autoIpv4Hint"], "true");
            assert_eq!(p["autoIpv6Hint"], "false");
        }
    }

    #[rstest]
    fn https_omits_svc_params_when_none() {
        let r = RecordData::Https {
            svc_priority: 1,
            svc_target_name: "svc.example.com".into(),
            svc_params: None,
            auto_ipv4_hint: false,
            auto_ipv6_hint: false,
        };
        let p = params_map(&r);
        assert!(!p.contains_key("svcParams"));
    }

    #[rstest]
    fn uri_uses_uri_prefix_keys() {
        let r = RecordData::Uri {
            priority: 5,
            weight: 3,
            uri: "https://example.com/path".into(),
        };
        let p = params_map(&r);
        assert_eq!(p["uriPriority"], "5");
        assert_eq!(p["uriWeight"], "3");
        assert_eq!(p["uri"], "https://example.com/path");
    }

    #[rstest]
    fn naptr_uses_naptr_prefix_keys() {
        let r = RecordData::Naptr {
            order: 10,
            preference: 20,
            flags: "U".into(),
            services: "E2U+sip".into(),
            regexp: "!^.*$!sip:info@example.com!".into(),
            replacement: ".".into(),
        };
        let p = params_map(&r);
        assert_eq!(p["naptrOrder"], "10");
        assert_eq!(p["naptrPreference"], "20");
        assert_eq!(p["naptrFlags"], "U");
        assert_eq!(p["naptrServices"], "E2U+sip");
        assert_eq!(p["naptrRegexp"], "!^.*$!sip:info@example.com!");
        assert_eq!(p["naptrReplacement"], ".");
    }

    #[rstest]
    fn txt_includes_split_text_flag() {
        let r = RecordData::Txt {
            text: "v=spf1 ~all".into(),
            split_text: true,
        };
        let p = params_map(&r);
        assert_eq!(p["text"], "v=spf1 ~all");
        assert_eq!(p["splitText"], "true");
    }

    // ── type_name is always first param ──────────────────────────────────────

    #[rstest]
    fn type_param_is_always_first(
        #[values(
            RecordData::A { ip: "1.2.3.4".parse().unwrap() },
            RecordData::Cname { target: "www.example.com".into() },
            RecordData::Txt { text: "test".into(), split_text: false }
        )]
        record: RecordData,
    ) {
        let params = record.to_api_params();
        assert_eq!(params[0].0, "type");
        assert_eq!(params[0].1, record.type_name());
    }
}
