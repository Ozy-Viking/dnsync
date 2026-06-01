//! `RecordSelector` — record selection for deletion.

use super::*;

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
    Apl {
        #[arg(long = "prefix")]
        #[serde(rename = "addressPrefixes")]
        address_prefixes: Option<Vec<String>>,
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
            Self::Apl { .. } => "APL",
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
            Self::Apl { address_prefixes } => {
                if let Some(prefixes) = address_prefixes {
                    p.push(("addressPrefixes", prefixes.join(" ")));
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
