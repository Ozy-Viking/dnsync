//! `RecordData` — typed record payloads and API param mapping.

use super::*;

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
    /// RFC 3123 Address Prefix List  e.g. `apl --prefix 1:10.5.161.84/32 --prefix 1:10.5.161.85/32`
    ///
    /// Each prefix entry is a string of the form `[!]addressFamily:afdPart/prefixLength`
    /// where `1` = IPv4 and `2` = IPv6. A leading `!` negates the entry.
    Apl {
        #[arg(long = "prefix")]
        #[serde(rename = "addressPrefixes")]
        address_prefixes: Vec<String>,
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

pub(crate) fn default_mx_preference() -> u16 {
    10
}
pub(crate) fn default_fwd_priority() -> u16 {
    10
}

impl RecordData {
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
            Self::A { ip } => p.push(("ipAddress", ip.to_string())),
            Self::Aaaa { ip } => p.push(("ipAddress", ip.to_string())),
            Self::Apl { address_prefixes } => {
                p.push(("addressPrefixes", address_prefixes.join(" ")));
            }
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
