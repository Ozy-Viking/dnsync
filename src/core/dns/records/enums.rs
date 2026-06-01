//! DNSSEC/SSHFP/TLSA/forwarder enum helpers.

use super::*;

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
