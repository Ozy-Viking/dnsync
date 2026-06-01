//! SSHFP/TLSA/DS numeric<->string conversions.

// ─── SSHFP ─────────────────────────────────────────────────────────────────

pub fn sshfp_algorithm_to_str(n: u64) -> &'static str {
    match n {
        1 => "RSA",
        2 => "DSA",
        3 => "ECDSA",
        4 => "Ed25519",
        6 => "Ed448",
        _ => "RSA",
    }
}

pub fn sshfp_algorithm_to_num(alg: &crate::core::dns::records::SshfpAlgorithm) -> u8 {
    use crate::core::dns::records::SshfpAlgorithm::*;
    match alg {
        Rsa => 1,
        Dsa => 2,
        Ecdsa => 3,
        Ed25519 => 4,
        Ed448 => 6,
    }
}

pub fn sshfp_fp_type_to_str(n: u64) -> &'static str {
    match n {
        1 => "SHA1",
        2 => "SHA256",
        _ => "SHA256",
    }
}

pub fn sshfp_fp_type_to_num(ft: &crate::core::dns::records::SshfpFingerprintType) -> u8 {
    use crate::core::dns::records::SshfpFingerprintType::*;
    match ft {
        Sha1 => 1,
        Sha256 => 2,
    }
}

// ─── TLSA ──────────────────────────────────────────────────────────────────

pub fn tlsa_cert_usage_to_num(cu: &crate::core::dns::records::TlsaCertUsage) -> u8 {
    use crate::core::dns::records::TlsaCertUsage::*;
    match cu {
        PkixTa => 0,
        PkixEe => 1,
        DaneTa => 2,
        DaneEe => 3,
    }
}

pub fn tlsa_cert_usage_to_str(n: u64) -> &'static str {
    match n {
        0 => "PKIX-TA",
        1 => "PKIX-EE",
        2 => "DANE-TA",
        3 => "DANE-EE",
        _ => "DANE-EE",
    }
}

pub fn tlsa_selector_to_num(s: &crate::core::dns::records::TlsaSelector) -> u8 {
    use crate::core::dns::records::TlsaSelector::*;
    match s {
        Cert => 0,
        Spki => 1,
    }
}

pub fn tlsa_selector_to_str(n: u64) -> &'static str {
    match n {
        0 => "Cert",
        1 => "SPKI",
        _ => "Cert",
    }
}

pub fn tlsa_matching_type_to_num(mt: &crate::core::dns::records::TlsaMatchingType) -> u8 {
    use crate::core::dns::records::TlsaMatchingType::*;
    match mt {
        Full => 0,
        Sha2_256 => 1,
        Sha2_512 => 2,
    }
}

pub fn tlsa_matching_type_to_str(n: u64) -> &'static str {
    match n {
        0 => "Full",
        1 => "SHA2-256",
        2 => "SHA2-512",
        _ => "Full",
    }
}

// ─── DS ────────────────────────────────────────────────────────────────────

pub fn ds_algorithm_to_num(alg: &crate::core::dns::records::DsAlgorithm) -> u8 {
    use crate::core::dns::records::DsAlgorithm::*;
    match alg {
        Rsamd5 => 1,
        Dsa => 3,
        Rsasha1 => 5,
        DsaNsec3Sha1 => 6,
        Rsasha1Nsec3Sha1 => 7,
        Rsasha256 => 8,
        Rsasha512 => 10,
        EccGost => 12,
        Ecdsap256sha256 => 13,
        Ecdsap384sha384 => 14,
        Ed25519 => 15,
        Ed448 => 16,
    }
}

pub fn ds_algorithm_to_str(n: u64) -> &'static str {
    match n {
        1 => "RSAMD5",
        3 => "DSA",
        5 => "RSASHA1",
        6 => "DSA-NSEC3-SHA1",
        7 => "RSASHA1-NSEC3-SHA1",
        8 => "RSASHA256",
        10 => "RSASHA512",
        12 => "ECC-GOST",
        13 => "ECDSAP256SHA256",
        14 => "ECDSAP384SHA384",
        15 => "ED25519",
        16 => "ED448",
        _ => "RSASHA256",
    }
}

pub fn ds_digest_type_to_num(dt: &crate::core::dns::records::DigestType) -> u8 {
    use crate::core::dns::records::DigestType::*;
    match dt {
        Sha1 => 1,
        Sha256 => 2,
        GostR341194 => 3,
        Sha384 => 4,
    }
}

pub fn ds_digest_type_to_str(n: u64) -> &'static str {
    match n {
        1 => "SHA1",
        2 => "SHA256",
        3 => "GOST-R-34-11-94",
        4 => "SHA384",
        _ => "SHA256",
    }
}
