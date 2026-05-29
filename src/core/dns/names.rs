//! DNS name normalization helpers shared by vendor adapters.

/// Strip the trailing `.{zone_name}` suffix from an FQDN and return a
/// zone-relative owner name.
///
/// Returns `"@"` for the zone apex. If the name is outside the supplied zone,
/// the original name is returned unchanged.
pub fn relative_to_zone(fqdn: &str, zone_name: &str) -> String {
    let fqdn_lower = fqdn.to_ascii_lowercase();
    let zone_lower = zone_name.to_ascii_lowercase();

    if fqdn_lower == zone_lower {
        return "@".to_string();
    }

    let suffix = format!(".{zone_lower}");
    if fqdn_lower.ends_with(&suffix) {
        fqdn[..fqdn.len() - suffix.len()].to_string()
    } else {
        fqdn.to_string()
    }
}

/// True when `domain` is the zone apex or a name below the zone.
pub fn domain_matches_zone(domain: &str, zone_name: &str) -> bool {
    let domain = domain.to_lowercase();
    let zone = zone_name.to_lowercase();
    domain == zone || domain.ends_with(&format!(".{zone}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_to_zone_returns_at_for_apex() {
        assert_eq!(relative_to_zone("example.com", "example.com"), "@");
    }

    #[test]
    fn relative_to_zone_strips_zone_suffix_case_insensitively() {
        assert_eq!(relative_to_zone("Api.Example.Com", "example.com"), "Api");
    }

    #[test]
    fn relative_to_zone_preserves_out_of_zone_name() {
        assert_eq!(relative_to_zone("other.net", "example.com"), "other.net");
    }

    #[test]
    fn domain_matches_zone_accepts_apex_and_children() {
        assert!(domain_matches_zone("example.com", "example.com"));
        assert!(domain_matches_zone("api.example.com", "example.com"));
        assert!(!domain_matches_zone("badexample.com", "example.com"));
    }
}
