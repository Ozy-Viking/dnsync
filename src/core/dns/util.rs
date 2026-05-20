/// Build the fully-qualified domain name from a possibly-relative label and an optional zone.
///
/// Examples:
/// - `("huly", Some("hankin.io"))` → `"huly.hankin.io"`
/// - `("huly.hankin.io", Some("hankin.io"))` → `"huly.hankin.io"` (already qualified)
/// - `("@", Some("hankin.io"))` → `"hankin.io"` (zone apex)
/// - `("huly.hankin.io", None)` → `"huly.hankin.io"` (passed through)
pub fn resolve_fqdn(domain: &str, zone: Option<&str>) -> String {
    let Some(zone) = zone else {
        return domain.trim_end_matches('.').to_string();
    };
    let domain = domain.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if domain == "@" {
        return zone.to_string();
    }
    let d_lower = domain.to_lowercase();
    let z_lower = zone.to_lowercase();
    if d_lower == z_lower || d_lower.ends_with(&format!(".{z_lower}")) {
        domain.to_string()
    } else {
        format!("{domain}.{zone}")
    }
}

/// Strip the leftmost DNS label to get the likely parent zone name.
/// Returns `None` for single-label names (e.g. `"hankin"`).
pub fn infer_zone(fqdn: &str) -> Option<String> {
    let fqdn = fqdn.trim_end_matches('.');
    fqdn.find('.').map(|pos| fqdn[pos + 1..].to_string())
}
