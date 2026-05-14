/// Shared DNS zone summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSummary {
    pub name: String,
    pub zone_type: String,
    pub disabled: bool,
}
