/// Describes DNS features supported by a vendor adapter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VendorCapabilities {
    pub zones: bool,
    pub records: bool,
    pub cache: bool,
    pub access_lists: bool,
    pub settings: bool,
    pub zone_import: bool,
    pub zone_export: bool,
}
