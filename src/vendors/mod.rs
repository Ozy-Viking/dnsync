pub use crate::core::dns::service::{DnsRead, DnsService, DnsVendor, DnsWrite};

pub mod runtime;

#[cfg(feature = "technitium")]
pub mod technitium;

#[cfg(feature = "pangolin")]
pub mod pangolin;

#[cfg(feature = "cloudflare")]
pub mod cloudflare;

/// Identifies which DNS vendor backend a server entry uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum VendorKind {
    #[default]
    Technitium,
    Pangolin,
    Cloudflare,
}

/// Returns the default base URL for a vendor backend.
pub fn vendor_default_base_url(vendor: VendorKind) -> &'static str {
    match vendor {
        #[cfg(feature = "technitium")]
        VendorKind::Technitium => technitium::TECHNITIUM_DEFAULT_BASE_URL,
        #[cfg(feature = "pangolin")]
        VendorKind::Pangolin => pangolin::PANGOLIN_DEFAULT_BASE_URL,
        #[cfg(feature = "cloudflare")]
        VendorKind::Cloudflare => cloudflare::CLOUDFLARE_DEFAULT_BASE_URL,
        #[allow(unreachable_patterns)]
        _ => "",
    }
}

pub struct DnsClient<Vendor> {
    vendor_id: VendorKind,
    vendor_client: Vendor,
}

impl<Vendor> DnsClient<Vendor> {
    pub fn new(vendor_id: VendorKind, vendor_client: Vendor) -> Self {
        Self {
            vendor_id,
            vendor_client,
        }
    }

    pub fn vendor_id(&self) -> VendorKind {
        self.vendor_id
    }

    pub fn vendor_client(&self) -> &Vendor {
        &self.vendor_client
    }

    pub fn into_vendor_client(self) -> Vendor {
        self.vendor_client
    }
}
