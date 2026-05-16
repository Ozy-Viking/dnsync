use crate::control_plane::config::VendorKind;

pub use crate::core::dns::service::{DnsRead, DnsService, DnsVendor, DnsWrite};

#[cfg(feature = "technitium")]
pub mod technitium;

#[cfg(feature = "pangolin")]
pub mod pangolin;

#[cfg(feature = "cloudflare")]
pub mod cloudflare;

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
