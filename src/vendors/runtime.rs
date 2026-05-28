use serde_json::Value;

use crate::control_plane::config::{self, DnsServerConfig, VendorKind};
use crate::core::dns::capabilities::VendorCapabilities;
use crate::core::dns::logs::{LogLine, LogsOptions, LogsRead};
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::ListRecordsResponse;
use crate::core::dns::service::{
    AccessListRead, AccessListWrite, CacheRead, CacheWrite, DnsVendor, ListRecordsOptions,
    RecordWrite, SettingsRead, StatsRead, ZoneExport, ZoneImport, ZoneRead, ZoneWrite,
};
use crate::core::error::{Error, Result};

#[derive(Debug, Clone, Copy, Default)]
pub struct ClientOverrides<'a> {
    pub selected_server: Option<&'a str>,
    pub base_url: Option<&'a str>,
    pub token: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub enum VendorClient {
    #[cfg(feature = "technitium")]
    Technitium(crate::vendors::technitium::client::TechnitiumClient),
    #[cfg(feature = "pangolin")]
    Pangolin(crate::vendors::pangolin::client::PangolinClient),
    #[cfg(feature = "cloudflare")]
    Cloudflare(crate::vendors::cloudflare::client::CloudflareClient),
    #[cfg(feature = "unifi")]
    Unifi(crate::vendors::unifi::client::UnifiClient),
    #[cfg(feature = "pihole")]
    Pihole(crate::vendors::pihole::client::PiholeClient),
}

impl VendorClient {
    pub fn from_cli_options(
        app_config: Option<&config::AppConfig>,
        overrides: ClientOverrides<'_>,
    ) -> Result<Self> {
        let Some(app_config) = app_config else {
            return Self::client_without_config(overrides);
        };

        let server = app_config.selected_server(overrides.selected_server)?;
        Self::from_selected_server(server, overrides)
    }

    pub fn from_server(server: &DnsServerConfig) -> Result<Self> {
        match server.vendor {
            #[cfg(feature = "technitium")]
            VendorKind::Technitium => Ok(Self::Technitium(
                crate::vendors::technitium::client_from_server(server, ClientOverrides::default())?,
            )),
            #[cfg(feature = "pangolin")]
            VendorKind::Pangolin => Ok(Self::Pangolin(
                crate::vendors::pangolin::client_from_server(server, ClientOverrides::default())?,
            )),
            #[cfg(feature = "cloudflare")]
            VendorKind::Cloudflare => Ok(Self::Cloudflare(
                crate::vendors::cloudflare::client_from_server(server, ClientOverrides::default())?,
            )),
            #[cfg(feature = "unifi")]
            VendorKind::Unifi => Ok(Self::Unifi(crate::vendors::unifi::client_from_server(
                server,
                ClientOverrides::default(),
            )?)),
            #[cfg(feature = "pihole")]
            VendorKind::Pihole => Ok(Self::Pihole(
                crate::vendors::pihole::client_from_server(server, ClientOverrides::default())?,
            )),
            #[allow(unreachable_patterns)]
            _ => Err(Error::parse(format!(
                "server '{}' has unsupported vendor in this build",
                server.id
            ))),
        }
    }

    pub async fn export_zone_for_server(server: &DnsServerConfig, zone: &str) -> Result<String> {
        let _ = zone;
        // Keep unsupported vendors from resolving credentials before reporting
        // capability errors; zone transfer should fail on support, not auth.
        match server.vendor {
            #[cfg(feature = "technitium")]
            VendorKind::Technitium => {
                let client = crate::vendors::technitium::client_from_server(
                    server,
                    ClientOverrides::default(),
                )?;
                client.export_zone_file(zone).await
            }
            #[cfg(feature = "cloudflare")]
            VendorKind::Cloudflare => {
                let client = crate::vendors::cloudflare::client_from_server(
                    server,
                    ClientOverrides::default(),
                )?;
                client.export_zone_file(zone).await
            }
            #[cfg(feature = "pangolin")]
            VendorKind::Pangolin => Err(Error::unsupported("Pangolin", "zone export")),
            #[cfg(feature = "unifi")]
            VendorKind::Unifi => Err(Error::unsupported("UniFi", "zone export")),
            #[cfg(feature = "pihole")]
            VendorKind::Pihole => Err(Error::unsupported("Pi-hole", "zone export")),
            #[allow(unreachable_patterns)]
            _ => Err(Error::parse(format!(
                "server '{}' has unsupported vendor in this build",
                server.id
            ))),
        }
    }

    pub async fn import_zone_for_server(
        server: &DnsServerConfig,
        zone: &str,
        file_name: String,
        file_bytes: Vec<u8>,
        overwrite: bool,
        overwrite_zone: bool,
    ) -> Result<Value> {
        let _ = (zone, &file_name, &file_bytes, overwrite, overwrite_zone);
        // Keep unsupported vendors from resolving credentials before reporting
        // capability errors; zone transfer should fail on support, not auth.
        match server.vendor {
            #[cfg(feature = "technitium")]
            VendorKind::Technitium => {
                let client = crate::vendors::technitium::client_from_server(
                    server,
                    ClientOverrides::default(),
                )?;
                client
                    .import_zone_file(
                        zone,
                        file_name,
                        file_bytes,
                        overwrite,
                        overwrite_zone,
                        false,
                    )
                    .await
            }
            #[cfg(feature = "cloudflare")]
            VendorKind::Cloudflare => {
                let client = crate::vendors::cloudflare::client_from_server(
                    server,
                    ClientOverrides::default(),
                )?;
                client
                    .import_zone_file(
                        zone,
                        file_name,
                        file_bytes,
                        overwrite,
                        overwrite_zone,
                        false,
                    )
                    .await
            }
            #[cfg(feature = "pangolin")]
            VendorKind::Pangolin => Err(Error::unsupported("Pangolin", "zone import")),
            #[cfg(feature = "unifi")]
            VendorKind::Unifi => Err(Error::unsupported("UniFi", "zone import")),
            #[cfg(feature = "pihole")]
            VendorKind::Pihole => Err(Error::unsupported("Pi-hole", "zone import")),
            #[allow(unreachable_patterns)]
            _ => Err(Error::parse(format!(
                "server '{}' has unsupported vendor in this build",
                server.id
            ))),
        }
    }

    fn from_selected_server(
        server: &DnsServerConfig,
        overrides: ClientOverrides<'_>,
    ) -> Result<Self> {
        match server.vendor {
            #[cfg(feature = "technitium")]
            VendorKind::Technitium => Ok(Self::Technitium(
                crate::vendors::technitium::client_from_server(server, overrides)?,
            )),
            #[cfg(feature = "pangolin")]
            VendorKind::Pangolin => Ok(Self::Pangolin(
                crate::vendors::pangolin::client_from_server(server, overrides)?,
            )),
            #[cfg(feature = "cloudflare")]
            VendorKind::Cloudflare => Ok(Self::Cloudflare(
                crate::vendors::cloudflare::client_from_server(server, overrides)?,
            )),
            #[cfg(feature = "unifi")]
            VendorKind::Unifi => Ok(Self::Unifi(crate::vendors::unifi::client_from_server(
                server, overrides,
            )?)),
            #[cfg(feature = "pihole")]
            VendorKind::Pihole => Ok(Self::Pihole(
                crate::vendors::pihole::client_from_server(server, overrides)?,
            )),
            #[allow(unreachable_patterns)]
            _ => Err(Error::parse(format!(
                "server '{}' has unsupported vendor in this build",
                server.id
            ))),
        }
    }

    #[cfg(feature = "technitium")]
    fn client_without_config(overrides: ClientOverrides<'_>) -> Result<Self> {
        Ok(Self::Technitium(
            crate::vendors::technitium::client_from_cli_without_config(overrides)?,
        ))
    }

    #[cfg(not(feature = "technitium"))]
    fn client_without_config(_overrides: ClientOverrides<'_>) -> Result<Self> {
        Err(Error::parse(
            "Technitium vendor is not supported in this build",
        ))
    }
}

macro_rules! delegate_vendor {
    ($self:expr, $client:ident => $body:expr) => {
        match $self {
            #[cfg(feature = "technitium")]
            Self::Technitium($client) => $body,
            #[cfg(feature = "pangolin")]
            Self::Pangolin($client) => $body,
            #[cfg(feature = "cloudflare")]
            Self::Cloudflare($client) => $body,
            #[cfg(feature = "unifi")]
            Self::Unifi($client) => $body,
            #[cfg(feature = "pihole")]
            Self::Pihole($client) => $body,
        }
    };
}

impl DnsVendor for VendorClient {
    fn kind(&self) -> VendorKind {
        delegate_vendor!(self, client => client.kind())
    }

    fn capabilities(&self) -> VendorCapabilities {
        delegate_vendor!(self, client => client.capabilities())
    }
}

impl ZoneRead for VendorClient {
    async fn list_zones(&self, page: u32, per_page: u32) -> Result<Value> {
        delegate_vendor!(self, client => client.list_zones(page, per_page).await)
    }

    async fn list_records(
        &self,
        domain: &str,
        zone: Option<&str>,
        options: ListRecordsOptions,
    ) -> Result<ListRecordsResponse> {
        delegate_vendor!(self, client => client.list_records(domain, zone, options).await)
    }
}

impl ZoneWrite for VendorClient {
    async fn create_zone(&self, zone: &str, zone_type: &str) -> Result<Value> {
        delegate_vendor!(self, client => client.create_zone(zone, zone_type).await)
    }

    async fn delete_zone(&self, zone: &str) -> Result<Value> {
        delegate_vendor!(self, client => client.delete_zone(zone).await)
    }

    async fn enable_zone(&self, zone: &str) -> Result<Value> {
        delegate_vendor!(self, client => client.enable_zone(zone).await)
    }

    async fn disable_zone(&self, zone: &str) -> Result<Value> {
        delegate_vendor!(self, client => client.disable_zone(zone).await)
    }
}

impl RecordWrite for VendorClient {
    async fn add_record(
        &self,
        zone: &str,
        domain: &str,
        ttl: u32,
        record: &RecordData,
    ) -> Result<Value> {
        delegate_vendor!(self, client => client.add_record(zone, domain, ttl, record).await)
    }

    async fn delete_record(
        &self,
        zone: &str,
        domain: &str,
        type_params: &[(&str, String)],
    ) -> Result<Value> {
        delegate_vendor!(self, client => client.delete_record(zone, domain, type_params).await)
    }
}

impl CacheRead for VendorClient {
    async fn list_cache(&self, domain: &str) -> Result<Value> {
        delegate_vendor!(self, client => client.list_cache(domain).await)
    }
}

impl CacheWrite for VendorClient {
    async fn delete_cache_zone(&self, domain: &str) -> Result<Value> {
        delegate_vendor!(self, client => client.delete_cache_zone(domain).await)
    }

    async fn flush_cache(&self) -> Result<Value> {
        delegate_vendor!(self, client => client.flush_cache().await)
    }
}

impl StatsRead for VendorClient {
    async fn get_stats(&self, stats_type: &str) -> Result<Value> {
        delegate_vendor!(self, client => client.get_stats(stats_type).await)
    }
}

impl AccessListRead for VendorClient {
    async fn list_blocked(&self) -> Result<Value> {
        delegate_vendor!(self, client => client.list_blocked().await)
    }

    async fn list_allowed(&self) -> Result<Value> {
        delegate_vendor!(self, client => client.list_allowed().await)
    }
}

impl AccessListWrite for VendorClient {
    async fn add_blocked(&self, domain: &str) -> Result<Value> {
        delegate_vendor!(self, client => client.add_blocked(domain).await)
    }

    async fn delete_blocked(&self, domain: &str) -> Result<Value> {
        delegate_vendor!(self, client => client.delete_blocked(domain).await)
    }

    async fn add_allowed(&self, domain: &str) -> Result<Value> {
        delegate_vendor!(self, client => client.add_allowed(domain).await)
    }

    async fn delete_allowed(&self, domain: &str) -> Result<Value> {
        delegate_vendor!(self, client => client.delete_allowed(domain).await)
    }
}

impl ZoneImport for VendorClient {
    async fn import_zone_file(
        &self,
        zone: &str,
        file_name: String,
        file_bytes: Vec<u8>,
        overwrite: bool,
        overwrite_zone: bool,
        overwrite_soa_serial: bool,
    ) -> Result<Value> {
        delegate_vendor!(self, client => {
            client
                .import_zone_file(
                    zone,
                    file_name,
                    file_bytes,
                    overwrite,
                    overwrite_zone,
                    overwrite_soa_serial,
                )
                .await
        })
    }
}

impl ZoneExport for VendorClient {
    async fn export_zone_file(&self, zone: &str) -> Result<String> {
        delegate_vendor!(self, client => client.export_zone_file(zone).await)
    }
}

impl SettingsRead for VendorClient {
    async fn get_settings(&self) -> Result<Value> {
        delegate_vendor!(self, client => client.get_settings().await)
    }
}

impl LogsRead for VendorClient {
    async fn get_logs(&self, options: LogsOptions) -> Result<Vec<LogLine>> {
        delegate_vendor!(self, client => client.get_logs(options).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "technitium")]
    #[test]
    fn default_without_config_builds_technitium_client() {
        let client = VendorClient::from_cli_options(
            None,
            ClientOverrides {
                token: Some("token"),
                ..ClientOverrides::default()
            },
        )
        .unwrap();

        assert_eq!(client.kind(), VendorKind::Technitium);
    }
}
