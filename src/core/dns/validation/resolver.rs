//! DNS endpoint resolver trait and implementations.

use super::*;

/// Result type returned by endpoint resolvers.
pub type DnsEndpointResolverResult<T> = std::result::Result<T, ValidationFailureKind>;

/// Async DNS endpoint resolver abstraction used by validation code.
///
/// Implementations query one configured endpoint for one FQDN and record type.
/// Tests can implement this trait without opening network sockets.
pub trait DnsEndpointResolver {
    /// Query a validation endpoint for records visible at that endpoint.
    fn query_endpoint<'a>(
        &'a self,
        endpoint: &'a ValidationEndpointConfig,
        fqdn: &'a str,
        record_type: &'a str,
        timeout: Duration,
    ) -> impl Future<Output = DnsEndpointResolverResult<Vec<ObservedRecord>>> + Send + 'a;
}
/// Production resolver backed by Hickory's async Tokio resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct HickoryDnsEndpointResolver;

impl HickoryDnsEndpointResolver {
    /// Build a production Hickory resolver for one validation endpoint.
    ///
    /// Delegates to [`build_resolver`] via a [`ResolverTarget`] derived
    /// from the legacy endpoint shape; behaviour is unchanged.
    pub fn resolver_for_endpoint(
        endpoint: &ValidationEndpointConfig,
        timeout: Duration,
    ) -> DnsEndpointResolverResult<Resolver<TokioRuntimeProvider>> {
        let mut target = ResolverTarget::from_endpoint(endpoint);
        target.timeout = timeout;
        build_resolver(&target)
    }
}

impl DnsEndpointResolver for HickoryDnsEndpointResolver {
    fn query_endpoint<'a>(
        &'a self,
        endpoint: &'a ValidationEndpointConfig,
        fqdn: &'a str,
        record_type: &'a str,
        timeout: Duration,
    ) -> impl Future<Output = DnsEndpointResolverResult<Vec<ObservedRecord>>> + Send + 'a {
        async move {
            let rr_type = record_type
                .parse::<RecordType>()
                .map_err(|_| ValidationFailureKind::MalformedResponse)?;
            let resolver = Self::resolver_for_endpoint(endpoint, timeout)?;

            let lookup = tokio::time::timeout(timeout, resolver.lookup(fqdn, rr_type))
                .await
                .map_err(|_| ValidationFailureKind::Timeout)?
                .map_err(|err| classify_hickory_error(endpoint.transport, &err.to_string()))?;

            Ok(lookup
                .answers()
                .iter()
                .map(|record| ObservedRecord {
                    name: record.name.to_string(),
                    record_type: record.record_type().to_string(),
                    ttl: Some(record.ttl),
                    values: vec![record.data.to_string()],
                })
                .collect())
        }
    }
}

/// Return the configured endpoint timeout, defaulting to five seconds.
#[must_use]
pub fn endpoint_timeout(endpoint: &ValidationEndpointConfig) -> Duration {
    Duration::from_millis(endpoint.timeout_ms.unwrap_or(5_000))
}

/// Deterministic resolver helper for unit tests.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct FakeDnsEndpointResolver {
    result: DnsEndpointResolverResult<Vec<ObservedRecord>>,
}

#[cfg(test)]
impl FakeDnsEndpointResolver {
    pub fn with_records(records: Vec<ObservedRecord>) -> Self {
        Self {
            result: Ok(records),
        }
    }

    pub fn with_failure(failure: ValidationFailureKind) -> Self {
        Self {
            result: Err(failure),
        }
    }
}

#[cfg(test)]
impl DnsEndpointResolver for FakeDnsEndpointResolver {
    fn query_endpoint(
        &self,
        _endpoint: &ValidationEndpointConfig,
        _fqdn: &str,
        _record_type: &str,
        _timeout: Duration,
    ) -> impl Future<Output = DnsEndpointResolverResult<Vec<ObservedRecord>>> + Send + '_ {
        std::future::ready(self.result.clone())
    }
}
