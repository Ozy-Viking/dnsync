//! Configuration validation helpers.

use super::*;

pub(crate) fn validate_validation_endpoints(server: &DnsServerConfig) -> Result<()> {
    for endpoint in &server.validation_endpoints {
        if endpoint.name.trim().is_empty() {
            return Err(Error::config(format!(
                "DNS server '{}' contains a validation endpoint with an empty name",
                server.id
            )));
        }

        match endpoint.transport {
            ValidationTransport::Dns | ValidationTransport::Dot | ValidationTransport::Doq
                if endpoint.address.trim().is_empty() =>
            {
                return Err(Error::config(format!(
                    "validation endpoint '{}' on DNS server '{}' requires address for {:?} transport",
                    endpoint.name, server.id, endpoint.transport
                )));
            }
            ValidationTransport::Doh
                if endpoint
                    .url
                    .as_deref()
                    .is_none_or(|url| url.trim().is_empty()) =>
            {
                return Err(Error::config(format!(
                    "validation endpoint '{}' on DNS server '{}' requires url for doh transport",
                    endpoint.name, server.id
                )));
            }
            _ => {}
        }
    }

    Ok(())
}

pub(crate) fn validate_server_transports(server: &DnsServerConfig) -> Result<()> {
    if let Some(dns) = &server.dns
        && dns.enabled
        && dns
            .addr
            .as_deref()
            .is_none_or(|addr| addr.trim().is_empty())
    {
        return Err(Error::config(format!(
            "DNS server '{}' has enabled dns transport without addr",
            server.id
        )));
    }

    if let Some(dot) = &server.dot
        && dot.enabled
        && dot
            .addr
            .as_deref()
            .is_none_or(|addr| addr.trim().is_empty())
    {
        return Err(Error::config(format!(
            "DNS server '{}' has enabled dot transport without addr",
            server.id
        )));
    }

    if let Some(doh) = &server.doh
        && doh.enabled
        && doh.url.as_deref().is_none_or(|url| url.trim().is_empty())
    {
        return Err(Error::config(format!(
            "DNS server '{}' has enabled doh transport without url",
            server.id
        )));
    }

    if let Some(doq) = &server.doq
        && doq.enabled
        && doq
            .addr
            .as_deref()
            .is_none_or(|addr| addr.trim().is_empty())
    {
        return Err(Error::config(format!(
            "DNS server '{}' has enabled doq transport without addr",
            server.id
        )));
    }

    Ok(())
}

pub(crate) fn validate_clusters(
    clusters: &BTreeMap<String, ClusterConfig>,
    server_ids: &HashSet<String>,
) -> Result<()> {
    for (id, cluster) in clusters {
        if id.trim().is_empty() {
            return Err(Error::config("config contains a cluster with an empty id"));
        }

        for member in &cluster.members {
            if !server_ids.contains(&member.to_lowercase()) {
                return Err(Error::config(format!(
                    "cluster '{id}' references unknown DNS server '{member}'"
                )));
            }
        }

        for field in [cluster.primary.as_ref(), cluster.preferred_writer.as_ref()]
            .into_iter()
            .flatten()
        {
            if !field.eq_ignore_ascii_case("auto") && !server_ids.contains(&field.to_lowercase()) {
                return Err(Error::config(format!(
                    "cluster '{id}' references unknown DNS server '{field}'"
                )));
            }
        }
    }

    Ok(())
}

/// Validate a single `ip_map` entry by ensuring both endpoints are valid IPs and belong to the same IP family.
///
/// Returns an `Err(Error::config(...))` if either `src` or `dst` is not a valid IP address, or if one is IPv4 and the other is IPv6.
///
/// # Examples
///
/// ```text
/// # use std::net::IpAddr;
/// # fn validate_ip_pair_for_job(_job_id: &str, _src: &str, _dst: &str) -> Result<(), ()> { Ok(()) }
/// // Basic usage: IPv4 pair is accepted
/// let res = validate_ip_pair_for_job("job1", "192.0.2.1", "198.51.100.2");
/// assert!(res.is_ok());
/// ```
pub(crate) fn validate_ip_pair_for_job(job_id: &str, src: &str, dst: &str) -> Result<()> {
    let source: IpAddr = src
        .parse()
        .map_err(|_| Error::config(format!("job '{job_id}': '{src}' is not a valid IP address")))?;
    let dest: IpAddr = dst
        .parse()
        .map_err(|_| Error::config(format!("job '{job_id}': '{dst}' is not a valid IP address")))?;
    if source.is_ipv4() != dest.is_ipv4() {
        return Err(Error::config(format!(
            "job '{job_id}': IP mapping '{src}' = '{dst}' mixes IPv4 and IPv6"
        )));
    }
    Ok(())
}

/// Validate job definitions and their references.
///
/// Performs semantic checks on each `JobConfig`:
/// - each job must have a non-empty, unique id (case-insensitive);
/// - exactly one of `schedule` or `interval` must be present (whitespace-only counts as absent);
/// - for `RecordSync` and `ZoneSync` jobs, `from` and `to` must be present, refer to known servers,
///   and must not be the same server (comparison is case-insensitive);
/// - for `ZoneExport` jobs, `output_dir` must be present and non-empty;
/// - every entry in `ip_map` must parse as an IP address and use a consistent IP family per pair;
/// - every `ignore` pattern must compile as a valid regular expression.
///
/// `server_ids` should contain the set of known server ids (lowercased) used to validate `from`/`to`.
///
/// # Errors
///
/// Returns an `Err(Error::config(...))` describing the first validation failure encountered.
///
/// # Examples
///
/// ```text
/// use std::collections::HashSet;
///
/// // empty job list is valid
/// let jobs: Vec<crate::control_plane::config::JobConfig> = Vec::new();
/// let server_ids: HashSet<String> = HashSet::new();
/// assert!(crate::control_plane::config::validate_jobs(&jobs, &server_ids).is_ok());
/// ```
pub(crate) fn validate_jobs(jobs: &[JobConfig], server_ids: &HashSet<String>) -> Result<()> {
    let mut job_ids: HashSet<String> = HashSet::new();
    for job in jobs {
        if job.id.trim().is_empty() {
            return Err(Error::config("config contains a job with an empty id"));
        }
        if !job_ids.insert(job.id.to_lowercase()) {
            return Err(Error::config(format!(
                "config contains duplicate job id '{}'",
                job.id
            )));
        }

        // Exactly one of schedule / interval (whitespace-only strings count as absent).
        let has_schedule = job
            .schedule
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        let has_interval = job
            .interval
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        match (has_schedule, has_interval) {
            (true, true) => {
                return Err(Error::config(format!(
                    "job '{}' specifies both 'schedule' and 'interval'; use only one",
                    job.id
                )));
            }
            (false, false) => {
                return Err(Error::config(format!(
                    "job '{}' must specify either 'schedule' or 'interval'",
                    job.id
                )));
            }
            _ => {}
        }

        match job.kind {
            JobKind::RecordSync | JobKind::ZoneSync => {
                let from = job.from.as_deref().unwrap_or("").trim();
                let to = job.to.as_deref().unwrap_or("").trim();

                if from.is_empty() {
                    return Err(Error::config(format!(
                        "job '{}' of kind {:?} requires 'from'",
                        job.id, job.kind
                    )));
                }
                if to.is_empty() {
                    return Err(Error::config(format!(
                        "job '{}' of kind {:?} requires 'to'",
                        job.id, job.kind
                    )));
                }
                if !server_ids.contains(&from.to_lowercase()) {
                    return Err(Error::config(format!(
                        "job '{}' references unknown source server '{from}'",
                        job.id
                    )));
                }
                if !server_ids.contains(&to.to_lowercase()) {
                    return Err(Error::config(format!(
                        "job '{}' references unknown destination server '{to}'",
                        job.id
                    )));
                }
                if from.to_lowercase() == to.to_lowercase() {
                    return Err(Error::config(format!(
                        "job '{}' has identical source and destination server '{from}'",
                        job.id
                    )));
                }
            }
            JobKind::ZoneExport => {
                if job
                    .output_dir
                    .as_deref()
                    .is_none_or(|s| s.trim().is_empty())
                {
                    return Err(Error::config(format!(
                        "job '{}' of kind zone_export requires 'output_dir'",
                        job.id
                    )));
                }
            }
        }

        for (src, dst) in &job.ip_map {
            validate_ip_pair_for_job(&job.id, src, dst)?;
        }

        for pattern in &job.ignore {
            Regex::new(pattern).map_err(|e| {
                Error::config(format!(
                    "job '{}': ignore pattern '{pattern}' is not valid regex: {e}",
                    job.id
                ))
            })?;
        }
    }
    Ok(())
}
