use super::*;

// ── VendorKind / capabilities ─────────────────────────────────────────────

#[test]
fn kind_returns_cloudflare() {
    let client = make_client();
    assert_eq!(client.kind(), VendorKind::Cloudflare);
}

#[test]
fn capabilities_match_supported_operations() {
    let caps = make_client().capabilities();
    assert!(caps.zones);
    assert!(caps.records);
    assert!(!caps.cache);
    assert!(!caps.access_lists);
    assert!(caps.settings);
    assert!(caps.zone_import);
    assert!(caps.zone_export);
    assert!(!caps.logs);
}

#[tokio::test]
async fn get_logs_is_unsupported() {
    use crate::core::dns::logs::LogsOptions;
    let err = make_client()
        .get_logs(LogsOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Cloudflare",
            ..
        }
    ));
}

// ── Unsupported operations return correct error ────────────────────────────

#[tokio::test]
async fn enable_zone_is_unsupported() {
    let err = make_client().enable_zone("example.com").await.unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Cloudflare",
            ..
        }
    ));
}

#[tokio::test]
async fn disable_zone_is_unsupported() {
    let err = make_client().disable_zone("example.com").await.unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Cloudflare",
            ..
        }
    ));
}

#[tokio::test]
async fn list_cache_is_unsupported() {
    let err = make_client().list_cache("example.com").await.unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Cloudflare",
            ..
        }
    ));
}

#[tokio::test]
async fn flush_cache_is_unsupported() {
    let err = make_client().flush_cache().await.unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Cloudflare",
            ..
        }
    ));
}

#[tokio::test]
async fn get_stats_is_unsupported() {
    let err = make_client().get_stats("last7days").await.unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Cloudflare",
            ..
        }
    ));
}

#[tokio::test]
async fn list_blocked_is_unsupported() {
    let err = make_client().list_blocked().await.unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Cloudflare",
            ..
        }
    ));
}

#[tokio::test]
async fn zone_import_attempts_api_call_with_default_flags() {
    // overwrite=true, overwrite_zone=false — network error confirms it reaches the API
    let err = make_client()
        .import_zone_file("example.com", "zone.txt".into(), vec![], true, false, false)
        .await
        .unwrap_err();
    assert!(!matches!(err, Error::Unsupported { .. }));
}

#[tokio::test]
async fn zone_import_overwrite_zone_warns_and_proceeds() {
    // overwrite_zone=true emits a warning but still reaches the API (not an error)
    let err = make_client()
        .import_zone_file("example.com", "zone.txt".into(), vec![], true, true, false)
        .await
        .unwrap_err();
    assert!(!matches!(err, Error::Unsupported { .. }));
}

#[tokio::test]
async fn zone_import_no_overwrite_warns_and_proceeds() {
    // overwrite=false emits a warning but still reaches the API (not an error)
    let err = make_client()
        .import_zone_file(
            "example.com",
            "zone.txt".into(),
            vec![],
            false,
            false,
            false,
        )
        .await
        .unwrap_err();
    assert!(!matches!(err, Error::Unsupported { .. }));
}
