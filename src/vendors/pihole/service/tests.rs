use super::*;

fn make_client() -> PiholeClient {
    PiholeClient::new(
        "http://pi.hole".to_string(),
        crate::core::secret::ApiToken::new("test-password"),
    )
    .unwrap()
}

#[test]
fn kind_returns_pihole() {
    assert_eq!(make_client().kind(), VendorKind::Pihole);
}

#[test]
fn capabilities_match_supported_operations() {
    let caps = make_client().capabilities();
    assert!(!caps.zones);
    assert!(caps.records);
    assert!(caps.cache);
    assert!(caps.access_lists);
    assert!(caps.settings);
    assert!(!caps.zone_import);
    assert!(!caps.zone_export);
}

#[tokio::test]
async fn list_zones_is_unsupported() {
    let err = make_client().list_zones(1, 100).await.unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Pi-hole",
            ..
        }
    ));
}

#[tokio::test]
async fn create_zone_is_unsupported() {
    let err = make_client()
        .create_zone("example.com", "Primary")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Pi-hole",
            ..
        }
    ));
}

#[tokio::test]
async fn delete_zone_is_unsupported() {
    let err = make_client().delete_zone("example.com").await.unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Pi-hole",
            ..
        }
    ));
}

#[tokio::test]
async fn enable_zone_is_unsupported() {
    let err = make_client().enable_zone("example.com").await.unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Pi-hole",
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
            vendor: "Pi-hole",
            ..
        }
    ));
}

#[tokio::test]
async fn delete_cache_zone_is_unsupported() {
    let err = make_client()
        .delete_cache_zone("example.com")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Pi-hole",
            ..
        }
    ));
}

#[tokio::test]
async fn zone_import_is_unsupported() {
    let err = make_client()
        .import_zone_file("example.com", "zone.txt".into(), vec![], true, false, false)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Pi-hole",
            ..
        }
    ));
}

#[tokio::test]
async fn zone_export_is_unsupported() {
    let err = make_client()
        .export_zone_file("example.com")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Pi-hole",
            ..
        }
    ));
}

#[tokio::test]
async fn add_unsupported_record_type_is_unsupported() {
    let record = RecordData::Mx {
        preference: 10,
        exchange: "mail.example.com".into(),
    };
    let err = make_client()
        .add_record("home.lan", "example.com", 300, &record)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "Pi-hole",
            ..
        }
    ));
}
