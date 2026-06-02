//! Tests for owner-only permission enforcement on config files.
//!
//! These guarantees protect API tokens stored in the config file, so the
//! permission bits are asserted directly rather than inferred. The mode-bit
//! assertions are Unix-only; the cross-platform behaviours (overwrite refusal,
//! round-trip) are exercised everywhere.

use super::*;

use std::sync::atomic::{AtomicU32, Ordering};

/// Unique scratch directory for a single test, created fresh under the temp dir.
fn scratch_dir(label: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = env::temp_dir().join(format!(
        "dnsync-secure-io-{}-{label}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).expect("metadata").mode() & 0o777
}

#[cfg(unix)]
#[test]
fn write_private_file_creates_owner_only_file() {
    let path = scratch_dir("create").join("config.toml");
    write_private_file(&path, "token = \"secret\"\n").expect("write");
    assert_eq!(
        mode_of(&path),
        0o600,
        "new file must be owner read/write only"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "token = \"secret\"\n"
    );
}

#[cfg(unix)]
#[test]
fn write_private_file_tightens_permissions_on_overwrite() {
    use std::os::unix::fs::PermissionsExt;

    let path = scratch_dir("overwrite").join("config.toml");
    std::fs::write(&path, "old").unwrap();
    // Simulate a pre-existing world-readable file.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(mode_of(&path), 0o644);

    write_private_file(&path, "new").expect("overwrite");
    assert_eq!(
        mode_of(&path),
        0o600,
        "overwriting must reset permissions to owner-only"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
}

#[cfg(unix)]
#[test]
fn restrict_dir_permissions_sets_owner_only_dir() {
    let dir = scratch_dir("dir");
    restrict_dir_permissions(&dir).expect("restrict");
    assert_eq!(mode_of(&dir), 0o700);
}

#[cfg(unix)]
#[test]
fn check_config_permissions_accepts_owner_only() {
    let path = scratch_dir("ok").join("config.toml");
    write_private_file(&path, "token = \"x\"\n").unwrap();
    check_config_permissions(&path).expect("0o600 file must be accepted");
}

#[cfg(unix)]
#[test]
fn check_config_permissions_rejects_group_or_world_readable() {
    use std::os::unix::fs::PermissionsExt;

    for bad in [0o640, 0o604, 0o644, 0o666] {
        let path = scratch_dir(&format!("bad-{bad:o}")).join("config.toml");
        std::fs::write(&path, "token = \"x\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(bad)).unwrap();

        let err = check_config_permissions(&path)
            .expect_err(&format!("mode {bad:o} should be rejected"))
            .to_string();
        assert!(
            err.contains("group or world can read it"),
            "unexpected error for {bad:o}: {err}"
        );
        // The remediation hint should be actionable.
        assert!(err.contains("chmod 600"), "missing remediation: {err}");
    }
}

#[cfg(unix)]
#[test]
fn ensure_config_dir_restricts_parent_directory() {
    let base = scratch_dir("ensure");
    let path = base.join("nested").join("config.toml");
    ensure_config_dir(&path).expect("ensure dir");
    let parent = path.parent().unwrap();
    assert!(parent.exists());
    assert_eq!(mode_of(parent), 0o700);
}

// ── cross-platform behaviours ───────────────────────────────────────────────

#[test]
fn write_default_config_refuses_existing_without_force() {
    let path = scratch_dir("force").join("config.toml");
    write_default_config(&path, false).expect("first write");
    let err = write_default_config(&path, false)
        .expect_err("second write without force must fail")
        .to_string();
    assert!(err.contains("already exists"), "unexpected: {err}");
}

#[test]
fn write_default_config_force_overwrites() {
    let path = scratch_dir("force2").join("config.toml");
    write_default_config(&path, false).expect("first write");
    std::fs::write(&path, "garbage").unwrap();
    write_default_config(&path, true).expect("force overwrite");
    // The starter config is valid and loadable again.
    let cfg = load_from_path(&path).expect("reload starter config");
    assert_eq!(cfg.servers.len(), 1);
}

#[test]
fn write_default_then_load_round_trips() {
    let path = scratch_dir("roundtrip").join("config.toml");
    write_default_config(&path, false).expect("write starter");
    let cfg = load_from_path(&path).expect("load starter");
    assert_eq!(cfg.servers[0].id, "default");
    assert_eq!(cfg.servers[0].vendor, VendorKind::Technitium);
}
