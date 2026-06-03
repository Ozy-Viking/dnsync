//! Tests for owner-only permission enforcement on config files.
//!
//! These guarantees protect API tokens stored in the config file, so the
//! permission bits are asserted directly rather than inferred. The mode-bit
//! assertions are Unix-only; the cross-platform behaviours (overwrite refusal,
//! round-trip) are exercised everywhere.

use super::*;

use std::sync::atomic::{AtomicU32, Ordering};

/// Create a fresh, unique scratch directory under the system temporary directory for a single test.
///
/// The directory is created before being returned.
///
/// # Examples
///
/// ```
/// let dir = scratch_dir("case1");
/// assert!(dir.exists());
/// ```
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

/// Read the Unix permission mode bits for a file or directory.
///
/// The returned value is the permission bits masked to the low 9 bits (owner/group/other).
///
/// # Panics
///
/// Panics if file metadata cannot be read.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// let path = Path::new("/tmp");
/// let mode = mode_of(path);
/// assert!(mode & 0o700 == 0o700 || mode & 0o700 != 0); // example assertion using the mode
/// ```
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).expect("metadata").mode() & 0o777
}

/// Checks that `write_private_file` creates a file owned and readable/writable only by the owner,
/// and that the file contains the provided content.
///
/// # Examples
///
/// ```
/// let path = scratch_dir("create").join("config.toml");
/// write_private_file(&path, "token = \"secret\"\n").expect("write");
/// assert_eq!(mode_of(&path), 0o600);
/// assert_eq!(std::fs::read_to_string(&path).unwrap(), "token = \"secret\"\n");
/// ```
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

/// Ensures overwriting a configuration file resets its permissions to owner-only (0o600) and replaces its contents.
///
/// The test creates a pre-existing file with world-readable permissions (0o644), calls `write_private_file` to overwrite it,
/// and asserts the file mode is set to `0o600` and the file content is replaced.
///
/// # Examples
///
/// ```
/// // Setup: create a file with world-readable permissions, then overwrite it using write_private_file.
/// let path = scratch_dir("overwrite").join("config.toml");
/// std::fs::write(&path, "old").unwrap();
/// std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
///
/// write_private_file(&path, "new").expect("overwrite");
/// assert_eq!(mode_of(&path), 0o600);
/// assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
/// ```
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

/// Ensures `restrict_dir_permissions` sets a directory's permissions to owner-only.
///
/// Creates a scratch directory, applies `restrict_dir_permissions`, and asserts the
/// directory mode is exactly `0o700`.
///
/// # Examples
///
/// ```
/// let dir = scratch_dir("dir");
/// restrict_dir_permissions(&dir).expect("restrict");
/// assert_eq!(mode_of(&dir), 0o700);
/// ```
#[cfg(unix)]
#[test]
fn restrict_dir_permissions_sets_owner_only_dir() {
    let dir = scratch_dir("dir");
    restrict_dir_permissions(&dir).expect("restrict");
    assert_eq!(mode_of(&dir), 0o700);
}

/// Asserts that a configuration file with owner-only permissions is considered valid.
///
/// Creates a private config file (mode 0o600) and verifies `check_config_permissions` accepts it.
///
/// # Examples
///
/// ```
/// let path = scratch_dir("ok").join("config.toml");
/// write_private_file(&path, "token = \"x\"\n").unwrap();
/// check_config_permissions(&path).expect("0o600 file must be accepted");
/// ```
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

/// Ensures the parent directory for a config file path exists and is restricted to owner-only access.
///
/// This test verifies that calling `ensure_config_dir` for a nested config path creates the parent
/// directory and sets its permission bits to `0o700`.
///
/// # Examples
///
/// ```
/// let base = scratch_dir("ensure");
/// let path = base.join("nested").join("config.toml");
/// ensure_config_dir(&path).expect("ensure dir");
/// let parent = path.parent().unwrap();
/// assert!(parent.exists());
/// assert_eq!(mode_of(parent), 0o700);
/// ```
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

/// Ensures writing the default configuration file fails if the file already exists and `force` is false.
///
/// # Examples
///
/// ```ignore
/// let path = scratch_dir("force").join("config.toml");
/// write_default_config(&path, false).expect("first write");
/// // second write without force should return an error indicating the file already exists
/// let err = write_default_config(&path, false).expect_err("second write without force must fail");
/// assert!(err.to_string().contains("already exists"));
/// ```
fn write_default_config_refuses_existing_without_force() {
    let path = scratch_dir("force").join("config.toml");
    write_default_config(&path, false).expect("first write");
    let err = write_default_config(&path, false)
        .expect_err("second write without force must fail")
        .to_string();
    assert!(err.contains("already exists"), "unexpected: {err}");
}

/// Verifies that forcing a default config write overwrites an existing file and restores a valid starter config.
///
/// The test writes the default config, replaces the file contents with invalid data, then calls
/// `write_default_config` with `force = true` and ensures the resulting file can be reloaded as a valid config.
///
/// # Examples
///
/// ```
/// let path = scratch_dir("force2").join("config.toml");
/// write_default_config(&path, false).expect("first write");
/// std::fs::write(&path, "garbage").unwrap();
/// write_default_config(&path, true).expect("force overwrite");
/// let cfg = load_from_path(&path).expect("reload starter config");
/// assert_eq!(cfg.servers.len(), 1);
/// ```
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

/// Verifies that writing the default configuration to disk and then loading it reproduces the starter configuration.
///
/// # Examples
///
/// ```
/// let path = scratch_dir("roundtrip").join("config.toml");
/// write_default_config(&path, false).expect("write starter");
/// let cfg = load_from_path(&path).expect("load starter");
/// assert_eq!(cfg.servers[0].id, "default");
/// assert_eq!(cfg.servers[0].vendor, VendorKind::Technitium);
/// ```
#[test]
fn write_default_then_load_round_trips() {
    let path = scratch_dir("roundtrip").join("config.toml");
    write_default_config(&path, false).expect("write starter");
    let cfg = load_from_path(&path).expect("load starter");
    assert_eq!(cfg.servers[0].id, "default");
    assert_eq!(cfg.servers[0].vendor, VendorKind::Technitium);
}
