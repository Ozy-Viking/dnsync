//! Config file IO and owner-only permission enforcement.

use super::*;

/// Write the starter application configuration to `path`, creating parent directories as needed.

///

/// If a config file already exists at `path` this returns an error unless `force` is `true`,

/// in which case the file is overwritten. The function ensures the configuration directory

/// is present (with restrictive permissions on supported platforms) and writes the default

/// TOML contents using secure file permissions.

///

/// # Errors

///

/// Returns an `Error::config` if the file exists and `force` is `false`. Other I/O or

/// serialization errors are returned as appropriate.

///

/// # Examples

///

/// ```text

/// use std::path::Path;

/// # fn try_example() -> Result<(), Box<dyn std::error::Error>> {

/// let path = Path::new("/tmp/dnsync_config.toml");

/// // Write default config, overwriting if it already exists

/// crate::control_plane::config::write_default_config(path, true)?;

/// # Ok(()) }

/// ```

pub(crate) fn write_default_config(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(Error::config(format!(
            "config file '{}' already exists; pass --force to overwrite it",
            path.display()
        )));
    }

    ensure_config_dir(path)?;
    let contents = AppConfig::render_starter_toml()?;
    write_private_file(path, &contents)
}

pub(crate) fn ensure_config_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::io(
                format!("creating config directory '{}'", parent.display()),
                e,
            )
        })?;
        restrict_dir_permissions(parent)?;
    }
    Ok(())
}

pub(crate) fn load_from_path(path: &Path) -> Result<AppConfig> {
    check_config_permissions(path)?;
    let contents = std::fs::read_to_string(path)
        .map_err(|e| Error::io(format!("reading config file '{}'", path.display()), e))?;
    let config: AppConfig = toml::from_str(&contents).map_err(|e| {
        Error::config(format!(
            "could not parse config file '{}': {e}",
            path.display()
        ))
    })?;
    config.validate()?;
    Ok(config)
}

/// Write `contents` to `path` with owner-only permissions (0o600 on Unix).
/// Uses `OpenOptions::mode` so the file is never created world-readable,
/// then explicitly sets permissions to handle the overwrite (force) case.
#[cfg(unix)]
pub(crate) fn write_private_file(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| Error::io(format!("creating config file '{}'", path.display()), e))?;

    file.write_all(contents.as_bytes())
        .map_err(|e| Error::io(format!("writing config file '{}'", path.display()), e))?;

    // mode() only applies when the file is newly created; set explicitly for overwrites.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::io(format!("setting permissions on '{}'", path.display()), e))
}

#[cfg(not(unix))]
pub(crate) fn write_private_file(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)
        .map_err(|e| Error::io(format!("creating config file '{}'", path.display()), e))
}

/// Restrict the config directory to owner-only access (0o700 on Unix).
#[cfg(unix)]
pub(crate) fn restrict_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io(format!("setting permissions on '{}'", path.display()), e))
}

#[cfg(not(unix))]
pub(crate) fn restrict_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Error if the config file is readable by anyone other than the owner.
#[cfg(unix)]
pub(crate) fn check_config_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| Error::io(format!("reading metadata for '{}'", path.display()), e))?;
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::config(format!(
            "config file '{}' has permissions {:04o} — group or world can read it.\n\
             API tokens must be owner-readable only. Fix with:\n\
             \n    chmod 600 {}",
            path.display(),
            mode,
            path.display(),
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn check_config_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
