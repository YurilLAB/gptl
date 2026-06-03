//! Named configuration profiles.
//!
//! Profiles are TOML files stored in `~/.config/gptl/profiles/<name>.toml`.
//!
//! Three read-only built-in profiles are always available:
//!   standard  — maps to SecurityLevel::Standard with recommended settings
//!   enhanced  — maps to SecurityLevel::Enhanced (default)
//!   maximum   — maps to SecurityLevel::Maximum with all defenses at maximum

use crate::config::{ConfigError, GptlConfig, SecurityLevel};
use std::path::{Path, PathBuf};

/// Built-in profile names. These are read-only and cannot be overwritten or deleted.
pub const BUILTIN: &[&str] = &["standard", "enhanced", "maximum"];

/// Returns the directory where user-saved profiles are stored.
pub fn profiles_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("profiles")
}

/// Build the config represented by a built-in profile name, if applicable.
fn builtin_config(name: &str) -> Option<GptlConfig> {
    let level = match name {
        "standard" => SecurityLevel::Standard,
        "enhanced" => SecurityLevel::Enhanced,
        "maximum" => SecurityLevel::Maximum,
        _ => return None,
    };
    let mut cfg = GptlConfig::default();
    cfg.security_level = level;
    cfg.core = level.recommended_core();
    cfg.routing = level.recommended_routing();
    Some(cfg)
}

/// Returns all available profile names with a flag indicating whether they are built-in.
///
/// Order: built-ins first, then user-saved profiles in alphabetical order.
pub fn list(config_path: &Path) -> Result<Vec<(String, bool)>, ConfigError> {
    let mut profiles: Vec<(String, bool)> = BUILTIN.iter().map(|n| (n.to_string(), true)).collect();

    let dir = profiles_dir(config_path);
    if dir.exists() {
        let mut user: Vec<String> = std::fs::read_dir(&dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let p = e.path();
                if p.extension().map_or(false, |x| x == "toml") {
                    p.file_stem()
                        .and_then(|s| s.to_str())
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
            .filter(|name| !BUILTIN.contains(&name.as_str()))
            .collect();
        user.sort();
        for name in user {
            profiles.push((name, false));
        }
    }
    Ok(profiles)
}

/// Load a profile by name. Handles built-ins transparently.
pub fn load(name: &str, config_path: &Path) -> Result<GptlConfig, ConfigError> {
    if let Some(cfg) = builtin_config(name) {
        return Ok(cfg);
    }
    // Reject path separators / `..` before building a filesystem path, so a
    // crafted name (e.g. "../../etc/passwd") cannot escape the profiles dir.
    validate_name(name)?;
    let path = profiles_dir(config_path).join(format!("{}.toml", name));
    if !path.exists() {
        return Err(ConfigError::UnknownKey(format!(
            "profile '{}' not found — run 'gptl profile list' to see available profiles",
            name
        )));
    }
    GptlConfig::load(&path)
}

/// Save the current config as a named profile.
///
/// Returns an error if `name` is a built-in.
pub fn save(name: &str, config: &GptlConfig, config_path: &Path) -> Result<(), ConfigError> {
    if BUILTIN.contains(&name) {
        return Err(ConfigError::InvalidValue {
            key: "profile name".to_string(),
            message: format!(
                "'{}' is a built-in profile and cannot be overwritten. Choose a different name.",
                name
            ),
        });
    }
    validate_name(name)?;
    let dir = profiles_dir(config_path);
    let path = dir.join(format!("{}.toml", name));
    config.save(&path)
}

/// Delete a saved profile by name.
///
/// Returns an error if `name` is a built-in.
pub fn delete(name: &str, config_path: &Path) -> Result<(), ConfigError> {
    if BUILTIN.contains(&name) {
        return Err(ConfigError::InvalidValue {
            key: "profile name".to_string(),
            message: format!("'{}' is a built-in profile and cannot be deleted.", name),
        });
    }
    // Reject path separators / `..` so delete can't remove files outside the
    // profiles directory (e.g. "../config" or an absolute path).
    validate_name(name)?;
    let path = profiles_dir(config_path).join(format!("{}.toml", name));
    if !path.exists() {
        return Err(ConfigError::UnknownKey(format!(
            "profile '{}' not found",
            name
        )));
    }
    std::fs::remove_file(&path)?;
    Ok(())
}

/// Validates a profile name: alphanumeric, hyphens, underscores only.
fn validate_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        return Err(ConfigError::InvalidValue {
            key: "profile name".to_string(),
            message: "profile name cannot be empty".to_string(),
        });
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ConfigError::InvalidValue {
            key: "profile name".to_string(),
            message: format!(
                "'{}' contains invalid characters. Use only letters, digits, hyphens, and underscores.",
                name
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_load_and_delete_reject_path_traversal() {
        let cfg = PathBuf::from("/tmp/gptl-nonexistent/config.toml");
        for bad in [
            "../config",
            "../../etc/passwd",
            "a/b",
            "/etc/shadow",
            "..",
            "foo/../bar",
        ] {
            assert!(
                load(bad, &cfg).is_err(),
                "load must reject traversal name {:?}",
                bad
            );
            assert!(
                delete(bad, &cfg).is_err(),
                "delete must reject traversal name {:?}",
                bad
            );
        }
    }

    #[test]
    fn test_validate_name_accepts_normal_names() {
        assert!(validate_name("my-profile_1").is_ok());
        assert!(validate_name("work").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("../x").is_err());
    }
}
