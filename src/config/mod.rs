pub mod credentials;

use std::path::PathBuf;

use miette::{IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};

use crate::error::AkError;

/// Top-level CLI configuration.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AppConfig {
    /// Name of the default instance.
    #[serde(default)]
    pub default_instance: Option<String>,

    /// Default output format.
    #[serde(default = "default_format")]
    pub output_format: String,

    /// Color mode (auto, always, never).
    #[serde(default = "default_color")]
    pub color: String,

    /// Configured instances.
    #[serde(default)]
    pub instances: std::collections::BTreeMap<String, InstanceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceConfig {
    pub url: String,
    #[serde(default = "default_api_version")]
    pub api_version: String,
    /// User has explicitly acknowledged that this instance uses plaintext
    /// HTTP to a non-loopback host (`ak instance add --insecure-http`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_insecure_http: bool,
}

fn default_format() -> String {
    "table".to_string()
}

fn default_color() -> String {
    "auto".to_string()
}

fn default_api_version() -> String {
    "v1".to_string()
}

impl AppConfig {
    /// Load config from disk, creating defaults if it doesn't exist.
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        if path.exists() {
            let content = std::fs::read_to_string(&path).into_diagnostic()?;
            toml::from_str(&content).into_diagnostic()
        } else {
            Ok(Self::default())
        }
    }

    /// Save config to disk.
    pub fn save(&self) -> Result<()> {
        let path = config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).into_diagnostic()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                    .into_diagnostic()?;
            }
        }
        let content = toml::to_string_pretty(self).into_diagnostic()?;
        write_private_atomic(&path, &content)
    }

    /// Get the active instance config, resolving from flag → env → default. The flag
    /// and the env var can hold a URL instead of a name.
    pub fn resolve_instance<'a>(
        &'a self,
        override_name: Option<&'a str>,
    ) -> Result<(&'a str, &'a InstanceConfig)> {
        let name = override_name
            .or(self.default_instance.as_deref())
            .ok_or(AkError::NoInstance)?;

        if is_instance_url(name) {
            return self.resolve_instance_url(name);
        }

        let instance = self
            .instances
            .get(name)
            .ok_or_else(|| AkError::InstanceNotFound(name.to_string()))?;

        Ok((name, instance))
    }

    /// `--instance` or `AK_INSTANCE` given as a URL. A configured instance at exactly
    /// that URL is used with its login. Any other URL has no login of its own, so the
    /// only token it can get is `AK_TOKEN`, sent to the URL the user just named.
    ///
    /// The process is short-lived and resolves this a handful of times, so the
    /// instance it makes up is leaked to give it the same lifetime as the others.
    fn resolve_instance_url<'a>(&'a self, url: &str) -> Result<(&'a str, &'a InstanceConfig)> {
        let url = normalize_instance_url(url)?;
        if let Some((name, instance)) = self.instance_at(&url) {
            return Ok((name, instance));
        }
        let instance: &'static InstanceConfig = Box::leak(Box::new(InstanceConfig {
            url: url.clone(),
            api_version: default_api_version(),
            allow_insecure_http: false,
        }));
        Ok((Box::leak(url.into_boxed_str()), instance))
    }

    /// The configured instance at exactly this URL, scheme included: a login made
    /// over https doesn't go to the same host over http.
    pub fn instance_at(&self, url: &str) -> Option<(&str, &InstanceConfig)> {
        self.instances
            .iter()
            .find(|(_, instance)| instance.url.trim_end_matches('/') == url)
            .map(|(name, instance)| (name.as_str(), instance))
    }

    /// A name for a new instance at this URL: its host, or with its port or a number
    /// if that's taken.
    pub fn name_for_url(&self, url: &str) -> String {
        let parsed = reqwest::Url::parse(url).ok();
        let host = parsed
            .as_ref()
            .and_then(|u| u.host_str())
            .unwrap_or("instance")
            .to_string();
        if !self.instances.contains_key(&host) {
            return host;
        }
        if let Some(port) = parsed.and_then(|u| u.port()) {
            let with_port = format!("{host}-{port}");
            if !self.instances.contains_key(&with_port) {
                return with_port;
            }
        }
        (2..)
            .map(|n| format!("{host}-{n}"))
            .find(|name| !self.instances.contains_key(name))
            .expect("some number is free")
    }
}

/// Whether `--instance` or `AK_INSTANCE` holds a URL rather than a name.
pub fn is_instance_url(value: &str) -> bool {
    value.contains("://")
}

/// Check an instance URL and put it in the form the rest of ak expects: an http or
/// https URL with nothing after the path, no trailing slash and no `/api/v1`, which ak
/// adds itself. Credentials don't go in it, because it's printed and kept in plain text.
pub fn normalize_instance_url(url: &str) -> Result<String> {
    let trimmed = url.trim();
    if !is_instance_url(trimmed) {
        return Err(AkError::Usage(format!(
            "'{trimmed}' has no scheme. Give the whole URL, such as https://{trimmed}"
        ))
        .into());
    }
    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|e| AkError::Usage(format!("'{}' isn't a valid URL: {e}", shown_url(trimmed))))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(AkError::Usage(format!(
            "An instance URL starts with https:// or http://, not {}://",
            parsed.scheme()
        ))
        .into());
    }
    if parsed.host_str().is_none() {
        return Err(AkError::Usage("The instance URL has no host".to_string()).into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AkError::Usage(
            "An instance URL can't hold a username or password. Use `ak auth login`.".to_string(),
        )
        .into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(
            AkError::Usage("An instance URL can't have a query or a fragment".to_string()).into(),
        );
    }

    let whole = parsed.as_str().trim_end_matches('/');
    match whole.strip_suffix("/api/v1") {
        Some(base) => {
            warn_api_path_once(base);
            Ok(base.trim_end_matches('/').to_string())
        }
        None => Ok(whole.to_string()),
    }
}

/// A URL that couldn't be parsed may still hold a password, so only its start is shown.
fn shown_url(url: &str) -> String {
    match url.split_once('@') {
        Some((_, host)) => format!("...@{host}"),
        None => url.to_string(),
    }
}

/// This URL is resolved several times in one command, and once is enough to say so.
fn warn_api_path_once(base: &str) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        eprintln!("Warning: ak adds /api/v1 itself, so it's using {base}");
    });
}

/// Write `content` to `path` without the file ever being readable by other
/// users, and without readers observing a partially written file.
///
/// The content is first written to a uniquely named temporary file created in
/// the same directory as `path` (so the final rename stays on one filesystem
/// and is atomic), then renamed over `path`, replacing any previous version.
///
/// On Unix the temporary file is created with mode `0o600` (via `O_CREAT |
/// O_EXCL`), so at no point does a file with the secret content exist with
/// group/world-readable permissions — unlike a plain `fs::write` followed by
/// `set_permissions`, which leaves a umask-dependent race window. On other
/// platforms the file inherits the default ACLs of the (already restricted)
/// parent directory.
pub(crate) fn write_private_atomic(
    path: &std::path::Path,
    content: impl AsRef<[u8]>,
) -> Result<()> {
    use std::io::Write;

    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };

    let mut builder = tempfile::Builder::new();
    builder.prefix(".ak-write-").suffix(".tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o600));
    }

    let mut tmp = builder.tempfile_in(&parent).into_diagnostic()?;
    tmp.write_all(content.as_ref()).into_diagnostic()?;
    tmp.as_file().sync_all().into_diagnostic()?;
    // `persist` renames the temp file over `path`, atomically replacing any
    // existing file; on failure the temp file is cleaned up.
    tmp.persist(path)
        .map_err(|e| AkError::ConfigError(format!("Failed to write {}: {}", path.display(), e)))?;
    Ok(())
}

/// Returns the path to the config directory.
pub fn config_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("AK_CONFIG_DIR") {
        Ok(PathBuf::from(dir))
    } else {
        Ok(dirs::config_dir()
            .ok_or_else(|| AkError::ConfigError("Cannot determine config directory".into()))?
            .join("artifact-keeper"))
    }
}

fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::ENV_LOCK;

    fn with_temp_config<F: FnOnce()>(f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };
        f();
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    // ---- AppConfig defaults ----

    #[test]
    fn default_config_has_no_instance() {
        let config = AppConfig::default();
        assert!(config.default_instance.is_none());
        assert!(config.instances.is_empty());
    }

    #[test]
    fn default_serde_values() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert_eq!(config.output_format, "table");
        assert_eq!(config.color, "auto");
        assert!(config.default_instance.is_none());
        assert!(config.instances.is_empty());
    }

    // ---- Serialization roundtrip ----

    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut config = AppConfig::default();
        config.default_instance = Some("prod".into());
        config.output_format = "json".into();
        config.color = "always".into();
        config.instances.insert(
            "prod".into(),
            InstanceConfig {
                url: "https://prod.example.com".into(),
                api_version: "v1".into(),
                allow_insecure_http: false,
            },
        );

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let loaded: AppConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(loaded.default_instance, Some("prod".into()));
        assert_eq!(loaded.output_format, "json");
        assert_eq!(loaded.color, "always");
        assert!(loaded.instances.contains_key("prod"));
        assert_eq!(loaded.instances["prod"].url, "https://prod.example.com");
    }

    #[test]
    fn instance_config_default_api_version() {
        let toml_str = r#"
[instances.test]
url = "https://test.com"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.instances["test"].api_version, "v1");
    }

    // ---- resolve_instance ----

    #[test]
    fn resolve_instance_no_instances_no_override() {
        let config = AppConfig::default();
        let result = config.resolve_instance(None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_instance_with_override() {
        let mut config = AppConfig::default();
        config.instances.insert(
            "prod".into(),
            InstanceConfig {
                url: "https://prod.example.com".into(),
                api_version: "v1".into(),
                allow_insecure_http: false,
            },
        );

        let (name, inst) = config.resolve_instance(Some("prod")).unwrap();
        assert_eq!(name, "prod");
        assert_eq!(inst.url, "https://prod.example.com");
    }

    #[test]
    fn resolve_instance_uses_default() {
        let mut config = AppConfig::default();
        config.default_instance = Some("staging".into());
        config.instances.insert(
            "staging".into(),
            InstanceConfig {
                url: "https://staging.example.com".into(),
                api_version: "v1".into(),
                allow_insecure_http: false,
            },
        );

        let (name, _) = config.resolve_instance(None).unwrap();
        assert_eq!(name, "staging");
    }

    #[test]
    fn resolve_instance_override_trumps_default() {
        let mut config = AppConfig::default();
        config.default_instance = Some("staging".into());
        config.instances.insert(
            "staging".into(),
            InstanceConfig {
                url: "https://staging.example.com".into(),
                api_version: "v1".into(),
                allow_insecure_http: false,
            },
        );
        config.instances.insert(
            "prod".into(),
            InstanceConfig {
                url: "https://prod.example.com".into(),
                api_version: "v1".into(),
                allow_insecure_http: false,
            },
        );

        let (name, _) = config.resolve_instance(Some("prod")).unwrap();
        assert_eq!(name, "prod");
    }

    #[test]
    fn resolve_instance_not_found() {
        let config = AppConfig::default();
        let result = config.resolve_instance(Some("nonexistent"));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_instance_default_not_in_map() {
        let mut config = AppConfig::default();
        config.default_instance = Some("deleted".into());
        let result = config.resolve_instance(None);
        assert!(result.is_err());
    }

    // ---- config_dir ----

    #[test]
    fn config_dir_from_env() {
        let _guard = crate::test_utils::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("AK_CONFIG_DIR", "/tmp/ak-test-config-dir") };
        let dir = config_dir().unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/ak-test-config-dir"));
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn config_dir_default_contains_artifact_keeper() {
        let _guard = crate::test_utils::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
        let dir = config_dir().unwrap();
        assert!(
            dir.to_string_lossy().contains("artifact-keeper"),
            "Default config dir should contain 'artifact-keeper': {}",
            dir.display()
        );
    }

    // ---- load / save ----

    #[test]
    fn load_nonexistent_returns_default() {
        with_temp_config(|| {
            let config = AppConfig::load().unwrap();
            assert!(config.default_instance.is_none());
            assert!(config.instances.is_empty());
            // Default::default() gives empty strings; serde defaults only apply during deserialization.
            // Downstream code (get_value) treats empty as "table"/"auto".
            assert!(config.output_format.is_empty());
            assert!(config.color.is_empty());
        });
    }

    #[test]
    fn save_and_load_roundtrip() {
        with_temp_config(|| {
            let mut config = AppConfig::default();
            config.default_instance = Some("test".into());
            config.output_format = "yaml".into();
            config.instances.insert(
                "test".into(),
                InstanceConfig {
                    url: "https://test.example.com".into(),
                    api_version: "v2".into(),
                    allow_insecure_http: false,
                },
            );
            config.save().unwrap();

            let loaded = AppConfig::load().unwrap();
            assert_eq!(loaded.default_instance, Some("test".into()));
            assert_eq!(loaded.output_format, "yaml");
            assert!(loaded.instances.contains_key("test"));
            assert_eq!(loaded.instances["test"].url, "https://test.example.com");
            assert_eq!(loaded.instances["test"].api_version, "v2");
        });
    }

    #[test]
    fn save_creates_parent_dirs() {
        with_temp_config(|| {
            let config = AppConfig::default();
            // save should work even if the parent dir doesn't exist yet
            config.save().unwrap();
            let loaded = AppConfig::load().unwrap();
            assert!(loaded.default_instance.is_none());
        });
    }

    #[test]
    fn save_overwrites_existing() {
        with_temp_config(|| {
            let mut config = AppConfig::default();
            config.output_format = "json".into();
            config.save().unwrap();

            let mut config2 = AppConfig::load().unwrap();
            config2.output_format = "yaml".into();
            config2.save().unwrap();

            let loaded = AppConfig::load().unwrap();
            assert_eq!(loaded.output_format, "yaml");
        });
    }

    // ---- write_private_atomic ----

    #[test]
    fn write_private_atomic_creates_file_with_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        write_private_atomic(&path, "top-secret").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "top-secret");
    }

    #[cfg(unix)]
    #[test]
    fn write_private_atomic_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        write_private_atomic(&path, "token").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "credential file must not be group/world accessible, got {mode:o}"
        );
        assert_eq!(mode, 0o600, "credential file should be 0600, got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn write_private_atomic_overwrite_keeps_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        // Simulate a pre-existing file with overly broad permissions.
        std::fs::write(&path, "old").unwrap();
        // The 0644 is the point of this test: write_private_atomic must tighten it to 0600.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap(); // NOSONAR

        write_private_atomic(&path, "new").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "replaced file should be 0600, got {mode:o}");
    }

    #[test]
    fn write_private_atomic_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        write_private_atomic(&path, "a").unwrap();
        write_private_atomic(&path, "b").unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["secret.json"], "no temp files should remain");
    }

    #[cfg(unix)]
    #[test]
    fn save_config_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        with_temp_config(|| {
            let config = AppConfig::default();
            config.save().unwrap();
            let path = config_path().unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "config.toml should be 0600, got {mode:o}");
        });
    }

    #[test]
    fn multiple_instances_roundtrip() {
        with_temp_config(|| {
            let mut config = AppConfig::default();
            config.default_instance = Some("prod".into());
            for name in &["prod", "staging", "dev"] {
                config.instances.insert(
                    name.to_string(),
                    InstanceConfig {
                        url: format!("https://{name}.example.com"),
                        api_version: "v1".into(),
                        allow_insecure_http: false,
                    },
                );
            }
            config.save().unwrap();

            let loaded = AppConfig::load().unwrap();
            assert_eq!(loaded.instances.len(), 3);
            assert!(loaded.instances.contains_key("prod"));
            assert!(loaded.instances.contains_key("staging"));
            assert!(loaded.instances.contains_key("dev"));
        });
    }
}
