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
        }
        let content = toml::to_string_pretty(self).into_diagnostic()?;
        std::fs::write(&path, content).into_diagnostic()?;
        Ok(())
    }

    /// Get the active instance config, resolving from flag → env → default.
    pub fn resolve_instance<'a>(
        &'a self,
        override_name: Option<&'a str>,
    ) -> Result<(&'a str, &'a InstanceConfig)> {
        let name = override_name
            .or(self.default_instance.as_deref())
            .ok_or(AkError::NoInstance)?;

        let instance = self
            .instances
            .get(name)
            .ok_or_else(|| AkError::InstanceNotFound(name.to_string()))?;

        Ok((name, instance))
    }
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
            },
        );
        config.instances.insert(
            "prod".into(),
            InstanceConfig {
                url: "https://prod.example.com".into(),
                api_version: "v1".into(),
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
