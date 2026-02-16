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
