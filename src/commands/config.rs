use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::Result;

use crate::cli::GlobalArgs;
use crate::config::{self, AppConfig};
use crate::error::AkError;
use crate::output::{self, OutputFormat};

/// Recognised top-level config keys.
const KNOWN_KEYS: &[&str] = &["default_instance", "output_format", "color"];

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Get a configuration value
    Get {
        /// Configuration key (default_instance, output_format, color)
        key: String,
    },

    /// Set a configuration value
    Set {
        /// Configuration key (default_instance, output_format, color)
        key: String,
        /// Configuration value
        value: String,
    },

    /// List all configuration values
    List,

    /// Show the path to the configuration file
    Path,
}

impl ConfigCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Get { key } => config_get(&key, &global.format),
            Self::Set { key, value } => config_set(&key, &value),
            Self::List => config_list(&global.format),
            Self::Path => config_path(),
        }
    }
}

fn get_value(cfg: &AppConfig, key: &str) -> Result<String> {
    let value = match key {
        "default_instance" => cfg
            .default_instance
            .clone()
            .unwrap_or_else(|| "(not set)".into()),
        "output_format" if cfg.output_format.is_empty() => "table".into(),
        "output_format" => cfg.output_format.clone(),
        "color" if cfg.color.is_empty() => "auto".into(),
        "color" => cfg.color.clone(),
        _ => {
            return Err(AkError::ConfigError(format!(
                "Unknown config key '{key}'. Valid keys: {}",
                KNOWN_KEYS.join(", ")
            ))
            .into());
        }
    };
    Ok(value)
}

fn config_get(key: &str, format: &OutputFormat) -> Result<()> {
    let cfg = AppConfig::load()?;
    let value = get_value(&cfg, key)?;

    let data = serde_json::json!({ "key": key, "value": value });
    let table_str = value.clone();

    println!("{}", output::render(&data, format, Some(table_str)));
    Ok(())
}

fn config_set(key: &str, value: &str) -> Result<()> {
    let mut cfg = AppConfig::load()?;

    match key {
        "default_instance" => {
            if value == "(not set)" || value.is_empty() {
                cfg.default_instance = None;
            } else if !cfg.instances.contains_key(value) {
                return Err(AkError::ConfigError(format!(
                    "Instance '{value}' not found. Run `ak instance list` to see available instances."
                ))
                .into());
            } else {
                cfg.default_instance = Some(value.to_string());
            }
        }
        "output_format" => {
            if !matches!(value, "table" | "json" | "yaml" | "quiet") {
                return Err(AkError::ConfigError(format!(
                    "Invalid output format '{value}'. Valid values: table, json, yaml, quiet"
                ))
                .into());
            }
            cfg.output_format = value.to_string();
        }
        "color" => {
            if !matches!(value, "auto" | "always" | "never") {
                return Err(AkError::ConfigError(format!(
                    "Invalid color mode '{value}'. Valid values: auto, always, never"
                ))
                .into());
            }
            cfg.color = value.to_string();
        }
        _ => {
            return Err(AkError::ConfigError(format!(
                "Unknown config key '{key}'. Valid keys: {}",
                KNOWN_KEYS.join(", ")
            ))
            .into());
        }
    }

    cfg.save()?;
    eprintln!("Set {key} = {value}");
    Ok(())
}

fn config_list(format: &OutputFormat) -> Result<()> {
    let cfg = AppConfig::load()?;

    let entries: Vec<_> = KNOWN_KEYS
        .iter()
        .map(|&key| {
            let value = get_value(&cfg, key).unwrap_or_default();
            serde_json::json!({ "key": key, "value": value })
        })
        .collect();

    if matches!(format, OutputFormat::Quiet) {
        for entry in &entries {
            println!(
                "{}={}",
                entry["key"].as_str().unwrap_or_default(),
                entry["value"].as_str().unwrap_or_default()
            );
        }
        return Ok(());
    }

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["KEY", "VALUE"]);

        for entry in &entries {
            table.add_row(vec![
                entry["key"].as_str().unwrap_or_default(),
                entry["value"].as_str().unwrap_or_default(),
            ]);
        }

        table.to_string()
    };

    println!("{}", output::render(&entries, format, Some(table_str)));
    Ok(())
}

fn config_path() -> Result<()> {
    let path = config::config_dir()?.join("config.toml");
    println!("{}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::InstanceConfig;
    use crate::test_utils::ENV_LOCK;

    fn make_config(default_instance: Option<&str>, output_format: &str, color: &str) -> AppConfig {
        let mut cfg = AppConfig::default();
        cfg.default_instance = default_instance.map(|s| s.to_string());
        cfg.output_format = output_format.to_string();
        cfg.color = color.to_string();
        cfg
    }

    // ---- get_value ----

    #[test]
    fn get_value_default_instance_set() {
        let cfg = make_config(Some("prod"), "table", "auto");
        assert_eq!(get_value(&cfg, "default_instance").unwrap(), "prod");
    }

    #[test]
    fn get_value_default_instance_not_set() {
        let cfg = make_config(None, "table", "auto");
        assert_eq!(get_value(&cfg, "default_instance").unwrap(), "(not set)");
    }

    #[test]
    fn get_value_output_format_table() {
        let cfg = make_config(None, "table", "auto");
        assert_eq!(get_value(&cfg, "output_format").unwrap(), "table");
    }

    #[test]
    fn get_value_output_format_json() {
        let cfg = make_config(None, "json", "auto");
        assert_eq!(get_value(&cfg, "output_format").unwrap(), "json");
    }

    #[test]
    fn get_value_output_format_empty_defaults_to_table() {
        let cfg = make_config(None, "", "auto");
        assert_eq!(get_value(&cfg, "output_format").unwrap(), "table");
    }

    #[test]
    fn get_value_color_auto() {
        let cfg = make_config(None, "table", "auto");
        assert_eq!(get_value(&cfg, "color").unwrap(), "auto");
    }

    #[test]
    fn get_value_color_always() {
        let cfg = make_config(None, "table", "always");
        assert_eq!(get_value(&cfg, "color").unwrap(), "always");
    }

    #[test]
    fn get_value_color_empty_defaults_to_auto() {
        let cfg = make_config(None, "table", "");
        assert_eq!(get_value(&cfg, "color").unwrap(), "auto");
    }

    #[test]
    fn get_value_unknown_key() {
        let cfg = AppConfig::default();
        let result = get_value(&cfg, "nonexistent");
        assert!(result.is_err());
    }

    // ---- KNOWN_KEYS ----

    #[test]
    fn known_keys_contains_expected() {
        assert!(KNOWN_KEYS.contains(&"default_instance"));
        assert!(KNOWN_KEYS.contains(&"output_format"));
        assert!(KNOWN_KEYS.contains(&"color"));
    }

    // ---- config_set ----

    #[test]
    fn config_set_output_format_valid() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let cfg = AppConfig::default();
        cfg.save().unwrap();

        config_set("output_format", "json").unwrap();

        let loaded = AppConfig::load().unwrap();
        assert_eq!(loaded.output_format, "json");
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn config_set_output_format_invalid() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let cfg = AppConfig::default();
        cfg.save().unwrap();

        let result = config_set("output_format", "xml");
        assert!(result.is_err());
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn config_set_color_valid() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let cfg = AppConfig::default();
        cfg.save().unwrap();

        config_set("color", "always").unwrap();

        let loaded = AppConfig::load().unwrap();
        assert_eq!(loaded.color, "always");
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn config_set_color_invalid() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let cfg = AppConfig::default();
        cfg.save().unwrap();

        let result = config_set("color", "rainbow");
        assert!(result.is_err());
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn config_set_default_instance_valid() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let mut cfg = AppConfig::default();
        cfg.instances.insert(
            "prod".into(),
            InstanceConfig {
                url: "https://prod.example.com".into(),
                api_version: "v1".into(),
            },
        );
        cfg.save().unwrap();

        config_set("default_instance", "prod").unwrap();

        let loaded = AppConfig::load().unwrap();
        assert_eq!(loaded.default_instance, Some("prod".into()));
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn config_set_default_instance_not_found() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let cfg = AppConfig::default();
        cfg.save().unwrap();

        let result = config_set("default_instance", "nonexistent");
        assert!(result.is_err());
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn config_set_default_instance_clear() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let mut cfg = AppConfig::default();
        cfg.default_instance = Some("old".into());
        cfg.save().unwrap();

        config_set("default_instance", "(not set)").unwrap();

        let loaded = AppConfig::load().unwrap();
        assert!(loaded.default_instance.is_none());
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn config_set_unknown_key() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let cfg = AppConfig::default();
        cfg.save().unwrap();

        let result = config_set("unknown_key", "value");
        assert!(result.is_err());
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    // ---- config_list ----

    #[test]
    fn config_list_returns_all_keys() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let cfg = AppConfig::default();
        cfg.save().unwrap();

        config_list(&OutputFormat::Quiet).unwrap();
        config_list(&OutputFormat::Json).unwrap();

        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    // ---- config_path ----

    #[test]
    fn config_path_returns_ok() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        config_path().unwrap();

        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }
}
