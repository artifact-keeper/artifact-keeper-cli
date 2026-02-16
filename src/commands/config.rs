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
