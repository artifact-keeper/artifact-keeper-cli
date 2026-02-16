use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::Result;

use crate::cli::GlobalArgs;
use crate::config::{AppConfig, InstanceConfig};
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum InstanceCommand {
    /// Add an Artifact Keeper server
    Add {
        /// Friendly name for this instance
        name: String,

        /// Server URL (e.g., https://registry.company.com)
        url: String,

        /// API version
        #[arg(long, default_value = "v1")]
        api_version: String,
    },

    /// Remove a configured instance
    Remove {
        /// Instance name to remove
        name: String,
    },

    /// List all configured instances
    List,

    /// Set the default instance
    Use {
        /// Instance name to set as default
        name: String,
    },

    /// Show details about an instance
    Info {
        /// Instance name (uses default if omitted)
        name: Option<String>,
    },
}

impl InstanceCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Add {
                name,
                url,
                api_version,
            } => add_instance(&name, &url, &api_version),
            Self::Remove { name } => remove_instance(&name),
            Self::List => list_instances(&global.format),
            Self::Use { name } => use_instance(&name),
            Self::Info { name } => info_instance(name.as_deref(), global),
        }
    }
}

fn add_instance(name: &str, url: &str, api_version: &str) -> Result<()> {
    let mut config = AppConfig::load()?;

    if config.instances.contains_key(name) {
        return Err(AkError::ConfigError(format!(
            "Instance '{name}' already exists. Use `ak instance remove {name}` first."
        ))
        .into());
    }

    let url = url.trim_end_matches('/').to_string();
    let is_first = config.instances.is_empty();

    config.instances.insert(
        name.to_string(),
        InstanceConfig {
            url: url.clone(),
            api_version: api_version.to_string(),
        },
    );

    if is_first {
        config.default_instance = Some(name.to_string());
        eprintln!("Added instance '{name}' at {url} (set as default)");
    } else {
        eprintln!("Added instance '{name}' at {url}");
    }

    config.save()?;
    Ok(())
}

fn remove_instance(name: &str) -> Result<()> {
    let mut config = AppConfig::load()?;

    if config.instances.remove(name).is_none() {
        return Err(AkError::InstanceNotFound(name.to_string()).into());
    }

    if config.default_instance.as_deref() == Some(name) {
        config.default_instance = config.instances.keys().next().cloned();
        if let Some(ref new_default) = config.default_instance {
            eprintln!("Removed instance '{name}'. Default switched to '{new_default}'.");
        } else {
            eprintln!("Removed instance '{name}'. No instances remaining.");
        }
    } else {
        eprintln!("Removed instance '{name}'.");
    }

    config.save()?;
    Ok(())
}

fn list_instances(format: &OutputFormat) -> Result<()> {
    let config = AppConfig::load()?;

    if config.instances.is_empty() {
        eprintln!("No instances configured. Run `ak instance add <name> <url>` to add one.");
        return Ok(());
    }

    let is_default = |name: &str| config.default_instance.as_deref() == Some(name);

    if matches!(format, OutputFormat::Quiet) {
        for name in config.instances.keys() {
            println!("{name}");
        }
        return Ok(());
    }

    let entries: Vec<_> = config
        .instances
        .iter()
        .map(|(name, inst)| {
            serde_json::json!({
                "name": name,
                "url": inst.url,
                "api_version": inst.api_version,
                "default": is_default(name),
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["", "NAME", "URL", "API VERSION"]);

        for (name, inst) in &config.instances {
            let marker = if is_default(name) { "*" } else { " " };
            table.add_row(vec![marker, name, &inst.url, &inst.api_version]);
        }

        table.to_string()
    };

    println!("{}", output::render(&entries, format, Some(table_str)));

    Ok(())
}

fn use_instance(name: &str) -> Result<()> {
    let mut config = AppConfig::load()?;

    if !config.instances.contains_key(name) {
        return Err(AkError::InstanceNotFound(name.to_string()).into());
    }

    config.default_instance = Some(name.to_string());
    config.save()?;

    eprintln!("Default instance set to '{name}'.");
    Ok(())
}

fn info_instance(name: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;

    let (resolved_name, instance) = config.resolve_instance(name.or(global.instance.as_deref()))?;
    let is_default = config.default_instance.as_deref() == Some(resolved_name);

    let info = serde_json::json!({
        "name": resolved_name,
        "url": instance.url,
        "api_version": instance.api_version,
        "default": is_default,
    });

    let table_str = format!(
        "Name:        {}\nURL:         {}\nAPI Version: {}\nDefault:     {}",
        resolved_name,
        instance.url,
        instance.api_version,
        if is_default { "yes" } else { "no" },
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
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

    // ---- add_instance ----

    #[test]
    fn add_instance_first_becomes_default() {
        with_temp_config(|| {
            add_instance("prod", "https://prod.example.com", "v1").unwrap();

            let config = AppConfig::load().unwrap();
            assert!(config.instances.contains_key("prod"));
            assert_eq!(config.default_instance, Some("prod".into()));
            assert_eq!(config.instances["prod"].url, "https://prod.example.com");
        });
    }

    #[test]
    fn add_instance_second_not_default() {
        with_temp_config(|| {
            add_instance("prod", "https://prod.example.com", "v1").unwrap();
            add_instance("staging", "https://staging.example.com", "v1").unwrap();

            let config = AppConfig::load().unwrap();
            assert_eq!(config.instances.len(), 2);
            assert_eq!(config.default_instance, Some("prod".into()));
        });
    }

    #[test]
    fn add_instance_duplicate_fails() {
        with_temp_config(|| {
            add_instance("prod", "https://prod.example.com", "v1").unwrap();
            let result = add_instance("prod", "https://other.com", "v1");
            assert!(result.is_err());
        });
    }

    #[test]
    fn add_instance_strips_trailing_slash() {
        with_temp_config(|| {
            add_instance("test", "https://example.com/", "v1").unwrap();

            let config = AppConfig::load().unwrap();
            assert_eq!(config.instances["test"].url, "https://example.com");
        });
    }

    #[test]
    fn add_instance_custom_api_version() {
        with_temp_config(|| {
            add_instance("test", "https://example.com", "v2").unwrap();

            let config = AppConfig::load().unwrap();
            assert_eq!(config.instances["test"].api_version, "v2");
        });
    }

    // ---- remove_instance ----

    #[test]
    fn remove_instance_exists() {
        with_temp_config(|| {
            add_instance("prod", "https://prod.example.com", "v1").unwrap();
            add_instance("staging", "https://staging.example.com", "v1").unwrap();

            remove_instance("staging").unwrap();

            let config = AppConfig::load().unwrap();
            assert_eq!(config.instances.len(), 1);
            assert!(!config.instances.contains_key("staging"));
        });
    }

    #[test]
    fn remove_instance_not_found() {
        with_temp_config(|| {
            let result = remove_instance("nonexistent");
            assert!(result.is_err());
        });
    }

    #[test]
    fn remove_default_instance_switches_default() {
        with_temp_config(|| {
            add_instance("alpha", "https://alpha.com", "v1").unwrap();
            add_instance("beta", "https://beta.com", "v1").unwrap();

            // alpha is default (first added)
            remove_instance("alpha").unwrap();

            let config = AppConfig::load().unwrap();
            assert_eq!(config.instances.len(), 1);
            // default should switch to the remaining instance
            assert!(config.default_instance.is_some());
        });
    }

    #[test]
    fn remove_last_instance_clears_default() {
        with_temp_config(|| {
            add_instance("only", "https://only.com", "v1").unwrap();
            remove_instance("only").unwrap();

            let config = AppConfig::load().unwrap();
            assert!(config.instances.is_empty());
            assert!(config.default_instance.is_none());
        });
    }

    // ---- use_instance ----

    #[test]
    fn use_instance_sets_default() {
        with_temp_config(|| {
            add_instance("prod", "https://prod.com", "v1").unwrap();
            add_instance("staging", "https://staging.com", "v1").unwrap();

            use_instance("staging").unwrap();

            let config = AppConfig::load().unwrap();
            assert_eq!(config.default_instance, Some("staging".into()));
        });
    }

    #[test]
    fn use_instance_not_found() {
        with_temp_config(|| {
            let result = use_instance("nonexistent");
            assert!(result.is_err());
        });
    }

    // ---- list_instances ----

    #[test]
    fn list_instances_empty() {
        with_temp_config(|| {
            // Should not error even with no instances
            list_instances(&OutputFormat::Quiet).unwrap();
        });
    }

    #[test]
    fn list_instances_with_entries() {
        with_temp_config(|| {
            add_instance("prod", "https://prod.com", "v1").unwrap();
            add_instance("staging", "https://staging.com", "v1").unwrap();

            list_instances(&OutputFormat::Quiet).unwrap();
            list_instances(&OutputFormat::Json).unwrap();
            list_instances(&OutputFormat::Yaml).unwrap();
            list_instances(&OutputFormat::Table).unwrap();
        });
    }

    // ---- info_instance ----

    #[test]
    fn info_instance_default() {
        with_temp_config(|| {
            add_instance("prod", "https://prod.com", "v1").unwrap();

            let global = GlobalArgs {
                format: OutputFormat::Quiet,
                instance: None,
                no_input: true,
            };
            info_instance(None, &global).unwrap();
        });
    }

    #[test]
    fn info_instance_by_name() {
        with_temp_config(|| {
            add_instance("prod", "https://prod.com", "v1").unwrap();
            add_instance("staging", "https://staging.com", "v1").unwrap();

            let global = GlobalArgs {
                format: OutputFormat::Json,
                instance: None,
                no_input: true,
            };
            info_instance(Some("staging"), &global).unwrap();
        });
    }
}
