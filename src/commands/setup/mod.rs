use std::path::{Path, PathBuf};

use artifact_keeper_sdk::ClientRepositoriesExt;
use clap::Subcommand;
use miette::{IntoDiagnostic, Result};

use super::client::authenticated_client;
use crate::cli::GlobalArgs;
use crate::error::AkError;

#[derive(Subcommand)]
pub enum SetupCommand {
    /// Auto-detect project toolchain and configure all package managers
    Auto,

    /// Configure npm/pnpm/yarn to use Artifact Keeper
    Npm {
        /// Repository key (auto-detected if only one npm repo exists)
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure pip/poetry/pipenv to use Artifact Keeper
    Pip {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure Cargo to use Artifact Keeper
    Cargo {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure Docker to use Artifact Keeper
    Docker {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure Maven to use Artifact Keeper
    Maven {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure Gradle to use Artifact Keeper
    Gradle {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure Go modules to use Artifact Keeper
    Go {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure Helm to use Artifact Keeper
    Helm {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure NuGet to use Artifact Keeper
    Nuget {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure yum/dnf to use Artifact Keeper (requires sudo)
    Yum {
        #[arg(long)]
        repo: Option<String>,
    },

    /// Configure apt to use Artifact Keeper (requires sudo)
    Apt {
        #[arg(long)]
        repo: Option<String>,
    },
}

impl SetupCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Auto => auto_detect(global).await,
            Self::Npm { repo } => setup_npm(repo.as_deref(), global).await,
            Self::Pip { repo } => setup_pip(repo.as_deref(), global).await,
            Self::Cargo { repo } => setup_cargo(repo.as_deref(), global).await,
            Self::Docker { repo } => setup_docker(repo.as_deref(), global).await,
            Self::Maven { repo } => setup_maven(repo.as_deref(), global).await,
            Self::Gradle { repo } => setup_gradle(repo.as_deref(), global).await,
            Self::Go { repo } => setup_go(repo.as_deref(), global).await,
            Self::Helm { repo } => setup_helm(repo.as_deref(), global).await,
            Self::Nuget { repo } => setup_nuget(repo.as_deref(), global).await,
            Self::Yum { repo } => setup_yum(repo.as_deref(), global).await,
            Self::Apt { repo } => setup_apt(repo.as_deref(), global).await,
        }
    }
}

struct DetectedEcosystem {
    name: &'static str,
    format: &'static str,
    marker: &'static str,
}

const ECOSYSTEMS: &[DetectedEcosystem] = &[
    DetectedEcosystem {
        name: "npm",
        format: "npm",
        marker: "package.json",
    },
    DetectedEcosystem {
        name: "pip",
        format: "pypi",
        marker: "pyproject.toml",
    },
    DetectedEcosystem {
        name: "pip",
        format: "pypi",
        marker: "requirements.txt",
    },
    DetectedEcosystem {
        name: "pip",
        format: "pypi",
        marker: "setup.py",
    },
    DetectedEcosystem {
        name: "cargo",
        format: "cargo",
        marker: "Cargo.toml",
    },
    DetectedEcosystem {
        name: "docker",
        format: "docker",
        marker: "Dockerfile",
    },
    DetectedEcosystem {
        name: "docker",
        format: "docker",
        marker: "docker-compose.yml",
    },
    DetectedEcosystem {
        name: "maven",
        format: "maven",
        marker: "pom.xml",
    },
    DetectedEcosystem {
        name: "gradle",
        format: "maven",
        marker: "build.gradle",
    },
    DetectedEcosystem {
        name: "gradle",
        format: "maven",
        marker: "build.gradle.kts",
    },
    DetectedEcosystem {
        name: "go",
        format: "go",
        marker: "go.mod",
    },
    DetectedEcosystem {
        name: "nuget",
        format: "nuget",
        marker: "*.csproj",
    },
    DetectedEcosystem {
        name: "nuget",
        format: "nuget",
        marker: "*.fsproj",
    },
    DetectedEcosystem {
        name: "helm",
        format: "helm",
        marker: "Chart.yaml",
    },
];

fn detect_ecosystems(dir: &Path) -> Vec<&'static str> {
    let mut found = Vec::new();
    for eco in ECOSYSTEMS {
        if found.contains(&eco.name) {
            continue;
        }
        if eco.marker.contains('*') {
            if let Ok(matches) = glob::glob(&dir.join(eco.marker).to_string_lossy()) {
                if matches.into_iter().any(|m| m.is_ok()) {
                    found.push(eco.name);
                }
            }
        } else if dir.join(eco.marker).exists() {
            found.push(eco.name);
        }
    }
    found
}

/// Resolved setup context: repository key, registry URL, instance name, and access token.
struct SetupContext {
    repo_key: String,
    registry_url: String,
    instance_name: String,
    token: String,
}

/// Resolve instance, credentials, and pick a repository for the given format.
async fn resolve_setup(
    format: &str,
    explicit_repo: Option<&str>,
    global: &GlobalArgs,
) -> Result<SetupContext> {
    let (instance_name, instance, client) = authenticated_client(global)?;

    let registry_url = format!("{}/api/{}/{}", instance.url, instance.api_version, format);

    let repo_key = if let Some(key) = explicit_repo {
        key.to_string()
    } else {
        let spinner = crate::output::spinner(&format!("Fetching {format} repositories..."));

        let repos = client
            .list_repositories()
            .format(format)
            .per_page(100)
            .send()
            .await
            .map_err(|e| AkError::ServerError(format!("Failed to list repositories: {e}")))?;

        spinner.finish_and_clear();

        if repos.items.is_empty() {
            return Err(AkError::ConfigError(format!(
                "No {format} repositories found. Create one with `ak repo create <key> --format {format}`"
            ))
            .into());
        }

        if repos.items.len() == 1 {
            let key = repos.items[0].key.clone();
            eprintln!("Using repository: {key}");
            key
        } else if global.no_input {
            return Err(AkError::ConfigError(format!(
                "Multiple {format} repositories found. Use --repo to specify one."
            ))
            .into());
        } else {
            let items: Vec<String> = repos
                .items
                .iter()
                .map(|r| {
                    if r.repo_type == "virtual" {
                        format!("{} (virtual)", r.key)
                    } else {
                        format!("{} ({})", r.key, r.repo_type)
                    }
                })
                .collect();

            let selection = dialoguer::FuzzySelect::new()
                .with_prompt(format!("Select {format} repository"))
                .items(&items)
                .interact()
                .into_diagnostic()?;

            repos.items[selection].key.clone()
        }
    };

    let cred = crate::config::credentials::get_credential(&instance_name)?;

    Ok(SetupContext {
        repo_key,
        registry_url,
        instance_name,
        token: cred.access_token,
    })
}

fn home_dir() -> Result<PathBuf> {
    dirs::home_dir()
        .ok_or_else(|| AkError::ConfigError("Cannot determine home directory".into()).into())
}

fn config_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .ok_or_else(|| AkError::ConfigError("Cannot determine config directory".into()).into())
}

/// Extract the host portion from a URL (strips protocol and trailing path).
fn host_from_url(url: &str) -> &str {
    strip_protocol(url).split('/').next().unwrap_or("")
}

fn strip_protocol(url: &str) -> &str {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
}

fn write_config_file(path: &Path, content: &str, description: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).into_diagnostic()?;
    }

    if path.exists() {
        eprintln!(
            "Backing up existing {} to {}.bak",
            description,
            path.display()
        );
        std::fs::copy(path, path.with_extension("bak")).into_diagnostic()?;
    }

    std::fs::write(path, content).into_diagnostic()?;
    eprintln!("Wrote {}: {}", description, path.display());
    Ok(())
}

fn confirm_write(path: &Path, content: &str, no_input: bool) -> Result<bool> {
    eprintln!("\nConfiguration to write to {}:\n", path.display());
    eprintln!("{content}");

    if no_input {
        return Ok(true);
    }

    dialoguer::Confirm::new()
        .with_prompt("Write this configuration?")
        .default(true)
        .interact()
        .into_diagnostic()
}

/// Write content to a system path using `sudo tee`.
fn sudo_write(path: &Path, content: &str) -> Result<()> {
    let status = std::process::Command::new("sudo")
        .args(["tee", &path.to_string_lossy()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(content.as_bytes())?;
            }
            child.wait()
        })
        .into_diagnostic()?;

    if !status.success() {
        return Err(AkError::ServerError(format!("Failed to write {}", path.display())).into());
    }

    Ok(())
}

async fn auto_detect(global: &GlobalArgs) -> Result<()> {
    let cwd = std::env::current_dir().into_diagnostic()?;
    let detected = detect_ecosystems(&cwd);

    if detected.is_empty() {
        eprintln!("No recognized project files found in the current directory.");
        eprintln!("Run `ak setup <ecosystem>` to configure a specific package manager.");
        return Ok(());
    }

    eprintln!("Detected project toolchain:");
    for name in &detected {
        eprintln!("  * {name}");
    }
    eprintln!();

    for name in &detected {
        eprintln!("--- Setting up {name} ---");
        match *name {
            "npm" => setup_npm(None, global).await?,
            "pip" => setup_pip(None, global).await?,
            "cargo" => setup_cargo(None, global).await?,
            "docker" => setup_docker(None, global).await?,
            "maven" => setup_maven(None, global).await?,
            "gradle" => setup_gradle(None, global).await?,
            "go" => setup_go(None, global).await?,
            "helm" => setup_helm(None, global).await?,
            "nuget" => setup_nuget(None, global).await?,
            _ => {}
        }
        eprintln!();
    }

    eprintln!("All done! Your tools are configured.");
    Ok(())
}

async fn setup_npm(repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("npm", repo, global).await?;
    let npm_registry_url = format!("{}/{}/", ctx.registry_url, ctx.repo_key);

    let npmrc_content = format!(
        "registry={npm_registry_url}\n\
         //{host}:_authToken={token}\n",
        host = strip_protocol(&npm_registry_url),
        token = ctx.token,
    );

    let npmrc_path = std::env::current_dir().into_diagnostic()?.join(".npmrc");

    if !confirm_write(&npmrc_path, &npmrc_content, global.no_input)? {
        eprintln!("Skipped npm configuration.");
        return Ok(());
    }

    write_config_file(&npmrc_path, &npmrc_content, ".npmrc")?;
    eprintln!(
        "npm is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_pip(repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("pypi", repo, global).await?;
    let index_url = format!("{}/{}/simple/", ctx.registry_url, ctx.repo_key);

    let pip_conf_content = format!(
        "[global]\n\
         index-url = https://__token__:{token}@{host_and_path}\n",
        token = ctx.token,
        host_and_path = strip_protocol(&index_url),
    );

    let filename = if cfg!(windows) { "pip.ini" } else { "pip.conf" };
    let pip_conf_path = config_dir()?.join("pip").join(filename);

    if !confirm_write(&pip_conf_path, &pip_conf_content, global.no_input)? {
        eprintln!("Skipped pip configuration.");
        return Ok(());
    }

    write_config_file(&pip_conf_path, &pip_conf_content, "pip.conf")?;
    eprintln!(
        "pip is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_cargo(repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("cargo", repo, global).await?;
    let cargo_registry_url = format!("{}/{}/", ctx.registry_url, ctx.repo_key);

    let cargo_home = std::env::var("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".cargo")
        });

    let config_content = format!(
        "[registries.artifact-keeper]\n\
         index = \"{cargo_registry_url}\"\n\
         \n\
         [registry]\n\
         default = \"artifact-keeper\"\n"
    );

    let credentials_content = format!(
        "[registries.artifact-keeper]\n\
         token = \"Bearer {}\"\n",
        ctx.token,
    );

    let config_path = cargo_home.join("config.toml");
    let creds_path = cargo_home.join("credentials.toml");

    eprintln!("Will write two files:");
    if !confirm_write(&config_path, &config_content, global.no_input)? {
        eprintln!("Skipped Cargo configuration.");
        return Ok(());
    }

    write_config_file(&config_path, &config_content, "cargo config.toml")?;

    if !confirm_write(&creds_path, &credentials_content, global.no_input)? {
        eprintln!("Skipped Cargo credentials.");
        return Ok(());
    }

    write_config_file(&creds_path, &credentials_content, "cargo credentials.toml")?;
    eprintln!(
        "Cargo is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_docker(repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("docker", repo, global).await?;

    let config = crate::config::AppConfig::load()?;
    let (_, instance) = config.resolve_instance(Some(&ctx.instance_name))?;
    let host = url::Url::parse(&instance.url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| instance.url.clone());

    eprintln!("Running: docker login {host}");
    eprintln!(
        "Using token authentication for repository '{}'",
        ctx.repo_key
    );

    let status = std::process::Command::new("docker")
        .args(["login", &host, "-u", "__token__", "--password-stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(ctx.token.as_bytes())?;
            }
            child.wait()
        })
        .into_diagnostic()?;

    if !status.success() {
        return Err(
            AkError::ServerError("Docker login failed. Check your credentials.".into()).into(),
        );
    }

    eprintln!("Docker login succeeded for '{}'.", ctx.repo_key);
    Ok(())
}

async fn setup_maven(repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("maven", repo, global).await?;
    let maven_url = format!("{}/{}/", ctx.registry_url, ctx.repo_key);

    let settings_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0
                              http://maven.apache.org/xsd/settings-1.0.0.xsd">
  <servers>
    <server>
      <id>artifact-keeper</id>
      <username>__token__</username>
      <password>{token}</password>
    </server>
  </servers>
  <profiles>
    <profile>
      <id>artifact-keeper</id>
      <repositories>
        <repository>
          <id>artifact-keeper</id>
          <url>{maven_url}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>artifact-keeper</activeProfile>
  </activeProfiles>
</settings>
"#,
        token = ctx.token,
    );

    let settings_path = home_dir()?.join(".m2").join("settings.xml");

    if !confirm_write(&settings_path, &settings_content, global.no_input)? {
        eprintln!("Skipped Maven configuration.");
        return Ok(());
    }

    write_config_file(&settings_path, &settings_content, "Maven settings.xml")?;
    eprintln!(
        "Maven is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_gradle(repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("maven", repo, global).await?;
    let gradle_url = format!("{}/{}/", ctx.registry_url, ctx.repo_key);

    let init_content = format!(
        r#"allprojects {{
    repositories {{
        maven {{
            url "{gradle_url}"
            credentials {{
                username = "__token__"
                password = "{token}"
            }}
        }}
    }}
}}
"#,
        token = ctx.token,
    );

    let init_path = home_dir()?
        .join(".gradle")
        .join("init.d")
        .join("artifact-keeper.gradle");

    if !confirm_write(&init_path, &init_content, global.no_input)? {
        eprintln!("Skipped Gradle configuration.");
        return Ok(());
    }

    write_config_file(&init_path, &init_content, "Gradle init script")?;
    eprintln!(
        "Gradle is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_go(repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("go", repo, global).await?;
    let goproxy_url = format!("{}/{}/", ctx.registry_url, ctx.repo_key);
    let host = host_from_url(&goproxy_url);

    eprintln!("Add the following to your shell profile (~/.bashrc, ~/.zshrc, etc.):\n");
    eprintln!("  export GOPROXY=\"{goproxy_url},direct\"");
    eprintln!("  export GONOSUMDB=\"{host}\"");
    eprintln!("  export GONOSUMCHECK=\"{host}\"");
    eprintln!();

    let netrc_line = format!("machine {host} login __token__ password {}", ctx.token);
    let netrc_path = home_dir()?.join(".netrc");

    eprintln!(
        "For authentication, add this line to {}:",
        netrc_path.display()
    );
    eprintln!("  {netrc_line}");

    if global.no_input {
        return Ok(());
    }

    let write_netrc = dialoguer::Confirm::new()
        .with_prompt("Append to .netrc now?")
        .default(true)
        .interact()
        .into_diagnostic()?;

    if write_netrc {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&netrc_path)
            .into_diagnostic()?;
        writeln!(file, "{netrc_line}").into_diagnostic()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&netrc_path, std::fs::Permissions::from_mode(0o600))
                .into_diagnostic()?;
        }

        eprintln!("Updated {}", netrc_path.display());
    }

    eprintln!("Go is configured to use repository '{}'.", ctx.repo_key);
    Ok(())
}

async fn setup_helm(repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("helm", repo, global).await?;
    let helm_url = format!("{}/{}/", ctx.registry_url, ctx.repo_key);

    eprintln!("Running: helm repo add artifact-keeper {helm_url}");

    let status = std::process::Command::new("helm")
        .args([
            "repo",
            "add",
            "artifact-keeper",
            &helm_url,
            "--username",
            "__token__",
            "--password",
            &ctx.token,
        ])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .into_diagnostic()?;

    if !status.success() {
        return Err(AkError::ServerError("helm repo add failed".into()).into());
    }

    eprintln!("Helm repository added. Run `helm repo update` to fetch charts.");
    Ok(())
}

async fn setup_nuget(repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("nuget", repo, global).await?;
    let nuget_url = format!("{}/{}/index.json", ctx.registry_url, ctx.repo_key);

    let nuget_config = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="ArtifactKeeper" value="{nuget_url}" />
  </packageSources>
  <packageSourceCredentials>
    <ArtifactKeeper>
      <add key="Username" value="__token__" />
      <add key="ClearTextPassword" value="{token}" />
    </ArtifactKeeper>
  </packageSourceCredentials>
</configuration>
"#,
        token = ctx.token,
    );

    let config_path = std::env::current_dir()
        .into_diagnostic()?
        .join("nuget.config");

    if !confirm_write(&config_path, &nuget_config, global.no_input)? {
        eprintln!("Skipped NuGet configuration.");
        return Ok(());
    }

    write_config_file(&config_path, &nuget_config, "nuget.config")?;
    eprintln!(
        "NuGet is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_yum(repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("rpm", repo, global).await?;
    let yum_url = format!("{}/{}/", ctx.registry_url, ctx.repo_key);

    let repo_content = format!(
        "[artifact-keeper-{repo_key}]\n\
         name=Artifact Keeper - {repo_key}\n\
         baseurl={yum_url}\n\
         enabled=1\n\
         gpgcheck=0\n\
         username=__token__\n\
         password={token}\n",
        repo_key = ctx.repo_key,
        token = ctx.token,
    );

    let repo_path = PathBuf::from(format!(
        "/etc/yum.repos.d/artifact-keeper-{}.repo",
        ctx.repo_key
    ));

    eprintln!(
        "This requires writing to {} (needs sudo).",
        repo_path.display()
    );
    eprintln!("\nConfiguration:\n{repo_content}");

    if global.no_input {
        eprintln!("Run the following command manually:");
        eprintln!(
            "  sudo tee {} <<'EOF'\n{}EOF",
            repo_path.display(),
            repo_content
        );
        return Ok(());
    }

    let proceed = dialoguer::Confirm::new()
        .with_prompt("Write with sudo?")
        .default(false)
        .interact()
        .into_diagnostic()?;

    if !proceed {
        eprintln!("Skipped. Run the command above manually.");
        return Ok(());
    }

    sudo_write(&repo_path, &repo_content)?;
    eprintln!(
        "yum/dnf is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_apt(repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("deb", repo, global).await?;
    let apt_url = format!("{}/{}/", ctx.registry_url, ctx.repo_key);
    let host = host_from_url(&apt_url);

    let sources_content = format!("deb [trusted=yes] {apt_url} stable main\n");
    let auth_content = format!(
        "machine {host}\n\
         login __token__\n\
         password {}\n",
        ctx.token,
    );

    let sources_path = PathBuf::from(format!(
        "/etc/apt/sources.list.d/artifact-keeper-{}.list",
        ctx.repo_key
    ));
    let auth_path = PathBuf::from("/etc/apt/auth.conf.d/artifact-keeper.conf");

    eprintln!("This requires writing to /etc/apt/ (needs sudo).");
    eprintln!("\nSources list:\n{sources_content}");
    eprintln!("Auth config:\n{auth_content}");

    if global.no_input {
        eprintln!("Run the following commands manually:");
        eprintln!(
            "  sudo tee {} <<'EOF'\n{}EOF",
            sources_path.display(),
            sources_content
        );
        eprintln!(
            "  sudo tee {} <<'EOF'\n{}EOF",
            auth_path.display(),
            auth_content
        );
        return Ok(());
    }

    let proceed = dialoguer::Confirm::new()
        .with_prompt("Write with sudo?")
        .default(false)
        .interact()
        .into_diagnostic()?;

    if !proceed {
        eprintln!("Skipped. Run the commands above manually.");
        return Ok(());
    }

    for (path, content, desc) in [
        (&sources_path, sources_content.as_str(), "sources list"),
        (&auth_path, auth_content.as_str(), "auth config"),
    ] {
        sudo_write(path, content)?;
        eprintln!("Wrote {desc}: {}", path.display());
    }

    eprintln!(
        "apt is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}
