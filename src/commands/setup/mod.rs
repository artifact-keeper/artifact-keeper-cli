mod merge;

use std::path::{Path, PathBuf};

use artifact_keeper_sdk::{ClientAuthExt, ClientRepositoriesExt};
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
    pub async fn execute(self, options: SetupOptions, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Auto => auto_detect(options, global).await,
            Self::Npm { repo } => setup_npm(repo.as_deref(), options, global).await,
            Self::Pip { repo } => setup_pip(repo.as_deref(), options, global).await,
            Self::Cargo { repo } => setup_cargo(repo.as_deref(), options, global).await,
            Self::Docker { repo } => setup_docker(repo.as_deref(), options, global).await,
            Self::Maven { repo } => setup_maven(repo.as_deref(), options, global).await,
            Self::Gradle { repo } => setup_gradle(repo.as_deref(), options, global).await,
            Self::Go { repo } => setup_go(repo.as_deref(), options, global).await,
            Self::Helm { repo } => setup_helm(repo.as_deref(), options, global).await,
            Self::Nuget { repo } => setup_nuget(repo.as_deref(), options, global).await,
            Self::Yum { repo } => setup_yum(repo.as_deref(), options, global).await,
            Self::Apt { repo } => setup_apt(repo.as_deref(), options, global).await,
        }
    }
}

struct DetectedEcosystem {
    name: &'static str,
    marker: &'static str,
}

const ECOSYSTEMS: &[DetectedEcosystem] = &[
    DetectedEcosystem {
        name: "npm",
        marker: "package.json",
    },
    DetectedEcosystem {
        name: "pip",
        marker: "pyproject.toml",
    },
    DetectedEcosystem {
        name: "pip",
        marker: "requirements.txt",
    },
    DetectedEcosystem {
        name: "pip",
        marker: "setup.py",
    },
    DetectedEcosystem {
        name: "cargo",
        marker: "Cargo.toml",
    },
    DetectedEcosystem {
        name: "docker",
        marker: "Dockerfile",
    },
    DetectedEcosystem {
        name: "docker",
        marker: "docker-compose.yml",
    },
    DetectedEcosystem {
        name: "maven",
        marker: "pom.xml",
    },
    DetectedEcosystem {
        name: "gradle",
        marker: "build.gradle",
    },
    DetectedEcosystem {
        name: "gradle",
        marker: "build.gradle.kts",
    },
    DetectedEcosystem {
        name: "go",
        marker: "go.mod",
    },
    DetectedEcosystem {
        name: "nuget",
        marker: "*.csproj",
    },
    DetectedEcosystem {
        name: "nuget",
        marker: "*.fsproj",
    },
    DetectedEcosystem {
        name: "helm",
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
            if let Ok(matches) = glob::glob(&dir.join(eco.marker).to_string_lossy())
                && matches.into_iter().any(|m| m.is_ok())
            {
                found.push(eco.name);
            }
        } else if dir.join(eco.marker).exists() {
            found.push(eco.name);
        }
    }
    found
}

/// How `setup` gets a credential that outlives the current login, and what it may
/// do to a file that's already there.
#[derive(clap::Args, Clone, Copy, Debug, Default)]
pub struct SetupOptions {
    /// Lifetime in days of the API token created for this package manager
    #[arg(
        long,
        global = true,
        default_value_t = DEFAULT_TOKEN_DAYS,
        value_parser = clap::value_parser!(u32).range(1..),
    )]
    pub token_days: u32,

    /// Write the current login's token instead of creating an API token. Login
    /// tokens expire soon, and the package manager stops working when this one does
    #[arg(long, global = true)]
    pub session_token: bool,

    /// Replace an existing Maven settings.xml or NuGet.Config that setup didn't
    /// write, keeping a backup. Without this, setup leaves such a file alone. npm,
    /// pip and Cargo files don't need it: setup changes only its own keys in them
    #[arg(long, global = true)]
    pub replace: bool,
}

/// Scopes of a token `setup` creates: package managers install and publish.
const CONFIG_TOKEN_SCOPES: [&str; 2] = ["read:artifacts", "write:artifacts"];
const DEFAULT_TOKEN_DAYS: u32 = 90;
/// A token with less life than this isn't fit to write into a config file. The
/// server's login tokens last about 30 minutes.
const SHORT_LIVED_SECS: i64 = 7 * 24 * 60 * 60;

/// Resolved setup context: what's needed to build URLs and write credentials.
struct SetupContext {
    repo_key: String,
    /// The instance URL with no trailing slash, scheme and port as configured.
    base_url: String,
    token: String,
    client: artifact_keeper_sdk::Client,
    options: SetupOptions,
    /// Names the package manager in the name of the token `setup` creates.
    tool: &'static str,
}

impl SetupContext {
    /// `{instance}/{prefix}/{repo}/`: format endpoints are mounted at the root
    /// of the server, not under `/api/v1`.
    fn format_url(&self, prefix: &str) -> String {
        format_url(&self.base_url, prefix, &self.repo_key)
    }

    fn is_plain_http(&self) -> bool {
        self.base_url.starts_with("http://")
    }

    /// `host` or `host:port`, for the tools that identify a server that way.
    fn host_and_port(&self) -> &str {
        host_from_url(&self.base_url)
    }

    /// True for plain HTTP to anything but this machine, which package managers
    /// treat as insecure.
    fn is_remote_http(&self) -> bool {
        crate::transport::classify_url(&self.base_url)
            == crate::transport::TransportSecurity::HttpRemote
    }

    /// The token to put in a file or hand to a package manager's own store.
    ///
    /// A config file is there for good and a login token lasts about 30 minutes,
    /// so writing one gives a config that silently stops working. A login token
    /// is swapped here for a dedicated API token, and each is named so it can be
    /// found and revoked by itself. A token that already lasts, such as an API
    /// token in `AK_TOKEN`, is used as it is.
    ///
    /// Call this only once the user has agreed to the write, so that declining
    /// leaves no credential behind.
    async fn token_for_config(&self) -> Result<String> {
        let now = chrono::Utc::now().timestamp();
        let Some(remaining) = token_lifetime(&self.token, now) else {
            return Ok(self.token.clone());
        };
        if remaining >= SHORT_LIVED_SECS {
            return Ok(self.token.clone());
        }
        if self.options.session_token {
            warn_short_lived(remaining);
            return Ok(self.token.clone());
        }

        let name = format!("ak-setup-{}-{}", self.tool, self.repo_key);
        let body = artifact_keeper_sdk::types::CreateApiTokenRequest {
            name: name.clone(),
            scopes: CONFIG_TOKEN_SCOPES.map(String::from).to_vec(),
            expires_in_days: Some(i64::from(self.options.token_days)),
            repo_selector: None,
        };
        match self.client.create_api_token().body(body).send().await {
            Ok(created) => {
                let expires = created
                    .expires_at
                    .map_or_else(|| "never".to_string(), |t| t.format("%Y-%m-%d").to_string());
                eprintln!(
                    "Created API token '{name}' for this configuration (expires: {expires}). \
                     Revoke it with: ak auth revoke-token {}",
                    created.id
                );
                Ok(created.into_inner().token)
            }
            // A config that works for 30 minutes passes every check at the time and
            // fails later, somewhere harder to trace, so nothing is written. Whoever
            // wants that can ask for it with --session-token.
            Err(e) => Err(AkError::SetupToken(e.to_string()).into()),
        }
    }
}

fn format_url(base_url: &str, prefix: &str, repo_key: &str) -> String {
    format!("{base_url}/{prefix}/{repo_key}/")
}

/// Seconds left on a token, or `None` if it isn't a JWT with an expiry. Tokens
/// that aren't JWTs are the server's API tokens.
fn token_lifetime(token: &str, now: i64) -> Option<i64> {
    super::helpers::decode_jwt_expiry(token).map(|exp| exp - now)
}

fn warn_short_lived(remaining: i64) {
    eprintln!(
        "Warning: this configuration uses your login token, which expires in about {} \
         minutes. The package manager will get 401 errors after that. Create a lasting \
         token with `ak auth token create` and put it in the configuration.",
        (remaining / 60).max(0)
    );
}

/// Resolve instance, credentials, and pick a repository for the given format.
async fn resolve_setup(
    tool: &'static str,
    format: &str,
    explicit_repo: Option<&str>,
    options: SetupOptions,
    global: &GlobalArgs,
) -> Result<SetupContext> {
    let (instance_name, instance, client) = authenticated_client(global)?;

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
                "No {format} repositories found. Create one with `ak repo create <key> --pkg-format {format}`"
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
        base_url: instance.url.trim_end_matches('/').to_string(),
        token: cred.access_token,
        client,
        options,
        tool,
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

    // Write through a symlink rather than replacing it, so a dotfile managed
    // elsewhere stays managed.
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

    if target.exists() {
        let existing = std::fs::read(&target).into_diagnostic()?;
        // Nothing is being replaced, so there's nothing to keep.
        if existing != content.as_bytes() {
            let backup = write_backup(&target, &existing)?;
            eprintln!("Backed up existing {} to {}", description, backup.display());
        }
    }

    // Owner-only from the moment the file exists: this content has a token in it.
    crate::config::write_private_atomic(&target, content.as_bytes())?;
    eprintln!("Wrote {}: {}", description, path.display());
    Ok(())
}

/// Keep a copy of a file about to be replaced, in a new file: `name.bak`, then
/// `name.bak.1` and so on. An earlier backup may be the only copy of what the user
/// had, so it's never overwritten, whichever process got there first.
///
/// The file may hold a token, so its backup is owner-only from creation, or
/// stricter if the original is.
fn write_backup(target: &Path, content: &[u8]) -> Result<PathBuf> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let original = std::fs::metadata(target).into_diagnostic()?;
        options.mode(original.permissions().mode() & 0o600);
    }

    for attempt in 0u32.. {
        let backup = match attempt {
            0 => target.with_extension("bak"),
            n => target.with_extension(format!("bak.{n}")),
        };
        let mut file = match options.open(&backup) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).into_diagnostic(),
        };
        // A partial backup would look like a good one, and the caller is about to
        // replace the original, so it stops here if this fails.
        if let Err(e) = file.write_all(content).and_then(|()| file.sync_all()) {
            let _ = std::fs::remove_file(&backup);
            return Err(e).into_diagnostic();
        }
        return Ok(backup);
    }
    Err(AkError::ConfigError(format!("No free backup name for {}", target.display())).into())
}

/// Stands in for the token in every config template, and is what the user sees
/// in a preview. Previews are built from the template, so they never hold the
/// token at all: nothing has to find it and remove it, and nothing can miss it.
const TOKEN_SLOT: &str = "****";

/// The bytes for disk: the template with the real token in the slot.
fn fill_token(template: &str, token: &str) -> String {
    template.replace(TOKEN_SLOT, token)
}

/// Encode a token for the userinfo part of a URL.
fn url_encode(token: &str) -> String {
    url::form_urlencoded::byte_serialize(token.as_bytes()).collect()
}

/// The `index-url` for `pip.conf`, keeping the instance's scheme and port.
fn pip_index_url(ctx: &SetupContext, token: &str) -> String {
    let index_url = format!("{}simple/", ctx.format_url("pypi"));
    let (scheme, rest) = index_url.split_once("://").unwrap_or(("https", &index_url));
    format!("{scheme}://__token__:{token}@{rest}")
}

/// pip refuses plain HTTP to anything but this machine unless it's told to trust
/// the host.
fn pip_trusted_host(ctx: &SetupContext) -> Option<&str> {
    ctx.is_remote_http().then(|| ctx.host_and_port())
}

/// Whether two paths are the same file, as a symlink from one to the other is.
fn same_file(a: &Path, b: &Path) -> bool {
    matches!(
        (std::fs::canonicalize(a), std::fs::canonicalize(b)),
        (Ok(a), Ok(b)) if a == b
    )
}

/// What a config file holds now, empty if it isn't there. A file that isn't text
/// can't be edited by key, so it's left alone.
fn read_existing(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(AkError::ConfigError(format!("Can't read {}: {e}", path.display())).into()),
    }
}

/// Refuse a file that `setup` can't safely add its settings to. A wrong guess here
/// would leave the tool broken with `setup` saying it's configured, so say what to
/// add. This comes before any prompt or token, so refusing costs nothing.
fn refuse_merge(path: &Path, reason: String, snippet: &str) -> miette::Report {
    eprintln!(
        "\n{} wasn't changed, because {reason}. To use Artifact Keeper, add this to it, with \
         a token from `ak auth token create` in place of {TOKEN_SLOT}:\n\n{snippet}",
        path.display()
    );
    AkError::SetupFileNotMerged(path.display().to_string(), reason).into()
}

/// Say which of the user's own settings a merge replaced. Only the key is named:
/// a value such as a URL can hold a password.
fn report_replaced(path: &Path, keys: &[&str]) {
    for key in keys {
        eprintln!(
            "{key} in {} had another value. setup replaced it, and the old value is in the backup.",
            path.display()
        );
    }
}

/// Maven and NuGet files are XML with no safe way to edit by key here, so `setup`
/// replaces one only if it wrote the file itself, or if it's told to. Otherwise
/// it says what to add. This comes before any prompt or token, so refusing costs
/// nothing.
fn check_replaceable(
    path: &Path,
    template: &str,
    url: &str,
    snippet: &str,
    options: SetupOptions,
) -> Result<()> {
    let existing = read_existing(path)?;
    if existing.is_empty()
        || options.replace
        || merge::is_generated(&existing, template, url, TOKEN_SLOT)
    {
        return Ok(());
    }
    eprintln!(
        "\n{} has settings setup didn't write, so it's unchanged. To use Artifact Keeper, add \
         this to it, with a token from `ak auth token create` in place of {TOKEN_SLOT}:\n\n{snippet}",
        path.display()
    );
    Err(AkError::SetupFileNotOurs(path.display().to_string()).into())
}

/// The `.netrc` line for Go module authentication, as a template.
fn go_netrc_line(host: &str) -> String {
    format!("machine {host} login __token__ password {TOKEN_SLOT}")
}

/// The yum/dnf `.repo` file, as a template.
fn yum_repo_file(repo_key: &str, yum_url: &str) -> String {
    format!(
        "[artifact-keeper-{repo_key}]\n\
         name=Artifact Keeper - {repo_key}\n\
         baseurl={yum_url}\n\
         enabled=1\n\
         gpgcheck=0\n\
         username=__token__\n\
         password={TOKEN_SLOT}\n"
    )
}

/// Show a config template and ask whether to write it.
fn confirm_write(path: &Path, template: &str, no_input: bool) -> Result<bool> {
    eprintln!("\nConfiguration to write to {}:\n", path.display());
    eprintln!("{template}");
    confirm_prompt(no_input)
}

/// `confirm_write` for a file that `setup` edits by key.
fn confirm_merge(path: &Path, template: &str, no_input: bool) -> Result<bool> {
    if !path.exists() {
        return confirm_write(path, template, no_input);
    }
    eprintln!(
        "\nSettings to set in {}. Everything else in the file stays:\n",
        path.display()
    );
    eprintln!("{template}");
    confirm_prompt(no_input)
}

fn confirm_prompt(no_input: bool) -> Result<bool> {
    if no_input {
        return Ok(true);
    }

    dialoguer::Confirm::new()
        .with_prompt("Write this configuration?")
        .default(true)
        .interact()
        .into_diagnostic()
}

/// Write content to a system path with `sudo install`, which creates the file
/// with its final mode. The content goes over stdin, so it's never on a command
/// line. `sudo tee` followed by `chmod` would leave a credential file readable
/// by everyone until the `chmod` ran.
fn sudo_write(path: &Path, content: &str, mode: &str) -> Result<()> {
    let status = std::process::Command::new("sudo")
        .args(["install", "-m", mode, "/dev/stdin", &path.to_string_lossy()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(content.as_bytes())?;
            }
            child.wait()
        })
        .into_diagnostic()?;

    if !status.success() {
        return Err(AkError::ConfigError(format!("Failed to write {}", path.display())).into());
    }

    Ok(())
}

/// Run a package manager's CLI with a secret on its stdin. A secret on the
/// command line would be readable through `ps` and /proc by every local user
/// for as long as the program runs.
fn run_with_secret_on_stdin(
    program: &str,
    args: &[&str],
    secret: &str,
) -> Result<std::process::ExitStatus> {
    std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(secret.as_bytes())?;
            }
            child.wait()
        })
        .into_diagnostic()
}

async fn auto_detect(options: SetupOptions, global: &GlobalArgs) -> Result<()> {
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

    // A file setup won't touch is one tool, and it shouldn't stop the others.
    let mut left_alone = None;
    for name in &detected {
        eprintln!("--- Setting up {name} ---");
        let outcome = match *name {
            "npm" => setup_npm(None, options, global).await,
            "pip" => setup_pip(None, options, global).await,
            "cargo" => setup_cargo(None, options, global).await,
            "docker" => setup_docker(None, options, global).await,
            "maven" => setup_maven(None, options, global).await,
            "gradle" => setup_gradle(None, options, global).await,
            "go" => setup_go(None, options, global).await,
            "helm" => setup_helm(None, options, global).await,
            "nuget" => setup_nuget(None, options, global).await,
            _ => Ok(()),
        };
        match outcome {
            Err(e)
                if matches!(
                    e.downcast_ref(),
                    Some(AkError::SetupFileNotOurs(_) | AkError::SetupFileNotMerged(..))
                ) =>
            {
                left_alone.get_or_insert(e);
            }
            other => other?,
        }
        eprintln!();
    }

    if let Some(e) = left_alone {
        eprintln!("The other tools are configured.");
        return Err(e);
    }
    eprintln!("All done! Your tools are configured.");
    Ok(())
}

async fn setup_npm(repo: Option<&str>, options: SetupOptions, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("npm", "npm", repo, options, global).await?;
    let npm_registry_url = ctx.format_url("npm");

    let auth_key = format!("//{}:_authToken", strip_protocol(&npm_registry_url));
    let npmrc_path = home_dir()?.join(".npmrc");
    let existing = read_existing(&npmrc_path)?;
    let preview = merge::npmrc("", &npm_registry_url, &auth_key, TOKEN_SLOT).text;

    if !confirm_merge(&npmrc_path, &preview, global.no_input)? {
        eprintln!("Skipped npm configuration.");
        return Ok(());
    }

    let token = ctx.token_for_config().await?;
    let merged = merge::npmrc(&existing, &npm_registry_url, &auth_key, &token);
    write_config_file(&npmrc_path, &merged.text, ".npmrc")?;
    report_replaced(&npmrc_path, &merged.replaced);
    eprintln!(
        "npm is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_pip(repo: Option<&str>, options: SetupOptions, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("pip", "pypi", repo, options, global).await?;
    let trusted_host = pip_trusted_host(&ctx);
    let slot_url = pip_index_url(&ctx, TOKEN_SLOT);
    let preview = merge::pip_conf("", &slot_url, trusted_host)
        .expect("an empty file can be merged")
        .text;

    let filename = if cfg!(windows) { "pip.ini" } else { "pip.conf" };
    let pip_conf_path = config_dir()?.join("pip").join(filename);
    let existing = read_existing(&pip_conf_path)?;
    merge::pip_conf(&existing, &slot_url, trusted_host)
        .map_err(|reason| refuse_merge(&pip_conf_path, reason, &preview))?;

    if !confirm_merge(&pip_conf_path, &preview, global.no_input)? {
        eprintln!("Skipped pip configuration.");
        return Ok(());
    }

    let token = ctx.token_for_config().await?;
    let index_url = pip_index_url(&ctx, &url_encode(&token));
    let merged = merge::pip_conf(&existing, &index_url, trusted_host)
        .map_err(|reason| refuse_merge(&pip_conf_path, reason, &preview))?;
    write_config_file(&pip_conf_path, &merged.text, "pip.conf")?;
    report_replaced(&pip_conf_path, &merged.replaced);
    eprintln!(
        "pip is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_cargo(repo: Option<&str>, options: SetupOptions, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("cargo", "cargo", repo, options, global).await?;
    // Sparse protocol: config.json and the index are served under this URL.
    let cargo_registry_url = format!("sparse+{}", ctx.format_url("cargo"));

    let cargo_home = std::env::var("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".cargo")
        });

    let config_path = cargo_home.join("config.toml");
    let creds_path = cargo_home.join("credentials.toml");
    let existing_config = read_existing(&config_path)?;
    let existing_creds = read_existing(&creds_path)?;
    let config_preview = merge::cargo_config("", &cargo_registry_url)
        .expect("an empty file can be merged")
        .text;
    let creds_preview =
        merge::cargo_credentials("", TOKEN_SLOT).expect("an empty file can be merged");

    // Cargo uses the old name if it's there, and ignores the file with the new one.
    for (legacy, snippet) in [("config", &config_preview), ("credentials", &creds_preview)] {
        let legacy = cargo_home.join(legacy);
        if tokio::fs::metadata(&legacy)
            .await
            .is_ok_and(|m| m.is_file())
            && !same_file(
                &legacy,
                &cargo_home.join(format!("{}.toml", legacy.display())),
            )
        {
            return Err(refuse_merge(
                &legacy,
                "Cargo reads it in preference to the file with .toml on its name".to_string(),
                snippet,
            ));
        }
    }

    // Both are checked before any prompt or token: neither file should change if
    // the other can't be merged.
    let config = merge::cargo_config(&existing_config, &cargo_registry_url)
        .map_err(|reason| refuse_merge(&config_path, reason, &config_preview))?;
    merge::cargo_credentials(&existing_creds, TOKEN_SLOT)
        .map_err(|reason| refuse_merge(&creds_path, reason, &creds_preview))?;

    eprintln!("Will write two files:");
    if !confirm_merge(&config_path, &config_preview, global.no_input)? {
        eprintln!("Skipped Cargo configuration.");
        return Ok(());
    }

    let write_credentials = confirm_merge(&creds_path, &creds_preview, global.no_input)?;
    // Before any write, so that no token leaves the existing files as they were.
    let token = if write_credentials {
        Some(ctx.token_for_config().await?)
    } else {
        None
    };

    // The credentials first. A token nothing uses yet does no harm if the next write
    // fails, but a default registry with no token breaks every cargo command.
    if let Some(token) = &token {
        let credentials = merge::cargo_credentials(&existing_creds, token)
            .map_err(|reason| refuse_merge(&creds_path, reason, &creds_preview))?;
        write_config_file(&creds_path, &credentials, "cargo credentials.toml")?;
    } else {
        eprintln!("Skipped Cargo credentials.");
    }
    write_config_file(&config_path, &config.text, "cargo config.toml")?;
    report_replaced(&config_path, &config.replaced);
    if token.is_none() {
        return Ok(());
    }
    eprintln!(
        "Cargo is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_docker(
    repo: Option<&str>,
    options: SetupOptions,
    global: &GlobalArgs,
) -> Result<()> {
    let ctx = resolve_setup("docker", "docker", repo, options, global).await?;
    // The registry is the instance's host and port. Docker reads a name without
    // a port as port 443, which isn't this server unless it's configured that way.
    let host = ctx.host_and_port().to_string();

    eprintln!("Running: docker login {host}");
    eprintln!(
        "Using token authentication for repository '{}'",
        ctx.repo_key
    );
    if ctx.is_plain_http() {
        eprintln!(
            "This instance uses plain HTTP. Docker only allows that for localhost, or for \
             {host} listed under insecure-registries in its daemon configuration."
        );
    }

    let token = ctx.token_for_config().await?;
    let status = run_with_secret_on_stdin(
        "docker",
        &["login", &host, "-u", "__token__", "--password-stdin"],
        &token,
    )?;

    if !status.success() {
        return Err(
            AkError::ConfigError("Docker login failed. Check your credentials.".into()).into(),
        );
    }

    eprintln!(
        "Docker login succeeded. Name images {host}/{}/<image>:<tag>.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_maven(repo: Option<&str>, options: SetupOptions, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("maven", "maven", repo, options, global).await?;
    let maven_url = ctx.format_url("maven");

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
      <password>{TOKEN_SLOT}</password>
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
"#
    );

    let settings_path = home_dir()?.join(".m2").join("settings.xml");
    let snippet = format!(
        r#"In <servers>:
    <server>
      <id>artifact-keeper</id>
      <username>__token__</username>
      <password>{TOKEN_SLOT}</password>
    </server>
In <profiles>:
    <profile>
      <id>artifact-keeper</id>
      <repositories>
        <repository>
          <id>artifact-keeper</id>
          <url>{maven_url}</url>
        </repository>
      </repositories>
    </profile>
In <activeProfiles>:
    <activeProfile>artifact-keeper</activeProfile>
"#
    );
    check_replaceable(
        &settings_path,
        &settings_content,
        &maven_url,
        &snippet,
        options,
    )?;

    if !confirm_write(&settings_path, &settings_content, global.no_input)? {
        eprintln!("Skipped Maven configuration.");
        return Ok(());
    }

    if ctx.is_remote_http() {
        eprintln!(
            "Maven 3.8.1 and newer block plain HTTP repositories other than localhost. \
             Use an https:// instance, or override the maven-default-http-blocker mirror."
        );
    }

    let token = ctx.token_for_config().await?;
    write_config_file(
        &settings_path,
        &fill_token(&settings_content, &token),
        "Maven settings.xml",
    )?;
    eprintln!(
        "Maven is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_gradle(
    repo: Option<&str>,
    options: SetupOptions,
    global: &GlobalArgs,
) -> Result<()> {
    let ctx = resolve_setup("gradle", "maven", repo, options, global).await?;
    let gradle_url = ctx.format_url("maven");
    // Gradle refuses http:// repositories unless told otherwise.
    let allow_http = if ctx.is_plain_http() {
        "\n            allowInsecureProtocol = true"
    } else {
        ""
    };

    let init_content = format!(
        r#"allprojects {{
    repositories {{
        maven {{
            url = uri("{gradle_url}"){allow_http}
            credentials {{
                username = "__token__"
                password = "{TOKEN_SLOT}"
            }}
        }}
    }}
}}
"#
    );

    let init_path = home_dir()?
        .join(".gradle")
        .join("init.d")
        .join("artifact-keeper.gradle");

    if !confirm_write(&init_path, &init_content, global.no_input)? {
        eprintln!("Skipped Gradle configuration.");
        return Ok(());
    }

    let token = ctx.token_for_config().await?;
    write_config_file(
        &init_path,
        &fill_token(&init_content, &token),
        "Gradle init script",
    )?;
    eprintln!(
        "Gradle is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_go(repo: Option<&str>, options: SetupOptions, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("go", "go", repo, options, global).await?;
    let goproxy_url = ctx.format_url("go");
    // The go command matches this against the host and port of the request.
    let host = ctx.host_and_port().to_string();

    eprintln!("Add the following to your shell profile (~/.bashrc, ~/.zshrc, etc.):\n");
    eprintln!("  export GOPROXY=\"{goproxy_url},direct\"");
    eprintln!("  export GONOSUMDB=\"<your private module prefixes, such as example.com/*>\"");
    eprintln!();

    if ctx.is_plain_http() {
        // Tested with go 1.24: it ignores .netrc for http:// and refuses
        // credentials in the GOPROXY URL.
        eprintln!(
            "This instance uses plain HTTP, and the go command only sends credentials over \
             HTTPS. It can read from this repository only if the repository allows anonymous \
             access, so no .netrc entry is needed. Use an https:// instance for a private one."
        );
        return Ok(());
    }

    let netrc_template = go_netrc_line(&host);
    let netrc_path = home_dir()?.join(".netrc");

    eprintln!(
        "For authentication, add this line to {}:",
        netrc_path.display()
    );
    eprintln!("  {netrc_template}");

    if global.no_input {
        return Ok(());
    }

    let write_netrc = dialoguer::Confirm::new()
        .with_prompt("Write this to .netrc now?")
        .default(true)
        .interact()
        .into_diagnostic()?;

    if write_netrc {
        let existing = read_existing(&netrc_path)?;
        merge::netrc(&existing, &host, &netrc_template)
            .map_err(|reason| refuse_merge(&netrc_path, reason, &netrc_template))?;
        let token = ctx.token_for_config().await?;
        let merged = merge::netrc(&existing, &host, &fill_token(&netrc_template, &token))
            .map_err(|reason| refuse_merge(&netrc_path, reason, &netrc_template))?;
        write_config_file(&netrc_path, &merged, ".netrc")?;
    }

    eprintln!("Go is configured to use repository '{}'.", ctx.repo_key);
    Ok(())
}

async fn setup_helm(repo: Option<&str>, options: SetupOptions, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("helm", "helm", repo, options, global).await?;
    let helm_url = ctx.format_url("helm");

    eprintln!("Running: helm repo add artifact-keeper {helm_url}");

    let token = ctx.token_for_config().await?;
    let status = run_with_secret_on_stdin(
        "helm",
        &[
            "repo",
            "add",
            "artifact-keeper",
            &helm_url,
            "--username",
            "__token__",
            "--password-stdin",
        ],
        &token,
    )?;

    if !status.success() {
        return Err(AkError::ConfigError("helm repo add failed".into()).into());
    }

    eprintln!("Helm repository added. Run `helm repo update` to fetch charts.");
    Ok(())
}

async fn setup_nuget(repo: Option<&str>, options: SetupOptions, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("nuget", "nuget", repo, options, global).await?;
    let nuget_url = format!("{}v3/index.json", ctx.format_url("nuget"));
    // NuGet 6.12 and newer refuse http:// sources unless the source allows it.
    let allow_http = if ctx.is_plain_http() {
        " allowInsecureConnections=\"true\""
    } else {
        ""
    };

    let nuget_config = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="ArtifactKeeper" value="{nuget_url}" protocolVersion="3"{allow_http} />
  </packageSources>
  <packageSourceCredentials>
    <ArtifactKeeper>
      <add key="Username" value="__token__" />
      <add key="ClearTextPassword" value="{TOKEN_SLOT}" />
    </ArtifactKeeper>
  </packageSourceCredentials>
</configuration>
"#
    );

    let config_path = if cfg!(windows) {
        config_dir()?.join("NuGet").join("NuGet.Config")
    } else {
        home_dir()?
            .join(".nuget")
            .join("NuGet")
            .join("NuGet.Config")
    };

    let snippet = format!(
        r#"In <packageSources>:
    <add key="ArtifactKeeper" value="{nuget_url}" protocolVersion="3"{allow_http} />
In <packageSourceCredentials>:
    <ArtifactKeeper>
      <add key="Username" value="__token__" />
      <add key="ClearTextPassword" value="{TOKEN_SLOT}" />
    </ArtifactKeeper>
"#
    );
    check_replaceable(&config_path, &nuget_config, &nuget_url, &snippet, options)?;

    if !confirm_write(&config_path, &nuget_config, global.no_input)? {
        eprintln!("Skipped NuGet configuration.");
        return Ok(());
    }

    let token = ctx.token_for_config().await?;
    write_config_file(
        &config_path,
        &fill_token(&nuget_config, &token),
        "nuget.config",
    )?;
    eprintln!(
        "NuGet is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_yum(repo: Option<&str>, options: SetupOptions, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("yum", "rpm", repo, options, global).await?;
    let yum_url = ctx.format_url("rpm");

    let repo_template = yum_repo_file(&ctx.repo_key, &yum_url);

    let repo_path = PathBuf::from(format!(
        "/etc/yum.repos.d/artifact-keeper-{}.repo",
        ctx.repo_key
    ));

    eprintln!(
        "This requires writing to {} (needs sudo).",
        repo_path.display()
    );
    eprintln!("\nConfiguration:\n{repo_template}");

    if global.no_input {
        eprintln!("Run the following command manually, with your token in place of ****:");
        eprintln!(
            "  sudo install -m 600 /dev/stdin {} <<'EOF'\n{}EOF",
            repo_path.display(),
            repo_template
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

    let token = ctx.token_for_config().await?;
    sudo_write(&repo_path, &fill_token(&repo_template, &token), "600")?;
    eprintln!(
        "yum/dnf is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

async fn setup_apt(repo: Option<&str>, options: SetupOptions, global: &GlobalArgs) -> Result<()> {
    let ctx = resolve_setup("apt", "debian", repo, options, global).await?;
    let apt_url = ctx.format_url("debian");
    // apt withholds credentials from plain HTTP unless the entry names the
    // protocol.
    let machine = if ctx.is_plain_http() {
        format!("http://{}", ctx.host_and_port())
    } else {
        ctx.host_and_port().to_string()
    };

    let sources_content = format!("deb [trusted=yes] {apt_url} stable main\n");
    let auth_template = format!(
        "machine {machine}\n\
         login __token__\n\
         password {TOKEN_SLOT}\n"
    );

    let sources_path = PathBuf::from(format!(
        "/etc/apt/sources.list.d/artifact-keeper-{}.list",
        ctx.repo_key
    ));
    let auth_path = PathBuf::from("/etc/apt/auth.conf.d/artifact-keeper.conf");

    eprintln!("This requires writing to /etc/apt/ (needs sudo).");
    eprintln!("\nSources list:\n{sources_content}");
    eprintln!("Auth config:\n{auth_template}");

    if global.no_input {
        eprintln!("Run the following commands manually, with your token in place of ****:");
        eprintln!(
            "  sudo install -m 644 /dev/stdin {} <<'EOF'\n{}EOF",
            sources_path.display(),
            sources_content
        );
        eprintln!(
            "  sudo install -m 600 /dev/stdin {} <<'EOF'\n{}EOF",
            auth_path.display(),
            auth_template
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

    let token = ctx.token_for_config().await?;
    let auth_content = fill_token(&auth_template, &token);
    for (path, content, desc, mode) in [
        (
            &sources_path,
            sources_content.as_str(),
            "sources list",
            "644",
        ),
        (&auth_path, auth_content.as_str(), "auth config", "600"),
    ] {
        sudo_write(path, content, mode)?;
        eprintln!("Wrote {desc}: {}", path.display());
    }

    eprintln!(
        "apt is now configured to use repository '{}'.",
        ctx.repo_key
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- strip_protocol ----

    #[test]
    fn strip_protocol_https() {
        assert_eq!(strip_protocol("https://example.com"), "example.com");
    }

    #[test]
    fn strip_protocol_http() {
        assert_eq!(strip_protocol("http://example.com"), "example.com");
    }

    #[test]
    fn strip_protocol_no_protocol() {
        assert_eq!(strip_protocol("example.com"), "example.com");
    }

    #[test]
    fn strip_protocol_with_path() {
        assert_eq!(
            strip_protocol("https://example.com/api/v1"),
            "example.com/api/v1"
        );
    }

    #[test]
    fn strip_protocol_with_port() {
        assert_eq!(
            strip_protocol("https://example.com:8080"),
            "example.com:8080"
        );
    }

    // ---- host_from_url ----

    #[test]
    fn host_from_url_basic() {
        assert_eq!(host_from_url("https://example.com"), "example.com");
    }

    #[test]
    fn host_from_url_with_path() {
        assert_eq!(
            host_from_url("https://example.com/api/v1/npm"),
            "example.com"
        );
    }

    #[test]
    fn host_from_url_with_port() {
        assert_eq!(
            host_from_url("https://example.com:8080/path"),
            "example.com:8080"
        );
    }

    #[test]
    fn host_from_url_no_protocol() {
        assert_eq!(host_from_url("example.com/path"), "example.com");
    }

    #[test]
    fn host_from_url_empty() {
        assert_eq!(host_from_url(""), "");
    }

    // ---- detect_ecosystems ----

    #[test]
    fn detect_ecosystems_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = detect_ecosystems(dir.path());
        assert!(result.is_empty());
    }

    #[test]
    fn detect_ecosystems_npm() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["npm"]);
    }

    #[test]
    fn detect_ecosystems_pip_pyproject() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pyproject.toml"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["pip"]);
    }

    #[test]
    fn detect_ecosystems_pip_requirements() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["pip"]);
    }

    #[test]
    fn detect_ecosystems_pip_setup_py() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("setup.py"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["pip"]);
    }

    #[test]
    fn detect_ecosystems_cargo() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["cargo"]);
    }

    #[test]
    fn detect_ecosystems_docker() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["docker"]);
    }

    #[test]
    fn detect_ecosystems_docker_compose() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("docker-compose.yml"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["docker"]);
    }

    #[test]
    fn detect_ecosystems_maven() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pom.xml"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["maven"]);
    }

    #[test]
    fn detect_ecosystems_gradle() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("build.gradle"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["gradle"]);
    }

    #[test]
    fn detect_ecosystems_gradle_kts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("build.gradle.kts"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["gradle"]);
    }

    #[test]
    fn detect_ecosystems_go() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("go.mod"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["go"]);
    }

    #[test]
    fn detect_ecosystems_nuget_csproj() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("MyApp.csproj"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["nuget"]);
    }

    #[test]
    fn detect_ecosystems_nuget_fsproj() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("MyApp.fsproj"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["nuget"]);
    }

    #[test]
    fn detect_ecosystems_helm() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Chart.yaml"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["helm"]);
    }

    #[test]
    fn detect_ecosystems_multiple() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "").unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["npm", "cargo", "docker"]);
    }

    #[test]
    fn detect_ecosystems_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        // Both pyproject.toml and requirements.txt → only one "pip"
        std::fs::write(dir.path().join("pyproject.toml"), "").unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["pip"]);
    }

    #[test]
    fn detect_ecosystems_deduplicates_docker() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), "").unwrap();
        std::fs::write(dir.path().join("docker-compose.yml"), "").unwrap();
        let result = detect_ecosystems(dir.path());
        assert_eq!(result, vec!["docker"]);
    }

    // ---- write_config_file ----

    #[test]
    fn write_config_file_creates_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.conf");
        write_config_file(&path, "content here", "test config").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "content here");
    }

    #[test]
    fn write_config_file_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deep").join("test.conf");
        write_config_file(&path, "nested content", "nested config").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "nested content");
    }

    #[test]
    fn write_config_file_backs_up_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.conf");

        std::fs::write(&path, "original").unwrap();
        write_config_file(&path, "updated", "config").unwrap();

        // New content written
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "updated");

        // Backup created
        let backup = dir.path().join("existing.bak");
        assert!(backup.exists());
        let backup_content = std::fs::read_to_string(&backup).unwrap();
        assert_eq!(backup_content, "original");
    }

    // ---- confirm_write ----

    #[test]
    fn confirm_write_no_input_returns_true() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.conf");
        let result = confirm_write(&path, "content", true).unwrap();
        assert!(result);
    }

    // ---- format_url ----

    #[test]
    fn format_urls_are_root_mounted_and_keep_scheme_and_port() {
        // Each of these got a 200 or 401 from a real 1.11.10 backend.
        assert_eq!(
            format_url("http://ak:8080", "pypi", "r"),
            "http://ak:8080/pypi/r/"
        );
        assert_eq!(
            format_url("https://ak.example.com", "debian", "r"),
            "https://ak.example.com/debian/r/"
        );
        assert!(!format_url("http://ak:8080", "npm", "r").contains("/api/"));
    }

    // ---- token_lifetime ----

    #[test]
    fn token_lifetime_is_none_for_an_api_token() {
        assert_eq!(token_lifetime("not-a-jwt", 1_700_000_000), None);
    }

    #[test]
    fn token_lifetime_counts_down_from_the_jwt_expiry() {
        use base64::Engine;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"exp":1700000000,"sub":"user"}"#);
        let jwt = format!("header.{payload}.signature");
        assert_eq!(token_lifetime(&jwt, 1_699_998_200), Some(1800));
    }

    // ---- fill_token ----

    #[test]
    fn fill_token_fills_every_slot() {
        let filled = fill_token(&format!("a={TOKEN_SLOT} b={TOKEN_SLOT}"), "tok");
        assert_eq!(filled, "a=tok b=tok");
    }

    #[cfg(unix)]
    #[test]
    fn write_config_file_is_owner_only_and_so_is_its_backup() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pip.conf");
        std::fs::write(&path, "old-token").unwrap();
        // The broad mode is the point: neither the new file nor the backup may inherit it.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap(); // NOSONAR

        write_config_file(&path, "new-token", "pip.conf").unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        let backup = dir.path().join("pip.bak");
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "old-token");
        assert_eq!(mode(&backup), 0o600);
    }

    #[test]
    fn write_config_file_never_overwrites_a_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pip.conf");
        std::fs::write(&path, "original").unwrap();

        write_config_file(&path, "second", "pip.conf").unwrap();
        write_config_file(&path, "third", "pip.conf").unwrap();
        write_config_file(&path, "fourth", "pip.conf").unwrap();

        let read = |name: &str| std::fs::read_to_string(dir.path().join(name)).unwrap();
        assert_eq!(read("pip.bak"), "original");
        assert_eq!(read("pip.bak.1"), "second");
        assert_eq!(read("pip.bak.2"), "third");
        assert_eq!(read("pip.conf"), "fourth");
    }

    #[test]
    fn write_config_file_leaves_a_backup_the_user_already_had() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pip.conf");
        std::fs::write(&path, "original").unwrap();
        std::fs::write(dir.path().join("pip.bak"), "the user's own").unwrap();

        write_config_file(&path, "new", "pip.conf").unwrap();

        let read = |name: &str| std::fs::read_to_string(dir.path().join(name)).unwrap();
        assert_eq!(read("pip.bak"), "the user's own");
        assert_eq!(read("pip.bak.1"), "original");
    }

    #[test]
    fn write_config_file_with_the_same_content_makes_no_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pip.conf");
        std::fs::write(&path, "same").unwrap();

        write_config_file(&path, "same", "pip.conf").unwrap();

        assert!(!dir.path().join("pip.bak").exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_config_file_backup_keeps_a_stricter_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pip.conf");
        std::fs::write(&path, "original").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();

        write_config_file(&path, "new", "pip.conf").unwrap();

        let mode = std::fs::metadata(dir.path().join("pip.bak"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o400);
    }

    #[cfg(unix)]
    #[test]
    fn write_config_file_writes_through_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("dotfiles-npmrc");
        std::fs::write(&real, "old").unwrap();
        let link = dir.path().join(".npmrc");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        write_config_file(&link, "new", ".npmrc").unwrap();

        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "new");
    }

    // ---- templates hold no token, and filling one in gives the real file ----

    #[test]
    fn go_netrc_line_is_a_template() {
        let token = "unit-test-token-1234";
        let template = go_netrc_line("example.com");
        assert_eq!(
            template,
            "machine example.com login __token__ password ****"
        );
        assert_eq!(
            fill_token(&template, token),
            format!("machine example.com login __token__ password {token}")
        );
    }

    #[test]
    fn yum_repo_file_is_a_template() {
        let token = "unit-test-token-1234";
        let template = yum_repo_file("rpm-local", "https://ak.example.com/rpm/rpm-local/");
        assert!(template.contains("password=****"));
        assert!(template.contains("[artifact-keeper-rpm-local]"));
        assert!(template.contains("baseurl=https://ak.example.com/rpm/rpm-local/"));
        assert!(fill_token(&template, token).contains(&format!("password={token}")));
    }

    // ---- DetectedEcosystem struct ----

    #[test]
    fn ecosystems_constant_has_entries() {
        assert!(!ECOSYSTEMS.is_empty());
        assert!(ECOSYSTEMS.len() >= 14);
    }

    #[test]
    fn ecosystems_all_have_names() {
        for eco in ECOSYSTEMS {
            assert!(!eco.name.is_empty());
            assert!(!eco.marker.is_empty());
        }
    }
}
