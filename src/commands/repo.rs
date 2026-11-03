use artifact_keeper_sdk::ClientRepositoriesExt;
use clap::{Args, Subcommand};
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use futures::StreamExt;
use miette::{IntoDiagnostic, Result};

use super::client::{client_for, client_for_optional_auth};
use super::helpers::{
    confirm_action, emit_mutation, emit_mutation_raw, new_table, parse_json_arg, raw_err,
    read_inline_or_file, refuse_flags_before_1_11, resolve_secret, sdk_err,
};
use super::repo_settings::{
    self, AllowlistCommand, EgressProxyCommand, NpmScopePolicyCommand, UpstreamFilterCommand,
};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum RepoCommand {
    /// List repositories (filtered by your permissions)
    List {
        /// Filter by package format (npm, pypi, maven, docker, etc.)
        #[arg(long = "pkg-format", id = "pkg_format")]
        pkg_format: Option<String>,

        /// Filter by repository type (local, remote, virtual)
        #[arg(long, name = "type")]
        repo_type: Option<String>,

        /// Search by name
        #[arg(long)]
        search: Option<String>,

        /// Only repositories in this project (ID)
        #[arg(long)]
        project: Option<uuid::Uuid>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "50")]
        per_page: i32,
    },

    /// Show repository details
    Show {
        /// Repository key
        key: String,
    },

    /// Create a new repository
    Create {
        /// Repository key (URL slug)
        key: String,

        /// Package format. On a 1.11 server: alpine, ansible, bazel, cargo, chef, cocoapods, composer, conan, conda, conda_native, cran, debian, generic, gitlfs, go, helm, hex, huggingface, incus, jetbrains, maven, mlmodel, npm, nuget, oci, opkg, p2, pacman, protobuf, pub, puppet, pypi, rpm, rubygems, sbt, swift, terraform, vagrant, vscode. `ak admin formats list` shows your server's
        #[arg(long = "pkg-format", id = "pkg_format_create", value_name = "FORMAT")]
        pkg_format: String,

        /// Repository type: local, remote, virtual or staging. `proxy` means
        /// `remote` and `hosted` means `local`
        #[arg(long, default_value = "local")]
        repo_type: String,

        /// Display name (defaults to the key)
        #[arg(long)]
        name: Option<String>,

        /// Upstream URL
        #[arg(long, default_value = None, required_if_eq_any([("repo_type", "remote"), ("repo_type", "proxy")]))]
        upstream_url: Option<String>,

        /// Description
        #[arg(long)]
        description: Option<String>,

        /// Make repository public
        #[arg(long, default_value = None)]
        public: bool,

        /// Allow anonymous (unauthenticated) downloads (true/false)
        #[arg(long = "allow-anonymous")]
        allow_anonymous: Option<bool>,

        /// Restrict this repository to receive artifacts via promotion only (true/false)
        #[arg(long = "promotion-only")]
        promotion_only: Option<bool>,

        /// Storage quota in bytes
        #[arg(long = "quota-bytes")]
        quota_bytes: Option<i64>,

        /// Cargo index upstream URL (remote repos)
        #[arg(long = "index-upstream-url")]
        index_upstream_url: Option<String>,

        /// PyPI simple-index prefix ("" for flat CDN, "simple" for PEP 503 default)
        #[arg(long = "pypi-upstream-index-path")]
        pypi_upstream_index_path: Option<String>,

        /// Custom format key for a WASM plugin format handler
        #[arg(long = "format-key")]
        format_key: Option<String>,

        /// Member of a virtual repository, as `key` or `key=priority` (repeatable)
        #[arg(long = "member")]
        members: Vec<String>,

        /// Storage backend, instead of the server's default
        #[arg(long = "storage-backend")]
        storage_backend: Option<String>,

        /// Upstream auth type (basic or bearer)
        #[arg(long = "upstream-auth-type")]
        upstream_auth_type: Option<String>,

        /// Username for upstream basic auth
        #[arg(long = "upstream-username")]
        upstream_username: Option<String>,

        /// Password or token for upstream auth. Prefer --upstream-password-stdin
        #[arg(long = "upstream-password")]
        upstream_password: Option<String>,

        /// Read the upstream password or token from stdin
        #[arg(long = "upstream-password-stdin", conflicts_with = "upstream_password")]
        upstream_password_stdin: bool,

        #[command(flatten)]
        settings: RepoSettingsArgs,
    },

    /// Delete a repository. From backend 1.12.0 the server runs this as a
    /// background job and answers with its ID
    Delete {
        /// Repository key
        key: String,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,

        /// Wait for a background deletion to finish
        #[arg(long)]
        wait: bool,

        /// How long --wait waits, in seconds
        #[arg(long = "wait-timeout", default_value = "1800", requires = "wait")]
        wait_timeout: u64,
    },

    /// Interactively browse artifacts in a repository
    Browse {
        /// Repository key
        key: String,
    },

    /// Update repository settings (partial; only provided fields are changed)
    Update {
        /// Repository key
        key: String,

        /// New repository key (rename the URL slug)
        #[arg(long = "new-key")]
        new_key: Option<String>,

        /// Display name
        #[arg(long)]
        name: Option<String>,

        /// Description
        #[arg(long)]
        description: Option<String>,

        /// Public visibility (true/false)
        #[arg(long)]
        public: Option<bool>,

        /// Allow anonymous (unauthenticated) downloads (true/false)
        #[arg(long = "allow-anonymous")]
        allow_anonymous: Option<bool>,

        /// Restrict this repository to receive artifacts via promotion only (true/false)
        #[arg(long = "promotion-only")]
        promotion_only: Option<bool>,

        /// Storage quota in bytes (0 or negative clears the quota server-side)
        #[arg(long = "quota-bytes")]
        quota_bytes: Option<i64>,

        /// Hold newly uploaded artifacts until scanned (true/false)
        #[arg(long = "quarantine-enabled")]
        quarantine_enabled: Option<bool>,

        /// Quarantine hold duration in minutes
        #[arg(long = "quarantine-duration-minutes")]
        quarantine_duration_minutes: Option<i64>,

        /// Cargo index upstream URL (remote repos)
        #[arg(long = "index-upstream-url")]
        index_upstream_url: Option<String>,

        /// PyPI simple-index prefix ("" for flat CDN, "simple" for PEP 503 default)
        #[arg(long = "pypi-upstream-index-path")]
        pypi_upstream_index_path: Option<String>,

        /// Link this staging repo to a release repo by key ("" removes the link)
        #[arg(long = "release-repository-key")]
        release_repository_key: Option<String>,

        /// Replace the upstream URL (remote repos)
        #[arg(long = "upstream-url")]
        upstream_url: Option<String>,

        /// Enforce curation rules on this repository's proxy paths (true/false)
        #[arg(long = "curation-enabled")]
        curation_enabled: Option<bool>,

        /// Curation action when no rule matches: allow or review
        #[arg(long = "curation-default-action")]
        curation_default_action: Option<String>,

        /// Serve a partial merge when a virtual member's metadata can't be read (true/false)
        #[arg(long = "virtual-metadata-partial")]
        virtual_metadata_partial: Option<bool>,

        /// Take the repository out of its project
        #[arg(long = "clear-project", conflicts_with = "project_id")]
        clear_project: bool,

        /// Remove the trusted upstream OpenPGP key
        #[arg(long = "clear-trusted-gpg-key", conflicts_with = "trusted_gpg_key")]
        clear_trusted_gpg_key: bool,

        #[command(flatten)]
        settings: RepoSettingsArgs,
    },

    /// Manage virtual-repository members
    Members {
        #[command(subcommand)]
        command: MembersCommand,
    },

    /// Manage remote-repository routing rules (path rewrites)
    RoutingRules {
        #[command(subcommand)]
        command: RoutingRulesCommand,
    },

    /// Manage the proxy cache of a remote repository
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },

    /// Manage PEP 708 PyPI `tracks` declarations
    PypiTracks {
        #[command(subcommand)]
        command: PypiTracksCommand,
    },

    /// Manage the package allowlist of a virtual conda repository
    Allowlist {
        #[command(subcommand)]
        command: AllowlistCommand,
    },

    /// Manage which paths a remote repository may fetch from its upstream
    UpstreamFilter {
        #[command(subcommand)]
        command: UpstreamFilterCommand,
    },

    /// Manage the outbound proxy of a remote repository
    EgressProxy {
        #[command(subcommand)]
        command: EgressProxyCommand,
    },

    /// Manage which npm names can resolve through a remote repository
    NpmScopePolicy {
        #[command(subcommand)]
        command: NpmScopePolicyCommand,
    },

    /// Show what this server's repositories support
    Capabilities,

    /// Show a repository's storage use, deduplicated
    Storage {
        /// Repository key
        key: String,

        /// Show use per folder rather than the totals
        #[arg(long)]
        tree: bool,

        /// Folder to start from
        #[arg(long, requires = "tree")]
        prefix: Option<String>,

        /// How many folder levels to show below the start
        #[arg(long, requires = "tree")]
        depth: Option<i32>,

        /// The most folders to list
        #[arg(long, requires = "tree")]
        limit: Option<i64>,
    },

    /// Delete a repository's unreferenced storage objects
    StorageGc {
        /// Repository key
        key: String,

        /// Report what would be deleted, without deleting it
        #[arg(long)]
        dry_run: bool,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Set or remove upstream auth for a remote repository
    UpstreamAuth {
        /// Repository key
        key: String,

        /// Auth type: basic, bearer, aws_ecr, aws_codeartifact, or none (removes stored auth)
        #[arg(long = "type", name = "type")]
        auth_type: String,

        /// Username (basic auth)
        #[arg(long)]
        username: Option<String>,

        /// Password (basic) or token (bearer); prompted if omitted for basic/bearer
        #[arg(long)]
        password: Option<String>,

        /// Read the password or token from stdin
        #[arg(long = "password-stdin", conflicts_with = "password")]
        password_stdin: bool,

        /// Provider settings for aws_ecr and aws_codeartifact, as JSON text, @file
        /// or @-: `{region, domain, domain_owner, duration_seconds, registry_id}`
        #[arg(long)]
        aws: Option<String>,

        /// Accept upstream credentials on a public repository (true/false)
        #[arg(long = "allow-public-with-upstream-credentials")]
        allow_public_with_upstream_credentials: Option<bool>,
    },

    /// Test connectivity to a remote repository's upstream URL
    TestUpstream {
        /// Repository key
        key: String,
    },

    /// Browse the artifact tree of a repository
    Tree {
        /// Repository key
        key: String,

        /// Path prefix to browse within the repository
        #[arg(long)]
        path: Option<String>,

        /// Include per-node metadata (size, timestamps)
        #[arg(long)]
        metadata: bool,
    },

    /// Print the raw content of an artifact by path
    Cat {
        /// Repository key
        key: String,

        /// Full artifact path within the repository
        path: String,

        /// Maximum number of bytes to fetch (truncates the response)
        #[arg(long = "max-bytes")]
        max_bytes: Option<i64>,
    },
}

/// Settings `repo create` and `repo update` have in common.
#[derive(Args, Debug, Default)]
pub struct RepoSettingsArgs {
    /// Who can read before any grant is consulted: public, internal or private
    #[arg(long, value_parser = ["public", "internal", "private"])]
    visibility: Option<String>,

    /// Accept a public repository that carries upstream credentials (true/false)
    #[arg(long = "allow-public-with-upstream-credentials")]
    allow_public_with_upstream_credentials: Option<bool>,

    /// Project to assign this repository to (ID)
    #[arg(long = "project-id")]
    project_id: Option<uuid::Uuid>,

    /// Append immutable revisions on upload (Generic and ML model repos; true/false)
    #[arg(long = "versioning-enabled")]
    versioning_enabled: Option<bool>,

    /// Metadata root directory depth (local RPM repos)
    #[arg(long = "repodata-depth")]
    repodata_depth: Option<i32>,

    /// User-Agent for requests to the upstream ("" removes it on update)
    #[arg(long = "custom-user-agent")]
    custom_user_agent: Option<String>,

    /// Trusted upstream OpenPGP public key for RPM curation: armored text, @file or @-
    #[arg(long = "trusted-gpg-key")]
    trusted_gpg_key: Option<String>,

    /// Ingest unverified upstream metadata on keyless RPM curation sync (true/false)
    #[arg(long = "curation-allow-unverified")]
    curation_allow_unverified: Option<bool>,

    /// Debian remote settings: JSON text, @file or @-
    #[arg(long)]
    debian: Option<String>,

    /// Origin field of Debian/APT Release files
    #[arg(long = "apt-origin")]
    apt_origin: Option<String>,

    /// Label field of Debian/APT Release files
    #[arg(long = "apt-label")]
    apt_label: Option<String>,

    /// Description field of Debian/APT Release files
    #[arg(long = "apt-description")]
    apt_description: Option<String>,

    /// Version field of Debian/APT Release files
    #[arg(long = "apt-release-version")]
    apt_release_version: Option<String>,

    /// Allowed npm @scopes, comma separated ("" clears them on update)
    #[arg(long = "npm-allowed-scopes", value_delimiter = ',')]
    npm_allowed_scopes: Option<Vec<String>>,

    /// Allowed npm full-name globs, comma separated ("" clears them on update)
    #[arg(long = "npm-allowed-name-patterns", value_delimiter = ',')]
    npm_allowed_name_patterns: Option<Vec<String>>,

    /// Let unscoped npm names resolve through this remote (true/false)
    #[arg(long = "npm-allow-unscoped")]
    npm_allow_unscoped: Option<bool>,

    /// npm virtual isolate mode: a hosted member's name is served only from
    /// hosted members (true/false)
    #[arg(long = "npm-virtual-isolate-hosted-names")]
    npm_virtual_isolate_hosted_names: Option<bool>,

    /// Cross-origin OCI Bearer token realms to trust, comma separated ("" clears them on update)
    #[arg(long = "oci-trusted-bearer-realms", value_delimiter = ',')]
    oci_trusted_bearer_realms: Option<Vec<String>>,
}

impl RepoSettingsArgs {
    /// The flags set here that a server before 1.11 silently drops.
    fn flags_needing_1_11(&self) -> Vec<&'static str> {
        [
            ("--visibility", self.visibility.is_some()),
            (
                "--allow-public-with-upstream-credentials",
                self.allow_public_with_upstream_credentials.is_some(),
            ),
            ("--repodata-depth", self.repodata_depth.is_some()),
            (
                "--npm-virtual-isolate-hosted-names",
                self.npm_virtual_isolate_hosted_names.is_some(),
            ),
            (
                "--oci-trusted-bearer-realms",
                self.oci_trusted_bearer_realms.is_some(),
            ),
        ]
        .into_iter()
        .filter_map(|(flag, set)| set.then_some(flag))
        .collect()
    }
}

/// A create or update request: the fields given, plus the ones from
/// [`RepoSettingsArgs`], which the two requests name the same way.
macro_rules! with_settings {
    ($request:ident, $settings:ident, $debian:ident, { $($fields:tt)* }) => {
        artifact_keeper_sdk::types::$request {
            $($fields)*
            visibility: parse_visibility($settings.visibility)?,
            allow_public_with_upstream_credentials: $settings
                .allow_public_with_upstream_credentials,
            project_id: $settings.project_id,
            versioning_enabled: $settings.versioning_enabled,
            repodata_depth: $settings.repodata_depth,
            custom_user_agent: $settings.custom_user_agent,
            trusted_gpg_key: trusted_key($settings.trusted_gpg_key)?,
            curation_allow_unverified: $settings.curation_allow_unverified,
            debian: $debian,
            apt_origin: $settings.apt_origin,
            apt_label: $settings.apt_label,
            apt_description: $settings.apt_description,
            apt_release_version: $settings.apt_release_version,
            npm_allowed_scopes: list_flag($settings.npm_allowed_scopes),
            npm_allowed_name_patterns: list_flag($settings.npm_allowed_name_patterns),
            npm_allow_unscoped: $settings.npm_allow_unscoped,
            npm_virtual_isolate_hosted_names: $settings.npm_virtual_isolate_hosted_names,
            oci_trusted_bearer_realms: list_flag($settings.oci_trusted_bearer_realms),
        }
    };
}

/// A list flag's values, with `""` meaning an empty list.
fn list_flag(values: Option<Vec<String>>) -> Option<Vec<String>> {
    values.map(|v| v.into_iter().filter(|s| !s.is_empty()).collect())
}

fn parse_visibility(
    value: Option<String>,
) -> Result<Option<artifact_keeper_sdk::types::RepositoryVisibility>> {
    value
        .map(|v| {
            v.parse()
                .map_err(|e| AkError::Usage(format!("Invalid --visibility: {e}")).into())
        })
        .transpose()
}

/// The text of an armored key given inline, as `@file` or as `@-`.
fn trusted_key(value: Option<String>) -> Result<Option<String>> {
    value
        .map(|v| {
            let bytes = read_inline_or_file(&v, "--trusted-gpg-key")?;
            String::from_utf8(bytes)
                .map_err(|_| AkError::Usage("--trusted-gpg-key: the key isn't text".into()).into())
        })
        .transpose()
}

/// The repository type the API calls this. It says `remote` where a user might
/// say `proxy`, and rejects `proxy` outright (#154).
fn api_repo_type(repo_type: &str) -> &str {
    match repo_type {
        "proxy" => "remote",
        other => other,
    }
}

/// `key` or `key=priority`, as a virtual repository member at creation.
fn parse_member(entry: &str) -> Result<artifact_keeper_sdk::types::CreateVirtualMemberInput> {
    let (repo_key, priority) = match entry.split_once('=') {
        Some((key, priority)) => {
            let priority = priority
                .parse()
                .map_err(|_| AkError::Usage(format!("Invalid priority in --member '{entry}'")))?;
            (key, Some(priority))
        }
        None => (entry, None),
    };
    Ok(artifact_keeper_sdk::types::CreateVirtualMemberInput {
        repo_key: repo_key.to_string(),
        priority,
    })
}

/// Virtual-repository member management.
#[derive(Subcommand)]
pub enum MembersCommand {
    /// List members of a virtual repository
    List {
        /// Repository key
        key: String,
    },

    /// Add a member repository to a virtual repository
    Add {
        /// Virtual repository key
        key: String,

        /// Member repository key to add
        member_key: String,

        /// Resolution priority (lower wins first)
        #[arg(long)]
        priority: Option<i32>,
    },

    /// Remove a member repository from a virtual repository
    Remove {
        /// Virtual repository key
        key: String,

        /// Member repository key to remove
        member_key: String,
    },

    /// Reorder all members by priority (bulk). Each entry is `member_key=priority`.
    Reorder {
        /// Virtual repository key
        key: String,

        /// Member priorities as `member_key=priority` (repeatable)
        #[arg(required = true)]
        members: Vec<String>,
    },
}

/// Remote-repository routing-rule management.
#[derive(Subcommand)]
pub enum RoutingRulesCommand {
    /// Show the routing rules for a repository
    Get {
        /// Repository key
        key: String,
    },

    /// Replace the routing rules for a repository. Each rule is `pattern=>rewrite`.
    Set {
        /// Repository key
        key: String,

        /// Routing rule as `<regex-pattern>=><rewrite-template>` (repeatable)
        #[arg(long = "rule", required = true)]
        rules: Vec<String>,
    },

    /// Delete all routing rules for a repository
    Delete {
        /// Repository key
        key: String,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

/// Proxy-cache management for remote repositories.
#[derive(Subcommand)]
pub enum CacheCommand {
    /// Show the proxy cache TTL for a repository
    GetTtl {
        /// Repository key
        key: String,
    },

    /// Set the proxy cache TTL (in seconds) for a repository
    SetTtl {
        /// Repository key
        key: String,

        /// Cache TTL in seconds
        seconds: i64,
    },

    /// Invalidate a single cached artifact entry
    Invalidate {
        /// Repository key
        key: String,

        /// Artifact path to evict from the proxy cache
        path: String,
    },
}

/// PEP 708 PyPI `tracks` declaration management.
#[derive(Subcommand)]
pub enum PypiTracksCommand {
    /// List `tracks` declarations on a repository
    List {
        /// Repository key
        key: String,
    },

    /// Declare (upsert) that a local project tracks an upstream one
    Set {
        /// Repository key
        key: String,

        /// Local project name (PEP 503 normalized server-side)
        project: String,

        /// Upstream Simple index project URL this project tracks
        #[arg(long = "tracks-url")]
        tracks_url: String,
    },

    /// Remove a `tracks` declaration, restoring local-precedence isolation
    Remove {
        /// Repository key
        key: String,

        /// Local project name (PEP 503 normalized server-side)
        project: String,
    },
}

impl RepoCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List {
                pkg_format,
                repo_type,
                search,
                project,
                page,
                per_page,
            } => {
                list_repos(
                    pkg_format.as_deref(),
                    repo_type.as_deref(),
                    search.as_deref(),
                    project,
                    page,
                    per_page,
                    global,
                )
                .await
            }
            Self::Show { key } => show_repo(&key, global).await,
            Self::Create {
                key,
                pkg_format,
                repo_type,
                name,
                upstream_url,
                description,
                public,
                allow_anonymous,
                promotion_only,
                quota_bytes,
                index_upstream_url,
                pypi_upstream_index_path,
                format_key,
                members,
                storage_backend,
                upstream_auth_type,
                upstream_username,
                upstream_password,
                upstream_password_stdin,
                settings,
            } => {
                refuse_flags_before_1_11(&settings.flags_needing_1_11(), global).await?;
                let upstream_password = resolve_secret(
                    upstream_password,
                    upstream_password_stdin,
                    "--upstream-password",
                    None,
                    global.no_input,
                )?;
                let member_repos = members
                    .iter()
                    .map(|m| parse_member(m))
                    .collect::<Result<Vec<_>>>()?;
                let debian = settings
                    .debian
                    .as_deref()
                    .map(|v| parse_json_arg(v, "--debian"))
                    .transpose()?;
                let body = with_settings!(CreateRepositoryRequest, settings, debian, {
                    name: name.unwrap_or_else(|| key.clone()),
                    key,
                    format: pkg_format,
                    repo_type: api_repo_type(&repo_type).to_string(),
                    upstream_url,
                    description,
                    // Only when asked for: `false` next to --visibility is a contradiction.
                    is_public: public.then_some(true),
                    allow_anonymous_access: allow_anonymous,
                    promotion_only,
                    quota_bytes,
                    index_upstream_url,
                    pypi_upstream_index_path,
                    format_key,
                    member_repos: (!member_repos.is_empty()).then_some(member_repos),
                    storage_backend,
                    upstream_auth_type,
                    upstream_username,
                    upstream_password,
                });
                create_repo(body, global).await
            }
            Self::Delete {
                key,
                yes,
                wait,
                wait_timeout,
            } => delete_repo(&key, yes, wait.then_some(wait_timeout), global).await,
            Self::Browse { key } => browse_repo(&key, global).await,
            Self::Update {
                key,
                new_key,
                name,
                description,
                public,
                allow_anonymous,
                promotion_only,
                quota_bytes,
                quarantine_enabled,
                quarantine_duration_minutes,
                index_upstream_url,
                pypi_upstream_index_path,
                release_repository_key,
                upstream_url,
                curation_enabled,
                curation_default_action,
                virtual_metadata_partial,
                clear_project,
                clear_trusted_gpg_key,
                settings,
            } => {
                let debian = settings
                    .debian
                    .as_deref()
                    .map(|v| parse_json_arg(v, "--debian"))
                    .transpose()?;
                let mut needs_1_11 = settings.flags_needing_1_11();
                for (flag, set) in [
                    ("--upstream-url", upstream_url.is_some()),
                    (
                        "--virtual-metadata-partial",
                        virtual_metadata_partial.is_some(),
                    ),
                    ("--clear-project", clear_project),
                ] {
                    if set {
                        needs_1_11.push(flag);
                    }
                }
                refuse_flags_before_1_11(&needs_1_11, global).await?;
                let clear = [
                    ("project_id", clear_project),
                    ("trusted_gpg_key", clear_trusted_gpg_key),
                ]
                .into_iter()
                .filter_map(|(field, on)| on.then_some(field))
                .collect::<Vec<_>>();
                update_repo(
                    &key,
                    with_settings!(UpdateRepositoryRequest, settings, debian, {
                        key: new_key,
                        name,
                        description,
                        is_public: public,
                        allow_anonymous_access: allow_anonymous,
                        promotion_only,
                        quota_bytes,
                        quarantine_enabled,
                        quarantine_duration_minutes,
                        index_upstream_url,
                        pypi_upstream_index_path,
                        release_repository_key,
                        upstream_url,
                        curation_enabled,
                        curation_default_action,
                        virtual_metadata_partial,
                    }),
                    &clear,
                    global,
                )
                .await
            }
            Self::Members { command } => match command {
                MembersCommand::List { key } => list_members(&key, global).await,
                MembersCommand::Add {
                    key,
                    member_key,
                    priority,
                } => add_member(&key, &member_key, priority, global).await,
                MembersCommand::Remove { key, member_key } => {
                    remove_member(&key, &member_key, global).await
                }
                MembersCommand::Reorder { key, members } => {
                    reorder_members(&key, &members, global).await
                }
            },
            Self::RoutingRules { command } => match command {
                RoutingRulesCommand::Get { key } => get_routing_rules(&key, global).await,
                RoutingRulesCommand::Set { key, rules } => {
                    set_routing_rules(&key, &rules, global).await
                }
                RoutingRulesCommand::Delete { key, yes } => {
                    delete_routing_rules(&key, yes, global).await
                }
            },
            Self::Cache { command } => match command {
                CacheCommand::GetTtl { key } => get_cache_ttl(&key, global).await,
                CacheCommand::SetTtl { key, seconds } => set_cache_ttl(&key, seconds, global).await,
                CacheCommand::Invalidate { key, path } => {
                    invalidate_cache(&key, &path, global).await
                }
            },
            Self::PypiTracks { command } => match command {
                PypiTracksCommand::List { key } => list_pypi_tracks(&key, global).await,
                PypiTracksCommand::Set {
                    key,
                    project,
                    tracks_url,
                } => put_pypi_track(&key, &project, &tracks_url, global).await,
                PypiTracksCommand::Remove { key, project } => {
                    delete_pypi_track(&key, &project, global).await
                }
            },
            Self::UpstreamAuth {
                key,
                auth_type,
                username,
                password,
                password_stdin,
                aws,
                allow_public_with_upstream_credentials,
            } => {
                if allow_public_with_upstream_credentials.is_some() {
                    refuse_flags_before_1_11(&["--allow-public-with-upstream-credentials"], global)
                        .await?;
                }
                let needs_secret = matches!(auth_type.as_str(), "basic" | "bearer");
                let password = resolve_secret(
                    password,
                    password_stdin,
                    "--password",
                    needs_secret.then_some("Upstream password/token"),
                    global.no_input,
                )?;
                let aws = aws
                    .as_deref()
                    .map(|v| parse_json_arg(v, "--aws"))
                    .transpose()?;
                let body = artifact_keeper_sdk::types::UpstreamAuthRequest {
                    auth_type,
                    username,
                    password,
                    allow_public_with_upstream_credentials,
                    aws,
                };
                set_upstream_auth(&key, body, global).await
            }
            Self::Allowlist { command } => command.execute(global).await,
            Self::UpstreamFilter { command } => command.execute(global).await,
            Self::EgressProxy { command } => command.execute(global).await,
            Self::NpmScopePolicy { command } => command.execute(global).await,
            Self::Capabilities => repo_settings::capabilities(global).await,
            Self::Storage {
                key,
                tree,
                prefix,
                depth,
                limit,
            } => {
                if tree {
                    repo_settings::storage_tree(&key, prefix.as_deref(), depth, limit, global).await
                } else {
                    repo_settings::storage(&key, global).await
                }
            }
            Self::StorageGc { key, dry_run, yes } => {
                repo_settings::storage_gc(&key, dry_run, yes, global).await
            }
            Self::TestUpstream { key } => test_upstream(&key, global).await,
            Self::Tree {
                key,
                path,
                metadata,
            } => browse_tree(&key, path.as_deref(), metadata, global).await,
            Self::Cat {
                key,
                path,
                max_bytes,
            } => cat_content(&key, &path, max_bytes, global).await,
        }
    }
}

async fn list_repos(
    format_filter: Option<&str>,
    type_filter: Option<&str>,
    search: Option<&str>,
    project: Option<uuid::Uuid>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let spinner = crate::output::spinner("Fetching repositories...");

    let mut req = client.list_repositories().page(page).per_page(per_page);

    if let Some(fmt) = format_filter {
        req = req.format(fmt);
    }
    if let Some(t) = type_filter {
        req = req.type_(api_repo_type(t));
    }
    if let Some(q) = search {
        req = req.q(q);
    }
    if let Some(project) = project {
        req = req.project(project);
    }

    let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
    let resp = resp.map_err(|e| crate::commands::helpers::sdk_err("list repositories", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No repositories found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for repo in &resp.items {
            println!("{}", repo.key);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "key": r.key,
                "name": r.name,
                "format": r.format,
                "type": r.repo_type,
                "public": r.is_public,
                "storage_used": format_bytes(displayed_storage_bytes(r)),
                "storage_used_bytes": r.storage_used_bytes,
                "member_storage_used_bytes": r.member_storage_used_bytes,
                "description": r.description,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_style(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["KEY", "NAME", "FORMAT", "TYPE", "PUBLIC", "STORAGE"]);

        for r in &resp.items {
            let public = if r.is_public { "yes" } else { "no" };
            let storage = storage_label(r);
            table.add_row(vec![
                r.key.as_str(),
                r.name.as_str(),
                r.format.as_str(),
                r.repo_type.as_str(),
                public,
                &storage,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    // Show pagination info on stderr
    if resp.pagination.total_pages > 1 {
        eprintln!(
            "Page {} of {} ({} total repositories)",
            resp.pagination.page, resp.pagination.total_pages, resp.pagination.total
        );
    }

    Ok(())
}

/// Send a request over raw HTTP and return the body of a success response, for
/// what the SDK can't do: send a `null`, or keep a body its spec doesn't describe.
async fn raw_json_call(
    method: reqwest::Method,
    segments: &[&str],
    body: Option<&serde_json::Value>,
    action: &str,
    global: &GlobalArgs,
) -> Result<Vec<u8>> {
    let (base_url, auth_header) = super::client::resolve_base_url_and_auth(global)?;
    let mut url = reqwest::Url::parse(&base_url)
        .map_err(|e| AkError::ConfigError(format!("Invalid instance URL {base_url}: {e}")))?;
    url.path_segments_mut()
        .map_err(|_| AkError::ConfigError(format!("Invalid instance URL: {base_url}")))?
        .pop_if_empty()
        .extend(["api", "v1"])
        .extend(segments);

    let mut request = super::client::raw_http_client()?
        .request(method, url)
        .header(reqwest::header::AUTHORIZATION, auth_header);
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("Failed to {action}: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(raw_err(&format!("Failed to {action}"), status, &text).into());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| AkError::NetworkError(format!("Failed to {action}: {e}")))?;
    Ok(bytes.to_vec())
}

/// PATCH a repository with fields set to `null`, which is how the API clears
/// them. The SDK's types can't say this: they leave a `None` out, and leaving a
/// field out means "keep it".
async fn patch_with_nulls(
    key: &str,
    body: &artifact_keeper_sdk::types::UpdateRepositoryRequest,
    clear: &[&str],
    global: &GlobalArgs,
) -> Result<(
    artifact_keeper_sdk::types::RepositoryResponse,
    Option<Vec<u8>>,
)> {
    let mut json = serde_json::to_value(body).into_diagnostic()?;
    for field in clear {
        json[*field] = serde_json::Value::Null;
    }
    let bytes = raw_json_call(
        reqwest::Method::PATCH,
        &["repositories", key],
        Some(&json),
        "update repository",
        global,
    )
    .await?;
    let parsed = serde_json::from_slice(&bytes)
        .map_err(|e| AkError::ServerError(format!("Invalid update response: {e}")))?;
    Ok((parsed, Some(bytes)))
}

/// The size to show for a repository. A virtual repository stores nothing of
/// its own (`storage_used_bytes` is 0), so show the total of its members. Sums
/// across repositories must keep using `storage_used_bytes`, or they count
/// those bytes twice.
pub(super) fn displayed_storage_bytes(
    repo: &artifact_keeper_sdk::types::RepositoryResponse,
) -> i64 {
    repo.member_storage_used_bytes
        .unwrap_or(repo.storage_used_bytes)
}

fn storage_label(repo: &artifact_keeper_sdk::types::RepositoryResponse) -> String {
    let size = format_bytes(displayed_storage_bytes(repo));
    if repo.member_storage_used_bytes.is_some() {
        format!("{size} (members)")
    } else {
        size
    }
}

async fn show_repo(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let (repo, raw) =
        artifact_keeper_sdk::raw::capture(client.get_repository().key(key).send()).await;
    let repo = repo.map_err(|e| crate::commands::helpers::sdk_err("get repository", e))?;

    let info = serde_json::json!({
        "id": repo.id,
        "key": repo.key,
        "name": repo.name,
        "format": repo.format,
        "type": repo.repo_type,
        "upstream_url": repo.upstream_url,
        "public": repo.is_public,
        "description": repo.description,
        "storage_used": format_bytes(displayed_storage_bytes(&repo)),
        "storage_used_bytes": repo.storage_used_bytes,
        "member_storage_used_bytes": repo.member_storage_used_bytes,
        "quota_bytes": repo.quota_bytes,
        "created_at": repo.created_at.to_rfc3339(),
        "updated_at": repo.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:           {}\n\
         Key:          {}\n\
         Name:         {}\n\
         Format:       {}\n\
         Type:         {}\n\
         Upstream URL: {}\n\
         Public:       {}\n\
         Description:  {}\n\
         Storage Used: {}\n\
         Quota:        {}\n\
         Created:      {}\n\
         Updated:      {}",
        repo.id,
        repo.key,
        repo.name,
        repo.format,
        repo.repo_type,
        repo.upstream_url.as_deref().unwrap_or("-"),
        if repo.is_public { "yes" } else { "no" },
        repo.description.as_deref().unwrap_or("-"),
        storage_label(&repo),
        repo.quota_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "unlimited".into()),
        repo.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        repo.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn create_repo(
    body: artifact_keeper_sdk::types::CreateRepositoryRequest,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.create_repository().body(body).send()).await;
    let resp = resp.map_err(|e| crate::commands::helpers::sdk_err("create repository", e))?;

    emit_mutation_raw(
        raw.as_deref(),
        &*resp,
        &resp.key,
        &format!(
            "Created repository '{}' (format: {}, type: {})",
            resp.key, resp.format, resp.repo_type
        ),
        global,
    );

    Ok(())
}

async fn delete_repo(
    key: &str,
    skip_confirm: bool,
    wait_secs: Option<u64>,
    global: &GlobalArgs,
) -> Result<()> {
    if !confirm_action(
        &format!("Delete repository '{key}'? This cannot be undone"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;

    match client.delete_repository().key(key).send().await {
        Ok(_) => {
            emit_mutation(
                &serde_json::json!({ "key": key, "status": "deleted" }),
                key,
                &format!("Deleted repository '{key}'."),
                global,
            );
            Ok(())
        }
        // Backend 1.12.0 accepts the delete and runs it as a job. The SDK is
        // generated from 1.11, where 202 isn't a documented answer, so it arrives
        // here as an error carrying the body.
        Err(e) if e.status() == Some(reqwest::StatusCode::ACCEPTED) => {
            deletion_accepted(key, e.body().unwrap_or_default(), wait_secs, global).await
        }
        Err(e) => Err(sdk_err("delete repository", e).into()),
    }
}

/// The server took a repository delete as a background job: report the job, and
/// follow it when asked to. Being unable to read the answer doesn't turn an
/// accepted delete into a failure, unless the caller needed to wait for it.
async fn deletion_accepted(
    key: &str,
    body: &[u8],
    wait_secs: Option<u64>,
    global: &GlobalArgs,
) -> Result<()> {
    let job: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let Some(job_id) = job["id"]
        .as_str()
        .and_then(|id| id.parse::<uuid::Uuid>().ok())
    else {
        if wait_secs.is_some() {
            return Err(AkError::ServerError(format!(
                "The server accepted the delete of '{key}' but gave no job ID, so --wait can't follow it"
            ))
            .into());
        }
        emit_mutation_raw(
            Some(body),
            &serde_json::json!({ "key": key, "status": "accepted" }),
            key,
            &format!("The server accepted the delete of repository '{key}'."),
            global,
        );
        return Ok(());
    };

    let Some(timeout) = wait_secs else {
        emit_mutation_raw(
            Some(body),
            &job,
            &job_id.to_string(),
            &format!(
                "Deleting repository '{key}' in the background (job {job_id}). \
                 Check it with: ak api GET /api/v1/repository-deletions/{job_id}"
            ),
            global,
        );
        return Ok(());
    };

    let final_body = wait_for_deletion(key, job_id, timeout, global).await?;
    emit_mutation_raw(
        Some(&final_body),
        &job,
        &job_id.to_string(),
        &format!("Deleted repository '{key}' (job {job_id})."),
        global,
    );
    Ok(())
}

/// Consecutive failed polls `--wait` puts up with before giving up on a job.
const MAX_POLL_FAILURES: u32 = 5;

/// Poll a repository deletion job until it ends, returning its last body. A job
/// that ends in anything but `completed` is an error.
async fn wait_for_deletion(
    key: &str,
    job_id: uuid::Uuid,
    timeout_secs: u64,
    global: &GlobalArgs,
) -> Result<Vec<u8>> {
    let (base_url, auth_header) = super::client::resolve_base_url_and_auth(global)?;
    let url = format!(
        "{}/api/v1/repository-deletions/{job_id}",
        base_url.trim_end_matches('/')
    );
    let http = super::client::raw_http_client()?;
    let spinner = output::spinner(&format!("Deleting '{key}'..."));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut failures = 0;

    loop {
        let response = http
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, &auth_header)
            .send()
            .await;
        let polled = match response {
            Ok(r) if r.status().is_success() => r.bytes().await.ok(),
            Ok(r) if r.status().is_client_error() => {
                spinner.finish_and_clear();
                let status = r.status();
                let text = r.text().await.unwrap_or_default();
                return Err(
                    raw_err(&format!("Follow deletion job {job_id}"), status, &text).into(),
                );
            }
            _ => None,
        };

        match polled {
            Some(bytes) => {
                failures = 0;
                let job: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
                match job["status"].as_str() {
                    Some("completed") => {
                        spinner.finish_and_clear();
                        return Ok(bytes.to_vec());
                    }
                    Some(status @ ("failed" | "cancelled")) => {
                        spinner.finish_and_clear();
                        let reason = job["error_summary"].as_str().unwrap_or("no reason given");
                        return Err(AkError::ReportedFailure(format!(
                            "Deletion job {job_id} for '{key}' {status}: {}",
                            output::sanitize_terminal(reason)
                        ))
                        .into());
                    }
                    _ => {}
                }
            }
            None => {
                failures += 1;
                if failures >= MAX_POLL_FAILURES {
                    spinner.finish_and_clear();
                    return Err(AkError::ServerError(format!(
                        "Can't read deletion job {job_id} for '{key}'. It may still be running: \
                         ak api GET /api/v1/repository-deletions/{job_id}"
                    ))
                    .into());
                }
            }
        }

        if std::time::Instant::now() >= deadline {
            spinner.finish_and_clear();
            return Err(AkError::ServerError(format!(
                "Deletion job {job_id} for '{key}' hasn't finished after {timeout_secs}s. It's still \
                 running: ak api GET /api/v1/repository-deletions/{job_id}"
            ))
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn browse_repo(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let spinner = crate::output::spinner("Loading artifacts...");

    let resp = client
        .list_artifacts()
        .key(key)
        .per_page(100)
        .send()
        .await
        .map_err(|e| crate::commands::helpers::sdk_err("list artifacts", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No artifacts in repository '{key}'.");
        return Ok(());
    }

    if global.no_input {
        // Non-interactive: just list artifacts
        for a in &resp.items {
            println!("{}", a.path);
        }
        return Ok(());
    }

    // Interactive fuzzy select
    let items: Vec<String> = resp.items.iter().map(|a| a.path.clone()).collect();

    let selection = dialoguer::FuzzySelect::new()
        .with_prompt(format!("Browse artifacts in '{key}'"))
        .items(&items)
        .interact_opt()
        .into_diagnostic()?;

    if let Some(idx) = selection {
        let artifact = &resp.items[idx];
        println!(
            "{}",
            serde_json::to_string_pretty(artifact).unwrap_or_default()
        );
    }

    Ok(())
}

async fn update_repo(
    key: &str,
    body: artifact_keeper_sdk::types::UpdateRepositoryRequest,
    clear: &[&str],
    global: &GlobalArgs,
) -> Result<()> {
    let spinner = output::spinner("Updating repository...");

    let (resp, raw) = if clear.is_empty() {
        let client = client_for(global)?;
        let (resp, raw) = artifact_keeper_sdk::raw::capture(
            client.update_repository().key(key).body(body).send(),
        )
        .await;
        (
            resp.map_err(|e| sdk_err("update repository", e))?
                .into_inner(),
            raw,
        )
    } else {
        patch_with_nulls(key, &body, clear, global).await?
    };

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "key": resp.key,
        "name": resp.name,
        "format": resp.format,
        "type": resp.repo_type,
        "public": resp.is_public,
        "allow_anonymous_access": resp.allow_anonymous_access,
        "promotion_only": resp.promotion_only,
        "description": resp.description,
        "quota_bytes": resp.quota_bytes,
        "quarantine_enabled": resp.quarantine_enabled,
        "quarantine_duration_minutes": resp.quarantine_duration_minutes,
        "upstream_url": resp.upstream_url,
    });

    emit_mutation_raw(
        raw.as_deref(),
        &info,
        &resp.key,
        &format!("Updated repository '{}'.", resp.key),
        global,
    );

    Ok(())
}

async fn list_members(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching members...");

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.list_virtual_members().key(key).send()).await;
    let resp = resp.map_err(|e| sdk_err("list virtual members", e))?;

    spinner.finish_and_clear();

    if resp.members.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No members on virtual repository '{key}'.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for m in &resp.members {
            println!("{}", m.member_repo_key);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .members
        .iter()
        .map(|m| {
            serde_json::json!({
                "member_key": m.member_repo_key,
                "name": m.member_repo_name,
                "type": m.member_repo_type,
                "priority": m.priority,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["MEMBER KEY", "NAME", "TYPE", "PRIORITY"]);
        for m in &resp.members {
            let priority = m.priority.to_string();
            table.add_row(vec![
                m.member_repo_key.as_str(),
                m.member_repo_name.as_str(),
                m.member_repo_type.as_str(),
                priority.as_str(),
            ]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn add_member(
    key: &str,
    member_key: &str,
    priority: Option<i32>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Adding member...");

    let body = artifact_keeper_sdk::types::AddVirtualMemberRequest {
        member_key: member_key.to_string(),
        priority,
    };

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.add_virtual_member().key(key).body(body).send())
            .await;
    let resp = resp.map_err(|e| sdk_err("add virtual member", e))?;

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &*resp,
        &resp.member_repo_key,
        &format!(
            "Added '{}' to virtual repository '{key}'.",
            resp.member_repo_key
        ),
        global,
    );

    Ok(())
}

async fn remove_member(key: &str, member_key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    client
        .remove_virtual_member()
        .key(key)
        .member_key(member_key)
        .send()
        .await
        .map_err(|e| sdk_err("remove virtual member", e))?;

    emit_mutation(
        &serde_json::json!({ "member_key": member_key, "status": "removed" }),
        member_key,
        &format!("Removed '{member_key}' from virtual repository '{key}'."),
        global,
    );

    Ok(())
}

async fn reorder_members(key: &str, members: &[String], global: &GlobalArgs) -> Result<()> {
    let mut priorities = Vec::with_capacity(members.len());
    for entry in members {
        let (member_key, priority) = entry.split_once('=').ok_or_else(|| {
            AkError::Usage(format!(
                "Member priority must be in 'member_key=priority' format: {entry}"
            ))
        })?;
        let priority: i32 = priority.parse().map_err(|_| {
            AkError::Usage(format!("Invalid priority '{priority}' in entry '{entry}'"))
        })?;
        priorities.push(artifact_keeper_sdk::types::VirtualMemberPriority {
            member_key: member_key.to_string(),
            priority,
        });
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Reordering members...");

    let (resp, raw) = artifact_keeper_sdk::raw::capture(
        client
            .update_virtual_members()
            .key(key)
            .body(artifact_keeper_sdk::types::UpdateVirtualMembersRequest {
                members: priorities,
            })
            .send(),
    )
    .await;
    let resp = resp.map_err(|e| sdk_err("reorder virtual members", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "members": resp.members.iter().map(|m| serde_json::json!({
            "member_key": m.member_repo_key,
            "priority": m.priority,
        })).collect::<Vec<_>>(),
    });

    emit_mutation_raw(
        raw.as_deref(),
        &info,
        key,
        &format!("Reordered {} member(s) on '{key}'.", resp.members.len()),
        global,
    );

    Ok(())
}

async fn get_routing_rules(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching routing rules...");

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.get_routing_rules().key(key).send()).await;
    let resp = resp.map_err(|e| sdk_err("get routing rules", e))?;

    spinner.finish_and_clear();

    if resp.rules.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No routing rules on repository '{key}'.");
        return Ok(());
    }

    let entries: Vec<_> = resp
        .rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "path_pattern": r.path_pattern,
                "rewrite_to": r.rewrite_to,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["PATTERN", "REWRITE TO"]);
        for r in &resp.rules {
            table.add_row(vec![r.path_pattern.as_str(), r.rewrite_to.as_str()]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn set_routing_rules(key: &str, rules: &[String], global: &GlobalArgs) -> Result<()> {
    let mut parsed = Vec::with_capacity(rules.len());
    for rule in rules {
        let (pattern, rewrite) = rule.split_once("=>").ok_or_else(|| {
            AkError::Usage(format!(
                "Routing rule must be in '<pattern>=><rewrite>' format: {rule}"
            ))
        })?;
        parsed.push(artifact_keeper_sdk::types::RoutingRule {
            path_pattern: pattern.trim().to_string(),
            rewrite_to: rewrite.trim().to_string(),
        });
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Setting routing rules...");

    let (resp, raw) = artifact_keeper_sdk::raw::capture(
        client
            .set_routing_rules()
            .key(key)
            .body(artifact_keeper_sdk::types::SetRoutingRulesRequest { rules: parsed })
            .send(),
    )
    .await;
    let resp = resp.map_err(|e| sdk_err("set routing rules", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "repository_key": resp.repository_key,
        "rules": resp.rules.iter().map(|r| serde_json::json!({
            "path_pattern": r.path_pattern,
            "rewrite_to": r.rewrite_to,
        })).collect::<Vec<_>>(),
    });

    emit_mutation_raw(
        raw.as_deref(),
        &info,
        &resp.repository_key,
        &format!("Set {} routing rule(s) on '{key}'.", resp.rules.len()),
        global,
    );

    Ok(())
}

async fn delete_routing_rules(key: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    if !confirm_action(
        &format!("Delete all routing rules for '{key}'?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    // Raw: the spec gives this route no response body, so the SDK drops the one
    // the server sends.
    let raw = raw_json_call(
        reqwest::Method::DELETE,
        &["repositories", key, "routing-rules"],
        None,
        "delete routing rules",
        global,
    )
    .await?;

    emit_mutation_raw(
        Some(&raw),
        &serde_json::json!({ "key": key, "status": "deleted" }),
        key,
        &format!("Deleted routing rules for '{key}'."),
        global,
    );

    Ok(())
}

async fn get_cache_ttl(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.get_cache_ttl().key(key).send()).await;
    let resp = resp.map_err(|e| sdk_err("get cache TTL", e))?;

    let info = serde_json::json!({
        "repository_key": resp.repository_key,
        "cache_ttl_seconds": resp.cache_ttl_seconds,
    });

    let table_str = format!(
        "Repository:  {}\nCache TTL:   {} seconds",
        resp.repository_key, resp.cache_ttl_seconds
    );

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn set_cache_ttl(key: &str, seconds: i64, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let (resp, raw) = artifact_keeper_sdk::raw::capture(
        client
            .set_cache_ttl()
            .key(key)
            .body(artifact_keeper_sdk::types::SetCacheTtlRequest {
                cache_ttl_seconds: seconds,
            })
            .send(),
    )
    .await;
    let resp = resp.map_err(|e| sdk_err("set cache TTL", e))?;

    let info = serde_json::json!({
        "repository_key": resp.repository_key,
        "cache_ttl_seconds": resp.cache_ttl_seconds,
    });

    emit_mutation_raw(
        raw.as_deref(),
        &info,
        &resp.repository_key,
        &format!(
            "Set cache TTL for '{}' to {} seconds.",
            resp.repository_key, resp.cache_ttl_seconds
        ),
        global,
    );

    Ok(())
}

async fn invalidate_cache(key: &str, path: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.invalidate_cache().key(key).path(path).send())
            .await;
    let resp = resp.map_err(|e| sdk_err("invalidate cache", e))?;

    let info = serde_json::json!({
        "repository_key": resp.repository_key,
        "path": resp.path,
        "invalidated": resp.invalidated,
    });

    emit_mutation_raw(
        raw.as_deref(),
        &info,
        &resp.path,
        &format!(
            "Invalidated cache entry '{}' on '{}' (invalidated: {}).",
            resp.path, resp.repository_key, resp.invalidated
        ),
        global,
    );

    Ok(())
}

async fn list_pypi_tracks(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching PyPI tracks...");

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.list_pypi_tracks().key(key).send()).await;
    let resp = resp.map_err(|e| sdk_err("list PyPI tracks", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No PyPI tracks declared on repository '{key}'.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for t in &resp.items {
            println!("{}", t.normalized_name);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|t| {
            serde_json::json!({
                "normalized_name": t.normalized_name,
                "tracks_url": t.tracks_url,
                "repository_key": t.repository_key,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["PROJECT", "TRACKS URL"]);
        for t in &resp.items {
            table.add_row(vec![t.normalized_name.as_str(), t.tracks_url.as_str()]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn put_pypi_track(
    key: &str,
    project: &str,
    tracks_url: &str,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let (resp, raw) = artifact_keeper_sdk::raw::capture(
        client
            .put_pypi_track()
            .key(key)
            .project(project)
            .body(artifact_keeper_sdk::types::PypiTrackRequest {
                tracks_url: tracks_url.to_string(),
            })
            .send(),
    )
    .await;
    let resp = resp.map_err(|e| sdk_err("set PyPI track", e))?;

    let info = serde_json::json!({
        "normalized_name": resp.normalized_name,
        "tracks_url": resp.tracks_url,
        "repository_key": resp.repository_key,
    });

    emit_mutation_raw(
        raw.as_deref(),
        &info,
        &resp.normalized_name,
        &format!(
            "Declared track '{}' -> {} on '{key}'.",
            resp.normalized_name, resp.tracks_url
        ),
        global,
    );

    Ok(())
}

async fn delete_pypi_track(key: &str, project: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    client
        .delete_pypi_track()
        .key(key)
        .project(project)
        .send()
        .await
        .map_err(|e| sdk_err("remove PyPI track", e))?;

    emit_mutation(
        &serde_json::json!({ "project": project, "status": "removed" }),
        project,
        &format!("Removed PyPI track '{project}' from '{key}'."),
        global,
    );

    Ok(())
}

async fn set_upstream_auth(
    key: &str,
    body: artifact_keeper_sdk::types::UpstreamAuthRequest,
    global: &GlobalArgs,
) -> Result<()> {
    let auth_type = body.auth_type.clone();
    let json = serde_json::to_value(&body).into_diagnostic()?;
    // Raw: the spec gives this route no response body, so the SDK drops the one
    // the server sends.
    let raw = raw_json_call(
        reqwest::Method::PUT,
        &["repositories", key, "upstream-auth"],
        Some(&json),
        "set upstream auth",
        global,
    )
    .await?;

    let action = if auth_type == "none" {
        format!("Removed upstream auth from '{key}'.")
    } else {
        format!("Set upstream auth ({auth_type}) on '{key}'.")
    };

    emit_mutation_raw(
        Some(&raw),
        &serde_json::json!({ "key": key, "auth_type": auth_type }),
        key,
        &action,
        global,
    );

    Ok(())
}

async fn test_upstream(key: &str, global: &GlobalArgs) -> Result<()> {
    let spinner = output::spinner("Testing upstream connectivity...");

    // Raw: the spec gives this route no response body, so the SDK drops the one
    // the server sends.
    let raw = raw_json_call(
        reqwest::Method::POST,
        &["repositories", key, "test-upstream"],
        None,
        "test upstream",
        global,
    )
    .await;
    spinner.finish_and_clear();
    let raw = raw?;

    emit_mutation_raw(
        Some(&raw),
        &serde_json::json!({ "key": key, "upstream": "reachable" }),
        key,
        &format!("Upstream for '{key}' is reachable."),
        global,
    );

    Ok(())
}

async fn browse_tree(
    key: &str,
    path: Option<&str>,
    metadata: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Loading tree...");

    let mut req = client.get_tree().repository_key(key);
    if let Some(p) = path {
        req = req.path(p);
    }
    if metadata {
        req = req.include_metadata(true);
    }

    let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
    let resp = resp.map_err(|e| sdk_err("browse tree", e))?;

    spinner.finish_and_clear();

    if resp.nodes.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No nodes under '{key}'.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for n in &resp.nodes {
            println!("{}", n.path);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .nodes
        .iter()
        .map(|n| {
            serde_json::json!({
                "name": n.name,
                "path": n.path,
                "type": n.type_,
                "has_children": n.has_children,
                "size_bytes": n.size_bytes,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["NAME", "TYPE", "PATH", "SIZE"]);
        for n in &resp.nodes {
            let size = n.size_bytes.map(format_bytes).unwrap_or_else(|| "-".into());
            table.add_row(vec![
                n.name.as_str(),
                n.type_.as_str(),
                n.path.as_str(),
                size.as_str(),
            ]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn cat_content(
    key: &str,
    path: &str,
    max_bytes: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let mut req = client.get_content().repository_key(key).path(path);
    if let Some(mb) = max_bytes {
        req = req.max_bytes(mb);
    }

    let resp = req.send().await.map_err(|e| sdk_err("get content", e))?;

    let mut stream = resp.into_inner();
    let mut stdout = tokio::io::stdout();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| sdk_err("read content", e))?;
        tokio::io::AsyncWriteExt::write_all(&mut stdout, &chunk)
            .await
            .into_diagnostic()?;
    }
    tokio::io::AsyncWriteExt::flush(&mut stdout)
        .await
        .into_diagnostic()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    // ---- TestCli wrapper for parsing ----

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: RepoCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- List subcommand parsing ----

    #[test]
    fn parse_list() {
        let cli = parse(&["test", "list"]);
        assert!(matches!(cli.command, RepoCommand::List { .. }));
    }

    #[test]
    fn parse_list_defaults() {
        let cli = parse(&["test", "list"]);
        if let RepoCommand::List {
            pkg_format,
            repo_type,
            search,
            page,
            per_page,
            ..
        } = cli.command
        {
            assert!(pkg_format.is_none());
            assert!(repo_type.is_none());
            assert!(search.is_none());
            assert_eq!(page, 1);
            assert_eq!(per_page, 50);
        } else {
            panic!("Expected RepoCommand::List");
        }
    }

    #[test]
    fn parse_list_with_format_filter() {
        let cli = parse(&["test", "list", "--pkg-format", "npm"]);
        if let RepoCommand::List { pkg_format, .. } = cli.command {
            assert_eq!(pkg_format.as_deref(), Some("npm"));
        } else {
            panic!("Expected RepoCommand::List");
        }
    }

    #[test]
    fn parse_list_with_type_filter() {
        let cli = parse(&["test", "list", "--repo-type", "local"]);
        if let RepoCommand::List { repo_type, .. } = cli.command {
            assert_eq!(repo_type.as_deref(), Some("local"));
        } else {
            panic!("Expected RepoCommand::List");
        }
    }

    #[test]
    fn parse_list_with_search() {
        let cli = parse(&["test", "list", "--search", "my-repo"]);
        if let RepoCommand::List { search, .. } = cli.command {
            assert_eq!(search.as_deref(), Some("my-repo"));
        } else {
            panic!("Expected RepoCommand::List");
        }
    }

    #[test]
    fn parse_list_custom_pagination() {
        let cli = parse(&["test", "list", "--page", "5", "--per-page", "25"]);
        if let RepoCommand::List { page, per_page, .. } = cli.command {
            assert_eq!(page, 5);
            assert_eq!(per_page, 25);
        } else {
            panic!("Expected RepoCommand::List");
        }
    }

    #[test]
    fn parse_list_all_options() {
        let cli = parse(&[
            "test",
            "list",
            "--pkg-format",
            "maven",
            "--repo-type",
            "remote",
            "--search",
            "libs",
            "--page",
            "2",
            "--per-page",
            "10",
        ]);
        if let RepoCommand::List {
            pkg_format,
            repo_type,
            search,
            page,
            per_page,
            ..
        } = cli.command
        {
            assert_eq!(pkg_format.as_deref(), Some("maven"));
            assert_eq!(repo_type.as_deref(), Some("remote"));
            assert_eq!(search.as_deref(), Some("libs"));
            assert_eq!(page, 2);
            assert_eq!(per_page, 10);
        } else {
            panic!("Expected RepoCommand::List");
        }
    }

    // ---- Show subcommand parsing ----

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "my-npm-repo"]);
        if let RepoCommand::Show { key } = cli.command {
            assert_eq!(key, "my-npm-repo");
        } else {
            panic!("Expected RepoCommand::Show");
        }
    }

    #[test]
    fn parse_show_missing_key_fails() {
        assert!(try_parse(&["test", "show"]).is_err());
    }

    // ---- Create subcommand parsing ----

    #[test]
    fn parse_create() {
        let cli = parse(&["test", "create", "my-repo", "--pkg-format", "npm"]);
        if let RepoCommand::Create {
            key,
            pkg_format,
            repo_type,
            upstream_url,
            description,
            public,
            ..
        } = cli.command
        {
            assert_eq!(key, "my-repo");
            assert_eq!(pkg_format, "npm");
            assert_eq!(repo_type, "local"); // default
            assert!(upstream_url.is_none());
            assert!(description.is_none());
            assert_eq!(public, false)
        } else {
            panic!("Expected RepoCommand::Create");
        }
    }

    #[test]
    fn parse_create_with_all_options() {
        let cli = parse(&[
            "test",
            "create",
            "my-pypi",
            "--pkg-format",
            "pypi",
            "--repo-type",
            "remote",
            "--upstream-url",
            "https://pypi.org/simple",
            "--description",
            "Python packages mirror",
            "--public",
        ]);
        if let RepoCommand::Create {
            key,
            pkg_format,
            repo_type,
            upstream_url,
            description,
            public,
            ..
        } = cli.command
        {
            assert_eq!(key, "my-pypi");
            assert_eq!(pkg_format, "pypi");
            assert_eq!(repo_type, "remote");
            assert_eq!(upstream_url.as_deref(), Some("https://pypi.org/simple"));
            assert_eq!(description.as_deref(), Some("Python packages mirror"));
            assert_eq!(public, true)
        } else {
            panic!("Expected RepoCommand::Create");
        }
    }

    #[test]
    fn parse_create_missing_format_fails() {
        assert!(try_parse(&["test", "create", "key"]).is_err());
    }

    #[test]
    fn parse_create_missing_key_fails() {
        assert!(try_parse(&["test", "create", "--pkg-format", "npm"]).is_err());
    }

    // ---- Delete subcommand parsing ----

    #[test]
    fn parse_delete() {
        let cli = parse(&["test", "delete", "my-repo"]);
        if let RepoCommand::Delete { key, yes, .. } = cli.command {
            assert_eq!(key, "my-repo");
            assert!(!yes);
        } else {
            panic!("Expected RepoCommand::Delete");
        }
    }

    #[test]
    fn parse_delete_with_yes() {
        let cli = parse(&["test", "delete", "my-repo", "--yes"]);
        if let RepoCommand::Delete { key, yes, .. } = cli.command {
            assert_eq!(key, "my-repo");
            assert!(yes);
        } else {
            panic!("Expected RepoCommand::Delete");
        }
    }

    #[test]
    fn parse_delete_missing_key_fails() {
        assert!(try_parse(&["test", "delete"]).is_err());
    }

    // ---- Browse subcommand parsing ----

    #[test]
    fn parse_browse() {
        let cli = parse(&["test", "browse", "my-repo"]);
        if let RepoCommand::Browse { key } = cli.command {
            assert_eq!(key, "my-repo");
        } else {
            panic!("Expected RepoCommand::Browse");
        }
    }

    #[test]
    fn parse_browse_missing_key_fails() {
        assert!(try_parse(&["test", "browse"]).is_err());
    }

    // ---- Update subcommand parsing ----

    #[test]
    fn parse_update_partial() {
        let cli = parse(&["test", "update", "my-repo", "--description", "hi"]);
        if let RepoCommand::Update {
            key,
            name,
            description,
            public,
            ..
        } = cli.command
        {
            assert_eq!(key, "my-repo");
            assert!(name.is_none());
            assert_eq!(description.as_deref(), Some("hi"));
            assert!(public.is_none());
        } else {
            panic!("Expected RepoCommand::Update");
        }
    }

    #[test]
    fn parse_update_bool_and_numeric_flags() {
        let cli = parse(&[
            "test",
            "update",
            "r",
            "--public",
            "true",
            "--promotion-only",
            "false",
            "--quota-bytes",
            "1048576",
            "--new-key",
            "renamed",
        ]);
        if let RepoCommand::Update {
            new_key,
            public,
            promotion_only,
            quota_bytes,
            ..
        } = cli.command
        {
            assert_eq!(new_key.as_deref(), Some("renamed"));
            assert_eq!(public, Some(true));
            assert_eq!(promotion_only, Some(false));
            assert_eq!(quota_bytes, Some(1048576));
        } else {
            panic!("Expected RepoCommand::Update");
        }
    }

    #[test]
    fn parse_update_missing_key_fails() {
        assert!(try_parse(&["test", "update"]).is_err());
    }

    // ---- Members subcommand parsing ----

    #[test]
    fn parse_members_list() {
        let cli = parse(&["test", "members", "list", "virt"]);
        assert!(matches!(
            cli.command,
            RepoCommand::Members {
                command: MembersCommand::List { .. }
            }
        ));
    }

    #[test]
    fn parse_members_add_with_priority() {
        let cli = parse(&["test", "members", "add", "virt", "mem", "--priority", "5"]);
        if let RepoCommand::Members {
            command:
                MembersCommand::Add {
                    key,
                    member_key,
                    priority,
                },
        } = cli.command
        {
            assert_eq!(key, "virt");
            assert_eq!(member_key, "mem");
            assert_eq!(priority, Some(5));
        } else {
            panic!("Expected MembersCommand::Add");
        }
    }

    #[test]
    fn parse_members_reorder_variadic() {
        let cli = parse(&["test", "members", "reorder", "virt", "a=1", "b=2"]);
        if let RepoCommand::Members {
            command: MembersCommand::Reorder { key, members },
        } = cli.command
        {
            assert_eq!(key, "virt");
            assert_eq!(members, vec!["a=1".to_string(), "b=2".to_string()]);
        } else {
            panic!("Expected MembersCommand::Reorder");
        }
    }

    #[test]
    fn parse_members_reorder_requires_entries() {
        assert!(try_parse(&["test", "members", "reorder", "virt"]).is_err());
    }

    // ---- Routing-rules subcommand parsing ----

    #[test]
    fn parse_routing_rules_set() {
        let cli = parse(&["test", "routing-rules", "set", "r", "--rule", "a=>b"]);
        if let RepoCommand::RoutingRules {
            command: RoutingRulesCommand::Set { key, rules },
        } = cli.command
        {
            assert_eq!(key, "r");
            assert_eq!(rules, vec!["a=>b".to_string()]);
        } else {
            panic!("Expected RoutingRulesCommand::Set");
        }
    }

    #[test]
    fn parse_routing_rules_get() {
        let cli = parse(&["test", "routing-rules", "get", "r"]);
        assert!(matches!(
            cli.command,
            RepoCommand::RoutingRules {
                command: RoutingRulesCommand::Get { .. }
            }
        ));
    }

    // ---- Cache subcommand parsing ----

    #[test]
    fn parse_cache_set_ttl() {
        let cli = parse(&["test", "cache", "set-ttl", "r", "3600"]);
        if let RepoCommand::Cache {
            command: CacheCommand::SetTtl { key, seconds },
        } = cli.command
        {
            assert_eq!(key, "r");
            assert_eq!(seconds, 3600);
        } else {
            panic!("Expected CacheCommand::SetTtl");
        }
    }

    #[test]
    fn parse_cache_invalidate() {
        let cli = parse(&["test", "cache", "invalidate", "r", "some/path.tgz"]);
        if let RepoCommand::Cache {
            command: CacheCommand::Invalidate { key, path },
        } = cli.command
        {
            assert_eq!(key, "r");
            assert_eq!(path, "some/path.tgz");
        } else {
            panic!("Expected CacheCommand::Invalidate");
        }
    }

    // ---- PyPI tracks subcommand parsing ----

    #[test]
    fn parse_pypi_tracks_set() {
        let cli = parse(&[
            "test",
            "pypi-tracks",
            "set",
            "r",
            "acme",
            "--tracks-url",
            "https://pypi.org/simple/acme/",
        ]);
        if let RepoCommand::PypiTracks {
            command:
                PypiTracksCommand::Set {
                    key,
                    project,
                    tracks_url,
                },
        } = cli.command
        {
            assert_eq!(key, "r");
            assert_eq!(project, "acme");
            assert_eq!(tracks_url, "https://pypi.org/simple/acme/");
        } else {
            panic!("Expected PypiTracksCommand::Set");
        }
    }

    // ---- Upstream-auth / test-upstream parsing ----

    #[test]
    fn parse_upstream_auth() {
        let cli = parse(&[
            "test",
            "upstream-auth",
            "r",
            "--type",
            "basic",
            "--username",
            "u",
            "--password",
            "p",
        ]);
        if let RepoCommand::UpstreamAuth {
            key,
            auth_type,
            username,
            password,
            ..
        } = cli.command
        {
            assert_eq!(key, "r");
            assert_eq!(auth_type, "basic");
            assert_eq!(username.as_deref(), Some("u"));
            assert_eq!(password.as_deref(), Some("p"));
        } else {
            panic!("Expected RepoCommand::UpstreamAuth");
        }
    }

    #[test]
    fn parse_test_upstream() {
        let cli = parse(&["test", "test-upstream", "r"]);
        assert!(matches!(cli.command, RepoCommand::TestUpstream { .. }));
    }

    // ---- Tree / cat parsing ----

    #[test]
    fn parse_tree_with_options() {
        let cli = parse(&["test", "tree", "r", "--path", "sub", "--metadata"]);
        if let RepoCommand::Tree {
            key,
            path,
            metadata,
        } = cli.command
        {
            assert_eq!(key, "r");
            assert_eq!(path.as_deref(), Some("sub"));
            assert!(metadata);
        } else {
            panic!("Expected RepoCommand::Tree");
        }
    }

    #[test]
    fn parse_cat() {
        let cli = parse(&["test", "cat", "r", "a/b.txt", "--max-bytes", "1024"]);
        if let RepoCommand::Cat {
            key,
            path,
            max_bytes,
        } = cli.command
        {
            assert_eq!(key, "r");
            assert_eq!(path, "a/b.txt");
            assert_eq!(max_bytes, Some(1024));
        } else {
            panic!("Expected RepoCommand::Cat");
        }
    }

    // ---- Error cases ----

    #[test]
    fn parse_no_subcommand_fails() {
        assert!(try_parse(&["test"]).is_err());
    }

    #[test]
    fn parse_unknown_subcommand_fails() {
        assert!(try_parse(&["test", "unknown"]).is_err());
    }

    // ---- Format function tests ----

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    #[test]
    fn storage_label_uses_member_total_for_virtual_repos() {
        let mut virtual_repo = repo_json("v");
        virtual_repo["repo_type"] = serde_json::json!("virtual");
        virtual_repo["storage_used_bytes"] = serde_json::json!(0);
        virtual_repo["member_storage_used_bytes"] = serde_json::json!(2048);
        let virtual_repo: artifact_keeper_sdk::types::RepositoryResponse =
            serde_json::from_value(virtual_repo).unwrap();
        assert_eq!(displayed_storage_bytes(&virtual_repo), 2048);
        assert_eq!(storage_label(&virtual_repo), "2.0 KB (members)");

        let local_repo: artifact_keeper_sdk::types::RepositoryResponse =
            serde_json::from_value(repo_json("l")).unwrap();
        assert_eq!(displayed_storage_bytes(&local_repo), 1024);
        assert_eq!(storage_label(&local_repo), "1.0 KB");
    }

    /// A 1.10 server doesn't send the fields 1.11 added.
    #[test]
    fn repo_response_parses_without_fields_new_in_1_11() {
        let mut repo = repo_json("r");
        let fields = repo.as_object_mut().unwrap();
        for field in [
            "allow_public_with_upstream_credentials",
            "public_with_upstream_credentials",
            "repodata_depth",
            "repodata_depth_editable",
            "storage_backend",
            "upstream_url_has_credentials",
            "visibility",
        ] {
            fields.remove(field);
        }
        assert!(
            serde_json::from_value::<artifact_keeper_sdk::types::RepositoryResponse>(repo).is_ok()
        );
    }

    fn repo_json(key: &str) -> serde_json::Value {
        json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "key": key,
            "name": key,
            "format": "npm",
            "repo_type": "local",
            "is_public": true,
            "allow_anonymous_access": false,
            "promotion_only": false,
            "description": "Test repo",
            "storage_used_bytes": 1024,
            "quota_bytes": null,
            "upstream_url": null,
            "upstream_auth_type": null,
            "upstream_auth_configured": false,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z",
            "repodata_depth": 0,
            "repodata_depth_editable": true,
            "visibility": "public",
            "versioning_enabled": false,
            "storage_backend": "filesystem",
            "has_trusted_gpg_key": false,
            "upstream_url_has_credentials": false,
            "public_with_upstream_credentials": false,
            "allow_public_with_upstream_credentials": false,
            "curation_enabled": false,
            "curation_default_action": "allow"
        })
    }

    #[tokio::test]
    async fn handler_list_repos_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 50, "total": 0, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_repos(None, None, None, None, 1, 50, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_repos_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [repo_json("npm-local")],
                "pagination": { "page": 1, "per_page": 50, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_repos(None, None, None, None, 1, 50, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_repos_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [repo_json("npm-local")],
                "pagination": { "page": 1, "per_page": 50, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = list_repos(None, None, None, None, 1, 50, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_repo() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories/npm-local"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repo_json("npm-local")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_repo("npm-local", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    fn create_body() -> artifact_keeper_sdk::types::CreateRepositoryRequest {
        serde_json::from_value(json!({
            "key": "new-repo", "name": "new-repo", "format": "npm", "repo_type": "local"
        }))
        .expect("valid request")
    }

    #[tokio::test]
    async fn handler_create_repo_json() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repo_json("new-repo")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = create_repo(create_body(), &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_repo_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repo_json("new-repo")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = create_repo(create_body(), &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_repo() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path("/api/v1/repositories/old-repo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        // skip_confirm=true and no_input=true so no prompt
        let result = delete_repo("old-repo", true, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_browse_repo_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/npm-local/artifacts.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 100, "total": 0, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = browse_repo("npm-local", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_browse_repo_no_input() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/npm-local/artifacts.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "path": "express/4.18.2",
                    "name": "express",
                    "size_bytes": 2048_i64,
                    "content_type": "application/gzip",
                    "checksum_sha256": "abc123",
                    "analyzable": true,
                    "download_count": 0_i64,
                    "created_at": "2026-01-15T12:00:00Z",
                    "repository_key": "npm-local",
                    "quarantine_status": "not_quarantined"
                }],
                "pagination": { "page": 1, "per_page": 100, "total": 1_i64, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = browse_repo("npm-local", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- handler tests for gap-fill repo ops ----

    #[tokio::test]
    async fn handler_update_repo() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PATCH"))
            .and(path("/api/v1/repositories/npm-local"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repo_json("npm-local")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let body = artifact_keeper_sdk::types::UpdateRepositoryRequest {
            description: Some("updated".into()),
            ..Default::default()
        };
        let result = update_repo("npm-local", body, &[], &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_members() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories/virt/members"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "members": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "member_repo_id": "00000000-0000-0000-0000-000000000002",
                    "member_repo_key": "npm-local",
                    "member_repo_name": "NPM Local",
                    "member_repo_type": "local",
                    "priority": 10,
                    "created_at": "2026-01-15T12:00:00Z"
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(list_members("virt", &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_add_member() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/repositories/virt/members"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "member_repo_id": "00000000-0000-0000-0000-000000000002",
                "member_repo_key": "npm-local",
                "member_repo_name": "NPM Local",
                "member_repo_type": "local",
                "priority": 10,
                "created_at": "2026-01-15T12:00:00Z"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            add_member("virt", "npm-local", Some(10), &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_remove_member() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path("/api/v1/repositories/virt/members/npm-local"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(remove_member("virt", "npm-local", &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_reorder_members() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path("/api/v1/repositories/virt/members"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "members": [] })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let members = vec!["a=1".to_string(), "b=2".to_string()];
        assert!(reorder_members("virt", &members, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn reorder_members_rejects_bad_entry() {
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        let global = crate::test_utils::test_global(OutputFormat::Json);
        // missing '=' separator
        assert!(
            reorder_members("virt", &["oops".to_string()], &global)
                .await
                .is_err()
        );
        // non-numeric priority
        assert!(
            reorder_members("virt", &["a=x".to_string()], &global)
                .await
                .is_err()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_routing_rules_get_set_delete() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let rules_body = json!({
            "repository_key": "remote",
            "rules": [{ "path_pattern": "a/(.*)", "rewrite_to": "b/$1" }]
        });
        Mock::given(method("GET"))
            .and(path("/api/v1/repositories/remote/routing-rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rules_body.clone()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/repositories/remote/routing-rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rules_body))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/repositories/remote/routing-rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(get_routing_rules("remote", &global).await.is_ok());
        assert!(
            set_routing_rules("remote", &["a/(.*)=>b/$1".to_string()], &global)
                .await
                .is_ok()
        );
        assert!(delete_routing_rules("remote", true, &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn set_routing_rules_rejects_bad_entry() {
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            set_routing_rules("remote", &["no-separator".to_string()], &global)
                .await
                .is_err()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_cache_ttl_get_set_invalidate() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let ttl_body = json!({ "repository_key": "remote", "cache_ttl_seconds": 7200_i64 });
        Mock::given(method("GET"))
            .and(path("/api/v1/repositories/remote/cache-ttl"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ttl_body.clone()))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/api/v1/repositories/remote/cache-ttl"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ttl_body))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/repositories/remote/cache/invalidate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "repository_key": "remote", "path": "p/x.tgz", "invalidated": true
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(get_cache_ttl("remote", &global).await.is_ok());
        assert!(set_cache_ttl("remote", 7200, &global).await.is_ok());
        assert!(invalidate_cache("remote", "p/x.tgz", &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_pypi_tracks_list_set_remove() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let track = json!({
            "normalized_name": "acme",
            "repository_key": "pypi-local",
            "tracks_url": "https://pypi.org/simple/acme/"
        });
        Mock::given(method("GET"))
            .and(path("/api/v1/repositories/pypi-local/pypi-tracks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "items": [track.clone()] })),
            )
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/api/v1/repositories/pypi-local/pypi-tracks/acme"))
            .respond_with(ResponseTemplate::new(200).set_body_json(track))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/repositories/pypi-local/pypi-tracks/acme"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(list_pypi_tracks("pypi-local", &global).await.is_ok());
        assert!(
            put_pypi_track(
                "pypi-local",
                "acme",
                "https://pypi.org/simple/acme/",
                &global
            )
            .await
            .is_ok()
        );
        assert!(
            delete_pypi_track("pypi-local", "acme", &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_upstream_auth_and_test() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path("/api/v1/repositories/remote/upstream-auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/repositories/remote/test-upstream"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            set_upstream_auth(
                "remote",
                serde_json::from_value(json!({"auth_type": "bearer", "password": "tok"}))
                    .expect("valid request"),
                &global,
            )
            .await
            .is_ok()
        );
        assert!(test_upstream("remote", &global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_browse_tree() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/tree"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "nodes": [{
                    "id": "n1",
                    "name": "express",
                    "path": "express",
                    "type": "directory",
                    "has_children": true,
                    "size_bytes": null
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            browse_tree("npm-local", Some("express"), true, &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_cat_content() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/tree/content"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello world"))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        assert!(
            cat_content("npm-local", "a/b.txt", Some(1024), &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_repo_list_json() {
        let items = vec![
            json!({
                "key": "npm-local",
                "name": "NPM Local",
                "format": "npm",
                "type": "local",
                "public": true,
                "storage_used": "1.5 GB",
            }),
            json!({
                "key": "maven-central",
                "name": "Maven Central",
                "format": "maven",
                "type": "remote",
                "public": false,
                "storage_used": "500.0 MB",
            }),
        ];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("repo_list_json", parsed);
    }

    #[test]
    fn snapshot_repo_show_json() {
        let repo = repo_json("npm-local");
        let output = crate::output::render(&repo, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("repo_show_json", parsed);
    }
}
