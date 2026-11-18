//! `ak admin settings system|token-policy|totp-policy`: settings the server keeps
//! at runtime, each with its own route.

use artifact_keeper_sdk::ClientAdminExt;
use artifact_keeper_sdk::types::{
    RuntimeSettingsResponse, TokenPolicyResponse, TotpPolicy, TotpPolicyResponse,
    UpdateRuntimeSettingsRequest, UpdateTokenPolicyRequest, UpdateTotpPolicyRequest,
};
use clap::{ArgAction, Subcommand, ValueEnum};
use miette::Result;

use crate::cli::GlobalArgs;
use crate::commands::client::client_for;
use crate::commands::helpers::{confirm_action, refuse_flags_before, sdk_err};
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum SystemCommand {
    /// Show the runtime settings and where each value comes from
    Show,

    /// Change runtime settings. Those you leave out keep their values
    #[command(group(
        clap::ArgGroup::new("setting")
            .required(true)
            .multiple(true)
            .args(["guest_access", "hidden_nav_items", "no_hidden_nav_items", "upstream_jobs_paused"])
    ))]
    Update {
        /// Allow anonymous access to public repositories
        #[arg(long, action = ArgAction::Set)]
        guest_access: Option<bool>,

        /// Hide these web UI navigation entries from every user, comma-separated, such
        /// as /peers. Replaces the list. A hidden page stays reachable by its URL, with
        /// the same permission checks. Needs a 1.12 server
        #[arg(long, value_delimiter = ',', conflicts_with = "no_hidden_nav_items")]
        hidden_nav_items: Option<Vec<String>>,

        /// Show every web UI navigation entry again. Needs a 1.12 server
        #[arg(long)]
        no_hidden_nav_items: bool,

        /// Pause (true) or resume (false) every scheduled job that contacts an upstream
        /// on its own: curation sync, environment re-evaluation, the npm feed, peer
        /// replication and scheduled mirrors. Needs a 1.12 server
        #[arg(long, action = ArgAction::Set)]
        upstream_jobs_paused: Option<bool>,
    },
}

#[derive(Subcommand)]
pub enum TokenPolicyCommand {
    /// Show the API token expiration policy
    Show,

    /// Change the API token expiration policy. Fields you leave out keep their
    /// current values
    Set {
        /// Require every new token to expire
        #[arg(long, action = ArgAction::Set)]
        require_expiration: Option<bool>,

        /// Shortest allowed lifetime, in days
        #[arg(long)]
        min_days: Option<i64>,

        /// Longest allowed lifetime, in days
        #[arg(long)]
        max_days: Option<i64>,

        /// Lifetime of a token created without one, in days
        #[arg(long, conflicts_with = "no_default_days")]
        default_days: Option<i64>,

        /// Clear the default lifetime
        #[arg(long)]
        no_default_days: bool,

        /// Apply the policy to service account tokens too
        #[arg(long, action = ArgAction::Set)]
        apply_to_service_accounts: Option<bool>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum TotpPolicyArg {
    /// Nobody has to use two-factor authentication
    Disabled,
    /// Local admins have to
    RequiredForAdmins,
    /// All local users have to
    RequiredForAll,
}

#[derive(Subcommand)]
pub enum TotpPolicyCommand {
    /// Show the two-factor authentication policy and enrollment counts
    Show,

    /// Change the two-factor authentication policy
    Set {
        /// The new policy
        #[arg(value_enum, value_name = "POLICY")]
        policy: TotpPolicyArg,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

impl SystemCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        let (resp, raw, done) = match self {
            Self::Show => {
                let (resp, raw) =
                    artifact_keeper_sdk::raw::capture(client.get_runtime_settings().send()).await;
                let resp = resp.map_err(|e| sdk_err("get runtime settings", e))?;
                (resp, raw, None)
            }
            Self::Update {
                guest_access,
                hidden_nav_items,
                no_hidden_nav_items,
                upstream_jobs_paused,
            } => {
                if hidden_nav_items
                    .as_ref()
                    .is_some_and(|items| items.iter().any(|i| i.trim().is_empty()))
                {
                    return Err(AkError::Usage(
                        "--hidden-nav-items has an empty entry. To show every entry again, use \
                         --no-hidden-nav-items"
                            .into(),
                    )
                    .into());
                }
                let hidden_nav_items = match (hidden_nav_items, no_hidden_nav_items) {
                    (_, true) => Some(Vec::new()),
                    (items, false) => items,
                };
                // A 1.11 server refuses the whole body with a 422 that names the
                // field, not the version.
                let mut newer = Vec::new();
                if hidden_nav_items.is_some() {
                    newer.push(if no_hidden_nav_items {
                        "--no-hidden-nav-items"
                    } else {
                        "--hidden-nav-items"
                    });
                }
                if upstream_jobs_paused.is_some() {
                    newer.push("--upstream-jobs-paused");
                }
                refuse_flags_before(&newer, (1, 12), global).await?;
                let body = UpdateRuntimeSettingsRequest {
                    guest_access_enabled: guest_access,
                    hidden_nav_items,
                    upstream_jobs_paused,
                };
                let (resp, raw) = artifact_keeper_sdk::raw::capture(
                    client.update_runtime_settings().body(body).send(),
                )
                .await;
                let resp = resp.map_err(|e| sdk_err("update runtime settings", e))?;
                (resp, raw, Some("Runtime settings updated."))
            }
        };
        let settings: RuntimeSettingsResponse = resp.into_inner();
        if matches!(global.format, OutputFormat::Quiet) {
            println!("{}", settings.guest_access_enabled);
            return Ok(());
        }
        if let (Some(done), OutputFormat::Table) = (done, &global.format) {
            eprintln!("{done}");
        }
        let mut table = format!(
            "Guest access:   {}\n\
             Source:         {}\n\
             Editable:       {}\n\
             Stored value:   {}",
            settings.guest_access_enabled,
            settings.guest_access_source,
            settings.guest_access_editable,
            settings
                .guest_access_stored
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
        );
        // A 1.11 server has neither.
        if let Some(paused) = settings.upstream_jobs_paused {
            table.push_str(&format!(
                "\n\nUpstream jobs paused: {paused}\n\
                 Source:               {}\n\
                 Stored value:         {}\n\
                 Hidden nav items:     {}",
                settings
                    .upstream_jobs_paused_source
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".into()),
                settings
                    .upstream_jobs_paused_stored
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into()),
                if settings.hidden_nav_items.is_empty() {
                    "none".to_string()
                } else {
                    settings.hidden_nav_items.join(", ")
                },
            ));
        }
        println!(
            "{}",
            output::render_raw(raw.as_deref(), &settings, &global.format, Some(table))
        );
        Ok(())
    }
}

impl TokenPolicyCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        let (resp, raw, done) = match self {
            Self::Show => {
                let (resp, raw) =
                    artifact_keeper_sdk::raw::capture(client.get_token_policy().send()).await;
                (resp.map_err(|e| sdk_err("get token policy", e))?, raw, None)
            }
            Self::Set {
                require_expiration,
                min_days,
                max_days,
                default_days,
                no_default_days,
                apply_to_service_accounts,
            } => {
                if require_expiration.is_none()
                    && min_days.is_none()
                    && max_days.is_none()
                    && default_days.is_none()
                    && !no_default_days
                    && apply_to_service_accounts.is_none()
                {
                    return Err(AkError::Usage(
                        "Nothing to change. Run `ak admin settings token-policy set --help` to \
                         see the fields."
                            .into(),
                    )
                    .into());
                }
                // The route replaces the whole policy and most fields are required.
                let mut policy = client
                    .get_token_policy()
                    .send()
                    .await
                    .map_err(|e| sdk_err("get token policy", e))?
                    .into_inner()
                    .policy;
                if let Some(value) = require_expiration {
                    policy.require_expiration = value;
                }
                if let Some(value) = min_days {
                    policy.min_days = value;
                }
                if let Some(value) = max_days {
                    policy.max_days = value;
                }
                if default_days.is_some() || no_default_days {
                    policy.default_days = default_days;
                }
                if apply_to_service_accounts.is_some() {
                    policy.apply_to_service_accounts = apply_to_service_accounts;
                }
                let (resp, raw) = artifact_keeper_sdk::raw::capture(
                    client
                        .update_token_policy()
                        .body(UpdateTokenPolicyRequest { policy })
                        .send(),
                )
                .await;
                (
                    resp.map_err(|e| sdk_err("update token policy", e))?,
                    raw,
                    Some("Token policy updated."),
                )
            }
        };
        let resp: TokenPolicyResponse = resp.into_inner();
        if matches!(global.format, OutputFormat::Quiet) {
            println!("{}", resp.policy.require_expiration);
            return Ok(());
        }
        if let (Some(done), OutputFormat::Table) = (done, &global.format) {
            eprintln!("{done}");
        }
        let table = format!(
            "Require expiration:             {}\n\
             Minimum days:                   {}\n\
             Maximum days:                   {}\n\
             Default days:                   {}\n\
             Applies to service accounts:    {}\n\
             Source:                         {}\n\
             Editable:                       {}\n\
             Non-expiring user tokens:       {}\n\
             Non-expiring service tokens:    {}",
            resp.policy.require_expiration,
            resp.policy.min_days,
            resp.policy.max_days,
            resp.policy
                .default_days
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            resp.policy
                .apply_to_service_accounts
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            resp.source,
            resp.editable,
            resp.non_expiring_user_tokens,
            resp.non_expiring_service_account_tokens,
        );
        println!(
            "{}",
            output::render_raw(raw.as_deref(), &resp, &global.format, Some(table))
        );
        Ok(())
    }
}

impl TotpPolicyCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        let client = client_for(global)?;
        let (resp, raw, done) = match self {
            Self::Show => {
                let (resp, raw) =
                    artifact_keeper_sdk::raw::capture(client.get_totp_policy().send()).await;
                (resp.map_err(|e| sdk_err("get TOTP policy", e))?, raw, None)
            }
            Self::Set { policy, yes } => {
                let policy = match policy {
                    TotpPolicyArg::Disabled => TotpPolicy::Disabled,
                    TotpPolicyArg::RequiredForAdmins => TotpPolicy::RequiredForAdmins,
                    TotpPolicyArg::RequiredForAll => TotpPolicy::RequiredForAll,
                };
                let prompt = format!(
                    "Set the two-factor authentication policy to {policy}? It changes what \
                     every affected user has to do to log in."
                );
                if !confirm_action(&prompt, yes, global.no_input)? {
                    return Ok(());
                }
                let (resp, raw) = artifact_keeper_sdk::raw::capture(
                    client
                        .update_totp_policy()
                        .body(UpdateTotpPolicyRequest { policy })
                        .send(),
                )
                .await;
                (
                    resp.map_err(|e| sdk_err("update TOTP policy", e))?,
                    raw,
                    Some("Two-factor authentication policy updated."),
                )
            }
        };
        let resp: TotpPolicyResponse = resp.into_inner();
        if matches!(global.format, OutputFormat::Quiet) {
            println!("{}", resp.policy);
            return Ok(());
        }
        if let (Some(done), OutputFormat::Table) = (done, &global.format) {
            eprintln!("{done}");
        }
        let table = format!(
            "Policy:               {}\n\
             Source:               {}\n\
             Editable:             {}\n\
             Local admins:         {} ({} with TOTP)\n\
             Local users:          {} ({} with TOTP)\n\
             You have TOTP:        {}",
            resp.policy,
            resp.source,
            resp.editable,
            resp.local_admins,
            resp.local_admins_with_totp,
            resp.local_users,
            resp.local_users_with_totp,
            resp.caller_totp_enabled,
        );
        println!(
            "{}",
            output::render_raw(raw.as_deref(), &resp, &global.format, Some(table))
        );
        Ok(())
    }
}
