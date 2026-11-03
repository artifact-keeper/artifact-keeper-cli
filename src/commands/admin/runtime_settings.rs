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
use crate::commands::helpers::{confirm_action, or_since_1_11, sdk_err};
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum SystemCommand {
    /// Show the runtime settings and where each value comes from
    Show,

    /// Change a runtime setting
    Update {
        /// Allow anonymous access to public repositories
        #[arg(long, action = ArgAction::Set, required = true)]
        guest_access: Option<bool>,
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
        #[arg(long)]
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
                let resp = or_since_1_11(
                    resp,
                    "get runtime settings",
                    "admin settings system",
                    global,
                )
                .await?;
                (resp, raw, None)
            }
            Self::Update { guest_access } => {
                let body = UpdateRuntimeSettingsRequest {
                    guest_access_enabled: guest_access,
                };
                let (resp, raw) = artifact_keeper_sdk::raw::capture(
                    client.update_runtime_settings().body(body).send(),
                )
                .await;
                let resp = or_since_1_11(
                    resp,
                    "update runtime settings",
                    "admin settings system",
                    global,
                )
                .await?;
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
        let table = format!(
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
