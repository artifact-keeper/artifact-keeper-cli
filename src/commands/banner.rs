use artifact_keeper_sdk::ClientBannersExt;
use artifact_keeper_sdk::types::{
    AdminBanner, BannerInput, BannerSeverity, BannerTarget, PublicBanner,
};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use miette::Result;

use super::client::{client_for, client_for_optional_auth};
use super::helpers::{
    confirm_action, emit_mutation, emit_mutation_raw, new_table, or_since_1_11, parse_uuid,
};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

/// The group, for the message on a server older than these routes.
const COMMAND: &str = "banner";

const SEVERITIES: [&str; 3] = ["info", "warning", "critical"];
const TARGETS: [&str; 3] = ["all", "ui", "api"];

#[derive(Subcommand)]
pub enum BannerCommand {
    /// Show the banners active right now. Needs no login
    Active {
        /// Only banners for this surface
        #[arg(long, value_parser = TARGETS)]
        target: Option<String>,
    },

    /// List every banner, active or not (admin only)
    List,

    /// Show a banner (admin only)
    Show {
        /// Banner ID
        id: String,
    },

    /// Create a banner (admin only)
    Create {
        /// Banner title
        title: String,

        /// Banner text
        #[arg(long)]
        message: String,

        /// Visual weight (server default: info)
        #[arg(long, value_parser = SEVERITIES)]
        severity: Option<String>,

        /// Surface it's for (server default: all)
        #[arg(long, value_parser = TARGETS)]
        target: Option<String>,

        /// Call-to-action link, http or https
        #[arg(long)]
        link_url: Option<String>,

        /// Show from this RFC 3339 time (default: immediately)
        #[arg(long, value_name = "TIME")]
        starts_at: Option<String>,

        /// Hide from this RFC 3339 time (default: until disabled or deleted)
        #[arg(long, value_name = "TIME")]
        ends_at: Option<String>,

        /// Create it disabled
        #[arg(long)]
        disabled: bool,
    },

    /// Update a banner (admin only). Only what you pass changes
    Update {
        /// Banner ID
        id: String,

        /// New title
        #[arg(long)]
        title: Option<String>,

        /// New text
        #[arg(long)]
        message: Option<String>,

        /// New visual weight
        #[arg(long, value_parser = SEVERITIES)]
        severity: Option<String>,

        /// New surface
        #[arg(long, value_parser = TARGETS)]
        target: Option<String>,

        /// New call-to-action link, http or https
        #[arg(long, conflicts_with = "no_link_url")]
        link_url: Option<String>,

        /// Remove the link
        #[arg(long)]
        no_link_url: bool,

        /// Show from this RFC 3339 time
        #[arg(long, value_name = "TIME", conflicts_with = "no_starts_at")]
        starts_at: Option<String>,

        /// Show immediately
        #[arg(long)]
        no_starts_at: bool,

        /// Hide from this RFC 3339 time
        #[arg(long, value_name = "TIME", conflicts_with = "no_ends_at")]
        ends_at: Option<String>,

        /// Show until disabled or deleted
        #[arg(long)]
        no_ends_at: bool,

        /// Enable the banner
        #[arg(long, conflicts_with = "disable")]
        enable: bool,

        /// Disable the banner
        #[arg(long)]
        disable: bool,
    },

    /// Delete a banner (admin only)
    Delete {
        /// Banner ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

impl BannerCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Active { target } => list_active(target.as_deref(), global).await,
            Self::List => list_banners(global).await,
            Self::Show { id } => show_banner(&id, global).await,
            Self::Create {
                title,
                message,
                severity,
                target,
                link_url,
                starts_at,
                ends_at,
                disabled,
            } => {
                let input = BannerInput {
                    // Unset leaves the server's default: enabled.
                    enabled: disabled.then_some(false),
                    ends_at: parse_time(ends_at.as_deref(), "--ends-at")?,
                    link_url,
                    message,
                    severity: severity.as_deref().map(parse_severity).transpose()?,
                    starts_at: parse_time(starts_at.as_deref(), "--starts-at")?,
                    target: target.as_deref().map(parse_target).transpose()?,
                    title,
                };
                create_banner(input, global).await
            }
            Self::Update {
                id,
                title,
                message,
                severity,
                target,
                link_url,
                no_link_url,
                starts_at,
                no_starts_at,
                ends_at,
                no_ends_at,
                enable,
                disable,
            } => {
                let changes = BannerChanges {
                    title,
                    message,
                    severity: severity.as_deref().map(parse_severity).transpose()?,
                    target: target.as_deref().map(parse_target).transpose()?,
                    link_url: Change::of(link_url, no_link_url),
                    starts_at: Change::of(
                        parse_time(starts_at.as_deref(), "--starts-at")?,
                        no_starts_at,
                    ),
                    ends_at: Change::of(parse_time(ends_at.as_deref(), "--ends-at")?, no_ends_at),
                    enabled: (enable || disable).then_some(enable),
                };
                update_banner(&id, changes, global).await
            }
            Self::Delete { id, yes } => delete_banner(&id, yes, global).await,
        }
    }
}

fn parse_severity(value: &str) -> Result<BannerSeverity> {
    value
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid severity: {value}")).into())
}

fn parse_target(value: &str) -> Result<BannerTarget> {
    value
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid target: {value}")).into())
}

pub(super) fn parse_time(value: Option<&str>, flag: &str) -> Result<Option<DateTime<Utc>>> {
    value
        .map(|v| {
            DateTime::parse_from_rfc3339(v)
                .map(|t| t.with_timezone(&Utc))
                .map_err(|_| {
                    AkError::ConfigError(format!(
                        "{flag} needs an RFC 3339 time such as 2026-12-01T09:00:00Z, not '{v}'"
                    ))
                    .into()
                })
        })
        .transpose()
}

/// A nullable field in `banner update`: leave it, set it, or clear it.
#[derive(Debug, PartialEq)]
enum Change<T> {
    Keep,
    Set(T),
    Clear,
}

impl<T> Change<T> {
    fn of(value: Option<T>, clear: bool) -> Self {
        match (value, clear) {
            (Some(value), _) => Self::Set(value),
            (None, true) => Self::Clear,
            (None, false) => Self::Keep,
        }
    }

    fn apply(self, current: Option<T>) -> Option<T> {
        match self {
            Self::Keep => current,
            Self::Set(value) => Some(value),
            Self::Clear => None,
        }
    }
}

struct BannerChanges {
    title: Option<String>,
    message: Option<String>,
    severity: Option<BannerSeverity>,
    target: Option<BannerTarget>,
    link_url: Change<String>,
    starts_at: Change<DateTime<Utc>>,
    ends_at: Change<DateTime<Utc>>,
    enabled: Option<bool>,
}

/// The API replaces a banner whole, so an update sends everything: the changes on
/// top of what's stored.
fn merged_input(current: AdminBanner, changes: BannerChanges) -> BannerInput {
    BannerInput {
        enabled: Some(changes.enabled.unwrap_or(current.enabled)),
        ends_at: changes.ends_at.apply(current.ends_at),
        link_url: changes.link_url.apply(current.link_url),
        message: changes.message.unwrap_or(current.message),
        severity: Some(changes.severity.unwrap_or(current.severity)),
        starts_at: changes.starts_at.apply(current.starts_at),
        target: Some(changes.target.unwrap_or(current.target)),
        title: changes.title.unwrap_or(current.title),
    }
}

async fn list_active(target: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let target = target.map(parse_target).transpose()?;
    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching active banners...");
    let mut req = client.list_active_banners();
    if let Some(target) = target {
        req = req.target(target);
    }
    let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
    let list = or_since_1_11(resp, "list active banners", COMMAND, global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    if list.banners.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No active banners.");
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for banner in &list.banners {
            println!("{}", banner.id);
        }
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &list,
            &global.format,
            Some(active_table(&list.banners))
        )
    );
    Ok(())
}

async fn list_banners(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching banners...");
    let (resp, raw) = artifact_keeper_sdk::raw::capture(client.list_banners().send()).await;
    let list = or_since_1_11(resp, "list banners", COMMAND, global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    if list.banners.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No banners found.");
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for banner in &list.banners {
            println!("{}", banner.id);
        }
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &list,
            &global.format,
            Some(banners_table(&list.banners))
        )
    );
    Ok(())
}

async fn show_banner(id: &str, global: &GlobalArgs) -> Result<()> {
    let banner_id = parse_uuid(id, "banner")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching banner...");
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.get_banner().id(banner_id).send()).await;
    let banner = or_since_1_11(resp, "get banner", COMMAND, global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", banner.id);
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &banner,
            &global.format,
            Some(banner_detail(&banner))
        )
    );
    Ok(())
}

async fn create_banner(input: BannerInput, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Creating banner...");
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.create_banner().body(input).send()).await;
    let banner = or_since_1_11(resp, "create banner", COMMAND, global).await?;
    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &*banner,
        &banner.id.to_string(),
        &format!("Banner '{}' created (ID: {}).", banner.title, banner.id),
        global,
    );
    Ok(())
}

async fn update_banner(id: &str, changes: BannerChanges, global: &GlobalArgs) -> Result<()> {
    let banner_id = parse_uuid(id, "banner")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Updating banner...");
    let current = or_since_1_11(
        client.get_banner().id(banner_id).send().await,
        "get banner",
        COMMAND,
        global,
    )
    .await?
    .into_inner();
    let input = merged_input(current, changes);
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.update_banner().id(banner_id).body(input).send())
            .await;
    let banner = or_since_1_11(resp, "update banner", COMMAND, global).await?;
    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &*banner,
        &banner.id.to_string(),
        &format!("Banner '{}' updated.", banner.title),
        global,
    );
    Ok(())
}

async fn delete_banner(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let banner_id = parse_uuid(id, "banner")?;
    if !confirm_action(
        &format!("Delete banner {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }
    let client = client_for(global)?;
    let spinner = output::spinner("Deleting banner...");
    or_since_1_11(
        client.delete_banner().id(banner_id).send().await,
        "delete banner",
        COMMAND,
        global,
    )
    .await?;
    spinner.finish_and_clear();

    emit_mutation(
        &serde_json::json!({ "id": id, "status": "deleted" }),
        id,
        &format!("Banner {id} deleted."),
        global,
    );
    Ok(())
}

fn time(value: Option<DateTime<Utc>>) -> String {
    value
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| "-".to_string())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn active_table(banners: &[PublicBanner]) -> String {
    let mut table = new_table(vec!["ID", "SEVERITY", "TARGET", "TITLE", "MESSAGE", "ENDS"]);
    for b in banners {
        table.add_row(vec![
            b.id.to_string(),
            b.severity.to_string(),
            b.target.to_string(),
            b.title.clone(),
            b.message.clone(),
            time(b.ends_at),
        ]);
    }
    table.to_string()
}

fn banners_table(banners: &[AdminBanner]) -> String {
    let mut table = new_table(vec![
        "ID", "SEVERITY", "TARGET", "TITLE", "ENABLED", "ACTIVE", "STARTS", "ENDS",
    ]);
    for b in banners {
        table.add_row(vec![
            b.id.to_string(),
            b.severity.to_string(),
            b.target.to_string(),
            b.title.clone(),
            yes_no(b.enabled).to_string(),
            yes_no(b.active).to_string(),
            time(b.starts_at),
            time(b.ends_at),
        ]);
    }
    table.to_string()
}

fn banner_detail(b: &AdminBanner) -> String {
    format!(
        "ID:       {}\n\
         Title:    {}\n\
         Message:  {}\n\
         Severity: {}\n\
         Target:   {}\n\
         Link:     {}\n\
         Enabled:  {}\n\
         Active:   {}\n\
         Starts:   {}\n\
         Ends:     {}\n\
         Created:  {}\n\
         Updated:  {}",
        b.id,
        b.title,
        b.message,
        b.severity,
        b.target,
        b.link_url.as_deref().unwrap_or("-"),
        yes_no(b.enabled),
        yes_no(b.active),
        time(b.starts_at),
        time(b.ends_at),
        b.created_at.to_rfc3339(),
        b.updated_at.to_rfc3339(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    fn stored() -> AdminBanner {
        AdminBanner {
            active: true,
            created_at: at("2026-01-15T12:00:00Z"),
            created_by: None,
            enabled: true,
            ends_at: Some(at("2026-03-01T00:00:00Z")),
            id: uuid::Uuid::nil(),
            link_url: Some("https://status.example.com".to_string()),
            message: "stored message".to_string(),
            severity: BannerSeverity::Warning,
            starts_at: Some(at("2026-02-01T00:00:00Z")),
            target: BannerTarget::Ui,
            title: "stored title".to_string(),
            updated_at: at("2026-01-15T12:00:00Z"),
            updated_by: None,
        }
    }

    fn no_changes() -> BannerChanges {
        BannerChanges {
            title: None,
            message: None,
            severity: None,
            target: None,
            link_url: Change::Keep,
            starts_at: Change::Keep,
            ends_at: Change::Keep,
            enabled: None,
        }
    }

    #[test]
    fn an_update_keeps_what_it_was_not_told_to_change() {
        let mut changes = no_changes();
        changes.title = Some("new title".to_string());
        let input = merged_input(stored(), changes);
        assert_eq!(input.title, "new title");
        assert_eq!(input.message, "stored message");
        assert_eq!(input.enabled, Some(true));
        assert_eq!(input.severity, Some(BannerSeverity::Warning));
        assert_eq!(input.target, Some(BannerTarget::Ui));
        assert_eq!(
            input.link_url.as_deref(),
            Some("https://status.example.com")
        );
        assert_eq!(input.starts_at, Some(at("2026-02-01T00:00:00Z")));
        assert_eq!(input.ends_at, Some(at("2026-03-01T00:00:00Z")));
    }

    #[test]
    fn an_update_can_clear_the_nullable_fields() {
        let mut changes = no_changes();
        changes.link_url = Change::Clear;
        changes.starts_at = Change::Clear;
        changes.ends_at = Change::Clear;
        changes.enabled = Some(false);
        let input = merged_input(stored(), changes);
        assert_eq!(input.link_url, None);
        assert_eq!(input.starts_at, None);
        assert_eq!(input.ends_at, None);
        assert_eq!(input.enabled, Some(false));
    }

    #[test]
    fn times_must_be_rfc3339() {
        assert_eq!(
            parse_time(Some("2026-12-01T10:00:00+01:00"), "--ends-at").unwrap(),
            Some(at("2026-12-01T09:00:00Z"))
        );
        assert!(parse_time(Some("tomorrow"), "--ends-at").is_err());
        assert_eq!(parse_time(None, "--ends-at").unwrap(), None);
    }

    #[test]
    fn the_flag_values_are_the_ones_the_sdk_accepts() {
        for value in SEVERITIES {
            parse_severity(value).unwrap();
        }
        for value in TARGETS {
            parse_target(value).unwrap();
        }
    }

    #[test]
    fn the_detail_shows_what_is_stored() {
        let detail = banner_detail(&stored());
        assert!(detail.contains("Severity: warning"));
        assert!(detail.contains("Link:     https://status.example.com"));
    }
}
