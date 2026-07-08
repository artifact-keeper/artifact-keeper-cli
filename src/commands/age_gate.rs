use artifact_keeper_sdk::ClientAgeGateExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum AgeGateCommand {
    /// Show the age-gate configuration for a repository
    Get {
        /// Repository key
        repo: String,
    },

    /// Update the age-gate configuration for a repository
    Set {
        /// Repository key
        repo: String,

        /// Minimum upstream age (in days) before a package is served
        #[arg(long, visible_alias = "threshold-days")]
        min_age_days: i32,

        /// Enable the age gate
        #[arg(long, conflicts_with = "disabled")]
        enabled: bool,

        /// Disable the age gate
        #[arg(long, conflicts_with = "enabled")]
        disabled: bool,
    },

    /// List age-gate review requests in the admin queue
    Reviews {
        /// Filter by repository key
        #[arg(long)]
        repo: Option<String>,

        /// Filter by status (pending, approved, rejected)
        #[arg(long)]
        status: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: i32,
    },

    /// Show a single age-gate review request
    Review {
        /// Review ID
        id: String,
    },

    /// Approve a pending age-gate review request
    Approve {
        /// Review ID
        id: String,

        /// Reason for the decision
        #[arg(long)]
        reason: Option<String>,
    },

    /// Reject a pending age-gate review request
    Reject {
        /// Review ID
        id: String,

        /// Reason for the decision
        #[arg(long)]
        reason: Option<String>,
    },
}

impl AgeGateCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Get { repo } => get_config(&repo, global).await,
            Self::Set {
                repo,
                min_age_days,
                enabled,
                disabled,
            } => set_config(&repo, min_age_days, enabled, disabled, global).await,
            Self::Reviews {
                repo,
                status,
                page,
                per_page,
            } => list_reviews(repo.as_deref(), status.as_deref(), page, per_page, global).await,
            Self::Review { id } => show_review(&id, global).await,
            Self::Approve { id, reason } => {
                review_decision(&id, reason.as_deref(), true, global).await
            }
            Self::Reject { id, reason } => {
                review_decision(&id, reason.as_deref(), false, global).await
            }
        }
    }
}

async fn get_config(repo: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching age-gate configuration...");

    let config = client
        .get_repo_age_gate()
        .key(repo)
        .send()
        .await
        .map_err(|e| sdk_err("get age-gate configuration", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "repository_key": config.repository_key,
        "enabled": config.enabled,
        "min_age_days": config.min_age_days,
    });

    let table_str = format_config_detail(&info);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn set_config(
    repo: &str,
    min_age_days: i32,
    enabled: bool,
    disabled: bool,
    global: &GlobalArgs,
) -> Result<()> {
    // Default to enabled unless --disabled was explicitly given.
    let is_enabled = !disabled || enabled;

    let client = client_for(global)?;
    let spinner = output::spinner("Updating age-gate configuration...");

    let body = artifact_keeper_sdk::types::UpdateAgeGateConfigRequest {
        enabled: is_enabled,
        min_age_days,
    };

    let config = client
        .update_repo_age_gate()
        .key(repo)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update age-gate configuration", e))?;

    spinner.finish_and_clear();

    eprintln!(
        "Age gate for '{}' is now {} (min age {} days).",
        config.repository_key,
        if config.enabled { "enabled" } else { "disabled" },
        config.min_age_days
    );

    let info = serde_json::json!({
        "repository_key": config.repository_key,
        "enabled": config.enabled,
        "min_age_days": config.min_age_days,
    });

    let table_str = format_config_detail(&info);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn list_reviews(
    repo: Option<&str>,
    status: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching age-gate reviews...");

    let mut req = client.list_reviews().page(page).per_page(per_page);
    if let Some(r) = repo {
        req = req.repository_key(r);
    }
    if let Some(s) = status {
        req = req.status(s);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("list age-gate reviews", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No age-gate reviews found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for r in &resp.items {
            println!("{}", r.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "repository_key": r.repository_key,
                "package_name": r.package_name,
                "package_version": r.package_version,
                "status": r.status,
                "request_count": r.request_count,
                "requested_at": r.requested_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID", "REPOSITORY", "PACKAGE", "VERSION", "STATUS", "REQ", "REQUESTED",
        ]);

        for r in &resp.items {
            let id_short = short_id(&r.id);
            let count = r.request_count.to_string();
            let date = r.requested_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![
                &id_short,
                &r.repository_key,
                &r.package_name,
                &r.package_version,
                &r.status,
                &count,
                &date,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    if resp.pagination.total_pages > 1 {
        eprintln!(
            "Page {} of {} ({} total reviews)",
            resp.pagination.page, resp.pagination.total_pages, resp.pagination.total
        );
    }

    Ok(())
}

async fn show_review(id: &str, global: &GlobalArgs) -> Result<()> {
    let review_id = parse_uuid(id, "review")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching age-gate review...");

    let review = client
        .get_review()
        .id(review_id)
        .send()
        .await
        .map_err(|e| sdk_err("get age-gate review", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "id": review.id.to_string(),
        "repository_key": review.repository_key,
        "package_name": review.package_name,
        "package_version": review.package_version,
        "status": review.status,
        "request_count": review.request_count,
        "requested_at": review.requested_at.to_rfc3339(),
        "last_requested_at": review.last_requested_at.to_rfc3339(),
        "upstream_published_at": review.upstream_published_at.map(|t| t.to_rfc3339()),
        "reviewed_by": review.reviewed_by.map(|u| u.to_string()),
        "reviewed_at": review.reviewed_at.map(|t| t.to_rfc3339()),
        "review_reason": review.review_reason,
    });

    let table_str = format_review_detail(&info);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn review_decision(
    id: &str,
    reason: Option<&str>,
    approve: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let review_id = parse_uuid(id, "review")?;

    let client = client_for(global)?;
    let action = if approve { "Approving" } else { "Rejecting" };
    let spinner = output::spinner(&format!("{action} age-gate review..."));

    let body = artifact_keeper_sdk::types::ReviewActionRequest {
        reason: reason.map(|s| s.to_string()),
    };

    let review = if approve {
        client
            .approve_review()
            .id(review_id)
            .body(body)
            .send()
            .await
            .map_err(|e| sdk_err("approve age-gate review", e))?
    } else {
        client
            .reject_review()
            .id(review_id)
            .body(body)
            .send()
            .await
            .map_err(|e| sdk_err("reject age-gate review", e))?
    };

    spinner.finish_and_clear();
    let verb = if approve { "approved" } else { "rejected" };
    eprintln!(
        "Review {} {verb} ({} {} in {}).",
        review.id, review.package_name, review.package_version, review.repository_key
    );

    Ok(())
}

fn format_config_detail(item: &serde_json::Value) -> String {
    format!(
        "Repository:       {}\n\
         Enabled:          {}\n\
         Min Age (days):   {}",
        item["repository_key"].as_str().unwrap_or("-"),
        if item["enabled"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        },
        item["min_age_days"].as_i64().unwrap_or(0),
    )
}

fn format_review_table(items: &[serde_json::Value]) -> String {
    let mut table = new_table(vec![
        "ID", "REPOSITORY", "PACKAGE", "VERSION", "STATUS", "REQ", "REQUESTED",
    ]);

    for r in items {
        let id = r["id"].as_str().unwrap_or("-");
        let id_short = if id.len() >= 8 { &id[..8] } else { id };
        table.add_row(vec![
            id_short,
            r["repository_key"].as_str().unwrap_or("-"),
            r["package_name"].as_str().unwrap_or("-"),
            r["package_version"].as_str().unwrap_or("-"),
            r["status"].as_str().unwrap_or("-"),
            &r["request_count"].as_i64().unwrap_or(0).to_string(),
            r["requested_at"].as_str().unwrap_or("-"),
        ]);
    }

    table.to_string()
}

fn format_review_detail(item: &serde_json::Value) -> String {
    format!(
        "ID:                {}\n\
         Repository:        {}\n\
         Package:           {}\n\
         Version:           {}\n\
         Status:            {}\n\
         Request Count:     {}\n\
         Requested At:      {}\n\
         Last Requested:    {}\n\
         Upstream Published:{}\n\
         Reviewed By:       {}\n\
         Reviewed At:       {}\n\
         Reason:            {}",
        item["id"].as_str().unwrap_or("-"),
        item["repository_key"].as_str().unwrap_or("-"),
        item["package_name"].as_str().unwrap_or("-"),
        item["package_version"].as_str().unwrap_or("-"),
        item["status"].as_str().unwrap_or("-"),
        item["request_count"].as_i64().unwrap_or(0),
        item["requested_at"].as_str().unwrap_or("-"),
        item["last_requested_at"].as_str().unwrap_or("-"),
        item["upstream_published_at"].as_str().unwrap_or("-"),
        item["reviewed_by"].as_str().unwrap_or("-"),
        item["reviewed_at"].as_str().unwrap_or("-"),
        item["review_reason"].as_str().unwrap_or("-"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: AgeGateCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- parsing: get ----

    #[test]
    fn parse_get() {
        let cli = parse(&["test", "get", "npm-proxy"]);
        match cli.command {
            AgeGateCommand::Get { repo } => assert_eq!(repo, "npm-proxy"),
            _ => panic!("expected Get"),
        }
    }

    #[test]
    fn parse_get_missing_repo() {
        assert!(try_parse(&["test", "get"]).is_err());
    }

    // ---- parsing: set ----

    #[test]
    fn parse_set_enabled() {
        let cli = parse(&["test", "set", "npm-proxy", "--min-age-days", "7", "--enabled"]);
        match cli.command {
            AgeGateCommand::Set {
                repo,
                min_age_days,
                enabled,
                disabled,
            } => {
                assert_eq!(repo, "npm-proxy");
                assert_eq!(min_age_days, 7);
                assert!(enabled);
                assert!(!disabled);
            }
            _ => panic!("expected Set"),
        }
    }

    #[test]
    fn parse_set_threshold_days_alias() {
        let cli = parse(&[
            "test",
            "set",
            "npm-proxy",
            "--threshold-days",
            "14",
            "--enabled",
        ]);
        match cli.command {
            AgeGateCommand::Set { min_age_days, .. } => assert_eq!(min_age_days, 14),
            _ => panic!("expected Set"),
        }
    }

    #[test]
    fn parse_set_disabled() {
        let cli = parse(&["test", "set", "npm-proxy", "--min-age-days", "0", "--disabled"]);
        match cli.command {
            AgeGateCommand::Set {
                enabled, disabled, ..
            } => {
                assert!(!enabled);
                assert!(disabled);
            }
            _ => panic!("expected Set"),
        }
    }

    #[test]
    fn parse_set_enabled_disabled_conflict() {
        let result = try_parse(&[
            "test",
            "set",
            "npm-proxy",
            "--min-age-days",
            "7",
            "--enabled",
            "--disabled",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_set_missing_min_age() {
        assert!(try_parse(&["test", "set", "npm-proxy", "--enabled"]).is_err());
    }

    // ---- parsing: reviews ----

    #[test]
    fn parse_reviews_defaults() {
        let cli = parse(&["test", "reviews"]);
        match cli.command {
            AgeGateCommand::Reviews {
                repo,
                status,
                page,
                per_page,
            } => {
                assert!(repo.is_none());
                assert!(status.is_none());
                assert_eq!(page, 1);
                assert_eq!(per_page, 20);
            }
            _ => panic!("expected Reviews"),
        }
    }

    #[test]
    fn parse_reviews_with_filters() {
        let cli = parse(&[
            "test",
            "reviews",
            "--repo",
            "npm-proxy",
            "--status",
            "pending",
            "--page",
            "2",
            "--per-page",
            "5",
        ]);
        match cli.command {
            AgeGateCommand::Reviews {
                repo,
                status,
                page,
                per_page,
            } => {
                assert_eq!(repo.as_deref(), Some("npm-proxy"));
                assert_eq!(status.as_deref(), Some("pending"));
                assert_eq!(page, 2);
                assert_eq!(per_page, 5);
            }
            _ => panic!("expected Reviews"),
        }
    }

    // ---- parsing: review / approve / reject ----

    #[test]
    fn parse_review_show() {
        let cli = parse(&["test", "review", "00000000-0000-0000-0000-000000000001"]);
        match cli.command {
            AgeGateCommand::Review { id } => {
                assert_eq!(id, "00000000-0000-0000-0000-000000000001");
            }
            _ => panic!("expected Review"),
        }
    }

    #[test]
    fn parse_approve_no_reason() {
        let cli = parse(&["test", "approve", "some-id"]);
        match cli.command {
            AgeGateCommand::Approve { id, reason } => {
                assert_eq!(id, "some-id");
                assert!(reason.is_none());
            }
            _ => panic!("expected Approve"),
        }
    }

    #[test]
    fn parse_approve_with_reason() {
        let cli = parse(&["test", "approve", "some-id", "--reason", "Vetted"]);
        match cli.command {
            AgeGateCommand::Approve { id, reason } => {
                assert_eq!(id, "some-id");
                assert_eq!(reason.as_deref(), Some("Vetted"));
            }
            _ => panic!("expected Approve"),
        }
    }

    #[test]
    fn parse_reject_with_reason() {
        let cli = parse(&["test", "reject", "some-id", "--reason", "Too new"]);
        match cli.command {
            AgeGateCommand::Reject { id, reason } => {
                assert_eq!(id, "some-id");
                assert_eq!(reason.as_deref(), Some("Too new"));
            }
            _ => panic!("expected Reject"),
        }
    }

    #[test]
    fn parse_approve_missing_id() {
        assert!(try_parse(&["test", "approve"]).is_err());
    }

    // ---- format functions ----

    #[test]
    fn format_config_detail_enabled() {
        let item = json!({
            "repository_key": "npm-proxy",
            "enabled": true,
            "min_age_days": 7,
        });
        let detail = format_config_detail(&item);
        assert!(detail.contains("npm-proxy"));
        assert!(detail.contains("yes"));
        assert!(detail.contains("7"));
    }

    #[test]
    fn format_config_detail_disabled() {
        let item = json!({
            "repository_key": "pypi-proxy",
            "enabled": false,
            "min_age_days": 0,
        });
        let detail = format_config_detail(&item);
        assert!(detail.contains("pypi-proxy"));
        assert!(detail.contains("no"));
    }

    #[test]
    fn format_review_table_renders() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "repository_key": "npm-proxy",
            "package_name": "left-pad",
            "package_version": "1.3.0",
            "status": "pending",
            "request_count": 5,
            "requested_at": "2026-07-01 12:00",
        })];
        let table = format_review_table(&items);
        assert!(table.contains("00000000"));
        assert!(table.contains("npm-proxy"));
        assert!(table.contains("left-pad"));
        assert!(table.contains("pending"));
    }

    #[test]
    fn format_review_table_multiple_rows() {
        let items = vec![
            json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "repository_key": "npm-proxy",
                "package_name": "left-pad",
                "package_version": "1.3.0",
                "status": "pending",
                "request_count": 5,
                "requested_at": "2026-07-01",
            }),
            json!({
                "id": "11111111-1111-1111-1111-111111111111",
                "repository_key": "pypi-proxy",
                "package_name": "requests",
                "package_version": "2.32.0",
                "status": "approved",
                "request_count": 2,
                "requested_at": "2026-07-02",
            }),
        ];
        let table = format_review_table(&items);
        assert!(table.contains("left-pad"));
        assert!(table.contains("requests"));
        assert!(table.contains("pending"));
        assert!(table.contains("approved"));
    }

    #[test]
    fn format_review_detail_renders() {
        let item = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "repository_key": "npm-proxy",
            "package_name": "left-pad",
            "package_version": "1.3.0",
            "status": "pending",
            "request_count": 5,
            "requested_at": "2026-07-01T12:00:00Z",
            "last_requested_at": "2026-07-02T12:00:00Z",
            "upstream_published_at": null,
            "reviewed_by": null,
            "reviewed_at": null,
            "review_reason": null,
        });
        let detail = format_review_detail(&item);
        assert!(detail.contains("left-pad"));
        assert!(detail.contains("pending"));
        // Null optionals render as "-"
        assert!(detail.contains("Reviewed By:"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn config_json() -> serde_json::Value {
        json!({
            "repository_key": "npm-proxy",
            "enabled": true,
            "min_age_days": 7,
        })
    }

    fn review_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "repository_key": "npm-proxy",
            "package_name": "left-pad",
            "package_version": "1.3.0",
            "status": "pending",
            "request_count": 5,
            "requested_at": "2026-07-01T12:00:00Z",
            "last_requested_at": "2026-07-02T12:00:00Z",
            "upstream_published_at": null,
            "reviewed_by": null,
            "reviewed_at": null,
            "review_reason": null
        })
    }

    #[tokio::test]
    async fn handler_get_config() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories/npm-proxy/age-gate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(config_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = get_config("npm-proxy", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_set_config() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path("/api/v1/repositories/npm-proxy/age-gate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(config_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = set_config("npm-proxy", 7, true, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_reviews_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/age-gate/reviews"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 20, "total": 0, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_reviews(None, None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_reviews_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/age-gate/reviews"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [review_json()],
                "pagination": { "page": 1, "per_page": 20, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_reviews(Some("npm-proxy"), Some("pending"), 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_reviews_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/age-gate/reviews"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [review_json()],
                "pagination": { "page": 1, "per_page": 20, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_reviews(None, None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_review() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/admin/age-gate/reviews/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(review_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_review(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_approve_review() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let mut approved = review_json();
        approved["status"] = json!("approved");

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/admin/age-gate/reviews/{NIL_UUID}/approve")))
            .respond_with(ResponseTemplate::new(200).set_body_json(approved))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = review_decision(NIL_UUID, Some("Vetted"), true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_reject_review() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let mut rejected = review_json();
        rejected["status"] = json!("rejected");

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/admin/age-gate/reviews/{NIL_UUID}/reject")))
            .respond_with(ResponseTemplate::new(200).set_body_json(rejected))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = review_decision(NIL_UUID, Some("Too new"), false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_age_gate_reviews_json() {
        let items = vec![review_json()];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("age_gate_reviews_json", parsed);
    }

    #[test]
    fn snapshot_age_gate_reviews_table() {
        let items = vec![review_json()];
        let table = format_review_table(&items);
        insta::assert_snapshot!("age_gate_reviews_table", table);
    }
}
