use artifact_keeper_sdk::ClientApprovalExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum ApprovalCommand {
    /// List pending approvals
    List {
        /// Filter by status (pending, approved, rejected)
        #[arg(long)]
        status: Option<String>,

        /// Filter by source repository
        #[arg(long)]
        repo: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: i32,
    },

    /// Show approval details
    Show {
        /// Approval ID
        id: String,
    },

    /// Approve a pending promotion
    Approve {
        /// Approval ID
        id: String,

        /// Review notes
        #[arg(long)]
        comment: Option<String>,
    },

    /// Reject a pending promotion
    Reject {
        /// Approval ID
        id: String,

        /// Review notes
        #[arg(long)]
        comment: Option<String>,
    },
}

impl ApprovalCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List {
                status,
                repo,
                page,
                per_page,
            } => list_approvals(status.as_deref(), repo.as_deref(), page, per_page, global).await,
            Self::Show { id } => show_approval(&id, global).await,
            Self::Approve { id, comment } => {
                review_promotion(&id, comment.as_deref(), true, global).await
            }
            Self::Reject { id, comment } => {
                review_promotion(&id, comment.as_deref(), false, global).await
            }
        }
    }
}

async fn list_approvals(
    status: Option<&str>,
    repo: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching approvals...");

    // Use history endpoint when filtering by status, pending endpoint otherwise
    let resp = if status.is_some() {
        let mut req = client.list_approval_history().page(page).per_page(per_page);
        if let Some(s) = status {
            req = req.status(s);
        }
        if let Some(r) = repo {
            req = req.source_repository(r);
        }
        req.send().await.map_err(|e| sdk_err("list approvals", e))?
    } else {
        let mut req = client
            .list_pending_approvals()
            .page(page)
            .per_page(per_page);
        if let Some(r) = repo {
            req = req.source_repository(r);
        }
        req.send().await.map_err(|e| sdk_err("list approvals", e))?
    };

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No approvals found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for a in &resp.items {
            println!("{}", a.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|a| {
            serde_json::json!({
                "id": a.id.to_string(),
                "artifact_id": a.artifact_id.to_string(),
                "source_repository": a.source_repository,
                "target_repository": a.target_repository,
                "status": a.status,
                "requested_at": a.requested_at.to_rfc3339(),
                "reviewed_at": a.reviewed_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "SOURCE", "TARGET", "STATUS", "REQUESTED"]);

        for a in &resp.items {
            let id_short = short_id(&a.id);
            let date = a.requested_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![
                &id_short,
                &a.source_repository,
                &a.target_repository,
                &a.status,
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
            "Page {} of {} ({} total approvals)",
            resp.pagination.page, resp.pagination.total_pages, resp.pagination.total
        );
    }

    Ok(())
}

async fn show_approval(id: &str, global: &GlobalArgs) -> Result<()> {
    let approval_id = parse_uuid(id, "approval")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching approval...");

    let approval = client
        .get_approval()
        .id(approval_id)
        .send()
        .await
        .map_err(|e| sdk_err("get approval", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "id": approval.id.to_string(),
        "artifact_id": approval.artifact_id.to_string(),
        "source_repository": approval.source_repository,
        "target_repository": approval.target_repository,
        "status": approval.status,
        "requested_by": approval.requested_by.to_string(),
        "requested_at": approval.requested_at.to_rfc3339(),
        "reviewed_by": approval.reviewed_by.map(|u| u.to_string()),
        "reviewed_at": approval.reviewed_at.map(|t| t.to_rfc3339()),
        "notes": approval.notes,
        "review_notes": approval.review_notes,
    });

    let table_str = format!(
        "ID:               {}\n\
         Artifact:         {}\n\
         Source:           {}\n\
         Target:           {}\n\
         Status:           {}\n\
         Requested By:     {}\n\
         Requested At:     {}\n\
         Reviewed By:      {}\n\
         Reviewed At:      {}\n\
         Notes:            {}\n\
         Review Notes:     {}",
        approval.id,
        approval.artifact_id,
        approval.source_repository,
        approval.target_repository,
        approval.status,
        approval.requested_by,
        approval.requested_at.format("%Y-%m-%d %H:%M:%S UTC"),
        approval
            .reviewed_by
            .map(|u| u.to_string())
            .unwrap_or_else(|| "-".to_string()),
        approval
            .reviewed_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string()),
        approval.notes.as_deref().unwrap_or("-"),
        approval.review_notes.as_deref().unwrap_or("-"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

fn format_approval_table(items: &[serde_json::Value]) -> String {
    let mut table = new_table(vec!["ID", "SOURCE", "TARGET", "STATUS", "REQUESTED"]);

    for a in items {
        let id = a["id"].as_str().unwrap_or("-");
        let id_short = if id.len() >= 8 { &id[..8] } else { id };
        table.add_row(vec![
            id_short,
            a["source_repository"].as_str().unwrap_or("-"),
            a["target_repository"].as_str().unwrap_or("-"),
            a["status"].as_str().unwrap_or("-"),
            a["requested_at"].as_str().unwrap_or("-"),
        ]);
    }

    table.to_string()
}

fn format_approval_detail(item: &serde_json::Value) -> String {
    format!(
        "ID:               {}\n\
         Artifact:         {}\n\
         Source:           {}\n\
         Target:           {}\n\
         Status:           {}\n\
         Requested By:     {}\n\
         Requested At:     {}\n\
         Reviewed By:      {}\n\
         Reviewed At:      {}\n\
         Notes:            {}\n\
         Review Notes:     {}",
        item["id"].as_str().unwrap_or("-"),
        item["artifact_id"].as_str().unwrap_or("-"),
        item["source_repository"].as_str().unwrap_or("-"),
        item["target_repository"].as_str().unwrap_or("-"),
        item["status"].as_str().unwrap_or("-"),
        item["requested_by"].as_str().unwrap_or("-"),
        item["requested_at"].as_str().unwrap_or("-"),
        item["reviewed_by"].as_str().unwrap_or("-"),
        item["reviewed_at"].as_str().unwrap_or("-"),
        item["notes"].as_str().unwrap_or("-"),
        item["review_notes"].as_str().unwrap_or("-"),
    )
}

async fn review_promotion(
    id: &str,
    comment: Option<&str>,
    approve: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let approval_id = parse_uuid(id, "approval")?;

    let client = client_for(global)?;
    let action = if approve { "Approving" } else { "Rejecting" };
    let spinner = output::spinner(&format!("{action} promotion..."));

    let body = artifact_keeper_sdk::types::ReviewRequest {
        notes: comment.map(|s| s.to_string()),
    };

    let resp = if approve {
        client
            .approve_promotion()
            .id(approval_id)
            .body(body)
            .send()
            .await
            .map_err(|e| sdk_err("approve promotion", e))?
    } else {
        client
            .reject_promotion()
            .id(approval_id)
            .body(body)
            .send()
            .await
            .map_err(|e| sdk_err("reject promotion", e))?
    };

    spinner.finish_and_clear();
    let verb = if approve { "approved" } else { "rejected" };
    eprintln!(
        "Approval {} {verb} (artifact {} -> {}).",
        resp.id, resp.source_repository, resp.target_repository
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: ApprovalCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- parsing: list ----

    #[test]
    fn parse_list_defaults() {
        let cli = parse(&["test", "list"]);
        match cli.command {
            ApprovalCommand::List {
                status,
                repo,
                page,
                per_page,
            } => {
                assert!(status.is_none());
                assert!(repo.is_none());
                assert_eq!(page, 1);
                assert_eq!(per_page, 20);
            }
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn parse_list_with_status() {
        let cli = parse(&["test", "list", "--status", "pending"]);
        match cli.command {
            ApprovalCommand::List { status, .. } => {
                assert_eq!(status.as_deref(), Some("pending"));
            }
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn parse_list_with_repo() {
        let cli = parse(&["test", "list", "--repo", "maven-releases"]);
        match cli.command {
            ApprovalCommand::List { repo, .. } => {
                assert_eq!(repo.as_deref(), Some("maven-releases"));
            }
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn parse_list_with_all_options() {
        let cli = parse(&[
            "test",
            "list",
            "--status",
            "approved",
            "--repo",
            "npm-local",
            "--page",
            "3",
            "--per-page",
            "10",
        ]);
        match cli.command {
            ApprovalCommand::List {
                status,
                repo,
                page,
                per_page,
            } => {
                assert_eq!(status.as_deref(), Some("approved"));
                assert_eq!(repo.as_deref(), Some("npm-local"));
                assert_eq!(page, 3);
                assert_eq!(per_page, 10);
            }
            _ => panic!("expected List"),
        }
    }

    // ---- parsing: show ----

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "00000000-0000-0000-0000-000000000001"]);
        match cli.command {
            ApprovalCommand::Show { id } => {
                assert_eq!(id, "00000000-0000-0000-0000-000000000001");
            }
            _ => panic!("expected Show"),
        }
    }

    #[test]
    fn parse_show_missing_id() {
        let result = try_parse(&["test", "show"]);
        assert!(result.is_err());
    }

    // ---- parsing: approve ----

    #[test]
    fn parse_approve_no_comment() {
        let cli = parse(&["test", "approve", "some-id"]);
        match cli.command {
            ApprovalCommand::Approve { id, comment } => {
                assert_eq!(id, "some-id");
                assert!(comment.is_none());
            }
            _ => panic!("expected Approve"),
        }
    }

    #[test]
    fn parse_approve_with_comment() {
        let cli = parse(&["test", "approve", "some-id", "--comment", "Looks good"]);
        match cli.command {
            ApprovalCommand::Approve { id, comment } => {
                assert_eq!(id, "some-id");
                assert_eq!(comment.as_deref(), Some("Looks good"));
            }
            _ => panic!("expected Approve"),
        }
    }

    #[test]
    fn parse_approve_missing_id() {
        let result = try_parse(&["test", "approve"]);
        assert!(result.is_err());
    }

    // ---- parsing: reject ----

    #[test]
    fn parse_reject_no_comment() {
        let cli = parse(&["test", "reject", "some-id"]);
        match cli.command {
            ApprovalCommand::Reject { id, comment } => {
                assert_eq!(id, "some-id");
                assert!(comment.is_none());
            }
            _ => panic!("expected Reject"),
        }
    }

    #[test]
    fn parse_reject_with_comment() {
        let cli = parse(&[
            "test",
            "reject",
            "some-id",
            "--comment",
            "Needs security review",
        ]);
        match cli.command {
            ApprovalCommand::Reject { id, comment } => {
                assert_eq!(id, "some-id");
                assert_eq!(comment.as_deref(), Some("Needs security review"));
            }
            _ => panic!("expected Reject"),
        }
    }

    // ---- format functions ----

    #[test]
    fn format_approval_table_renders() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "artifact_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "source_repository": "maven-staging",
            "target_repository": "maven-releases",
            "status": "pending",
            "requested_at": "2026-01-15 12:00",
        })];
        let table = format_approval_table(&items);
        assert!(table.contains("00000000"));
        assert!(table.contains("maven-staging"));
        assert!(table.contains("maven-releases"));
        assert!(table.contains("pending"));
    }

    #[test]
    fn format_approval_table_multiple_rows() {
        let items = vec![
            json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "source_repository": "npm-staging",
                "target_repository": "npm-releases",
                "status": "pending",
                "requested_at": "2026-01-15",
            }),
            json!({
                "id": "11111111-1111-1111-1111-111111111111",
                "source_repository": "pypi-staging",
                "target_repository": "pypi-releases",
                "status": "approved",
                "requested_at": "2026-01-16",
            }),
        ];
        let table = format_approval_table(&items);
        assert!(table.contains("npm-staging"));
        assert!(table.contains("pypi-staging"));
        assert!(table.contains("pending"));
        assert!(table.contains("approved"));
    }

    #[test]
    fn format_approval_detail_renders() {
        let item = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "artifact_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "source_repository": "maven-staging",
            "target_repository": "maven-releases",
            "status": "pending",
            "requested_by": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "requested_at": "2026-01-15T12:00:00Z",
            "reviewed_by": null,
            "reviewed_at": null,
            "notes": "Please promote to production",
            "review_notes": null,
        });
        let detail = format_approval_detail(&item);
        assert!(detail.contains("00000000-0000-0000-0000-000000000001"));
        assert!(detail.contains("maven-staging"));
        assert!(detail.contains("maven-releases"));
        assert!(detail.contains("pending"));
        assert!(detail.contains("Please promote to production"));
    }

    #[test]
    fn format_approval_detail_all_null_optionals() {
        let item = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "artifact_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "source_repository": "src",
            "target_repository": "tgt",
            "status": "pending",
            "requested_by": "user-1",
            "requested_at": "2026-01-01",
            "reviewed_by": null,
            "reviewed_at": null,
            "notes": null,
            "review_notes": null,
        });
        let detail = format_approval_detail(&item);
        assert!(detail.contains("Notes:"));
        assert!(detail.contains("Review Notes:"));
        // Null fields show as "-"
        let lines: Vec<&str> = detail.lines().collect();
        let notes_line = lines
            .iter()
            .find(|l| l.contains("Notes:") && !l.contains("Review"))
            .unwrap();
        assert!(notes_line.contains("-"));
    }

    #[test]
    fn format_approval_detail_with_review() {
        let item = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "artifact_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "source_repository": "staging",
            "target_repository": "releases",
            "status": "approved",
            "requested_by": "user-1",
            "requested_at": "2026-01-15T12:00:00Z",
            "reviewed_by": "user-2",
            "reviewed_at": "2026-01-16T09:00:00Z",
            "notes": "Ready for prod",
            "review_notes": "LGTM",
        });
        let detail = format_approval_detail(&item);
        assert!(detail.contains("approved"));
        assert!(detail.contains("user-2"));
        assert!(detail.contains("LGTM"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn approval_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "artifact_id": NIL_UUID,
            "source_repository": "maven-staging",
            "target_repository": "maven-releases",
            "status": "pending",
            "requested_by": NIL_UUID,
            "requested_at": "2026-01-15T12:00:00Z",
            "reviewed_by": null,
            "reviewed_at": null,
            "notes": "Please promote",
            "review_notes": null,
            "policy_result": null
        })
    }

    #[tokio::test]
    async fn handler_list_approvals_pending_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/approval/pending"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 20, "total": 0, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_approvals(None, None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_approvals_pending_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/approval/pending"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [approval_json()],
                "pagination": { "page": 1, "per_page": 20, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_approvals(None, None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_approvals_history() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/approval/history"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [approval_json()],
                "pagination": { "page": 1, "per_page": 20, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_approvals(Some("approved"), None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_approvals_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/approval/pending"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [approval_json()],
                "pagination": { "page": 1, "per_page": 20, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_approvals(None, None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_approval() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/approval/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(approval_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_approval(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_approve_promotion() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let mut approved = approval_json();
        approved["status"] = json!("approved");

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/approval/{NIL_UUID}/approve")))
            .respond_with(ResponseTemplate::new(200).set_body_json(approved))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = review_promotion(NIL_UUID, Some("LGTM"), true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_reject_promotion() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let mut rejected = approval_json();
        rejected["status"] = json!("rejected");

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/approval/{NIL_UUID}/reject")))
            .respond_with(ResponseTemplate::new(200).set_body_json(rejected))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = review_promotion(NIL_UUID, Some("Needs changes"), false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }
}
