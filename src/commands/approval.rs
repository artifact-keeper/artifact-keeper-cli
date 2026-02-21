use artifact_keeper_sdk::ClientApprovalExt;
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::Result;

use super::client::client_for;
use crate::cli::GlobalArgs;
use crate::error::AkError;
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
                approve_promotion(&id, comment.as_deref(), global).await
            }
            Self::Reject { id, comment } => reject_promotion(&id, comment.as_deref(), global).await,
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
        req.send()
            .await
            .map_err(|e| AkError::ServerError(format!("Failed to list approvals: {e}")))?
    } else {
        let mut req = client
            .list_pending_approvals()
            .page(page)
            .per_page(per_page);
        if let Some(r) = repo {
            req = req.source_repository(r);
        }
        req.send()
            .await
            .map_err(|e| AkError::ServerError(format!("Failed to list approvals: {e}")))?
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
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["ID", "SOURCE", "TARGET", "STATUS", "REQUESTED"]);

        for a in &resp.items {
            let id_short = &a.id.to_string()[..8];
            let date = a.requested_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![
                id_short,
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
    let approval_id: uuid::Uuid = id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid approval ID: {id}")))?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching approval...");

    let approval = client
        .get_approval()
        .id(approval_id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get approval: {e}")))?;

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

async fn approve_promotion(id: &str, comment: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let approval_id: uuid::Uuid = id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid approval ID: {id}")))?;

    let client = client_for(global)?;
    let spinner = output::spinner("Approving promotion...");

    let body = artifact_keeper_sdk::types::ReviewRequest {
        notes: comment.map(|s| s.to_string()),
    };

    let resp = client
        .approve_promotion()
        .id(approval_id)
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to approve promotion: {e}")))?;

    spinner.finish_and_clear();
    eprintln!(
        "Approval {} approved (artifact {} -> {}).",
        resp.id, resp.source_repository, resp.target_repository
    );

    Ok(())
}

async fn reject_promotion(id: &str, comment: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let approval_id: uuid::Uuid = id
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid approval ID: {id}")))?;

    let client = client_for(global)?;
    let spinner = output::spinner("Rejecting promotion...");

    let body = artifact_keeper_sdk::types::ReviewRequest {
        notes: comment.map(|s| s.to_string()),
    };

    let resp = client
        .reject_promotion()
        .id(approval_id)
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to reject promotion: {e}")))?;

    spinner.finish_and_clear();
    eprintln!(
        "Approval {} rejected (artifact {} -> {}).",
        resp.id, resp.source_repository, resp.target_repository
    );

    Ok(())
}
