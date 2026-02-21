use artifact_keeper_sdk::ClientPermissionsExt;
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::Result;

use super::client::client_for;
use super::helpers::{confirm_action, parse_uuid, print_page_info};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum PermissionCommand {
    /// List permission rules
    List {
        /// Filter by target type (repository, group)
        #[arg(long)]
        target_type: Option<String>,

        /// Filter by principal type (user, group)
        #[arg(long)]
        principal_type: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "50")]
        per_page: i32,
    },

    /// Create a permission rule
    Create {
        /// Principal ID (user or group UUID)
        #[arg(long)]
        principal: String,

        /// Principal type (user, group)
        #[arg(long)]
        principal_type: String,

        /// Target ID (repository or group UUID)
        #[arg(long)]
        target: String,

        /// Target type (repository, group)
        #[arg(long)]
        target_type: String,

        /// Actions to grant (comma-separated: read, write, admin)
        #[arg(long, value_delimiter = ',')]
        actions: Vec<String>,
    },

    /// Delete a permission rule
    Delete {
        /// Permission ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

impl PermissionCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List {
                target_type,
                principal_type,
                page,
                per_page,
            } => {
                list_permissions(
                    target_type.as_deref(),
                    principal_type.as_deref(),
                    page,
                    per_page,
                    global,
                )
                .await
            }
            Self::Create {
                principal,
                principal_type,
                target,
                target_type,
                actions,
            } => {
                create_permission(
                    &principal,
                    &principal_type,
                    &target,
                    &target_type,
                    actions,
                    global,
                )
                .await
            }
            Self::Delete { id, yes } => delete_permission(&id, yes, global).await,
        }
    }
}

async fn list_permissions(
    target_type: Option<&str>,
    principal_type: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching permissions...");

    let mut req = client.list_permissions().page(page).per_page(per_page);
    if let Some(tt) = target_type {
        req = req.target_type(tt);
    }
    if let Some(pt) = principal_type {
        req = req.principal_type(pt);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list permissions: {e}")))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No permissions found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &resp.items {
            println!("{}", p.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_string(),
                "principal_type": p.principal_type,
                "principal_name": p.principal_name,
                "target_type": p.target_type,
                "target_name": p.target_name,
                "actions": p.actions,
                "created_at": p.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["ID", "PRINCIPAL", "TYPE", "TARGET", "TYPE", "ACTIONS"]);

        for p in &resp.items {
            let id_str = p.id.to_string();
            let id_short = &id_str[..8];
            let principal_id_str = p.principal_id.to_string();
            let principal = p.principal_name.as_deref().unwrap_or(&principal_id_str);
            let target_id_str = p.target_id.to_string();
            let target = p.target_name.as_deref().unwrap_or(&target_id_str);
            let actions = p.actions.join(", ");
            table.add_row(vec![
                id_short,
                principal,
                &p.principal_type,
                target,
                &p.target_type,
                &actions,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    print_page_info(
        resp.pagination.page,
        resp.pagination.total_pages,
        resp.pagination.total,
        "permissions",
    );

    Ok(())
}

async fn create_permission(
    principal: &str,
    principal_type: &str,
    target: &str,
    target_type: &str,
    actions: Vec<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let principal_id = parse_uuid(principal, "principal")?;
    let target_id = parse_uuid(target, "target")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Creating permission...");

    let body = artifact_keeper_sdk::types::CreatePermissionRequest {
        principal_id,
        principal_type: principal_type.to_string(),
        target_id,
        target_type: target_type.to_string(),
        actions,
    };

    let perm = client
        .create_permission()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to create permission: {e}")))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", perm.id);
        return Ok(());
    }

    eprintln!(
        "Permission created (ID: {}): {} {} on {} {}",
        perm.id,
        perm.principal_type,
        perm.principal_name.as_deref().unwrap_or("?"),
        perm.target_type,
        perm.target_name.as_deref().unwrap_or("?"),
    );

    Ok(())
}

async fn delete_permission(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let perm_id = parse_uuid(id, "permission")?;

    if !confirm_action(
        &format!("Delete permission {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting permission...");

    client
        .delete_permission()
        .id(perm_id)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to delete permission: {e}")))?;

    spinner.finish_and_clear();
    eprintln!("Permission {id} deleted.");

    Ok(())
}
