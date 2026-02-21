use artifact_keeper_sdk::ClientPermissionsExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{confirm_action, new_table, parse_uuid, print_page_info, sdk_err};
use crate::cli::GlobalArgs;
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
        .map_err(|e| sdk_err("list permissions", e))?;

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
        let mut table = new_table(vec!["ID", "PRINCIPAL", "TYPE", "TARGET", "TYPE", "ACTIONS"]);

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
        .map_err(|e| sdk_err("create permission", e))?;

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

fn format_permission_table(items: &[serde_json::Value]) -> String {
    let mut table = new_table(vec!["ID", "PRINCIPAL", "TYPE", "TARGET", "TYPE", "ACTIONS"]);

    for p in items {
        let id = p["id"].as_str().unwrap_or("-");
        let id_short = if id.len() >= 8 { &id[..8] } else { id };
        let principal = p["principal_name"].as_str().unwrap_or("-");
        let principal_type = p["principal_type"].as_str().unwrap_or("-");
        let target = p["target_name"].as_str().unwrap_or("-");
        let target_type = p["target_type"].as_str().unwrap_or("-");
        let actions = p["actions"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "-".to_string());
        table.add_row(vec![
            id_short,
            principal,
            principal_type,
            target,
            target_type,
            &actions,
        ]);
    }

    table.to_string()
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
        .map_err(|e| sdk_err("delete permission", e))?;

    spinner.finish_and_clear();
    eprintln!("Permission {id} deleted.");

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
        command: PermissionCommand,
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
            PermissionCommand::List {
                target_type,
                principal_type,
                page,
                per_page,
            } => {
                assert!(target_type.is_none());
                assert!(principal_type.is_none());
                assert_eq!(page, 1);
                assert_eq!(per_page, 50);
            }
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn parse_list_with_filters() {
        let cli = parse(&[
            "test",
            "list",
            "--target-type",
            "repository",
            "--principal-type",
            "user",
        ]);
        match cli.command {
            PermissionCommand::List {
                target_type,
                principal_type,
                ..
            } => {
                assert_eq!(target_type.as_deref(), Some("repository"));
                assert_eq!(principal_type.as_deref(), Some("user"));
            }
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn parse_list_with_pagination() {
        let cli = parse(&["test", "list", "--page", "2", "--per-page", "10"]);
        match cli.command {
            PermissionCommand::List { page, per_page, .. } => {
                assert_eq!(page, 2);
                assert_eq!(per_page, 10);
            }
            _ => panic!("expected List"),
        }
    }

    // ---- parsing: create ----

    #[test]
    fn parse_create_all_required() {
        let cli = parse(&[
            "test",
            "create",
            "--principal",
            "00000000-0000-0000-0000-000000000001",
            "--principal-type",
            "user",
            "--target",
            "00000000-0000-0000-0000-000000000002",
            "--target-type",
            "repository",
            "--actions",
            "read,write",
        ]);
        match cli.command {
            PermissionCommand::Create {
                principal,
                principal_type,
                target,
                target_type,
                actions,
            } => {
                assert_eq!(principal, "00000000-0000-0000-0000-000000000001");
                assert_eq!(principal_type, "user");
                assert_eq!(target, "00000000-0000-0000-0000-000000000002");
                assert_eq!(target_type, "repository");
                assert_eq!(actions, vec!["read", "write"]);
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn parse_create_single_action() {
        let cli = parse(&[
            "test",
            "create",
            "--principal",
            "id1",
            "--principal-type",
            "group",
            "--target",
            "id2",
            "--target-type",
            "group",
            "--actions",
            "admin",
        ]);
        match cli.command {
            PermissionCommand::Create { actions, .. } => {
                assert_eq!(actions, vec!["admin"]);
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn parse_create_three_actions_comma_separated() {
        let cli = parse(&[
            "test",
            "create",
            "--principal",
            "id1",
            "--principal-type",
            "user",
            "--target",
            "id2",
            "--target-type",
            "repository",
            "--actions",
            "read,write,admin",
        ]);
        match cli.command {
            PermissionCommand::Create { actions, .. } => {
                assert_eq!(actions, vec!["read", "write", "admin"]);
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn parse_create_missing_principal() {
        let result = try_parse(&[
            "test",
            "create",
            "--principal-type",
            "user",
            "--target",
            "id2",
            "--target-type",
            "repository",
            "--actions",
            "read",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_create_missing_actions() {
        let result = try_parse(&[
            "test",
            "create",
            "--principal",
            "id1",
            "--principal-type",
            "user",
            "--target",
            "id2",
            "--target-type",
            "repository",
        ]);
        // actions defaults to empty vec, so parsing succeeds
        let cli = result.unwrap();
        match cli.command {
            PermissionCommand::Create { actions, .. } => {
                assert!(actions.is_empty());
            }
            _ => panic!("expected Create"),
        }
    }

    // ---- parsing: delete ----

    #[test]
    fn parse_delete_no_yes() {
        let cli = parse(&["test", "delete", "some-id"]);
        match cli.command {
            PermissionCommand::Delete { id, yes } => {
                assert_eq!(id, "some-id");
                assert!(!yes);
            }
            _ => panic!("expected Delete"),
        }
    }

    #[test]
    fn parse_delete_with_yes() {
        let cli = parse(&["test", "delete", "some-id", "--yes"]);
        match cli.command {
            PermissionCommand::Delete { yes, .. } => {
                assert!(yes);
            }
            _ => panic!("expected Delete"),
        }
    }

    #[test]
    fn parse_delete_missing_id() {
        let result = try_parse(&["test", "delete"]);
        assert!(result.is_err());
    }

    // ---- format functions ----

    #[test]
    fn format_permission_table_renders() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "principal_name": "alice",
            "principal_type": "user",
            "target_name": "maven-releases",
            "target_type": "repository",
            "actions": ["read", "write"],
            "created_at": "2026-01-15",
        })];
        let table = format_permission_table(&items);
        assert!(table.contains("00000000"));
        assert!(table.contains("alice"));
        assert!(table.contains("user"));
        assert!(table.contains("maven-releases"));
        assert!(table.contains("repository"));
        assert!(table.contains("read, write"));
    }

    #[test]
    fn format_permission_table_null_names() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "principal_name": null,
            "principal_type": "group",
            "target_name": null,
            "target_type": "group",
            "actions": ["admin"],
            "created_at": "2026-01-01",
        })];
        let table = format_permission_table(&items);
        assert!(table.contains("admin"));
        assert!(table.contains("group"));
    }

    #[test]
    fn format_permission_table_empty_actions() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "principal_name": "bob",
            "principal_type": "user",
            "target_name": "npm-local",
            "target_type": "repository",
            "actions": [],
            "created_at": "2026-01-01",
        })];
        let table = format_permission_table(&items);
        assert!(table.contains("bob"));
    }

    #[test]
    fn format_permission_table_multiple_rows() {
        let items = vec![
            json!({
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "principal_name": "alice",
                "principal_type": "user",
                "target_name": "repo-a",
                "target_type": "repository",
                "actions": ["read"],
                "created_at": "2026-01-01",
            }),
            json!({
                "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "principal_name": "dev-team",
                "principal_type": "group",
                "target_name": "repo-b",
                "target_type": "repository",
                "actions": ["read", "write", "admin"],
                "created_at": "2026-01-02",
            }),
        ];
        let table = format_permission_table(&items);
        assert!(table.contains("alice"));
        assert!(table.contains("dev-team"));
        assert!(table.contains("repo-a"));
        assert!(table.contains("repo-b"));
    }
}
