use artifact_keeper_sdk::ClientGroupsExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{confirm_action, new_table, parse_uuid, print_page_info, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum GroupCommand {
    /// List all groups
    List {
        /// Search by name
        #[arg(long)]
        search: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "50")]
        per_page: i32,
    },

    /// Show group details
    Show {
        /// Group ID
        id: String,
    },

    /// Create a new group
    Create {
        /// Group name
        name: String,

        /// Description
        #[arg(long)]
        description: Option<String>,
    },

    /// Delete a group
    Delete {
        /// Group ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Add a user to a group
    AddMember {
        /// Group ID
        group: String,

        /// User ID to add
        user: String,
    },

    /// Remove a user from a group
    RemoveMember {
        /// Group ID
        group: String,

        /// User ID to remove
        user: String,
    },
}

impl GroupCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List {
                search,
                page,
                per_page,
            } => list_groups(search.as_deref(), page, per_page, global).await,
            Self::Show { id } => show_group(&id, global).await,
            Self::Create { name, description } => {
                create_group(&name, description.as_deref(), global).await
            }
            Self::Delete { id, yes } => delete_group(&id, yes, global).await,
            Self::AddMember { group, user } => add_member(&group, &user, global).await,
            Self::RemoveMember { group, user } => remove_member(&group, &user, global).await,
        }
    }
}

async fn list_groups(
    search: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching groups...");

    let mut req = client.list_groups().page(page).per_page(per_page);
    if let Some(s) = search {
        req = req.search(s);
    }

    let resp = req.send().await.map_err(|e| sdk_err("list groups", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No groups found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for g in &resp.items {
            println!("{}", g.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|g| {
            serde_json::json!({
                "id": g.id.to_string(),
                "name": g.name,
                "description": g.description,
                "member_count": g.member_count,
                "created_at": g.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "DESCRIPTION", "MEMBERS", "CREATED"]);

        for g in &resp.items {
            let id_short = short_id(&g.id);
            let desc = g.description.as_deref().unwrap_or("-");
            let created = g.created_at.format("%Y-%m-%d").to_string();
            table.add_row(vec![
                &id_short,
                &g.name,
                desc,
                &g.member_count.to_string(),
                &created,
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
        "groups",
    );

    Ok(())
}

async fn show_group(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let group_id = parse_uuid(id, "group")?;

    let spinner = output::spinner("Fetching group...");
    let group = client
        .get_group()
        .id(group_id)
        .send()
        .await
        .map_err(|e| sdk_err("get group", e))?;
    spinner.finish_and_clear();

    let info = serde_json::json!({
        "id": group.id.to_string(),
        "name": group.name,
        "description": group.description,
        "member_count": group.member_count,
        "created_at": group.created_at.to_rfc3339(),
        "updated_at": group.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:           {}\n\
         Name:         {}\n\
         Description:  {}\n\
         Members:      {}\n\
         Created:      {}\n\
         Updated:      {}",
        group.id,
        group.name,
        group.description.as_deref().unwrap_or("-"),
        group.member_count,
        group.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        group.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn create_group(name: &str, description: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Creating group...");

    let body = artifact_keeper_sdk::types::CreateGroupRequest {
        name: name.to_string(),
        description: description.map(|s| s.to_string()),
    };

    let group = client
        .create_group()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create group", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", group.id);
        return Ok(());
    }

    eprintln!("Group '{}' created (ID: {}).", group.name, group.id);

    Ok(())
}

async fn delete_group(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let group_id = parse_uuid(id, "group")?;

    if !confirm_action(
        &format!("Delete group {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting group...");

    client
        .delete_group()
        .id(group_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete group", e))?;

    spinner.finish_and_clear();
    eprintln!("Group {id} deleted.");

    Ok(())
}

async fn add_member(group_id: &str, user_id: &str, global: &GlobalArgs) -> Result<()> {
    let gid = parse_uuid(group_id, "group")?;
    let uid = parse_uuid(user_id, "user")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Adding member...");

    let body = artifact_keeper_sdk::types::MembersRequest {
        user_ids: vec![uid],
    };

    client
        .add_members()
        .id(gid)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("add member", e))?;

    spinner.finish_and_clear();
    eprintln!("Added user {user_id} to group {group_id}.");

    Ok(())
}

fn format_group_table(items: &[serde_json::Value]) -> String {
    let mut table = new_table(vec!["ID", "NAME", "DESCRIPTION", "MEMBERS", "CREATED"]);

    for g in items {
        let id = g["id"].as_str().unwrap_or("-");
        let id_short = if id.len() >= 8 { &id[..8] } else { id };
        table.add_row(vec![
            id_short,
            g["name"].as_str().unwrap_or("-"),
            g["description"].as_str().unwrap_or("-"),
            &g["member_count"].to_string(),
            g["created_at"].as_str().unwrap_or("-"),
        ]);
    }

    table.to_string()
}

fn format_group_detail(item: &serde_json::Value) -> String {
    format!(
        "ID:           {}\n\
         Name:         {}\n\
         Description:  {}\n\
         Members:      {}\n\
         Created:      {}\n\
         Updated:      {}",
        item["id"].as_str().unwrap_or("-"),
        item["name"].as_str().unwrap_or("-"),
        item["description"].as_str().unwrap_or("-"),
        item["member_count"],
        item["created_at"].as_str().unwrap_or("-"),
        item["updated_at"].as_str().unwrap_or("-"),
    )
}

async fn remove_member(group_id: &str, user_id: &str, global: &GlobalArgs) -> Result<()> {
    let gid = parse_uuid(group_id, "group")?;
    let uid = parse_uuid(user_id, "user")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Removing member...");

    let body = artifact_keeper_sdk::types::MembersRequest {
        user_ids: vec![uid],
    };

    client
        .remove_members()
        .id(gid)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("remove member", e))?;

    spinner.finish_and_clear();
    eprintln!("Removed user {user_id} from group {group_id}.");

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
        command: GroupCommand,
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
            GroupCommand::List {
                search,
                page,
                per_page,
            } => {
                assert!(search.is_none());
                assert_eq!(page, 1);
                assert_eq!(per_page, 50);
            }
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn parse_list_with_search() {
        let cli = parse(&["test", "list", "--search", "admins"]);
        match cli.command {
            GroupCommand::List { search, .. } => {
                assert_eq!(search.as_deref(), Some("admins"));
            }
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn parse_list_with_pagination() {
        let cli = parse(&["test", "list", "--page", "3", "--per-page", "25"]);
        match cli.command {
            GroupCommand::List { page, per_page, .. } => {
                assert_eq!(page, 3);
                assert_eq!(per_page, 25);
            }
            _ => panic!("expected List"),
        }
    }

    // ---- parsing: show ----

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "00000000-0000-0000-0000-000000000001"]);
        match cli.command {
            GroupCommand::Show { id } => {
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

    // ---- parsing: create ----

    #[test]
    fn parse_create_minimal() {
        let cli = parse(&["test", "create", "developers"]);
        match cli.command {
            GroupCommand::Create { name, description } => {
                assert_eq!(name, "developers");
                assert!(description.is_none());
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn parse_create_with_description() {
        let cli = parse(&[
            "test",
            "create",
            "developers",
            "--description",
            "Core dev team",
        ]);
        match cli.command {
            GroupCommand::Create { name, description } => {
                assert_eq!(name, "developers");
                assert_eq!(description.as_deref(), Some("Core dev team"));
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn parse_create_missing_name() {
        let result = try_parse(&["test", "create"]);
        assert!(result.is_err());
    }

    // ---- parsing: delete ----

    #[test]
    fn parse_delete_no_yes() {
        let cli = parse(&["test", "delete", "some-id"]);
        match cli.command {
            GroupCommand::Delete { id, yes } => {
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
            GroupCommand::Delete { yes, .. } => {
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

    // ---- parsing: add-member ----

    #[test]
    fn parse_add_member() {
        let cli = parse(&["test", "add-member", "group-id", "user-id"]);
        match cli.command {
            GroupCommand::AddMember { group, user } => {
                assert_eq!(group, "group-id");
                assert_eq!(user, "user-id");
            }
            _ => panic!("expected AddMember"),
        }
    }

    #[test]
    fn parse_add_member_missing_user() {
        let result = try_parse(&["test", "add-member", "group-id"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_add_member_missing_both() {
        let result = try_parse(&["test", "add-member"]);
        assert!(result.is_err());
    }

    // ---- parsing: remove-member ----

    #[test]
    fn parse_remove_member() {
        let cli = parse(&["test", "remove-member", "group-id", "user-id"]);
        match cli.command {
            GroupCommand::RemoveMember { group, user } => {
                assert_eq!(group, "group-id");
                assert_eq!(user, "user-id");
            }
            _ => panic!("expected RemoveMember"),
        }
    }

    #[test]
    fn parse_remove_member_missing_user() {
        let result = try_parse(&["test", "remove-member", "group-id"]);
        assert!(result.is_err());
    }

    // ---- format functions ----

    #[test]
    fn format_group_table_renders() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "developers",
            "description": "Core dev team",
            "member_count": 5,
            "created_at": "2026-01-15",
        })];
        let table = format_group_table(&items);
        assert!(table.contains("00000000"));
        assert!(table.contains("developers"));
        assert!(table.contains("Core dev team"));
        assert!(table.contains("5"));
    }

    #[test]
    fn format_group_table_multiple_rows() {
        let items = vec![
            json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "admins",
                "description": null,
                "member_count": 2,
                "created_at": "2026-01-01",
            }),
            json!({
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "devs",
                "description": "Developers",
                "member_count": 10,
                "created_at": "2026-02-01",
            }),
        ];
        let table = format_group_table(&items);
        assert!(table.contains("admins"));
        assert!(table.contains("devs"));
        assert!(table.contains("Developers"));
    }

    #[test]
    fn format_group_table_null_description() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "test",
            "description": null,
            "member_count": 0,
            "created_at": "2026-01-01",
        })];
        let table = format_group_table(&items);
        assert!(table.contains("-"));
    }

    #[test]
    fn format_group_detail_renders() {
        let item = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "developers",
            "description": "Core dev team",
            "member_count": 5,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-20T12:00:00Z",
        });
        let detail = format_group_detail(&item);
        assert!(detail.contains("00000000-0000-0000-0000-000000000001"));
        assert!(detail.contains("developers"));
        assert!(detail.contains("Core dev team"));
        assert!(detail.contains("5"));
        assert!(detail.contains("2026-01-15"));
        assert!(detail.contains("2026-01-20"));
    }

    #[test]
    fn format_group_detail_null_fields() {
        let item = json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "test",
            "description": null,
            "member_count": 0,
            "created_at": null,
            "updated_at": null,
        });
        let detail = format_group_detail(&item);
        assert!(detail.contains("Name:"));
        assert!(detail.contains("test"));
        // Null description and dates show as "-"
        assert!(detail.contains("-"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn setup_env(tmp: &tempfile::TempDir) -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::test_utils::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("AK_CONFIG_DIR", tmp.path());
            std::env::set_var("AK_TOKEN", "test-token");
        }
        guard
    }

    fn teardown_env() {
        unsafe {
            std::env::remove_var("AK_CONFIG_DIR");
            std::env::remove_var("AK_TOKEN");
        }
    }

    fn group_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "developers",
            "description": "Core dev team",
            "member_count": 5,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    #[tokio::test]
    async fn handler_list_groups_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 50, "total": 0, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_groups(None, 1, 50, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_list_groups_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [group_json()],
                "pagination": { "page": 1, "per_page": 50, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_groups(None, 1, 50, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_list_groups_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [group_json()],
                "pagination": { "page": 1, "per_page": 50, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_groups(None, 1, 50, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_show_group() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/groups/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(group_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_group(NIL_UUID, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_create_group_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(group_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_group("developers", Some("Core dev team"), &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_group() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/groups/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = delete_group(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_add_member() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/groups/{NIL_UUID}/members")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = add_member(NIL_UUID, NIL_UUID, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_remove_member() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/groups/{NIL_UUID}/members")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = remove_member(NIL_UUID, NIL_UUID, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }
}
