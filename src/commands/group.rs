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
