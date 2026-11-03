use artifact_keeper_sdk::ClientProjectsExt;
use artifact_keeper_sdk::types::{
    AddProjectMemberRequest, CreateProjectRequest, Project, ProjectMemberRow,
    RemoveProjectMemberRequest, UpdateProjectRequest,
};
use clap::Subcommand;
use miette::Result;
use uuid::Uuid;

use super::client::client_for;
use super::helpers::{
    confirm_action, emit_mutation, emit_mutation_raw, new_table, parse_uuid, sdk_err,
};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum ProjectCommand {
    /// List projects
    List,

    /// Show a project
    Show {
        /// Project key or ID
        project: String,
    },

    /// Create a project (admin only)
    Create {
        /// Unique, URL-safe project key, for example "payments"
        key: String,

        /// Display name (defaults to the key)
        #[arg(long)]
        name: Option<String>,

        /// Description
        #[arg(long)]
        description: Option<String>,

        /// Storage cap in bytes across the project's repositories. Zero or less means unlimited
        #[arg(long, allow_negative_numbers = true)]
        quota_bytes: Option<i64>,
    },

    /// Update a project. Only the fields you pass change
    Update {
        /// Project key or ID
        project: String,

        /// New display name
        #[arg(long)]
        name: Option<String>,

        /// New description
        #[arg(long)]
        description: Option<String>,

        /// New storage cap in bytes (global admin only). Zero or less means unlimited
        #[arg(long, allow_negative_numbers = true)]
        quota_bytes: Option<i64>,
    },

    /// Delete a project. Its repositories stay, but no longer belong to a project
    Delete {
        /// Project key or ID
        project: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Manage who can use a project's repositories
    #[command(subcommand)]
    Members(MembersCommand),
}

#[derive(Subcommand)]
pub enum MembersCommand {
    /// List a project's membership grants
    List {
        /// Project key or ID
        project: String,
    },

    /// Grant a principal actions on every repository in a project. Granting again replaces the actions
    Add {
        /// Project key or ID
        project: String,

        /// ID of the user, service account or group
        #[arg(long)]
        principal: String,

        /// One of: user, service_account, group
        #[arg(long, default_value = "user")]
        principal_type: String,

        /// Actions to grant, comma-separated, for example read,write
        #[arg(long, required = true, value_delimiter = ',')]
        actions: Vec<String>,
    },

    /// Remove a principal's grant on a project
    Remove {
        /// Project key or ID
        project: String,

        /// ID of the user, service account or group
        #[arg(long)]
        principal: String,

        /// One of: user, service_account, group
        #[arg(long, default_value = "user")]
        principal_type: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

impl ProjectCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List => list_projects(global).await,
            Self::Show { project } => show_project(&project, global).await,
            Self::Create {
                key,
                name,
                description,
                quota_bytes,
            } => create_project(key, name, description, quota_bytes, global).await,
            Self::Update {
                project,
                name,
                description,
                quota_bytes,
            } => update_project(&project, name, description, quota_bytes, global).await,
            Self::Delete { project, yes } => delete_project(&project, yes, global).await,
            Self::Members(command) => command.execute(global).await,
        }
    }
}

impl MembersCommand {
    async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { project } => list_members(&project, global).await,
            Self::Add {
                project,
                principal,
                principal_type,
                actions,
            } => add_member(&project, &principal, principal_type, actions, global).await,
            Self::Remove {
                project,
                principal,
                principal_type,
                yes,
            } => remove_member(&project, &principal, principal_type, yes, global).await,
        }
    }
}

/// Turn what a user typed for a project into its ID: a UUID is used as it is, and
/// anything else is looked up as a project key.
async fn resolve_project_id(client: &artifact_keeper_sdk::Client, project: &str) -> Result<Uuid> {
    if let Ok(id) = project.parse() {
        return Ok(id);
    }
    let list = client
        .projects_list()
        .send()
        .await
        .map_err(|e| sdk_err("list projects", e))?;
    list.items
        .iter()
        .find(|p| p.key == project)
        .map(|p| p.id)
        .ok_or_else(|| {
            AkError::NotFound(format!(
                "No project with key '{project}'. Run `ak project list` to see projects."
            ))
            .into()
        })
}

async fn list_projects(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching projects...");
    let (resp, raw) = artifact_keeper_sdk::raw::capture(client.projects_list().send()).await;
    let list = resp.map_err(|e| sdk_err("list projects", e))?.into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No projects found.");
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for project in &list.items {
            println!("{}", project.id);
        }
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &list,
            &global.format,
            Some(projects_table(&list.items))
        )
    );
    Ok(())
}

async fn show_project(project: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = resolve_project_id(&client, project).await?;
    let spinner = output::spinner("Fetching project...");
    let (resp, raw) = artifact_keeper_sdk::raw::capture(client.projects_get().id(id).send()).await;
    let project = resp.map_err(|e| sdk_err("get project", e))?.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", project.id);
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &project,
            &global.format,
            Some(project_detail(&project))
        )
    );
    Ok(())
}

async fn create_project(
    key: String,
    name: Option<String>,
    description: Option<String>,
    quota_bytes: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Creating project...");
    let body = CreateProjectRequest {
        name: name.unwrap_or_else(|| key.clone()),
        key,
        description,
        quota_bytes,
    };
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.projects_create().body(body).send()).await;
    let project = resp.map_err(|e| sdk_err("create project", e))?;
    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &*project,
        &project.id.to_string(),
        &format!("Project '{}' created (ID: {}).", project.key, project.id),
        global,
    );
    Ok(())
}

async fn update_project(
    project: &str,
    name: Option<String>,
    description: Option<String>,
    quota_bytes: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    if name.is_none() && description.is_none() && quota_bytes.is_none() {
        return Err(AkError::Usage(
            "Nothing to update. Pass --name, --description or --quota-bytes.".to_string(),
        )
        .into());
    }
    let client = client_for(global)?;
    let id = resolve_project_id(&client, project).await?;
    let spinner = output::spinner("Updating project...");
    let body = UpdateProjectRequest {
        name,
        description,
        quota_bytes,
    };
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.projects_update().id(id).body(body).send()).await;
    let project = resp.map_err(|e| sdk_err("update project", e))?;
    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &*project,
        &project.id.to_string(),
        &format!("Project '{}' updated.", project.key),
        global,
    );
    Ok(())
}

async fn delete_project(project: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    if !confirm_action(
        &format!("Delete project {project}? Its repositories stay, without a project."),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }
    let client = client_for(global)?;
    let id = resolve_project_id(&client, project).await?;
    let spinner = output::spinner("Deleting project...");
    client
        .projects_delete()
        .id(id)
        .send()
        .await
        .map_err(|e| sdk_err("delete project", e))?;
    spinner.finish_and_clear();

    let id = id.to_string();
    emit_mutation(
        &serde_json::json!({ "id": id, "status": "deleted" }),
        &id,
        &format!("Project {project} deleted."),
        global,
    );
    Ok(())
}

async fn list_members(project: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = resolve_project_id(&client, project).await?;
    let spinner = output::spinner("Fetching project members...");
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.projects_list_members().id(id).send()).await;
    let list = resp
        .map_err(|e| sdk_err("list project members", e))?
        .into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No members found.");
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for member in &list.items {
            println!("{}", member.principal_id);
        }
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &list,
            &global.format,
            Some(members_table(&list.items))
        )
    );
    Ok(())
}

async fn add_member(
    project: &str,
    principal: &str,
    principal_type: String,
    actions: Vec<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let principal_id = parse_uuid(principal, "principal")?;
    let client = client_for(global)?;
    let id = resolve_project_id(&client, project).await?;
    let spinner = output::spinner("Adding project member...");
    let body = AddProjectMemberRequest {
        actions,
        principal_id,
        principal_type,
    };
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.projects_add_member().id(id).body(body).send())
            .await;
    let member = resp.map_err(|e| sdk_err("add project member", e))?;
    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &*member,
        &member.principal_id.to_string(),
        &format!(
            "Granted {} {} on project {project}: {}.",
            member.principal_type,
            member.principal_id,
            member.actions.join(", ")
        ),
        global,
    );
    Ok(())
}

async fn remove_member(
    project: &str,
    principal: &str,
    principal_type: String,
    skip_confirm: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let principal_id = parse_uuid(principal, "principal")?;
    if !confirm_action(
        &format!("Remove {principal_type} {principal} from project {project}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }
    let client = client_for(global)?;
    let id = resolve_project_id(&client, project).await?;
    let spinner = output::spinner("Removing project member...");
    let body = RemoveProjectMemberRequest {
        principal_id,
        principal_type: principal_type.clone(),
    };
    client
        .projects_remove_member()
        .id(id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("remove project member", e))?;
    spinner.finish_and_clear();

    emit_mutation(
        &serde_json::json!({
            "project_id": id.to_string(),
            "principal_type": principal_type,
            "principal_id": principal,
            "status": "removed",
        }),
        principal,
        &format!("Removed {principal_type} {principal} from project {project}."),
        global,
    );
    Ok(())
}

fn quota(bytes: Option<i64>) -> String {
    match bytes {
        Some(b) if b > 0 => format_bytes(b),
        _ => "unlimited".to_string(),
    }
}

fn projects_table(projects: &[Project]) -> String {
    let mut table = new_table(vec!["ID", "KEY", "NAME", "QUOTA", "DESCRIPTION"]);
    for p in projects {
        table.add_row(vec![
            p.id.to_string(),
            p.key.clone(),
            p.name.clone(),
            quota(p.quota_bytes),
            p.description.clone().unwrap_or_else(|| "-".to_string()),
        ]);
    }
    table.to_string()
}

fn project_detail(p: &Project) -> String {
    format!(
        "ID:          {}\n\
         Key:         {}\n\
         Name:        {}\n\
         Description: {}\n\
         Quota:       {}\n\
         Created:     {}\n\
         Updated:     {}",
        p.id,
        p.key,
        p.name,
        p.description.as_deref().unwrap_or("-"),
        quota(p.quota_bytes),
        p.created_at.to_rfc3339(),
        p.updated_at.to_rfc3339(),
    )
}

fn members_table(members: &[ProjectMemberRow]) -> String {
    let mut table = new_table(vec!["PRINCIPAL ID", "TYPE", "ACTIONS"]);
    for m in members {
        table.add_row(vec![
            m.principal_id.to_string(),
            m.principal_type.clone(),
            m.actions.join(", "),
        ]);
    }
    table.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> Project {
        Project {
            created_at: "2026-01-15T12:00:00Z".parse().unwrap(),
            description: None,
            id: Uuid::nil(),
            key: "payments".to_string(),
            name: "Payments".to_string(),
            quota_bytes: None,
            updated_at: "2026-01-15T12:00:00Z".parse().unwrap(),
        }
    }

    #[test]
    fn a_quota_of_zero_or_less_means_unlimited() {
        assert_eq!(quota(None), "unlimited");
        assert_eq!(quota(Some(0)), "unlimited");
        assert_eq!(quota(Some(-1)), "unlimited");
        assert_eq!(quota(Some(1024)), format_bytes(1024));
    }

    #[test]
    fn tables_show_the_id_and_key() {
        let list = projects_table(&[project()]);
        assert!(list.contains("payments") && list.contains(&Uuid::nil().to_string()));
        let detail = project_detail(&project());
        assert!(detail.contains("Quota:       unlimited"));
        assert!(detail.contains("Description: -"));
    }
}
