use artifact_keeper_sdk::ClientRepositoriesExt;
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::{IntoDiagnostic, Result};

use super::client::{client_for, client_for_optional_auth};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum RepoCommand {
    /// List repositories (filtered by your permissions)
    List {
        /// Filter by package format (npm, pypi, maven, docker, etc.)
        #[arg(long = "pkg-format", id = "pkg_format")]
        pkg_format: Option<String>,

        /// Filter by repository type (local, remote, virtual)
        #[arg(long, name = "type")]
        repo_type: Option<String>,

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

    /// Show repository details
    Show {
        /// Repository key
        key: String,
    },

    /// Create a new repository
    Create {
        /// Repository key (URL slug)
        key: String,

        /// Package format
        #[arg(long = "pkg-format", id = "pkg_format_create")]
        pkg_format: String,

        /// Repository type
        #[arg(long, default_value = "local")]
        repo_type: String,

        /// Description
        #[arg(long)]
        description: Option<String>,
    },

    /// Delete a repository
    Delete {
        /// Repository key
        key: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Interactively browse artifacts in a repository
    Browse {
        /// Repository key
        key: String,
    },
}

impl RepoCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List {
                pkg_format,
                repo_type,
                search,
                page,
                per_page,
            } => {
                list_repos(
                    pkg_format.as_deref(),
                    repo_type.as_deref(),
                    search.as_deref(),
                    page,
                    per_page,
                    global,
                )
                .await
            }
            Self::Show { key } => show_repo(&key, global).await,
            Self::Create {
                key,
                pkg_format,
                repo_type,
                description,
            } => {
                create_repo(
                    &key,
                    &pkg_format,
                    &repo_type,
                    description.as_deref(),
                    global,
                )
                .await
            }
            Self::Delete { key, yes } => delete_repo(&key, yes, global).await,
            Self::Browse { key } => browse_repo(&key, global).await,
        }
    }
}

async fn list_repos(
    format_filter: Option<&str>,
    type_filter: Option<&str>,
    search: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let spinner = crate::output::spinner("Fetching repositories...");

    let mut req = client.list_repositories().page(page).per_page(per_page);

    if let Some(fmt) = format_filter {
        req = req.format(fmt);
    }
    if let Some(t) = type_filter {
        req = req.type_(t);
    }
    if let Some(q) = search {
        req = req.q(q);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list repositories: {e}")))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No repositories found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for repo in &resp.items {
            println!("{}", repo.key);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|r| {
            serde_json::json!({
                "key": r.key,
                "name": r.name,
                "format": r.format,
                "type": r.repo_type,
                "public": r.is_public,
                "storage_used": format_bytes(r.storage_used_bytes),
                "storage_used_bytes": r.storage_used_bytes,
                "description": r.description,
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["KEY", "NAME", "FORMAT", "TYPE", "PUBLIC", "STORAGE"]);

        for r in &resp.items {
            let public = if r.is_public { "yes" } else { "no" };
            let storage = format_bytes(r.storage_used_bytes);
            table.add_row(vec![
                r.key.as_str(),
                r.name.as_str(),
                r.format.as_str(),
                r.repo_type.as_str(),
                public,
                &storage,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    // Show pagination info on stderr
    if resp.pagination.total_pages > 1 {
        eprintln!(
            "Page {} of {} ({} total repositories)",
            resp.pagination.page, resp.pagination.total_pages, resp.pagination.total
        );
    }

    Ok(())
}

async fn show_repo(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let repo = client
        .get_repository()
        .key(key)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to get repository: {e}")))?;

    let info = serde_json::json!({
        "key": repo.key,
        "name": repo.name,
        "format": repo.format,
        "type": repo.repo_type,
        "public": repo.is_public,
        "description": repo.description,
        "storage_used": format_bytes(repo.storage_used_bytes),
        "storage_used_bytes": repo.storage_used_bytes,
        "quota_bytes": repo.quota_bytes,
        "created_at": repo.created_at.to_rfc3339(),
        "updated_at": repo.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "Key:          {}\n\
         Name:         {}\n\
         Format:       {}\n\
         Type:         {}\n\
         Public:       {}\n\
         Description:  {}\n\
         Storage Used: {}\n\
         Quota:        {}\n\
         Created:      {}\n\
         Updated:      {}",
        repo.key,
        repo.name,
        repo.format,
        repo.repo_type,
        if repo.is_public { "yes" } else { "no" },
        repo.description.as_deref().unwrap_or("-"),
        format_bytes(repo.storage_used_bytes),
        repo.quota_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "unlimited".into()),
        repo.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        repo.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn create_repo(
    key: &str,
    format: &str,
    repo_type: &str,
    description: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let body = artifact_keeper_sdk::types::CreateRepositoryRequest {
        key: key.to_string(),
        name: key.to_string(),
        format: format.to_string(),
        repo_type: repo_type.to_string(),
        description: description.map(|d| d.to_string()),
        is_public: None,
        quota_bytes: None,
        upstream_url: None,
    };

    let resp = client
        .create_repository()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to create repository: {e}")))?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.key);
        return Ok(());
    }

    eprintln!(
        "Created repository '{}' (format: {}, type: {})",
        resp.key, resp.format, resp.repo_type
    );

    Ok(())
}

async fn delete_repo(key: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let needs_confirmation = !skip_confirm && !global.no_input;
    if needs_confirmation {
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!("Delete repository '{key}'? This cannot be undone"))
            .default(false)
            .interact()
            .into_diagnostic()?;

        if !confirmed {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    client
        .delete_repository()
        .key(key)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to delete repository: {e}")))?;

    eprintln!("Deleted repository '{key}'.");
    Ok(())
}

async fn browse_repo(key: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let spinner = crate::output::spinner("Loading artifacts...");

    let resp = client
        .list_artifacts()
        .key(key)
        .per_page(100)
        .send()
        .await
        .map_err(|e| AkError::ServerError(format!("Failed to list artifacts: {e}")))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No artifacts in repository '{key}'.");
        return Ok(());
    }

    if global.no_input {
        // Non-interactive: just list artifacts
        for a in &resp.items {
            println!("{}", a.path);
        }
        return Ok(());
    }

    // Interactive fuzzy select
    let items: Vec<String> = resp.items.iter().map(|a| a.path.clone()).collect();

    let selection = dialoguer::FuzzySelect::new()
        .with_prompt(format!("Browse artifacts in '{key}'"))
        .items(&items)
        .interact_opt()
        .into_diagnostic()?;

    if let Some(idx) = selection {
        let artifact = &resp.items[idx];
        println!(
            "{}",
            serde_json::to_string_pretty(artifact).unwrap_or_default()
        );
    }

    Ok(())
}

/// Format a list of repository entries as a table string.
fn format_repos_table(items: &[serde_json::Value]) -> String {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["KEY", "NAME", "FORMAT", "TYPE", "PUBLIC", "STORAGE"]);

    for r in items {
        let public = if r["public"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        table.add_row(vec![
            r["key"].as_str().unwrap_or("-"),
            r["name"].as_str().unwrap_or("-"),
            r["format"].as_str().unwrap_or("-"),
            r["type"].as_str().unwrap_or("-"),
            public,
            r["storage_used"].as_str().unwrap_or("-"),
        ]);
    }

    table.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    // ---- TestCli wrapper for parsing ----

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: RepoCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- List subcommand parsing ----

    #[test]
    fn parse_list() {
        let cli = parse(&["test", "list"]);
        assert!(matches!(cli.command, RepoCommand::List { .. }));
    }

    #[test]
    fn parse_list_defaults() {
        let cli = parse(&["test", "list"]);
        if let RepoCommand::List {
            pkg_format,
            repo_type,
            search,
            page,
            per_page,
        } = cli.command
        {
            assert!(pkg_format.is_none());
            assert!(repo_type.is_none());
            assert!(search.is_none());
            assert_eq!(page, 1);
            assert_eq!(per_page, 50);
        } else {
            panic!("Expected RepoCommand::List");
        }
    }

    #[test]
    fn parse_list_with_format_filter() {
        let cli = parse(&["test", "list", "--pkg-format", "npm"]);
        if let RepoCommand::List { pkg_format, .. } = cli.command {
            assert_eq!(pkg_format.as_deref(), Some("npm"));
        } else {
            panic!("Expected RepoCommand::List");
        }
    }

    #[test]
    fn parse_list_with_type_filter() {
        let cli = parse(&["test", "list", "--repo-type", "local"]);
        if let RepoCommand::List { repo_type, .. } = cli.command {
            assert_eq!(repo_type.as_deref(), Some("local"));
        } else {
            panic!("Expected RepoCommand::List");
        }
    }

    #[test]
    fn parse_list_with_search() {
        let cli = parse(&["test", "list", "--search", "my-repo"]);
        if let RepoCommand::List { search, .. } = cli.command {
            assert_eq!(search.as_deref(), Some("my-repo"));
        } else {
            panic!("Expected RepoCommand::List");
        }
    }

    #[test]
    fn parse_list_custom_pagination() {
        let cli = parse(&["test", "list", "--page", "5", "--per-page", "25"]);
        if let RepoCommand::List { page, per_page, .. } = cli.command {
            assert_eq!(page, 5);
            assert_eq!(per_page, 25);
        } else {
            panic!("Expected RepoCommand::List");
        }
    }

    #[test]
    fn parse_list_all_options() {
        let cli = parse(&[
            "test",
            "list",
            "--pkg-format",
            "maven",
            "--repo-type",
            "remote",
            "--search",
            "libs",
            "--page",
            "2",
            "--per-page",
            "10",
        ]);
        if let RepoCommand::List {
            pkg_format,
            repo_type,
            search,
            page,
            per_page,
        } = cli.command
        {
            assert_eq!(pkg_format.as_deref(), Some("maven"));
            assert_eq!(repo_type.as_deref(), Some("remote"));
            assert_eq!(search.as_deref(), Some("libs"));
            assert_eq!(page, 2);
            assert_eq!(per_page, 10);
        } else {
            panic!("Expected RepoCommand::List");
        }
    }

    // ---- Show subcommand parsing ----

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "my-npm-repo"]);
        if let RepoCommand::Show { key } = cli.command {
            assert_eq!(key, "my-npm-repo");
        } else {
            panic!("Expected RepoCommand::Show");
        }
    }

    #[test]
    fn parse_show_missing_key_fails() {
        assert!(try_parse(&["test", "show"]).is_err());
    }

    // ---- Create subcommand parsing ----

    #[test]
    fn parse_create() {
        let cli = parse(&["test", "create", "my-repo", "--pkg-format", "npm"]);
        if let RepoCommand::Create {
            key,
            pkg_format,
            repo_type,
            description,
        } = cli.command
        {
            assert_eq!(key, "my-repo");
            assert_eq!(pkg_format, "npm");
            assert_eq!(repo_type, "local"); // default
            assert!(description.is_none());
        } else {
            panic!("Expected RepoCommand::Create");
        }
    }

    #[test]
    fn parse_create_with_all_options() {
        let cli = parse(&[
            "test",
            "create",
            "my-pypi",
            "--pkg-format",
            "pypi",
            "--repo-type",
            "remote",
            "--description",
            "Python packages mirror",
        ]);
        if let RepoCommand::Create {
            key,
            pkg_format,
            repo_type,
            description,
        } = cli.command
        {
            assert_eq!(key, "my-pypi");
            assert_eq!(pkg_format, "pypi");
            assert_eq!(repo_type, "remote");
            assert_eq!(description.as_deref(), Some("Python packages mirror"));
        } else {
            panic!("Expected RepoCommand::Create");
        }
    }

    #[test]
    fn parse_create_missing_format_fails() {
        assert!(try_parse(&["test", "create", "key"]).is_err());
    }

    #[test]
    fn parse_create_missing_key_fails() {
        assert!(try_parse(&["test", "create", "--pkg-format", "npm"]).is_err());
    }

    // ---- Delete subcommand parsing ----

    #[test]
    fn parse_delete() {
        let cli = parse(&["test", "delete", "my-repo"]);
        if let RepoCommand::Delete { key, yes } = cli.command {
            assert_eq!(key, "my-repo");
            assert!(!yes);
        } else {
            panic!("Expected RepoCommand::Delete");
        }
    }

    #[test]
    fn parse_delete_with_yes() {
        let cli = parse(&["test", "delete", "my-repo", "--yes"]);
        if let RepoCommand::Delete { key, yes } = cli.command {
            assert_eq!(key, "my-repo");
            assert!(yes);
        } else {
            panic!("Expected RepoCommand::Delete");
        }
    }

    #[test]
    fn parse_delete_missing_key_fails() {
        assert!(try_parse(&["test", "delete"]).is_err());
    }

    // ---- Browse subcommand parsing ----

    #[test]
    fn parse_browse() {
        let cli = parse(&["test", "browse", "my-repo"]);
        if let RepoCommand::Browse { key } = cli.command {
            assert_eq!(key, "my-repo");
        } else {
            panic!("Expected RepoCommand::Browse");
        }
    }

    #[test]
    fn parse_browse_missing_key_fails() {
        assert!(try_parse(&["test", "browse"]).is_err());
    }

    // ---- Error cases ----

    #[test]
    fn parse_no_subcommand_fails() {
        assert!(try_parse(&["test"]).is_err());
    }

    #[test]
    fn parse_unknown_subcommand_fails() {
        assert!(try_parse(&["test", "unknown"]).is_err());
    }

    // ---- Format function tests ----

    #[test]
    fn format_repos_table_renders() {
        let items = vec![json!({
            "key": "my-npm-repo",
            "name": "My NPM Repo",
            "format": "npm",
            "type": "local",
            "public": true,
            "storage_used": "1.5 GB",
        })];
        let table = format_repos_table(&items);
        assert!(table.contains("my-npm-repo"));
        assert!(table.contains("My NPM Repo"));
        assert!(table.contains("npm"));
        assert!(table.contains("local"));
        assert!(table.contains("yes"));
        assert!(table.contains("1.5 GB"));
    }

    #[test]
    fn format_repos_table_private_repo() {
        let items = vec![json!({
            "key": "internal-maven",
            "name": "Internal Maven",
            "format": "maven",
            "type": "local",
            "public": false,
            "storage_used": "500.0 MB",
        })];
        let table = format_repos_table(&items);
        assert!(table.contains("internal-maven"));
        assert!(table.contains("no"));
    }

    #[test]
    fn format_repos_table_empty() {
        let items: Vec<serde_json::Value> = vec![];
        let table = format_repos_table(&items);
        assert!(table.contains("KEY"));
        assert!(table.contains("FORMAT"));
        assert!(table.contains("TYPE"));
    }

    #[test]
    fn format_repos_table_multiple_rows() {
        let items = vec![
            json!({
                "key": "npm-repo",
                "name": "NPM",
                "format": "npm",
                "type": "local",
                "public": true,
                "storage_used": "1.0 GB",
            }),
            json!({
                "key": "pypi-repo",
                "name": "PyPI",
                "format": "pypi",
                "type": "remote",
                "public": false,
                "storage_used": "500.0 MB",
            }),
            json!({
                "key": "docker-repo",
                "name": "Docker",
                "format": "docker",
                "type": "virtual",
                "public": true,
                "storage_used": "10.0 GB",
            }),
        ];
        let table = format_repos_table(&items);
        assert!(table.contains("npm-repo"));
        assert!(table.contains("pypi-repo"));
        assert!(table.contains("docker-repo"));
        assert!(table.contains("npm"));
        assert!(table.contains("pypi"));
        assert!(table.contains("docker"));
    }

    #[test]
    fn format_repos_table_missing_fields_use_dash() {
        let items = vec![json!({
            "key": "test-repo",
        })];
        let table = format_repos_table(&items);
        assert!(table.contains("test-repo"));
        // Missing fields should render as "-"
        assert!(table.contains("-"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

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

    fn repo_json(key: &str) -> serde_json::Value {
        json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "key": key,
            "name": key,
            "format": "npm",
            "repo_type": "local",
            "is_public": true,
            "description": "Test repo",
            "storage_used_bytes": 1024,
            "quota_bytes": null,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    #[tokio::test]
    async fn handler_list_repos_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 50, "total": 0, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_repos(None, None, None, 1, 50, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_list_repos_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [repo_json("npm-local")],
                "pagination": { "page": 1, "per_page": 50, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_repos(None, None, None, 1, 50, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_list_repos_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [repo_json("npm-local")],
                "pagination": { "page": 1, "per_page": 50, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = list_repos(None, None, None, 1, 50, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_show_repo() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories/npm-local"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repo_json("npm-local")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_repo("npm-local", &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_create_repo_json() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repo_json("new-repo")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = create_repo("new-repo", "npm", "local", None, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_create_repo_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(repo_json("new-repo")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = create_repo("new-repo", "npm", "local", Some("A test repo"), &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_repo() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path("/api/v1/repositories/old-repo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        // skip_confirm=true and no_input=true so no prompt
        let result = delete_repo("old-repo", true, &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_browse_repo_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/npm-local/artifacts.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 100, "total": 0, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = browse_repo("npm-local", &global).await;
        assert!(result.is_ok());
        teardown_env();
    }

    #[tokio::test]
    async fn handler_browse_repo_no_input() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/npm-local/artifacts.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "path": "express/4.18.2",
                    "name": "express",
                    "size_bytes": 2048_i64,
                    "content_type": "application/gzip",
                    "checksum_sha256": "abc123",
                    "download_count": 0_i64,
                    "created_at": "2026-01-15T12:00:00Z",
                    "repository_key": "npm-local"
                }],
                "pagination": { "page": 1, "per_page": 100, "total": 1_i64, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = browse_repo("npm-local", &global).await;
        assert!(result.is_ok());
        teardown_env();
    }
}
