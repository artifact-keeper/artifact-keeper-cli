use artifact_keeper_sdk::{ClientPackagesExt, ClientRepositoriesExt};
use clap::Subcommand;
use futures::StreamExt;
use miette::{IntoDiagnostic, Result};

use super::client::client_for_optional_auth;
use super::helpers::{new_table, parse_uuid, print_page_info, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum PackagesCommand {
    /// List packages across repositories
    List {
        /// Filter by repository key
        #[arg(long)]
        repo: Option<String>,

        /// Filter by package format (npm, pypi, maven, ...)
        #[arg(long)]
        pkg_format: Option<String>,

        /// Search by package name
        #[arg(long)]
        search: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: i32,
    },

    /// Show details for a single package
    Show {
        /// Package ID
        id: String,
    },

    /// List the versions of a package
    Versions {
        /// Package ID
        id: String,
    },

    /// Browse a repository's artifact tree (or fetch a file with --content)
    Tree {
        /// Repository key to browse
        repo: String,

        /// Path prefix to browse within the repository (or the full artifact
        /// path when used with --content)
        #[arg(long)]
        path: Option<String>,

        /// Include metadata in the tree response
        #[arg(long)]
        metadata: bool,

        /// Fetch and print the raw content of the artifact at --path
        #[arg(long, requires = "path")]
        content: bool,

        /// Truncate fetched content to at most this many bytes (with --content)
        #[arg(long)]
        max_bytes: Option<i64>,
    },
}

impl PackagesCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List {
                repo,
                pkg_format,
                search,
                page,
                per_page,
            } => {
                list_packages(
                    repo.as_deref(),
                    pkg_format.as_deref(),
                    search.as_deref(),
                    page,
                    per_page,
                    global,
                )
                .await
            }
            Self::Show { id } => show_package(&id, global).await,
            Self::Versions { id } => list_versions(&id, global).await,
            Self::Tree {
                repo,
                path,
                metadata,
                content,
                max_bytes,
            } => browse_tree(&repo, path.as_deref(), metadata, content, max_bytes, global).await,
        }
    }
}

async fn list_packages(
    repo: Option<&str>,
    pkg_format: Option<&str>,
    search: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching packages...");

    let mut req = client.list_packages().page(page).per_page(per_page);
    if let Some(r) = repo {
        req = req.repository_key(r);
    }
    if let Some(f) = pkg_format {
        req = req.format(f);
    }
    if let Some(q) = search {
        req = req.search(q);
    }

    let resp = req.send().await.map_err(|e| sdk_err("list packages", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No packages found.");
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
                "name": p.name,
                "version": p.version,
                "format": p.format,
                "repository_key": p.repository_key,
                "size_bytes": p.size_bytes,
                "download_count": p.download_count,
                "updated_at": p.updated_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID",
            "NAME",
            "VERSION",
            "FORMAT",
            "REPOSITORY",
            "SIZE",
            "DOWNLOADS",
            "UPDATED",
        ]);

        for p in &resp.items {
            let id_short = short_id(&p.id);
            let size = format_bytes(p.size_bytes);
            let downloads = p.download_count.to_string();
            let updated = p.updated_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![
                &id_short,
                &p.name,
                &p.version,
                &p.format,
                &p.repository_key,
                &size,
                &downloads,
                &updated,
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
        "packages",
    );

    Ok(())
}

async fn show_package(id: &str, global: &GlobalArgs) -> Result<()> {
    let package_id = parse_uuid(id, "package")?;

    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching package...");

    let pkg = client
        .get_package()
        .id(package_id)
        .send()
        .await
        .map_err(|e| sdk_err("get package", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "id": pkg.id.to_string(),
        "name": pkg.name,
        "version": pkg.version,
        "format": pkg.format,
        "repository_key": pkg.repository_key,
        "description": pkg.description,
        "size_bytes": pkg.size_bytes,
        "download_count": pkg.download_count,
        "metadata": pkg.metadata,
        "created_at": pkg.created_at.to_rfc3339(),
        "updated_at": pkg.updated_at.to_rfc3339(),
    });

    let table_str = format_package_detail(&pkg);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn list_versions(id: &str, global: &GlobalArgs) -> Result<()> {
    let package_id = parse_uuid(id, "package")?;

    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching package versions...");

    let resp = client
        .get_package_versions()
        .id(package_id)
        .send()
        .await
        .map_err(|e| sdk_err("get package versions", e))?;

    spinner.finish_and_clear();

    if resp.versions.is_empty() {
        eprintln!("No versions found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for v in &resp.versions {
            println!("{}", v.version);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .versions
        .iter()
        .map(|v| {
            serde_json::json!({
                "version": v.version,
                "size_bytes": v.size_bytes,
                "download_count": v.download_count,
                "checksum_sha256": v.checksum_sha256,
                "created_at": v.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["VERSION", "SIZE", "DOWNLOADS", "SHA256", "CREATED"]);

        for v in &resp.versions {
            let size = format_bytes(v.size_bytes);
            let downloads = v.download_count.to_string();
            let checksum = if v.checksum_sha256.len() >= 12 {
                &v.checksum_sha256[..12]
            } else {
                &v.checksum_sha256
            };
            let created = v.created_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![&v.version, &size, &downloads, checksum, &created]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn browse_tree(
    repo: &str,
    path: Option<&str>,
    metadata: bool,
    content: bool,
    max_bytes: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    if content {
        return fetch_content(repo, path, max_bytes, global).await;
    }

    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Browsing repository tree...");

    let mut req = client.get_tree().repository_key(repo);
    if let Some(p) = path {
        req = req.path(p);
    }
    if metadata {
        req = req.include_metadata(true);
    }

    let resp = req.send().await.map_err(|e| sdk_err("browse tree", e))?;

    spinner.finish_and_clear();

    if resp.nodes.is_empty() {
        eprintln!("No entries found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for n in &resp.nodes {
            println!("{}", n.path);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .nodes
        .iter()
        .map(|n| {
            serde_json::json!({
                "name": n.name,
                "type": n.type_,
                "path": n.path,
                "size_bytes": n.size_bytes,
                "has_children": n.has_children,
                "children_count": n.children_count,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["NAME", "TYPE", "PATH", "SIZE", "CHILDREN"]);

        for n in &resp.nodes {
            let size = n
                .size_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "-".to_string());
            let children = n
                .children_count
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![&n.name, &n.type_, &n.path, &size, &children]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn fetch_content(
    repo: &str,
    path: Option<&str>,
    max_bytes: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let path = path.ok_or_else(|| {
        AkError::ConfigError("--path is required when using --content".to_string())
    })?;

    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching content...");

    let mut req = client.get_content().repository_key(repo).path(path);
    if let Some(n) = max_bytes {
        req = req.max_bytes(n);
    }

    let resp = req.send().await.map_err(|e| sdk_err("get content", e))?;

    spinner.finish_and_clear();

    let mut stream = resp.into_inner();
    let mut stdout = tokio::io::stdout();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| AkError::ServerError(format!("content stream error: {e}")))?;
        tokio::io::AsyncWriteExt::write_all(&mut stdout, &chunk)
            .await
            .into_diagnostic()?;
    }
    tokio::io::AsyncWriteExt::flush(&mut stdout)
        .await
        .into_diagnostic()?;

    Ok(())
}

fn format_package_detail(pkg: &artifact_keeper_sdk::types::PackageResponse) -> String {
    format!(
        "ID:           {}\n\
         Name:         {}\n\
         Version:      {}\n\
         Format:       {}\n\
         Repository:   {}\n\
         Description:  {}\n\
         Size:         {}\n\
         Downloads:    {}\n\
         Created:      {}\n\
         Updated:      {}",
        pkg.id,
        pkg.name,
        pkg.version,
        pkg.format,
        pkg.repository_key,
        pkg.description.as_deref().unwrap_or("-"),
        format_bytes(pkg.size_bytes),
        pkg.download_count,
        pkg.created_at.to_rfc3339(),
        pkg.updated_at.to_rfc3339(),
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
        command: PackagesCommand,
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
            PackagesCommand::List {
                repo,
                pkg_format,
                search,
                page,
                per_page,
            } => {
                assert!(repo.is_none());
                assert!(pkg_format.is_none());
                assert!(search.is_none());
                assert_eq!(page, 1);
                assert_eq!(per_page, 20);
            }
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn parse_list_with_filters() {
        let cli = parse(&[
            "test",
            "list",
            "--repo",
            "npm-local",
            "--pkg-format",
            "npm",
            "--search",
            "left-pad",
            "--page",
            "2",
            "--per-page",
            "5",
        ]);
        match cli.command {
            PackagesCommand::List {
                repo,
                pkg_format,
                search,
                page,
                per_page,
            } => {
                assert_eq!(repo.as_deref(), Some("npm-local"));
                assert_eq!(pkg_format.as_deref(), Some("npm"));
                assert_eq!(search.as_deref(), Some("left-pad"));
                assert_eq!(page, 2);
                assert_eq!(per_page, 5);
            }
            _ => panic!("expected List"),
        }
    }

    // ---- parsing: show / versions ----

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "00000000-0000-0000-0000-000000000001"]);
        match cli.command {
            PackagesCommand::Show { id } => {
                assert_eq!(id, "00000000-0000-0000-0000-000000000001");
            }
            _ => panic!("expected Show"),
        }
    }

    #[test]
    fn parse_show_missing_id() {
        assert!(try_parse(&["test", "show"]).is_err());
    }

    #[test]
    fn parse_versions() {
        let cli = parse(&["test", "versions", "some-id"]);
        match cli.command {
            PackagesCommand::Versions { id } => assert_eq!(id, "some-id"),
            _ => panic!("expected Versions"),
        }
    }

    // ---- parsing: tree ----

    #[test]
    fn parse_tree_minimal() {
        let cli = parse(&["test", "tree", "npm-local"]);
        match cli.command {
            PackagesCommand::Tree {
                repo,
                path,
                metadata,
                content,
                max_bytes,
            } => {
                assert_eq!(repo, "npm-local");
                assert!(path.is_none());
                assert!(!metadata);
                assert!(!content);
                assert!(max_bytes.is_none());
            }
            _ => panic!("expected Tree"),
        }
    }

    #[test]
    fn parse_tree_with_path_metadata() {
        let cli = parse(&[
            "test",
            "tree",
            "npm-local",
            "--path",
            "org/pkg",
            "--metadata",
        ]);
        match cli.command {
            PackagesCommand::Tree {
                repo,
                path,
                metadata,
                ..
            } => {
                assert_eq!(repo, "npm-local");
                assert_eq!(path.as_deref(), Some("org/pkg"));
                assert!(metadata);
            }
            _ => panic!("expected Tree"),
        }
    }

    #[test]
    fn parse_tree_content() {
        let cli = parse(&[
            "test",
            "tree",
            "npm-local",
            "--path",
            "org/pkg/1.0/pkg.tgz",
            "--content",
            "--max-bytes",
            "1024",
        ]);
        match cli.command {
            PackagesCommand::Tree {
                content, max_bytes, ..
            } => {
                assert!(content);
                assert_eq!(max_bytes, Some(1024));
            }
            _ => panic!("expected Tree"),
        }
    }

    #[test]
    fn parse_tree_content_requires_path() {
        // --content without --path must be rejected by clap (requires = "path").
        assert!(try_parse(&["test", "tree", "npm-local", "--content"]).is_err());
    }

    #[test]
    fn parse_tree_missing_repo() {
        assert!(try_parse(&["test", "tree"]).is_err());
    }

    // ---- format function ----

    #[test]
    fn format_package_detail_renders() {
        let pkg: artifact_keeper_sdk::types::PackageResponse =
            serde_json::from_value(package_json()).unwrap();
        let detail = format_package_detail(&pkg);
        assert!(detail.contains("left-pad"));
        assert!(detail.contains("1.3.0"));
        assert!(detail.contains("npm"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn package_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "left-pad",
            "version": "1.3.0",
            "format": "npm",
            "repository_key": "npm-local",
            "description": "String padding",
            "size_bytes": 2048,
            "download_count": 42,
            "metadata": {},
            "created_at": "2026-07-01T12:00:00Z",
            "updated_at": "2026-07-02T12:00:00Z"
        })
    }

    fn versions_json() -> serde_json::Value {
        json!({
            "versions": [
                {
                    "version": "1.3.0",
                    "checksum_sha256": "abc123def456abc123def456",
                    "size_bytes": 2048,
                    "download_count": 42,
                    "created_at": "2026-07-01T12:00:00Z"
                }
            ]
        })
    }

    fn tree_json() -> serde_json::Value {
        json!({
            "nodes": [
                {
                    "id": "node-1",
                    "name": "left-pad",
                    "type": "directory",
                    "path": "left-pad",
                    "has_children": true,
                    "children_count": 3,
                    "size_bytes": null,
                    "repository_key": "npm-local",
                    "created_at": null
                }
            ]
        })
    }

    #[tokio::test]
    async fn handler_list_packages_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/packages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 20, "total": 0, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_packages(None, None, None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_packages_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/packages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [package_json()],
                "pagination": { "page": 1, "per_page": 20, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result =
            list_packages(Some("npm-local"), Some("npm"), Some("left"), 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_packages_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/packages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [package_json()],
                "pagination": { "page": 1, "per_page": 20, "total": 1, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_packages(None, None, None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_package() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/packages/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(package_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_package(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_versions() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/packages/{NIL_UUID}/versions")))
            .respond_with(ResponseTemplate::new(200).set_body_json(versions_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_versions(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_browse_tree() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/tree"))
            .respond_with(ResponseTemplate::new(200).set_body_json(tree_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = browse_tree("npm-local", Some("left-pad"), true, false, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_browse_tree_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/tree"))
            .respond_with(ResponseTemplate::new(200).set_body_json(tree_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = browse_tree("npm-local", None, false, false, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_fetch_content() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/tree/content"))
            .respond_with(ResponseTemplate::new(200).set_body_string("file body"))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = browse_tree(
            "npm-local",
            Some("a/b/c.txt"),
            false,
            true,
            Some(1024),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn fetch_content_requires_path() {
        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = fetch_content("npm-local", None, None, &global).await;
        assert!(result.is_err());
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_packages_json() {
        let items = vec![package_json()];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("packages_json", parsed);
    }
}
