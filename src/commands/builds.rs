use artifact_keeper_sdk::ClientBuildsExt;
use clap::Subcommand;
use miette::Result;

use super::client::{client_for, client_for_optional_auth};
use super::helpers::{new_table, parse_uuid, print_page_info, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum BuildsCommand {
    /// List CI build records
    List {
        /// Filter by build status (running, success, failed, etc.)
        #[arg(long)]
        status: Option<String>,

        /// Search by build name
        #[arg(long)]
        search: Option<String>,

        /// Sort field (created_at, number, name, status)
        #[arg(long)]
        sort_by: Option<String>,

        /// Sort order (asc, desc)
        #[arg(long)]
        sort_order: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: i32,
    },

    /// Show details for a build
    Show {
        /// Build ID
        id: String,
    },

    /// Diff the artifacts of two builds
    Diff {
        /// First build ID
        build_a: String,

        /// Second build ID
        build_b: String,
    },

    /// Record a new build
    Create {
        /// Build name
        name: String,

        /// Build number
        #[arg(long)]
        number: i32,

        /// Build agent / runner
        #[arg(long)]
        agent: Option<String>,

        /// VCS branch
        #[arg(long)]
        vcs_branch: Option<String>,

        /// VCS revision (commit SHA)
        #[arg(long)]
        vcs_revision: Option<String>,

        /// VCS repository URL
        #[arg(long)]
        vcs_url: Option<String>,

        /// VCS commit message
        #[arg(long)]
        vcs_message: Option<String>,

        /// Metadata as a JSON object (e.g. '{"pipeline":"ci"}')
        #[arg(long)]
        metadata: Option<String>,
    },

    /// Update build status
    Update {
        /// Build ID
        id: String,

        /// New status (running, success, failed, cancelled)
        #[arg(long)]
        status: String,

        /// Finish timestamp (RFC 3339, e.g. 2026-01-15T12:00:00Z)
        #[arg(long)]
        finished_at: Option<String>,
    },

    /// Attach artifacts to a build
    AddArtifacts {
        /// Build ID
        id: String,

        /// Artifact in the form name:path:sha256:size_bytes[:module] (repeatable)
        #[arg(long = "artifact", required = true)]
        artifacts: Vec<String>,
    },
}

impl BuildsCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List {
                status,
                search,
                sort_by,
                sort_order,
                page,
                per_page,
            } => {
                list_builds(
                    status.as_deref(),
                    search.as_deref(),
                    sort_by.as_deref(),
                    sort_order.as_deref(),
                    page,
                    per_page,
                    global,
                )
                .await
            }
            Self::Show { id } => show_build(&id, global).await,
            Self::Diff { build_a, build_b } => diff_builds(&build_a, &build_b, global).await,
            Self::Create {
                name,
                number,
                agent,
                vcs_branch,
                vcs_revision,
                vcs_url,
                vcs_message,
                metadata,
            } => {
                create_build(
                    &name,
                    number,
                    agent.as_deref(),
                    vcs_branch.as_deref(),
                    vcs_revision.as_deref(),
                    vcs_url.as_deref(),
                    vcs_message.as_deref(),
                    metadata.as_deref(),
                    global,
                )
                .await
            }
            Self::Update {
                id,
                status,
                finished_at,
            } => update_build(&id, &status, finished_at.as_deref(), global).await,
            Self::AddArtifacts { id, artifacts } => add_artifacts(&id, &artifacts, global).await,
        }
    }
}

async fn list_builds(
    status: Option<&str>,
    search: Option<&str>,
    sort_by: Option<&str>,
    sort_order: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching builds...");

    let mut req = client.list_builds().page(page).per_page(per_page);
    if let Some(s) = status {
        req = req.status(s);
    }
    if let Some(q) = search {
        req = req.search(q);
    }
    if let Some(f) = sort_by {
        req = req.sort_by(f);
    }
    if let Some(o) = sort_order {
        req = req.sort_order(o);
    }

    let resp = req.send().await.map_err(|e| sdk_err("list builds", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No builds found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for b in &resp.items {
            println!("{}", b.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|b| {
            serde_json::json!({
                "id": b.id.to_string(),
                "name": b.name,
                "number": b.number,
                "status": b.status,
                "agent": b.agent,
                "artifact_count": b.artifact_count,
                "vcs_branch": b.vcs_branch,
                "vcs_revision": b.vcs_revision,
                "created_at": b.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID",
            "NAME",
            "NUM",
            "STATUS",
            "AGENT",
            "ARTIFACTS",
            "CREATED",
        ]);

        for b in &resp.items {
            let id_short = short_id(&b.id);
            let number = b.number.to_string();
            let agent = b.agent.as_deref().unwrap_or("-");
            let count = b
                .artifact_count
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());
            let created = b.created_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![
                &id_short, &b.name, &number, &b.status, agent, &count, &created,
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
        "builds",
    );

    Ok(())
}

async fn show_build(id: &str, global: &GlobalArgs) -> Result<()> {
    let build_id = parse_uuid(id, "build")?;

    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Fetching build...");

    let build = client
        .get_build()
        .id(build_id)
        .send()
        .await
        .map_err(|e| sdk_err("get build", e))?;

    spinner.finish_and_clear();

    let modules: Vec<_> = build
        .modules
        .as_ref()
        .map(|ms| ms.iter().map(|m| m.name.clone()).collect())
        .unwrap_or_default();

    let info = serde_json::json!({
        "id": build.id.to_string(),
        "name": build.name,
        "number": build.number,
        "status": build.status,
        "agent": build.agent,
        "artifact_count": build.artifact_count,
        "duration_ms": build.duration_ms,
        "vcs_branch": build.vcs_branch,
        "vcs_revision": build.vcs_revision,
        "vcs_url": build.vcs_url,
        "vcs_message": build.vcs_message,
        "modules": modules,
        "metadata": build.metadata,
        "started_at": build.started_at.map(|d| d.to_rfc3339()),
        "finished_at": build.finished_at.map(|d| d.to_rfc3339()),
        "created_at": build.created_at.to_rfc3339(),
        "updated_at": build.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:          {}\n\
         Name:        {}\n\
         Number:      {}\n\
         Status:      {}\n\
         Agent:       {}\n\
         Artifacts:   {}\n\
         Duration:    {}\n\
         VCS Branch:  {}\n\
         VCS Rev:     {}\n\
         VCS URL:     {}\n\
         Started:     {}\n\
         Finished:    {}\n\
         Created:     {}\n\
         Updated:     {}",
        build.id,
        build.name,
        build.number,
        build.status,
        build.agent.as_deref().unwrap_or("-"),
        build
            .artifact_count
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".into()),
        build
            .duration_ms
            .map(|d| format!("{d} ms"))
            .unwrap_or_else(|| "-".into()),
        build.vcs_branch.as_deref().unwrap_or("-"),
        build.vcs_revision.as_deref().unwrap_or("-"),
        build.vcs_url.as_deref().unwrap_or("-"),
        build
            .started_at
            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".into()),
        build
            .finished_at
            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".into()),
        build.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        build.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn diff_builds(build_a: &str, build_b: &str, global: &GlobalArgs) -> Result<()> {
    let a = parse_uuid(build_a, "build")?;
    let b = parse_uuid(build_b, "build")?;

    let client = client_for_optional_auth(global)?;
    let spinner = output::spinner("Computing build diff...");

    let diff = client
        .get_build_diff()
        .build_a(a)
        .build_b(b)
        .send()
        .await
        .map_err(|e| sdk_err("diff builds", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "build_a": diff.build_a.to_string(),
        "build_b": diff.build_b.to_string(),
        "added": diff.added.iter().map(|a| serde_json::json!({
            "name": a.name,
            "path": a.path,
            "size_bytes": a.size_bytes,
        })).collect::<Vec<_>>(),
        "removed": diff.removed.iter().map(|r| serde_json::json!({
            "name": r.name,
            "path": r.path,
            "size_bytes": r.size_bytes,
        })).collect::<Vec<_>>(),
        "modified": diff.modified.iter().map(|m| serde_json::json!({
            "name": m.name,
            "path": m.path,
            "old_size_bytes": m.old_size_bytes,
            "new_size_bytes": m.new_size_bytes,
        })).collect::<Vec<_>>(),
    });

    if matches!(global.format, OutputFormat::Quiet) {
        println!(
            "+{} -{} ~{}",
            diff.added.len(),
            diff.removed.len(),
            diff.modified.len()
        );
        return Ok(());
    }

    let table_str = {
        let mut table = new_table(vec!["CHANGE", "NAME", "PATH", "SIZE"]);
        for a in &diff.added {
            table.add_row(vec![
                "added",
                &a.name,
                &a.path,
                &output::format_bytes(a.size_bytes),
            ]);
        }
        for r in &diff.removed {
            table.add_row(vec![
                "removed",
                &r.name,
                &r.path,
                &output::format_bytes(r.size_bytes),
            ]);
        }
        for m in &diff.modified {
            let size = format!(
                "{} -> {}",
                output::format_bytes(m.old_size_bytes),
                output::format_bytes(m.new_size_bytes)
            );
            table.add_row(vec!["modified", &m.name, &m.path, &size]);
        }
        table.to_string()
    };

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    eprintln!(
        "{} added, {} removed, {} modified.",
        diff.added.len(),
        diff.removed.len(),
        diff.modified.len()
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create_build(
    name: &str,
    number: i32,
    agent: Option<&str>,
    vcs_branch: Option<&str>,
    vcs_revision: Option<&str>,
    vcs_url: Option<&str>,
    vcs_message: Option<&str>,
    metadata: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let metadata_map = parse_metadata(metadata)?;

    let client = client_for(global)?;
    let spinner = output::spinner("Recording build...");

    let body = artifact_keeper_sdk::types::CreateBuildRequest {
        name: name.to_string(),
        build_number: number,
        agent: agent.map(|s| s.to_string()),
        vcs_branch: vcs_branch.map(|s| s.to_string()),
        vcs_revision: vcs_revision.map(|s| s.to_string()),
        vcs_url: vcs_url.map(|s| s.to_string()),
        vcs_message: vcs_message.map(|s| s.to_string()),
        started_at: None,
        metadata: metadata_map,
    };

    let build = client
        .create_build()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create build", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", build.id);
        return Ok(());
    }

    eprintln!(
        "Recorded build '{}' #{} (ID: {}, status: {}).",
        build.name, build.number, build.id, build.status
    );

    Ok(())
}

async fn update_build(
    id: &str,
    status: &str,
    finished_at: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let build_id = parse_uuid(id, "build")?;
    let finished = parse_datetime(finished_at)?;

    let client = client_for(global)?;
    let spinner = output::spinner("Updating build...");

    let body = artifact_keeper_sdk::types::UpdateBuildRequest {
        status: status.to_string(),
        finished_at: finished,
    };

    let build = client
        .update_build()
        .id(build_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update build", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", build.id);
        return Ok(());
    }

    eprintln!("Build {} updated (status: {}).", build.id, build.status);

    Ok(())
}

async fn add_artifacts(id: &str, artifacts: &[String], global: &GlobalArgs) -> Result<()> {
    let build_id = parse_uuid(id, "build")?;

    let payloads = artifacts
        .iter()
        .map(|s| parse_artifact_spec(s))
        .collect::<Result<Vec<_>>>()?;

    let client = client_for(global)?;
    let spinner = output::spinner("Attaching artifacts...");

    let body = artifact_keeper_sdk::types::AddBuildArtifactsRequest {
        artifacts: payloads,
    };

    let resp = client
        .add_build_artifacts()
        .id(build_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("add build artifacts", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        for a in &resp.artifacts {
            println!("{}", a.id);
        }
        return Ok(());
    }

    if resp.artifacts.is_empty() {
        eprintln!("No artifacts attached.");
        return Ok(());
    }

    let entries: Vec<_> = resp
        .artifacts
        .iter()
        .map(|a| {
            serde_json::json!({
                "id": a.id.to_string(),
                "name": a.name,
                "path": a.path,
                "module": a.module_name,
                "size_bytes": a.size_bytes,
                "checksum_sha256": a.checksum_sha256,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "PATH", "MODULE", "SIZE"]);
        for a in &resp.artifacts {
            let id_short = short_id(&a.id);
            let module = a.module_name.as_deref().unwrap_or("-");
            let size = output::format_bytes(a.size_bytes);
            table.add_row(vec![&id_short, &a.name, &a.path, module, &size]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} artifact(s) attached.", resp.artifacts.len());

    Ok(())
}

/// Parse a `--metadata` JSON object string into a serde_json map.
fn parse_metadata(metadata: Option<&str>) -> Result<serde_json::Map<String, serde_json::Value>> {
    match metadata {
        None => Ok(serde_json::Map::new()),
        Some(raw) => {
            let value: serde_json::Value = serde_json::from_str(raw)
                .map_err(|e| AkError::ConfigError(format!("Invalid metadata JSON: {e}")))?;
            match value {
                serde_json::Value::Object(map) => Ok(map),
                _ => Err(AkError::ConfigError("Metadata must be a JSON object".to_string()).into()),
            }
        }
    }
}

/// Parse an optional RFC 3339 timestamp into a UTC datetime.
fn parse_datetime(value: Option<&str>) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    match value {
        None => Ok(None),
        Some(raw) => {
            let dt = chrono::DateTime::parse_from_rfc3339(raw)
                .map_err(|e| AkError::ConfigError(format!("Invalid timestamp '{raw}': {e}")))?;
            Ok(Some(dt.with_timezone(&chrono::Utc)))
        }
    }
}

/// Parse a `name:path:sha256:size_bytes[:module]` artifact spec.
fn parse_artifact_spec(
    spec: &str,
) -> Result<artifact_keeper_sdk::types::BuildArtifactInputPayload> {
    let parts: Vec<&str> = spec.splitn(5, ':').collect();
    if parts.len() < 4 {
        return Err(AkError::ConfigError(format!(
            "Invalid artifact spec '{spec}': expected name:path:sha256:size_bytes[:module]"
        ))
        .into());
    }
    let size_bytes: i64 = parts[3]
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid size in artifact spec '{spec}'")))?;
    let module_name = parts
        .get(4)
        .filter(|m| !m.is_empty())
        .map(|m| m.to_string());

    Ok(artifact_keeper_sdk::types::BuildArtifactInputPayload {
        name: parts[0].to_string(),
        path: parts[1].to_string(),
        checksum_sha256: parts[2].to_string(),
        size_bytes,
        module_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: BuildsCommand,
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
        if let BuildsCommand::List {
            status,
            search,
            sort_by,
            sort_order,
            page,
            per_page,
        } = cli.command
        {
            assert!(status.is_none());
            assert!(search.is_none());
            assert!(sort_by.is_none());
            assert!(sort_order.is_none());
            assert_eq!(page, 1);
            assert_eq!(per_page, 20);
        } else {
            panic!("expected List");
        }
    }

    #[test]
    fn parse_list_all_options() {
        let cli = parse(&[
            "test",
            "list",
            "--status",
            "success",
            "--search",
            "nightly",
            "--sort-by",
            "number",
            "--sort-order",
            "desc",
            "--page",
            "3",
            "--per-page",
            "10",
        ]);
        if let BuildsCommand::List {
            status,
            search,
            sort_by,
            sort_order,
            page,
            per_page,
        } = cli.command
        {
            assert_eq!(status.as_deref(), Some("success"));
            assert_eq!(search.as_deref(), Some("nightly"));
            assert_eq!(sort_by.as_deref(), Some("number"));
            assert_eq!(sort_order.as_deref(), Some("desc"));
            assert_eq!(page, 3);
            assert_eq!(per_page, 10);
        } else {
            panic!("expected List");
        }
    }

    // ---- parsing: show ----

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "00000000-0000-0000-0000-000000000001"]);
        if let BuildsCommand::Show { id } = cli.command {
            assert_eq!(id, "00000000-0000-0000-0000-000000000001");
        } else {
            panic!("expected Show");
        }
    }

    #[test]
    fn parse_show_missing_id_fails() {
        assert!(try_parse(&["test", "show"]).is_err());
    }

    // ---- parsing: diff ----

    #[test]
    fn parse_diff() {
        let cli = parse(&["test", "diff", "aaaa", "bbbb"]);
        if let BuildsCommand::Diff { build_a, build_b } = cli.command {
            assert_eq!(build_a, "aaaa");
            assert_eq!(build_b, "bbbb");
        } else {
            panic!("expected Diff");
        }
    }

    #[test]
    fn parse_diff_missing_second_fails() {
        assert!(try_parse(&["test", "diff", "aaaa"]).is_err());
    }

    // ---- parsing: create ----

    #[test]
    fn parse_create_minimal() {
        let cli = parse(&["test", "create", "my-build", "--number", "42"]);
        if let BuildsCommand::Create { name, number, .. } = cli.command {
            assert_eq!(name, "my-build");
            assert_eq!(number, 42);
        } else {
            panic!("expected Create");
        }
    }

    #[test]
    fn parse_create_with_vcs() {
        let cli = parse(&[
            "test",
            "create",
            "ci-build",
            "--number",
            "7",
            "--agent",
            "runner-1",
            "--vcs-branch",
            "main",
            "--vcs-revision",
            "abc123",
            "--vcs-url",
            "https://git.example.com/repo",
            "--vcs-message",
            "fix: bug",
            "--metadata",
            "{\"pipeline\":\"nightly\"}",
        ]);
        if let BuildsCommand::Create {
            agent,
            vcs_branch,
            vcs_revision,
            vcs_url,
            vcs_message,
            metadata,
            ..
        } = cli.command
        {
            assert_eq!(agent.as_deref(), Some("runner-1"));
            assert_eq!(vcs_branch.as_deref(), Some("main"));
            assert_eq!(vcs_revision.as_deref(), Some("abc123"));
            assert_eq!(vcs_url.as_deref(), Some("https://git.example.com/repo"));
            assert_eq!(vcs_message.as_deref(), Some("fix: bug"));
            assert_eq!(metadata.as_deref(), Some("{\"pipeline\":\"nightly\"}"));
        } else {
            panic!("expected Create");
        }
    }

    #[test]
    fn parse_create_missing_number_fails() {
        assert!(try_parse(&["test", "create", "my-build"]).is_err());
    }

    // ---- parsing: update ----

    #[test]
    fn parse_update() {
        let cli = parse(&["test", "update", "some-id", "--status", "success"]);
        if let BuildsCommand::Update {
            id,
            status,
            finished_at,
        } = cli.command
        {
            assert_eq!(id, "some-id");
            assert_eq!(status, "success");
            assert!(finished_at.is_none());
        } else {
            panic!("expected Update");
        }
    }

    #[test]
    fn parse_update_with_finished_at() {
        let cli = parse(&[
            "test",
            "update",
            "some-id",
            "--status",
            "failed",
            "--finished-at",
            "2026-01-15T12:00:00Z",
        ]);
        if let BuildsCommand::Update { finished_at, .. } = cli.command {
            assert_eq!(finished_at.as_deref(), Some("2026-01-15T12:00:00Z"));
        } else {
            panic!("expected Update");
        }
    }

    #[test]
    fn parse_update_missing_status_fails() {
        assert!(try_parse(&["test", "update", "some-id"]).is_err());
    }

    // ---- parsing: add-artifacts ----

    #[test]
    fn parse_add_artifacts() {
        let cli = parse(&[
            "test",
            "add-artifacts",
            "some-id",
            "--artifact",
            "app.jar:com/example/app.jar:deadbeef:1024",
            "--artifact",
            "lib.jar:com/example/lib.jar:cafe:512:core",
        ]);
        if let BuildsCommand::AddArtifacts { id, artifacts } = cli.command {
            assert_eq!(id, "some-id");
            assert_eq!(artifacts.len(), 2);
        } else {
            panic!("expected AddArtifacts");
        }
    }

    #[test]
    fn parse_add_artifacts_missing_artifact_fails() {
        assert!(try_parse(&["test", "add-artifacts", "some-id"]).is_err());
    }

    // ---- parse_metadata ----

    #[test]
    fn parse_metadata_none_is_empty() {
        let map = parse_metadata(None).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn parse_metadata_valid_object() {
        let map = parse_metadata(Some("{\"a\":1,\"b\":\"x\"}")).unwrap();
        assert_eq!(map.get("a").and_then(|v| v.as_i64()), Some(1));
        assert_eq!(map.get("b").and_then(|v| v.as_str()), Some("x"));
    }

    #[test]
    fn parse_metadata_non_object_fails() {
        assert!(parse_metadata(Some("[1,2,3]")).is_err());
    }

    #[test]
    fn parse_metadata_invalid_json_fails() {
        assert!(parse_metadata(Some("{not json")).is_err());
    }

    // ---- parse_datetime ----

    #[test]
    fn parse_datetime_none() {
        assert!(parse_datetime(None).unwrap().is_none());
    }

    #[test]
    fn parse_datetime_valid() {
        let dt = parse_datetime(Some("2026-01-15T12:00:00Z")).unwrap();
        assert!(dt.is_some());
    }

    #[test]
    fn parse_datetime_invalid_fails() {
        assert!(parse_datetime(Some("not-a-date")).is_err());
    }

    // ---- parse_artifact_spec ----

    #[test]
    fn parse_artifact_spec_minimal() {
        let a = parse_artifact_spec("app.jar:com/example/app.jar:deadbeef:1024").unwrap();
        assert_eq!(a.name, "app.jar");
        assert_eq!(a.path, "com/example/app.jar");
        assert_eq!(a.checksum_sha256, "deadbeef");
        assert_eq!(a.size_bytes, 1024);
        assert!(a.module_name.is_none());
    }

    #[test]
    fn parse_artifact_spec_with_module() {
        let a = parse_artifact_spec("lib.jar:com/example/lib.jar:cafe:512:core").unwrap();
        assert_eq!(a.module_name.as_deref(), Some("core"));
        assert_eq!(a.size_bytes, 512);
    }

    #[test]
    fn parse_artifact_spec_too_few_fields_fails() {
        assert!(parse_artifact_spec("app.jar:path:checksum").is_err());
    }

    #[test]
    fn parse_artifact_spec_bad_size_fails() {
        assert!(parse_artifact_spec("app.jar:path:checksum:notanumber").is_err());
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn build_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "nightly",
            "number": 42,
            "status": "success",
            "agent": "runner-1",
            "artifact_count": 2,
            "duration_ms": 12000_i64,
            "metadata": {},
            "vcs_branch": "main",
            "vcs_revision": "abc123",
            "vcs_url": "https://git.example.com/repo",
            "vcs_message": "fix: bug",
            "started_at": "2026-01-15T12:00:00Z",
            "finished_at": "2026-01-15T12:00:12Z",
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:12Z"
        })
    }

    #[tokio::test]
    async fn handler_list_builds_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/builds"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 20, "total": 0, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_builds(None, None, None, None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_builds_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/builds"))
            .and(query_param("status", "success"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [build_json()],
                "pagination": { "page": 1, "per_page": 20, "total": 1_i64, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_builds(Some("success"), None, None, None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_build() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/builds/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(build_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_build(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_diff_builds() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/builds/diff"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "build_a": NIL_UUID,
                "build_b": NIL_UUID,
                "added": [{ "name": "new.jar", "path": "com/new.jar", "checksum_sha256": "aa", "size_bytes": 100_i64 }],
                "removed": [],
                "modified": [{ "name": "app.jar", "path": "com/app.jar", "old_checksum": "bb", "new_checksum": "cc", "old_size_bytes": 200_i64, "new_size_bytes": 250_i64 }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = diff_builds(NIL_UUID, NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_build_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/builds"))
            .respond_with(ResponseTemplate::new(200).set_body_json(build_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = create_build("nightly", 42, None, None, None, None, None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_build() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/builds/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(build_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = update_build(NIL_UUID, "success", None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_add_artifacts() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/builds/.*/artifacts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "artifacts": [{
                    "id": NIL_UUID,
                    "build_id": NIL_UUID,
                    "name": "app.jar",
                    "path": "com/example/app.jar",
                    "module_name": "core",
                    "checksum_sha256": "deadbeef",
                    "size_bytes": 1024_i64,
                    "created_at": "2026-01-15T12:00:00Z"
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let specs = vec!["app.jar:com/example/app.jar:deadbeef:1024:core".to_string()];
        let result = add_artifacts(NIL_UUID, &specs, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot ----

    #[test]
    fn snapshot_build_list_json() {
        let items = vec![json!({
            "id": NIL_UUID,
            "name": "nightly",
            "number": 42,
            "status": "success",
            "agent": "runner-1",
            "artifact_count": 2,
            "vcs_branch": "main",
            "vcs_revision": "abc123",
            "created_at": "2026-01-15T12:00:00Z",
        })];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("builds_list_json", parsed);
    }
}
