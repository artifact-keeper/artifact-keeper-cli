use std::io::Read;

use artifact_keeper_sdk::ClientBundlesExt;
use artifact_keeper_sdk::types::{
    BundleFormatResponse, BundleJob, BundleJobItem, CreateBundleExportRequest,
    ManifestValidationReport, MediaProfile,
};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::{client_for, raw_http_client, resolve_base_url_and_auth};
use super::helpers::{new_table, or_since_1_11, parse_uuid, since_1_11_raw};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

/// The group, for the message on a server older than these routes.
const COMMAND: &str = "bundle";

const MEDIA_PROFILES: [&str; 5] = ["unbounded", "dvd_r", "dvd_r_dl", "bd_r", "bd_r_xl"];

#[derive(Subcommand)]
pub enum BundleCommand {
    /// Show the bundle format this server reads and writes, and whether it can yet
    Format,

    /// Check a manifest.json without importing anything. Exits 1 if it isn't valid
    ValidateManifest {
        /// Path to the manifest, or - for stdin
        manifest: String,
    },

    /// Export repositories into a bundle. Servers up to 1.11.11 answer 501 Not Implemented
    Export {
        /// Repository key to export (repeat, or comma-separated)
        #[arg(long = "repo", required = true, value_delimiter = ',')]
        repos: Vec<String>,

        /// Media the volume set is sized for (server default: unbounded)
        #[arg(long, value_parser = MEDIA_PROFILES)]
        media_profile: Option<String>,

        /// Custodian's media control number, recorded in the manifest
        #[arg(long)]
        media_control_number: Option<String>,
    },

    /// Import a bundle. Servers up to 1.11.11 answer 501 Not Implemented
    Import,

    /// Inspect export and import jobs
    #[command(subcommand)]
    Jobs(JobsCommand),
}

#[derive(Subcommand)]
pub enum JobsCommand {
    /// List jobs, newest first
    List {
        /// export or import
        #[arg(long)]
        direction: Option<String>,

        /// pending, running, verifying, committing, completed, failed or cancelled
        #[arg(long)]
        status: Option<String>,

        /// Page number
        #[arg(long)]
        page: Option<i64>,

        /// Jobs per page, 1 to 200
        #[arg(long)]
        per_page: Option<i64>,
    },

    /// Show a job
    Show {
        /// Job ID
        id: String,
    },

    /// List the artifact records of a job
    Items {
        /// Job ID
        id: String,

        /// pending, verified, committed, skipped, conflict or failed
        #[arg(long)]
        status: Option<String>,

        /// Page number
        #[arg(long)]
        page: Option<i64>,

        /// Items per page, 1 to 200
        #[arg(long)]
        per_page: Option<i64>,
    },
}

impl BundleCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Format => show_format(global).await,
            Self::ValidateManifest { manifest } => validate_manifest(&manifest, global).await,
            Self::Export {
                repos,
                media_profile,
                media_control_number,
            } => {
                export(
                    repos,
                    media_profile.as_deref(),
                    media_control_number,
                    global,
                )
                .await
            }
            Self::Import => import(global).await,
            Self::Jobs(command) => command.execute(global).await,
        }
    }
}

impl JobsCommand {
    async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List {
                direction,
                status,
                page,
                per_page,
            } => list_jobs(direction, status, page, per_page, global).await,
            Self::Show { id } => show_job(&id, global).await,
            Self::Items {
                id,
                status,
                page,
                per_page,
            } => list_items(&id, status, page, per_page, global).await,
        }
    }
}

/// Read a file, or stdin for `-`.
pub(super) fn read_input(path: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let read = if path == "-" {
        std::io::stdin().lock().read_to_end(&mut bytes).map(|_| ())
    } else {
        std::fs::read(path).map(|content| bytes = content)
    };
    read.map_err(|e| AkError::Usage(format!("Can't read {path}: {e}")))?;
    Ok(bytes)
}

async fn show_format(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching bundle format...");
    let (resp, raw) = artifact_keeper_sdk::raw::capture(client.get_bundle_format().send()).await;
    let format = or_since_1_11(resp, "get bundle format", COMMAND, global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", format.format);
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &format,
            &global.format,
            Some(format_detail(&format))
        )
    );
    Ok(())
}

/// Sends the file's bytes as they are, rather than the SDK's typed manifest: the
/// server's job is to report what's wrong with a manifest, so the CLI mustn't
/// refuse one for failing to parse.
async fn validate_manifest(manifest: &str, global: &GlobalArgs) -> Result<()> {
    let bytes = read_input(manifest)?;
    let (base_url, auth) = resolve_base_url_and_auth(global)?;
    let spinner = output::spinner("Validating manifest...");
    let resp = raw_http_client()?
        .post(format!("{base_url}/api/v1/bundles/manifest/validate"))
        .header(reqwest::header::AUTHORIZATION, &auth)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(bytes)
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("Validate manifest failed: {e}")))?;
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .map_err(|e| AkError::NetworkError(format!("Validate manifest failed: {e}")))?;
    spinner.finish_and_clear();

    if !status.is_success() {
        return Err(since_1_11_raw(
            status,
            &String::from_utf8_lossy(&body),
            "Validate manifest",
            COMMAND,
            global,
        )
        .await
        .into());
    }
    let report: ManifestValidationReport = serde_json::from_slice(&body).map_err(|e| {
        AkError::ServerError(format!("Validate manifest: unexpected response: {e}"))
    })?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", report.valid);
    } else {
        println!(
            "{}",
            output::render_raw(
                Some(&body),
                &report,
                &global.format,
                Some(report_detail(&report))
            )
        );
    }
    if !report.valid {
        std::process::exit(crate::error::EXIT_REPORTED_FAILURE.into());
    }
    Ok(())
}

async fn export(
    repository_keys: Vec<String>,
    media_profile: Option<&str>,
    media_control_number: Option<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let media_profile = media_profile
        .map(|p| p.parse::<MediaProfile>())
        .transpose()
        .map_err(|_| AkError::Usage("Invalid media profile".to_string()))?;
    let body = CreateBundleExportRequest {
        media_control_number,
        media_profile,
        repository_keys,
    };
    let body = serde_json::to_vec(&body)
        .map_err(|e| AkError::Local(format!("Can't encode the request: {e}")))?;
    post_job(
        "/api/v1/bundles/exports",
        Some(body),
        "Export bundle",
        global,
    )
    .await
}

async fn import(global: &GlobalArgs) -> Result<()> {
    post_job("/api/v1/bundles/imports", None, "Import bundle", global).await
}

/// Start an export or import. These are raw requests because the spec lists no
/// success response for either operation yet, so the SDK would treat one as an
/// error. Any 2xx prints what the server sent, and a later server that implements
/// them works without a new CLI.
async fn post_job(
    route: &str,
    body: Option<Vec<u8>>,
    action: &str,
    global: &GlobalArgs,
) -> Result<()> {
    let (base_url, auth) = resolve_base_url_and_auth(global)?;
    let spinner = output::spinner(&format!("{action}..."));
    let mut request = raw_http_client()?
        .post(format!("{base_url}{route}"))
        .header(reqwest::header::AUTHORIZATION, &auth);
    if let Some(body) = body {
        request = request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
    }
    let resp = request
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("{action} failed: {e}")))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| AkError::NetworkError(format!("{action} failed: {e}")))?;
    spinner.finish_and_clear();

    if !status.is_success() {
        return Err(since_1_11_raw(status, &text, action, COMMAND, global)
            .await
            .into());
    }
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", value["id"].as_str().unwrap_or_default());
        return Ok(());
    }
    let human = serde_json::to_string_pretty(&value).unwrap_or_default();
    println!(
        "{}",
        output::render_raw(Some(text.as_bytes()), &value, &global.format, Some(human))
    );
    Ok(())
}

async fn list_jobs(
    direction: Option<String>,
    status: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching bundle jobs...");
    let mut req = client.list_bundle_jobs();
    if let Some(direction) = direction {
        req = req.direction(direction);
    }
    if let Some(status) = status {
        req = req.status(status);
    }
    if let Some(page) = page {
        req = req.page(page);
    }
    if let Some(per_page) = per_page {
        req = req.per_page(per_page);
    }
    let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
    let list = or_since_1_11(resp, "list bundle jobs", COMMAND, global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No bundle jobs found.");
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for job in &list.items {
            println!("{}", job.id);
        }
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &list,
            &global.format,
            Some(jobs_table(&list.items))
        )
    );
    Ok(())
}

async fn show_job(id: &str, global: &GlobalArgs) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching bundle job...");
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.get_bundle_job().id(job_id).send()).await;
    let job = or_since_1_11(resp, "get bundle job", COMMAND, global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", job.id);
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &job, &global.format, Some(job_detail(&job)))
    );
    Ok(())
}

async fn list_items(
    id: &str,
    status: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
    global: &GlobalArgs,
) -> Result<()> {
    let job_id = parse_uuid(id, "job")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching bundle job items...");
    let mut req = client.list_bundle_job_items().id(job_id);
    if let Some(status) = status {
        req = req.status(status);
    }
    if let Some(page) = page {
        req = req.page(page);
    }
    if let Some(per_page) = per_page {
        req = req.per_page(per_page);
    }
    let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
    let list = or_since_1_11(resp, "list bundle job items", COMMAND, global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No items found.");
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for item in &list.items {
            println!("{}", item.id);
        }
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &list,
            &global.format,
            Some(items_table(&list.items))
        )
    );
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn format_detail(f: &BundleFormatResponse) -> String {
    let profiles = f
        .media_profiles
        .iter()
        .map(|p| match p.capacity_bytes {
            Some(bytes) => format!("{} ({})", p.profile, format_bytes(bytes)),
            None => p.profile.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "Format:          {}\n\
         Schema versions: {} to {}\n\
         Container:       {}\n\
         File extension:  {}\n\
         Manifest path:   {}\n\
         Export:          {}\n\
         Import:          {}\n\
         Media profiles:  {}\n\
         Layout:\n  {}",
        f.format,
        f.min_schema_version,
        f.schema_version,
        f.container,
        f.file_extension,
        f.manifest_path,
        if f.export_available {
            "available"
        } else {
            "not available on this server"
        },
        if f.import_available {
            "available"
        } else {
            "not available on this server"
        },
        profiles,
        f.layout.join("\n  "),
    )
}

fn report_detail(r: &ManifestValidationReport) -> String {
    let mut out = format!(
        "Valid:           {}\n\
         Importable:      {}\n\
         Schema version:  {}\n\
         Bundle ID:       {}\n\
         Kind:            {}\n\
         Repositories:    {}\n\
         Items:           {}\n\
         Total size:      {}\n\
         Scan evidence:   {}\n\
         SHA-256:         {}",
        yes_no(r.valid),
        yes_no(r.importable),
        r.schema_version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        r.bundle_id
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        r.kind
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        r.repository_count,
        r.item_count,
        format_bytes(r.total_bytes),
        r.scan_evidence_count,
        r.manifest_sha256,
    );
    for (label, lines) in [
        ("Problems", &r.problems),
        ("Unsupported features", &r.unsupported_features),
    ] {
        if !lines.is_empty() {
            out.push_str(&format!("\n{label}:\n  {}", lines.join("\n  ")));
        }
    }
    out
}

fn jobs_table(jobs: &[BundleJob]) -> String {
    let mut table = new_table(vec![
        "ID",
        "DIRECTION",
        "STATUS",
        "KIND",
        "REPOSITORIES",
        "DONE",
        "FAILED",
        "CREATED",
    ]);
    for j in jobs {
        table.add_row(vec![
            j.id.to_string(),
            j.direction.clone(),
            j.status.clone(),
            j.bundle_kind.clone(),
            j.repository_keys.join(", "),
            format!("{}/{}", j.completed_items, j.total_items),
            j.failed_items.to_string(),
            j.created_at.to_rfc3339(),
        ]);
    }
    table.to_string()
}

fn job_detail(j: &BundleJob) -> String {
    let optional_time = |t: Option<chrono::DateTime<chrono::Utc>>| {
        t.map(|t| t.to_rfc3339()).unwrap_or_else(|| "-".to_string())
    };
    format!(
        "ID:           {}\n\
         Direction:    {}\n\
         Status:       {}\n\
         Kind:         {}\n\
         Bundle ID:    {}\n\
         Repositories: {}\n\
         Media:        {}\n\
         Volumes:      {}\n\
         Items:        {} of {} done, {} failed, {} skipped\n\
         Transferred:  {} of {}\n\
         Error:        {}\n\
         Created:      {}\n\
         Started:      {}\n\
         Finished:     {}",
        j.id,
        j.direction,
        j.status,
        j.bundle_kind,
        j.bundle_id
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        j.repository_keys.join(", "),
        j.media_profile.as_deref().unwrap_or("-"),
        j.volume_count
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string()),
        j.completed_items,
        j.total_items,
        j.failed_items,
        j.skipped_items,
        format_bytes(j.transferred_bytes),
        format_bytes(j.total_bytes),
        j.error_summary.as_deref().unwrap_or("-"),
        j.created_at.to_rfc3339(),
        optional_time(j.started_at),
        optional_time(j.finished_at),
    )
}

fn items_table(items: &[BundleJobItem]) -> String {
    let mut table = new_table(vec!["ID", "REPOSITORY", "PATH", "STATUS", "SIZE", "ERROR"]);
    for i in items {
        table.add_row(vec![
            i.id.to_string(),
            i.repository_key.clone(),
            i.logical_path.clone(),
            i.status.clone(),
            format_bytes(i.size_bytes),
            i.error_message.clone().unwrap_or_else(|| "-".to_string()),
        ]);
    }
    table.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(valid: bool, problems: &[&str]) -> ManifestValidationReport {
        ManifestValidationReport {
            bundle_id: None,
            importable: false,
            item_count: 0,
            kind: None,
            manifest_sha256: "abc".to_string(),
            problems: problems.iter().map(|p| p.to_string()).collect(),
            repository_count: 0,
            scan_evidence_count: 0,
            schema_version: None,
            supported_by_importer: false,
            supported_schema_versions: vec![1, 1],
            total_bytes: 0,
            unsupported_features: Vec::new(),
            valid,
        }
    }

    #[test]
    fn the_report_lists_the_problems() {
        let detail = report_detail(&report(false, &["bad schema", "no items"]));
        assert!(detail.contains("Valid:           no"));
        assert!(detail.contains("Problems:\n  bad schema\n  no items"));
        assert!(!report_detail(&report(true, &[])).contains("Problems"));
    }

    #[test]
    fn the_media_profile_values_are_the_ones_the_sdk_accepts() {
        for profile in MEDIA_PROFILES {
            profile.parse::<MediaProfile>().unwrap();
        }
    }

    #[test]
    fn read_input_names_the_file_it_cant_read() {
        let err = read_input("/no/such/file").unwrap_err().to_string();
        assert!(err.contains("/no/such/file"), "{err}");
    }
}
