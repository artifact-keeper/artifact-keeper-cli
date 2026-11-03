use std::path::{Path, PathBuf};

use artifact_keeper_sdk::raw::capture;
use artifact_keeper_sdk::{
    ClientArtifactsExt, ClientPromotionExt, ClientRepositoriesExt, ClientSearchExt,
    ClientUploadsExt,
};
use clap::{Args, Subcommand};
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use futures::StreamExt;
use miette::{IntoDiagnostic, Result};

use super::chunked_upload::{self, SessionMetadata, UploadOutcome};
use super::client::{client_for, client_for_optional_auth};
use super::helpers::{
    confirm_action, emit_mutation, emit_mutation_raw, new_table, read_inline_or_file,
    refuse_flags_before_1_11, resolve_artifact_id, sdk_err, since_1_11,
};
use crate::cli::GlobalArgs;
use crate::config::AppConfig;
use crate::config::credentials::get_credential;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum ArtifactCommand {
    /// Upload an artifact to a repository
    Push {
        /// Repository key
        repo: String,

        /// File(s) to upload (supports glob patterns)
        #[arg(required = true)]
        files: Vec<String>,

        /// Target path within the repository
        #[arg(long)]
        path: Option<String>,

        /// Chunk size for large file uploads (e.g. "8MB", "16MB")
        #[arg(long, default_value = "8MB")]
        chunk_size: String,

        /// Disable chunked upload (force single PUT even for large files)
        #[arg(long, conflicts_with = "session")]
        no_chunked: bool,

        /// Override the Content-Type sent to the server (e.g.
        /// "application/x-rpm"). When omitted, the type is detected from the
        /// file extension, falling back to "application/octet-stream".
        #[arg(long = "content-type", id = "content_type")]
        content_type: Option<String>,

        /// Upload as multipart/form-data rather than a raw body. A --path ending
        /// in `/` is sent as the form's `path` field. The server works out the
        /// content type itself, so this can't go with --content-type
        #[arg(long, conflicts_with_all = ["no_chunked", "session", "content_type"])]
        multipart: bool,

        /// Human tag for this revision of a versioned repository's artifact
        #[arg(long = "version-label", conflicts_with = "session")]
        version_label: Option<String>,

        #[command(flatten)]
        session: SessionArgs,
    },

    /// Download an artifact from a repository
    #[command(disable_version_flag = true)]
    Pull {
        /// Repository key
        repo: String,

        /// Artifact path within the repository
        path: String,

        /// Output file path (defaults to artifact filename)
        #[arg(short, long)]
        output: Option<String>,

        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,

        /// Revision to download, from `ak artifact versions`
        #[arg(long)]
        version: Option<String>,
    },

    /// List artifacts in a repository
    List {
        /// Repository key
        repo: String,

        /// Search within the repository
        #[arg(long)]
        search: Option<String>,

        #[command(flatten)]
        filters: ListFilters,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "50")]
        per_page: i32,
    },

    /// Show artifact metadata and details
    #[command(disable_version_flag = true)]
    Info {
        /// Repository key
        repo: String,

        /// Artifact path
        path: String,

        /// Revision to show, from `ak artifact versions`
        #[arg(long)]
        version: Option<String>,
    },

    /// Show an artifact by its ID or <repo-key>/<path>
    Show {
        /// Artifact ID or <repo-key>/<path>
        id: String,
    },

    /// Show format-specific metadata for an artifact
    Metadata {
        /// Artifact ID or <repo-key>/<path>
        id: String,
    },

    /// Show download statistics for an artifact
    Stats {
        /// Artifact ID or <repo-key>/<path>
        id: String,
    },

    /// Show what the server found inside a package: vendored components and install scripts
    PackageAnalysis {
        /// Artifact ID or <repo-key>/<path>
        id: String,
    },

    /// List the revisions of an artifact in a versioned repository
    Versions {
        /// Repository key
        repo: String,

        /// Artifact path
        path: String,
    },

    /// Report which artifacts a repository doesn't already hold
    Missing {
        /// Repository key
        repo: String,

        /// An artifact to check, as `path=sha256` (repeatable)
        #[arg(long = "item")]
        items: Vec<String>,

        /// Artifacts to check: a JSON array of `{path, sha256}`, or `sha256sum`
        /// output, from a file or `-` for stdin
        #[arg(long)]
        from: Option<String>,
    },

    /// Inspect or cancel a chunked upload session
    UploadSession {
        #[command(subcommand)]
        command: UploadSessionCommand,
    },

    /// Delete an artifact
    Delete {
        /// Repository key
        repo: String,

        /// Artifact path
        path: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Search artifacts across all repositories
    #[command(disable_version_flag = true)]
    Search {
        /// Search query
        query: Option<String>,

        /// Filter by repository
        #[arg(long)]
        repo: Option<String>,

        /// Filter by package format
        #[arg(long = "pkg-format", id = "pkg_format")]
        pkg_format: Option<String>,

        #[command(flatten)]
        filters: SearchFilters,
    },

    /// Copy an artifact between repositories (same or cross-instance)
    Copy {
        /// Source: repo/path
        source: String,

        /// Destination: repo or repo/path
        destination: String,

        /// Source instance (defaults to current instance)
        #[arg(long)]
        from_instance: Option<String>,

        /// Destination instance (defaults to current instance)
        #[arg(long)]
        to_instance: Option<String>,

        /// Notes to record on the promotion
        #[arg(long)]
        notes: Option<String>,

        /// Skip the promotion policy check (admin)
        #[arg(long = "skip-policy-check")]
        skip_policy_check: bool,
    },
}

/// Fields of a chunked upload session. Giving any of them makes the push chunked,
/// whatever the file's size, because a plain PUT has nowhere to put them.
#[derive(Args, Debug, Default)]
#[group(id = "session", multiple = true)]
pub struct SessionArgs {
    /// Don't upload if the artifact already holds this content
    #[arg(long = "skip-if-present")]
    skip_if_present: bool,

    /// Artifact name to record
    #[arg(long = "artifact-name")]
    artifact_name: Option<String>,

    /// Artifact version to record
    #[arg(long = "artifact-version")]
    artifact_version: Option<String>,

    /// Package description to record
    #[arg(long = "package-description")]
    package_description: Option<String>,

    /// Package catalog metadata: JSON text, @file or @-
    #[arg(long = "package-metadata")]
    package_metadata: Option<String>,

    /// Artifact metadata: JSON text, @file or @-
    #[arg(long = "artifact-metadata")]
    artifact_metadata: Option<String>,

    /// Format of the artifact metadata
    #[arg(long = "artifact-metadata-format")]
    artifact_metadata_format: Option<String>,

    /// Artifact metadata properties: JSON text, @file or @-
    #[arg(long = "artifact-metadata-properties")]
    artifact_metadata_properties: Option<String>,
}

impl SessionArgs {
    fn into_metadata(self) -> Result<SessionMetadata> {
        Ok(SessionMetadata {
            skip_if_present: self.skip_if_present,
            artifact_name: self.artifact_name,
            artifact_version: self.artifact_version,
            package_description: self.package_description,
            package_metadata: json_flag(self.package_metadata, "--package-metadata")?,
            artifact_metadata: json_flag(self.artifact_metadata, "--artifact-metadata")?,
            artifact_metadata_format: self.artifact_metadata_format,
            artifact_metadata_properties: json_flag(
                self.artifact_metadata_properties,
                "--artifact-metadata-properties",
            )?,
        })
    }
}

fn json_flag(value: Option<String>, flag: &str) -> Result<Option<serde_json::Value>> {
    value
        .map(|v| {
            let bytes = read_inline_or_file(&v, flag)?;
            serde_json::from_slice(&bytes)
                .map_err(|e| AkError::Usage(format!("{flag}: invalid JSON: {e}")).into())
        })
        .transpose()
}

/// Filters for `ak artifact list`.
#[derive(Args, Debug, Default)]
pub struct ListFilters {
    /// Only artifacts under this path
    #[arg(long = "path-prefix")]
    path_prefix: Option<String>,

    /// Group on the server: maven_component or docker_tag
    #[arg(long = "group-by")]
    group_by: Option<String>,

    /// Continue from a listing's `next_cursor`. `--page` is ignored with this
    #[arg(long)]
    cursor: Option<String>,

    /// Total-count mode for keyset-paged listings: `exact` for an exact total
    #[arg(long)]
    count: Option<String>,
}

/// Filters for `ak artifact search`.
#[derive(Args, Debug, Default)]
pub struct SearchFilters {
    /// Artifact name
    #[arg(long)]
    name: Option<String>,

    /// Artifact path
    #[arg(long)]
    path: Option<String>,

    /// Artifact version
    #[arg(long)]
    version: Option<String>,

    /// Smallest size, in bytes
    #[arg(long = "min-size")]
    min_size: Option<i64>,

    /// Largest size, in bytes
    #[arg(long = "max-size")]
    max_size: Option<i64>,

    /// Created after this time (RFC 3339)
    #[arg(long = "created-after")]
    created_after: Option<String>,

    /// Created before this time (RFC 3339)
    #[arg(long = "created-before")]
    created_before: Option<String>,

    /// Field to sort by
    #[arg(long = "sort-by")]
    sort_by: Option<String>,

    /// Sort order: asc or desc
    #[arg(long = "sort-order")]
    sort_order: Option<String>,

    /// Page number
    #[arg(long)]
    page: Option<i32>,

    /// Results per page
    #[arg(long = "per-page")]
    per_page: Option<i32>,
}

/// Chunked upload sessions.
#[derive(Subcommand)]
pub enum UploadSessionCommand {
    /// List the sessions this machine left unfinished, to resume or cancel
    List,

    /// Show a session's progress
    Status {
        /// Session ID
        session_id: uuid::Uuid,
    },

    /// Cancel a session and discard what it uploaded
    Cancel {
        /// Session ID
        session_id: uuid::Uuid,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

impl ArtifactCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Push {
                repo,
                files,
                path,
                chunk_size,
                no_chunked,
                content_type,
                multipart,
                version_label,
                session,
            } => {
                let force_chunked = session.skip_if_present
                    || session.artifact_name.is_some()
                    || session.artifact_version.is_some()
                    || session.package_description.is_some()
                    || session.package_metadata.is_some()
                    || session.artifact_metadata.is_some()
                    || session.artifact_metadata_format.is_some()
                    || session.artifact_metadata_properties.is_some();
                if session.skip_if_present {
                    refuse_flags_before_1_11(&["--skip-if-present"], global).await?;
                }
                let mode = if multipart {
                    UploadMode::Multipart
                } else if force_chunked {
                    UploadMode::Chunked
                } else if no_chunked || version_label.is_some() {
                    UploadMode::Put
                } else {
                    UploadMode::BySize
                };
                push(
                    &repo,
                    &files,
                    &PushOptions {
                        target_path: path,
                        chunk_size,
                        mode,
                        content_type,
                        version_label,
                        session: session.into_metadata()?,
                    },
                    global,
                )
                .await
            }
            Self::Pull {
                repo,
                path,
                output,
                force,
                version,
            } => {
                pull(
                    &repo,
                    &path,
                    output.as_deref(),
                    force,
                    version.as_deref(),
                    global,
                )
                .await
            }
            Self::List {
                repo,
                search,
                filters,
                page,
                per_page,
            } => list(&repo, search.as_deref(), &filters, page, per_page, global).await,
            Self::Info {
                repo,
                path,
                version,
            } => info(&repo, &path, version.as_deref(), global).await,
            Self::Show { id } => show_by_id(&id, global).await,
            Self::Metadata { id } => show_metadata(&id, global).await,
            Self::Stats { id } => show_stats(&id, global).await,
            Self::PackageAnalysis { id } => package_analysis(&id, global).await,
            Self::Versions { repo, path } => versions(&repo, &path, global).await,
            Self::Missing { repo, items, from } => {
                missing(&repo, &items, from.as_deref(), global).await
            }
            Self::UploadSession { command } => match command {
                UploadSessionCommand::List => upload_sessions(global),
                UploadSessionCommand::Status { session_id } => {
                    upload_session_status(session_id, global).await
                }
                UploadSessionCommand::Cancel { session_id, yes } => {
                    upload_session_cancel(session_id, yes, global).await
                }
            },
            Self::Delete { repo, path, yes } => delete(&repo, &path, yes, global).await,
            Self::Search {
                query,
                repo,
                pkg_format,
                filters,
            } => {
                search(
                    query.as_deref(),
                    repo.as_deref(),
                    pkg_format.as_deref(),
                    &filters,
                    global,
                )
                .await
            }
            Self::Copy {
                source,
                destination,
                from_instance,
                to_instance,
                notes,
                skip_policy_check,
            } => {
                let promotion = artifact_keeper_sdk::types::PromoteArtifactRequest {
                    target_repository: None,
                    notes,
                    skip_policy_check: skip_policy_check.then_some(true),
                };
                copy(
                    &source,
                    &destination,
                    from_instance.as_deref(),
                    to_instance.as_deref(),
                    promotion,
                    global,
                )
                .await
            }
        }
    }
}

/// Detect the `Content-Type` to declare for an upload, which the server stores
/// with the artifact and returns on download.
///
/// This only sets the stored `content_type`. It does not decide the artifact's
/// format or whether it gets indexed; the server does that from the repository
/// format and the file itself.
///
/// Resolution order:
/// 1. A curated override table, for extensions the bundled `mime_guess` database
///    gets wrong for packages:
///    - `.rpm` maps to `audio/x-pn-realaudio-plugin` (a legacy collision).
///    - `.deb` maps to `application/octet-stream`.
///    - `.tgz` maps to the vague `application/x-compressed`, while `.tar.gz`
///      gets `application/gzip`.
///    - `.mod` (Go modules) maps to `video/mpeg` and `.ts` (usually TypeScript)
///      to an MPEG transport stream type. There's no type to say what those
///      really are, so they stay opaque.
/// 2. `mime_guess` for the long tail of common extensions.
/// 3. `application/octet-stream` for unknown or extensionless files. This
///    includes `.whl`, `.crate`, `.nupkg` and `.gem`, which aren't in the
///    database.
fn content_type_for_path(path: &str) -> String {
    const OCTET_STREAM: &str = "application/octet-stream";

    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);

    // 1. Curated overrides (DB is wrong or too vague for these).
    if let Some(ext) = ext.as_deref() {
        let override_type = match ext {
            "rpm" => Some("application/x-rpm"),
            "deb" | "udeb" => Some("application/vnd.debian.binary-package"),
            "tgz" => Some("application/gzip"),
            "mod" | "ts" => Some(OCTET_STREAM),
            _ => None,
        };
        if let Some(t) = override_type {
            return t.to_string();
        }
    }

    // 2. mime_guess for everything else, 3. octet-stream fallback.
    mime_guess::from_path(path)
        .first_raw()
        .unwrap_or(OCTET_STREAM)
        .to_string()
}

/// How `ak artifact push` sends a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UploadMode {
    /// Chunked from the threshold up, a single PUT below it.
    BySize,
    Put,
    Chunked,
    Multipart,
}

struct PushOptions {
    target_path: Option<String>,
    chunk_size: String,
    mode: UploadMode,
    content_type: Option<String>,
    version_label: Option<String>,
    session: SessionMetadata,
}

async fn push(
    repo: &str,
    file_patterns: &[String],
    options: &PushOptions,
    global: &GlobalArgs,
) -> Result<()> {
    let (base_url, auth_header) = super::client::resolve_base_url_and_auth(global)?;
    let chunk_size = chunked_upload::parse_size(&options.chunk_size)?;
    let threshold = chunked_upload::chunked_threshold()?;

    let mut files_to_upload: Vec<PathBuf> = Vec::new();
    for pattern in file_patterns {
        let matches: Vec<_> = glob::glob(pattern)
            .into_diagnostic()?
            .filter_map(|r| r.ok())
            .filter(|p| p.is_file())
            .collect();

        if matches.is_empty() {
            let path = PathBuf::from(pattern);
            if path.is_file() {
                files_to_upload.push(path);
            } else {
                return Err(AkError::Usage(format!("No files match pattern: {pattern}")).into());
            }
        } else {
            files_to_upload.extend(matches);
        }
    }

    for file_path in &files_to_upload {
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let artifact_path = options
            .target_path
            .as_deref()
            .map(|p| {
                if p.ends_with('/') {
                    format!("{p}{file_name}")
                } else if files_to_upload.len() > 1 {
                    format!("{p}/{file_name}")
                } else {
                    p.to_string()
                }
            })
            .unwrap_or_else(|| file_name.to_string());

        let file_size = tokio::fs::metadata(file_path)
            .await
            .into_diagnostic()?
            .len();

        let content_type = match options.content_type.as_deref() {
            Some(ct) => ct.to_string(),
            None => content_type_for_path(&artifact_path),
        };

        let use_chunked = match options.mode {
            UploadMode::Chunked => true,
            UploadMode::BySize => file_size >= threshold,
            UploadMode::Put | UploadMode::Multipart => false,
        };

        let uploaded = if use_chunked {
            chunked_upload::chunked_upload(
                &base_url,
                &auth_header,
                file_path,
                repo,
                &artifact_path,
                chunk_size,
                file_size,
                file_name,
                &content_type,
                &options.session,
            )
            .await?
        } else {
            let pb = indicatif::ProgressBar::new(file_size);
            pb.set_style(
                indicatif::ProgressStyle::with_template(
                    "{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})",
                )
                .unwrap()
                .progress_chars("##-"),
            );
            pb.set_message(format!("Uploading {file_name}"));

            let file = tokio::fs::File::open(file_path).await.into_diagnostic()?;
            let stream = tokio_util::io::ReaderStream::new(file);
            let pb_clone = pb.clone();
            let stream = stream.map(move |chunk| {
                if let Ok(ref bytes) = chunk {
                    pb_clone.inc(bytes.len() as u64);
                }
                chunk
            });
            let body = reqwest::Body::wrap_stream(stream);

            let uploaded = if options.mode == UploadMode::Multipart {
                // A directory goes as is, and the server adds the file's name. Any
                // other path is this file's own, or several would land on one path.
                let target = options
                    .target_path
                    .as_deref()
                    .map(|p| if p.ends_with('/') { p } else { &artifact_path });
                multipart_upload(
                    &base_url,
                    &auth_header,
                    repo,
                    target,
                    file_name,
                    file_size,
                    body,
                    &content_type,
                    options.version_label.as_deref(),
                )
                .await?
            } else {
                single_put_upload(
                    &base_url,
                    &auth_header,
                    repo,
                    &artifact_path,
                    body,
                    &content_type,
                    options.version_label.as_deref(),
                )
                .await?
            };

            pb.finish_with_message(format!("Uploaded {file_name}"));
            uploaded
        };

        let note = match (use_chunked, uploaded.already_present) {
            (_, true) => " [already present]",
            (true, false) => " [chunked]",
            (false, false) => "",
        };
        emit_mutation_raw(
            Some(&uploaded.raw),
            &serde_json::json!({ "path": uploaded.path, "size": uploaded.size }),
            &output::sanitize_terminal(&uploaded.path),
            &format!(
                "  {} ({}) -> {}:{}{note}",
                file_name,
                format_bytes(uploaded.size),
                repo,
                output::sanitize_terminal(&uploaded.path),
            ),
            global,
        );
    }

    if matches!(global.format, OutputFormat::Table) && files_to_upload.len() > 1 {
        eprintln!("Uploaded {} files.", files_to_upload.len());
    }

    Ok(())
}

/// The URL of an artifact route: `/api/v1/repositories/<repo>/<route>/<path>`,
/// with each segment encoded.
fn artifact_url(
    base_url: &str,
    repo: &str,
    route: &str,
    artifact_path: Option<&str>,
) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(base_url)
        .map_err(|e| AkError::ConfigError(format!("Invalid instance URL {base_url}: {e}")))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| AkError::ConfigError(format!("Invalid instance URL: {base_url}")))?;
        segments
            .pop_if_empty()
            .extend(["api", "v1", "repositories", repo, route]);
        if let Some(path) = artifact_path {
            segments.extend(path.split('/'));
        }
    }
    Ok(url)
}

/// What an upload response says, kept with the body as the server sent it.
async fn read_upload_response(resp: reqwest::Response) -> Result<UploadOutcome> {
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(super::helpers::raw_err("Upload failed", status, &text).into());
    }
    let raw = resp
        .bytes()
        .await
        .map_err(|e| AkError::NetworkError(format!("Upload failed: {e}")))?
        .to_vec();
    let parsed: SinglePutUploadResponse = serde_json::from_slice(&raw)
        .map_err(|e| AkError::ServerError(format!("Invalid upload response: {e}")))?;
    Ok(UploadOutcome {
        path: parsed.path,
        size: parsed.size_bytes,
        already_present: false,
        raw,
    })
}

/// Response from the upload endpoints (the subset of the API's `ArtifactResponse`
/// that `push` uses).
#[derive(Debug, serde::Deserialize)]
struct SinglePutUploadResponse {
    path: String,
    size_bytes: i64,
}

/// Upload a small file via a single `PUT` using a raw HTTP request.
///
/// The generated builder takes the whole body in memory, so this raw path is
/// what lets a push stream from disk. It surfaces HTTP errors with status and
/// body, as `chunked_upload` does.
async fn single_put_upload(
    base_url: &str,
    auth_header: &str,
    repo: &str,
    artifact_path: &str,
    body: reqwest::Body,
    content_type: &str,
    version_label: Option<&str>,
) -> Result<UploadOutcome> {
    let url = artifact_url(base_url, repo, "artifacts", Some(artifact_path))?;

    let mut request = super::client::raw_http_client()?
        .put(url)
        .header(reqwest::header::AUTHORIZATION, auth_header)
        .header(reqwest::header::CONTENT_TYPE, content_type);
    if let Some(label) = version_label {
        request = request.header("X-Artifact-Version", label);
    }
    let resp = request
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("Upload failed: {e}")))?;

    read_upload_response(resp).await
}

/// Upload a file as multipart/form-data, which isn't in the OpenAPI spec:
///
/// - no `--path`: `POST .../artifacts`, and the server names it after the file
/// - `--path` ending in `/`: the same route, with `--path` as the `path` field
/// - any other `--path`: `POST .../artifacts/<path>`
#[allow(clippy::too_many_arguments)]
async fn multipart_upload(
    base_url: &str,
    auth_header: &str,
    repo: &str,
    target_path: Option<&str>,
    file_name: &str,
    file_size: u64,
    body: reqwest::Body,
    content_type: &str,
    version_label: Option<&str>,
) -> Result<UploadOutcome> {
    let (url_path, form_path) = match target_path {
        Some(p) if p.ends_with('/') => (None, Some(p)),
        Some(p) => (Some(p), None),
        None => (None, None),
    };
    let url = artifact_url(base_url, repo, "artifacts", url_path)?;

    let part = reqwest::multipart::Part::stream_with_length(body, file_size)
        .file_name(file_name.to_string())
        .mime_str(content_type)
        .map_err(|e| AkError::Usage(format!("Invalid content type: {e}")))?;
    let mut form = reqwest::multipart::Form::new();
    if let Some(path) = form_path {
        form = form.text("path", path.to_string());
    }
    form = form.part("file", part);

    let mut request = super::client::raw_http_client()?
        .post(url)
        .header(reqwest::header::AUTHORIZATION, auth_header);
    if let Some(label) = version_label {
        request = request.header("X-Artifact-Version", label);
    }
    let resp = request
        .multipart(form)
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("Upload failed: {e}")))?;

    read_upload_response(resp).await
}

/// Start a download. This is raw HTTP because the SDK's client has a 30-second
/// limit on the whole request, body included, which a large artifact outlasts.
async fn fetch_artifact(
    base_url: &str,
    auth_header: &str,
    repo: &str,
    artifact_path: &str,
    version: Option<&str>,
) -> Result<reqwest::Response> {
    let url = artifact_url(base_url, repo, "download", Some(artifact_path))?;
    let mut request = super::client::raw_download_client()?
        .get(url)
        .header(reqwest::header::AUTHORIZATION, auth_header);
    if let Some(version) = version {
        request = request.query(&[("version", version)]);
    }
    let resp = request
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("Download failed: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(super::helpers::raw_err("Download failed", status, &text).into());
    }
    Ok(resp)
}

/// Open the pull output file for writing.
///
/// Always creates the file with `create_new` (`O_CREAT | O_EXCL`), which
/// refuses to follow an existing symlink and never truncates existing data.
/// Without `--force`, an existing file (or symlink) at the path is an error;
/// with `--force`, the existing entry is removed first and the output is
/// recreated as a regular file, so the download never writes through a
/// symlink to some other location.
async fn open_pull_output(out_path: &Path, force: bool) -> Result<tokio::fs::File> {
    if force {
        match tokio::fs::remove_file(out_path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(AkError::Local(format!(
                    "Cannot overwrite '{}': {e}",
                    out_path.display()
                ))
                .into());
            }
        }
    }

    tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out_path)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                AkError::Usage(format!(
                    "Output file '{}' already exists. Pass --force to overwrite it, \
                     or use --output to choose a different path.",
                    out_path.display()
                ))
                .into()
            } else {
                AkError::Local(format!(
                    "Cannot create output file '{}': {e}",
                    out_path.display()
                ))
                .into()
            }
        })
}

async fn pull(
    repo: &str,
    artifact_path: &str,
    output: Option<&str>,
    force: bool,
    version: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let (base_url, auth_header) = super::client::resolve_base_url_and_auth(global)?;

    let out_path = output.map(PathBuf::from).unwrap_or_else(|| {
        let filename = Path::new(artifact_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("download");
        PathBuf::from(filename)
    });

    // Fail fast (before the download) when the destination already exists.
    let mut file = open_pull_output(&out_path, force).await?;

    let spinner = output::spinner(&format!("Downloading {artifact_path}..."));

    let resp = match fetch_artifact(&base_url, &auth_header, repo, artifact_path, version).await {
        Ok(resp) => resp,
        Err(e) => {
            spinner.finish_and_clear();
            // Don't leave an empty placeholder file behind on failure.
            drop(file);
            let _ = tokio::fs::remove_file(&out_path).await;
            return Err(e);
        }
    };

    spinner.finish_and_clear();
    let mut stream = resp.bytes_stream();
    let mut total_bytes: u64 = 0;
    let copy_result: Result<()> = async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                crate::commands::helpers::classified(format!("Download error: {e}"), &e)
            })?;
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
                .await
                .into_diagnostic()?;
            total_bytes += chunk.len() as u64;
        }
        Ok(())
    }
    .await;

    if let Err(e) = copy_result {
        // Remove the partial download so a retry doesn't require --force.
        drop(file);
        let _ = tokio::fs::remove_file(&out_path).await;
        return Err(e);
    }

    // tokio::fs::File does not flush pending writes on drop; flush explicitly
    // so the file is complete before success is reported.
    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .into_diagnostic()?;
    drop(file);

    eprintln!(
        "Downloaded {}:{} -> {} ({})",
        repo,
        artifact_path,
        out_path.display(),
        format_bytes(total_bytes as i64),
    );

    Ok(())
}

async fn list(
    repo: &str,
    search: Option<&str>,
    filters: &ListFilters,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let spinner = output::spinner("Fetching artifacts...");

    let mut req = client
        .list_artifacts()
        .key(repo)
        .page(page)
        .per_page(per_page);
    if let Some(q) = search {
        req = req.q(q);
    }
    if let Some(prefix) = &filters.path_prefix {
        req = req.path_prefix(prefix);
    }
    if let Some(group_by) = &filters.group_by {
        req = req.group_by(group_by);
    }
    if let Some(cursor) = &filters.cursor {
        req = req.cursor(cursor);
    }
    if let Some(count) = &filters.count {
        req = req.count(count);
    }

    let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
    let resp = resp.map_err(|e| crate::commands::helpers::sdk_err("list artifacts", e))?;

    spinner.finish_and_clear();

    if let Some(table_str) = grouped_table(&resp) {
        println!(
            "{}",
            output::render_raw(raw.as_deref(), &*resp, &global.format, Some(table_str))
        );
        print_next_cursor(resp.next_cursor.as_deref());
        return Ok(());
    }

    if resp.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No artifacts found in '{repo}'.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for a in &resp.items {
            println!("{}", output::sanitize_terminal(&a.path));
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|a| {
            serde_json::json!({
                "id": a.id,
                "path": a.path,
                "name": a.name,
                "version": a.version,
                "size": format_bytes(a.size_bytes),
                "size_bytes": a.size_bytes,
                "downloads": a.download_count,
                "created_at": a.created_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_style(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["PATH", "VERSION", "SIZE", "DOWNLOADS", "CREATED"]);

        for a in &resp.items {
            let path = output::sanitize_terminal(&a.path);
            let version = output::sanitize_terminal(a.version.as_deref().unwrap_or("-"));
            let size = format_bytes(a.size_bytes);
            let created = a.created_at.format("%Y-%m-%d").to_string();
            table.add_row(vec![
                path,
                version,
                size,
                a.download_count.to_string(),
                created,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    if resp.pagination.total_pages > 1 {
        eprintln!(
            "Page {} of {} ({} total artifacts)",
            resp.pagination.page, resp.pagination.total_pages, resp.pagination.total
        );
    }
    print_next_cursor(resp.next_cursor.as_deref());

    Ok(())
}

fn print_next_cursor(cursor: Option<&str>) {
    if let Some(cursor) = cursor {
        eprintln!(
            "More results: --cursor {}",
            output::sanitize_terminal(cursor)
        );
    }
}

/// The table for `--group-by`, whose rows aren't in `items`.
fn grouped_table(resp: &artifact_keeper_sdk::types::ArtifactListResponse) -> Option<String> {
    if let Some(tags) = &resp.docker_tags {
        let mut table = new_table(vec!["IMAGE", "TAG", "SIZE", "LAYERS", "PUSHED"]);
        for t in tags {
            table.add_row(vec![
                t.image.clone(),
                t.tag.clone(),
                format_bytes(t.total_size_bytes),
                t.layer_count.to_string(),
                t.last_pushed_at.format("%Y-%m-%d").to_string(),
            ]);
        }
        return Some(table.to_string());
    }
    if let Some(components) = &resp.components {
        let mut table = new_table(vec!["GROUP", "ARTIFACT", "VERSION", "SIZE", "DOWNLOADS"]);
        for c in components {
            table.add_row(vec![
                c.group_id.clone(),
                c.artifact_id.clone(),
                c.version.clone(),
                format_bytes(c.size_bytes),
                c.download_count.to_string(),
            ]);
        }
        return Some(table.to_string());
    }
    None
}

async fn info(
    repo: &str,
    artifact_path: &str,
    version: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let mut req = client
        .get_repository_artifact_metadata()
        .key(repo)
        .path(artifact_path);
    if let Some(version) = version {
        req = req.version(version);
    }
    let (artifact, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
    let artifact = artifact.map_err(|e| {
        if e.status() == Some(reqwest::StatusCode::NOT_FOUND) {
            AkError::NotFound(format!("Artifact '{artifact_path}' not found in '{repo}'"))
        } else {
            crate::commands::helpers::sdk_err("find artifact", e)
        }
    })?;

    let info = serde_json::json!({
        "id": artifact.id,
        "path": artifact.path,
        "name": artifact.name,
        "version": artifact.version,
        "size": format_bytes(artifact.size_bytes),
        "size_bytes": artifact.size_bytes,
        "content_type": artifact.content_type,
        "sha256": artifact.checksum_sha256,
        "downloads": artifact.download_count,
        "repository": artifact.repository_key,
        "created_at": artifact.created_at.to_rfc3339(),
    });

    let table_str = format!(
        "Path:         {}\n\
         Name:         {}\n\
         Version:      {}\n\
         Size:         {}\n\
         Content Type: {}\n\
         SHA-256:      {}\n\
         Downloads:    {}\n\
         Repository:   {}\n\
         Created:      {}",
        artifact.path,
        artifact.name,
        artifact.version.as_deref().unwrap_or("-"),
        format_bytes(artifact.size_bytes),
        artifact.content_type,
        artifact.checksum_sha256,
        artifact.download_count,
        artifact.repository_key,
        artifact.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_by_id(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let artifact_id = resolve_artifact_id(&client, id).await?;

    let (artifact, raw) =
        artifact_keeper_sdk::raw::capture(client.get_artifact().id(artifact_id).send()).await;
    let artifact = artifact
        .map_err(|e| crate::commands::helpers::sdk_err("get artifact", e))?
        .into_inner();

    let info = serde_json::json!({
        "id": artifact.id.to_string(),
        "path": artifact.path,
        "name": artifact.name,
        "version": artifact.version,
        "size": format_bytes(artifact.size_bytes),
        "size_bytes": artifact.size_bytes,
        "content_type": artifact.content_type,
        "sha256": artifact.checksum_sha256,
        "downloads": artifact.download_count,
        "repository": artifact.repository_key,
        "created_at": artifact.created_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:           {}\n\
         Path:         {}\n\
         Name:         {}\n\
         Version:      {}\n\
         Size:         {}\n\
         Content Type: {}\n\
         SHA-256:      {}\n\
         Downloads:    {}\n\
         Repository:   {}\n\
         Created:      {}",
        artifact.id,
        artifact.path,
        artifact.name,
        artifact.version.as_deref().unwrap_or("-"),
        format_bytes(artifact.size_bytes),
        artifact.content_type,
        artifact.checksum_sha256,
        artifact.download_count,
        artifact.repository_key,
        artifact.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_metadata(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let artifact_id = resolve_artifact_id(&client, id).await?;

    let (meta, raw) =
        artifact_keeper_sdk::raw::capture(client.get_artifact_metadata().id(artifact_id).send())
            .await;
    let meta = meta
        .map_err(|e| crate::commands::helpers::sdk_err("get artifact metadata", e))?
        .into_inner();

    let info = serde_json::json!({
        "artifact_id": meta.artifact_id.to_string(),
        "format": meta.format,
        "metadata": meta.metadata,
        "properties": meta.properties,
    });

    let table_str = format!(
        "Artifact:   {}\n\
         Format:     {}\n\
         Metadata:   {}\n\
         Properties: {}",
        meta.artifact_id,
        meta.format,
        serde_json::to_string(&meta.metadata).unwrap_or_else(|_| "-".to_string()),
        serde_json::to_string(&meta.properties).unwrap_or_else(|_| "-".to_string()),
    );

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_stats(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let artifact_id = resolve_artifact_id(&client, id).await?;

    let (stats, raw) =
        artifact_keeper_sdk::raw::capture(client.get_artifact_stats().id(artifact_id).send()).await;
    let stats = stats
        .map_err(|e| crate::commands::helpers::sdk_err("get artifact stats", e))?
        .into_inner();

    let info = serde_json::json!({
        "artifact_id": stats.artifact_id.to_string(),
        "download_count": stats.download_count,
        "first_downloaded": stats.first_downloaded.map(|t| t.to_rfc3339()),
        "last_downloaded": stats.last_downloaded.map(|t| t.to_rfc3339()),
    });

    let fmt_dt = |dt: Option<chrono::DateTime<chrono::Utc>>| {
        dt.map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string())
    };

    let table_str = format!(
        "Artifact:        {}\n\
         Downloads:       {}\n\
         First Download:  {}\n\
         Last Download:   {}",
        stats.artifact_id,
        stats.download_count,
        fmt_dt(stats.first_downloaded),
        fmt_dt(stats.last_downloaded),
    );

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn package_analysis(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let artifact_id = resolve_artifact_id(&client, id).await?;

    let (resp, raw) = capture(client.get_package_analysis().id(artifact_id).send()).await;
    let resp = match resp {
        Ok(resp) => resp,
        Err(e) => {
            let action = "get package analysis";
            return Err(since_1_11(e, action, "artifact package-analysis", global)
                .await
                .into());
        }
    };

    let mut text = format!(
        "Format:       {}\nCompleteness: {}\nAnalyzed:     {}\nComponents:   {}\nScripts:      {}",
        resp.format,
        resp.completeness.status,
        resp.analyzed_at.as_deref().unwrap_or("-"),
        resp.vendored_components.len(),
        resp.install_scripts.len(),
    );
    if let Some(reason) = &resp.completeness.reason {
        text.push_str(&format!("\nIncomplete:   {reason}"));
    }
    if !resp.vendored_components.is_empty() {
        let mut table = new_table(vec!["COMPONENT", "VERSION", "CONFIDENCE"]);
        for c in &resp.vendored_components {
            table.add_row(vec![
                c.name.clone(),
                c.version.clone().unwrap_or_else(|| "-".into()),
                c.confidence.clone(),
            ]);
        }
        text.push_str(&format!("\n{table}"));
    }
    if !resp.install_scripts.is_empty() {
        let mut table = new_table(vec!["SCRIPT", "KIND", "SIZE"]);
        for script in &resp.install_scripts {
            table.add_row(vec![
                script.path.clone(),
                script.kind.clone(),
                format_bytes(script.size_bytes),
            ]);
        }
        text.push_str(&format!("\n{table}"));
    }

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &*resp, &global.format, Some(text))
    );
    Ok(())
}

async fn versions(repo: &str, artifact_path: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let (resp, raw) = capture(
        client
            .list_artifact_versions()
            .key(repo)
            .path(artifact_path)
            .send(),
    )
    .await;
    let resp = resp.map_err(|e| sdk_err("list artifact versions", e))?;

    if resp.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No revisions of '{artifact_path}' in '{repo}'.");
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for v in &resp.items {
            println!("{}", v.revision);
        }
        return Ok(());
    }

    let mut table = new_table(vec!["REVISION", "LABEL", "SIZE", "SHA-256", "CREATED"]);
    for v in &resp.items {
        table.add_row(vec![
            v.revision.to_string(),
            v.version_label.clone().unwrap_or_else(|| "-".into()),
            format_bytes(v.size_bytes),
            v.checksum_sha256.clone(),
            v.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        ]);
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &*resp,
            &global.format,
            Some(table.to_string())
        )
    );
    Ok(())
}

/// `path=sha256`
fn parse_presence_item(entry: &str) -> Result<artifact_keeper_sdk::types::ArtifactPresenceItem> {
    let (path, sha256) = entry
        .rsplit_once('=')
        .ok_or_else(|| AkError::Usage(format!("--item must be 'path=sha256', got '{entry}'")))?;
    Ok(artifact_keeper_sdk::types::ArtifactPresenceItem {
        path: path.to_string(),
        sha256: sha256.to_string(),
    })
}

/// The items in a `--from` file: a JSON array of `{path, sha256}`, or `sha256sum`
/// lines of `<sha256>  <path>`.
fn parse_presence_list(
    text: &str,
) -> Result<Vec<artifact_keeper_sdk::types::ArtifactPresenceItem>> {
    if text.trim_start().starts_with('[') {
        return serde_json::from_str(text)
            .map_err(|e| AkError::Usage(format!("--from: invalid JSON: {e}")).into());
    }
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (sha256, path) = line.split_once(char::is_whitespace).ok_or_else(|| {
                AkError::Usage(format!("--from: expected '<sha256>  <path>', got '{line}'"))
            })?;
            // sha256sum marks a binary-mode file with `*` before its name.
            let path = path.trim_start();
            let path = path.strip_prefix('*').unwrap_or(path);
            Ok(artifact_keeper_sdk::types::ArtifactPresenceItem {
                path: path.to_string(),
                sha256: sha256.to_string(),
            })
        })
        .collect()
}

async fn missing(
    repo: &str,
    items: &[String],
    from: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let mut all = items
        .iter()
        .map(|item| parse_presence_item(item))
        .collect::<Result<Vec<_>>>()?;
    if let Some(from) = from {
        let source = if from == "-" {
            "@-".to_string()
        } else {
            format!("@{from}")
        };
        let bytes = read_inline_or_file(&source, "--from")?;
        let text = String::from_utf8(bytes)
            .map_err(|_| AkError::Usage("--from: the input isn't text".into()))?;
        all.extend(parse_presence_list(&text)?);
    }
    if all.is_empty() {
        return Err(AkError::Usage("Give at least one --item, or --from".into()).into());
    }

    let client = client_for(global)?;
    let (resp, raw) = capture(
        client
            .missing_artifacts()
            .key(repo)
            .body(artifact_keeper_sdk::types::MissingArtifactsRequest { items: all })
            .send(),
    )
    .await;
    let resp = match resp {
        Ok(resp) => resp,
        Err(e) => {
            let action = "check for missing artifacts";
            return Err(since_1_11(e, action, "artifact missing", global)
                .await
                .into());
        }
    };

    if matches!(global.format, OutputFormat::Quiet) {
        for m in &resp.missing {
            println!("{}", output::sanitize_terminal(&m.path));
        }
        return Ok(());
    }

    let mut text = format!("{} checked, {} missing.", resp.checked, resp.missing.len());
    if !resp.missing.is_empty() {
        let mut table = new_table(vec!["PATH", "REASON", "SHA-256"]);
        for m in &resp.missing {
            table.add_row(vec![m.path.clone(), m.reason.to_string(), m.sha256.clone()]);
        }
        text.push_str(&format!("\n{table}"));
    }
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &*resp, &global.format, Some(text))
    );
    Ok(())
}

/// Sessions left in the local cache. Nothing on the server lists them, and this
/// is the only place their IDs are kept.
fn upload_sessions(global: &GlobalArgs) -> Result<()> {
    let sessions = chunked_upload::cached_sessions()?;
    if matches!(global.format, OutputFormat::Quiet) {
        for session in &sessions {
            println!("{}", session.session_id);
        }
        return Ok(());
    }
    if sessions.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No unfinished upload sessions on this machine.");
        return Ok(());
    }
    let mut table = new_table(vec![
        "SESSION",
        "REPOSITORY",
        "PATH",
        "FILE",
        "SIZE",
        "STARTED",
    ]);
    for session in &sessions {
        table.add_row(vec![
            session.session_id.clone(),
            session.repository_key.clone(),
            session.artifact_path.clone(),
            session.file_path.clone(),
            format_bytes(session.total_size as i64),
            session.created_at.format("%Y-%m-%d %H:%M").to_string(),
        ]);
    }
    println!(
        "{}",
        output::render(&sessions, &global.format, Some(table.to_string()))
    );
    Ok(())
}

async fn upload_session_status(session_id: uuid::Uuid, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let (resp, raw) = capture(client.get_session_status().session_id(session_id).send()).await;
    let resp = resp.map_err(|e| sdk_err("get upload session", e))?;
    let text = format!(
        "Session:    {}\nStatus:     {}\nRepository: {}\nPath:       {}\nReceived:   {} of {}\n\
         Chunks:     {} of {}\nCreated:    {}\nExpires:    {}",
        resp.session_id,
        resp.status,
        resp.repository_key,
        resp.artifact_path,
        format_bytes(resp.bytes_received),
        format_bytes(resp.total_size),
        resp.chunks_completed,
        resp.chunks_total,
        resp.created_at,
        resp.expires_at,
    );
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &*resp, &global.format, Some(text))
    );
    Ok(())
}

async fn upload_session_cancel(
    session_id: uuid::Uuid,
    yes: bool,
    global: &GlobalArgs,
) -> Result<()> {
    if !confirm_action(
        &format!("Cancel upload session {session_id} and discard what it uploaded?"),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }
    let client = client_for(global)?;
    client
        .cancel()
        .session_id(session_id)
        .send()
        .await
        .map_err(|e| sdk_err("cancel upload session", e))?;
    chunked_upload::forget_session(&session_id.to_string())?;

    emit_mutation(
        &serde_json::json!({ "session_id": session_id, "status": "cancelled" }),
        &session_id.to_string(),
        &format!("Cancelled upload session {session_id}."),
        global,
    );
    Ok(())
}

async fn delete(
    repo: &str,
    artifact_path: &str,
    skip_confirm: bool,
    global: &GlobalArgs,
) -> Result<()> {
    if !confirm_action(
        &format!("Delete '{artifact_path}' from '{repo}'? This cannot be undone"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;

    client
        .delete_artifact()
        .key(repo)
        .path(artifact_path)
        .send()
        .await
        .map_err(|e| crate::commands::helpers::sdk_err("delete artifact", e))?;

    emit_mutation(
        &serde_json::json!({ "repo_key": repo, "path": artifact_path, "status": "deleted" }),
        artifact_path,
        &format!("Deleted '{artifact_path}' from '{repo}'."),
        global,
    );
    Ok(())
}

async fn search(
    query: Option<&str>,
    repo: Option<&str>,
    format: Option<&str>,
    filters: &SearchFilters,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for_optional_auth(global)?;

    let spinner = output::spinner("Searching...");

    let mut req = client.advanced_search();
    if let Some(q) = query {
        req = req.query(q);
    }
    if let Some(v) = &filters.name {
        req = req.name(v);
    }
    if let Some(v) = &filters.path {
        req = req.path(v);
    }
    if let Some(v) = &filters.version {
        req = req.version(v);
    }
    if let Some(v) = filters.min_size {
        req = req.min_size(v);
    }
    if let Some(v) = filters.max_size {
        req = req.max_size(v);
    }
    if let Some(v) = &filters.created_after {
        req = req.created_after(v);
    }
    if let Some(v) = &filters.created_before {
        req = req.created_before(v);
    }
    if let Some(v) = &filters.sort_by {
        req = req.sort_by(v);
    }
    if let Some(v) = &filters.sort_order {
        req = req.sort_order(v);
    }
    if let Some(v) = filters.page {
        req = req.page(v);
    }
    if let Some(v) = filters.per_page {
        req = req.per_page(v);
    }
    if let Some(r) = repo {
        req = req.repository_key(r);
    }
    if let Some(f) = format {
        req = req.format(f);
    }

    let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
    let resp =
        resp.map_err(|e| crate::commands::helpers::classified(format!("Search failed: {e}"), &e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No results found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for item in &resp.items {
            println!("{}", output::sanitize_terminal(&item.name));
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|item| {
            serde_json::json!({
                "id": item.id,
                "name": item.name,
                "path": item.path,
                "repository": item.repository_key,
                "format": item.format,
                "version": item.version,
                "type": item.type_,
                "size": item.size_bytes.map(format_bytes),
            })
        })
        .collect();

    let table_str = {
        let mut table = Table::new();
        table
            .load_style(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["NAME", "REPOSITORY", "FORMAT", "VERSION", "SIZE"]);

        for item in &resp.items {
            let name = output::sanitize_terminal(&item.name);
            let repository = output::sanitize_terminal(&item.repository_key);
            let version = output::sanitize_terminal(item.version.as_deref().unwrap_or("-"));
            let format_str = output::sanitize_terminal(item.format.as_deref().unwrap_or("-"));
            let size = item
                .size_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "-".into());
            table.add_row(vec![name, repository, format_str, version, size]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    eprintln!("{} results found.", resp.items.len());

    Ok(())
}

/// `<repo>` or `<repo>/<path>`, with the path defaulting to the source's.
fn parse_copy_destination<'a>(
    destination: &'a str,
    src_path: &'a str,
) -> Result<(&'a str, &'a str)> {
    let (repo, path) = match destination.split_once('/') {
        Some((repo, path)) => (repo, path.trim_end_matches('/')),
        None => (destination, ""),
    };
    if repo.is_empty() {
        return Err(AkError::Usage(format!(
            "Destination must be 'repo' or 'repo/path', got '{destination}'"
        ))
        .into());
    }
    Ok((repo, if path.is_empty() { src_path } else { path }))
}

async fn copy(
    source: &str,
    destination: &str,
    from_instance: Option<&str>,
    to_instance: Option<&str>,
    promotion: artifact_keeper_sdk::types::PromoteArtifactRequest,
    global: &GlobalArgs,
) -> Result<()> {
    let (src_repo, src_path) = source
        .split_once('/')
        .filter(|(repo, path)| !repo.is_empty() && !path.is_empty())
        .ok_or_else(|| AkError::Usage("Source must be in format 'repo/path'".into()))?;
    let (dst_repo, dst_path) = parse_copy_destination(destination, src_path)?;

    let is_cross_instance = from_instance.is_some() || to_instance.is_some();

    // The server's promotion keeps the path. Anything else goes through a download
    // and an upload.
    if is_cross_instance || dst_path != src_path {
        if promotion.notes.is_some() || promotion.skip_policy_check.is_some() {
            return Err(AkError::Usage(
                "--notes and --skip-policy-check apply to a promotion, which needs the same \
                 instance and the same path"
                    .into(),
            )
            .into());
        }
        transfer_copy(
            src_repo,
            src_path,
            dst_repo,
            dst_path,
            from_instance,
            to_instance,
            global,
        )
        .await
    } else {
        same_instance_copy(src_repo, src_path, dst_repo, promotion, global).await
    }
}

async fn same_instance_copy(
    src_repo: &str,
    src_path: &str,
    dst_repo: &str,
    promotion: artifact_keeper_sdk::types::PromoteArtifactRequest,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let spinner = output::spinner("Finding artifact...");

    let artifact = client
        .get_repository_artifact_metadata()
        .key(src_repo)
        .path(src_path)
        .send()
        .await
        .map_err(|e| {
            spinner.finish_and_clear();
            if e.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                AkError::NotFound(format!("Artifact '{src_path}' not found in '{src_repo}'"))
            } else {
                sdk_err("find source artifact", e)
            }
        })?;

    spinner.set_message("Copying...");

    let body = artifact_keeper_sdk::types::PromoteArtifactRequest {
        target_repository: Some(dst_repo.to_string()),
        ..promotion
    };

    let (result, raw) = capture(
        client
            .promote_artifact()
            .key(src_repo)
            .artifact_id(artifact.id)
            .body(body)
            .send(),
    )
    .await;
    spinner.finish_and_clear();
    let result = result
        .map_err(|e| crate::commands::helpers::classified(format!("Copy failed: {e}"), &e))?;

    // A promotion a policy turned down still answers 200.
    if !result.promoted {
        let reasons = result
            .policy_violations
            .iter()
            .map(|v| v.message.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        let message = result.message.as_deref().unwrap_or("refused by policy");
        return Err(AkError::ReportedFailure(format!(
            "Copy failed: {}{}{}",
            output::sanitize_terminal(message),
            if reasons.is_empty() { "" } else { ": " },
            output::sanitize_terminal(&reasons),
        ))
        .into());
    }

    emit_mutation_raw(
        raw.as_deref(),
        &serde_json::json!({
            "source": format!("{src_repo}/{src_path}"),
            "destination": format!("{dst_repo}/{src_path}"),
            "status": "copied",
        }),
        dst_repo,
        &format!("Copied '{src_path}' from '{src_repo}' to '{dst_repo}'."),
        global,
    );

    Ok(())
}

/// Copy by downloading and uploading: between instances, or to a different path.
async fn transfer_copy(
    src_repo: &str,
    src_path: &str,
    dst_repo: &str,
    dst_path: &str,
    from_instance: Option<&str>,
    to_instance: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let config = AppConfig::load()?;

    let (src_name, src_instance) =
        config.resolve_instance(from_instance.or(global.instance.as_deref()))?;
    let (dst_name, dst_instance) =
        config.resolve_instance(to_instance.or(global.instance.as_deref()))?;
    crate::transport::warn_if_insecure(src_name, src_instance);
    crate::transport::warn_if_insecure(dst_name, dst_instance);
    let src_auth = format!("Bearer {}", get_credential(src_name)?.access_token);
    let dst_auth = format!("Bearer {}", get_credential(dst_name)?.access_token);

    let spinner = output::spinner(&format!(
        "Downloading from {src_name}:{src_repo}/{src_path}..."
    ));

    let resp = fetch_artifact(&src_instance.url, &src_auth, src_repo, src_path, None)
        .await
        .inspect_err(|_| spinner.finish_and_clear())?;
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| content_type_for_path(dst_path), str::to_string);

    let tmp_file = tempfile::NamedTempFile::new().into_diagnostic()?;
    let tmp_path = tmp_file.path().to_path_buf();
    let mut file = tokio::fs::File::create(&tmp_path).await.into_diagnostic()?;
    let mut stream = resp.bytes_stream();
    let mut total_bytes: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            crate::commands::helpers::classified(format!("Download error: {e}"), &e)
        })?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
            .await
            .into_diagnostic()?;
        total_bytes += chunk.len() as u64;
    }
    // tokio::fs::File does not flush pending writes on drop; flush before the
    // re-open below so the upload doesn't read a truncated file.
    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .into_diagnostic()?;
    drop(file);

    spinner.set_message(format!("Uploading to {dst_name}:{dst_repo}/{dst_path}..."));

    let upload_file = tokio::fs::File::open(&tmp_path).await.into_diagnostic()?;
    let upload_stream = tokio_util::io::ReaderStream::new(upload_file);
    let body = reqwest::Body::wrap_stream(upload_stream);

    let uploaded = single_put_upload(
        &dst_instance.url,
        &dst_auth,
        dst_repo,
        dst_path,
        body,
        &content_type,
        None,
    )
    .await
    .inspect_err(|_| spinner.finish_and_clear())?;

    spinner.finish_and_clear();

    emit_mutation_raw(
        Some(&uploaded.raw),
        &serde_json::json!({
            "source": format!("{src_repo}/{src_path}"),
            "destination": format!("{dst_repo}/{dst_path}"),
            "status": "copied",
        }),
        &output::sanitize_terminal(&uploaded.path),
        &format!(
            "Copied {src_name}:{src_repo}/{src_path} -> {dst_name}:{dst_repo}/{dst_path} ({})",
            format_bytes(total_bytes as i64),
        ),
        global,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    fn test_push_options(
        target_path: Option<&str>,
        chunk_size: &str,
        no_chunked: bool,
        content_type: Option<&str>,
    ) -> PushOptions {
        PushOptions {
            target_path: target_path.map(str::to_string),
            chunk_size: chunk_size.to_string(),
            mode: if no_chunked {
                UploadMode::Put
            } else {
                UploadMode::BySize
            },
            content_type: content_type.map(str::to_string),
            version_label: None,
            session: SessionMetadata::default(),
        }
    }

    // ---- TestCli wrapper for parsing ----

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: ArtifactCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    #[test]
    fn content_type_uses_overrides_then_mime_guess_then_octet_stream() {
        // Curated overrides: the bundled mime.types DB gets these wrong.
        assert_eq!(
            content_type_for_path("pkg-1.0-1.el9.x86_64.rpm"),
            "application/x-rpm"
        );
        assert_eq!(
            content_type_for_path("nested/dir/PKG.RPM"),
            "application/x-rpm"
        );
        assert_eq!(
            content_type_for_path("app.deb"),
            "application/vnd.debian.binary-package"
        );

        assert_eq!(content_type_for_path("pkg-1.0.tgz"), "application/gzip");
        assert_eq!(content_type_for_path("pkg-1.0.tar.gz"), "application/gzip");
        assert_eq!(
            content_type_for_path("v1.0.0.mod"),
            "application/octet-stream"
        );
        assert_eq!(
            content_type_for_path("index.ts"),
            "application/octet-stream"
        );

        // Package formats not in the database stay octet-stream, same as before.
        for name in [
            "a-1.0-py3-none-any.whl",
            "a-1.0.crate",
            "a.1.0.nupkg",
            "a-1.0.gem",
        ] {
            assert_eq!(
                content_type_for_path(name),
                "application/octet-stream",
                "{name}"
            );
        }

        // Long tail resolved via mime_guess (like Python's mimetypes).
        assert_eq!(content_type_for_path("lib.jar"), "application/java-archive");
        assert_eq!(content_type_for_path("notes.txt"), "text/plain");
        assert_eq!(content_type_for_path("page.html"), "text/html");

        // Unknown / extensionless stays the correct generic blob type.
        assert_eq!(
            content_type_for_path("release-1.0"),
            "application/octet-stream"
        );
        assert_eq!(content_type_for_path("README"), "application/octet-stream");
        assert_eq!(
            content_type_for_path("archive.unknownext"),
            "application/octet-stream"
        );
    }

    // ---- Push subcommand parsing ----

    #[test]
    fn parse_push_single_file() {
        let cli = parse(&["test", "push", "my-repo", "package.tar.gz"]);
        if let ArtifactCommand::Push {
            repo, files, path, ..
        } = cli.command
        {
            assert_eq!(repo, "my-repo");
            assert_eq!(files, vec!["package.tar.gz"]);
            assert!(path.is_none());
        } else {
            panic!("Expected ArtifactCommand::Push");
        }
    }

    #[test]
    fn parse_push_multiple_files() {
        let cli = parse(&[
            "test",
            "push",
            "my-repo",
            "file1.jar",
            "file2.jar",
            "file3.jar",
        ]);
        if let ArtifactCommand::Push {
            repo, files, path, ..
        } = cli.command
        {
            assert_eq!(repo, "my-repo");
            assert_eq!(files, vec!["file1.jar", "file2.jar", "file3.jar"]);
            assert!(path.is_none());
        } else {
            panic!("Expected ArtifactCommand::Push");
        }
    }

    #[test]
    fn parse_push_with_path() {
        let cli = parse(&[
            "test",
            "push",
            "my-repo",
            "package.tar.gz",
            "--path",
            "org/pkg/1.0/",
        ]);
        if let ArtifactCommand::Push {
            repo, files, path, ..
        } = cli.command
        {
            assert_eq!(repo, "my-repo");
            assert_eq!(files, vec!["package.tar.gz"]);
            assert_eq!(path.as_deref(), Some("org/pkg/1.0/"));
        } else {
            panic!("Expected ArtifactCommand::Push");
        }
    }

    #[test]
    fn parse_push_glob_pattern() {
        let cli = parse(&["test", "push", "my-repo", "*.tar.gz"]);
        if let ArtifactCommand::Push { repo, files, .. } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(files, vec!["*.tar.gz"]);
        } else {
            panic!("Expected ArtifactCommand::Push");
        }
    }

    #[test]
    fn parse_push_missing_files_fails() {
        assert!(try_parse(&["test", "push", "my-repo"]).is_err());
    }

    #[test]
    fn parse_push_missing_repo_fails() {
        assert!(try_parse(&["test", "push"]).is_err());
    }

    #[test]
    fn parse_push_chunk_size_flag() {
        let cli = parse(&[
            "test",
            "push",
            "my-repo",
            "file.bin",
            "--chunk-size",
            "16MB",
        ]);
        if let ArtifactCommand::Push {
            chunk_size,
            no_chunked,
            ..
        } = cli.command
        {
            assert_eq!(chunk_size, "16MB");
            assert!(!no_chunked);
        } else {
            panic!("Expected ArtifactCommand::Push");
        }
    }

    #[test]
    fn parse_push_content_type_flag() {
        let cli = parse(&[
            "test",
            "push",
            "my-repo",
            "file.bin",
            "--content-type",
            "application/x-rpm",
        ]);
        if let ArtifactCommand::Push { content_type, .. } = cli.command {
            assert_eq!(content_type.as_deref(), Some("application/x-rpm"));
        } else {
            panic!("Expected ArtifactCommand::Push");
        }

        // Omitted => None (detection path).
        let cli = parse(&["test", "push", "my-repo", "file.bin"]);
        if let ArtifactCommand::Push { content_type, .. } = cli.command {
            assert!(content_type.is_none());
        } else {
            panic!("Expected ArtifactCommand::Push");
        }
    }

    #[test]
    fn parse_push_no_chunked_flag() {
        let cli = parse(&["test", "push", "my-repo", "file.bin", "--no-chunked"]);
        if let ArtifactCommand::Push { no_chunked, .. } = cli.command {
            assert!(no_chunked);
        } else {
            panic!("Expected ArtifactCommand::Push");
        }
    }

    #[test]
    fn parse_push_default_chunk_size() {
        let cli = parse(&["test", "push", "my-repo", "file.bin"]);
        if let ArtifactCommand::Push { chunk_size, .. } = cli.command {
            assert_eq!(chunk_size, "8MB");
        } else {
            panic!("Expected ArtifactCommand::Push");
        }
    }

    // ---- Pull subcommand parsing ----

    #[test]
    fn parse_pull() {
        let cli = parse(&["test", "pull", "my-repo", "org/pkg/1.0/pkg.jar"]);
        if let ArtifactCommand::Pull {
            repo,
            path,
            output,
            force,
            ..
        } = cli.command
        {
            assert_eq!(repo, "my-repo");
            assert_eq!(path, "org/pkg/1.0/pkg.jar");
            assert!(output.is_none());
            assert!(!force, "force must default to off");
        } else {
            panic!("Expected ArtifactCommand::Pull");
        }
    }

    #[test]
    fn parse_pull_with_output() {
        let cli = parse(&[
            "test",
            "pull",
            "my-repo",
            "org/pkg/1.0/pkg.jar",
            "-o",
            "local-pkg.jar",
        ]);
        if let ArtifactCommand::Pull {
            repo, path, output, ..
        } = cli.command
        {
            assert_eq!(repo, "my-repo");
            assert_eq!(path, "org/pkg/1.0/pkg.jar");
            assert_eq!(output.as_deref(), Some("local-pkg.jar"));
        } else {
            panic!("Expected ArtifactCommand::Pull");
        }
    }

    #[test]
    fn parse_pull_with_force() {
        let cli = parse(&["test", "pull", "my-repo", "path/to/file", "--force"]);
        if let ArtifactCommand::Pull { force, .. } = cli.command {
            assert!(force);
        } else {
            panic!("Expected ArtifactCommand::Pull");
        }
    }

    #[test]
    fn parse_pull_with_long_output() {
        let cli = parse(&[
            "test",
            "pull",
            "my-repo",
            "path/to/file",
            "--output",
            "out.bin",
        ]);
        if let ArtifactCommand::Pull { output, .. } = cli.command {
            assert_eq!(output.as_deref(), Some("out.bin"));
        } else {
            panic!("Expected ArtifactCommand::Pull");
        }
    }

    #[test]
    fn parse_pull_missing_path_fails() {
        assert!(try_parse(&["test", "pull", "my-repo"]).is_err());
    }

    #[test]
    fn parse_pull_missing_repo_fails() {
        assert!(try_parse(&["test", "pull"]).is_err());
    }

    // ---- List subcommand parsing ----

    #[test]
    fn parse_list() {
        let cli = parse(&["test", "list", "my-repo"]);
        if let ArtifactCommand::List {
            repo,
            search,
            page,
            per_page,
            ..
        } = cli.command
        {
            assert_eq!(repo, "my-repo");
            assert!(search.is_none());
            assert_eq!(page, 1);
            assert_eq!(per_page, 50);
        } else {
            panic!("Expected ArtifactCommand::List");
        }
    }

    #[test]
    fn parse_list_with_search() {
        let cli = parse(&["test", "list", "my-repo", "--search", "log4j"]);
        if let ArtifactCommand::List { search, .. } = cli.command {
            assert_eq!(search.as_deref(), Some("log4j"));
        } else {
            panic!("Expected ArtifactCommand::List");
        }
    }

    #[test]
    fn parse_list_custom_pagination() {
        let cli = parse(&["test", "list", "my-repo", "--page", "3", "--per-page", "25"]);
        if let ArtifactCommand::List { page, per_page, .. } = cli.command {
            assert_eq!(page, 3);
            assert_eq!(per_page, 25);
        } else {
            panic!("Expected ArtifactCommand::List");
        }
    }

    #[test]
    fn parse_list_missing_repo_fails() {
        assert!(try_parse(&["test", "list"]).is_err());
    }

    // ---- Info subcommand parsing ----

    #[test]
    fn parse_info() {
        let cli = parse(&["test", "info", "my-repo", "org/pkg/1.0/pkg.jar"]);
        if let ArtifactCommand::Info { repo, path, .. } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(path, "org/pkg/1.0/pkg.jar");
        } else {
            panic!("Expected ArtifactCommand::Info");
        }
    }

    #[test]
    fn parse_info_missing_path_fails() {
        assert!(try_parse(&["test", "info", "my-repo"]).is_err());
    }

    #[test]
    fn parse_info_missing_repo_fails() {
        assert!(try_parse(&["test", "info"]).is_err());
    }

    // ---- Show/Metadata/Stats (by-id) subcommand parsing ----

    #[test]
    fn parse_show_by_id() {
        let cli = parse(&["test", "show", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]);
        if let ArtifactCommand::Show { id } = cli.command {
            assert_eq!(id, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        } else {
            panic!("Expected ArtifactCommand::Show");
        }
    }

    #[test]
    fn parse_show_by_id_missing_id_fails() {
        assert!(try_parse(&["test", "show"]).is_err());
    }

    #[test]
    fn parse_metadata_by_id() {
        let cli = parse(&["test", "metadata", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]);
        if let ArtifactCommand::Metadata { id } = cli.command {
            assert_eq!(id, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        } else {
            panic!("Expected ArtifactCommand::Metadata");
        }
    }

    #[test]
    fn parse_stats_by_id() {
        let cli = parse(&["test", "stats", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]);
        if let ArtifactCommand::Stats { id } = cli.command {
            assert_eq!(id, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        } else {
            panic!("Expected ArtifactCommand::Stats");
        }
    }

    // ---- Delete subcommand parsing ----

    #[test]
    fn parse_delete() {
        let cli = parse(&["test", "delete", "my-repo", "org/pkg/1.0/pkg.jar"]);
        if let ArtifactCommand::Delete { repo, path, yes } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(path, "org/pkg/1.0/pkg.jar");
            assert!(!yes);
        } else {
            panic!("Expected ArtifactCommand::Delete");
        }
    }

    #[test]
    fn parse_delete_with_yes() {
        let cli = parse(&["test", "delete", "my-repo", "path/to/file", "--yes"]);
        if let ArtifactCommand::Delete { repo, path, yes } = cli.command {
            assert_eq!(repo, "my-repo");
            assert_eq!(path, "path/to/file");
            assert!(yes);
        } else {
            panic!("Expected ArtifactCommand::Delete");
        }
    }

    #[test]
    fn parse_delete_missing_path_fails() {
        assert!(try_parse(&["test", "delete", "my-repo"]).is_err());
    }

    // ---- Search subcommand parsing ----

    #[test]
    fn parse_search() {
        let cli = parse(&["test", "search", "log4j"]);
        if let ArtifactCommand::Search {
            query,
            repo,
            pkg_format,
            ..
        } = cli.command
        {
            assert_eq!(query.as_deref(), Some("log4j"));
            assert!(repo.is_none());
            assert!(pkg_format.is_none());
        } else {
            panic!("Expected ArtifactCommand::Search");
        }
    }

    #[test]
    fn parse_search_with_repo_filter() {
        let cli = parse(&["test", "search", "log4j", "--repo", "maven-central"]);
        if let ArtifactCommand::Search { query, repo, .. } = cli.command {
            assert_eq!(query.as_deref(), Some("log4j"));
            assert_eq!(repo.as_deref(), Some("maven-central"));
        } else {
            panic!("Expected ArtifactCommand::Search");
        }
    }

    #[test]
    fn parse_search_with_format_filter() {
        let cli = parse(&["test", "search", "express", "--pkg-format", "npm"]);
        if let ArtifactCommand::Search {
            query, pkg_format, ..
        } = cli.command
        {
            assert_eq!(query.as_deref(), Some("express"));
            assert_eq!(pkg_format.as_deref(), Some("npm"));
        } else {
            panic!("Expected ArtifactCommand::Search");
        }
    }

    #[test]
    fn parse_search_all_options() {
        let cli = parse(&[
            "test",
            "search",
            "flask",
            "--repo",
            "pypi-repo",
            "--pkg-format",
            "pypi",
        ]);
        if let ArtifactCommand::Search {
            query,
            repo,
            pkg_format,
            ..
        } = cli.command
        {
            assert_eq!(query.as_deref(), Some("flask"));
            assert_eq!(repo.as_deref(), Some("pypi-repo"));
            assert_eq!(pkg_format.as_deref(), Some("pypi"));
        } else {
            panic!("Expected ArtifactCommand::Search");
        }
    }

    #[test]
    fn parse_search_query_is_optional() {
        assert!(try_parse(&["test", "search", "--name", "a"]).is_ok());
    }

    // ---- Copy subcommand parsing ----

    #[test]
    fn parse_copy() {
        let cli = parse(&["test", "copy", "src-repo/path/to/file", "dst-repo"]);
        if let ArtifactCommand::Copy {
            source,
            destination,
            from_instance,
            to_instance,
            ..
        } = cli.command
        {
            assert_eq!(source, "src-repo/path/to/file");
            assert_eq!(destination, "dst-repo");
            assert!(from_instance.is_none());
            assert!(to_instance.is_none());
        } else {
            panic!("Expected ArtifactCommand::Copy");
        }
    }

    #[test]
    fn parse_copy_cross_instance() {
        let cli = parse(&[
            "test",
            "copy",
            "src/path",
            "dst/path",
            "--from-instance",
            "staging",
            "--to-instance",
            "prod",
        ]);
        if let ArtifactCommand::Copy {
            source,
            destination,
            from_instance,
            to_instance,
            ..
        } = cli.command
        {
            assert_eq!(source, "src/path");
            assert_eq!(destination, "dst/path");
            assert_eq!(from_instance.as_deref(), Some("staging"));
            assert_eq!(to_instance.as_deref(), Some("prod"));
        } else {
            panic!("Expected ArtifactCommand::Copy");
        }
    }

    #[test]
    fn parse_copy_from_instance_only() {
        let cli = parse(&[
            "test",
            "copy",
            "src/path",
            "dst/path",
            "--from-instance",
            "staging",
        ]);
        if let ArtifactCommand::Copy {
            from_instance,
            to_instance,
            ..
        } = cli.command
        {
            assert_eq!(from_instance.as_deref(), Some("staging"));
            assert!(to_instance.is_none());
        } else {
            panic!("Expected ArtifactCommand::Copy");
        }
    }

    #[test]
    fn parse_copy_missing_destination_fails() {
        assert!(try_parse(&["test", "copy", "src/path"]).is_err());
    }

    #[test]
    fn parse_copy_missing_source_fails() {
        assert!(try_parse(&["test", "copy"]).is_err());
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

    // ========================================================================
    // Wiremock-based handler tests
    // ========================================================================

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    #[tokio::test]
    async fn handler_list_artifacts_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/.+/artifacts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 50, "total": 0_i64, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list("my-repo", None, &ListFilters::default(), 1, 50, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_artifacts_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/.+/artifacts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "path": "org/example/lib/1.0/lib-1.0.jar",
                    "name": "lib",
                    "version": "1.0",
                    "size_bytes": 2621440_i64,
                    "content_type": "application/java-archive",
                    "checksum_sha256": "abc123def456",
                    "analyzable": true,
                    "download_count": 150_i64,
                    "repository_key": "maven-central",
                    "created_at": "2026-01-15T10:00:00Z",
                    "quarantine_status": "not_quarantined"
                }],
                "pagination": { "page": 1, "per_page": 50, "total": 1_i64, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list(
            "maven-central",
            None,
            &ListFilters::default(),
            1,
            50,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_artifact_info() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/.+/artifacts/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "id": "00000000-0000-0000-0000-000000000001",
                    "path": "org/example/lib/1.0/lib-1.0.jar",
                    "name": "lib",
                    "version": "1.0",
                    "size_bytes": 2621440_i64,
                    "content_type": "application/java-archive",
                    "checksum_sha256": "abc123def456",
                    "analyzable": true,
                    "download_count": 150_i64,
                    "repository_key": "maven-central",
                    "created_at": "2026-01-15T10:00:00Z",
                    "quarantine_status": "not_quarantined"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = info(
            "maven-central",
            "org/example/lib/1.0/lib-1.0.jar",
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_artifact_info_not_found() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/.+/artifacts/.+"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = info("my-repo", "nonexistent", None, &global).await;
        assert!(result.is_err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_by_id() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/artifacts/[^/]+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "path": "org/example/lib/1.0/lib-1.0.jar",
                "name": "lib",
                "version": "1.0",
                "size_bytes": 2621440_i64,
                "content_type": "application/java-archive",
                "checksum_sha256": "abc123def456",
                "analyzable": true,
                "download_count": 150_i64,
                "repository_key": "maven-central",
                "created_at": "2026-01-15T10:00:00Z",
                "quarantine_status": "not_quarantined"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_by_id("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_metadata() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/artifacts/[^/]+/metadata$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "artifact_id": "00000000-0000-0000-0000-000000000001",
                "format": "maven",
                "metadata": { "groupId": "org.example" },
                "properties": { "build": "42" }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_metadata("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_stats() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/artifacts/[^/]+/stats$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "artifact_id": "00000000-0000-0000-0000-000000000001",
                "download_count": 150_i64,
                "first_downloaded": "2026-01-10T10:00:00Z",
                "last_downloaded": "2026-01-15T10:00:00Z"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_stats("00000000-0000-0000-0000-000000000001", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_search_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/search/advanced"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "facets": { "formats": [], "repositories": [], "content_types": [] },
                "pagination": { "page": 1, "per_page": 50, "total": 0_i64, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = search(
            Some("nonexistent"),
            None,
            None,
            &SearchFilters::default(),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_search_with_results() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/search/advanced"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "name": "log4j-core",
                    "path": "org/apache/logging/log4j/log4j-core/2.17.1/log4j-core-2.17.1.jar",
                    "repository_key": "maven-central",
                    "format": "maven",
                    "version": "2.17.1",
                    "type": "library",
                    "size_bytes": 1887436_i64,
                    "created_at": "2026-01-15T10:00:00Z",
                    "quarantine_status": "not_quarantined"
                }],
                "facets": { "formats": [], "repositories": [], "content_types": [] },
                "pagination": { "page": 1, "per_page": 50, "total": 1_i64, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = search(
            Some("log4j"),
            None,
            None,
            &SearchFilters::default(),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_artifact() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path_regex("/api/v1/repositories/.+/artifacts/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        // no_input=true in test_global, so no confirmation prompt
        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = delete("my-repo", "path/to/file", true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_same_instance_copy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        // Mock for finding the source artifact
        Mock::given(method("GET"))
            .and(path_regex("/api/v1/repositories/.+/artifacts/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000099",
                "path": "pkg/lib-1.0.jar",
                "name": "lib",
                "version": "1.0",
                "size_bytes": 1024_i64,
                "content_type": "application/java-archive",
                "checksum_sha256": "abc123",
                "analyzable": true,
                "download_count": 5_i64,
                "repository_key": "src-repo",
                "created_at": "2026-01-15T10:00:00Z",
                "quarantine_status": "not_quarantined"
            })))
            .mount(&server)
            .await;

        // Mock for promote_artifact
        Mock::given(method("POST"))
            .and(path_regex(
                "/api/v1/promotion/repositories/.+/artifacts/.+/promote",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "promoted": true,
                "source": "src-repo",
                "target": "dst-repo",
                "policy_violations": [],
                "message": "Artifact promoted",
                "gate_results": []
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = same_instance_copy(
            "src-repo",
            "pkg/lib-1.0.jar",
            "dst-repo",
            artifact_keeper_sdk::types::PromoteArtifactRequest {
                target_repository: None,
                notes: Some("n".to_string()),
                skip_policy_check: None,
            },
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_artifact_list_json() {
        let items = vec![json!({
            "path": "org/example/lib/1.0.0/lib-1.0.0.jar",
            "version": "1.0.0",
            "size": "2.5 MB",
            "downloads": 150,
            "created_at": "2026-01-15",
        })];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("artifact_list_json", parsed);
    }

    #[test]
    fn snapshot_search_results_json() {
        let items = vec![json!({
            "name": "log4j-core",
            "repository": "maven-central",
            "format": "maven",
            "version": "2.17.1",
            "size": "1.8 MB",
        })];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("artifact_search_json", parsed);
    }

    // ---- push (single-PUT small-file path) ----

    fn upload_response_json(path: &str, size_bytes: i64) -> serde_json::Value {
        json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "repository_key": "my-repo",
            "path": path,
            "name": path,
            "version": null,
            "size_bytes": size_bytes,
            "checksum_sha256": "abc123",
            "content_type": "application/octet-stream",
            "download_count": 0_i64,
            "created_at": "2026-01-15T12:00:00Z",
            "metadata": null,
            "analyzable": true,
            "quarantine_status": "not_quarantined"
        })
    }

    /// The backend returns `201 Created` on the single-PUT upload path;
    /// a successful small-file push must not be treated as an error (#91).
    #[tokio::test]
    async fn handler_push_small_file_accepts_201() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path("/api/v1/repositories/my-repo/artifacts/small.bin"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(upload_response_json("small.bin", 9)),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("small.bin");
        std::fs::write(&file, b"test data").unwrap();

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = push(
            "my-repo",
            &[file.to_string_lossy().into_owned()],
            &test_push_options(None, "8MB", false, None),
            &global,
        )
        .await;
        assert!(result.is_ok(), "201 Created must be a success: {result:?}");
        crate::test_utils::teardown_env();
    }

    /// A plain `200 OK` (what the OpenAPI spec declares) must keep working.
    #[tokio::test]
    async fn handler_push_small_file_accepts_200() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path("/api/v1/repositories/my-repo/artifacts/small.bin"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(upload_response_json("small.bin", 9)),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("small.bin");
        std::fs::write(&file, b"test data").unwrap();

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = push(
            "my-repo",
            &[file.to_string_lossy().into_owned()],
            &test_push_options(None, "8MB", false, None),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    /// A target path with subdirectories must hit the nested artifact route.
    #[tokio::test]
    async fn handler_push_small_file_nested_target_path() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(
                "/api/v1/repositories/my-repo/artifacts/nested/dir/small.bin",
            ))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(upload_response_json("nested/dir/small.bin", 9)),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("small.bin");
        std::fs::write(&file, b"test data").unwrap();

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = push(
            "my-repo",
            &[file.to_string_lossy().into_owned()],
            &test_push_options(Some("nested/dir/"), "8MB", false, None),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    /// Genuine HTTP failures (e.g. unknown repository) must still error.
    #[tokio::test]
    async fn handler_push_small_file_404_is_error() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path_regex("^/api/v1/repositories/.+/artifacts/.+$"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({"error": "repository not found"})),
            )
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("small.bin");
        std::fs::write(&file, b"test data").unwrap();

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = push(
            "no-such-repo",
            &[file.to_string_lossy().into_owned()],
            &test_push_options(None, "8MB", false, None),
            &global,
        )
        .await;
        assert!(result.is_err(), "404 must remain an error");
        let msg = format!("{:?}", result.unwrap_err());
        assert!(msg.contains("404"), "error should carry the status: {msg}");
        crate::test_utils::teardown_env();
    }

    // ---- open_pull_output (overwrite / symlink safety) ----

    #[tokio::test]
    async fn pull_output_fresh_path_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("new-file.bin");
        let file = open_pull_output(&out, false).await;
        assert!(file.is_ok());
        assert!(out.exists());
    }

    #[tokio::test]
    async fn pull_output_existing_file_refused_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("existing.bin");
        std::fs::write(&out, b"precious data").unwrap();

        let result = open_pull_output(&out, false).await;
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("--force"),
            "error should mention --force: {msg}"
        );
        // The existing file must be untouched.
        assert_eq!(std::fs::read(&out).unwrap(), b"precious data");
    }

    #[tokio::test]
    async fn pull_output_existing_file_overwritten_with_force() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("existing.bin");
        std::fs::write(&out, b"old contents").unwrap();

        let mut file = open_pull_output(&out, true).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut file, b"new")
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::flush(&mut file).await.unwrap();
        drop(file);

        assert_eq!(std::fs::read(&out).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pull_output_symlink_refused_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, b"linked target").unwrap();
        let link = dir.path().join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = open_pull_output(&link, false).await;
        assert!(result.is_err(), "must not write through a symlink");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"linked target",
            "symlink target must be untouched"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pull_output_force_replaces_symlink_not_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, b"linked target").unwrap();
        let link = dir.path().join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let mut file = open_pull_output(&link, true).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut file, b"downloaded")
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::flush(&mut file).await.unwrap();
        drop(file);

        // The symlink itself was replaced by a regular file...
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(meta.file_type().is_file(), "output must be a regular file");
        assert_eq!(std::fs::read(&link).unwrap(), b"downloaded");
        // ...and the old target was not written through.
        assert_eq!(std::fs::read(&target).unwrap(), b"linked target");
    }

    // ---- pull handler (wiremock) ----

    #[tokio::test]
    async fn handler_pull_downloads_to_fresh_path() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("^/api/v1/repositories/.+/download/.+$"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"artifact bytes".to_vec()))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("pulled.bin");
        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = pull(
            "my-repo",
            "path/to/pulled.bin",
            Some(&out.to_string_lossy()),
            false,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok(), "pull to fresh path must work: {result:?}");
        assert_eq!(std::fs::read(&out).unwrap(), b"artifact bytes");
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_pull_refuses_existing_output_without_force() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        // No mock mounted: the request must never be sent — the pull should
        // fail fast on the local file check (wiremock would 404 anyway).
        drop(server);

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("existing.bin");
        std::fs::write(&out, b"do not clobber").unwrap();

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = pull(
            "my-repo",
            "path/to/existing.bin",
            Some(&out.to_string_lossy()),
            false,
            None,
            &global,
        )
        .await;
        assert!(
            result.is_err(),
            "existing output without --force must error"
        );
        assert_eq!(std::fs::read(&out).unwrap(), b"do not clobber");
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_pull_overwrites_existing_output_with_force() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("^/api/v1/repositories/.+/download/.+$"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fresh copy".to_vec()))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("existing.bin");
        std::fs::write(&out, b"stale copy").unwrap();

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = pull(
            "my-repo",
            "path/to/existing.bin",
            Some(&out.to_string_lossy()),
            true,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok(), "--force overwrite must work: {result:?}");
        assert_eq!(std::fs::read(&out).unwrap(), b"fresh copy");
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_pull_failed_download_removes_placeholder() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("^/api/v1/repositories/.+/download/.+$"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": "not found"})))
            .mount(&server)
            .await;

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("missing.bin");
        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = pull(
            "my-repo",
            "path/to/missing.bin",
            Some(&out.to_string_lossy()),
            false,
            None,
            &global,
        )
        .await;
        assert!(result.is_err());
        assert!(
            !out.exists(),
            "failed pull must not leave an empty placeholder file"
        );
        crate::test_utils::teardown_env();
    }

    #[test]
    fn copy_destination_defaults_to_the_source_path() {
        assert_eq!(
            parse_copy_destination("dst", "a/b.txt").unwrap(),
            ("dst", "a/b.txt")
        );
        assert_eq!(
            parse_copy_destination("dst/", "a/b.txt").unwrap(),
            ("dst", "a/b.txt")
        );
        assert_eq!(
            parse_copy_destination("dst/c/d.txt", "a/b.txt").unwrap(),
            ("dst", "c/d.txt")
        );
        assert!(parse_copy_destination("/x", "a").is_err());
    }

    #[test]
    fn presence_items_come_from_flags_json_and_sha256sum() {
        let item = parse_presence_item("a/b=c.txt=abc").unwrap();
        assert_eq!(
            (item.path.as_str(), item.sha256.as_str()),
            ("a/b=c.txt", "abc")
        );
        assert!(parse_presence_item("nope").is_err());

        let json = parse_presence_list(r#"[{"path":"a","sha256":"1"}]"#).unwrap();
        assert_eq!(json[0].path, "a");

        let lines = parse_presence_list("111  a b.txt\n222 *c.bin\n\n").unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].path, "a b.txt");
        assert_eq!(lines[1].path, "c.bin");
        assert_eq!(lines[1].sha256, "222");
        assert!(parse_presence_list("oneword").is_err());
    }
}
