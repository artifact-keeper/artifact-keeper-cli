use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use miette::{IntoDiagnostic, Result};
use reqwest::header::{AUTHORIZATION, CONTENT_RANGE, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::config;
use crate::error::AkError;

// ---------------------------------------------------------------------------
// Size parsing
// ---------------------------------------------------------------------------

/// Parse a human-readable size string (e.g. "8MB", "100mb", "1GB") into bytes.
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num_part, unit) = split_number_unit(s)?;
    let value: f64 = num_part
        .parse()
        .map_err(|_| AkError::ConfigError(format!("Invalid size number: {num_part}")))?;
    if value < 0.0 {
        return Err(AkError::ConfigError("Size cannot be negative".into()).into());
    }
    let multiplier = match unit.to_uppercase().as_str() {
        "B" | "" => 1u64,
        "KB" | "K" => 1024,
        "MB" | "M" => 1024 * 1024,
        "GB" | "G" => 1024 * 1024 * 1024,
        "TB" | "T" => 1024 * 1024 * 1024 * 1024,
        _ => return Err(AkError::ConfigError(format!("Unknown size unit: {unit}")).into()),
    };
    Ok((value * multiplier as f64) as u64)
}

fn split_number_unit(s: &str) -> Result<(&str, &str)> {
    let idx = s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len());
    if idx == 0 {
        return Err(AkError::ConfigError(format!("Invalid size: {s}")).into());
    }
    Ok((&s[..idx], &s[idx..]))
}

/// Return the chunked upload threshold in bytes.
/// Reads from AK_CHUNKED_THRESHOLD env var, defaulting to 100MB.
pub fn chunked_threshold() -> Result<u64> {
    match std::env::var("AK_CHUNKED_THRESHOLD") {
        Ok(val) => parse_size(&val),
        Err(_) => Ok(100 * 1024 * 1024), // 100MB
    }
}

// ---------------------------------------------------------------------------
// SHA256 streaming
// ---------------------------------------------------------------------------

/// Compute SHA256 of a file by streaming in 64KB chunks.
/// Returns the hex-encoded digest.
pub async fn sha256_file(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await.into_diagnostic()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await.into_diagnostic()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Compute SHA256 of a file path string (for cache key derivation).
pub fn sha256_of_string(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Session cache (for resume support)
// ---------------------------------------------------------------------------

/// Cached session info stored locally for resume support.
#[derive(Debug, Serialize, Deserialize)]
pub struct CachedSession {
    pub session_id: String,
    pub file_path: String,
    pub file_sha256: String,
    pub total_size: u64,
    pub chunk_size: u64,
    pub chunk_count: u64,
    pub repository_key: String,
    pub artifact_path: String,
    pub created_at: DateTime<Utc>,
}

/// Directory for upload session caches.
fn uploads_cache_dir() -> Result<PathBuf> {
    Ok(config::config_dir()?.join("uploads"))
}

/// Cache file path for a given file (keyed by absolute path SHA256).
fn cache_path_for(file_path: &Path) -> Result<PathBuf> {
    let canonical = file_path
        .canonicalize()
        .map_err(|e| AkError::ConfigError(format!("Cannot resolve path: {e}")))?;
    let key = sha256_of_string(&canonical.to_string_lossy());
    Ok(uploads_cache_dir()?.join(format!("{key}.json")))
}

/// Save a session to the local cache.
pub fn save_session_cache(file_path: &Path, session: &CachedSession) -> Result<()> {
    let path = cache_path_for(file_path)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).into_diagnostic()?;
    }
    let json = serde_json::to_string_pretty(session).into_diagnostic()?;
    std::fs::write(&path, json).into_diagnostic()?;
    Ok(())
}

/// Load a cached session for the given file, if one exists.
pub fn load_session_cache(file_path: &Path) -> Result<Option<CachedSession>> {
    let path = cache_path_for(file_path)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path).into_diagnostic()?;
    let session: CachedSession = serde_json::from_str(&content).into_diagnostic()?;
    Ok(Some(session))
}

/// Remove the cached session file for a given file path.
pub fn remove_session_cache(file_path: &Path) -> Result<()> {
    let path = cache_path_for(file_path)?;
    if path.exists() {
        std::fs::remove_file(&path).into_diagnostic()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// API request/response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct CreateSessionRequest {
    pub repository_key: String,
    pub artifact_path: String,
    pub total_size: u64,
    pub checksum_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub chunk_count: u64,
    pub chunk_size: u64,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct UploadChunkResponse {
    pub chunk_index: u64,
    pub bytes_received: u64,
    pub chunks_completed: u64,
    pub chunks_remaining: u64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SessionStatusResponse {
    pub session_id: String,
    pub status: String,
    pub total_size: u64,
    pub bytes_received: u64,
    pub chunks_completed: u64,
    pub chunks_total: u64,
    pub repository_key: String,
    pub artifact_path: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct FinalizeResponse {
    pub artifact_id: String,
    pub path: String,
    pub size: u64,
    pub checksum_sha256: String,
}

// ---------------------------------------------------------------------------
// Chunked upload logic
// ---------------------------------------------------------------------------

/// Perform the full chunked upload flow for a single file.
///
/// This function:
/// 1. Computes the file's SHA256 checksum (streaming)
/// 2. Checks for a resumable cached session
/// 3. Creates a new upload session or resumes an existing one
/// 4. Uploads chunks sequentially with retry logic
/// 5. Finalizes the upload
/// 6. Cleans up the session cache
#[allow(clippy::too_many_arguments)]
pub async fn chunked_upload(
    base_url: &str,
    auth_header: &str,
    file_path: &Path,
    repo: &str,
    artifact_path: &str,
    chunk_size: u64,
    file_size: u64,
    file_name: &str,
) -> Result<FinalizeResponse> {
    // Step 1: Compute SHA256
    let sha_spinner = crate::output::spinner(&format!("Computing checksum for {file_name}..."));
    let file_sha256 = sha256_file(file_path).await?;
    sha_spinner.finish_and_clear();

    // Step 2: Check for existing session to resume
    let http = reqwest::Client::new();
    let (session_id, server_chunk_size, chunks_completed) =
        match try_resume(&http, base_url, auth_header, file_path, &file_sha256).await? {
            Some((sid, cs, cc)) => {
                eprintln!(
                    "Resuming upload session {}: {}/{} chunks completed",
                    &sid[..8],
                    cc,
                    file_size.div_ceil(cs)
                );
                (sid, cs, cc)
            }
            None => {
                // Step 3: Create new session
                let resp = create_session(
                    &http,
                    base_url,
                    auth_header,
                    repo,
                    artifact_path,
                    file_size,
                    &file_sha256,
                    chunk_size,
                )
                .await?;

                // Cache the session for resume
                let cached = CachedSession {
                    session_id: resp.session_id.clone(),
                    file_path: file_path.to_string_lossy().into_owned(),
                    file_sha256: file_sha256.clone(),
                    total_size: file_size,
                    chunk_size: resp.chunk_size,
                    chunk_count: resp.chunk_count,
                    repository_key: repo.to_string(),
                    artifact_path: artifact_path.to_string(),
                    created_at: Utc::now(),
                };
                save_session_cache(file_path, &cached)?;

                (resp.session_id, resp.chunk_size, 0)
            }
        };

    let chunk_count = file_size.div_ceil(server_chunk_size);

    // Step 4: Upload chunks with progress bar
    let pb = indicatif::ProgressBar::new(file_size);
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} chunk {pos}/{len} ({bytes_per_sec}, {eta})",
        )
        .unwrap()
        .progress_chars("##-"),
    );
    pb.set_message(format!("Uploading {file_name}"));
    pb.set_length(file_size);
    // Set already-uploaded progress
    pb.set_position(chunks_completed * server_chunk_size);

    let mut file = tokio::fs::File::open(file_path).await.into_diagnostic()?;

    for chunk_idx in 0..chunk_count {
        // Skip already-completed chunks
        if chunk_idx < chunks_completed {
            continue;
        }

        let offset = chunk_idx * server_chunk_size;
        let end = std::cmp::min(offset + server_chunk_size, file_size);
        let this_chunk_size = end - offset;

        // Seek to the right position
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .into_diagnostic()?;

        // Read chunk into buffer
        let mut buf = vec![0u8; this_chunk_size as usize];
        file.read_exact(&mut buf).await.into_diagnostic()?;

        // Upload with retry
        let content_range = format!("bytes {offset}-{}/{file_size}", end - 1);
        let mut last_err = None;
        for attempt in 0..3 {
            if attempt > 0 {
                let delay = std::time::Duration::from_millis(500 * 2u64.pow(attempt as u32));
                tokio::time::sleep(delay).await;
            }
            match upload_chunk(
                &http,
                base_url,
                auth_header,
                &session_id,
                &content_range,
                &buf,
            )
            .await
            {
                Ok(_resp) => {
                    last_err = None;
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        if let Some(err) = last_err {
            // Save state so user can resume later
            pb.abandon_with_message(format!(
                "Upload paused at chunk {}/{chunk_count}",
                chunk_idx + 1
            ));
            eprintln!(
                "Upload failed after 3 retries. Resume with: ak artifact push {repo} {}",
                file_path.display()
            );
            return Err(err);
        }

        pb.set_position(end);
    }

    pb.finish_with_message(format!("Uploaded {file_name}"));

    // Step 5: Finalize
    let result = finalize_upload(&http, base_url, auth_header, &session_id).await?;

    // Step 6: Clean up cache
    remove_session_cache(file_path)?;

    Ok(result)
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn create_session(
    http: &reqwest::Client,
    base_url: &str,
    auth_header: &str,
    repo: &str,
    artifact_path: &str,
    total_size: u64,
    checksum_sha256: &str,
    chunk_size: u64,
) -> Result<CreateSessionResponse> {
    let body = CreateSessionRequest {
        repository_key: repo.to_string(),
        artifact_path: artifact_path.to_string(),
        total_size,
        checksum_sha256: checksum_sha256.to_string(),
        chunk_size: Some(chunk_size),
        content_type: None,
    };

    let resp = http
        .post(format!("{base_url}/api/v1/uploads"))
        .header(AUTHORIZATION, auth_header)
        .json(&body)
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("Failed to create upload session: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(
            AkError::ServerError(format!("Create session failed ({status}): {text}")).into(),
        );
    }

    resp.json::<CreateSessionResponse>()
        .await
        .map_err(|e| AkError::ServerError(format!("Invalid session response: {e}")).into())
}

async fn upload_chunk(
    http: &reqwest::Client,
    base_url: &str,
    auth_header: &str,
    session_id: &str,
    content_range: &str,
    data: &[u8],
) -> Result<UploadChunkResponse> {
    let resp = http
        .patch(format!("{base_url}/api/v1/uploads/{session_id}"))
        .header(AUTHORIZATION, auth_header)
        .header(CONTENT_RANGE, content_range)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(data.to_vec())
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("Chunk upload failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(AkError::ServerError(format!("Chunk upload failed ({status}): {text}")).into());
    }

    resp.json::<UploadChunkResponse>()
        .await
        .map_err(|e| AkError::ServerError(format!("Invalid chunk response: {e}")).into())
}

async fn get_session_status(
    http: &reqwest::Client,
    base_url: &str,
    auth_header: &str,
    session_id: &str,
) -> Result<Option<SessionStatusResponse>> {
    let resp = http
        .get(format!("{base_url}/api/v1/uploads/{session_id}"))
        .header(AUTHORIZATION, auth_header)
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("Session status check failed: {e}")))?;

    if resp.status() == reqwest::StatusCode::GONE {
        // Session expired
        return Ok(None);
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(
            AkError::ServerError(format!("Session status failed ({status}): {text}")).into(),
        );
    }

    let status = resp
        .json::<SessionStatusResponse>()
        .await
        .map_err(|e| AkError::ServerError(format!("Invalid status response: {e}")))?;

    Ok(Some(status))
}

async fn finalize_upload(
    http: &reqwest::Client,
    base_url: &str,
    auth_header: &str,
    session_id: &str,
) -> Result<FinalizeResponse> {
    let resp = http
        .put(format!("{base_url}/api/v1/uploads/{session_id}/complete"))
        .header(AUTHORIZATION, auth_header)
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("Finalize failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(AkError::ServerError(format!("Finalize failed ({status}): {text}")).into());
    }

    resp.json::<FinalizeResponse>()
        .await
        .map_err(|e| AkError::ServerError(format!("Invalid finalize response: {e}")).into())
}

/// Try to resume an existing upload session.
/// Returns Some((session_id, chunk_size, chunks_completed)) if resumable.
async fn try_resume(
    http: &reqwest::Client,
    base_url: &str,
    auth_header: &str,
    file_path: &Path,
    current_sha256: &str,
) -> Result<Option<(String, u64, u64)>> {
    let cached = match load_session_cache(file_path)? {
        Some(c) => c,
        None => return Ok(None),
    };

    // Verify the file hasn't changed
    if cached.file_sha256 != current_sha256 {
        eprintln!("File changed since last upload attempt, starting fresh");
        remove_session_cache(file_path)?;
        return Ok(None);
    }

    // Check if the server session is still alive
    match get_session_status(http, base_url, auth_header, &cached.session_id).await? {
        Some(status) if status.status != "completed" => Ok(Some((
            cached.session_id,
            cached.chunk_size,
            status.chunks_completed,
        ))),
        Some(_) => {
            // Session already completed somehow
            remove_session_cache(file_path)?;
            Ok(None)
        }
        None => {
            // Session expired (410 Gone)
            eprintln!("Previous upload session expired, starting new session");
            remove_session_cache(file_path)?;
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_size ----

    #[test]
    fn parse_size_bytes() {
        assert_eq!(parse_size("100B").unwrap(), 100);
        assert_eq!(parse_size("0B").unwrap(), 0);
    }

    #[test]
    fn parse_size_bare_number() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
    }

    #[test]
    fn parse_size_kilobytes() {
        assert_eq!(parse_size("1KB").unwrap(), 1024);
        assert_eq!(parse_size("1K").unwrap(), 1024);
        assert_eq!(parse_size("10KB").unwrap(), 10240);
    }

    #[test]
    fn parse_size_megabytes() {
        assert_eq!(parse_size("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("8MB").unwrap(), 8 * 1024 * 1024);
        assert_eq!(parse_size("100MB").unwrap(), 100 * 1024 * 1024);
        assert_eq!(parse_size("1M").unwrap(), 1024 * 1024);
    }

    #[test]
    fn parse_size_gigabytes() {
        assert_eq!(parse_size("1GB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_size_case_insensitive() {
        assert_eq!(parse_size("8mb").unwrap(), 8 * 1024 * 1024);
        assert_eq!(parse_size("8Mb").unwrap(), 8 * 1024 * 1024);
        assert_eq!(parse_size("1gb").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_size_with_whitespace() {
        assert_eq!(parse_size("  8MB  ").unwrap(), 8 * 1024 * 1024);
    }

    #[test]
    fn parse_size_fractional() {
        assert_eq!(parse_size("1.5MB").unwrap(), (1.5 * 1024.0 * 1024.0) as u64);
    }

    #[test]
    fn parse_size_invalid_unit() {
        assert!(parse_size("10XB").is_err());
    }

    #[test]
    fn parse_size_no_number() {
        assert!(parse_size("MB").is_err());
    }

    #[test]
    fn parse_size_negative() {
        assert!(parse_size("-5MB").is_err());
    }

    // ---- sha256_of_string ----

    #[test]
    fn sha256_of_string_deterministic() {
        let a = sha256_of_string("/path/to/file.tar.gz");
        let b = sha256_of_string("/path/to/file.tar.gz");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // hex-encoded SHA256 is 64 chars
    }

    #[test]
    fn sha256_of_string_different_inputs() {
        let a = sha256_of_string("/path/a");
        let b = sha256_of_string("/path/b");
        assert_ne!(a, b);
    }

    // ---- session cache ----

    #[test]
    fn cached_session_roundtrip() {
        let session = CachedSession {
            session_id: "test-id".into(),
            file_path: "/tmp/file.bin".into(),
            file_sha256: "abc123".into(),
            total_size: 1000,
            chunk_size: 100,
            chunk_count: 10,
            repository_key: "my-repo".into(),
            artifact_path: "file.bin".into(),
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&session).unwrap();
        let loaded: CachedSession = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.session_id, "test-id");
        assert_eq!(loaded.total_size, 1000);
        assert_eq!(loaded.chunk_count, 10);
    }

    #[test]
    fn session_cache_save_load_remove() {
        let _guard = crate::test_utils::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        // Create a temp file to use as the "upload file"
        let file_dir = tempfile::tempdir().unwrap();
        let file_path = file_dir.path().join("test-upload.bin");
        std::fs::write(&file_path, b"test data").unwrap();

        let session = CachedSession {
            session_id: "sess-123".into(),
            file_path: file_path.to_string_lossy().into_owned(),
            file_sha256: "deadbeef".into(),
            total_size: 9,
            chunk_size: 5,
            chunk_count: 2,
            repository_key: "repo".into(),
            artifact_path: "test-upload.bin".into(),
            created_at: Utc::now(),
        };

        // Save
        save_session_cache(&file_path, &session).unwrap();

        // Load
        let loaded = load_session_cache(&file_path).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.session_id, "sess-123");

        // Remove
        remove_session_cache(&file_path).unwrap();
        let gone = load_session_cache(&file_path).unwrap();
        assert!(gone.is_none());

        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn load_nonexistent_cache_returns_none() {
        let _guard = crate::test_utils::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let file_dir = tempfile::tempdir().unwrap();
        let file_path = file_dir.path().join("nonexistent-upload.bin");
        std::fs::write(&file_path, b"x").unwrap();

        let result = load_session_cache(&file_path).unwrap();
        assert!(result.is_none());

        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    // ---- API types serialization ----

    #[test]
    fn create_session_request_serialization() {
        let req = CreateSessionRequest {
            repository_key: "my-repo".into(),
            artifact_path: "images/vm.ova".into(),
            total_size: 21474836480,
            checksum_sha256: "abc123".into(),
            chunk_size: Some(8388608),
            content_type: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("my-repo"));
        assert!(json.contains("21474836480"));
        assert!(json.contains("8388608"));
        // content_type should be omitted when None
        assert!(!json.contains("content_type"));
    }

    #[test]
    fn create_session_request_with_content_type() {
        let req = CreateSessionRequest {
            repository_key: "repo".into(),
            artifact_path: "file.bin".into(),
            total_size: 1000,
            checksum_sha256: "hash".into(),
            chunk_size: None,
            content_type: Some("application/octet-stream".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("content_type"));
        // chunk_size should be omitted when None
        assert!(!json.contains("chunk_size"));
    }

    #[test]
    fn create_session_response_deserialization() {
        let json = r#"{
            "session_id": "uuid-here",
            "chunk_count": 100,
            "chunk_size": 8388608,
            "expires_at": "2026-03-24T00:00:00Z"
        }"#;
        let resp: CreateSessionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.session_id, "uuid-here");
        assert_eq!(resp.chunk_count, 100);
        assert_eq!(resp.chunk_size, 8388608);
    }

    #[test]
    fn upload_chunk_response_deserialization() {
        let json = r#"{
            "chunk_index": 5,
            "bytes_received": 8388608,
            "chunks_completed": 6,
            "chunks_remaining": 94
        }"#;
        let resp: UploadChunkResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.chunk_index, 5);
        assert_eq!(resp.chunks_completed, 6);
        assert_eq!(resp.chunks_remaining, 94);
    }

    #[test]
    fn session_status_response_deserialization() {
        let json = r#"{
            "session_id": "uuid",
            "status": "in_progress",
            "total_size": 21474836480,
            "bytes_received": 167772160,
            "chunks_completed": 20,
            "chunks_total": 2560,
            "repository_key": "my-repo",
            "artifact_path": "images/vm.ova",
            "created_at": "2026-03-23T00:00:00Z",
            "expires_at": "2026-03-24T00:00:00Z"
        }"#;
        let resp: SessionStatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "in_progress");
        assert_eq!(resp.chunks_completed, 20);
        assert_eq!(resp.chunks_total, 2560);
    }

    #[test]
    fn finalize_response_deserialization() {
        let json = r#"{
            "artifact_id": "artifact-uuid",
            "path": "images/vm.ova",
            "size": 21474836480,
            "checksum_sha256": "abc123"
        }"#;
        let resp: FinalizeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.artifact_id, "artifact-uuid");
        assert_eq!(resp.size, 21474836480);
    }

    // ---- sha256_file ----

    #[tokio::test]
    async fn sha256_file_computes_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"hello world").unwrap();

        let hash = sha256_file(&path).await.unwrap();
        // Known SHA256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[tokio::test]
    async fn sha256_file_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, b"").unwrap();

        let hash = sha256_file(&path).await.unwrap();
        // Known SHA256 of empty string
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ---- chunked_threshold ----

    #[test]
    fn chunked_threshold_default() {
        let _guard = crate::test_utils::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("AK_CHUNKED_THRESHOLD") };
        let threshold = chunked_threshold().unwrap();
        assert_eq!(threshold, 100 * 1024 * 1024);
        unsafe { std::env::remove_var("AK_CHUNKED_THRESHOLD") };
    }

    #[test]
    fn chunked_threshold_from_env() {
        let _guard = crate::test_utils::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("AK_CHUNKED_THRESHOLD", "50MB") };
        let threshold = chunked_threshold().unwrap();
        assert_eq!(threshold, 50 * 1024 * 1024);
        unsafe { std::env::remove_var("AK_CHUNKED_THRESHOLD") };
    }
}
