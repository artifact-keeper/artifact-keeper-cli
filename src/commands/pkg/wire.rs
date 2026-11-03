//! What the package-format helpers share: the request, the reply, and the file.
//!
//! A format's wire protocol isn't in the OpenAPI spec, so these go over raw HTTP
//! rather than the SDK. The token goes to the instance's own URL only, and the
//! redirect policy drops it if the server sends us elsewhere.

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, Result};
use reqwest::{Method, RequestBuilder, StatusCode, Url};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

use crate::cli::GlobalArgs;
use crate::commands::client::{raw_http_client, resolve_base_url_and_auth};
use crate::commands::helpers::{emit_mutation_raw, raw_err, since_1_11_raw};
use crate::error::AkError;

/// The instance, ready for raw requests.
pub struct Wire {
    client: reqwest::Client,
    base: Url,
    auth: String,
}

/// A response whose status was a success.
pub struct Reply {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

impl Wire {
    pub fn new(global: &GlobalArgs) -> Result<Self> {
        let (url, auth) = resolve_base_url_and_auth(global)?;
        let base = Url::parse(&url).map_err(|e| {
            AkError::ConfigError(format!("The instance URL {url} isn't valid: {e}"))
        })?;
        Ok(Self {
            client: raw_http_client()?,
            base,
            auth,
        })
    }

    /// The URL of a path on the instance. Each segment is encoded on its own, so a
    /// `/` inside a segment stays part of it.
    pub fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base.clone();
        url.set_query(None);
        url.set_fragment(None);
        if let Ok(mut path) = url.path_segments_mut() {
            path.pop_if_empty().extend(segments);
        }
        url
    }

    pub fn request(&self, method: Method, url: Url) -> RequestBuilder {
        self.client
            .request(method, url)
            .header(reqwest::header::AUTHORIZATION, &self.auth)
    }

    /// Send, and turn any status but a success into the server's own message.
    pub async fn send(&self, action: &str, request: RequestBuilder) -> Result<Reply> {
        let response = request.send().await.map_err(|e| {
            AkError::ServerError(format!("Failed to {action}: {}", e.without_url()))
        })?;
        let status = response.status();
        let body = response.bytes().await.into_diagnostic()?.to_vec();
        if !status.is_success() {
            return Err(raw_err(action, status, &String::from_utf8_lossy(&body)).into());
        }
        Ok(Reply { status, body })
    }
}

impl Wire {
    /// [`Wire::send`] for a route new in 1.11: a 404 from an older server names that
    /// as the problem, instead of a package that's really there.
    pub async fn send_since_1_11(
        &self,
        action: &str,
        command: &str,
        global: &GlobalArgs,
        request: RequestBuilder,
    ) -> Result<Reply> {
        let response = request.send().await.map_err(|e| {
            AkError::ServerError(format!("Failed to {action}: {}", e.without_url()))
        })?;
        let status = response.status();
        let body = response.bytes().await.into_diagnostic()?.to_vec();
        if !status.is_success() {
            let text = String::from_utf8_lossy(&body);
            return Err(since_1_11_raw(status, &text, action, command, global)
                .await
                .into());
        }
        Ok(Reply { status, body })
    }
}

/// A file to upload. Checked before anything is sent.
pub struct Upload {
    pub path: PathBuf,
    pub name: String,
    pub len: u64,
}

impl Upload {
    pub fn open(path: &Path) -> Result<Self> {
        let meta = std::fs::metadata(path)
            .map_err(|e| AkError::ConfigError(format!("Can't read {}: {e}", path.display())))?;
        if !meta.is_file() {
            return Err(AkError::ConfigError(format!("{} isn't a file", path.display())).into());
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .ok_or_else(|| AkError::ConfigError(format!("{} has no name", path.display())))?;
        Ok(Self {
            path: path.to_path_buf(),
            name,
            len: meta.len(),
        })
    }

    /// The file's bytes as a streamed request body, so a large file isn't held in memory.
    pub async fn body(&self) -> Result<reqwest::Body> {
        let file = tokio::fs::File::open(&self.path).await.into_diagnostic()?;
        Ok(reqwest::Body::wrap_stream(ReaderStream::with_capacity(
            file,
            256 * 1024,
        )))
    }

    /// The file as a multipart part with its name, streamed.
    pub async fn part(&self, content_type: &str) -> Result<reqwest::multipart::Part> {
        reqwest::multipart::Part::stream_with_length(self.body().await?, self.len)
            .file_name(self.name.clone())
            .mime_str(content_type)
            .into_diagnostic()
    }

    pub fn read(&self) -> Result<Vec<u8>> {
        std::fs::read(&self.path).map_err(|e| {
            AkError::ConfigError(format!("Can't read {}: {e}", self.path.display())).into()
        })
    }

    pub async fn sha256(&self) -> Result<String> {
        let mut file = tokio::fs::File::open(&self.path).await.into_diagnostic()?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 256 * 1024];
        loop {
            let read = file.read(&mut buffer).await.into_diagnostic()?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hex::encode(hasher.finalize()))
    }
}

/// Print the outcome: the server's body in `--format json`, `id` in quiet, and `human`
/// in a table. Plenty of these routes answer with an empty body or plain text, which
/// has nothing to print as received, so those get the status and the text.
pub fn emit(reply: &Reply, id: &str, human: &str, global: &GlobalArgs) {
    let text = String::from_utf8_lossy(&reply.body);
    let fallback = json!({"status": reply.status.as_u16(), "body": text.trim()});
    emit_mutation_raw(Some(&reply.body), &fallback, id, human, global);
}
