//! What the package-format helpers share: the request, the reply, and the file.
//!
//! A format's wire protocol isn't in the OpenAPI spec, so these go over raw HTTP
//! rather than the SDK. The token goes to the instance's own URL only, and the
//! redirect policy drops it if the server sends us elsewhere.

use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, Result};
use reqwest::header::HeaderMap;
use reqwest::{Method, RequestBuilder, Response, StatusCode, Url};
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
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    /// A reply this command made up, for what's several requests with no one answer.
    pub fn new(body: Value) -> Self {
        Self {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: body.to_string().into_bytes(),
        }
    }

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

    /// A request that carries its credential in the URL, so no header. See [`Wire::token`].
    pub fn request_no_header(&self, method: Method, url: Url) -> RequestBuilder {
        self.client.request(method, url)
    }

    /// The token itself, for a route that takes it in the URL. Never print a URL holding it.
    pub fn token(&self) -> &str {
        self.auth.strip_prefix("Bearer ").unwrap_or(&self.auth)
    }

    /// Send and hand back the response unread, for a download to stream. A failure still
    /// comes back as the server's own message.
    pub async fn send_streaming(&self, action: &str, request: RequestBuilder) -> Result<Response> {
        let response = request
            .send()
            .await
            .map_err(|e| crate::commands::helpers::network_err(action, e))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(raw_err(action, status, &body).into());
        }
        Ok(response)
    }

    /// Send, and turn any status but a success into the server's own message.
    pub async fn send(&self, action: &str, request: RequestBuilder) -> Result<Reply> {
        let response = request
            .send()
            .await
            .map_err(|e| crate::commands::helpers::network_err(action, e))?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await.into_diagnostic()?.to_vec();
        if !status.is_success() {
            return Err(raw_err(action, status, &String::from_utf8_lossy(&body)).into());
        }
        Ok(Reply {
            status,
            headers,
            body,
        })
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
        let response = request
            .send()
            .await
            .map_err(|e| crate::commands::helpers::network_err(action, e))?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await.into_diagnostic()?.to_vec();
        if !status.is_success() {
            let text = String::from_utf8_lossy(&body);
            return Err(since_1_11_raw(status, &text, action, command, global)
                .await
                .into());
        }
        Ok(Reply {
            status,
            headers,
            body,
        })
    }
}

/// Send a file as the body of `request`, and report it published. This is all a publish
/// is for a format whose server reads everything it needs from the file.
pub async fn publish_file(
    wire: &Wire,
    request: RequestBuilder,
    upload: &Upload,
    repo: &str,
    global: &GlobalArgs,
) -> Result<()> {
    let request = upload.attach(request, "application/octet-stream").await?;
    let reply = wire.send("upload the package", request).await?;
    emit(
        &reply,
        &upload.name,
        &format!("Published {} to {repo}.", upload.name),
        global,
    );
    Ok(())
}

/// `a/b/c` as segments. An empty or dot segment can't be meant: the URL would point
/// somewhere other than the path given.
pub fn split_path<'a>(path: &'a str, what: &str) -> Result<Vec<&'a str>> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if segments
        .iter()
        .any(|s| s.is_empty() || *s == "." || *s == "..")
    {
        return Err(AkError::Usage(format!("{what} `{path}` isn't a valid path")).into());
    }
    Ok(segments)
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
            .map_err(|e| AkError::Usage(format!("Can't read {}: {e}", path.display())))?;
        if !meta.is_file() {
            return Err(AkError::Usage(format!("{} isn't a file", path.display())).into());
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .ok_or_else(|| AkError::Usage(format!("{} has no name", path.display())))?;
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

    /// A request with the file as its body, its length known and streamed.
    pub async fn attach(
        &self,
        request: RequestBuilder,
        content_type: &str,
    ) -> Result<RequestBuilder> {
        Ok(request
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .header(reqwest::header::CONTENT_LENGTH, self.len)
            .body(self.body().await?))
    }

    /// The file as a multipart part with its name, streamed.
    pub async fn part(&self, content_type: &str) -> Result<reqwest::multipart::Part> {
        reqwest::multipart::Part::stream_with_length(self.body().await?, self.len)
            .file_name(self.name.clone())
            .mime_str(content_type)
            .into_diagnostic()
    }

    pub async fn read(&self) -> Result<Vec<u8>> {
        tokio::fs::read(&self.path)
            .await
            .map_err(|e| AkError::Usage(format!("Can't read {}: {e}", self.path.display())).into())
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
