//! The error every SDK operation returns.
//!
//! Progenitor's own error throws away the body of a documented error response,
//! and its `Display` prints response headers instead. This one keeps the body and
//! has no headers at all, so `{e}` gives a person the server's message and can't
//! put a header in a terminal or a log. `cargo xtask generate` swaps it into the
//! generated code.

use std::fmt;

use progenitor_client::Error as ProgenitorError;
use reqwest::StatusCode;

/// How much of an error body to keep. Error bodies are small, and this bounds
/// the memory a misbehaving server can make the CLI use.
const MAX_ERROR_BODY: usize = 1024 * 1024;
/// How much of a body with no JSON message to show.
const MAX_DISPLAYED_TEXT: usize = 500;

#[derive(Debug)]
pub enum Error {
    /// The request couldn't be built, such as when a required argument is missing.
    InvalidRequest(String),
    /// Nothing usable came back: connection, TLS or timeout.
    Communication(reqwest::Error),
    /// The server answered with a status the operation doesn't treat as success.
    Response { status: StatusCode, body: Vec<u8> },
    /// The status was right but the body wasn't what the API describes.
    InvalidPayload {
        status: Option<StatusCode>,
        reason: String,
    },
}

impl Error {
    /// The HTTP status, when the server answered.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Response { status, .. } => Some(*status),
            Self::InvalidPayload { status, .. } => *status,
            Self::Communication(e) => e.status(),
            Self::InvalidRequest(_) => None,
        }
    }

    /// The response body as received, for an error response.
    pub fn body(&self) -> Option<&[u8]> {
        match self {
            Self::Response { body, .. } => Some(body),
            _ => None,
        }
    }

    /// The server's own message for an error response.
    pub fn server_message(&self) -> Option<String> {
        self.body().and_then(server_message)
    }

    /// True for a failure to reach the server, rather than an answer from it.
    pub fn is_communication(&self) -> bool {
        matches!(self, Self::Communication(_))
    }

    /// A failure from one of progenitor's helpers. Used by generated code.
    pub fn from_progenitor(e: ProgenitorError<()>) -> Self {
        e.into()
    }

    /// Read an error response. Used by generated code.
    pub async fn from_response(mut response: reqwest::Response) -> Self {
        let status = response.status();
        let mut body = Vec::new();
        while let Ok(Some(chunk)) = response.chunk().await {
            let room = MAX_ERROR_BODY - body.len();
            body.extend_from_slice(&chunk[..chunk.len().min(room)]);
            if body.len() == MAX_ERROR_BODY {
                break;
            }
        }
        Self::Response { status, body }
    }
}

/// Extract a person-readable message from an error body: the JSON `message` or
/// `error` field, or else the text of a body that isn't JSON or HTML. Control
/// characters are escaped, because a hostile server chooses these bytes and a
/// terminal displays them.
pub fn server_message(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
        let field = ["message", "error", "detail"]
            .iter()
            .find_map(|key| json.get(key)?.as_str());
        return Some(inert(
            field.map_or_else(|| text.to_string(), str::to_string),
        ));
    }
    if text.starts_with('<') {
        // A proxy's HTML error page. The status says more than its markup would.
        return None;
    }
    let shown: String = text.chars().take(MAX_DISPLAYED_TEXT).collect();
    Some(inert(shown))
}

fn inert(s: String) -> String {
    if !s.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return s;
    }
    s.chars()
        .flat_map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => write!(f, "invalid request: {reason}"),
            Self::Communication(e) => {
                write!(f, "{}", without_secrets(e))?;
                // reqwest's top-level message is "error sending request for url":
                // the cause is further down the chain.
                let mut source = std::error::Error::source(e);
                while let Some(cause) = source {
                    write!(f, ": {cause}")?;
                    source = cause.source();
                }
                Ok(())
            }
            Self::Response { status, .. } => match self.server_message() {
                Some(message) => write!(f, "{status}: {message}"),
                None => write!(f, "{status}"),
            },
            Self::InvalidPayload { status, reason } => match status {
                Some(status) => write!(f, "couldn't read the {status} response: {reason}"),
                None => write!(f, "couldn't read the response: {reason}"),
            },
        }
    }
}

/// A reqwest error's text, with its URL cut down to where it went. Userinfo and a
/// query can hold secrets, and the text ends up on a terminal and in CI logs.
fn without_secrets(e: &reqwest::Error) -> String {
    let text = e.to_string();
    let Some(url) = e.url() else {
        return text;
    };
    let mut shown = url.clone();
    let _ = shown.set_username("");
    let _ = shown.set_password(None);
    shown.set_query(None);
    text.replace(url.as_str(), shown.as_str())
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Communication(e) => Some(e),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Self::Communication(e)
    }
}

impl From<reqwest::header::InvalidHeaderValue> for Error {
    fn from(e: reqwest::header::InvalidHeaderValue) -> Self {
        Self::InvalidRequest(e.to_string())
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(e: std::convert::Infallible) -> Self {
        match e {}
    }
}

/// Failures from progenitor's own helpers: request hooks and response parsing.
impl<E> From<ProgenitorError<E>> for Error {
    fn from(e: ProgenitorError<E>) -> Self {
        match e {
            ProgenitorError::InvalidRequest(reason) => Self::InvalidRequest(reason),
            ProgenitorError::CommunicationError(e)
            | ProgenitorError::InvalidUpgrade(e)
            | ProgenitorError::ResponseBodyError(e) => Self::Communication(e),
            ProgenitorError::InvalidResponsePayload(_, e) => Self::InvalidPayload {
                status: None,
                // The bytes stay out of this: they could be anything, of any size.
                reason: e.to_string(),
            },
            ProgenitorError::ErrorResponse(r) => Self::Response {
                status: r.status(),
                body: Vec::new(),
            },
            ProgenitorError::UnexpectedResponse(r) => Self::Response {
                status: r.status(),
                body: Vec::new(),
            },
            ProgenitorError::Custom(reason) => Self::InvalidRequest(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, body: &str) -> Error {
        Error::Response {
            status: StatusCode::from_u16(status).unwrap(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn json_message_is_shown_with_the_status() {
        let e = response(
            409,
            r#"{"code":"CONFLICT","message":"Artifact is immutable"}"#,
        );
        assert_eq!(e.to_string(), "409 Conflict: Artifact is immutable");
    }

    #[test]
    fn json_error_field_is_used_when_there_is_no_message() {
        let e = response(403, r#"{"error":"Forbidden by policy"}"#);
        assert_eq!(e.to_string(), "403 Forbidden: Forbidden by policy");
    }

    #[test]
    fn json_without_a_known_field_is_shown_whole() {
        let e = response(400, r#"{"reasons":["a"]}"#);
        assert_eq!(e.to_string(), r#"400 Bad Request: {"reasons":["a"]}"#);
    }

    #[test]
    fn plain_text_is_shown_and_bounded() {
        assert_eq!(
            response(403, "Token does not have required scope: x").to_string(),
            "403 Forbidden: Token does not have required scope: x"
        );
        let long = "x".repeat(MAX_DISPLAYED_TEXT * 2);
        assert!(response(500, &long).to_string().len() < MAX_DISPLAYED_TEXT + 40);
    }

    #[test]
    fn html_and_empty_bodies_give_just_the_status() {
        assert_eq!(
            response(502, "<html><body>Bad Gateway</body></html>").to_string(),
            "502 Bad Gateway"
        );
        assert_eq!(response(404, "").to_string(), "404 Not Found");
    }

    #[test]
    fn control_characters_from_the_server_are_made_inert() {
        let shown = response(400, "{\"message\":\"a\\u001b[2Jb\"}").to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        let shown = response(400, "plain\u{1b}[2Jtext").to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
    }

    #[test]
    fn status_and_body_are_available() {
        let e = response(404, "nope");
        assert_eq!(e.status(), Some(StatusCode::NOT_FOUND));
        assert_eq!(e.body(), Some(&b"nope"[..]));
        assert_eq!(e.server_message().as_deref(), Some("nope"));
    }
}
