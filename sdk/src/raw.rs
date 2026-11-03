//! The response body exactly as the server sent it.
//!
//! Typed responses drop any field the SDK's schema doesn't have, and a server is
//! usually newer than the SDK. Wrap an operation in [`capture`] to get the bytes
//! along with the parsed value, for output that must not lose anything:
//!
//! ```ignore
//! let (result, raw) = capture(client.get_repository().key(key).send()).await;
//! let repo = result?;
//! ```

use std::cell::RefCell;
use std::future::Future;

use progenitor_client::ResponseValue;

use crate::error::Error;

tokio::task_local! {
    static CAPTURED: RefCell<Option<Vec<u8>>>;
}

/// Run an operation and return its result with the body of its success response,
/// if it had one. The capture belongs to this future alone, so operations running
/// concurrently don't see each other's bodies.
pub async fn capture<F: Future>(operation: F) -> (F::Output, Option<Vec<u8>>) {
    CAPTURED
        .scope(RefCell::new(None), async move {
            let output = operation.await;
            let raw = CAPTURED.with(|cell| cell.borrow_mut().take());
            (output, raw)
        })
        .await
}

/// Parse a success response, keeping the bytes if a [`capture`] is listening.
/// Used by generated code.
pub async fn parse_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<ResponseValue<T>, Error> {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.bytes().await?;
    let _ = CAPTURED.try_with(|cell| *cell.borrow_mut() = Some(bytes.to_vec()));
    let inner = serde_json::from_slice(&bytes).map_err(|e| Error::InvalidPayload {
        status: Some(status),
        reason: e.to_string(),
    })?;
    Ok(ResponseValue::new(inner, status, headers))
}
