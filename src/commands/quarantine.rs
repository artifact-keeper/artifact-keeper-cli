use artifact_keeper_sdk::ClientQuarantineExt;
use clap::Subcommand;
use miette::Result;

use super::client::{client_for, resolve_base_url_and_auth};
use super::helpers::{emit_mutation, parse_uuid, sdk_err};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output;

#[derive(Subcommand)]
pub enum QuarantineCommand {
    /// Show the quarantine status for an artifact
    Status {
        /// Artifact ID (UUID)
        artifact: String,
    },

    /// Quarantine an artifact immediately, blocking downloads (admin only)
    Hold {
        /// Artifact ID (UUID)
        artifact: String,

        /// Reason shown to developers whose downloads are blocked
        /// (defaults server-side when omitted)
        #[arg(long)]
        reason: Option<String>,
    },

    /// Release a quarantined artifact so it can be served (admin only)
    Release {
        /// Artifact ID (UUID)
        artifact: String,
    },

    /// Reject (purge) a quarantined artifact, blocking it permanently (admin only)
    #[command(visible_alias = "purge")]
    Reject {
        /// Artifact ID (UUID)
        artifact: String,

        /// Reason for the rejection
        #[arg(long)]
        reason: Option<String>,
    },
}

impl QuarantineCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Status { artifact } => status(&artifact, global).await,
            Self::Hold { artifact, reason } => hold(&artifact, reason.as_deref(), global).await,
            Self::Release { artifact } => release(&artifact, global).await,
            Self::Reject { artifact, reason } => reject(&artifact, reason.as_deref(), global).await,
        }
    }
}

async fn status(artifact: &str, global: &GlobalArgs) -> Result<()> {
    let artifact_id = parse_uuid(artifact, "artifact")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching quarantine status...");

    let status = client
        .get_quarantine_status()
        .artifact_id(artifact_id)
        .send()
        .await
        .map_err(|e| sdk_err("get quarantine status", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "artifact_id": status.artifact_id.to_string(),
        "is_blocked": status.is_blocked,
        "quarantine_status": status.quarantine_status,
        "quarantine_until": status.quarantine_until.map(|t| t.to_rfc3339()),
    });

    let table_str = format_status_detail(&info);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn hold(artifact: &str, reason: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let artifact_id = parse_uuid(artifact, "artifact")?;

    // The vendored SDK's `ClientQuarantineExt` predates this route and exposes
    // no quarantine-now operation, so call it over raw HTTP the way other
    // post-SDK endpoints do (see email_subscriptions.rs).
    let (base_url, auth_header) = resolve_base_url_and_auth(global)?;
    let spinner = output::spinner("Quarantining artifact...");

    let http = super::client::raw_http_client()?;
    let resp = http
        .post(format!(
            "{}/api/v1/quarantine/{artifact_id}/quarantine",
            base_url.trim_end_matches('/')
        ))
        .header(reqwest::header::AUTHORIZATION, auth_header)
        .json(&serde_json::json!({ "reason": reason }))
        .send()
        .await
        .map_err(|e| sdk_err("quarantine artifact", e))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| sdk_err("quarantine artifact", e))?;

    spinner.finish_and_clear();

    if !status.is_success() {
        return Err(hold_error(status, &text, artifact_id).into());
    }

    let action: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| sdk_err("parse quarantine response", e))?;

    let id = action["artifact_id"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| artifact_id.to_string());
    let new_status = action["new_status"].as_str().unwrap_or("quarantined");
    let message = action["message"].as_str().unwrap_or("Artifact quarantined");

    let human = format!("Quarantined artifact {id} (status: {new_status}). {message}");
    emit_mutation(&action, &id, &human, global);

    Ok(())
}

/// Map a failed hold response to an actionable message.
///
/// The raw-HTTP path exposes the status code, so unlike the SDK-backed
/// subcommands this can explain what to do about a 403/404/409 instead of
/// surfacing a bare transport error.
fn hold_error(status: reqwest::StatusCode, text: &str, artifact_id: uuid::Uuid) -> AkError {
    let server_msg = serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| {
            v.get("message")
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| text.to_string());

    let detail = match status.as_u16() {
        403 => "Quarantining an artifact requires admin access.".to_string(),
        404 => format!("No artifact with ID {artifact_id} exists on this instance."),
        409 => {
            "The artifact was rejected during security review, so it cannot be quarantined again."
                .to_string()
        }
        _ => server_msg,
    };

    AkError::ServerError(format!(
        "quarantine artifact failed (HTTP {}): {detail}",
        status.as_u16()
    ))
}

async fn release(artifact: &str, global: &GlobalArgs) -> Result<()> {
    let artifact_id = parse_uuid(artifact, "artifact")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Releasing artifact from quarantine...");

    let action = client
        .release_artifact()
        .artifact_id(artifact_id)
        .send()
        .await
        .map_err(|e| sdk_err("release artifact from quarantine", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "artifact_id": action.artifact_id.to_string(),
        "message": action.message,
        "new_status": action.new_status,
    });

    let human = format!(
        "Released artifact {} (status: {}). {}",
        action.artifact_id, action.new_status, action.message
    );
    emit_mutation(&info, &action.artifact_id.to_string(), &human, global);

    Ok(())
}

async fn reject(artifact: &str, reason: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let artifact_id = parse_uuid(artifact, "artifact")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Rejecting quarantined artifact...");

    let body = artifact_keeper_sdk::types::RejectRequest {
        reason: reason.map(|s| s.to_string()),
    };

    let action = client
        .reject_quarantined_artifact()
        .artifact_id(artifact_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("reject quarantined artifact", e))?;

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "artifact_id": action.artifact_id.to_string(),
        "message": action.message,
        "new_status": action.new_status,
    });

    let human = format!(
        "Rejected artifact {} (status: {}). {}",
        action.artifact_id, action.new_status, action.message
    );
    emit_mutation(&info, &action.artifact_id.to_string(), &human, global);

    Ok(())
}

fn format_status_detail(item: &serde_json::Value) -> String {
    format!(
        "Artifact:          {}\n\
         Blocked:           {}\n\
         Quarantine Status: {}\n\
         Quarantine Until:  {}",
        item["artifact_id"].as_str().unwrap_or("-"),
        if item["is_blocked"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        },
        item["quarantine_status"].as_str().unwrap_or("-"),
        item["quarantine_until"].as_str().unwrap_or("-"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::OutputFormat;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: QuarantineCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- parsing: status ----

    #[test]
    fn parse_status() {
        let cli = parse(&["test", "status", "00000000-0000-0000-0000-000000000001"]);
        match cli.command {
            QuarantineCommand::Status { artifact } => {
                assert_eq!(artifact, "00000000-0000-0000-0000-000000000001");
            }
            _ => panic!("expected Status"),
        }
    }

    #[test]
    fn parse_status_missing_artifact() {
        assert!(try_parse(&["test", "status"]).is_err());
    }

    // ---- parsing: release ----

    #[test]
    fn parse_release() {
        let cli = parse(&["test", "release", "some-id"]);
        match cli.command {
            QuarantineCommand::Release { artifact } => assert_eq!(artifact, "some-id"),
            _ => panic!("expected Release"),
        }
    }

    #[test]
    fn parse_release_missing_artifact() {
        assert!(try_parse(&["test", "release"]).is_err());
    }

    // ---- parsing: reject / purge ----

    #[test]
    fn parse_reject_no_reason() {
        let cli = parse(&["test", "reject", "some-id"]);
        match cli.command {
            QuarantineCommand::Reject { artifact, reason } => {
                assert_eq!(artifact, "some-id");
                assert!(reason.is_none());
            }
            _ => panic!("expected Reject"),
        }
    }

    #[test]
    fn parse_reject_with_reason() {
        let cli = parse(&["test", "reject", "some-id", "--reason", "Malware"]);
        match cli.command {
            QuarantineCommand::Reject { artifact, reason } => {
                assert_eq!(artifact, "some-id");
                assert_eq!(reason.as_deref(), Some("Malware"));
            }
            _ => panic!("expected Reject"),
        }
    }

    #[test]
    fn parse_purge_alias() {
        let cli = parse(&["test", "purge", "some-id", "--reason", "CVE"]);
        match cli.command {
            QuarantineCommand::Reject { artifact, reason } => {
                assert_eq!(artifact, "some-id");
                assert_eq!(reason.as_deref(), Some("CVE"));
            }
            _ => panic!("expected Reject (via purge alias)"),
        }
    }

    #[test]
    fn parse_reject_missing_artifact() {
        assert!(try_parse(&["test", "reject"]).is_err());
    }

    // ---- parsing: hold ----

    #[test]
    fn parse_hold_no_reason() {
        let cli = parse(&["test", "hold", "some-id"]);
        match cli.command {
            QuarantineCommand::Hold { artifact, reason } => {
                assert_eq!(artifact, "some-id");
                // The endpoint substitutes a default reason for an absent one,
                // so --reason stays optional (matching `reject`).
                assert!(reason.is_none());
            }
            _ => panic!("expected Hold"),
        }
    }

    #[test]
    fn parse_hold_with_reason() {
        let cli = parse(&["test", "hold", "some-id", "--reason", "Failed scan"]);
        match cli.command {
            QuarantineCommand::Hold { artifact, reason } => {
                assert_eq!(artifact, "some-id");
                assert_eq!(reason.as_deref(), Some("Failed scan"));
            }
            _ => panic!("expected Hold"),
        }
    }

    #[test]
    fn parse_hold_missing_artifact() {
        assert!(try_parse(&["test", "hold"]).is_err());
    }

    // ---- format functions ----

    #[test]
    fn format_status_detail_blocked() {
        let item = json!({
            "artifact_id": "00000000-0000-0000-0000-000000000001",
            "is_blocked": true,
            "quarantine_status": "quarantined",
            "quarantine_until": "2026-07-10T12:00:00+00:00",
        });
        let detail = format_status_detail(&item);
        assert!(detail.contains("00000000-0000-0000-0000-000000000001"));
        assert!(detail.contains("yes"));
        assert!(detail.contains("quarantined"));
    }

    #[test]
    fn format_status_detail_not_blocked() {
        let item = json!({
            "artifact_id": "00000000-0000-0000-0000-000000000002",
            "is_blocked": false,
            "quarantine_status": null,
            "quarantine_until": null,
        });
        let detail = format_status_detail(&item);
        assert!(detail.contains("no"));
        // Null optionals render as "-"
        assert!(detail.contains("Quarantine Status: -"));
        assert!(detail.contains("Quarantine Until:  -"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn status_json() -> serde_json::Value {
        json!({
            "artifact_id": NIL_UUID,
            "is_blocked": true,
            "quarantine_status": "quarantined",
            "quarantine_until": "2026-07-10T12:00:00Z"
        })
    }

    fn action_json(new_status: &str) -> serde_json::Value {
        json!({
            "artifact_id": NIL_UUID,
            "message": "ok",
            "new_status": new_status
        })
    }

    #[tokio::test]
    async fn handler_status() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/quarantine/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(status_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = status(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_status_invalid_uuid() {
        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = status("not-a-uuid", &global).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handler_release() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/quarantine/{NIL_UUID}/release")))
            .respond_with(ResponseTemplate::new(200).set_body_json(action_json("released")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = release(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_reject() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/quarantine/{NIL_UUID}/reject")))
            .respond_with(ResponseTemplate::new(200).set_body_json(action_json("rejected")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = reject(NIL_UUID, Some("Malware"), &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_reject_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/quarantine/{NIL_UUID}/reject")))
            .respond_with(ResponseTemplate::new(200).set_body_json(action_json("rejected")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = reject(NIL_UUID, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- wiremock handler tests: hold ----

    /// The hold route is `/{id}/quarantine`, not `/{id}` (renamed upstream);
    /// pinning the path here is the point of this test.
    #[tokio::test]
    async fn handler_hold() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/quarantine/{NIL_UUID}/quarantine")))
            .respond_with(ResponseTemplate::new(200).set_body_json(action_json("quarantined")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = hold(NIL_UUID, Some("Failed scan"), &global).await;
        assert!(result.is_ok(), "hold failed: {:?}", result.err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_hold_no_reason() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/quarantine/{NIL_UUID}/quarantine")))
            .respond_with(ResponseTemplate::new(200).set_body_json(action_json("quarantined")))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = hold(NIL_UUID, None, &global).await;
        assert!(result.is_ok(), "hold failed: {:?}", result.err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_hold_invalid_uuid() {
        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = hold("not-a-uuid", None, &global).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handler_hold_forbidden_mentions_admin() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/quarantine/{NIL_UUID}/quarantine")))
            .respond_with(
                ResponseTemplate::new(403).set_body_json(json!({"message": "admin required"})),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let err = hold(NIL_UUID, None, &global).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("403"), "should carry the status: {msg}");
        assert!(
            msg.to_lowercase().contains("admin"),
            "403 should explain the admin requirement: {msg}"
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_hold_not_found_mentions_artifact() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/quarantine/{NIL_UUID}/quarantine")))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "not found"})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let err = hold(NIL_UUID, None, &global).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("404"), "should carry the status: {msg}");
        assert!(
            msg.contains(NIL_UUID),
            "404 should name the artifact looked for: {msg}"
        );
        crate::test_utils::teardown_env();
    }

    /// 409 is unique to hold: the artifact was already rejected in review.
    #[tokio::test]
    async fn handler_hold_conflict_is_error() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/quarantine/{NIL_UUID}/quarantine")))
            .respond_with(
                ResponseTemplate::new(409).set_body_json(json!({"message": "already rejected"})),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let err = hold(NIL_UUID, None, &global).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("409"), "should carry the status: {msg}");
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_quarantine_status_json() {
        let output = crate::output::render(&status_json(), &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("quarantine_status_json", parsed);
    }

    #[test]
    fn snapshot_quarantine_status_table() {
        let info = json!({
            "artifact_id": NIL_UUID,
            "is_blocked": true,
            "quarantine_status": "quarantined",
            "quarantine_until": "2026-07-10T12:00:00+00:00",
        });
        let detail = format_status_detail(&info);
        insta::assert_snapshot!("quarantine_status_table", detail);
    }
}
