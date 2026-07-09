use artifact_keeper_sdk::ClientQuarantineExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{emit_mutation, parse_uuid, sdk_err};
use crate::cli::GlobalArgs;
use crate::output;

#[derive(Subcommand)]
pub enum QuarantineCommand {
    /// Show the quarantine status for an artifact
    Status {
        /// Artifact ID (UUID)
        artifact: String,
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
