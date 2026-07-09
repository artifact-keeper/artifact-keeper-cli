use artifact_keeper_sdk::ClientEmailSubscriptionsExt;
use clap::Subcommand;
use miette::Result;

use super::client::{client_for, resolve_base_url_and_auth};
use super::helpers::{confirm_action, emit_mutation, new_table, parse_uuid, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum EmailSubscriptionsCommand {
    /// List the email subscriptions configured on a repository
    List {
        /// Repository key
        repo: String,
    },

    /// Subscribe recipients to repository events
    Subscribe {
        /// Repository key
        repo: String,

        /// Recipient email addresses (comma-separated)
        #[arg(long, value_delimiter = ',')]
        recipients: Vec<String>,

        /// Event types to subscribe to (comma-separated, e.g.
        /// artifact.uploaded, scan.completed, vulnerability.detected)
        #[arg(long, value_delimiter = ',')]
        events: Vec<String>,

        /// Create the subscription in a disabled state
        #[arg(long)]
        disabled: bool,
    },

    /// Remove an email subscription by id
    Unsubscribe {
        /// Repository key
        repo: String,

        /// Subscription ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

impl EmailSubscriptionsCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { repo } => list_subscriptions(&repo, global).await,
            Self::Subscribe {
                repo,
                recipients,
                events,
                disabled,
            } => subscribe(&repo, recipients, events, disabled, global).await,
            Self::Unsubscribe { repo, id, yes } => unsubscribe(&repo, &id, yes, global).await,
        }
    }
}

fn subscription_json(
    s: &artifact_keeper_sdk::types::EmailSubscriptionResponse,
) -> serde_json::Value {
    serde_json::json!({
        "id": s.id.to_string(),
        "repository_id": s.repository_id.map(|u| u.to_string()),
        "enabled": s.enabled,
        "event_types": s.event_types,
        "recipients": s.recipients,
        "created_at": s.created_at.to_rfc3339(),
        "updated_at": s.updated_at.to_rfc3339(),
    })
}

async fn list_subscriptions(repo: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching email subscriptions...");

    let resp = client
        .list_subscriptions()
        .key(repo)
        .send()
        .await
        .map_err(|e| sdk_err("list email subscriptions", e))?;

    spinner.finish_and_clear();

    if resp.subscriptions.is_empty() {
        eprintln!("No email subscriptions on repository '{repo}'.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for s in &resp.subscriptions {
            println!("{}", s.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp.subscriptions.iter().map(subscription_json).collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "ENABLED", "EVENTS", "RECIPIENTS"]);

        for s in &resp.subscriptions {
            let id_short = short_id(&s.id);
            let enabled = if s.enabled { "yes" } else { "no" };
            let events = s.event_types.join(", ");
            let recipients = s.recipients.join(", ");
            table.add_row(vec![&id_short, enabled, &events, &recipients]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn subscribe(
    repo: &str,
    recipients: Vec<String>,
    events: Vec<String>,
    disabled: bool,
    global: &GlobalArgs,
) -> Result<()> {
    if recipients.is_empty() {
        return Err(AkError::ConfigError(
            "At least one --recipients address is required.".to_string(),
        )
        .into());
    }
    if events.is_empty() {
        return Err(
            AkError::ConfigError("At least one --events type is required.".to_string()).into(),
        );
    }

    // NOTE: the SDK's `create_subscription` only accepts an HTTP 201 response,
    // but the live backend returns 200 for this endpoint (spec drift). Build the
    // request directly so any 2xx is treated as success.
    let body = serde_json::json!({
        "event_types": events,
        "recipients": recipients,
        "enabled": !disabled,
    });

    let (base_url, auth_header) = resolve_base_url_and_auth(global)?;
    let spinner = output::spinner("Creating email subscription...");

    let http = super::client::raw_http_client()?;
    let resp = http
        .post(format!(
            "{}/api/v1/repositories/{repo}/email-subscriptions",
            base_url.trim_end_matches('/')
        ))
        .header(reqwest::header::AUTHORIZATION, auth_header)
        .json(&body)
        .send()
        .await
        .map_err(|e| sdk_err("create email subscription", e))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| sdk_err("create email subscription", e))?;

    spinner.finish_and_clear();

    if !status.is_success() {
        let msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| {
                v.get("message")
                    .and_then(|m| m.as_str())
                    .map(str::to_string)
            })
            .unwrap_or(text);
        return Err(AkError::ServerError(format!(
            "create email subscription failed (HTTP {}): {msg}",
            status.as_u16()
        ))
        .into());
    }

    let sub: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| sdk_err("parse email subscription response", e))?;
    let id = sub["id"].as_str().unwrap_or_default().to_string();
    let recipient_count = sub["recipients"].as_array().map(|a| a.len()).unwrap_or(0);
    let event_count = sub["event_types"].as_array().map(|a| a.len()).unwrap_or(0);

    emit_mutation(
        &sub,
        &id,
        &format!(
            "Subscribed {recipient_count} recipient(s) to {event_count} event(s) on '{repo}' (ID: {id})."
        ),
        global,
    );

    Ok(())
}

async fn unsubscribe(repo: &str, id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let sub_id = parse_uuid(id, "subscription")?;

    if !confirm_action(
        &format!("Remove email subscription {id} from '{repo}'?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Removing email subscription...");

    client
        .delete_subscription()
        .key(repo)
        .subscription_id(sub_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete email subscription", e))?;

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "repo_key": repo, "id": id, "status": "removed" }),
        id,
        &format!("Email subscription {id} removed from '{repo}'."),
        global,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: EmailSubscriptionsCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- parsing: list ----

    #[test]
    fn parse_list() {
        let cli = parse(&["test", "list", "npm-local"]);
        match cli.command {
            EmailSubscriptionsCommand::List { repo } => assert_eq!(repo, "npm-local"),
            _ => panic!("expected List"),
        }
    }

    #[test]
    fn parse_list_missing_repo() {
        assert!(try_parse(&["test", "list"]).is_err());
    }

    // ---- parsing: subscribe ----

    #[test]
    fn parse_subscribe() {
        let cli = parse(&[
            "test",
            "subscribe",
            "npm-local",
            "--recipients",
            "ops@example.com,dev@example.com",
            "--events",
            "artifact.uploaded,scan.completed",
        ]);
        match cli.command {
            EmailSubscriptionsCommand::Subscribe {
                repo,
                recipients,
                events,
                disabled,
            } => {
                assert_eq!(repo, "npm-local");
                assert_eq!(recipients, vec!["ops@example.com", "dev@example.com"]);
                assert_eq!(events, vec!["artifact.uploaded", "scan.completed"]);
                assert!(!disabled);
            }
            _ => panic!("expected Subscribe"),
        }
    }

    #[test]
    fn parse_subscribe_disabled() {
        let cli = parse(&[
            "test",
            "subscribe",
            "npm-local",
            "--recipients",
            "ops@example.com",
            "--events",
            "scan.failed",
            "--disabled",
        ]);
        match cli.command {
            EmailSubscriptionsCommand::Subscribe { disabled, .. } => assert!(disabled),
            _ => panic!("expected Subscribe"),
        }
    }

    #[test]
    fn parse_subscribe_missing_repo() {
        assert!(try_parse(&["test", "subscribe", "--recipients", "a@b.com"]).is_err());
    }

    // ---- parsing: unsubscribe ----

    #[test]
    fn parse_unsubscribe() {
        let cli = parse(&[
            "test",
            "unsubscribe",
            "npm-local",
            "00000000-0000-0000-0000-000000000001",
            "--yes",
        ]);
        match cli.command {
            EmailSubscriptionsCommand::Unsubscribe { repo, id, yes } => {
                assert_eq!(repo, "npm-local");
                assert_eq!(id, "00000000-0000-0000-0000-000000000001");
                assert!(yes);
            }
            _ => panic!("expected Unsubscribe"),
        }
    }

    #[test]
    fn parse_unsubscribe_missing_id() {
        assert!(try_parse(&["test", "unsubscribe", "npm-local"]).is_err());
    }

    // ---- format function ----

    #[test]
    fn subscription_json_fields() {
        let s = artifact_keeper_sdk::types::EmailSubscriptionResponse {
            id: uuid::Uuid::nil(),
            repository_id: Some(uuid::Uuid::nil()),
            enabled: true,
            event_types: vec!["artifact.uploaded".to_string()],
            recipients: vec!["ops@example.com".to_string()],
            created_at: "2026-01-15T12:00:00Z".parse().unwrap(),
            updated_at: "2026-01-15T12:00:00Z".parse().unwrap(),
        };
        let v = subscription_json(&s);
        assert_eq!(v["enabled"], json!(true));
        assert_eq!(v["recipients"][0], json!("ops@example.com"));
        assert_eq!(v["event_types"][0], json!("artifact.uploaded"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn subscription_body() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "repository_id": NIL_UUID,
            "recipients": ["ops@example.com"],
            "event_types": ["artifact.uploaded"],
            "enabled": true,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    #[tokio::test]
    async fn handler_list_subscriptions_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories/npm-local/email-subscriptions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "subscriptions": [] })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_subscriptions("npm-local", &global).await;
        assert!(result.is_ok(), "list failed: {:?}", result.err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_subscriptions_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories/npm-local/email-subscriptions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "subscriptions": [subscription_body()] })),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Table);
        let result = list_subscriptions("npm-local", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_subscriptions_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/repositories/npm-local/email-subscriptions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "subscriptions": [subscription_body()] })),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_subscriptions("npm-local", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_subscribe() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        // The live backend returns 200 (not the spec's 201); the raw-request
        // path must accept any 2xx.
        Mock::given(method("POST"))
            .and(path("/api/v1/repositories/npm-local/email-subscriptions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(subscription_body()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = subscribe(
            "npm-local",
            vec!["ops@example.com".to_string()],
            vec!["artifact.uploaded".to_string()],
            false,
            &global,
        )
        .await;
        assert!(result.is_ok(), "subscribe failed: {:?}", result.err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_subscribe_no_recipients() {
        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = subscribe(
            "npm-local",
            vec![],
            vec!["artifact.uploaded".to_string()],
            false,
            &global,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handler_subscribe_no_events() {
        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = subscribe(
            "npm-local",
            vec!["ops@example.com".to_string()],
            vec![],
            false,
            &global,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handler_unsubscribe() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/repositories/npm-local/email-subscriptions/{NIL_UUID}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = unsubscribe("npm-local", NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_unsubscribe_invalid_id() {
        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = unsubscribe("npm-local", "not-a-uuid", true, &global).await;
        assert!(result.is_err());
    }
}
