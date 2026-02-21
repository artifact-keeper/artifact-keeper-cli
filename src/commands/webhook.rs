use artifact_keeper_sdk::ClientWebhooksExt;
use artifact_keeper_sdk::types::{
    CreateWebhookRequest, DeliveryResponse, TestWebhookResponse, WebhookResponse,
};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{
    confirm_action, new_table, parse_optional_uuid, parse_uuid, sdk_err, short_id,
};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum WebhookCommand {
    /// List webhooks
    List {
        /// Filter by repository ID
        #[arg(long)]
        repo: Option<String>,

        /// Filter by enabled status
        #[arg(long)]
        enabled: Option<bool>,
    },

    /// Show webhook details
    Show {
        /// Webhook ID
        id: String,
    },

    /// Create a new webhook
    Create {
        /// Webhook name
        name: String,

        /// Endpoint URL to receive events
        #[arg(long)]
        url: String,

        /// Events to subscribe to (comma-separated)
        #[arg(long, value_delimiter = ',', required = true)]
        events: Vec<String>,

        /// Webhook signing secret
        #[arg(long)]
        secret: Option<String>,

        /// Scope webhook to a specific repository
        #[arg(long)]
        repo: Option<String>,
    },

    /// Delete a webhook
    Delete {
        /// Webhook ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Send a test event to a webhook
    Test {
        /// Webhook ID
        id: String,
    },

    /// Enable a webhook
    Enable {
        /// Webhook ID
        id: String,
    },

    /// Disable a webhook
    Disable {
        /// Webhook ID
        id: String,
    },

    /// List deliveries for a webhook
    Deliveries {
        /// Webhook ID
        id: String,

        /// Filter by delivery status
        #[arg(long)]
        status: Option<String>,
    },

    /// Redeliver a failed webhook delivery
    Redeliver {
        /// Webhook ID
        id: String,

        /// Delivery ID to redeliver
        delivery_id: String,
    },
}

impl WebhookCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { repo, enabled } => list_webhooks(repo.as_deref(), enabled, global).await,
            Self::Show { id } => show_webhook(&id, global).await,
            Self::Create {
                name,
                url,
                events,
                secret,
                repo,
            } => {
                create_webhook(
                    &name,
                    &url,
                    &events,
                    secret.as_deref(),
                    repo.as_deref(),
                    global,
                )
                .await
            }
            Self::Delete { id, yes } => delete_webhook(&id, yes, global).await,
            Self::Test { id } => test_webhook(&id, global).await,
            Self::Enable { id } => enable_webhook(&id, global).await,
            Self::Disable { id } => disable_webhook(&id, global).await,
            Self::Deliveries { id, status } => {
                list_deliveries(&id, status.as_deref(), global).await
            }
            Self::Redeliver { id, delivery_id } => {
                redeliver_webhook(&id, &delivery_id, global).await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

async fn list_webhooks(
    repo: Option<&str>,
    enabled: Option<bool>,
    global: &GlobalArgs,
) -> Result<()> {
    let repo_id = parse_optional_uuid(repo, "repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching webhooks...");

    let mut req = client.list_webhooks();
    if let Some(id) = repo_id {
        req = req.repository_id(id);
    }
    if let Some(e) = enabled {
        req = req.enabled(e);
    }

    let resp = req.send().await.map_err(|e| sdk_err("list webhooks", e))?;
    let list = resp.into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() {
        eprintln!("No webhooks found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for w in &list.items {
            println!("{}", w.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_webhooks_table(&list.items);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_webhook(id: &str, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching webhook...");

    let webhook = client
        .get_webhook()
        .id(webhook_id)
        .send()
        .await
        .map_err(|e| sdk_err("get webhook", e))?;

    spinner.finish_and_clear();

    let (info, table_str) = format_webhook_detail(&webhook);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn create_webhook(
    name: &str,
    url: &str,
    events: &[String],
    secret: Option<&str>,
    repo: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let repo_id = parse_optional_uuid(repo, "repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Creating webhook...");

    let body = CreateWebhookRequest {
        name: name.to_string(),
        url: url.to_string(),
        events: events.to_vec(),
        secret: secret.map(|s| s.to_string()),
        repository_id: repo_id,
        headers: None,
    };

    let webhook = client
        .create_webhook()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create webhook", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", webhook.id);
        return Ok(());
    }

    eprintln!("Webhook '{}' created (ID: {}).", webhook.name, webhook.id);

    Ok(())
}

async fn delete_webhook(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;

    if !confirm_action(
        &format!("Delete webhook {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting webhook...");

    client
        .delete_webhook()
        .id(webhook_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete webhook", e))?;

    spinner.finish_and_clear();
    eprintln!("Webhook {id} deleted.");

    Ok(())
}

async fn test_webhook(id: &str, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Sending test event...");

    let result = client
        .test_webhook()
        .id(webhook_id)
        .send()
        .await
        .map_err(|e| sdk_err("test webhook", e))?;

    let result = result.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", result.success);
        return Ok(());
    }

    let (info, table_str) = format_test_result(&result);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn enable_webhook(id: &str, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Enabling webhook...");

    client
        .enable_webhook()
        .id(webhook_id)
        .send()
        .await
        .map_err(|e| sdk_err("enable webhook", e))?;

    spinner.finish_and_clear();
    eprintln!("Webhook {id} enabled.");

    Ok(())
}

async fn disable_webhook(id: &str, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Disabling webhook...");

    client
        .disable_webhook()
        .id(webhook_id)
        .send()
        .await
        .map_err(|e| sdk_err("disable webhook", e))?;

    spinner.finish_and_clear();
    eprintln!("Webhook {id} disabled.");

    Ok(())
}

async fn list_deliveries(id: &str, status: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching deliveries...");

    let mut req = client.list_deliveries().id(webhook_id);
    if let Some(s) = status {
        req = req.status(s);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("list deliveries", e))?;

    let list = resp.into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() {
        eprintln!("No deliveries found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for d in &list.items {
            println!("{}", d.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_deliveries_table(&list.items);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn redeliver_webhook(id: &str, delivery_id: &str, global: &GlobalArgs) -> Result<()> {
    let webhook_id = parse_uuid(id, "webhook")?;
    let del_id = parse_uuid(delivery_id, "delivery")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Redelivering webhook...");

    let delivery = client
        .redeliver()
        .id(webhook_id)
        .delivery_id(del_id)
        .send()
        .await
        .map_err(|e| sdk_err("redeliver webhook", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", delivery.id);
        return Ok(());
    }

    eprintln!("Delivery {} redelivered.", delivery.id);

    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_webhooks_table(webhooks: &[WebhookResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = webhooks
        .iter()
        .map(|w| {
            serde_json::json!({
                "id": w.id.to_string(),
                "name": w.name,
                "url": w.url,
                "is_enabled": w.is_enabled,
                "events": w.events,
                "last_triggered_at": w.last_triggered_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID",
            "NAME",
            "URL",
            "ENABLED",
            "EVENTS",
            "LAST TRIGGERED",
        ]);

        for w in webhooks {
            let id_short = short_id(&w.id);
            let enabled = if w.is_enabled { "yes" } else { "no" };
            let events = w.events.join(", ");
            let last_triggered = w
                .last_triggered_at
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                &id_short,
                &w.name,
                &w.url,
                enabled,
                &events,
                &last_triggered,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_webhook_detail(webhook: &WebhookResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": webhook.id.to_string(),
        "name": webhook.name,
        "url": webhook.url,
        "events": webhook.events,
        "is_enabled": webhook.is_enabled,
        "repository_id": webhook.repository_id.map(|id| id.to_string()),
        "headers": webhook.headers,
        "last_triggered_at": webhook.last_triggered_at.map(|t| t.to_rfc3339()),
        "created_at": webhook.created_at.to_rfc3339(),
    });

    let events = webhook.events.join(", ");
    let repo_id = webhook
        .repository_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "-".to_string());
    let headers = webhook
        .headers
        .as_ref()
        .map(|h| serde_json::to_string(h).unwrap_or_default())
        .unwrap_or_else(|| "-".to_string());
    let headers_display = if headers == "{}" { "-" } else { &headers };

    let table_str = format!(
        "ID:             {}\n\
         Name:           {}\n\
         URL:            {}\n\
         Events:         {}\n\
         Enabled:        {}\n\
         Repository:     {}\n\
         Headers:        {}\n\
         Last Triggered: {}\n\
         Created:        {}",
        webhook.id,
        webhook.name,
        webhook.url,
        events,
        if webhook.is_enabled { "yes" } else { "no" },
        repo_id,
        headers_display,
        webhook
            .last_triggered_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string()),
        webhook.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    (info, table_str)
}

fn format_test_result(result: &TestWebhookResponse) -> (Value, String) {
    let info = serde_json::json!({
        "success": result.success,
        "status_code": result.status_code,
        "response_body": result.response_body,
        "error": result.error,
    });

    let status = result
        .status_code
        .map(|c| c.to_string())
        .unwrap_or_else(|| "-".to_string());
    let body = result.response_body.as_deref().unwrap_or("-");
    let error = result.error.as_deref().unwrap_or("-");

    let table_str = format!(
        "Success:       {}\n\
         Status Code:   {}\n\
         Response Body: {}\n\
         Error:         {}",
        result.success, status, body, error,
    );

    (info, table_str)
}

fn format_deliveries_table(deliveries: &[DeliveryResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = deliveries
        .iter()
        .map(|d| {
            serde_json::json!({
                "id": d.id.to_string(),
                "event": d.event,
                "success": d.success,
                "attempts": d.attempts,
                "response_status": d.response_status,
                "created_at": d.created_at.to_rfc3339(),
                "delivered_at": d.delivered_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID",
            "EVENT",
            "SUCCESS",
            "ATTEMPTS",
            "STATUS",
            "CREATED",
            "DELIVERED",
        ]);

        for d in deliveries {
            let id_short = short_id(&d.id);
            let success = if d.success { "yes" } else { "no" };
            let attempts = d.attempts.to_string();
            let status = d
                .response_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string());
            let created = d.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string();
            let delivered = d
                .delivered_at
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "-".to_string());
            table.add_row(vec![
                &id_short, &d.event, success, &attempts, &status, &created, &delivered,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: WebhookCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> std::result::Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- Parsing tests ----

    #[test]
    fn parse_list_no_args() {
        let cli = parse(&["test", "list"]);
        if let WebhookCommand::List { repo, enabled } = cli.command {
            assert!(repo.is_none());
            assert!(enabled.is_none());
        } else {
            panic!("Expected List");
        }
    }

    #[test]
    fn parse_list_with_repo() {
        let cli = parse(&[
            "test",
            "list",
            "--repo",
            "00000000-0000-0000-0000-000000000001",
        ]);
        if let WebhookCommand::List { repo, enabled } = cli.command {
            assert_eq!(repo.unwrap(), "00000000-0000-0000-0000-000000000001");
            assert!(enabled.is_none());
        } else {
            panic!("Expected List with --repo");
        }
    }

    #[test]
    fn parse_list_with_enabled() {
        let cli = parse(&["test", "list", "--enabled", "true"]);
        if let WebhookCommand::List { repo, enabled } = cli.command {
            assert!(repo.is_none());
            assert_eq!(enabled.unwrap(), true);
        } else {
            panic!("Expected List with --enabled");
        }
    }

    #[test]
    fn parse_list_with_both_filters() {
        let cli = parse(&[
            "test",
            "list",
            "--repo",
            "00000000-0000-0000-0000-000000000001",
            "--enabled",
            "false",
        ]);
        if let WebhookCommand::List { repo, enabled } = cli.command {
            assert!(repo.is_some());
            assert_eq!(enabled.unwrap(), false);
        } else {
            panic!("Expected List with both filters");
        }
    }

    #[test]
    fn parse_show() {
        let cli = parse(&["test", "show", "webhook-id"]);
        if let WebhookCommand::Show { id } = cli.command {
            assert_eq!(id, "webhook-id");
        } else {
            panic!("Expected Show");
        }
    }

    #[test]
    fn parse_show_missing_id() {
        let result = try_parse(&["test", "show"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_create_minimal() {
        let cli = parse(&[
            "test",
            "create",
            "deploy-hook",
            "--url",
            "https://ci.example.com/hook",
            "--events",
            "artifact.pushed",
        ]);
        if let WebhookCommand::Create {
            name,
            url,
            events,
            secret,
            repo,
        } = cli.command
        {
            assert_eq!(name, "deploy-hook");
            assert_eq!(url, "https://ci.example.com/hook");
            assert_eq!(events, vec!["artifact.pushed"]);
            assert!(secret.is_none());
            assert!(repo.is_none());
        } else {
            panic!("Expected Create");
        }
    }

    #[test]
    fn parse_create_with_multiple_events() {
        let cli = parse(&[
            "test",
            "create",
            "my-hook",
            "--url",
            "https://example.com",
            "--events",
            "artifact.pushed,artifact.promoted,artifact.deleted",
        ]);
        if let WebhookCommand::Create { events, .. } = cli.command {
            assert_eq!(events.len(), 3);
            assert_eq!(events[0], "artifact.pushed");
            assert_eq!(events[1], "artifact.promoted");
            assert_eq!(events[2], "artifact.deleted");
        } else {
            panic!("Expected Create with multiple events");
        }
    }

    #[test]
    fn parse_create_full() {
        let cli = parse(&[
            "test",
            "create",
            "deploy-hook",
            "--url",
            "https://ci.example.com/hook",
            "--events",
            "artifact.pushed,artifact.promoted",
            "--secret",
            "my-secret",
            "--repo",
            "00000000-0000-0000-0000-000000000001",
        ]);
        if let WebhookCommand::Create {
            name,
            url,
            events,
            secret,
            repo,
        } = cli.command
        {
            assert_eq!(name, "deploy-hook");
            assert_eq!(url, "https://ci.example.com/hook");
            assert_eq!(events.len(), 2);
            assert_eq!(secret.unwrap(), "my-secret");
            assert!(repo.is_some());
        } else {
            panic!("Expected Create with full args");
        }
    }

    #[test]
    fn parse_create_missing_url() {
        let result = try_parse(&["test", "create", "my-hook", "--events", "push"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_create_missing_events() {
        let result = try_parse(&["test", "create", "my-hook", "--url", "https://example.com"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_create_missing_name() {
        let result = try_parse(&[
            "test",
            "create",
            "--url",
            "https://example.com",
            "--events",
            "push",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_delete() {
        let cli = parse(&["test", "delete", "webhook-id"]);
        if let WebhookCommand::Delete { id, yes } = cli.command {
            assert_eq!(id, "webhook-id");
            assert!(!yes);
        } else {
            panic!("Expected Delete");
        }
    }

    #[test]
    fn parse_delete_with_yes() {
        let cli = parse(&["test", "delete", "webhook-id", "--yes"]);
        if let WebhookCommand::Delete { id, yes } = cli.command {
            assert_eq!(id, "webhook-id");
            assert!(yes);
        } else {
            panic!("Expected Delete with --yes");
        }
    }

    #[test]
    fn parse_delete_missing_id() {
        let result = try_parse(&["test", "delete"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_test() {
        let cli = parse(&["test", "test", "webhook-id"]);
        if let WebhookCommand::Test { id } = cli.command {
            assert_eq!(id, "webhook-id");
        } else {
            panic!("Expected Test");
        }
    }

    #[test]
    fn parse_test_missing_id() {
        let result = try_parse(&["test", "test"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_enable() {
        let cli = parse(&["test", "enable", "webhook-id"]);
        if let WebhookCommand::Enable { id } = cli.command {
            assert_eq!(id, "webhook-id");
        } else {
            panic!("Expected Enable");
        }
    }

    #[test]
    fn parse_enable_missing_id() {
        let result = try_parse(&["test", "enable"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_disable() {
        let cli = parse(&["test", "disable", "webhook-id"]);
        if let WebhookCommand::Disable { id } = cli.command {
            assert_eq!(id, "webhook-id");
        } else {
            panic!("Expected Disable");
        }
    }

    #[test]
    fn parse_disable_missing_id() {
        let result = try_parse(&["test", "disable"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_deliveries() {
        let cli = parse(&["test", "deliveries", "webhook-id"]);
        if let WebhookCommand::Deliveries { id, status } = cli.command {
            assert_eq!(id, "webhook-id");
            assert!(status.is_none());
        } else {
            panic!("Expected Deliveries");
        }
    }

    #[test]
    fn parse_deliveries_with_status() {
        let cli = parse(&["test", "deliveries", "webhook-id", "--status", "failed"]);
        if let WebhookCommand::Deliveries { id, status } = cli.command {
            assert_eq!(id, "webhook-id");
            assert_eq!(status.unwrap(), "failed");
        } else {
            panic!("Expected Deliveries with --status");
        }
    }

    #[test]
    fn parse_deliveries_missing_id() {
        let result = try_parse(&["test", "deliveries"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_redeliver() {
        let cli = parse(&["test", "redeliver", "webhook-id", "delivery-id"]);
        if let WebhookCommand::Redeliver { id, delivery_id } = cli.command {
            assert_eq!(id, "webhook-id");
            assert_eq!(delivery_id, "delivery-id");
        } else {
            panic!("Expected Redeliver");
        }
    }

    #[test]
    fn parse_redeliver_missing_delivery_id() {
        let result = try_parse(&["test", "redeliver", "webhook-id"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_redeliver_missing_both_ids() {
        let result = try_parse(&["test", "redeliver"]);
        assert!(result.is_err());
    }

    // ---- Format function tests ----

    use chrono::Utc;
    use uuid::Uuid;

    fn make_test_webhook(name: &str, enabled: bool) -> WebhookResponse {
        WebhookResponse {
            id: Uuid::nil(),
            name: name.to_string(),
            url: "https://ci.example.com/hook".to_string(),
            events: vec![
                "artifact.pushed".to_string(),
                "artifact.promoted".to_string(),
            ],
            is_enabled: enabled,
            repository_id: None,
            headers: None,
            last_triggered_at: None,
            created_at: Utc::now(),
        }
    }

    fn make_test_delivery(success: bool, status_code: Option<i32>) -> DeliveryResponse {
        DeliveryResponse {
            id: Uuid::from_u128(1),
            webhook_id: Uuid::nil(),
            event: "artifact.pushed".to_string(),
            success,
            attempts: 1,
            response_status: status_code,
            response_body: Some("OK".to_string()),
            payload: serde_json::Map::new(),
            created_at: Utc::now(),
            delivered_at: if success { Some(Utc::now()) } else { None },
        }
    }

    fn make_test_result(success: bool) -> TestWebhookResponse {
        TestWebhookResponse {
            success,
            status_code: if success { Some(200) } else { None },
            response_body: if success {
                Some("OK".to_string())
            } else {
                None
            },
            error: if success {
                None
            } else {
                Some("Connection refused".to_string())
            },
        }
    }

    // ---- format_webhooks_table ----

    #[test]
    fn format_webhooks_table_single() {
        let webhooks = vec![make_test_webhook("deploy-hook", true)];
        let (entries, table_str) = format_webhooks_table(&webhooks);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "deploy-hook");
        assert_eq!(entries[0]["is_enabled"], true);

        assert!(table_str.contains("NAME"));
        assert!(table_str.contains("URL"));
        assert!(table_str.contains("ENABLED"));
        assert!(table_str.contains("deploy-hook"));
        assert!(table_str.contains("yes"));
    }

    #[test]
    fn format_webhooks_table_multiple() {
        let webhooks = vec![
            make_test_webhook("hook-a", true),
            make_test_webhook("hook-b", false),
        ];
        let (entries, table_str) = format_webhooks_table(&webhooks);

        assert_eq!(entries.len(), 2);
        assert!(table_str.contains("hook-a"));
        assert!(table_str.contains("hook-b"));
        assert!(table_str.contains("yes"));
        assert!(table_str.contains("no"));
    }

    #[test]
    fn format_webhooks_table_empty() {
        let (entries, table_str) = format_webhooks_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("NAME"));
    }

    #[test]
    fn format_webhooks_table_disabled() {
        let webhooks = vec![make_test_webhook("disabled-hook", false)];
        let (entries, table_str) = format_webhooks_table(&webhooks);

        assert_eq!(entries[0]["is_enabled"], false);
        assert!(table_str.contains("no"));
    }

    #[test]
    fn format_webhooks_table_with_last_triggered() {
        let mut webhook = make_test_webhook("recent", true);
        webhook.last_triggered_at = Some(Utc::now());
        let (entries, table_str) = format_webhooks_table(&[webhook]);

        assert!(entries[0]["last_triggered_at"].is_string());
        assert!(table_str.contains("UTC"));
    }

    #[test]
    fn format_webhooks_table_no_last_triggered() {
        let webhooks = vec![make_test_webhook("never-triggered", true)];
        let (_, table_str) = format_webhooks_table(&webhooks);
        // last_triggered_at is None, should show "-"
        assert!(table_str.contains("-"));
    }

    // ---- format_webhook_detail ----

    #[test]
    fn format_webhook_detail_full() {
        let webhook = make_test_webhook("detail-hook", true);
        let (info, table_str) = format_webhook_detail(&webhook);

        assert_eq!(info["name"], "detail-hook");
        assert_eq!(info["is_enabled"], true);
        assert!(info["url"].as_str().unwrap().contains("ci.example.com"));

        assert!(table_str.contains("detail-hook"));
        assert!(table_str.contains("yes"));
        assert!(table_str.contains("ci.example.com"));
        assert!(table_str.contains("artifact.pushed, artifact.promoted"));
    }

    #[test]
    fn format_webhook_detail_disabled() {
        let webhook = make_test_webhook("disabled", false);
        let (info, table_str) = format_webhook_detail(&webhook);

        assert_eq!(info["is_enabled"], false);
        assert!(table_str.contains("no"));
    }

    #[test]
    fn format_webhook_detail_with_repo() {
        let mut webhook = make_test_webhook("scoped", true);
        webhook.repository_id = Some(Uuid::nil());
        let (info, table_str) = format_webhook_detail(&webhook);

        assert!(info["repository_id"].is_string());
        assert!(table_str.contains("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn format_webhook_detail_no_repo() {
        let webhook = make_test_webhook("global", true);
        let (info, table_str) = format_webhook_detail(&webhook);

        assert!(info["repository_id"].is_null());
        assert!(table_str.contains("Repository:     -"));
    }

    #[test]
    fn format_webhook_detail_no_last_triggered() {
        let webhook = make_test_webhook("new-hook", true);
        let (info, table_str) = format_webhook_detail(&webhook);

        assert!(info["last_triggered_at"].is_null());
        assert!(table_str.contains("Last Triggered: -"));
    }

    // ---- format_test_result ----

    #[test]
    fn format_test_result_success() {
        let result = make_test_result(true);
        let (info, table_str) = format_test_result(&result);

        assert_eq!(info["success"], true);
        assert_eq!(info["status_code"], 200);
        assert_eq!(info["response_body"], "OK");

        assert!(table_str.contains("true"));
        assert!(table_str.contains("200"));
        assert!(table_str.contains("OK"));
    }

    #[test]
    fn format_test_result_failure() {
        let result = make_test_result(false);
        let (info, table_str) = format_test_result(&result);

        assert_eq!(info["success"], false);
        assert!(info["status_code"].is_null());
        assert_eq!(info["error"], "Connection refused");

        assert!(table_str.contains("false"));
        assert!(table_str.contains("Connection refused"));
    }

    #[test]
    fn format_test_result_no_body() {
        let result = TestWebhookResponse {
            success: true,
            status_code: Some(204),
            response_body: None,
            error: None,
        };
        let (_, table_str) = format_test_result(&result);

        assert!(table_str.contains("204"));
        assert!(table_str.contains("Response Body: -"));
    }

    // ---- format_deliveries_table ----

    #[test]
    fn format_deliveries_table_single() {
        let deliveries = vec![make_test_delivery(true, Some(200))];
        let (entries, table_str) = format_deliveries_table(&deliveries);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["event"], "artifact.pushed");
        assert_eq!(entries[0]["success"], true);
        assert_eq!(entries[0]["attempts"], 1);
        assert_eq!(entries[0]["response_status"], 200);

        assert!(table_str.contains("EVENT"));
        assert!(table_str.contains("SUCCESS"));
        assert!(table_str.contains("ATTEMPTS"));
        assert!(table_str.contains("artifact.pushed"));
        assert!(table_str.contains("yes"));
    }

    #[test]
    fn format_deliveries_table_multiple() {
        let deliveries = vec![
            make_test_delivery(true, Some(200)),
            make_test_delivery(false, Some(500)),
        ];
        let (entries, table_str) = format_deliveries_table(&deliveries);

        assert_eq!(entries.len(), 2);
        assert!(table_str.contains("yes"));
        assert!(table_str.contains("no"));
        assert!(table_str.contains("200"));
        assert!(table_str.contains("500"));
    }

    #[test]
    fn format_deliveries_table_empty() {
        let (entries, table_str) = format_deliveries_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("EVENT"));
    }

    #[test]
    fn format_deliveries_table_no_status() {
        let deliveries = vec![make_test_delivery(false, None)];
        let (entries, table_str) = format_deliveries_table(&deliveries);

        assert!(entries[0]["response_status"].is_null());
        // Table should show "-" for missing status
        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_deliveries_table_delivered() {
        let deliveries = vec![make_test_delivery(true, Some(200))];
        let (_, table_str) = format_deliveries_table(&deliveries);

        // A successful delivery should have a delivered_at timestamp
        assert!(table_str.contains("UTC"));
    }

    #[test]
    fn format_deliveries_table_not_delivered() {
        let mut delivery = make_test_delivery(false, None);
        delivery.delivered_at = None;
        let (_, table_str) = format_deliveries_table(&[delivery]);

        // Should show "-" for delivered column
        assert!(table_str.contains("-"));
    }

    // ---- wiremock handler tests ----

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";
    static DELIVERY_UUID: &str = "00000000-0000-0000-0000-000000000001";

    fn webhook_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "deploy-hook",
            "url": "https://ci.example.com/hook",
            "events": ["artifact.pushed", "artifact.promoted"],
            "is_enabled": true,
            "repository_id": null,
            "headers": null,
            "last_triggered_at": null,
            "created_at": "2026-01-15T12:00:00Z"
        })
    }

    fn delivery_json() -> serde_json::Value {
        json!({
            "id": DELIVERY_UUID,
            "webhook_id": NIL_UUID,
            "event": "artifact.pushed",
            "success": true,
            "attempts": 1,
            "response_status": 200,
            "response_body": "OK",
            "payload": {"artifact_id": "abc"},
            "created_at": "2026-01-15T12:00:00Z",
            "delivered_at": "2026-01-15T12:00:01Z"
        })
    }

    fn test_result_json() -> serde_json::Value {
        json!({
            "success": true,
            "status_code": 200,
            "response_body": "OK",
            "error": null
        })
    }

    #[tokio::test]
    async fn handler_list_webhooks_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/webhooks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "total": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_webhooks(None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_webhooks_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/webhooks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [webhook_json()],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_webhooks(None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_webhooks_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/webhooks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [webhook_json()],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_webhooks(None, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_webhook() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/webhooks/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(webhook_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_webhook(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_webhook() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/webhooks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(webhook_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let events = vec!["artifact.pushed".to_string()];
        let result = create_webhook(
            "deploy-hook",
            "https://ci.example.com/hook",
            &events,
            Some("secret"),
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_webhook_verbose() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/webhooks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(webhook_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let events = vec![
            "artifact.pushed".to_string(),
            "artifact.promoted".to_string(),
        ];
        let result = create_webhook(
            "deploy-hook",
            "https://ci.example.com/hook",
            &events,
            None,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_webhook() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/webhooks/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = delete_webhook(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_test_webhook() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/webhooks/{NIL_UUID}/test")))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_result_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = test_webhook(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_test_webhook_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/webhooks/{NIL_UUID}/test")))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_result_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = test_webhook(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_enable_webhook() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/webhooks/{NIL_UUID}/enable")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = enable_webhook(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_disable_webhook() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/webhooks/{NIL_UUID}/disable")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = disable_webhook(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_deliveries_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/webhooks/{NIL_UUID}/deliveries")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "total": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_deliveries(NIL_UUID, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_deliveries_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/webhooks/{NIL_UUID}/deliveries")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [delivery_json()],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_deliveries(NIL_UUID, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_deliveries_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/webhooks/{NIL_UUID}/deliveries")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [delivery_json()],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_deliveries(NIL_UUID, None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_redeliver() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/webhooks/{NIL_UUID}/deliveries/{DELIVERY_UUID}/redeliver"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(delivery_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = redeliver_webhook(NIL_UUID, DELIVERY_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_redeliver_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/webhooks/{NIL_UUID}/deliveries/{DELIVERY_UUID}/redeliver"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(delivery_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = redeliver_webhook(NIL_UUID, DELIVERY_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }
}
