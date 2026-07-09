use artifact_keeper_sdk::{ClientHealthExt, ClientMonitoringExt};
use clap::Subcommand;
use futures::StreamExt;
use miette::Result;

use super::client::client_for;
use super::helpers::{new_table, sdk_err};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum MonitoringCommand {
    /// Show the rich health status page (database, storage, optional services, DB pool)
    Health,

    /// Liveness probe — confirm the process is alive and can serve HTTP
    Live,

    /// Readiness probe — is the service ready to accept traffic?
    Ready,

    /// Dump the Prometheus metrics exposition (admin)
    Metrics,

    /// List current alert states for monitored services (admin)
    Alerts,

    /// Suppress alerting for a service until a given time (admin)
    Suppress {
        /// Service name to suppress (e.g. database, storage, trivy)
        service: String,

        /// Suppress until this RFC 3339 timestamp (e.g. 2026-07-10T00:00:00Z)
        #[arg(long)]
        until: String,
    },

    /// Manually trigger the health checks and return the results (admin)
    Check,

    /// Show the recorded service health-check log (admin)
    #[command(name = "health-log")]
    HealthLog {
        /// Maximum number of log entries to return
        #[arg(long)]
        limit: Option<i64>,

        /// Filter by service name
        #[arg(long)]
        service: Option<String>,
    },
}

impl MonitoringCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Health => health(global).await,
            Self::Live => live(global).await,
            Self::Ready => ready(global).await,
            Self::Metrics => metrics(global).await,
            Self::Alerts => alerts(global).await,
            Self::Suppress { service, until } => suppress(&service, &until, global).await,
            Self::Check => check(global).await,
            Self::HealthLog { limit, service } => {
                health_log(limit, service.as_deref(), global).await
            }
        }
    }
}

fn check_status_str(status: &str, message: Option<&str>) -> String {
    match message {
        Some(m) if !m.is_empty() => format!("{status} ({m})"),
        _ => status.to_string(),
    }
}

async fn health(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching health status...");

    let resp = client
        .health_check()
        .send()
        .await
        .map_err(|e| sdk_err("get health status", e))?;
    let h = resp.into_inner();

    spinner.finish_and_clear();

    let optional_check = |c: &Option<artifact_keeper_sdk::types::CheckStatus>| {
        c.as_ref()
            .map(|s| check_status_str(&s.status, s.message.as_deref()))
    };

    let info = serde_json::json!({
        "status": h.status,
        "version": h.version,
        "commit": h.commit,
        "dirty": h.dirty,
        "demo_mode": h.demo_mode,
        "database": check_status_str(&h.checks.database.status, h.checks.database.message.as_deref()),
        "storage": check_status_str(&h.checks.storage.status, h.checks.storage.message.as_deref()),
        "ldap": optional_check(&h.checks.ldap),
        "opensearch": optional_check(&h.checks.opensearch),
        "security_scanner": optional_check(&h.checks.security_scanner),
        "db_pool": h.db_pool.as_ref().map(|p| serde_json::json!({
            "size": p.size,
            "active": p.active_connections,
            "idle": p.idle_connections,
            "max": p.max_connections,
        })),
    });

    let table_str = format_health_detail(&info);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn live(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Checking liveness...");

    let resp = client
        .liveness_check()
        .send()
        .await
        .map_err(|e| sdk_err("get liveness", e))?;
    let l = resp.into_inner();

    spinner.finish_and_clear();

    let info = serde_json::json!({ "status": l.status });
    let table_str = format!("Status: {}", l.status);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn ready(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Checking readiness...");

    let resp = client
        .readiness_check()
        .send()
        .await
        .map_err(|e| sdk_err("get readiness", e))?;
    let r = resp.into_inner();

    spinner.finish_and_clear();

    let info = serde_json::json!({
        "status": r.status,
        "database": check_status_str(&r.checks.database.status, r.checks.database.message.as_deref()),
        "migrations": check_status_str(&r.checks.migrations.status, r.checks.migrations.message.as_deref()),
        "setup_complete": check_status_str(&r.checks.setup_complete.status, r.checks.setup_complete.message.as_deref()),
    });

    let table_str = format!(
        "Status:         {}\n\
         Database:       {}\n\
         Migrations:     {}\n\
         Setup Complete: {}",
        info["status"].as_str().unwrap_or("-"),
        info["database"].as_str().unwrap_or("-"),
        info["migrations"].as_str().unwrap_or("-"),
        info["setup_complete"].as_str().unwrap_or("-"),
    );
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn metrics(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching Prometheus metrics...");

    let resp = client
        .metrics()
        .send()
        .await
        .map_err(|e| sdk_err("get metrics", e))?;

    spinner.finish_and_clear();

    let mut stream = resp.into_inner();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| AkError::ServerError(format!("Metrics read error: {e}")))?;
        body.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&body).into_owned();

    // The metrics endpoint is a raw Prometheus exposition; JSON wraps it as a
    // single string field, everything else prints it verbatim.
    match global.format {
        OutputFormat::Json | OutputFormat::Yaml => {
            let info = serde_json::json!({ "metrics": text });
            println!("{}", output::render(&info, &global.format, None));
        }
        _ => print!("{text}"),
    }

    Ok(())
}

async fn alerts(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching alert states...");

    let resp = client
        .get_alert_states()
        .send()
        .await
        .map_err(|e| sdk_err("get alert states", e))?;
    let states = resp.into_inner();

    spinner.finish_and_clear();

    if states.is_empty() {
        eprintln!("No alert states found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for s in &states {
            println!("{}", s.service_name);
        }
        return Ok(());
    }

    let entries: Vec<_> = states
        .iter()
        .map(|s| {
            serde_json::json!({
                "service_name": s.service_name,
                "current_status": s.current_status,
                "consecutive_failures": s.consecutive_failures,
                "suppressed_until": s.suppressed_until.map(|t| t.to_rfc3339()),
                "last_alert_sent_at": s.last_alert_sent_at.map(|t| t.to_rfc3339()),
                "updated_at": s.updated_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "SERVICE",
            "STATUS",
            "FAILURES",
            "SUPPRESSED UNTIL",
            "UPDATED",
        ]);
        for s in &states {
            let failures = s.consecutive_failures.to_string();
            let suppressed = s
                .suppressed_until
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "-".to_string());
            let updated = s.updated_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![
                &s.service_name,
                &s.current_status,
                &failures,
                &suppressed,
                &updated,
            ]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn suppress(service: &str, until: &str, global: &GlobalArgs) -> Result<()> {
    let until_ts = chrono::DateTime::parse_from_rfc3339(until)
        .map_err(|e| AkError::ConfigError(format!("Invalid --until timestamp '{until}': {e}")))?
        .with_timezone(&chrono::Utc);

    let client = client_for(global)?;
    let spinner = output::spinner("Suppressing alert...");

    let body = artifact_keeper_sdk::types::SuppressRequest {
        service_name: service.to_string(),
        until: until_ts,
    };

    client
        .suppress_alert()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("suppress alert", e))?;

    spinner.finish_and_clear();
    eprintln!(
        "Alerting for '{}' suppressed until {}.",
        service,
        until_ts.to_rfc3339()
    );

    Ok(())
}

async fn check(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Running health checks...");

    let resp = client
        .run_health_check()
        .send()
        .await
        .map_err(|e| sdk_err("run health check", e))?;
    let entries = resp.into_inner();

    spinner.finish_and_clear();
    render_health_entries(&entries, global);
    Ok(())
}

async fn health_log(limit: Option<i64>, service: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching health log...");

    let mut req = client.get_health_log();
    if let Some(l) = limit {
        req = req.limit(l);
    }
    if let Some(s) = service {
        req = req.service(s);
    }

    let resp = req.send().await.map_err(|e| sdk_err("get health log", e))?;
    let entries = resp.into_inner();

    spinner.finish_and_clear();
    render_health_entries(&entries, global);
    Ok(())
}

fn render_health_entries(
    entries: &[artifact_keeper_sdk::types::ServiceHealthEntry],
    global: &GlobalArgs,
) {
    if entries.is_empty() {
        eprintln!("No health-check entries found.");
        return;
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for e in entries {
            println!("{}", e.service_name);
        }
        return;
    }

    let json_entries: Vec<_> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "service_name": e.service_name,
                "status": e.status,
                "previous_status": e.previous_status,
                "response_time_ms": e.response_time_ms,
                "message": e.message,
                "checked_at": e.checked_at.to_rfc3339(),
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "SERVICE",
            "STATUS",
            "PREVIOUS",
            "TIME (ms)",
            "CHECKED",
            "MESSAGE",
        ]);
        for e in entries {
            let previous = e.previous_status.as_deref().unwrap_or("-").to_string();
            let rtime = e
                .response_time_ms
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());
            let checked = e.checked_at.format("%Y-%m-%d %H:%M").to_string();
            let message = e.message.as_deref().unwrap_or("-").to_string();
            table.add_row(vec![
                &e.service_name,
                &e.status,
                &previous,
                &rtime,
                &checked,
                &message,
            ]);
        }
        table.to_string()
    };

    println!(
        "{}",
        output::render(&json_entries, &global.format, Some(table_str))
    );
}

fn format_health_detail(item: &serde_json::Value) -> String {
    let opt = |key: &str| item[key].as_str().unwrap_or("-").to_string();
    let db_pool = match item.get("db_pool") {
        Some(p) if p.is_object() => format!(
            "{}/{} active, {} idle (max {})",
            p["active"].as_i64().unwrap_or(0),
            p["size"].as_i64().unwrap_or(0),
            p["idle"].as_i64().unwrap_or(0),
            p["max"].as_i64().unwrap_or(0),
        ),
        _ => "-".to_string(),
    };
    format!(
        "Status:           {}\n\
         Version:          {}\n\
         Commit:           {}\n\
         Demo Mode:        {}\n\
         Database:         {}\n\
         Storage:          {}\n\
         LDAP:             {}\n\
         OpenSearch:       {}\n\
         Security Scanner: {}\n\
         DB Pool:          {}",
        opt("status"),
        opt("version"),
        item["commit"].as_str().unwrap_or("-"),
        item["demo_mode"].as_bool().unwrap_or(false),
        opt("database"),
        opt("storage"),
        item["ldap"].as_str().unwrap_or("-"),
        item["opensearch"].as_str().unwrap_or("-"),
        item["security_scanner"].as_str().unwrap_or("-"),
        db_pool,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: MonitoringCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- parsing ----

    #[test]
    fn parse_health() {
        let cli = parse(&["test", "health"]);
        assert!(matches!(cli.command, MonitoringCommand::Health));
    }

    #[test]
    fn parse_live() {
        let cli = parse(&["test", "live"]);
        assert!(matches!(cli.command, MonitoringCommand::Live));
    }

    #[test]
    fn parse_ready() {
        let cli = parse(&["test", "ready"]);
        assert!(matches!(cli.command, MonitoringCommand::Ready));
    }

    #[test]
    fn parse_metrics() {
        let cli = parse(&["test", "metrics"]);
        assert!(matches!(cli.command, MonitoringCommand::Metrics));
    }

    #[test]
    fn parse_alerts() {
        let cli = parse(&["test", "alerts"]);
        assert!(matches!(cli.command, MonitoringCommand::Alerts));
    }

    #[test]
    fn parse_suppress() {
        let cli = parse(&[
            "test",
            "suppress",
            "database",
            "--until",
            "2026-07-10T00:00:00Z",
        ]);
        match cli.command {
            MonitoringCommand::Suppress { service, until } => {
                assert_eq!(service, "database");
                assert_eq!(until, "2026-07-10T00:00:00Z");
            }
            _ => panic!("expected Suppress"),
        }
    }

    #[test]
    fn parse_suppress_missing_until() {
        assert!(try_parse(&["test", "suppress", "database"]).is_err());
    }

    #[test]
    fn parse_check() {
        let cli = parse(&["test", "check"]);
        assert!(matches!(cli.command, MonitoringCommand::Check));
    }

    #[test]
    fn parse_health_log_defaults() {
        let cli = parse(&["test", "health-log"]);
        match cli.command {
            MonitoringCommand::HealthLog { limit, service } => {
                assert!(limit.is_none());
                assert!(service.is_none());
            }
            _ => panic!("expected HealthLog"),
        }
    }

    #[test]
    fn parse_health_log_with_filters() {
        let cli = parse(&[
            "test",
            "health-log",
            "--limit",
            "50",
            "--service",
            "storage",
        ]);
        match cli.command {
            MonitoringCommand::HealthLog { limit, service } => {
                assert_eq!(limit, Some(50));
                assert_eq!(service.as_deref(), Some("storage"));
            }
            _ => panic!("expected HealthLog"),
        }
    }

    // ---- formatting helpers ----

    #[test]
    fn check_status_str_with_message() {
        assert_eq!(check_status_str("ok", Some("all good")), "ok (all good)");
        assert_eq!(check_status_str("ok", None), "ok");
        assert_eq!(check_status_str("ok", Some("")), "ok");
    }

    #[test]
    fn format_health_detail_renders() {
        let item = json!({
            "status": "ok",
            "version": "1.4.0",
            "commit": "abc123",
            "demo_mode": false,
            "database": "ok",
            "storage": "ok (writable)",
            "ldap": null,
            "opensearch": null,
            "security_scanner": null,
            "db_pool": { "size": 5, "active": 1, "idle": 4, "max": 10 },
        });
        let detail = format_health_detail(&item);
        assert!(detail.contains("1.4.0"));
        assert!(detail.contains("ok (writable)"));
        assert!(detail.contains("1/5 active"));
    }

    #[test]
    fn format_health_detail_no_db_pool() {
        let item = json!({
            "status": "degraded",
            "version": "1.4.0",
            "commit": null,
            "demo_mode": true,
            "database": "ok",
            "storage": "error",
            "ldap": null,
            "opensearch": null,
            "security_scanner": null,
            "db_pool": null,
        });
        let detail = format_health_detail(&item);
        assert!(detail.contains("degraded"));
        assert!(detail.contains("DB Pool:          -"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    fn health_json() -> serde_json::Value {
        json!({
            "status": "ok",
            "version": "1.4.0",
            "commit": "abc123",
            "dirty": false,
            "demo_mode": false,
            "checks": {
                "database": { "status": "ok", "message": null },
                "storage": { "status": "ok", "message": "writable" },
                "ldap": null,
                "opensearch": null,
                "security_scanner": null
            },
            "db_pool": { "size": 5, "active_connections": 1, "idle_connections": 4, "max_connections": 10 }
        })
    }

    #[tokio::test]
    async fn handler_health() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(health_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        assert!(health(&global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_live() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/livez"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "alive" })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        assert!(live(&global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_ready() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/readyz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "ready",
                "checks": {
                    "database": { "status": "ok", "message": null },
                    "migrations": { "status": "ok", "message": null },
                    "setup_complete": { "status": "ok", "message": null }
                }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        assert!(ready(&global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_metrics() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/metrics"))
            .respond_with(ResponseTemplate::new(200).set_body_string("# HELP ak_up 1\nak_up 1\n"))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        assert!(metrics(&global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_alerts() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/monitoring/alerts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
                "service_name": "database",
                "current_status": "ok",
                "consecutive_failures": 0,
                "last_alert_sent_at": null,
                "suppressed_until": null,
                "updated_at": "2026-07-01T12:00:00Z"
            }])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        assert!(alerts(&global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_alerts_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/monitoring/alerts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        assert!(alerts(&global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_suppress() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/monitoring/alerts/suppress"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        assert!(
            suppress("database", "2026-07-10T00:00:00Z", &global)
                .await
                .is_ok()
        );
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn suppress_rejects_bad_timestamp() {
        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        assert!(suppress("database", "not-a-date", &global).await.is_err());
    }

    fn entry_json() -> serde_json::Value {
        json!({
            "service_name": "storage",
            "status": "ok",
            "previous_status": "degraded",
            "response_time_ms": 12,
            "message": "writable",
            "checked_at": "2026-07-01T12:00:00Z"
        })
    }

    #[tokio::test]
    async fn handler_check() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/monitoring/check"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([entry_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        assert!(check(&global).await.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_health_log() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/monitoring/health-log"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([entry_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        assert!(health_log(Some(50), Some("storage"), &global).await.is_ok());
        crate::test_utils::teardown_env();
    }
}
