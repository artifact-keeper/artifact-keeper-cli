use artifact_keeper_sdk::ClientPromotionExt;
use clap::Subcommand;
use miette::Result;

use super::client::client_for;
use super::helpers::{confirm_action, new_table, parse_uuid, print_page_info, sdk_err, short_id};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum PromotionCommand {
    /// Promote an artifact from one repo to another
    Promote {
        /// Source repository key
        #[arg(long)]
        from: String,

        /// Artifact ID
        artifact: String,

        /// Target repository key
        #[arg(long)]
        to: String,

        /// Optional notes
        #[arg(long)]
        notes: Option<String>,

        /// Skip policy checks
        #[arg(long)]
        skip_checks: bool,
    },

    /// Manage promotion rules
    Rule {
        #[command(subcommand)]
        command: PromotionRuleCommand,
    },

    /// View promotion history
    History {
        /// Repository key
        #[arg(long)]
        repo: String,

        /// Filter by status (pending, approved, rejected, completed)
        #[arg(long)]
        status: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: i32,
    },
}

#[derive(Subcommand)]
pub enum PromotionRuleCommand {
    /// List promotion rules
    List {
        /// Filter by source repository ID
        #[arg(long)]
        from: Option<String>,
    },

    /// Create a promotion rule
    Create {
        /// Rule name
        name: String,

        /// Source repository ID
        #[arg(long)]
        from: String,

        /// Target repository ID
        #[arg(long)]
        to: String,

        /// Enable auto-promotion
        #[arg(long)]
        auto: bool,
    },

    /// Delete a promotion rule
    Delete {
        /// Rule ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

impl PromotionCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Promote {
                from,
                artifact,
                to,
                notes,
                skip_checks,
            } => {
                promote_artifact(&from, &artifact, &to, notes.as_deref(), skip_checks, global).await
            }
            Self::Rule { command } => match command {
                PromotionRuleCommand::List { from } => list_rules(from.as_deref(), global).await,
                PromotionRuleCommand::Create {
                    name,
                    from,
                    to,
                    auto,
                } => create_rule(&name, &from, &to, auto, global).await,
                PromotionRuleCommand::Delete { id, yes } => delete_rule(&id, yes, global).await,
            },
            Self::History {
                repo,
                status,
                page,
                per_page,
            } => promotion_history(&repo, status.as_deref(), page, per_page, global).await,
        }
    }
}

async fn promote_artifact(
    from: &str,
    artifact_id: &str,
    to: &str,
    notes: Option<&str>,
    skip_checks: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let aid = parse_uuid(artifact_id, "artifact")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Promoting artifact...");

    let body = artifact_keeper_sdk::types::PromoteArtifactRequest {
        target_repository: to.to_string(),
        notes: notes.map(|s| s.to_string()),
        skip_policy_check: skip_checks.then_some(true),
    };

    let resp = client
        .promote_artifact()
        .key(from)
        .artifact_id(aid)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("promote artifact", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        if let Some(id) = &resp.promotion_id {
            println!("{id}");
        }
        return Ok(());
    }

    if resp.promoted {
        eprintln!("Artifact promoted: {} -> {}", resp.source, resp.target);
        if let Some(msg) = &resp.message {
            eprintln!("{msg}");
        }
    } else {
        eprintln!("Promotion blocked.");
        if let Some(msg) = &resp.message {
            eprintln!("{msg}");
        }
        if !resp.policy_violations.is_empty() {
            eprintln!("Policy violations:");
            for v in &resp.policy_violations {
                let info = serde_json::to_string(v).unwrap_or_default();
                eprintln!("  - {info}");
            }
        }
    }

    Ok(())
}

async fn list_rules(source_repo_id: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching promotion rules...");

    let mut req = client.list_rules();
    if let Some(id) = source_repo_id {
        let uid = parse_uuid(id, "repository")?;
        req = req.source_repo_id(uid);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("list promotion rules", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No promotion rules found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for r in &resp.items {
            println!("{}", r.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "name": r.name,
                "source_repo_id": r.source_repo_id.to_string(),
                "target_repo_id": r.target_repo_id.to_string(),
                "auto_promote": r.auto_promote,
                "is_enabled": r.is_enabled,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "SOURCE", "TARGET", "AUTO", "ENABLED"]);

        for r in &resp.items {
            let id_short = short_id(&r.id);
            let src_short = short_id(&r.source_repo_id);
            let tgt_short = short_id(&r.target_repo_id);
            let auto = if r.auto_promote { "yes" } else { "no" };
            let enabled = if r.is_enabled { "yes" } else { "no" };
            table.add_row(vec![
                &id_short, &r.name, &src_short, &tgt_short, auto, enabled,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    eprintln!("{} rules total.", resp.total);

    Ok(())
}

async fn create_rule(
    name: &str,
    from: &str,
    to: &str,
    auto: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let source_id = parse_uuid(from, "source repository")?;
    let target_id = parse_uuid(to, "target repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Creating promotion rule...");

    let body = artifact_keeper_sdk::types::CreateRuleRequest {
        name: name.to_string(),
        source_repo_id: source_id,
        target_repo_id: target_id,
        auto_promote: auto.then_some(true),
        is_enabled: Some(true),
        min_staging_hours: None,
        max_artifact_age_days: None,
        max_cve_severity: None,
        min_health_score: None,
        allowed_licenses: None,
        require_signature: None,
    };

    let rule = client
        .create_rule()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create promotion rule", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", rule.id);
        return Ok(());
    }

    eprintln!("Promotion rule '{}' created (ID: {}).", rule.name, rule.id);

    Ok(())
}

async fn delete_rule(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let rule_id = parse_uuid(id, "rule")?;

    if !confirm_action(
        &format!("Delete promotion rule {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting promotion rule...");

    client
        .delete_rule()
        .id(rule_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete promotion rule", e))?;

    spinner.finish_and_clear();
    eprintln!("Promotion rule {id} deleted.");

    Ok(())
}

fn format_rule_table(items: &[serde_json::Value]) -> String {
    let mut table = new_table(vec!["ID", "NAME", "SOURCE", "TARGET", "AUTO", "ENABLED"]);

    for r in items {
        let id = r["id"].as_str().unwrap_or("-");
        let id_short = if id.len() >= 8 { &id[..8] } else { id };
        let src = r["source_repo_id"].as_str().unwrap_or("-");
        let src_short = if src.len() >= 8 { &src[..8] } else { src };
        let tgt = r["target_repo_id"].as_str().unwrap_or("-");
        let tgt_short = if tgt.len() >= 8 { &tgt[..8] } else { tgt };
        let auto = if r["auto_promote"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        let enabled = if r["is_enabled"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        table.add_row(vec![
            id_short,
            r["name"].as_str().unwrap_or("-"),
            src_short,
            tgt_short,
            auto,
            enabled,
        ]);
    }

    table.to_string()
}

fn format_history_table(items: &[serde_json::Value]) -> String {
    let mut table = new_table(vec!["ID", "ARTIFACT", "SOURCE", "TARGET", "STATUS", "DATE"]);

    for e in items {
        let id = e["id"].as_str().unwrap_or("-");
        let id_short = if id.len() >= 8 { &id[..8] } else { id };
        table.add_row(vec![
            id_short,
            e["artifact_path"].as_str().unwrap_or("-"),
            e["source_repo"].as_str().unwrap_or("-"),
            e["target_repo"].as_str().unwrap_or("-"),
            e["status"].as_str().unwrap_or("-"),
            e["created_at"].as_str().unwrap_or("-"),
        ]);
    }

    table.to_string()
}

async fn promotion_history(
    repo: &str,
    status: Option<&str>,
    page: i32,
    per_page: i32,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching promotion history...");

    let mut req = client
        .promotion_history()
        .key(repo)
        .page(page)
        .per_page(per_page);

    if let Some(s) = status {
        req = req.status(s);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("fetch promotion history", e))?;

    spinner.finish_and_clear();

    if resp.items.is_empty() {
        eprintln!("No promotion history found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for entry in &resp.items {
            println!("{}", entry.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = resp
        .items
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id.to_string(),
                "artifact_path": e.artifact_path,
                "source_repo": e.source_repo_key,
                "target_repo": e.target_repo_key,
                "status": e.status,
                "created_at": e.created_at.to_rfc3339(),
                "promoted_by": e.promoted_by_username,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "ARTIFACT", "SOURCE", "TARGET", "STATUS", "DATE"]);

        for e in &resp.items {
            let id_short = short_id(&e.id);
            let date = e.created_at.format("%Y-%m-%d %H:%M").to_string();
            table.add_row(vec![
                &id_short,
                &e.artifact_path,
                &e.source_repo_key,
                &e.target_repo_key,
                &e.status,
                &date,
            ]);
        }

        table.to_string()
    };

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    print_page_info(
        resp.pagination.page,
        resp.pagination.total_pages,
        resp.pagination.total,
        "entries",
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
        command: PromotionCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- parsing: promote ----

    #[test]
    fn parse_promote_minimal() {
        let cli = parse(&[
            "test",
            "promote",
            "--from",
            "maven-staging",
            "00000000-0000-0000-0000-000000000001",
            "--to",
            "maven-releases",
        ]);
        match cli.command {
            PromotionCommand::Promote {
                from,
                artifact,
                to,
                notes,
                skip_checks,
            } => {
                assert_eq!(from, "maven-staging");
                assert_eq!(artifact, "00000000-0000-0000-0000-000000000001");
                assert_eq!(to, "maven-releases");
                assert!(notes.is_none());
                assert!(!skip_checks);
            }
            _ => panic!("expected Promote"),
        }
    }

    #[test]
    fn parse_promote_with_notes_and_skip() {
        let cli = parse(&[
            "test",
            "promote",
            "--from",
            "staging",
            "artifact-id",
            "--to",
            "prod",
            "--notes",
            "Approved by QA",
            "--skip-checks",
        ]);
        match cli.command {
            PromotionCommand::Promote {
                notes, skip_checks, ..
            } => {
                assert_eq!(notes.as_deref(), Some("Approved by QA"));
                assert!(skip_checks);
            }
            _ => panic!("expected Promote"),
        }
    }

    #[test]
    fn parse_promote_missing_from() {
        let result = try_parse(&["test", "promote", "artifact-id", "--to", "prod"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_promote_missing_to() {
        let result = try_parse(&["test", "promote", "--from", "staging", "artifact-id"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_promote_missing_artifact() {
        let result = try_parse(&["test", "promote", "--from", "staging", "--to", "prod"]);
        assert!(result.is_err());
    }

    // ---- parsing: rule list ----

    #[test]
    fn parse_rule_list_no_filter() {
        let cli = parse(&["test", "rule", "list"]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::List { from },
            } => {
                assert!(from.is_none());
            }
            _ => panic!("expected Rule List"),
        }
    }

    #[test]
    fn parse_rule_list_with_from() {
        let cli = parse(&[
            "test",
            "rule",
            "list",
            "--from",
            "00000000-0000-0000-0000-000000000001",
        ]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::List { from },
            } => {
                assert_eq!(
                    from.as_deref(),
                    Some("00000000-0000-0000-0000-000000000001")
                );
            }
            _ => panic!("expected Rule List"),
        }
    }

    // ---- parsing: rule create ----

    #[test]
    fn parse_rule_create_minimal() {
        let cli = parse(&[
            "test",
            "rule",
            "create",
            "staging-to-prod",
            "--from",
            "repo-a-id",
            "--to",
            "repo-b-id",
        ]);
        match cli.command {
            PromotionCommand::Rule {
                command:
                    PromotionRuleCommand::Create {
                        name,
                        from,
                        to,
                        auto,
                    },
            } => {
                assert_eq!(name, "staging-to-prod");
                assert_eq!(from, "repo-a-id");
                assert_eq!(to, "repo-b-id");
                assert!(!auto);
            }
            _ => panic!("expected Rule Create"),
        }
    }

    #[test]
    fn parse_rule_create_with_auto() {
        let cli = parse(&[
            "test",
            "rule",
            "create",
            "auto-rule",
            "--from",
            "id1",
            "--to",
            "id2",
            "--auto",
        ]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::Create { auto, .. },
            } => {
                assert!(auto);
            }
            _ => panic!("expected Rule Create"),
        }
    }

    #[test]
    fn parse_rule_create_missing_name() {
        let result = try_parse(&["test", "rule", "create", "--from", "id1", "--to", "id2"]);
        assert!(result.is_err());
    }

    // ---- parsing: rule delete ----

    #[test]
    fn parse_rule_delete() {
        let cli = parse(&["test", "rule", "delete", "rule-id"]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::Delete { id, yes },
            } => {
                assert_eq!(id, "rule-id");
                assert!(!yes);
            }
            _ => panic!("expected Rule Delete"),
        }
    }

    #[test]
    fn parse_rule_delete_with_yes() {
        let cli = parse(&["test", "rule", "delete", "rule-id", "--yes"]);
        match cli.command {
            PromotionCommand::Rule {
                command: PromotionRuleCommand::Delete { yes, .. },
            } => {
                assert!(yes);
            }
            _ => panic!("expected Rule Delete"),
        }
    }

    #[test]
    fn parse_rule_delete_missing_id() {
        let result = try_parse(&["test", "rule", "delete"]);
        assert!(result.is_err());
    }

    // ---- parsing: history ----

    #[test]
    fn parse_history_minimal() {
        let cli = parse(&["test", "history", "--repo", "maven-releases"]);
        match cli.command {
            PromotionCommand::History {
                repo,
                status,
                page,
                per_page,
            } => {
                assert_eq!(repo, "maven-releases");
                assert!(status.is_none());
                assert_eq!(page, 1);
                assert_eq!(per_page, 20);
            }
            _ => panic!("expected History"),
        }
    }

    #[test]
    fn parse_history_with_all_options() {
        let cli = parse(&[
            "test",
            "history",
            "--repo",
            "npm-local",
            "--status",
            "completed",
            "--page",
            "2",
            "--per-page",
            "50",
        ]);
        match cli.command {
            PromotionCommand::History {
                repo,
                status,
                page,
                per_page,
            } => {
                assert_eq!(repo, "npm-local");
                assert_eq!(status.as_deref(), Some("completed"));
                assert_eq!(page, 2);
                assert_eq!(per_page, 50);
            }
            _ => panic!("expected History"),
        }
    }

    #[test]
    fn parse_history_missing_repo() {
        let result = try_parse(&["test", "history"]);
        assert!(result.is_err());
    }

    // ---- parsing: missing subcommand ----

    #[test]
    fn parse_rule_missing_subcommand() {
        let result = try_parse(&["test", "rule"]);
        assert!(result.is_err());
    }

    // ---- format functions ----

    #[test]
    fn format_rule_table_renders() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "staging-to-prod",
            "source_repo_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "target_repo_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "auto_promote": true,
            "is_enabled": true,
        })];
        let table = format_rule_table(&items);
        assert!(table.contains("00000000"));
        assert!(table.contains("staging-to-prod"));
        assert!(table.contains("aaaaaaaa"));
        assert!(table.contains("bbbbbbbb"));
        assert!(table.contains("yes"));
    }

    #[test]
    fn format_rule_table_disabled_no_auto() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "manual-rule",
            "source_repo_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "target_repo_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "auto_promote": false,
            "is_enabled": false,
        })];
        let table = format_rule_table(&items);
        assert!(table.contains("manual-rule"));
        // Both auto and enabled should show "no"
        let no_count = table.matches("no").count();
        assert!(no_count >= 2);
    }

    #[test]
    fn format_rule_table_multiple_rows() {
        let items = vec![
            json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "rule-a",
                "source_repo_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "target_repo_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "auto_promote": true,
                "is_enabled": true,
            }),
            json!({
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "rule-b",
                "source_repo_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
                "target_repo_id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
                "auto_promote": false,
                "is_enabled": true,
            }),
        ];
        let table = format_rule_table(&items);
        assert!(table.contains("rule-a"));
        assert!(table.contains("rule-b"));
    }

    #[test]
    fn format_history_table_renders() {
        let items = vec![json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "artifact_path": "com/example/app/1.0.0",
            "source_repo": "maven-staging",
            "target_repo": "maven-releases",
            "status": "completed",
            "created_at": "2026-01-15 12:00",
        })];
        let table = format_history_table(&items);
        assert!(table.contains("00000000"));
        assert!(table.contains("com/example/app/1.0.0"));
        assert!(table.contains("maven-staging"));
        assert!(table.contains("maven-releases"));
        assert!(table.contains("completed"));
    }

    #[test]
    fn format_history_table_multiple_rows() {
        let items = vec![
            json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "artifact_path": "pkg-a",
                "source_repo": "staging",
                "target_repo": "prod",
                "status": "completed",
                "created_at": "2026-01-15",
            }),
            json!({
                "id": "11111111-1111-1111-1111-111111111111",
                "artifact_path": "pkg-b",
                "source_repo": "dev",
                "target_repo": "staging",
                "status": "pending",
                "created_at": "2026-01-16",
            }),
        ];
        let table = format_history_table(&items);
        assert!(table.contains("pkg-a"));
        assert!(table.contains("pkg-b"));
        assert!(table.contains("completed"));
        assert!(table.contains("pending"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn rule_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "staging-to-prod",
            "source_repo_id": NIL_UUID,
            "target_repo_id": NIL_UUID,
            "auto_promote": false,
            "is_enabled": true,
            "require_signature": false,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    #[tokio::test]
    async fn handler_promote_artifact_json() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/promotion/repositories/staging/artifacts/{NIL_UUID}/promote"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "promoted": true,
                "source": "staging",
                "target": "releases",
                "message": "Promoted successfully",
                "promotion_id": NIL_UUID,
                "policy_violations": []
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = promote_artifact("staging", NIL_UUID, "releases", None, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_promote_artifact_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/promotion/repositories/staging/artifacts/{NIL_UUID}/promote"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "promoted": true,
                "source": "staging",
                "target": "releases",
                "promotion_id": NIL_UUID,
                "policy_violations": []
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = promote_artifact("staging", NIL_UUID, "releases", None, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_rules_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/promotion-rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "total": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_rules(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_rules_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/promotion-rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [rule_json()],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_rules(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_rules_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/promotion-rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [rule_json()],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_rules(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_rule_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/promotion-rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rule_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_rule("staging-to-prod", NIL_UUID, NIL_UUID, false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_rule() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/promotion-rules/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = delete_rule(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_promotion_history_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/promotion/repositories/.*/promotion-history",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [],
                "pagination": { "page": 1, "per_page": 20, "total": 0, "total_pages": 0 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = promotion_history("maven-releases", None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_promotion_history_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex(
                "/api/v1/promotion/repositories/.*/promotion-history",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "id": NIL_UUID,
                    "artifact_id": NIL_UUID,
                    "artifact_path": "com/example/app/1.0.0",
                    "source_repo_key": "maven-staging",
                    "target_repo_key": "maven-releases",
                    "status": "completed",
                    "promoted_by_username": "admin",
                    "created_at": "2026-01-15T12:00:00Z"
                }],
                "pagination": { "page": 1, "per_page": 20, "total": 1_i64, "total_pages": 1 }
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = promotion_history("maven-releases", None, 1, 20, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_promotion_rule_json() {
        let items = vec![rule_json()];
        let output = crate::output::render(&items, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("promotion_rule_json", parsed);
    }

    #[test]
    fn snapshot_promotion_rule_table() {
        let items = vec![rule_json()];
        let table = format_rule_table(&items);
        insta::assert_snapshot!("promotion_rule_table", table);
    }
}
