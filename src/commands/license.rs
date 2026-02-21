use artifact_keeper_sdk::ClientSbomExt;
use artifact_keeper_sdk::types::LicensePolicyResponse;
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
pub enum LicenseCommand {
    /// Manage license policies
    #[command(subcommand)]
    Policy(PolicyCommand),

    /// Check license compliance against active policies
    Check {
        /// SPDX license identifiers to check (comma-separated)
        #[arg(long, value_delimiter = ',')]
        licenses: Vec<String>,

        /// Scope check to a specific repository
        #[arg(long)]
        repo: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum PolicyCommand {
    /// List all license policies
    List,

    /// Show license policy details
    Show {
        /// Policy ID
        id: String,
    },

    /// Create a license policy
    Create {
        /// Policy name
        name: String,

        /// Allowed SPDX license identifiers (comma-separated)
        #[arg(long, value_delimiter = ',')]
        allowed: Vec<String>,

        /// Denied SPDX license identifiers (comma-separated)
        #[arg(long, value_delimiter = ',')]
        denied: Vec<String>,

        /// Allow artifacts with unknown licenses
        #[arg(long)]
        allow_unknown: bool,

        /// Enforcement action (allow, warn, block)
        #[arg(long)]
        action: Option<String>,

        /// Policy description
        #[arg(long)]
        description: Option<String>,

        /// Enable policy on creation (default: true)
        #[arg(long)]
        enabled: Option<bool>,

        /// Bind to a specific repository ID
        #[arg(long)]
        repo: Option<String>,
    },

    /// Delete a license policy
    Delete {
        /// Policy ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
}

impl LicenseCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Policy(cmd) => cmd.execute(global).await,
            Self::Check { licenses, repo } => {
                check_compliance(licenses, repo.as_deref(), global).await
            }
        }
    }
}

impl PolicyCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List => list_policies(global).await,
            Self::Show { id } => show_policy(&id, global).await,
            Self::Create {
                name,
                allowed,
                denied,
                allow_unknown,
                action,
                description,
                enabled,
                repo,
            } => {
                create_policy(
                    &name,
                    allowed,
                    denied,
                    allow_unknown,
                    action.as_deref(),
                    description.as_deref(),
                    enabled,
                    repo.as_deref(),
                    global,
                )
                .await
            }
            Self::Delete { id, yes } => delete_policy(&id, yes, global).await,
        }
    }
}

async fn list_policies(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching license policies...");

    let policies = client
        .list_license_policies()
        .send()
        .await
        .map_err(|e| sdk_err("list license policies", e))?;

    let policies = policies.into_inner();
    spinner.finish_and_clear();

    if policies.is_empty() {
        eprintln!("No license policies found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &policies {
            println!("{}", p.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_policies_table(&policies);

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_policy(id: &str, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "license policy")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Fetching license policy...");

    let policy = client
        .get_license_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| sdk_err("get license policy", e))?;

    spinner.finish_and_clear();

    let (info, table_str) = format_policy_detail(&policy);

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create_policy(
    name: &str,
    allowed: Vec<String>,
    denied: Vec<String>,
    allow_unknown: bool,
    action: Option<&str>,
    description: Option<&str>,
    enabled: Option<bool>,
    repo_id: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let repository_id = parse_optional_uuid(repo_id, "repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Creating license policy...");

    let body = artifact_keeper_sdk::types::UpsertLicensePolicyRequest {
        name: name.to_string(),
        allowed_licenses: allowed,
        denied_licenses: denied,
        allow_unknown: Some(allow_unknown),
        action: action.map(|s| s.to_string()),
        description: description.map(|s| s.to_string()),
        is_enabled: enabled,
        repository_id,
    };

    let policy = client
        .upsert_license_policy()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create license policy", e))?;

    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", policy.id);
        return Ok(());
    }

    eprintln!(
        "License policy '{}' created (ID: {}).",
        policy.name, policy.id
    );

    Ok(())
}

async fn delete_policy(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let policy_id = parse_uuid(id, "license policy")?;

    if !confirm_action(
        &format!("Delete license policy {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting license policy...");

    client
        .delete_license_policy()
        .id(policy_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete license policy", e))?;

    spinner.finish_and_clear();
    eprintln!("License policy {id} deleted.");

    Ok(())
}

async fn check_compliance(
    licenses: Vec<String>,
    repo_id: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let repository_id = parse_optional_uuid(repo_id, "repository")?;

    let client = client_for(global)?;
    let spinner = output::spinner("Checking license compliance...");

    let body = artifact_keeper_sdk::types::CheckLicenseComplianceRequest {
        licenses,
        repository_id,
    };

    let result = client
        .check_license_compliance()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("check license compliance", e))?;

    let result = result.into_inner();
    spinner.finish_and_clear();

    let info = serde_json::json!({
        "compliant": result.compliant,
        "violations": result.violations,
        "warnings": result.warnings,
    });

    if matches!(global.format, OutputFormat::Table) {
        if result.compliant {
            eprintln!("COMPLIANT: All licenses pass policy checks.");
        } else {
            eprintln!("NON-COMPLIANT: License policy violations detected.");
            if !result.violations.is_empty() {
                eprintln!("Violations:");
                for v in &result.violations {
                    eprintln!("  - {v}");
                }
            }
            if !result.warnings.is_empty() {
                eprintln!("Warnings:");
                for w in &result.warnings {
                    eprintln!("  - {w}");
                }
            }
        }
    } else {
        println!("{}", output::render(&info, &global.format, None));
    }

    if !result.compliant {
        std::process::exit(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_policies_table(policies: &[LicensePolicyResponse]) -> (Vec<Value>, String) {
    let entries: Vec<_> = policies
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_string(),
                "name": p.name,
                "action": p.action,
                "allow_unknown": p.allow_unknown,
                "enabled": p.is_enabled,
                "allowed_licenses": p.allowed_licenses,
                "denied_licenses": p.denied_licenses,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID",
            "NAME",
            "ACTION",
            "ALLOW UNKNOWN",
            "ENABLED",
            "ALLOWED",
            "DENIED",
        ]);

        for p in policies {
            let id_short = short_id(&p.id);
            let enabled = if p.is_enabled { "yes" } else { "no" };
            let allow_unknown = if p.allow_unknown { "yes" } else { "no" };
            let allowed = if p.allowed_licenses.is_empty() {
                "-".to_string()
            } else {
                p.allowed_licenses.join(", ")
            };
            let denied = if p.denied_licenses.is_empty() {
                "-".to_string()
            } else {
                p.denied_licenses.join(", ")
            };
            table.add_row(vec![
                &id_short,
                &p.name,
                &p.action,
                allow_unknown,
                enabled,
                &allowed,
                &denied,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_policy_detail(policy: &LicensePolicyResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": policy.id.to_string(),
        "name": policy.name,
        "description": policy.description,
        "action": policy.action,
        "enabled": policy.is_enabled,
        "allow_unknown": policy.allow_unknown,
        "allowed_licenses": policy.allowed_licenses,
        "denied_licenses": policy.denied_licenses,
        "repository_id": policy.repository_id.map(|u| u.to_string()),
        "created_at": policy.created_at.to_rfc3339(),
        "updated_at": policy.updated_at.map(|u| u.to_rfc3339()),
    });

    let allowed = if policy.allowed_licenses.is_empty() {
        "-".to_string()
    } else {
        policy.allowed_licenses.join(", ")
    };
    let denied = if policy.denied_licenses.is_empty() {
        "-".to_string()
    } else {
        policy.denied_licenses.join(", ")
    };

    let table_str = format!(
        "ID:            {}\n\
         Name:          {}\n\
         Description:   {}\n\
         Action:        {}\n\
         Enabled:       {}\n\
         Allow Unknown: {}\n\
         Allowed:       {}\n\
         Denied:        {}\n\
         Repository:    {}\n\
         Created:       {}",
        policy.id,
        policy.name,
        policy.description.as_deref().unwrap_or("-"),
        policy.action,
        if policy.is_enabled { "yes" } else { "no" },
        if policy.allow_unknown { "yes" } else { "no" },
        allowed,
        denied,
        policy
            .repository_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "global".to_string()),
        policy.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    (info, table_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: LicenseCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- LicenseCommand top-level ----

    #[test]
    fn parse_policy_subcommand() {
        let cli = parse(&["test", "policy", "list"]);
        assert!(matches!(cli.command, LicenseCommand::Policy(_)));
    }

    #[test]
    fn parse_check_with_licenses() {
        let cli = parse(&["test", "check", "--licenses", "MIT,Apache-2.0"]);
        if let LicenseCommand::Check { licenses, repo } = cli.command {
            assert_eq!(licenses, vec!["MIT", "Apache-2.0"]);
            assert!(repo.is_none());
        } else {
            panic!("Expected Check");
        }
    }

    #[test]
    fn parse_check_with_repo() {
        let cli = parse(&[
            "test",
            "check",
            "--licenses",
            "MIT",
            "--repo",
            "00000000-0000-0000-0000-000000000001",
        ]);
        if let LicenseCommand::Check { licenses, repo } = cli.command {
            assert_eq!(licenses, vec!["MIT"]);
            assert_eq!(repo.unwrap(), "00000000-0000-0000-0000-000000000001");
        } else {
            panic!("Expected Check with repo");
        }
    }

    #[test]
    fn parse_check_empty_licenses() {
        let cli = parse(&["test", "check"]);
        if let LicenseCommand::Check { licenses, .. } = cli.command {
            assert!(licenses.is_empty());
        } else {
            panic!("Expected Check");
        }
    }

    // ---- PolicyCommand ----

    #[test]
    fn parse_policy_list() {
        let cli = parse(&["test", "policy", "list"]);
        if let LicenseCommand::Policy(PolicyCommand::List) = cli.command {
            // pass
        } else {
            panic!("Expected Policy List");
        }
    }

    #[test]
    fn parse_policy_show() {
        let cli = parse(&["test", "policy", "show", "policy-id-123"]);
        if let LicenseCommand::Policy(PolicyCommand::Show { id }) = cli.command {
            assert_eq!(id, "policy-id-123");
        } else {
            panic!("Expected Policy Show");
        }
    }

    #[test]
    fn parse_policy_create_minimal() {
        let cli = parse(&["test", "policy", "create", "my-policy"]);
        if let LicenseCommand::Policy(PolicyCommand::Create {
            name,
            allowed,
            denied,
            allow_unknown,
            action,
            description,
            enabled,
            repo,
        }) = cli.command
        {
            assert_eq!(name, "my-policy");
            assert!(allowed.is_empty());
            assert!(denied.is_empty());
            assert!(!allow_unknown);
            assert!(action.is_none());
            assert!(description.is_none());
            assert!(enabled.is_none());
            assert!(repo.is_none());
        } else {
            panic!("Expected Policy Create");
        }
    }

    #[test]
    fn parse_policy_create_full() {
        let cli = parse(&[
            "test",
            "policy",
            "create",
            "strict-policy",
            "--allowed",
            "MIT,Apache-2.0",
            "--denied",
            "GPL-3.0",
            "--allow-unknown",
            "--action",
            "block",
            "--description",
            "Only permissive licenses",
            "--enabled",
            "true",
            "--repo",
            "00000000-0000-0000-0000-000000000001",
        ]);
        if let LicenseCommand::Policy(PolicyCommand::Create {
            name,
            allowed,
            denied,
            allow_unknown,
            action,
            description,
            enabled,
            repo,
        }) = cli.command
        {
            assert_eq!(name, "strict-policy");
            assert_eq!(allowed, vec!["MIT", "Apache-2.0"]);
            assert_eq!(denied, vec!["GPL-3.0"]);
            assert!(allow_unknown);
            assert_eq!(action.unwrap(), "block");
            assert_eq!(description.unwrap(), "Only permissive licenses");
            assert_eq!(enabled, Some(true));
            assert_eq!(repo.unwrap(), "00000000-0000-0000-0000-000000000001");
        } else {
            panic!("Expected Policy Create full");
        }
    }

    #[test]
    fn parse_policy_delete() {
        let cli = parse(&["test", "policy", "delete", "policy-id"]);
        if let LicenseCommand::Policy(PolicyCommand::Delete { id, yes }) = cli.command {
            assert_eq!(id, "policy-id");
            assert!(!yes);
        } else {
            panic!("Expected Policy Delete");
        }
    }

    #[test]
    fn parse_policy_delete_with_yes() {
        let cli = parse(&["test", "policy", "delete", "policy-id", "--yes"]);
        if let LicenseCommand::Policy(PolicyCommand::Delete { yes, .. }) = cli.command {
            assert!(yes);
        } else {
            panic!("Expected Policy Delete with --yes");
        }
    }

    #[test]
    fn parse_policy_create_missing_name() {
        let result = try_parse(&["test", "policy", "create"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_check_multiple_licenses_comma_separated() {
        let cli = parse(&[
            "test",
            "check",
            "--licenses",
            "MIT,BSD-2-Clause,ISC,Apache-2.0",
        ]);
        if let LicenseCommand::Check { licenses, .. } = cli.command {
            assert_eq!(licenses.len(), 4);
            assert_eq!(licenses[0], "MIT");
            assert_eq!(licenses[3], "Apache-2.0");
        } else {
            panic!("Expected Check");
        }
    }

    // ---- Format function tests ----

    use artifact_keeper_sdk::types::LicensePolicyResponse;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_test_policy(
        name: &str,
        action: &str,
        allowed: Vec<&str>,
        denied: Vec<&str>,
    ) -> LicensePolicyResponse {
        LicensePolicyResponse {
            id: Uuid::nil(),
            name: name.to_string(),
            action: action.to_string(),
            allow_unknown: false,
            is_enabled: true,
            allowed_licenses: allowed.into_iter().map(|s| s.to_string()).collect(),
            denied_licenses: denied.into_iter().map(|s| s.to_string()).collect(),
            description: Some("Test policy".to_string()),
            repository_id: None,
            created_at: Utc::now(),
            updated_at: None,
        }
    }

    #[test]
    fn format_policies_table_single() {
        let policies = vec![make_test_policy(
            "permissive",
            "warn",
            vec!["MIT", "Apache-2.0"],
            vec!["GPL-3.0"],
        )];
        let (entries, table_str) = format_policies_table(&policies);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "permissive");
        assert_eq!(entries[0]["action"], "warn");
        assert_eq!(entries[0]["enabled"], true);

        assert!(table_str.contains("NAME"));
        assert!(table_str.contains("ACTION"));
        assert!(table_str.contains("permissive"));
        assert!(table_str.contains("warn"));
        assert!(table_str.contains("yes"));
    }

    #[test]
    fn format_policies_table_multiple() {
        let policies = vec![
            make_test_policy("allow-all", "allow", vec![], vec![]),
            make_test_policy("strict", "block", vec!["MIT"], vec!["GPL-3.0"]),
        ];
        let (entries, table_str) = format_policies_table(&policies);

        assert_eq!(entries.len(), 2);
        assert!(table_str.contains("allow-all"));
        assert!(table_str.contains("strict"));
    }

    #[test]
    fn format_policies_table_empty() {
        let (entries, table_str) = format_policies_table(&[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("NAME"));
    }

    #[test]
    fn format_policies_table_empty_licenses_show_dash() {
        let policies = vec![make_test_policy("no-lists", "allow", vec![], vec![])];
        let (_entries, table_str) = format_policies_table(&policies);

        // Empty allowed/denied should show "-"
        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_policy_detail_with_licenses() {
        let policy = make_test_policy(
            "detailed-policy",
            "block",
            vec!["MIT", "BSD-2-Clause"],
            vec!["GPL-3.0", "AGPL-3.0"],
        );
        let (info, table_str) = format_policy_detail(&policy);

        assert_eq!(info["name"], "detailed-policy");
        assert_eq!(info["action"], "block");
        assert_eq!(info["enabled"], true);
        assert_eq!(info["description"], "Test policy");

        assert!(table_str.contains("detailed-policy"));
        assert!(table_str.contains("block"));
        assert!(table_str.contains("MIT, BSD-2-Clause"));
        assert!(table_str.contains("GPL-3.0, AGPL-3.0"));
        assert!(table_str.contains("global")); // no repo_id
    }

    #[test]
    fn format_policy_detail_no_description() {
        let mut policy = make_test_policy("bare", "warn", vec![], vec![]);
        policy.description = None;
        let (info, table_str) = format_policy_detail(&policy);

        assert!(info["description"].is_null());
        assert!(table_str.contains("Description:"));
    }

    #[test]
    fn format_policy_detail_with_repo() {
        let mut policy = make_test_policy("scoped", "block", vec!["MIT"], vec![]);
        policy.repository_id = Some(Uuid::nil());
        let (info, table_str) = format_policy_detail(&policy);

        assert!(info["repository_id"].is_string());
        assert!(table_str.contains("Repository:"));
        // Should show UUID instead of "global"
        assert!(table_str.contains("00000000"));
    }

    #[test]
    fn format_policy_detail_disabled() {
        let mut policy = make_test_policy("disabled-policy", "block", vec![], vec![]);
        policy.is_enabled = false;
        policy.allow_unknown = true;
        let (info, table_str) = format_policy_detail(&policy);

        assert_eq!(info["enabled"], false);
        assert_eq!(info["allow_unknown"], true);
        assert!(table_str.contains("Enabled:"));
        assert!(table_str.contains("Allow Unknown:"));
    }

    // ---- wiremock handler tests ----

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn policy_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "permissive-only",
            "action": "block",
            "allow_unknown": false,
            "is_enabled": true,
            "allowed_licenses": ["MIT", "Apache-2.0"],
            "denied_licenses": ["GPL-3.0"],
            "description": "Allow only permissive licenses",
            "repository_id": null,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": null
        })
    }

    #[tokio::test]
    async fn handler_list_policies_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/sbom/license-policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_policies_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/sbom/license-policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([policy_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_policies_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/sbom/license-policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([policy_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = list_policies(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/sbom/license-policies/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_policy(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_policy_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/sbom/license-policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(policy_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_policy(
            "permissive-only",
            vec!["MIT".to_string()],
            vec![],
            false,
            Some("block"),
            None,
            None,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_policy() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/sbom/license-policies/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = delete_policy(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_check_compliance_compliant() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/sbom/check-compliance"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "compliant": true,
                "violations": [],
                "warnings": []
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = check_compliance(vec!["MIT".to_string()], None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }
}
