//! `ak admin config`: the instance's repositories and their settings as one
//! document, to export, compare with an instance and apply to it. New in 1.12.

use std::io::Read;

use artifact_keeper_sdk::types::ConfigPlan;
use clap::{Args, Subcommand};
use miette::Result;
use serde_json::{Value, json};

use crate::cli::GlobalArgs;
use crate::commands::helpers::{
    Minor, RawFailure, bad_response, confirm_action, ensure_can_confirm, raw_json_call_with_query,
    reported_failure, since_raw, write_stdout,
};
use crate::error::AkError;
use crate::output::{self, OutputFormat};

const SINCE: Minor = (1, 12);

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Export the repositories and their settings as one JSON document. Credentials
    /// are never in it: each is a `secret_ref` placeholder, which `plan` and `apply`
    /// take values for from --secrets-file
    Export {
        /// Only these repositories, by key, comma-separated. Every repository if left out
        #[arg(long)]
        repositories: Option<String>,

        /// Write the document to this file rather than stdout, which `-` also means
        #[arg(long, short)]
        output: Option<String>,
    },

    /// Compare a document with this instance and say what `apply` would change.
    /// Changes nothing. Exits 7 when the document can't be applied as it is
    Plan(ImportArgs),

    /// Create the repositories a document has and this instance doesn't, and update
    /// the settings that differ. Asks first, with what a plan says it will change.
    /// The server plans again when it applies, so a change made on the instance
    /// between the prompt and the apply is applied without being shown
    Apply {
        #[command(flatten)]
        import: ImportArgs,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Args)]
pub struct ImportArgs {
    /// The document, as `ak admin config export` writes it, or `-` for stdin. A body
    /// with `document` and `secrets` keys is sent as it is
    file: String,

    /// Values for the document's `secret_ref` placeholders: a JSON object from each
    /// name to its value, in a file or `-` for stdin
    #[arg(long)]
    secrets_file: Option<String>,

    /// Also delete the repositories on this instance that the document doesn't name.
    /// 1.12.1 servers refuse it, and delete nothing
    #[arg(long)]
    prune: bool,
}

impl ConfigCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Export {
                repositories,
                output,
            } => export(repositories, output, global).await,
            Self::Plan(import) => plan(import, global).await,
            Self::Apply { import, yes } => apply(import, yes, global).await,
        }
    }
}

async fn export(
    repositories: Option<String>,
    output_file: Option<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let query: Vec<(&str, String)> = repositories
        .map(|keys| ("repositories", keys))
        .into_iter()
        .collect();
    let spinner = output::spinner("Exporting configuration...");
    // Raw, not through the SDK: its `ConfigDocument` refuses a field it doesn't know,
    // and the document has to reach the file as the server wrote it.
    let result = send(
        reqwest::Method::GET,
        &["admin", "config", "export"],
        &query,
        None,
        "export the configuration",
        "admin config export",
        global,
    )
    .await;
    spinner.finish_and_clear();
    let raw = result?;
    let document: Value =
        serde_json::from_slice(&raw).map_err(|e| bad_response("export the configuration", e))?;
    let count = document["repositories"].as_array().map_or(0, Vec::len);

    match output_file.as_deref() {
        Some(path) if path != "-" => {
            tokio::fs::write(path, &raw)
                .await
                .map_err(|e| AkError::Local(format!("Can't write {path}: {e}")))?;
            if !matches!(global.format, OutputFormat::Quiet) {
                eprintln!("Exported {count} repositories to {path}.");
            }
            Ok(())
        }
        // A document is for a file, and the server's bytes are the document, so stdout
        // gets them as sent whatever the format, but YAML, which is asked for by name.
        _ if matches!(global.format, OutputFormat::Yaml) => {
            println!(
                "{}",
                output::render_raw(Some(&raw), &document, &global.format, None)
            );
            Ok(())
        }
        _ => {
            let mut bytes = raw;
            if !bytes.ends_with(b"\n") {
                bytes.push(b'\n');
            }
            write_stdout(&bytes)
        }
    }
}

/// A raw call to a route new in 1.12: a 404 from an older server says so.
async fn send(
    method: reqwest::Method,
    segments: &[&str],
    query: &[(&str, String)],
    body: Option<&Value>,
    action: &str,
    command: &str,
    global: &GlobalArgs,
) -> Result<Vec<u8>> {
    match raw_json_call_with_query(method, segments, query, body, action, global).await {
        Ok(bytes) => Ok(bytes),
        Err(RawFailure::Status(status, text)) => Err(since_raw(
            SINCE,
            status,
            &text,
            &format!("Failed to {action}"),
            command,
            global,
        )
        .await
        .into()),
        Err(RawFailure::Other(report)) => Err(report),
    }
}

/// Read a file, or stdin for `-`.
fn read_input(path: &str, what: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let read = if path == "-" {
        std::io::stdin().lock().read_to_end(&mut bytes).map(|_| ())
    } else {
        std::fs::read(path).map(|content| bytes = content)
    };
    read.map_err(|e| AkError::Usage(format!("Can't read {what} {path}: {e}")))?;
    Ok(bytes)
}

/// The body `POST /api/v1/admin/config/import` takes: `{"document", "secrets"}`. A
/// bare document is wrapped, and the secrets file's values go in `secrets`.
fn import_body(import: &ImportArgs) -> Result<Value> {
    if import.file == "-" && import.secrets_file.as_deref() == Some("-") {
        return Err(AkError::Usage(
            "The document and --secrets-file can't both be read from stdin".into(),
        )
        .into());
    }
    let bytes = read_input(&import.file, "the document")?;
    let given: Value = serde_json::from_slice(&bytes)
        .map_err(|e| AkError::Usage(format!("{} isn't JSON: {e}", import.file)))?;
    if !given.is_object() {
        return Err(AkError::Usage(format!("{} must be a JSON object", import.file)).into());
    }
    let mut body = if given.get("document").is_some() {
        given
    } else {
        json!({ "document": given })
    };
    if let Some(path) = &import.secrets_file {
        let bytes = read_input(path, "--secrets-file")?;
        let secrets: serde_json::Map<String, Value> =
            serde_json::from_slice(&bytes).map_err(|e| {
                AkError::Usage(format!(
                    "--secrets-file must be a JSON object from each secret_ref name to its \
                     value: {e}"
                ))
            })?;
        if let Some((name, _)) = secrets.iter().find(|(_, v)| !v.is_string()) {
            return Err(AkError::Usage(format!(
                "--secrets-file: the value of {name} must be a string"
            ))
            .into());
        }
        let into = body
            .as_object_mut()
            .expect("an object")
            .entry("secrets")
            .or_insert_with(|| json!({}));
        let Some(into) = into.as_object_mut() else {
            return Err(AkError::Usage(format!(
                "{}: `secrets` must be a JSON object to add --secrets-file to",
                import.file
            ))
            .into());
        };
        into.extend(secrets);
    }
    Ok(body)
}

/// Send the document with `mode`. The plan comes back typed, and as sent.
async fn import(
    body: &Value,
    mode: &str,
    prune: bool,
    command: &str,
    global: &GlobalArgs,
) -> Result<(ConfigPlan, Vec<u8>)> {
    let action = if mode == "plan" {
        "plan the configuration"
    } else {
        "apply the configuration"
    };
    let mut query = vec![("mode", mode.to_string())];
    if prune {
        query.push(("prune", "true".to_string()));
    }
    let bytes = send(
        reqwest::Method::POST,
        &["admin", "config", "import"],
        &query,
        Some(body),
        action,
        command,
        global,
    )
    .await?;
    let plan: ConfigPlan = serde_json::from_slice(&bytes).map_err(|e| bad_response(action, e))?;
    Ok((plan, bytes))
}

fn has_changes(plan: &ConfigPlan) -> bool {
    !plan.create.is_empty() || !plan.update.is_empty()
}

/// What a plan says, for a person.
fn plan_text(plan: &ConfigPlan, prune: bool) -> String {
    let mut lines = Vec::new();
    for key in &plan.create {
        lines.push(format!("+ create {key}"));
    }
    for update in &plan.update {
        lines.push(format!(
            "~ update {}: {}",
            update.key,
            update.changes.join(", ")
        ));
    }
    if prune {
        for key in &plan.not_in_document {
            lines.push(format!("- delete {key}"));
        }
    }
    if lines.is_empty() {
        lines.push("No changes.".to_string());
    }
    lines.push(String::new());
    lines.push(format!(
        "Create: {}  Update: {}  Unchanged: {}  Not in the document: {}{}",
        plan.create.len(),
        plan.update.len(),
        plan.unchanged.len(),
        plan.not_in_document.len(),
        if prune { " (to delete)" } else { " (kept)" },
    ));
    for name in &plan.missing_secrets {
        lines.push(format!("Missing secret: {name}"));
    }
    for error in &plan.errors {
        lines.push(format!("Error: {error}"));
    }
    if plan.applied {
        lines.push("Applied.".to_string());
    }
    lines.join("\n")
}

fn print_plan(plan: &ConfigPlan, raw: &[u8], prune: bool, global: &GlobalArgs) {
    if matches!(global.format, OutputFormat::Quiet) {
        for key in plan.create.iter().chain(plan.update.iter().map(|u| &u.key)) {
            println!("{key}");
        }
        return;
    }
    println!(
        "{}",
        output::render_raw(
            Some(raw),
            plan,
            &global.format,
            Some(plan_text(plan, prune))
        )
    );
}

/// The error for a document the server says can't be applied as it is.
fn not_applicable(plan: &ConfigPlan) -> miette::Report {
    let mut reasons = Vec::new();
    if !plan.missing_secrets.is_empty() {
        reasons.push(format!(
            "{} secret(s) missing: {}. Give them with --secrets-file",
            plan.missing_secrets.len(),
            plan.missing_secrets.join(", ")
        ));
    }
    if !plan.errors.is_empty() {
        reasons.push(format!("{} change(s) it can't make", plan.errors.len()));
    }
    if reasons.is_empty() {
        reasons.push("the server says so".to_string());
    }
    reported_failure(&format!(
        "The document can't be applied: {}.",
        reasons.join("; ")
    ))
}

async fn plan(import_args: ImportArgs, global: &GlobalArgs) -> Result<()> {
    let body = import_body(&import_args)?;
    let spinner = output::spinner("Planning...");
    let result = import(
        &body,
        "plan",
        import_args.prune,
        "admin config plan",
        global,
    )
    .await;
    spinner.finish_and_clear();
    let (plan, raw) = result?;
    print_plan(&plan, &raw, import_args.prune, global);
    if !plan.applicable {
        return Err(not_applicable(&plan));
    }
    Ok(())
}

/// The prompt for an apply, from its plan.
fn apply_prompt(plan: &ConfigPlan, prune: bool) -> String {
    let mut parts = Vec::new();
    if !plan.create.is_empty() {
        parts.push(format!(
            "create {} repositories ({})",
            plan.create.len(),
            plan.create.join(", ")
        ));
    }
    if !plan.update.is_empty() {
        let keys: Vec<&str> = plan.update.iter().map(|u| u.key.as_str()).collect();
        parts.push(format!(
            "update the settings of {} ({})",
            plan.update.len(),
            keys.join(", ")
        ));
    }
    if prune && !plan.not_in_document.is_empty() {
        parts.push(format!(
            "DELETE {} repositories the document doesn't name, with everything in them ({})",
            plan.not_in_document.len(),
            plan.not_in_document.join(", ")
        ));
    }
    format!("Apply this document? It will {}", parts.join(", and "))
}

async fn apply(import_args: ImportArgs, yes: bool, global: &GlobalArgs) -> Result<()> {
    let prune = import_args.prune;
    let plain = if prune {
        "Apply this document, and delete every repository on this instance it doesn't name?"
    } else {
        "Apply this document to this instance?"
    };
    // Before anything is read or sent: --no-input without --yes sends nothing.
    ensure_can_confirm(plain, yes, global.no_input)?;
    let body = import_body(&import_args)?;

    if !yes {
        let spinner = output::spinner("Planning...");
        let result = import(&body, "plan", prune, "admin config apply", global).await;
        spinner.finish_and_clear();
        let (plan, raw) = result?;
        if !plan.applicable {
            print_plan(&plan, &raw, prune, global);
            return Err(not_applicable(&plan));
        }
        let deletes = prune && !plan.not_in_document.is_empty();
        if !has_changes(&plan) && !deletes {
            if !matches!(global.format, OutputFormat::Quiet) {
                eprintln!("Nothing to change: the instance already matches the document.");
            }
            return Ok(());
        }
        if matches!(global.format, OutputFormat::Table) {
            eprintln!("{}", output::sanitize_terminal(&plan_text(&plan, prune)));
        }
        if !confirm_action(&apply_prompt(&plan, prune), yes, global.no_input)? {
            return Ok(());
        }
    }

    let spinner = output::spinner("Applying...");
    let result = import(&body, "apply", prune, "admin config apply", global).await;
    spinner.finish_and_clear();
    let (plan, raw) = result?;
    print_plan(&plan, &raw, prune, global);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use artifact_keeper_sdk::types::ConfigPlanUpdate;

    fn plan() -> ConfigPlan {
        ConfigPlan {
            applicable: true,
            applied: false,
            create: vec!["new".into()],
            errors: vec![],
            missing_secrets: vec![],
            not_in_document: vec!["old".into()],
            unchanged: vec!["same".into()],
            update: vec![ConfigPlanUpdate {
                key: "changed".into(),
                changes: vec!["description".into(), "quota_bytes".into()],
            }],
        }
    }

    #[test]
    fn the_plan_reads_as_a_diff() {
        let text = plan_text(&plan(), false);
        assert!(text.contains("+ create new"), "{text}");
        assert!(
            text.contains("~ update changed: description, quota_bytes"),
            "{text}"
        );
        assert!(!text.contains("- delete old"), "{text}");
        assert!(text.contains("Not in the document: 1 (kept)"), "{text}");
        let pruned = plan_text(&plan(), true);
        assert!(pruned.contains("- delete old"), "{pruned}");
    }

    #[test]
    fn the_prompt_says_what_prune_deletes() {
        let prompt = apply_prompt(&plan(), false);
        assert!(prompt.contains("create 1 repositories (new)"), "{prompt}");
        assert!(
            prompt.contains("update the settings of 1 (changed)"),
            "{prompt}"
        );
        assert!(!prompt.contains("DELETE"), "{prompt}");
        let prompt = apply_prompt(&plan(), true);
        assert!(prompt.contains("DELETE 1 repositories"), "{prompt}");
        assert!(prompt.contains("(old)"), "{prompt}");
    }

    fn args(dir: &tempfile::TempDir, document: &str, secrets: Option<&str>) -> ImportArgs {
        let file = dir.path().join("doc.json");
        std::fs::write(&file, document).unwrap();
        let secrets_file = secrets.map(|text| {
            let path = dir.path().join("secrets.json");
            std::fs::write(&path, text).unwrap();
            path.to_string_lossy().to_string()
        });
        ImportArgs {
            file: file.to_string_lossy().to_string(),
            secrets_file,
            prune: false,
        }
    }

    #[test]
    fn a_bare_document_is_wrapped_and_takes_the_secrets() {
        let dir = tempfile::TempDir::new().unwrap();
        let body = import_body(&args(
            &dir,
            r#"{"schema_version":1,"repositories":[]}"#,
            Some(r#"{"upstream_auth/r":"pw"}"#),
        ))
        .unwrap();
        assert_eq!(
            body,
            json!({"document": {"schema_version": 1, "repositories": []},
                   "secrets": {"upstream_auth/r": "pw"}})
        );
    }

    #[test]
    fn a_wrapped_body_is_sent_as_it_is_with_the_secrets_added() {
        let dir = tempfile::TempDir::new().unwrap();
        let body = import_body(&args(
            &dir,
            r#"{"document":{"schema_version":1},"secrets":{"a":"1"}}"#,
            Some(r#"{"b":"2"}"#),
        ))
        .unwrap();
        assert_eq!(
            body,
            json!({"document": {"schema_version": 1}, "secrets": {"a": "1", "b": "2"}})
        );
        let body = import_body(&args(&dir, r#"{"document":{}}"#, None)).unwrap();
        assert_eq!(body, json!({"document": {}}));
    }

    #[test]
    fn a_bad_document_or_secrets_file_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        for (document, extra, needle) in [
            ("not json", None, "isn't JSON"),
            ("[1]", None, "must be a JSON object"),
            ("{}", Some("[1]"), "--secrets-file must be a JSON object"),
            ("{}", Some(r#"{"a":1}"#), "the value of a must be a string"),
        ] {
            let err = import_body(&args(&dir, document, extra))
                .unwrap_err()
                .to_string();
            assert!(err.contains(needle), "case {needle}: {err}");
        }
    }
}
