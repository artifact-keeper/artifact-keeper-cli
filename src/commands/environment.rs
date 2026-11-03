use artifact_keeper_sdk::ClientEnvironmentsExt;
use clap::Subcommand;
use miette::Result;
use serde_json::{Map, Value};
use uuid::Uuid;

use super::banner::parse_time;
use super::bundle::read_input;
use super::client::client_for;
use super::helpers::{confirm_action, emit_mutation, emit_mutation_raw, new_table, or_since_1_11};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

/// The group, for the message on a server older than these routes.
const COMMAND: &str = "environment";

#[derive(Subcommand)]
pub enum EnvironmentCommand {
    /// Store a lockfile as an environment. Ingesting the same name again replaces it
    Ingest {
        /// Repository key
        repo: String,

        /// Path to pixi.lock, conda-lock.yml, package-lock.json, Cargo.lock, poetry.lock
        /// or uv.lock, or - for stdin
        lockfile: String,

        /// Name that selects the parser (default: the lockfile's own). Required with stdin
        #[arg(long)]
        filename: Option<String>,

        /// Environment name in the repository (default: the file name)
        #[arg(long)]
        name: Option<String>,
    },

    /// List the environments stored in a repository
    List {
        /// Repository key
        repo: String,
    },

    /// Show an environment and its per-scope counts
    Show {
        /// Repository key
        repo: String,

        /// Environment name or ID
        environment: String,
    },

    /// Delete an environment
    Delete {
        /// Repository key
        repo: String,

        /// Environment name or ID
        environment: String,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Show the advisories currently affecting an environment
    Advisories {
        /// Repository key
        repo: String,

        /// Environment name or ID
        environment: String,
    },

    /// Find the stored environments that contain a component, and what pulls it in
    Lookup {
        /// Component purl, for example pkg:pypi/requests@2.31.0
        purl: String,

        /// Most inclusion paths to return per hit, 1 to 64 (server default: 8)
        #[arg(long)]
        max_paths: Option<u64>,
    },

    /// List environments becoming or ceasing to be affected by advisories, newest first
    AdvisoryTransitions {
        /// Only this advisory ID, for example GHSA-j8r2-6p8f-2345
        #[arg(long)]
        advisory: Option<String>,

        /// new-affected or no-longer-affected
        #[arg(long)]
        kind: Option<String>,

        /// Only those detected at or after this RFC 3339 time
        #[arg(long, value_name = "TIME")]
        since: Option<String>,

        /// Only those detected at or before this RFC 3339 time
        #[arg(long, value_name = "TIME")]
        until: Option<String>,

        /// Page size, 1 to 500 (server default: 100)
        #[arg(long)]
        limit: Option<i64>,
    },
}

impl EnvironmentCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Ingest {
                repo,
                lockfile,
                filename,
                name,
            } => ingest(&repo, &lockfile, filename, name, global).await,
            Self::List { repo } => list(&repo, global).await,
            Self::Show { repo, environment } => show(&repo, &environment, global).await,
            Self::Delete {
                repo,
                environment,
                yes,
            } => delete(&repo, &environment, yes, global).await,
            Self::Advisories { repo, environment } => advisories(&repo, &environment, global).await,
            Self::Lookup { purl, max_paths } => lookup(&purl, max_paths, global).await,
            Self::AdvisoryTransitions {
                advisory,
                kind,
                since,
                until,
                limit,
            } => {
                let since = parse_time(since.as_deref(), "--since")?;
                let until = parse_time(until.as_deref(), "--until")?;
                let client = client_for(global)?;
                let spinner = output::spinner("Fetching advisory transitions...");
                let mut req = client.list_advisory_transitions();
                if let Some(advisory) = advisory {
                    req = req.advisory(advisory);
                }
                if let Some(kind) = kind {
                    req = req.kind(kind);
                }
                if let Some(since) = since {
                    req = req.since(since);
                }
                if let Some(until) = until {
                    req = req.until(until);
                }
                if let Some(limit) = limit {
                    req = req.limit(limit);
                }
                let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
                let body = or_since_1_11(resp, "list advisory transitions", COMMAND, global)
                    .await?
                    .into_inner();
                spinner.finish_and_clear();
                print_rows(
                    raw.as_deref(),
                    &body,
                    "transitions",
                    "No advisory transitions found.",
                    |t| t["environment"]["id"].clone(),
                    transitions_table,
                    global,
                );
                Ok(())
            }
        }
    }
}

/// The name that selects the server's parser, from `--filename` or the path.
pub(super) fn parser_filename(lockfile: &str, filename: Option<String>) -> Result<String> {
    if let Some(filename) = filename {
        return Ok(filename);
    }
    if lockfile == "-" {
        return Err(AkError::Usage(
            "Reading a lockfile from stdin needs --filename, for example --filename uv.lock"
                .to_string(),
        )
        .into());
    }
    std::path::Path::new(lockfile)
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| AkError::Usage(format!("Can't tell the file name of {lockfile}")).into())
}

/// Turn what a user typed for an environment into its ID: a UUID is used as it is,
/// and anything else is looked up as a name in the repository.
async fn resolve_environment_id(
    client: &artifact_keeper_sdk::Client,
    repo: &str,
    environment: &str,
    global: &GlobalArgs,
) -> Result<Uuid> {
    if let Ok(id) = environment.parse() {
        return Ok(id);
    }
    let body = or_since_1_11(
        client.list_environments().key(repo).send().await,
        &format!("list environments in '{repo}'"),
        COMMAND,
        global,
    )
    .await?;
    rows(&body, "environments")
        .iter()
        .find(|e| e["name"] == environment)
        .and_then(|e| e["id"].as_str())
        .and_then(|id| id.parse().ok())
        .ok_or_else(|| {
            AkError::NotFound(format!(
                "No environment named '{environment}' in '{repo}'. \
                 Run `ak environment list {repo}` to see them."
            ))
            .into()
        })
}

async fn ingest(
    repo: &str,
    lockfile: &str,
    filename: Option<String>,
    name: Option<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let filename = parser_filename(lockfile, filename)?;
    let bytes = read_input(lockfile)?;
    let client = client_for(global)?;
    let spinner = output::spinner("Storing environment...");
    let mut req = client
        .ingest_environment()
        .key(repo)
        .filename(filename)
        .body(bytes);
    if let Some(name) = name {
        req = req.name(name);
    }
    let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
    let stored = or_since_1_11(resp, "ingest environment", COMMAND, global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &stored,
        text(&stored["id"]),
        &ingest_message(&stored),
        global,
    );
    Ok(())
}

async fn list(repo: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching environments...");
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.list_environments().key(repo).send()).await;
    let body = or_since_1_11(resp, "list environments", COMMAND, global)
        .await?
        .into_inner();
    spinner.finish_and_clear();
    print_rows(
        raw.as_deref(),
        &body,
        "environments",
        "No environments found.",
        |e| e["id"].clone(),
        environments_table,
        global,
    );
    Ok(())
}

async fn show(repo: &str, environment: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = resolve_environment_id(&client, repo, environment, global).await?;
    let spinner = output::spinner("Fetching environment...");
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.get_environment().key(repo).id(id).send()).await;
    let body = or_since_1_11(resp, "get environment", COMMAND, global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", text(&body["id"]));
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &body,
            &global.format,
            Some(environment_detail(&body))
        )
    );
    Ok(())
}

async fn delete(
    repo: &str,
    environment: &str,
    skip_confirm: bool,
    global: &GlobalArgs,
) -> Result<()> {
    if !confirm_action(
        &format!("Delete environment {environment} from {repo}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }
    let client = client_for(global)?;
    let id = resolve_environment_id(&client, repo, environment, global).await?;
    let spinner = output::spinner("Deleting environment...");
    or_since_1_11(
        client.delete_environment().key(repo).id(id).send().await,
        "delete environment",
        COMMAND,
        global,
    )
    .await?;
    spinner.finish_and_clear();

    let id = id.to_string();
    emit_mutation(
        &serde_json::json!({ "id": id, "status": "deleted" }),
        &id,
        &format!("Environment {environment} deleted from {repo}."),
        global,
    );
    Ok(())
}

async fn advisories(repo: &str, environment: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let id = resolve_environment_id(&client, repo, environment, global).await?;
    let spinner = output::spinner("Fetching advisories...");
    let (resp, raw) = artifact_keeper_sdk::raw::capture(
        client.get_environment_advisories().key(repo).id(id).send(),
    )
    .await;
    let body = or_since_1_11(resp, "get environment advisories", COMMAND, global)
        .await?
        .into_inner();
    spinner.finish_and_clear();
    print_rows(
        raw.as_deref(),
        &body,
        "affected",
        "No advisories affect this environment.",
        |a| a["advisory"]["id"].clone(),
        advisories_table,
        global,
    );
    Ok(())
}

async fn lookup(purl: &str, max_paths: Option<u64>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Looking up component...");
    let mut req = client.lookup_environments().purl(purl);
    if let Some(max_paths) = max_paths {
        req = req.max_paths(max_paths);
    }
    let (resp, raw) = artifact_keeper_sdk::raw::capture(req.send()).await;
    let body = or_since_1_11(resp, "look up environments", COMMAND, global)
        .await?
        .into_inner();
    spinner.finish_and_clear();

    if body.get("truncated") == Some(&Value::Bool(true))
        && matches!(global.format, OutputFormat::Table)
    {
        eprintln!("The server cut this list short: not every environment is shown.");
    }
    print_rows(
        raw.as_deref(),
        &body,
        "hits",
        "No stored environment contains this component.",
        |h| h["environment"]["id"].clone(),
        hits_table,
        global,
    );
    Ok(())
}

/// The rows of an untyped list body. The spec declares these responses as bare
/// objects, so a field is read by name and a missing one shows as `-`.
fn rows<'a>(body: &'a Map<String, Value>, field: &str) -> &'a [Value] {
    body.get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn print_rows(
    raw: Option<&[u8]>,
    body: &Map<String, Value>,
    field: &str,
    empty: &str,
    quiet: impl Fn(&Value) -> Value,
    table: impl Fn(&[Value]) -> String,
    global: &GlobalArgs,
) {
    let items = rows(body, field);
    if items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("{empty}");
        return;
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for item in items {
            println!("{}", text(&quiet(item)));
        }
        return;
    }
    println!(
        "{}",
        output::render_raw(raw, body, &global.format, Some(table(items)))
    );
}

/// A JSON value as a table cell.
fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("-")
}

fn number(value: &Value) -> String {
    value
        .as_i64()
        .map(|n| n.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn package(value: &Value) -> String {
    match value["version"].as_str() {
        Some(version) => format!("{}@{version}", text(&value["name"])),
        None => text(&value["name"]).to_string(),
    }
}

/// A lockfile with no named environments or platforms has one unnamed scope.
fn scope(value: &Value) -> String {
    match (value["environment"].as_str(), value["platform"].as_str()) {
        (None, None) => "-".to_string(),
        (environment, platform) => {
            format!("{}/{}", environment.unwrap_or("-"), platform.unwrap_or("-"))
        }
    }
}

fn ingest_message(stored: &Map<String, Value>) -> String {
    let verb = if stored.get("replaced") == Some(&Value::Bool(true)) {
        "replaced"
    } else {
        "stored"
    };
    let name = stored.get("name").map_or("-", text);
    let id = stored.get("id").map_or("-", text);
    let empty = Value::Null;
    let summary = stored.get("summary").unwrap_or(&empty);
    format!(
        "Environment '{name}' {verb} (ID: {id}): {} packages, scopes: {}.",
        number(&summary["distinctPackages"]),
        number(&summary["scopes"]),
    )
}

fn environments_table(items: &[Value]) -> String {
    let mut table = new_table(vec![
        "ID", "NAME", "FORMAT", "PACKAGES", "SCOPES", "UPDATED",
    ]);
    for e in items {
        table.add_row(vec![
            text(&e["id"]).to_string(),
            text(&e["name"]).to_string(),
            text(&e["lockfileFormat"]).to_string(),
            number(&e["summary"]["distinctPackages"]),
            number(&e["summary"]["scopes"]),
            text(&e["updatedAt"]).to_string(),
        ]);
    }
    table.to_string()
}

fn environment_detail(body: &Map<String, Value>) -> String {
    let get = |field: &str| body.get(field).map_or("-", text);
    let empty = Value::Null;
    let summary = body.get("summary").unwrap_or(&empty);
    let mut out = format!(
        "ID:       {}\n\
         Name:     {}\n\
         Format:   {}\n\
         SHA-256:  {}\n\
         Packages: {}\n\
         Edges:    {}\n\
         Unparsed: {}\n\
         Created:  {}\n\
         Updated:  {}",
        get("id"),
        get("name"),
        get("lockfileFormat"),
        get("contentSha256"),
        number(&summary["distinctPackages"]),
        number(&summary["edges"]),
        number(&summary["unparsed"]),
        get("createdAt"),
        get("updatedAt"),
    );
    let scopes = rows(body, "scopes");
    if !scopes.is_empty() {
        let mut table = new_table(vec!["ENVIRONMENT", "PLATFORM", "PACKAGES", "EDGES"]);
        for s in scopes {
            table.add_row(vec![
                text(&s["environment"]).to_string(),
                text(&s["platform"]).to_string(),
                number(&s["memberships"]),
                number(&s["edges"]),
            ]);
        }
        out.push_str(&format!("\n{table}"));
    }
    out
}

fn advisories_table(items: &[Value]) -> String {
    let mut table = new_table(vec![
        "ADVISORY",
        "SEVERITY",
        "PACKAGE",
        "FIXED IN",
        "AFFECTED SINCE",
    ]);
    for a in items {
        table.add_row(vec![
            text(&a["advisory"]["id"]).to_string(),
            text(&a["advisory"]["severity"]).to_string(),
            package(&a["package"]),
            text(&a["advisory"]["fixedVersion"]).to_string(),
            text(&a["affectedSince"]).to_string(),
        ]);
    }
    table.to_string()
}

fn hits_table(items: &[Value]) -> String {
    let mut table = new_table(vec![
        "REPOSITORY",
        "ENVIRONMENT",
        "SCOPE",
        "PACKAGE",
        "PULLED IN BY",
    ]);
    for h in items {
        let paths = h["paths"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|path| {
                path.as_array()
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                    .iter()
                    .map(text)
                    .collect::<Vec<_>>()
                    .join(" > ")
            })
            .collect::<Vec<_>>()
            .join("\n");
        table.add_row(vec![
            text(&h["repository"]["key"]).to_string(),
            text(&h["environment"]["name"]).to_string(),
            scope(&h["scope"]),
            package(&h["package"]),
            paths,
        ]);
    }
    table.to_string()
}

fn transitions_table(items: &[Value]) -> String {
    let mut table = new_table(vec![
        "DETECTED",
        "KIND",
        "ADVISORY",
        "SEVERITY",
        "REPOSITORY",
        "ENVIRONMENT",
        "PACKAGE",
    ]);
    for t in items {
        table.add_row(vec![
            text(&t["detectedAt"]).to_string(),
            text(&t["kind"]).to_string(),
            text(&t["advisory"]["id"]).to_string(),
            text(&t["advisory"]["severity"]).to_string(),
            text(&t["repository"]["key"]).to_string(),
            text(&t["environment"]["name"]).to_string(),
            package(&t["package"]),
        ]);
    }
    table.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_parser_name_comes_from_the_flag_or_the_path() {
        assert_eq!(parser_filename("/tmp/x/uv.lock", None).unwrap(), "uv.lock");
        assert_eq!(
            parser_filename("/tmp/x/my.lock", Some("uv.lock".to_string())).unwrap(),
            "uv.lock"
        );
        assert!(parser_filename("-", None).is_err());
        assert_eq!(
            parser_filename("-", Some("uv.lock".to_string())).unwrap(),
            "uv.lock"
        );
    }

    #[test]
    fn a_table_cell_with_no_value_is_a_dash() {
        let row = json!({"name": "e"});
        let table = environments_table(&[row]);
        assert!(table.contains('e') && table.contains('-'));
    }

    #[test]
    fn a_package_shows_its_version_when_it_has_one() {
        assert_eq!(package(&json!({"name": "a", "version": "1"})), "a@1");
        assert_eq!(package(&json!({"name": "a", "version": null})), "a");
    }

    #[test]
    fn hits_show_each_inclusion_path() {
        let hit = json!({
            "repository": {"key": "r"},
            "environment": {"name": "e"},
            "scope": {"environment": "default", "platform": "linux-64"},
            "package": {"name": "c", "version": "2"},
            "paths": [["a@1", "c@2"], ["b@1", "c@2"]],
        });
        let table = hits_table(&[hit]);
        assert!(
            table.contains("a@1 > c@2") && table.contains("b@1 > c@2"),
            "{table}"
        );
        assert!(table.contains("default/linux-64"), "{table}");
    }

    #[test]
    fn the_ingest_message_says_whether_it_replaced() {
        let body = |replaced| {
            json!({
                "id": "i", "name": "n", "replaced": replaced,
                "summary": {"distinctPackages": 3, "scopes": 1},
            })
            .as_object()
            .unwrap()
            .clone()
        };
        assert!(ingest_message(&body(true)).contains("'n' replaced"));
        assert!(ingest_message(&body(false)).contains("3 packages, scopes: 1"));
    }
}
