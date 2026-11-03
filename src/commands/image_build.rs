use artifact_keeper_sdk::ClientImageBuildsExt;
use artifact_keeper_sdk::types::{
    BaseImageInfo, ImageBuildResponse, ImageBuildSettingsResponse, ImageInspect,
    RenderImageBuildResponse,
};
use clap::{Args, Subcommand};
use miette::Result;
use serde_json::{Map, Value, json};

use super::bundle::read_input;
use super::client::{client_for, raw_http_client, resolve_base_url_and_auth};
use super::helpers::{emit_mutation_raw, new_table, parse_uuid, raw_err, sdk_err};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat, format_bytes};

#[derive(Subcommand)]
pub enum ImageBuildCommand {
    /// List a repository's builds, newest first
    List {
        /// Repository key
        repo: String,
    },

    /// Show a build
    Show {
        /// Repository key
        repo: String,

        /// Build ID
        id: String,
    },

    /// Print a build's log so far
    Log {
        /// Repository key
        repo: String,

        /// Build ID
        id: String,
    },

    /// Queue a build. Needs a server with a builder configured: see `settings`
    Create {
        /// Local container repository to push into
        repo: String,

        /// Image path within the repository, for example team/app
        image: String,

        /// Tag to push
        tag: String,

        #[command(flatten)]
        spec: SpecArgs,
    },

    /// Check a spec and print the Containerfile the server would build, without building
    Render {
        /// Container repository
        repo: String,

        #[command(flatten)]
        spec: SpecArgs,
    },

    /// Show whether builds are available here, and the policy that applies
    Settings {
        /// Repository key
        repo: String,
    },

    /// Show what this registry knows about a base image
    BaseInfo {
        /// Repository being built into
        repo: String,

        /// Base image as a spec names it, for example python:3.12-slim
        image: String,
    },

    /// Describe a pushed image: config, history, layers and provenance
    Inspect {
        /// Repository key
        repo: String,

        /// Image path within the repository
        image: String,

        /// Tag or sha256: digest
        reference: String,
    },
}

/// What to build. Flags are set on top of `--spec`.
#[derive(Args, Default)]
pub struct SpecArgs {
    /// The whole spec as JSON: inline, @file, or @- for stdin
    #[arg(long, value_name = "JSON")]
    spec: Option<String>,

    /// Image to build on, for example python:3.12-slim
    #[arg(long)]
    base_image: Option<String>,

    /// apt package (repeat)
    #[arg(long, value_name = "PACKAGE")]
    apt: Vec<String>,

    /// pip requirement (repeat)
    #[arg(long, value_name = "REQUIREMENT")]
    pip: Vec<String>,

    /// conda package (repeat)
    #[arg(long, value_name = "PACKAGE")]
    conda: Vec<String>,

    /// conda channel (repeat)
    #[arg(long, value_name = "CHANNEL")]
    conda_channel: Vec<String>,

    /// Install steps as a JSON array, in order: inline, @file, or @- for stdin
    #[arg(long, value_name = "JSON")]
    packages: Option<String>,

    /// Environment variable baked into the image (repeat)
    #[arg(long, value_name = "KEY=VALUE")]
    env: Vec<String>,

    /// OCI label baked into the image (repeat)
    #[arg(long, value_name = "KEY=VALUE")]
    label: Vec<String>,

    /// Raw RUN line (repeat). The server must allow these
    #[arg(long, value_name = "LINE")]
    run: Vec<String>,

    /// User the image runs as. Required when installing system packages
    #[arg(long)]
    user: Option<String>,

    /// Working directory the image starts in
    #[arg(long)]
    workdir: Option<String>,

    /// Build pip packages in a separate stage, so build tooling never ships
    #[arg(long)]
    multistage: bool,

    /// A whole Dockerfile instead (path, or - for stdin). The server must allow these
    #[arg(long, value_name = "PATH")]
    dockerfile: Option<String>,
}

impl ImageBuildCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { repo } => list(&repo, global).await,
            Self::Show { repo, id } => show(&repo, &id, global).await,
            Self::Log { repo, id } => log(&repo, &id, global).await,
            Self::Create {
                repo,
                image,
                tag,
                spec,
            } => create(&repo, &image, &tag, spec, global).await,
            Self::Render { repo, spec } => render(&repo, spec, global).await,
            Self::Settings { repo } => settings(&repo, global).await,
            Self::BaseInfo { repo, image } => base_info(&repo, &image, global).await,
            Self::Inspect {
                repo,
                image,
                reference,
            } => inspect(&repo, &image, &reference, global).await,
        }
    }
}

/// JSON given inline, as @file, or as @- for stdin.
fn json_arg(value: &str, flag: &str) -> Result<Value> {
    let bytes = match value.strip_prefix('@') {
        Some(path) => read_input(path)?,
        None => value.as_bytes().to_vec(),
    };
    serde_json::from_slice(&bytes)
        .map_err(|e| AkError::Usage(format!("{flag} isn't valid JSON: {e}")).into())
}

fn key_values(pairs: &[String], flag: &str) -> Result<Map<String, Value>> {
    pairs
        .iter()
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) if !key.is_empty() => Ok((key.to_string(), json!(value))),
            _ => Err(AkError::Usage(format!("{flag} needs KEY=VALUE, not '{pair}'")).into()),
        })
        .collect()
}

/// The spec as JSON: `--spec` with the other flags set on top. It stays JSON, not
/// the SDK's struct, so a field this CLI doesn't know yet still reaches the server.
fn build_spec(args: SpecArgs) -> Result<Value> {
    let mut spec = match args.spec.as_deref() {
        Some(value) => match json_arg(value, "--spec")? {
            Value::Object(map) => map,
            _ => {
                return Err(AkError::Usage("--spec must be a JSON object".to_string()).into());
            }
        },
        None => Map::new(),
    };
    let mut set = |field: &str, value: Value| {
        spec.insert(field.to_string(), value);
    };
    if let Some(base_image) = args.base_image {
        set("base_image", json!(base_image));
    }
    for (field, values) in [
        ("apt", args.apt),
        ("pip", args.pip),
        ("conda", args.conda),
        ("conda_channels", args.conda_channel),
        ("run", args.run),
    ] {
        if !values.is_empty() {
            set(field, json!(values));
        }
    }
    if let Some(packages) = args.packages.as_deref() {
        set("packages", json_arg(packages, "--packages")?);
    }
    if !args.env.is_empty() {
        set("env", Value::Object(key_values(&args.env, "--env")?));
    }
    if !args.label.is_empty() {
        set("labels", Value::Object(key_values(&args.label, "--label")?));
    }
    if let Some(user) = args.user {
        set("user", json!(user));
    }
    if let Some(workdir) = args.workdir {
        set("workdir", json!(workdir));
    }
    if args.multistage {
        set("multistage", json!(true));
    }
    if let Some(path) = args.dockerfile.as_deref() {
        let text = String::from_utf8(read_input(path)?)
            .map_err(|_| AkError::Usage(format!("{path} isn't UTF-8 text")))?;
        set("dockerfile", json!(text));
    }
    Ok(Value::Object(spec))
}

/// A URL under `/api/v1/repositories/<repo>/image-builds`.
fn builds_url(base: &str, repo: &str, tail: &[&str]) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(base)
        .map_err(|e| AkError::ConfigError(format!("Invalid instance URL {base}: {e}")))?;
    url.path_segments_mut()
        .map_err(|_| AkError::ConfigError(format!("Invalid instance URL {base}")))?
        .pop_if_empty()
        .extend(["api", "v1", "repositories", repo, "image-builds"])
        .extend(tail);
    Ok(url)
}

/// POST a spec. Raw, because the SDK's request type would drop a spec field it
/// doesn't know, and `--spec` takes whatever the server takes.
async fn post_spec(
    repo: &str,
    tail: &[&str],
    body: &Value,
    action: &str,
    global: &GlobalArgs,
) -> Result<Vec<u8>> {
    let (base_url, auth) = resolve_base_url_and_auth(global)?;
    let resp = raw_http_client()?
        .post(builds_url(&base_url, repo, tail)?)
        .header(reqwest::header::AUTHORIZATION, &auth)
        .json(body)
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("{action} failed: {e}")))?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| AkError::NetworkError(format!("{action} failed: {e}")))?;
    if !status.is_success() {
        return Err(raw_err(action, status, &String::from_utf8_lossy(&bytes)).into());
    }
    Ok(bytes.to_vec())
}

async fn list(repo: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching image builds...");
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.list_image_builds().key(repo).send()).await;
    let list = resp
        .map_err(|e| sdk_err("list image builds", e))?
        .into_inner();
    spinner.finish_and_clear();

    if list.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No image builds found.");
        return Ok(());
    }
    if matches!(global.format, OutputFormat::Quiet) {
        for build in &list.items {
            println!("{}", build.id);
        }
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &list,
            &global.format,
            Some(builds_table(&list.items))
        )
    );
    Ok(())
}

async fn show(repo: &str, id: &str, global: &GlobalArgs) -> Result<()> {
    let build_id = parse_uuid(id, "build")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching image build...");
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.get_image_build().key(repo).id(build_id).send())
            .await;
    let build = resp
        .map_err(|e| sdk_err("get image build", e))?
        .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", build.id);
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &build,
            &global.format,
            Some(build_detail(&build))
        )
    );
    Ok(())
}

/// Raw, because the log is text/plain and the spec declares no body for it, so
/// the SDK throws it away.
async fn log(repo: &str, id: &str, global: &GlobalArgs) -> Result<()> {
    let build_id = parse_uuid(id, "build")?.to_string();
    let (base_url, auth) = resolve_base_url_and_auth(global)?;
    let spinner = output::spinner("Fetching build log...");
    let resp = raw_http_client()?
        .get(builds_url(&base_url, repo, &[&build_id, "log"])?)
        .header(reqwest::header::AUTHORIZATION, &auth)
        .send()
        .await
        .map_err(|e| AkError::NetworkError(format!("Get build log failed: {e}")))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| AkError::NetworkError(format!("Get build log failed: {e}")))?;
    spinner.finish_and_clear();

    if !status.is_success() {
        return Err(raw_err("Get build log", status, &text).into());
    }
    // A build log carries what the build's commands printed. Don't let that drive
    // the user's terminal, but leave it alone in a pipe.
    if console::Term::stdout().is_term() {
        print!("{}", output::sanitize_terminal(&text));
    } else {
        print!("{text}");
    }
    Ok(())
}

async fn create(
    repo: &str,
    image: &str,
    tag: &str,
    spec: SpecArgs,
    global: &GlobalArgs,
) -> Result<()> {
    let body = json!({"image": image, "tag": tag, "spec": build_spec(spec)?});
    let spinner = output::spinner("Queueing image build...");
    let raw = post_spec(repo, &[], &body, "Create image build", global).await;
    spinner.finish_and_clear();
    let raw = raw?;
    let build: ImageBuildResponse = serde_json::from_slice(&raw)
        .map_err(|e| AkError::ServerError(format!("Create image build: bad response: {e}")))?;

    emit_mutation_raw(
        Some(&raw),
        &build,
        &build.id.to_string(),
        &format!(
            "Build of {} queued (ID: {}). Follow it with `ak image-build log {repo} {}`.",
            build.reference, build.id, build.id
        ),
        global,
    );
    Ok(())
}

async fn render(repo: &str, spec: SpecArgs, global: &GlobalArgs) -> Result<()> {
    let body = json!({"spec": build_spec(spec)?});
    let spinner = output::spinner("Rendering spec...");
    let raw = post_spec(repo, &["render"], &body, "Render image build", global).await;
    spinner.finish_and_clear();
    let raw = raw?;
    let rendered: RenderImageBuildResponse = serde_json::from_slice(&raw)
        .map_err(|e| AkError::ServerError(format!("Render image build: bad response: {e}")))?;

    match global.format {
        OutputFormat::Table | OutputFormat::Quiet => {
            // Stdout stays a usable Containerfile, warnings or not.
            for warning in &rendered.warnings {
                eprintln!("Warning: {warning}");
            }
            println!("{}", rendered.containerfile.trim_end());
        }
        _ => println!(
            "{}",
            output::render_raw(Some(&raw), &rendered, &global.format, None)
        ),
    }
    Ok(())
}

async fn settings(repo: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching build settings...");
    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.image_build_settings().key(repo).send()).await;
    let settings = resp
        .map_err(|e| sdk_err("get image build settings", e))?
        .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", settings.enabled);
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &settings,
            &global.format,
            Some(settings_detail(&settings))
        )
    );
    Ok(())
}

async fn base_info(repo: &str, image: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching base image info...");
    let (resp, raw) = artifact_keeper_sdk::raw::capture(
        client.image_build_base_info().key(repo).image(image).send(),
    )
    .await;
    let info = resp
        .map_err(|e| sdk_err("get base image info", e))?
        .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", info.found);
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &info,
            &global.format,
            Some(base_info_detail(&info))
        )
    );
    Ok(())
}

async fn inspect(repo: &str, image: &str, reference: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Inspecting image...");
    let (resp, raw) = artifact_keeper_sdk::raw::capture(
        client
            .inspect_image()
            .key(repo)
            .image(image)
            .reference(reference)
            .send(),
    )
    .await;
    let inspected = resp.map_err(|e| sdk_err("inspect image", e))?.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", inspected.digest);
        return Ok(());
    }
    println!(
        "{}",
        output::render_raw(
            raw.as_deref(),
            &inspected,
            &global.format,
            Some(inspect_detail(&inspected))
        )
    );
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn or_dash(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

fn list_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(" ")
    }
}

fn builds_table(builds: &[ImageBuildResponse]) -> String {
    let mut table = new_table(vec!["ID", "REFERENCE", "STATUS", "REQUESTED BY", "CREATED"]);
    for b in builds {
        table.add_row(vec![
            b.id.to_string(),
            b.reference.clone(),
            b.status.clone(),
            b.requested_by.clone(),
            b.created_at.to_rfc3339(),
        ]);
    }
    table.to_string()
}

fn build_detail(b: &ImageBuildResponse) -> String {
    let time = |t: Option<chrono::DateTime<chrono::Utc>>| {
        t.map(|t| t.to_rfc3339()).unwrap_or_else(|| "-".to_string())
    };
    format!(
        "ID:           {}\n\
         Reference:    {}\n\
         Status:       {}\n\
         Digest:       {}\n\
         Error:        {}\n\
         Requested by: {}\n\
         Log size:     {}\n\
         Created:      {}\n\
         Started:      {}\n\
         Finished:     {}\n\
         Containerfile:\n{}",
        b.id,
        b.reference,
        b.status,
        or_dash(b.digest.as_deref()),
        or_dash(b.error.as_deref()),
        b.requested_by,
        format_bytes(i64::from(b.log_bytes)),
        b.created_at.to_rfc3339(),
        time(b.started_at),
        time(b.finished_at),
        b.containerfile.trim_end(),
    )
}

fn settings_detail(s: &ImageBuildSettingsResponse) -> String {
    format!(
        "Builds enabled:       {}\n\
         Repository buildable: {}\n\
         You may build:        {}\n\
         Admin only:           {}\n\
         Base allowlist:       {}\n\
         RUN lines allowed:    {}\n\
         Dockerfiles allowed:  {}\n\
         Package managers:     {}\n\
         Pip index:            {}\n\
         Push registry:        {}\n\
         Timeout:              {}s\n\
         Max concurrent:       {}",
        yes_no(s.enabled),
        yes_no(s.repository_buildable),
        yes_no(s.caller_may_build),
        yes_no(s.admin_only),
        list_or_dash(&s.base_allowlist),
        yes_no(s.allow_run),
        yes_no(s.allow_dockerfile),
        list_or_dash(&s.supported_package_managers),
        or_dash(s.pip_index_url.as_deref()),
        or_dash(s.push_registry.as_deref()),
        s.timeout_secs,
        s.max_concurrent,
    )
}

fn base_info_detail(i: &BaseImageInfo) -> String {
    format!(
        "Found:          {}\n\
         Reference:      {}\n\
         Digest:         {}\n\
         Platform:       {}/{}\n\
         User:           {}\n\
         System manager: {}\n\
         Has pip:        {}\n\
         Has conda:      {}",
        yes_no(i.found),
        or_dash(i.reference.as_deref()),
        or_dash(i.digest.as_deref()),
        or_dash(i.os.as_deref()),
        or_dash(i.architecture.as_deref()),
        or_dash(i.user.as_deref()),
        or_dash(i.system_manager.as_deref()),
        yes_no(i.has_pip),
        yes_no(i.has_conda),
    )
}

fn inspect_detail(i: &ImageInspect) -> String {
    let platforms = i
        .platforms
        .iter()
        .map(|p| match &p.variant {
            Some(variant) => format!("{}/{}/{variant}", p.os, p.architecture),
            None => format!("{}/{}", p.os, p.architecture),
        })
        .collect::<Vec<_>>();
    let or_dash_empty = |value: &str| {
        if value.is_empty() {
            "-".to_string()
        } else {
            value.to_string()
        }
    };
    let mut out = format!(
        "Reference:  {}\n\
         Digest:     {}\n\
         Index:      {}\n\
         Platforms:  {}\n\
         Size:       {}\n\
         User:       {}\n\
         Workdir:    {}\n\
         Entrypoint: {}\n\
         Command:    {}\n\
         Ports:      {}\n\
         Provenance: {}",
        i.reference,
        i.digest,
        or_dash(i.index_digest.as_deref()),
        list_or_dash(&platforms),
        format_bytes(i.size_bytes),
        or_dash_empty(&i.config.user),
        or_dash_empty(&i.config.working_dir),
        list_or_dash(&i.config.entrypoint),
        list_or_dash(&i.config.cmd),
        list_or_dash(&i.config.exposed_ports),
        i.provenance
            .as_ref()
            .map_or("-", |p| p.attestation_digest.as_str()),
    );
    if !i.layers.is_empty() {
        let mut table = new_table(vec!["LAYER", "SIZE"]);
        for layer in &i.layers {
            table.add_row(vec![layer.digest.clone(), format_bytes(layer.size_bytes)]);
        }
        out.push_str(&format!("\n{table}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_build_each_field_of_the_spec() {
        let spec = build_spec(SpecArgs {
            base_image: Some("python:3.12-slim".to_string()),
            apt: vec!["curl".to_string()],
            pip: vec!["requests>=2,<3".to_string()],
            conda: vec!["numpy".to_string()],
            conda_channel: vec!["conda-forge".to_string()],
            packages: Some(r#"[{"manager":"apk","packages":["git"]}]"#.to_string()),
            env: vec!["A=b=c".to_string()],
            label: vec!["team=x".to_string()],
            run: vec!["echo a, b".to_string()],
            user: Some("1000".to_string()),
            workdir: Some("/app".to_string()),
            multistage: true,
            ..SpecArgs::default()
        })
        .unwrap();
        assert_eq!(
            spec,
            json!({
                "base_image": "python:3.12-slim",
                "apt": ["curl"],
                "pip": ["requests>=2,<3"],
                "conda": ["numpy"],
                "conda_channels": ["conda-forge"],
                "packages": [{"manager": "apk", "packages": ["git"]}],
                "env": {"A": "b=c"},
                "labels": {"team": "x"},
                "run": ["echo a, b"],
                "user": "1000",
                "workdir": "/app",
                "multistage": true,
            })
        );
    }

    #[test]
    fn flags_go_on_top_of_spec_and_unknown_fields_survive() {
        let spec = build_spec(SpecArgs {
            spec: Some(r#"{"base_image":"old","from_a_newer_server":1}"#.to_string()),
            base_image: Some("new".to_string()),
            ..SpecArgs::default()
        })
        .unwrap();
        assert_eq!(spec, json!({"base_image": "new", "from_a_newer_server": 1}));
    }

    #[test]
    fn bad_spec_input_is_refused() {
        let with_spec = |value: &str| SpecArgs {
            spec: Some(value.to_string()),
            ..SpecArgs::default()
        };
        assert!(build_spec(with_spec("[]")).is_err());
        assert!(build_spec(with_spec("{nope")).is_err());
        assert!(
            build_spec(SpecArgs {
                env: vec!["novalue".to_string()],
                ..SpecArgs::default()
            })
            .is_err()
        );
    }

    #[test]
    fn urls_encode_the_repository_and_keep_a_path_prefix() {
        let url = builds_url("https://x.example/ak/", "a b", &["render"]).unwrap();
        assert_eq!(
            url.as_str(),
            "https://x.example/ak/api/v1/repositories/a%20b/image-builds/render"
        );
    }
}
