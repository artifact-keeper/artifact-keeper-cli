//! SDK generation xtask.
//!
//! Reads the OpenAPI spec from `../artifact-keeper-api/openapi.json`,
//! converts OpenAPI 3.1 constructs to 3.0 compatible format, and generates
//! a Rust SDK via Progenitor.
//!
//! Usage:
//!   cargo xtask generate          # Generate SDK
//!   cargo xtask generate --check  # Verify generated code is up-to-date
//!   cargo xtask routes            # Write ROUTES.json from a backend checkout
//!   cargo xtask routes --check    # Verify ROUTES.json is up-to-date
//!   cargo xtask coverage --check  # The coverage gate

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};

mod coverage;
mod raw_layer;
mod routes;

/// Operations left out of the SDK, because Progenitor cannot generate
/// multipart/form-data. `src/commands` calls these over raw HTTP. Generation
/// fails on any other skip, so a new one can't silently drop out of the SDK.
const KNOWN_SKIPS: &[&str] = &["POST /api/v1/plugins", "POST /api/v1/plugins/install/zip"];

/// Response fields the spec requires and doesn't allow to be null, but the server
/// does send as null. They are generated as `Option`.
const NULL_DESPITE_THE_SPEC: &[(&str, &[&str])] = &[
    // A plugin installed with no config schema has null here. It would stop
    // `ak admin plugins list` reading the whole list.
    ("PluginResponse", &["config_schema"]),
];

/// Response fields the pinned API requires but the previous minor doesn't send.
///
/// `ak` supports the server minor it's built for and the one before it. The
/// generated SDK rejects a response that lacks a required field, so without this
/// every command touching one of these types fails on the previous minor. They
/// are generated as `Option`. Update this list when the pin moves to a new minor:
/// each schema's `required` in the pinned spec, minus the same in the previous
/// minor's specs (here 1.12.1 against 1.11.0 to 1.11.14), for the schemas
/// each of those specs has.
const NOT_REQUIRED_ON_PREVIOUS_MINOR: &[(&str, &[&str])] = &[
    ("AgeGateConfigResponse", &["instance_locked"]),
    ("AgeGateReviewResponse", &["instance_locked"]),
    ("AuthConfig", &["device_authorization_enabled"]),
    ("CiOidcProviderResponse", &["token_ttl_secs"]),
    ("CondaAllowlistResponse", &["scope"]),
    (
        "DashboardResponse",
        &[
            "proxy_blocked",
            "proxy_would_block",
            "repos_incomplete",
            "repos_rated",
            "repos_unrated",
        ],
    ),
    ("ExchangeCodeResponse", &["expires_in"]),
    ("FormatHandlerResponse", &["repository_types"]),
    ("GateResponse", &["accepted_grade_status"]),
    ("IngestExternalFindingsResponse", &["grade_status"]),
    ("NpmUpstreamFeedStatus", &["upstream_jobs_paused"]),
    ("PolicyResponse", &["block_uncataloged"]),
    ("PromotionRuleResponse", &["accepted_grade_status"]),
    ("RepoSecurityResponse", &["uncataloged_policy"]),
    ("RepositoryCapabilities", &["rpm_repodata_mode"]),
    (
        "RepositoryResponse",
        &[
            "allow_public_with_upstream_credentials",
            "public_with_upstream_credentials",
        ],
    ),
    ("RestoreResponse", &["excluded", "status"]),
    ("RotateWebhookSecretResponse", &["secret"]),
    (
        "RuntimeSettingsResponse",
        &[
            "hidden_nav_items",
            "upstream_jobs_paused",
            "upstream_jobs_paused_source",
        ],
    ),
    ("ScanConfigResponse", &["instance_locked"]),
    ("ScanResponse", &["grade_status"]),
    ("ScoreResponse", &["grade_status"]),
    ("SubscriptionResponse", &["effective"]),
    ("SystemConfigResponse", &["ui"]),
    (
        "SystemStats",
        &["max_upload_bytes", "storage_quota", "transfer_quota"],
    ),
    ("TokenInfoResponse", &["unreachable_member_count"]),
];

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(|s| s.as_str()).unwrap_or("generate");

    match subcommand {
        "generate" => {
            let check = args.iter().any(|a| a == "--check");
            generate_sdk(check)
        }
        "routes" => {
            let check = args.iter().any(|a| a == "--check");
            let backend = flag_value(&args, "--backend").map(PathBuf::from);
            routes::run(&workspace_root()?, backend, check)
        }
        "coverage" => coverage::run(
            &workspace_root()?,
            coverage::Options {
                check: args.iter().any(|a| a == "--check"),
                ak: flag_value(&args, "--ak").map(PathBuf::from),
                base_ref: flag_value(&args, "--base-ref"),
                spec: flag_value(&args, "--spec").map(PathBuf::from),
            },
        ),
        _ => {
            eprintln!(
                "Usage: cargo xtask generate [--check]\n       \
                 cargo xtask routes [--backend <dir>] [--check]\n       \
                 cargo xtask coverage [--check] [--ak <path>] [--base-ref <ref>] [--spec <file>]"
            );
            std::process::exit(1);
        }
    }
}

/// The value after `--name`, if it's on the command line.
fn flag_value(args: &[String], name: &str) -> Option<String> {
    let at = args.iter().position(|a| a == name)?;
    args.get(at + 1).cloned()
}

fn generate_sdk(check: bool) -> Result<()> {
    let workspace_root = workspace_root()?;
    let spec_path = workspace_root
        .parent()
        .expect("workspace has parent dir")
        .join("artifact-keeper-api/openapi.json");

    if !spec_path.exists() {
        bail!(
            "OpenAPI spec not found at {}. Clone artifact-keeper-api next to this repo.",
            spec_path.display()
        );
    }

    eprintln!("Reading OpenAPI spec from {}", spec_path.display());
    let spec_content = fs::read_to_string(&spec_path)
        .with_context(|| format!("Failed to read {}", spec_path.display()))?;

    let mut spec: serde_json::Value =
        serde_json::from_str(&spec_content).context("Failed to parse OpenAPI spec as JSON")?;

    check_version_pin(&workspace_root, &spec)?;

    // Convert OpenAPI 3.1 → 3.0 compatible format
    let skipped = convert_31_to_30(&mut spec);

    let unexpected: Vec<&String> = skipped
        .iter()
        .filter(|op| !KNOWN_SKIPS.contains(&op.as_str()))
        .collect();
    ensure!(
        unexpected.is_empty(),
        "Operations the SDK cannot generate, not in KNOWN_SKIPS: {unexpected:?}"
    );
    eprintln!(
        "{} operations generated, {} skipped",
        count_operations(&spec),
        skipped.len()
    );

    let spec_str = serde_json::to_string_pretty(&spec).context("Failed to serialize spec")?;

    eprintln!("Generating SDK with Progenitor...");
    let spec_parsed: openapiv3::OpenAPI =
        serde_json::from_str(&spec_str).context("Failed to parse converted spec as OpenAPI")?;

    let mut settings = progenitor::GenerationSettings::default();
    settings.with_interface(progenitor::InterfaceStyle::Builder);
    settings.with_tag(progenitor::TagStyle::Separate);

    let mut generator = progenitor::Generator::new(&settings);

    let tokens = generator
        .generate_tokens(&spec_parsed)
        .context("Progenitor code generation failed")?;

    let raw_code = tokens.to_string();
    let formatted = rustfmt(&use_sdk_error(&format_generated_code(&raw_code)?)?)?;

    let output_path = workspace_root.join("sdk/src/generated_sdk.rs");

    if check {
        let existing = fs::read_to_string(&output_path).unwrap_or_default();
        if existing != formatted {
            let line = existing
                .lines()
                .zip(formatted.lines())
                .position(|(a, b)| a != b)
                .unwrap_or(existing.lines().count().min(formatted.lines().count()))
                + 1;
            bail!(
                "Generated SDK is out of date. Run `cargo xtask generate` to update.\n\
                 First difference at line {line}: {} bytes committed, {} bytes generated",
                existing.len(),
                formatted.len()
            );
        }
        eprintln!("Generated SDK is up-to-date.");
    } else {
        fs::write(&output_path, &formatted)
            .with_context(|| format!("Failed to write {}", output_path.display()))?;
        eprintln!(
            "Generated SDK written to {} ({} bytes)",
            output_path.display(),
            formatted.len()
        );
    }

    Ok(())
}

/// Fail unless `API_VERSION`, the spec, and the SDK crate name the same version.
fn check_version_pin(workspace_root: &Path, spec: &serde_json::Value) -> Result<()> {
    let pin = fs::read_to_string(workspace_root.join("API_VERSION"))
        .context("Failed to read API_VERSION")?;
    let pin = pin.trim();

    let spec_version = spec
        .pointer("/info/version")
        .and_then(|v| v.as_str())
        .context("OpenAPI spec has no info.version")?;
    ensure!(
        spec_version == pin,
        "API_VERSION is {pin}, but the spec is {spec_version}. \
         Check out artifact-keeper-api at v{pin}."
    );

    let manifest = fs::read_to_string(workspace_root.join("sdk/Cargo.toml"))
        .context("Failed to read sdk/Cargo.toml")?;
    let sdk_version = manifest
        .lines()
        .find_map(|line| line.strip_prefix("version = "))
        .map(|v| v.trim().trim_matches('"'))
        .context("sdk/Cargo.toml has no version")?;
    ensure!(
        sdk_version == pin,
        "API_VERSION is {pin}, but sdk/Cargo.toml has version {sdk_version}."
    );

    Ok(())
}

const HTTP_METHODS: &[&str] = &["get", "post", "put", "delete", "patch", "head", "options"];

fn count_operations(spec: &serde_json::Value) -> usize {
    spec.get("paths")
        .and_then(|p| p.as_object())
        .map(|paths| {
            paths
                .values()
                .filter_map(|methods| methods.as_object())
                .flat_map(|methods| methods.keys())
                .filter(|method| HTTP_METHODS.contains(&method.as_str()))
                .count()
        })
        .unwrap_or(0)
}

/// Convert OpenAPI 3.1 constructs to 3.0 compatible format, returning the
/// operations that had to be removed.
///
/// Main differences handled:
/// - Version string: "3.1.0" → "3.0.3"
/// - Nullable types: `"type": ["string", "null"]` → `"type": "string", "nullable": true`
/// - oneOf/anyOf with null type → nullable reference
/// - `const` → `enum` with single value
/// - Remove `examples` (3.1) if `example` (3.0) exists
/// - Fix missing schemas for octet-stream/text-plain content types
fn convert_31_to_30(spec: &mut serde_json::Value) -> Vec<String> {
    // Downgrade version string
    if let Some(version) = spec.get_mut("openapi")
        && (version.as_str() == Some("3.1.0") || version.as_str() == Some("3.1.1"))
    {
        *version = serde_json::Value::String("3.0.3".to_string());
    }

    // Remove endpoints with unsupported content types (multipart/form-data)
    let skipped = remove_unsupported_endpoints(spec);

    // Progenitor rejects any other request content type it does not know
    alias_xml_request_bodies(spec);

    // Progenitor panics on an operation with a success body and a bodiless 2xx
    drop_bodiless_success_beside_a_body(spec);

    // Progenitor panics on an operation with two different success bodies
    merge_divergent_success_bodies(spec);

    // Progenitor generates `Option<Option<String>>` for these, which doesn't compile
    strip_null_from_optional_headers(spec);

    // Keep responses from the previous server minor deserializable
    relax_previous_minor_fields(spec);

    // Strip error response bodies that cause Progenitor to panic
    // (assertion `response_types.len() <= 1` when both success and error have different schemas)
    strip_error_response_bodies(spec);

    // Recursively transform the spec
    transform_value(spec);

    skipped
}

/// Remove endpoints that use content types Progenitor doesn't support, returning
/// them as `METHOD /path`.
fn remove_unsupported_endpoints(spec: &mut serde_json::Value) -> Vec<String> {
    let mut skipped = Vec::new();
    if let Some(paths) = spec.get_mut("paths")
        && let Some(paths_obj) = paths.as_object_mut()
    {
        let mut to_remove_methods: Vec<(String, String)> = Vec::new();

        for (path, methods) in paths_obj.iter() {
            if let Some(methods_obj) = methods.as_object() {
                for (method, detail) in methods_obj {
                    if let Some(content) = detail
                        .get("requestBody")
                        .and_then(|rb| rb.get("content"))
                        .and_then(|c| c.as_object())
                        && content.contains_key("multipart/form-data")
                    {
                        to_remove_methods.push((path.clone(), method.clone()));
                    }
                }
            }
        }

        for (path, method) in &to_remove_methods {
            if let Some(methods) = paths_obj.get_mut(path)
                && let Some(methods_obj) = methods.as_object_mut()
            {
                eprintln!(
                    "  Skipping {} {} (multipart/form-data not supported by Progenitor)",
                    method.to_uppercase(),
                    path
                );
                methods_obj.remove(method);
                skipped.push(format!("{} {path}", method.to_uppercase()));
            }
        }

        // Remove paths that have no methods left
        let empty_paths: Vec<String> = paths_obj
            .iter()
            .filter(|(_, v)| {
                v.as_object()
                    .map(|o| o.keys().all(|k| !HTTP_METHODS.contains(&k.as_str())))
                    .unwrap_or(true)
            })
            .map(|(k, _)| k.clone())
            .collect();

        for path in empty_paths {
            paths_obj.remove(&path);
        }
    }
    skipped
}

/// Drop `NOT_REQUIRED_ON_PREVIOUS_MINOR` and `NULL_DESPITE_THE_SPEC` fields from
/// their schemas' `required`, and allow null for the second.
fn relax_previous_minor_fields(spec: &mut serde_json::Value) {
    for (schema, fields) in NOT_REQUIRED_ON_PREVIOUS_MINOR
        .iter()
        .chain(NULL_DESPITE_THE_SPEC)
    {
        let pointer = format!("/components/schemas/{schema}/required");
        if let Some(required) = spec.pointer_mut(&pointer).and_then(|r| r.as_array_mut()) {
            required.retain(|field| !field.as_str().is_some_and(|f| fields.contains(&f)));
        }
    }
    for (schema, fields) in NULL_DESPITE_THE_SPEC {
        for field in *fields {
            let pointer = format!("/components/schemas/{schema}/properties/{field}");
            if let Some(property) = spec.pointer_mut(&pointer).and_then(|p| p.as_object_mut()) {
                property.insert("nullable".to_string(), serde_json::Value::Bool(true));
            }
        }
    }
}

/// Generate `text/xml` request bodies as `text/plain`.
///
/// Progenitor only accepts JSON, octet-stream, form and plain-text request
/// bodies, and fails the whole generation on anything else. The XML-RPC body of
/// `POST /pypi/{repo_key}/pypi` is an opaque string, and the backend handler
/// does not look at its Content-Type, so the plain-text path is equivalent.
/// Responses need no alias: a non-JSON response body is generated as raw bytes.
fn alias_xml_request_bodies(spec: &mut serde_json::Value) {
    let Some(paths) = spec.get_mut("paths").and_then(|p| p.as_object_mut()) else {
        return;
    };
    for (path, methods) in paths.iter_mut() {
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };
        for (method, detail) in methods.iter_mut() {
            if let Some(content) = detail
                .get_mut("requestBody")
                .and_then(|rb| rb.get_mut("content"))
                .and_then(|c| c.as_object_mut())
                && let Some(xml) = content.remove("text/xml")
            {
                eprintln!(
                    "  Aliasing text/xml request body of {} {} to text/plain",
                    method.to_uppercase(),
                    path
                );
                content.insert("text/plain".to_string(), xml);
            }
        }
    }
}

/// Drop a bodiless 2xx response from an operation whose other 2xx has a body.
///
/// Progenitor 0.12 panics (`response_types.len() <= 1`) on an operation that
/// answers, say, `200` with JSON and `204` with nothing, because the two are
/// different success types. The bodied response is what a caller reads, so it
/// stays; the bodiless status then comes back as an error carrying its status,
/// as any undocumented response does. Returns the dropped `METHOD /path status`.
fn drop_bodiless_success_beside_a_body(spec: &mut serde_json::Value) -> Vec<String> {
    let mut dropped = Vec::new();
    let Some(paths) = spec.get_mut("paths").and_then(|p| p.as_object_mut()) else {
        return dropped;
    };
    for (path, methods) in paths.iter_mut() {
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };
        for (method, detail) in methods.iter_mut() {
            let Some(responses) = detail.get_mut("responses").and_then(|r| r.as_object_mut())
            else {
                continue;
            };
            let bodiless = |resp: &serde_json::Value| {
                resp.get("content")
                    .and_then(|c| c.as_object())
                    .is_none_or(|c| c.is_empty())
            };
            let success: Vec<String> = responses
                .keys()
                .filter(|code| code.starts_with('2'))
                .cloned()
                .collect();
            if !success.iter().any(|code| !bodiless(&responses[code])) {
                continue;
            }
            for code in success {
                if bodiless(&responses[&code]) {
                    eprintln!(
                        "  Dropping bodiless {code} of {} {path}: it has a success body too",
                        method.to_uppercase()
                    );
                    responses.remove(&code);
                    dropped.push(format!("{} {path} {code}", method.to_uppercase()));
                }
            }
        }
    }
    dropped
}

/// Make optional header parameters non-nullable.
///
/// An optional parameter is already an `Option` in the SDK. A schema of
/// `["string", "null"]` on top makes Progenitor generate `Option<Option<String>>`
/// and then call `.to_string()` on the inner `Option`, which doesn't compile.
/// Leaving a header out is the only way to send "no value", so null adds nothing.
fn strip_null_from_optional_headers(spec: &mut serde_json::Value) {
    let Some(paths) = spec.get_mut("paths").and_then(|p| p.as_object_mut()) else {
        return;
    };
    let parameter_lists = paths
        .values_mut()
        .filter_map(|item| item.as_object_mut())
        .flat_map(|item| item.iter_mut())
        .filter_map(|(key, value)| {
            if key == "parameters" {
                Some(value)
            } else if HTTP_METHODS.contains(&key.as_str()) {
                value.get_mut("parameters")
            } else {
                None
            }
        });
    for list in parameter_lists {
        let Some(list) = list.as_array_mut() else {
            continue;
        };
        for param in list {
            let optional_header = param.get("in").and_then(|i| i.as_str()) == Some("header")
                && param.get("required").and_then(|r| r.as_bool()) != Some(true);
            if !optional_header {
                continue;
            }
            let Some(schema) = param.get_mut("schema").and_then(|s| s.as_object_mut()) else {
                continue;
            };
            schema.remove("nullable");
            if let Some(types) = schema.get_mut("type").and_then(|t| t.as_array_mut()) {
                types.retain(|t| t.as_str() != Some("null"));
                if types.len() == 1 {
                    let only = types[0].clone();
                    schema.insert("type".to_string(), only);
                }
            }
        }
    }
}

/// Give an operation with different 2xx JSON bodies one body type: a `oneOf`.
///
/// Progenitor 0.12 panics (`response_types.len() <= 1`) on these. The union is
/// added as `<operationId>_outcome`, and every 2xx response points at it, so
/// the operation stays in the SDK with all of its bodies typed.
fn merge_divergent_success_bodies(spec: &mut serde_json::Value) {
    // A JSON pointer escapes the `/` in a media type as `~1`.
    const JSON: &str = "/content/application~1json";
    let mut unions: Vec<(String, serde_json::Value)> = Vec::new();

    let Some(paths) = spec.get_mut("paths").and_then(|p| p.as_object_mut()) else {
        return;
    };
    for (path, methods) in paths.iter_mut() {
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };
        for (method, detail) in methods.iter_mut() {
            let op_id = detail
                .get("operationId")
                .and_then(|id| id.as_str())
                .unwrap_or_default()
                .to_string();
            let Some(responses) = detail.get_mut("responses").and_then(|r| r.as_object_mut())
            else {
                continue;
            };

            let mut bodies: Vec<serde_json::Value> = Vec::new();
            for (code, resp) in responses.iter() {
                if code.starts_with('2')
                    && let Some(schema) = resp.pointer(&format!("{JSON}/schema"))
                    && !bodies.contains(schema)
                {
                    bodies.push(schema.clone());
                }
            }
            if bodies.len() < 2 {
                continue;
            }

            let name = format!("{op_id}_outcome");
            eprintln!(
                "  Merging {} success bodies of {} {} into {name}",
                bodies.len(),
                method.to_uppercase(),
                path
            );
            let reference = format!("#/components/schemas/{name}");
            for (code, resp) in responses.iter_mut() {
                if code.starts_with('2')
                    && let Some(media) = resp.pointer_mut(JSON)
                {
                    media["schema"] = serde_json::json!({ "$ref": reference });
                }
            }
            unions.push((name, serde_json::json!({ "oneOf": bodies })));
        }
    }

    if let Some(schemas) = spec
        .pointer_mut("/components/schemas")
        .and_then(|s| s.as_object_mut())
    {
        schemas.extend(unions);
    }
}

/// Strip response bodies from 4xx/5xx error responses.
///
/// Progenitor 0.12 panics (`response_types.len() <= 1`) when an operation has
/// both a success response body and an error response body with a different schema.
/// Removing error response content lets Progenitor treat them as opaque errors.
fn strip_error_response_bodies(spec: &mut serde_json::Value) {
    if let Some(paths) = spec.get_mut("paths")
        && let Some(paths_obj) = paths.as_object_mut()
    {
        for (_path, methods) in paths_obj.iter_mut() {
            if let Some(methods_obj) = methods.as_object_mut() {
                for (_method, detail) in methods_obj.iter_mut() {
                    if let Some(responses) = detail.get_mut("responses")
                        && let Some(responses_obj) = responses.as_object_mut()
                    {
                        for (code, resp) in responses_obj.iter_mut() {
                            let code_num: u16 = code.parse().unwrap_or(0);
                            if code_num >= 400
                                && let Some(obj) = resp.as_object_mut()
                            {
                                obj.remove("content");
                            }
                        }
                    }
                }
            }
        }
    }
}

fn transform_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            // Handle nullable type arrays: ["string", "null"] → "string" + nullable: true
            if let Some(type_val) = map.get("type")
                && let Some(arr) = type_val.as_array()
            {
                let non_null: Vec<&serde_json::Value> =
                    arr.iter().filter(|v| v.as_str() != Some("null")).collect();
                let has_null = arr.iter().any(|v| v.as_str() == Some("null"));

                if has_null && non_null.len() == 1 {
                    map.insert("type".to_string(), non_null[0].clone());
                    map.insert("nullable".to_string(), serde_json::Value::Bool(true));
                } else if !has_null && non_null.len() == 1 {
                    // Single-element type array: ["string"] → "string"
                    map.insert("type".to_string(), non_null[0].clone());
                }
            }

            // Handle oneOf/anyOf with null: [{"type": "null"}, {"$ref": "..."}] → nullable + ref
            for key in &["oneOf", "anyOf"] {
                if let Some(items) = map.get(*key)
                    && let Some(arr) = items.as_array()
                {
                    let null_items: Vec<_> = arr
                        .iter()
                        .filter(|i| {
                            i.as_object()
                                .and_then(|o| o.get("type"))
                                .and_then(|t| t.as_str())
                                == Some("null")
                        })
                        .collect();
                    let non_null_items: Vec<_> = arr
                        .iter()
                        .filter(|i| {
                            i.as_object()
                                .and_then(|o| o.get("type"))
                                .and_then(|t| t.as_str())
                                != Some("null")
                        })
                        .cloned()
                        .collect();

                    if !null_items.is_empty() && non_null_items.len() == 1 {
                        let schema = non_null_items.into_iter().next().unwrap();
                        let key_owned = key.to_string();
                        map.remove(&key_owned);
                        if let serde_json::Value::Object(inner) = schema {
                            for (k, v) in inner {
                                map.insert(k, v);
                            }
                        }
                        map.insert("nullable".to_string(), serde_json::Value::Bool(true));
                        break;
                    }
                }
            }

            // Fix content type schemas for Progenitor compatibility
            for ct in &[
                "application/octet-stream",
                "multipart/form-data",
                "text/plain",
            ] {
                if let Some(content) = map.get_mut(*ct)
                    && let Some(obj) = content.as_object_mut()
                {
                    if !obj.contains_key("schema")
                        || obj.get("schema") == Some(&serde_json::json!({}))
                    {
                        let default_schema = if *ct == "text/plain" {
                            serde_json::json!({"type": "string"})
                        } else if *ct == "multipart/form-data" {
                            serde_json::json!({"type": "object"})
                        } else {
                            serde_json::json!({"type": "string", "format": "binary"})
                        };
                        obj.insert("schema".to_string(), default_schema);
                    } else if let Some(schema) = obj.get_mut("schema")
                        && let Some(s) = schema.as_object_mut()
                        && *ct == "application/octet-stream"
                    {
                        if s.get("type").and_then(|t| t.as_str()) == Some("string")
                            && !s.contains_key("format")
                        {
                            s.insert(
                                "format".to_string(),
                                serde_json::Value::String("binary".to_string()),
                            );
                        }
                        if s.get("type").and_then(|t| t.as_str()) == Some("array") {
                            *schema = serde_json::json!({"type": "string", "format": "binary"});
                        }
                    }
                }
            }

            // Convert `const` to single-value `enum`
            if let Some(const_val) = map.remove("const") {
                map.insert(
                    "enum".to_string(),
                    serde_json::Value::Array(vec![const_val]),
                );
            }

            // Remove `examples` array if `example` scalar exists (3.0 compat)
            if map.contains_key("example") {
                map.remove("examples");
            }

            // Recurse into all values
            for val in map.values_mut() {
                transform_value(val);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                transform_value(item);
            }
        }
        _ => {}
    }
}

/// Swap progenitor's error type for `sdk/src/error.rs`.
///
/// Progenitor drops the body of a documented error response before the caller
/// sees it, with no setting to change that, and its `Display` prints the response
/// headers. Every pattern here must match, so a progenitor upgrade that changes
/// its output fails generation instead of silently bringing that behaviour back.
fn use_sdk_error(code: &str) -> Result<String> {
    const REPLACEMENTS: &[(&str, &str)] = &[
        (
            "pub use progenitor_client::{ByteStream, ClientInfo, Error, ResponseValue};",
            "pub use crate::error::Error;\npub use progenitor_client::{ByteStream, ClientInfo, ResponseValue};",
        ),
        ("Error<()>", "Error"),
        (
            "Err(Error::ErrorResponse(ResponseValue::empty(response)))",
            "Err(Error::from_response(response).await)",
        ),
        (
            "Err(Error::UnexpectedResponse(response))",
            "Err(Error::from_response(response).await)",
        ),
        (
            "=> ResponseValue::from_response(response).await,",
            "=> crate::raw::parse_response(response).await,",
        ),
        (
            ".form_urlencoded(&body)?",
            ".form_urlencoded(&body).map_err(Error::from_progenitor)?",
        ),
        (
            "client.pre(&mut request, &info).await?;",
            "client.pre::<()>(&mut request, &info).await?;",
        ),
        (
            "client.post(&result, &info).await?;",
            "client.post::<()>(&result, &info).await?;",
        ),
    ];

    let mut code = code.to_string();
    for (from, to) in REPLACEMENTS {
        ensure!(
            code.contains(from),
            "generated code no longer contains `{from}`: update use_sdk_error"
        );
        code = code.replace(from, to);
    }
    for leftover in [
        "Error::ErrorResponse",
        "Error::UnexpectedResponse",
        "Error<",
    ] {
        ensure!(
            !code.contains(leftover),
            "generated code still uses progenitor's error type: `{leftover}`"
        );
    }
    Ok(code)
}

fn format_generated_code(code: &str) -> Result<String> {
    let header = "// This file is generated by `cargo xtask generate`. Do not edit.\n\
                  #![allow(clippy::all, unused, dead_code, unreachable_code)]\n\n";

    rustfmt(&format!("{header}{code}"))
}

fn rustfmt(full: &str) -> Result<String> {
    // Try to format with rustfmt
    let child = Command::new("rustfmt")
        .arg("--edition")
        .arg("2024")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    match child {
        Ok(mut child) => {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(full.as_bytes()).ok();
            }
            // Drop stdin to signal EOF before waiting
            drop(child.stdin.take());
            let output = child.wait_with_output()?;
            if output.status.success() {
                Ok(String::from_utf8(output.stdout)?)
            } else {
                eprintln!(
                    "rustfmt failed, using unformatted output: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                Ok(full.to_string())
            }
        }
        Err(_) => {
            eprintln!("rustfmt not found, using unformatted output");
            Ok(full.to_string())
        }
    }
}

fn workspace_root() -> Result<PathBuf> {
    let output = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()
        .context("Failed to run cargo locate-project")?;

    let path = String::from_utf8(output.stdout)?.trim().to_string();
    Ok(Path::new(&path)
        .parent()
        .expect("Cargo.toml has parent")
        .to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_bodiless_success_beside_a_body_is_dropped() {
        let mut spec = json!({"paths": {"/claim": {"post": {
            "operationId": "claim",
            "responses": {
                "200": {"content": {"application/json": {"schema": {"type": "object"}}}},
                "204": {"description": "Nothing is due"},
                "400": {"description": "Malformed"}
            }
        }}}});
        let dropped = drop_bodiless_success_beside_a_body(&mut spec);
        assert_eq!(dropped, ["POST /claim 204"]);
        let responses = &spec["paths"]["/claim"]["post"]["responses"];
        assert!(responses.get("200").is_some());
        assert!(responses.get("204").is_none());
        assert!(responses.get("400").is_some());
    }

    #[test]
    fn only_bodiless_successes_are_kept() {
        let mut spec = json!({"paths": {"/x": {"delete": {
            "responses": {"202": {"description": "Accepted"}, "204": {"description": "Gone"}}
        }}}});
        let before = spec.clone();
        assert!(drop_bodiless_success_beside_a_body(&mut spec).is_empty());
        assert_eq!(spec, before);
    }

    #[test]
    fn an_optional_header_loses_its_null() {
        let mut spec = json!({"paths": {"/a/{p}": {
            "parameters": [{"name": "Prefer", "in": "header", "schema": {"type": ["string", "null"]}}],
            "put": {"parameters": [
                {"name": "If-Match", "in": "header", "required": false, "schema": {"type": ["string", "null"]}},
                {"name": "If-None-Match", "in": "header", "schema": {"type": "string", "nullable": true}},
                {"name": "X-Must", "in": "header", "required": true, "schema": {"type": ["string", "null"]}},
                {"name": "q", "in": "query", "schema": {"type": ["string", "null"]}}
            ]}
        }}});
        strip_null_from_optional_headers(&mut spec);
        let path = &spec["paths"]["/a/{p}"];
        assert_eq!(path["parameters"][0]["schema"], json!({"type": "string"}));
        let params = &path["put"]["parameters"];
        assert_eq!(params[0]["schema"], json!({"type": "string"}));
        assert_eq!(params[1]["schema"], json!({"type": "string"}));
        assert_eq!(params[2]["schema"], json!({"type": ["string", "null"]}));
        assert_eq!(params[3]["schema"], json!({"type": ["string", "null"]}));
    }
}
