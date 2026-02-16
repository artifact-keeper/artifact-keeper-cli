//! SDK generation xtask.
//!
//! Reads the OpenAPI spec from `../artifact-keeper-api/openapi.json`,
//! converts OpenAPI 3.1 constructs to 3.0 compatible format, and generates
//! a Rust SDK via Progenitor.
//!
//! Usage:
//!   cargo xtask generate          # Generate SDK
//!   cargo xtask generate --check  # Verify generated code is up-to-date

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(|s| s.as_str()).unwrap_or("generate");

    match subcommand {
        "generate" => {
            let check = args.iter().any(|a| a == "--check");
            generate_sdk(check)
        }
        _ => {
            eprintln!("Usage: cargo xtask generate [--check]");
            std::process::exit(1);
        }
    }
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

    // Convert OpenAPI 3.1 → 3.0 compatible format
    convert_31_to_30(&mut spec);

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
    let formatted = format_generated_code(&raw_code)?;

    let output_path = workspace_root.join("sdk/src/generated_sdk.rs");

    if check {
        let existing = fs::read_to_string(&output_path).unwrap_or_default();
        if existing != formatted {
            bail!(
                "Generated SDK is out of date. Run `cargo xtask generate` to update.\n\
                 Diff: {} bytes existing vs {} bytes generated",
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

/// Convert OpenAPI 3.1 constructs to 3.0 compatible format.
///
/// Main differences handled:
/// - Version string: "3.1.0" → "3.0.3"
/// - Nullable types: `"type": ["string", "null"]` → `"type": "string", "nullable": true`
/// - oneOf/anyOf with null type → nullable reference
/// - `const` → `enum` with single value
/// - Remove `examples` (3.1) if `example` (3.0) exists
/// - Fix missing schemas for octet-stream/text-plain content types
fn convert_31_to_30(spec: &mut serde_json::Value) {
    // Downgrade version string
    if let Some(version) = spec.get_mut("openapi")
        && (version.as_str() == Some("3.1.0") || version.as_str() == Some("3.1.1"))
    {
        *version = serde_json::Value::String("3.0.3".to_string());
    }

    // Remove endpoints with unsupported content types (multipart/form-data)
    remove_unsupported_endpoints(spec);

    // Recursively transform the spec
    transform_value(spec);
}

/// Remove endpoints that use content types Progenitor doesn't support.
fn remove_unsupported_endpoints(spec: &mut serde_json::Value) {
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
            }
        }

        // Remove paths that have no methods left
        let empty_paths: Vec<String> = paths_obj
            .iter()
            .filter(|(_, v)| {
                v.as_object()
                    .map(|o| {
                        o.keys().all(|k| {
                            !["get", "post", "put", "delete", "patch", "head", "options"]
                                .contains(&k.as_str())
                        })
                    })
                    .unwrap_or(true)
            })
            .map(|(k, _)| k.clone())
            .collect();

        for path in empty_paths {
            paths_obj.remove(&path);
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

fn format_generated_code(code: &str) -> Result<String> {
    let header = "// This file is generated by `cargo xtask generate`. Do not edit.\n\
                  #![allow(clippy::all, unused, dead_code, unreachable_code)]\n\n";

    let full = format!("{header}{code}");

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
                Ok(full)
            }
        }
        Err(_) => {
            eprintln!("rustfmt not found, using unformatted output");
            Ok(full)
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
