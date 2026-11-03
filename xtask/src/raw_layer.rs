//! Does `--format json` print what the server sent?
//!
//! The typed SDK structs drop any field they don't know, so a command that prints a
//! server's JSON response has to wrap the call in `raw::capture` and print with
//! `output::render_raw`. This reads the source and fails on a function that calls an
//! SDK operation with a JSON response and doesn't capture it, or that prints with
//! `output::render`, unless [`OPT_OUTS`] says why.
//!
//! It's a check of the source, not of behaviour. It can't see a function that captures
//! the body and then ignores it. `tests/raw_json.rs` shows real output for those it
//! covers.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;

/// `(file under src/commands, function or "*", why it doesn't print the server's body)`.
const OPT_OUTS: &[(&str, &str, &str)] = &[
    (
        "agent/plugins.rs",
        "print_local",
        "Prints what this machine has or did: installs, a dry run, entries filtered from a marketplace",
    ),
    (
        "admin.rs",
        "proxy_request",
        "The SDK gives no proxied body to print, only the status",
    ),
    (
        "artifact.rs",
        "upload_sessions",
        "Sessions come from the local cache, not a server",
    ),
    (
        "auth.rs",
        "login_with_browser",
        "Prints a login URL it built, not a response",
    ),
    (
        "auth.rs",
        "refresh",
        "The body holds session tokens, which are stored and never printed",
    ),
    (
        "auth.rs",
        "store_token",
        "Reads the user to check the token, and prints no body",
    ),
    (
        "auth.rs",
        "login_with_password",
        "The body holds session tokens, which are stored and never printed",
    ),
    (
        "auth.rs",
        "exchange_and_store",
        "The body holds session tokens, which are stored and never printed",
    ),
    (
        "auth.rs",
        "complete_totp",
        "The body holds session tokens, which are stored and never printed",
    ),
    ("config.rs", "*", "Prints local configuration"),
    (
        "curation.rs",
        "delete_rule",
        "The server answers with no body, so this confirms the delete",
    ),
    (
        "device_flow.rs",
        "login_with_policy",
        "Reads the user to check the login, and prints no body",
    ),
    (
        "doctor.rs",
        "*",
        "A report of its own checks, not a response",
    ),
    (
        "environment.rs",
        "resolve_environment_id",
        "Looks up an ID for another call, and prints nothing",
    ),
    (
        "helpers.rs",
        "emit_mutation",
        "For a response with no body. A function that has one fails the rule on capture",
    ),
    (
        "helpers.rs",
        "resolve_repo_id",
        "Looks up an ID for another call, and prints nothing",
    ),
    (
        "helpers.rs",
        "resolve_artifact_id",
        "Looks up an ID for another call, and prints nothing",
    ),
    ("instance.rs", "*", "Prints local configuration"),
    (
        "migrate.rs",
        "execute",
        "A dry run lists artifacts gathered over many pages, so no one body is the answer",
    ),
    (
        "migrate.rs",
        "migrate_single_artifact",
        "One step of a transfer, and prints no body",
    ),
    (
        "monitoring.rs",
        "metrics",
        "The response is Prometheus text, not JSON, so JSON wraps it in one field",
    ),
    (
        "project.rs",
        "resolve_project_id",
        "Looks up an ID for another call, and prints nothing",
    ),
    (
        "repo.rs",
        "browse_repo",
        "An interactive browser with no JSON output",
    ),
    (
        "sbom.rs",
        "export_sbom",
        "Writes the SBOM's content field to a file",
    ),
    (
        "setup/mod.rs",
        "*",
        "Configures local tools, and never prints a token it creates",
    ),
    (
        "totp.rs",
        "disable",
        "The server answers with no body, so this confirms the change",
    ),
    (
        "totp.rs",
        "enroll_setup_request",
        "Its caller captures the body",
    ),
    (
        "totp.rs",
        "enroll_complete_request",
        "Its caller stores the session tokens in the body",
    ),
    (
        "totp.rs",
        "enroll_complete",
        "The body holds session tokens, which are stored and never printed",
    ),
    ("tui.rs", "*", "A terminal UI with no JSON output"),
];

/// What one function does, read from its tokens.
#[derive(Debug, Default, PartialEq, Eq)]
struct FnUse {
    /// Methods called with no arguments, a superset of the SDK operations it starts.
    calls: BTreeSet<String>,
    captures: bool,
    plain_render: bool,
}

fn scan_tokens(tokens: TokenStream, out: &mut FnUse) {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (i, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => scan_tokens(group.stream(), out),
            TokenTree::Ident(ident) => {
                let next_is_group = matches!(trees.get(i + 1), Some(TokenTree::Group(_)));
                let name = ident.to_string();
                if name == "capture" && next_is_group {
                    out.captures = true;
                }
                if name == "render" && next_is_group && follows_output_path(&trees, i) {
                    out.plain_render = true;
                }
                if let (Some(TokenTree::Punct(dot)), Some(TokenTree::Group(args))) = (
                    i.checked_sub(1).and_then(|p| trees.get(p)),
                    trees.get(i + 1),
                ) && dot.as_char() == '.'
                    && args.stream().is_empty()
                {
                    out.calls.insert(name);
                }
            }
            _ => {}
        }
    }
}

/// Is the identifier at `i` the end of `output::render`?
fn follows_output_path(trees: &[TokenTree], i: usize) -> bool {
    i >= 3
        && matches!(&trees[i - 1], TokenTree::Punct(p) if p.as_char() == ':')
        && matches!(&trees[i - 2], TokenTree::Punct(p) if p.as_char() == ':')
        && matches!(&trees[i - 3], TokenTree::Ident(id) if id == "output")
}

fn is_test_only(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|a| a.path().is_ident("cfg") && a.to_token_stream().to_string().contains("test"))
}

fn scan_items(items: &[syn::Item], out: &mut BTreeMap<String, FnUse>) {
    for item in items {
        match item {
            syn::Item::Fn(f) if !is_test_only(&f.attrs) => {
                let used = out.entry(f.sig.ident.to_string()).or_default();
                scan_tokens(f.block.to_token_stream(), used);
            }
            syn::Item::Impl(block) if !is_test_only(&block.attrs) => {
                for member in &block.items {
                    if let syn::ImplItem::Fn(f) = member {
                        let used = out.entry(f.sig.ident.to_string()).or_default();
                        scan_tokens(f.block.to_token_stream(), used);
                    }
                }
            }
            syn::Item::Mod(m) if !is_test_only(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    scan_items(inner, out);
                }
            }
            _ => {}
        }
    }
}

fn scan_source(source: &str) -> Result<BTreeMap<String, FnUse>> {
    let file = syn::parse_file(source)?;
    let mut out = BTreeMap::new();
    scan_items(&file.items, &mut out);
    Ok(out)
}

/// The SDK operations whose success response is a JSON body. Generated code has a
/// `fn op(&self) -> builder::Op<'_>` and an `impl<'a> Op<'a>` whose `send` names the type.
fn json_operations(sdk: &str) -> BTreeSet<String> {
    let mut with_body = BTreeSet::new();
    for (at, _) in sdk.match_indices("pub async fn send(") {
        let Some(start) = sdk[..at].rfind("impl<'a> ") else {
            continue;
        };
        let builder = sdk[start + "impl<'a> ".len()..]
            .split('<')
            .next()
            .unwrap_or_default();
        let signature = sdk[at..].split('{').next().unwrap_or_default();
        let Some(returned) = signature.split("ResponseValue<").nth(1) else {
            continue;
        };
        if !returned.starts_with("()") && !returned.contains("ByteStream") {
            with_body.insert(builder.to_string());
        }
    }
    let mut operations = BTreeSet::new();
    for line in sdk.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("fn ")
            && let Some((name, tail)) = rest.split_once("(&self) -> builder::")
            && let Some(builder) = tail.split('<').next()
            && with_body.contains(builder)
        {
            operations.insert(name.to_string());
        }
    }
    operations
}

/// A function that breaks the rule, from what it uses.
fn problem(used: &FnUse, operations: &BTreeSet<String>) -> Option<String> {
    if used.plain_render {
        return Some("prints with output::render".to_string());
    }
    if used.captures {
        return None;
    }
    let found: Vec<&str> = used
        .calls
        .iter()
        .filter(|c| operations.contains(*c))
        .map(String::as_str)
        .collect();
    (!found.is_empty()).then(|| format!("calls {} without raw::capture", found.join(", ")))
}

pub struct Summary {
    pub captured: usize,
    pub opted_out: usize,
    pub errors: Vec<String>,
}

fn evaluate(
    files: &BTreeMap<String, BTreeMap<String, FnUse>>,
    operations: &BTreeSet<String>,
    opt_outs: &[(&str, &str, &str)],
) -> Summary {
    let mut errors = Vec::new();
    let mut captured = 0;
    let mut used_opt_outs = BTreeSet::new();
    for (file, functions) in files {
        for (name, used) in functions {
            captured += usize::from(used.captures);
            let Some(what) = problem(used, operations) else {
                continue;
            };
            let opt_out = opt_outs
                .iter()
                .find(|(f, n, _)| f == file && (n == name || *n == "*"));
            match opt_out {
                Some((f, n, _)) => {
                    used_opt_outs.insert((*f, *n));
                }
                None => errors.push(format!(
                    "src/commands/{file} {name} {what}, so `--format json` can lose fields. \
                     Use raw::capture and output::render_raw, or add it to OPT_OUTS in \
                     xtask/src/raw_layer.rs with a reason"
                )),
            }
        }
    }
    for (file, name, reason) in opt_outs {
        if reason.trim().is_empty() {
            errors.push(format!("raw layer opt-out {file} {name} needs a reason"));
        }
        if !used_opt_outs.contains(&(*file, *name)) {
            errors.push(format!(
                "raw layer opt-out {file} {name} isn't needed any more: take it off"
            ));
        }
    }
    Summary {
        captured,
        opted_out: used_opt_outs.len(),
        errors,
    }
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

pub fn check(root: &Path) -> Result<Summary> {
    let sdk = fs::read_to_string(root.join("sdk/src/generated_sdk.rs"))?;
    let commands = root.join("src/commands");
    let mut paths = Vec::new();
    rust_files(&commands, &mut paths)?;
    let mut files = BTreeMap::new();
    for path in paths {
        let name = path.strip_prefix(&commands)?.to_string_lossy().into_owned();
        let source = fs::read_to_string(&path)?;
        let scanned = scan_source(&source).with_context(|| format!("parse {name}"))?;
        files.insert(name, scanned);
    }
    Ok(evaluate(&files, &json_operations(&sdk), OPT_OUTS))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDK: &str = "
pub trait ClientExt {
    fn get_thing(&self) -> builder::GetThing<'_>;
    fn delete_thing(&self) -> builder::DeleteThing<'_>;
    fn get_blob(&self) -> builder::GetBlob<'_>;
}
impl<'a> GetThing<'a> {
    pub async fn send(self) -> Result<ResponseValue<types::Thing>, Error<types::E>> {}
}
impl<'a> DeleteThing<'a> {
    pub async fn send(self) -> Result<ResponseValue<()>, Error<types::E>> {}
}
impl<'a> GetBlob<'a> {
    pub async fn send(self) -> Result<ResponseValue<ByteStream>, Error<types::E>> {}
}
";

    fn files(source: &str) -> BTreeMap<String, BTreeMap<String, FnUse>> {
        BTreeMap::from([("x.rs".to_string(), scan_source(source).unwrap())])
    }

    fn errors(source: &str, opt_outs: &[(&str, &str, &str)]) -> Vec<String> {
        evaluate(&files(source), &json_operations(SDK), opt_outs).errors
    }

    #[test]
    fn only_a_json_response_counts_as_a_body() {
        assert_eq!(
            json_operations(SDK),
            BTreeSet::from(["get_thing".to_string()])
        );
    }

    #[test]
    fn a_captured_call_printed_raw_passes() {
        let source = r#"async fn f() {
            let (r, raw) = raw::capture(client.get_thing().send()).await;
            println!("{}", output::render_raw(raw.as_deref(), &r, &f, None));
        }"#;
        assert_eq!(errors(source, &[]), Vec::<String>::new());
    }

    #[test]
    fn an_uncaptured_call_fails() {
        let found = errors("async fn f() { client.get_thing().send().await; }", &[]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("x.rs f calls get_thing"), "{found:?}");
    }

    #[test]
    fn plain_render_fails_even_inside_a_macro_or_with_a_capture() {
        let source = r#"async fn f() {
            let (r, raw) = raw::capture(client.get_thing().send()).await;
            println!("{}", output::render(&r, &f, None));
        }"#;
        let found = errors(source, &[]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("output::render"), "{found:?}");
    }

    #[test]
    fn a_call_with_no_body_needs_no_capture() {
        let source =
            "async fn f() { client.delete_thing().send().await; client.get_blob().send().await; }";
        assert_eq!(errors(source, &[]), Vec::<String>::new());
    }

    #[test]
    fn test_code_doesnt_count() {
        let source = r#"#[cfg(test)] mod tests { fn t() { println!("{}", output::render(&a, &b, None)); } }"#;
        assert_eq!(errors(source, &[]), Vec::<String>::new());
    }

    #[test]
    fn an_opt_out_excuses_a_function_and_a_stale_one_fails() {
        let source = "async fn f() { client.get_thing().send().await; }";
        assert_eq!(
            errors(source, &[("x.rs", "f", "why")]),
            Vec::<String>::new()
        );
        assert_eq!(
            errors(source, &[("x.rs", "*", "why")]),
            Vec::<String>::new()
        );
        let found = errors(source, &[("x.rs", "f", "why"), ("x.rs", "gone", "it left")]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("isn't needed"), "{found:?}");
    }

    #[test]
    fn an_opt_out_needs_a_reason() {
        let found = errors(
            "async fn f() { client.get_thing().send().await; }",
            &[("x.rs", "f", " ")],
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("needs a reason"), "{found:?}");
    }
}
