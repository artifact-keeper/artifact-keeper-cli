//! `xtask coverage --check`: the gate behind "anything curl can do, `ak` can do".
//!
//! It compares three things it doesn't trust each other about: the routes the server
//! really has (`ROUTES.json`, `OCI_ROUTES.json`), the operations the spec documents,
//! and the registry compiled into the `ak` binary (`ak __registry`).
//!
//! Each route ends up as one of:
//!
//! - **covered**: a registry line names a command. `tests/registry_contract.rs` checks
//!   the line is true.
//! - **excluded**: a registry line, or a class exclusion, says why `ak api` is enough.
//! - **pending**: listed in `COVERAGE_PENDING.json`. That list is empty, and nothing
//!   can be added to it.
//! - **missing**: none of those, which fails the gate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::routes::{RouteTable, shape};

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryLine {
    pub method: String,
    pub path: String,
    pub command: String,
    #[serde(default)]
    pub binds: Vec<String>,
    pub excluded: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClassExclusion {
    pub name: String,
    pub methods: Vec<String>,
    pub prefixes: Vec<String>,
    #[serde(default)]
    pub except: Vec<String>,
    pub reason: String,
}

/// A request field that no flag should set, and why.
#[derive(Debug, Clone, Deserialize)]
pub struct FieldOptOut {
    pub method: String,
    pub path: String,
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Registry {
    pub commands: Vec<RegistryLine>,
    pub class_exclusions: Vec<ClassExclusion>,
    #[serde(default)]
    pub field_opt_outs: Vec<FieldOptOut>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRoute {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pending {
    /// What this list is for, and who shrinks it.
    #[serde(default)]
    pub comment: String,
    pub routes: Vec<PendingRoute>,
}

/// One operation of the spec, with the fields a command should be able to set.
#[derive(Debug, Clone)]
pub struct SpecOp {
    pub method: String,
    pub path: String,
    pub tag: String,
    pub fields: BTreeSet<String>,
}

const METHODS: &[&str] = &["get", "put", "post", "delete", "options", "head", "patch"];

fn resolve<'a>(spec: &'a Value, node: &'a Value) -> &'a Value {
    let mut current = node;
    for _ in 0..16 {
        let Some(reference) = current.get("$ref").and_then(Value::as_str) else {
            return current;
        };
        let Some(target) = reference
            .strip_prefix("#/")
            .map(|p| p.split('/').fold(spec, |n, key| &n[key]))
        else {
            return current;
        };
        current = target;
    }
    current
}

/// The top-level property names of a schema, through `$ref`, `allOf`, `oneOf`, `anyOf`.
fn schema_fields(spec: &Value, schema: &Value, out: &mut BTreeSet<String>, depth: usize) {
    if depth > 8 {
        return;
    }
    let schema = resolve(spec, schema);
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        out.extend(properties.keys().cloned());
    }
    for key in ["allOf", "oneOf", "anyOf"] {
        if let Some(parts) = schema.get(key).and_then(Value::as_array) {
            for part in parts {
                schema_fields(spec, part, out, depth + 1);
            }
        }
    }
}

pub fn spec_operations(spec: &Value) -> Vec<SpecOp> {
    let mut ops = Vec::new();
    let Some(paths) = spec["paths"].as_object() else {
        return ops;
    };
    for (path, item) in paths {
        for method in METHODS {
            let Some(op) = item.get(*method) else {
                continue;
            };
            let mut fields = BTreeSet::new();
            let params = item
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .chain(
                    op.get("parameters")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten(),
                );
            for param in params {
                let param = resolve(spec, param);
                if param["in"] == "query"
                    && let Some(name) = param["name"].as_str()
                {
                    fields.insert(name.to_string());
                }
            }
            if let Some(content) = op.get("requestBody").map(|b| &resolve(spec, b)["content"])
                && let Some(content) = content.as_object()
            {
                for media in content.values() {
                    schema_fields(spec, &media["schema"], &mut fields, 0);
                }
            }
            let tag = op["tags"][0].as_str().unwrap_or("untagged").to_string();
            ops.push(SpecOp {
                method: method.to_ascii_uppercase(),
                path: path.clone(),
                tag,
                fields,
            });
        }
    }
    ops
}

/// Does `path` start with `prefix`, matching whole segments and ignoring parameter
/// names?
fn under(path: &str, prefix: &str) -> bool {
    let path = shape(path);
    let prefix = shape(prefix);
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

type Key = (String, String);

fn key(method: &str, path: &str) -> Key {
    (method.to_string(), shape(path))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Covered(Vec<String>),
    Excluded(String),
    Class(String),
    Pending,
    Missing,
}

/// One route of the server: from the route table, the OCI list, the spec or all three.
#[derive(Debug, Clone)]
pub struct RouteRow {
    pub method: String,
    pub path: String,
    /// The spec's tag, or for a route the spec doesn't have, its group.
    pub tag: String,
    pub in_spec: bool,
    pub status: Status,
}

#[derive(Debug, Default)]
pub struct Findings {
    pub rows: Vec<RouteRow>,
    /// Field gaps of covered spec operations: (METHOD path, fields).
    pub field_gaps: BTreeMap<String, BTreeSet<String>>,
    pub field_total: usize,
    /// Fields that no flag should set, each with a reason in the registry.
    pub field_opt_outs: usize,
    pub errors: Vec<String>,
    /// Per tag: request fields on covered operations, and how many have no flag.
    pub tag_fields: BTreeMap<String, (usize, usize)>,
    /// How many routes each class exclusion takes out.
    pub class_counts: BTreeMap<String, usize>,
}

/// Where a route the spec doesn't document goes in the table.
fn group_of(path: &str, handler: &str, formats: &[String]) -> String {
    if path.starts_with("/v2") {
        return "(oci)".to_string();
    }
    if formats.iter().any(|prefix| under(path, prefix)) {
        return "(format wire)".to_string();
    }
    if handler.is_empty() {
        return "(other)".to_string();
    }
    format!("(unspecced) {handler}")
}

/// `OCI_ROUTES.json`: the OCI surface, and what the OCI spec has that this server
/// doesn't.
#[derive(Debug, Clone, Deserialize)]
pub struct OciRoutes {
    pub routes: Vec<PendingRoute>,
    #[serde(default)]
    pub not_routes: Vec<PendingRoute>,
}

/// A route listed as not existing that something else says exists. The fallback
/// handler isn't in the route table, so `tests/e2e_pkg_oci.rs` asks the real server too.
fn not_routes_problems(
    oci: &OciRoutes,
    spec_ops: &[SpecOp],
    table: &RouteTable,
    registry: &Registry,
) -> Vec<String> {
    let mut known: BTreeSet<Key> = oci.routes.iter().map(|r| key(&r.method, &r.path)).collect();
    known.extend(spec_ops.iter().map(|o| key(&o.method, &o.path)));
    known.extend(table.routes.iter().map(|r| key(&r.method, &r.path)));
    known.extend(registry.commands.iter().map(|c| key(&c.method, &c.path)));
    oci.not_routes
        .iter()
        .filter(|r| known.contains(&key(&r.method, &r.path)))
        .map(|r| {
            format!(
                "{} {} is in not_routes in OCI_ROUTES.json, but the server has it now. \
                 Move it to routes and give it a command or an exclusion",
                r.method, r.path
            )
        })
        .collect()
}

pub fn evaluate(
    spec_ops: &[SpecOp],
    table: &RouteTable,
    oci: &[PendingRoute],
    registry: &Registry,
    pending: &Pending,
    base_pending: Option<&Pending>,
) -> Findings {
    let mut f = Findings::default();

    let mut lines: BTreeMap<Key, Vec<&RegistryLine>> = BTreeMap::new();
    for line in &registry.commands {
        lines
            .entry(key(&line.method, &line.path))
            .or_default()
            .push(line);
    }
    let formats: Vec<String> = registry
        .class_exclusions
        .iter()
        .filter(|c| c.name == "format-get")
        .flat_map(|c| c.prefixes.clone())
        .collect();

    // Every route, once. The route table says which exist; the spec and the OCI list
    // add what the table can't see.
    let mut routes: BTreeMap<Key, (String, String, Option<String>)> = BTreeMap::new();
    for route in &table.routes {
        routes.insert(
            key(&route.method, &route.path),
            (
                route.method.clone(),
                route.path.clone(),
                Some(route.handler.clone()),
            ),
        );
    }
    let mut phantom = Vec::new();
    let spec_by_key: BTreeMap<Key, &SpecOp> = spec_ops
        .iter()
        .map(|op| (key(&op.method, &op.path), op))
        .collect();
    for k in spec_by_key.keys() {
        if !routes.contains_key(k) && !table_answers(&routes, k) {
            phantom.push(format!("{} {}", k.0, k.1));
        }
    }
    for route in oci {
        routes.entry(key(&route.method, &route.path)).or_insert((
            route.method.clone(),
            route.path.clone(),
            None,
        ));
    }
    for gone in phantom {
        f.errors.push(format!(
            "The spec has {gone}, but the route table doesn't. Either the extractor missed \
             it or the spec lies"
        ));
    }

    let pending_keys: BTreeSet<Key> = pending
        .routes
        .iter()
        .map(|r| key(&r.method, &r.path))
        .collect();
    let mut seen_classes: BTreeSet<&str> = BTreeSet::new();

    for (k, (method, path, handler)) in &routes {
        let spec_op = spec_by_key.get(k);
        let tag = match spec_op {
            Some(op) => op.tag.clone(),
            None => group_of(path, handler.as_deref().unwrap_or(""), &formats),
        };
        let mut status = Status::Missing;
        if let Some(found) = lines.get(k) {
            let commands: Vec<String> = found
                .iter()
                .filter(|l| l.excluded.is_none())
                .map(|l| l.command.clone())
                .collect();
            if !commands.is_empty() {
                status = Status::Covered(commands);
            } else if let Some(reason) = found.iter().find_map(|l| l.excluded.clone()) {
                status = Status::Excluded(reason);
            }
        }
        if status == Status::Missing
            && let Some(class) = class_for(&registry.class_exclusions, method, path)
        {
            seen_classes.insert(&class.name);
            *f.class_counts.entry(class.name.clone()).or_default() += 1;
            status = Status::Class(class.name.clone());
        }
        if status == Status::Missing && pending_keys.contains(k) {
            status = Status::Pending;
        }
        f.rows.push(RouteRow {
            method: method.clone(),
            path: path.clone(),
            tag,
            in_spec: spec_op.is_some(),
            status,
        });
    }

    // Registry lines have to be about real routes, and say why.
    for line in &registry.commands {
        let k = key(&line.method, &line.path);
        if !routes.contains_key(&k) && !table_answers(&routes, &k) {
            f.errors.push(match &line.excluded {
                Some(_) => format!(
                    "The exclusion of {} {} is for a route that doesn't exist",
                    line.method, line.path
                ),
                None => format!(
                    "`ak {}` claims {} {}, which isn't a route (dead command?)",
                    line.command, line.method, line.path
                ),
            });
        }
        if let Some(reason) = &line.excluded {
            check_reason(
                reason,
                &format!("{} {}", line.method, line.path),
                &mut f.errors,
            );
        }
    }
    for class in &registry.class_exclusions {
        check_reason(
            &class.reason,
            &format!("class {}", class.name),
            &mut f.errors,
        );
        if !seen_classes.contains(class.name.as_str()) {
            f.errors.push(format!(
                "The class exclusion {} matches no route, so it should go",
                class.name
            ));
        }
    }

    // The pending list: only for routes that are really waiting, and only ever shorter.
    for route in &pending.routes {
        let k = key(&route.method, &route.path);
        let label = format!("{} {}", route.method, route.path);
        if !routes.contains_key(&k) {
            f.errors.push(format!(
                "{label} is in COVERAGE_PENDING.json, but the server no longer has it. Remove it"
            ));
            continue;
        }
        if lines.get(&k).is_some_and(|l| !l.is_empty()) {
            f.errors.push(format!(
                "{label} has a registry line now. Remove it from COVERAGE_PENDING.json"
            ));
        }
        if let Some(class) = class_for(&registry.class_exclusions, &route.method, &route.path) {
            f.errors.push(format!(
                "{label} is in COVERAGE_PENDING.json and in the class exclusion {}. Pick one",
                class.name
            ));
        }
        if !is_wire_route(&route.path, &formats) {
            f.errors.push(format!(
                "{label} isn't a package-format route, so it can't wait for WS-F"
            ));
        }
    }
    if let Some(base) = base_pending {
        let was: BTreeSet<Key> = base
            .routes
            .iter()
            .map(|r| key(&r.method, &r.path))
            .collect();
        for route in &pending.routes {
            if !was.contains(&key(&route.method, &route.path)) {
                f.errors.push(format!(
                    "{} {} was added to COVERAGE_PENDING.json. That list only shrinks: \
                     give the route a command",
                    route.method, route.path
                ));
            }
        }
    }

    // L2: each covered spec operation against the union of its lines' binds.
    let mut opted_out: BTreeSet<(Key, &str)> = BTreeSet::new();
    for out in &registry.field_opt_outs {
        let label = format!("{} {} {}", out.method, out.path, out.field);
        check_reason(&out.reason, &label, &mut f.errors);
        let k = key(&out.method, &out.path);
        if spec_by_key
            .get(&k)
            .is_none_or(|op| !op.fields.contains(&out.field))
        {
            f.errors.push(format!(
                "{label} is opted out, but the spec has no such field. Remove the opt-out"
            ));
        }
        opted_out.insert((k, &out.field));
    }
    for op in spec_ops {
        let k = key(&op.method, &op.path);
        let Some(found) = lines.get(&k) else { continue };
        if found.iter().all(|l| l.excluded.is_some()) {
            continue;
        }
        f.field_total += op.fields.len();
        f.tag_fields.entry(op.tag.clone()).or_default().0 += op.fields.len();
        let bound: BTreeSet<&String> = found.iter().flat_map(|l| l.binds.iter()).collect();
        for field in &op.fields {
            if opted_out.contains(&(k.clone(), field.as_str())) {
                f.field_opt_outs += 1;
                continue;
            }
            if !bound.contains(field) {
                f.tag_fields.entry(op.tag.clone()).or_default().1 += 1;
                f.field_gaps
                    .entry(format!("{} {}", op.method, op.path))
                    .or_default()
                    .insert(field.clone());
                f.errors.push(format!(
                    "{} {} {field}: no flag binds this field (or the registry line doesn't say so)",
                    op.method, op.path
                ));
            }
        }
    }

    for row in &f.rows {
        if row.status == Status::Missing {
            f.errors.push(format!(
                "{} {} ({}) has no command, no exclusion and isn't pending",
                row.method, row.path, row.tag
            ));
        }
    }
    f
}

/// A spec op or line for a method the route answers through `any`.
fn table_answers(routes: &BTreeMap<Key, (String, String, Option<String>)>, k: &Key) -> bool {
    routes.contains_key(&("ANY".to_string(), k.1.clone()))
}

fn check_reason(reason: &str, what: &str, errors: &mut Vec<String>) {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        errors.push(format!("{what}: an exclusion needs a reason"));
    }
    // The regen bot must never add exclusions on its own.
    if trimmed.to_ascii_lowercase().starts_with("auto") {
        errors.push(format!(
            "{what}: an exclusion can't be automatic: \"{trimmed}\""
        ));
    }
}

fn is_wire_route(path: &str, formats: &[String]) -> bool {
    under(path, "/v2") || under(path, "/ext") || formats.iter().any(|p| under(path, p))
}

fn class_for<'a>(
    classes: &'a [ClassExclusion],
    method: &str,
    path: &str,
) -> Option<&'a ClassExclusion> {
    classes.iter().find(|c| {
        (c.methods.is_empty() || c.methods.iter().any(|m| m == method))
            && c.prefixes.iter().any(|p| under(path, p))
            && !c.except.iter().any(|p| under(path, p))
    })
}

/// A table of the routes per tag, in the format of the coverage plan's section 2.
pub fn report(f: &Findings) -> String {
    #[derive(Default)]
    struct Row {
        total: usize,
        covered: usize,
        excluded: usize,
        pending: usize,
        missing: usize,
    }
    let mut tags: BTreeMap<String, Row> = BTreeMap::new();
    let mut scopes: BTreeMap<&str, Row> = BTreeMap::new();
    let mut all = Row::default();
    for route in &f.rows {
        let scope = if route.in_spec {
            "Spec operations"
        } else if route.tag == "(oci)" {
            "OCI /v2"
        } else if route.tag == "(format wire)" {
            "Format wire routes"
        } else {
            "Backend routes not in the spec"
        };
        for row in [
            tags.entry(route.tag.clone()).or_default(),
            scopes.entry(scope).or_default(),
            &mut all,
        ] {
            row.total += 1;
            match route.status {
                Status::Covered(_) => row.covered += 1,
                Status::Excluded(_) | Status::Class(_) => row.excluded += 1,
                Status::Pending => row.pending += 1,
                Status::Missing => row.missing += 1,
            }
        }
    }
    let line = |name: &str, r: &Row| {
        format!(
            "| {name} | {} | {} | {} | {} | {} |\n",
            r.total, r.covered, r.excluded, r.pending, r.missing
        )
    };
    let header =
        "| Scope | Total | Covered | Excluded | Pending | Missing |\n|---|---|---|---|---|---|\n";
    let mut out = String::from("## Routes (L1)\n\n");
    out.push_str(header);
    for (name, row) in &scopes {
        out.push_str(&line(name, row));
    }
    out.push_str(&line("**All routes**", &all));
    out.push_str("\n## Per tag\n\n");
    out.push_str(
        "| Tag | Total | Covered | Excluded | Pending | Missing | Fields | Fields with no flag |\n\
         |---|---|---|---|---|---|---|---|\n",
    );
    for (name, row) in &tags {
        let (fields, gaps) = f.tag_fields.get(name).copied().unwrap_or((0, 0));
        out.push_str(&format!(
            "| {name} | {} | {} | {} | {} | {} | {fields} | {gaps} |\n",
            row.total, row.covered, row.excluded, row.pending, row.missing
        ));
    }
    if !f.class_counts.is_empty() {
        out.push_str("\n## Class exclusions\n\n");
        for (name, count) in &f.class_counts {
            out.push_str(&format!("- {name}: {count} routes\n"));
        }
    }
    let gaps: usize = f.field_gaps.values().map(BTreeSet::len).sum();
    out.push_str(&format!(
        "\n## Fields (L2)\n\n{} request fields on covered spec operations: {} bound, {} opted out, {} with no flag.\n",
        f.field_total,
        f.field_total.saturating_sub(gaps + f.field_opt_outs),
        f.field_opt_outs,
        gaps
    ));
    for (op, fields) in &f.field_gaps {
        let names: Vec<&str> = fields.iter().map(String::as_str).collect();
        out.push_str(&format!("- {op}: {}\n", names.join(", ")));
    }
    out
}

pub struct Options {
    pub check: bool,
    pub ak: Option<PathBuf>,
    pub base_ref: Option<String>,
    pub spec: Option<PathBuf>,
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("Failed to parse {}", path.display()))
}

fn load_registry(root: &Path, ak: Option<PathBuf>) -> Result<Registry> {
    let output = match ak {
        Some(path) => Command::new(path).arg("__registry").output(),
        None => Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()))
            .current_dir(root)
            .args(["run", "--quiet", "--bin", "ak", "--", "__registry"])
            .output(),
    }
    .context("Failed to run ak __registry")?;
    if !output.status.success() {
        bail!(
            "ak __registry failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("ak __registry didn't print JSON")
}

/// The pending list as it was at `git_ref`. Nothing if the file wasn't there yet.
fn pending_at(root: &Path, git_ref: &str) -> Result<Option<Pending>> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["show", &format!("{git_ref}:COVERAGE_PENDING.json")])
        .output()
        .context("Failed to run git show")?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&output.stdout).with_context(
        || format!("COVERAGE_PENDING.json at {git_ref} isn't valid"),
    )?))
}

pub fn run(root: &Path, options: Options) -> Result<()> {
    let spec_path = options.spec.unwrap_or_else(|| {
        root.parent()
            .expect("workspace has parent dir")
            .join("artifact-keeper-api/openapi.json")
    });
    let spec: Value = read_json(&spec_path)?;
    let table: RouteTable = read_json(&root.join("ROUTES.json"))?;
    let oci: OciRoutes = read_json(&root.join("OCI_ROUTES.json"))?;
    let pending: Pending = read_json(&root.join("COVERAGE_PENDING.json"))?;
    let base = match &options.base_ref {
        Some(git_ref) => pending_at(root, git_ref)?,
        None => None,
    };
    let pin = fs::read_to_string(root.join("API_VERSION"))?
        .trim()
        .to_string();
    if table.backend_version != pin {
        bail!(
            "ROUTES.json is from backend {}, but API_VERSION is {pin}. Run `xtask routes`.",
            table.backend_version
        );
    }
    let registry = load_registry(root, options.ak)?;
    let spec_ops = spec_operations(&spec);
    let mut findings = evaluate(
        &spec_ops,
        &table,
        &oci.routes,
        &registry,
        &pending,
        base.as_ref(),
    );
    findings
        .errors
        .extend(not_routes_problems(&oci, &spec_ops, &table, &registry));
    println!("{}", report(&findings));
    let raw = crate::raw_layer::check(root)?;
    println!(
        "Raw JSON: {} functions print the server's body as sent, {} entries opt out with a reason.\n",
        raw.captured, raw.opted_out
    );
    let errors: Vec<&String> = findings.errors.iter().chain(&raw.errors).collect();
    if errors.is_empty() {
        println!("Coverage gate: OK");
        return Ok(());
    }
    println!("## Problems ({})\n", errors.len());
    for error in &errors {
        println!("- {error}");
    }
    if options.check {
        bail!("Coverage gate: {} problems", errors.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::Route;

    fn route(method: &str, path: &str) -> Route {
        Route {
            method: method.to_string(),
            path: path.to_string(),
            handler: "h".to_string(),
        }
    }

    fn table(routes: &[(&str, &str)]) -> RouteTable {
        RouteTable {
            backend_version: "1.0.0".to_string(),
            routes: routes.iter().map(|(m, p)| route(m, p)).collect(),
        }
    }

    fn line(method: &str, path: &str, command: &str, binds: &[&str]) -> RegistryLine {
        RegistryLine {
            method: method.to_string(),
            path: path.to_string(),
            command: command.to_string(),
            binds: binds.iter().map(|b| b.to_string()).collect(),
            excluded: None,
        }
    }

    fn excluded(method: &str, path: &str, reason: &str) -> RegistryLine {
        RegistryLine {
            excluded: Some(reason.to_string()),
            ..line(method, path, "", &[])
        }
    }

    fn registry(lines: Vec<RegistryLine>) -> Registry {
        Registry {
            commands: lines,
            class_exclusions: vec![ClassExclusion {
                name: "format-get".to_string(),
                methods: vec!["GET".to_string()],
                prefixes: vec!["/npm".to_string()],
                except: vec![],
                reason: "curl adds nothing".to_string(),
            }],
            field_opt_outs: vec![],
        }
    }

    fn pending(routes: &[(&str, &str)]) -> Pending {
        Pending {
            comment: String::new(),
            routes: routes
                .iter()
                .map(|(m, p)| PendingRoute {
                    method: m.to_string(),
                    path: p.to_string(),
                })
                .collect(),
        }
    }

    fn op(method: &str, path: &str, fields: &[&str]) -> SpecOp {
        SpecOp {
            method: method.to_string(),
            path: path.to_string(),
            tag: "t".to_string(),
            fields: fields.iter().map(|f| f.to_string()).collect(),
        }
    }

    /// A little server: one API route, one wire GET and one wire PUT.
    fn small() -> RouteTable {
        table(&[
            ("GET", "/api/v1/a/{id}"),
            ("GET", "/npm/{r}/{p}"),
            ("PUT", "/npm/{r}/{p}"),
        ])
    }

    fn errors(
        spec: &[SpecOp],
        table: &RouteTable,
        reg: &Registry,
        pend: &Pending,
        base: Option<&Pending>,
    ) -> Vec<String> {
        evaluate(spec, table, &[], reg, pend, base).errors
    }

    #[test]
    fn a_route_listed_as_not_existing_that_appears_fails() {
        let route = PendingRoute {
            method: "PUT".to_string(),
            path: "/npm/{r}/{p}".to_string(),
        };
        let oci = OciRoutes {
            routes: vec![],
            not_routes: vec![route.clone()],
        };
        let reg = registry(vec![]);
        let appeared = not_routes_problems(&oci, &[], &small(), &reg);
        assert!(appeared[0].contains("has it now"), "{appeared:?}");

        let oci_too = OciRoutes {
            routes: vec![route],
            not_routes: oci.not_routes.clone(),
        };
        let empty = table(&[]);
        assert_eq!(not_routes_problems(&oci_too, &[], &empty, &reg).len(), 1);
        assert!(not_routes_problems(&oci, &[], &empty, &reg).is_empty());
    }

    #[test]
    fn a_covered_server_passes() {
        let e = errors(
            &[op("GET", "/api/v1/a/{id}", &[])],
            &small(),
            &registry(vec![line("GET", "/api/v1/a/{name}", "a show", &[])]),
            &pending(&[("PUT", "/npm/{r}/{p}")]),
            None,
        );
        assert_eq!(e, Vec::<String>::new());
    }

    #[test]
    fn a_new_route_fails() {
        let mut t = small();
        t.routes.push(route("POST", "/api/v1/new"));
        let e = errors(
            &[],
            &t,
            &registry(vec![line("GET", "/api/v1/a/{id}", "a show", &[])]),
            &pending(&[("PUT", "/npm/{r}/{p}")]),
            None,
        );
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("POST /api/v1/new"), "{e:?}");
    }

    #[test]
    fn a_new_wire_route_fails_rather_than_counting_as_pending() {
        let mut t = small();
        t.routes.push(route("DELETE", "/npm/{r}/{p}"));
        let e = errors(
            &[],
            &t,
            &registry(vec![line("GET", "/api/v1/a/{id}", "a show", &[])]),
            &pending(&[("PUT", "/npm/{r}/{p}")]),
            None,
        );
        assert!(e.iter().any(|x| x.contains("DELETE /npm")), "{e:?}");
    }

    #[test]
    fn a_pending_route_that_got_a_command_fails_until_it_comes_off() {
        let e = errors(
            &[],
            &small(),
            &registry(vec![
                line("GET", "/api/v1/a/{id}", "a show", &[]),
                line("PUT", "/npm/{r}/{p}", "pkg npm publish", &[]),
            ]),
            &pending(&[("PUT", "/npm/{r}/{p}")]),
            None,
        );
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("Remove it from COVERAGE_PENDING"), "{e:?}");
    }

    #[test]
    fn the_pending_list_only_shrinks() {
        let mut t = small();
        t.routes.push(route("POST", "/npm/{r}/{p}"));
        let e = errors(
            &[],
            &t,
            &registry(vec![line("GET", "/api/v1/a/{id}", "a show", &[])]),
            &pending(&[("PUT", "/npm/{r}/{p}"), ("POST", "/npm/{r}/{p}")]),
            Some(&pending(&[("PUT", "/npm/{r}/{p}")])),
        );
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("only shrinks"), "{e:?}");
    }

    #[test]
    fn a_pending_route_the_server_dropped_fails() {
        let e = errors(
            &[],
            &small(),
            &registry(vec![line("GET", "/api/v1/a/{id}", "a show", &[])]),
            &pending(&[("PUT", "/npm/{r}/{p}"), ("PUT", "/npm/{r}/gone")]),
            None,
        );
        assert!(e.iter().any(|x| x.contains("no longer has")), "{e:?}");
    }

    #[test]
    fn an_api_route_cannot_wait_for_the_format_helpers() {
        let e = errors(
            &[],
            &small(),
            &registry(vec![]),
            &pending(&[("PUT", "/npm/{r}/{p}"), ("GET", "/api/v1/a/{id}")]),
            None,
        );
        assert!(e.iter().any(|x| x.contains("can't wait for WS-F")), "{e:?}");
    }

    #[test]
    fn a_format_get_is_excluded_by_its_class_but_a_put_is_not() {
        let f = evaluate(&[], &small(), &[], &registry(vec![]), &pending(&[]), None);
        let status = |m: &str| {
            f.rows
                .iter()
                .find(|r| r.method == m && r.path.starts_with("/npm"))
                .map(|r| r.status.clone())
        };
        assert_eq!(status("GET"), Some(Status::Class("format-get".to_string())));
        assert_eq!(status("PUT"), Some(Status::Missing));
    }

    #[test]
    fn a_class_exclusion_that_matches_nothing_fails() {
        let e = errors(
            &[],
            &table(&[("GET", "/api/v1/a")]),
            &registry(vec![line("GET", "/api/v1/a", "a", &[])]),
            &pending(&[]),
            None,
        );
        assert!(e.iter().any(|x| x.contains("matches no route")), "{e:?}");
    }

    #[test]
    fn a_registry_line_for_no_route_is_dead() {
        let e = errors(
            &[],
            &small(),
            &registry(vec![
                line("GET", "/api/v1/a/{id}", "a show", &[]),
                line("GET", "/api/v1/gone", "gone", &[]),
            ]),
            &pending(&[("PUT", "/npm/{r}/{p}")]),
            None,
        );
        assert!(e.iter().any(|x| x.contains("dead command")), "{e:?}");
    }

    #[test]
    fn an_exclusion_needs_a_real_reason_for_a_real_route() {
        let empty = errors(
            &[],
            &small(),
            &registry(vec![
                excluded("GET", "/api/v1/a/{id}", "  "),
                excluded("PUT", "/npm/{r}/{p}", "auto: added by the bot"),
                excluded("GET", "/api/v1/gone", "fine"),
            ]),
            &pending(&[]),
            None,
        );
        assert!(
            empty.iter().any(|x| x.contains("needs a reason")),
            "{empty:?}"
        );
        assert!(
            empty.iter().any(|x| x.contains("can't be automatic")),
            "{empty:?}"
        );
        assert!(
            empty.iter().any(|x| x.contains("doesn't exist")),
            "{empty:?}"
        );
    }

    #[test]
    fn the_spec_having_a_route_the_table_lacks_fails() {
        let e = errors(
            &[op("GET", "/api/v1/phantom", &[])],
            &small(),
            &registry(vec![line("GET", "/api/v1/a/{id}", "a show", &[])]),
            &pending(&[("PUT", "/npm/{r}/{p}")]),
            None,
        );
        assert!(e.iter().any(|x| x.contains("phantom")), "{e:?}");
    }

    #[test]
    fn a_field_with_no_flag_fails_unless_it_opts_out_with_a_reason() {
        let spec = [op("GET", "/api/v1/a/{id}", &["page", "size"])];
        let mut reg = registry(vec![line("GET", "/api/v1/a/{id}", "a show", &["page"])]);
        let pend = pending(&[("PUT", "/npm/{r}/{p}")]);
        let e = errors(&spec, &small(), &reg, &pend, None);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("size"), "{e:?}");

        let opt_out = |field: &str, reason: &str| FieldOptOut {
            method: "GET".to_string(),
            path: "/api/v1/a/{id}".to_string(),
            field: field.to_string(),
            reason: reason.to_string(),
        };
        reg.field_opt_outs = vec![opt_out("size", "the route already says")];
        assert_eq!(
            errors(&spec, &small(), &reg, &pend, None),
            Vec::<String>::new()
        );

        reg.field_opt_outs = vec![opt_out("size", " ")];
        let e = errors(&spec, &small(), &reg, &pend, None);
        assert!(e.iter().any(|x| x.contains("needs a reason")), "{e:?}");

        reg.field_opt_outs = vec![opt_out("size", "ok"), opt_out("gone", "ok")];
        let e = errors(&spec, &small(), &reg, &pend, None);
        assert!(e.iter().any(|x| x.contains("no such field")), "{e:?}");
    }

    #[test]
    fn spec_fields_come_from_query_and_body_through_refs() {
        let spec = serde_json::json!({
            "paths": {"/x/{id}": {"post": {
                "tags": ["t"],
                "parameters": [
                    {"name": "id", "in": "path"},
                    {"name": "page", "in": "query"},
                    {"$ref": "#/components/parameters/size"}
                ],
                "requestBody": {"content": {"application/json": {"schema":
                    {"$ref": "#/components/schemas/B"}}}}
            }}},
            "components": {
                "parameters": {"size": {"name": "size", "in": "query"}},
                "schemas": {"B": {"allOf": [
                    {"properties": {"a": {}}},
                    {"oneOf": [{"properties": {"b": {}}}]}
                ]}}
            }
        });
        let ops = spec_operations(&spec);
        assert_eq!(ops.len(), 1);
        let fields: Vec<&str> = ops[0].fields.iter().map(String::as_str).collect();
        assert_eq!(fields, ["a", "b", "page", "size"]);
    }

    #[test]
    fn the_report_counts_each_kind() {
        let f = evaluate(
            &[op("GET", "/api/v1/a/{id}", &[])],
            &small(),
            &[],
            &registry(vec![line("GET", "/api/v1/a/{id}", "a show", &[])]),
            &pending(&[("PUT", "/npm/{r}/{p}")]),
            None,
        );
        let text = report(&f);
        assert!(
            text.contains("| **All routes** | 3 | 1 | 1 | 1 | 0 |"),
            "{text}"
        );
        assert!(text.contains("format-get: 1 routes"), "{text}");
    }
}
