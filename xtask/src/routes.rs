//! `xtask routes`: the backend's route table, read from its source.
//!
//! The OpenAPI spec doesn't list every route the server has, so the coverage gate
//! needs the router itself. This walks `backend/src/api/routes.rs` from
//! `create_router`, following `.route`, `.nest` and `.merge` into the handler
//! modules, and writes `ROUTES.json`.
//!
//! It parses the source with `syn` and evaluates just enough of it: `let` and
//! assignment, `if` and `match` (every branch counts, so a route behind a config
//! switch or a cargo feature is still a route), `for` over a list of strings,
//! calls to router functions and to closures, and `format!` with inline string
//! arguments. Anything mounted that it can't resolve is an error, not a silently
//! shorter list.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use quote::ToTokens;
use serde::{Deserialize, Serialize};

/// Merged or nested things that aren't routers of the API. Swagger UI is opt-in and
/// `/api/v1/openapi.json` is added by hand in [`EXTRA_ROUTES`].
const IGNORED_MOUNTS: &[&str] = &["SwaggerUi"];

/// Routes added by a library rather than the backend's own router calls.
const EXTRA_ROUTES: &[(&str, &str, &str)] = &[
    ("GET", "/api/v1/openapi.json", "swagger"),
    ("GET", "/swagger-ui", "swagger"),
    ("GET", "/swagger-ui/{path}", "swagger"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub method: String,
    pub path: String,
    /// The handler module that defines it.
    pub handler: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTable {
    pub backend_version: String,
    pub routes: Vec<Route>,
}

/// `:name` and `*name` become `{name}`, and a trailing slash goes.
///
/// `nest("/x", Router::new().route("/", ..))` reads as `/x/` when the prefix and the
/// path are joined, while the spec and the registry write `/x`. A route written with
/// a real trailing slash, such as Ansible's `/api/`, is the same line of the gate as
/// the one without: `ak api` can send either.
pub fn normalize(path: &str) -> String {
    let segments: Vec<String> = path
        .split('/')
        .map(|segment| {
            // npm's scoped routes have `@:scope`, a parameter after a literal `@`.
            let (literal, rest) = match segment.strip_prefix('@') {
                Some(rest) => ("@", rest),
                None => ("", segment),
            };
            match rest.strip_prefix(':').or_else(|| rest.strip_prefix('*')) {
                Some(name) => format!("{literal}{{{name}}}"),
                None => segment.replacen("{*", "{", 1),
            }
        })
        .collect();
    let joined = segments.join("/");
    let trimmed = joined.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

/// The form two routes are compared in: parameter names don't count.
pub fn shape(path: &str) -> String {
    normalize(path)
        .split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "{}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[derive(Clone, Debug)]
enum Val {
    Router(Vec<Route>),
    Method(Vec<String>),
    Str(String),
    /// A slice or array of string literals, such as `const V: &[&str] = &["a", "b"]`.
    List(Vec<String>),
    Closure(Box<syn::ExprClosure>),
    Unknown(String),
}

#[derive(Default)]
struct Extractor {
    /// Handler module name to its parsed file. A child module, such as
    /// `handlers/repositories/delete_job.rs`, is `repositories/delete_job`.
    modules: HashMap<String, syn::File>,
    unresolved: BTreeSet<String>,
}

type Env = HashMap<String, Val>;

const METHOD_FNS: &[&str] = &["get", "post", "put", "delete", "patch", "head", "options"];

fn method_of(name: &str) -> Option<String> {
    if name == "any" {
        return Some("ANY".to_string());
    }
    METHOD_FNS
        .contains(&name)
        .then(|| name.to_ascii_uppercase())
}

fn is_test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg") && {
            let tokens = a.to_token_stream().to_string();
            tokens.contains("test") && !tokens.contains("not (test")
        }
    })
}

fn merge(a: Val, b: Val) -> Val {
    match (a, b) {
        (Val::Router(mut x), Val::Router(y)) => {
            x.extend(y);
            Val::Router(x)
        }
        (Val::Method(mut x), Val::Method(y)) => {
            x.extend(y);
            Val::Method(x)
        }
        // A branch that gives nothing we understand, next to one we do.
        (Val::Unknown(_), other) | (other, Val::Unknown(_)) => other,
        (a, _) => a,
    }
}

impl Extractor {
    fn find_fn(&self, module: &str, name: &str) -> Option<&syn::ItemFn> {
        self.modules.get(module)?.items.iter().find_map(|item| {
            let syn::Item::Fn(f) = item else { return None };
            (f.sig.ident == name && !is_test_only(&f.attrs)).then_some(f)
        })
    }

    fn call_fn(&mut self, module: &str, name: &str, args: Vec<Val>, depth: usize) -> Option<Val> {
        let f = self.find_fn(module, name)?.clone();
        let mut env = Env::new();
        for (input, value) in f.sig.inputs.iter().zip(args) {
            if let syn::FnArg::Typed(t) = input
                && let syn::Pat::Ident(p) = &*t.pat
            {
                env.insert(p.ident.to_string(), value);
            }
        }
        Some(self.block(&f.block, &mut env, module, depth + 1))
    }

    fn block(&mut self, block: &syn::Block, env: &mut Env, module: &str, depth: usize) -> Val {
        let mut last = Val::Unknown("empty block".to_string());
        for stmt in &block.stmts {
            match stmt {
                syn::Stmt::Local(local) => {
                    if is_test_only(&local.attrs) {
                        continue;
                    }
                    let name = match &local.pat {
                        syn::Pat::Ident(p) => Some(p.ident.to_string()),
                        syn::Pat::Type(t) => match &*t.pat {
                            syn::Pat::Ident(p) => Some(p.ident.to_string()),
                            _ => None,
                        },
                        _ => None,
                    };
                    if let (Some(name), Some(init)) = (name, &local.init) {
                        let value = self.expr(&init.expr, env, module, depth);
                        env.insert(name, value);
                    }
                    last = Val::Unknown("let".to_string());
                }
                syn::Stmt::Expr(expr, semi) => {
                    let value = self.expr(expr, env, module, depth);
                    last = if semi.is_some() {
                        Val::Unknown("statement".to_string())
                    } else {
                        value
                    };
                }
                syn::Stmt::Item(_) | syn::Stmt::Macro(_) => {}
            }
        }
        last
    }

    /// Run each branch on its own copy of the variables, then union what they did.
    fn branches(
        &mut self,
        blocks: Vec<BranchBody<'_>>,
        env: &mut Env,
        module: &str,
        depth: usize,
    ) -> Val {
        let before = env.clone();
        let mut result = Val::Unknown("no branch".to_string());
        let mut after: Vec<Env> = Vec::new();
        for body in blocks {
            let mut scope = before.clone();
            let value = match body {
                BranchBody::Block(b) => self.block(b, &mut scope, module, depth),
                BranchBody::Expr(e) => self.expr(e, &mut scope, module, depth),
            };
            result = merge(result, value);
            after.push(scope);
        }
        for scope in after {
            for (name, value) in scope {
                let Some(old) = env.get(&name) else { continue };
                let merged = merge(old.clone(), value);
                env.insert(name, merged);
            }
        }
        for value in env.values_mut() {
            if let Val::Router(routes) = value {
                dedup(routes);
            }
        }
        result
    }

    fn expr(&mut self, expr: &syn::Expr, env: &mut Env, module: &str, depth: usize) -> Val {
        if depth > 32 {
            return Val::Unknown("too deep".to_string());
        }
        match expr {
            syn::Expr::Paren(e) => self.expr(&e.expr, env, module, depth),
            syn::Expr::Group(e) => self.expr(&e.expr, env, module, depth),
            syn::Expr::Reference(e) => self.expr(&e.expr, env, module, depth),
            syn::Expr::Try(e) => self.expr(&e.expr, env, module, depth),
            syn::Expr::Return(e) => match &e.expr {
                Some(inner) => self.expr(inner, env, module, depth),
                None => Val::Unknown("return".to_string()),
            },
            syn::Expr::Lit(e) => match &e.lit {
                syn::Lit::Str(s) => Val::Str(s.value()),
                _ => Val::Unknown("literal".to_string()),
            },
            syn::Expr::Path(e) => match e.path.get_ident() {
                Some(ident) => env
                    .get(&ident.to_string())
                    .cloned()
                    .or_else(|| self.find_const(module, &ident.to_string()))
                    .unwrap_or_else(|| Val::Unknown(ident.to_string())),
                None => {
                    let segments: Vec<String> = e
                        .path
                        .segments
                        .iter()
                        .map(|s| s.ident.to_string())
                        .collect();
                    let name = segments.last().map(String::as_str).unwrap_or("");
                    let owner = segments
                        .iter()
                        .rev()
                        .nth(1)
                        .map(String::as_str)
                        .unwrap_or("");
                    self.find_const(&self.resolve_module(module, owner), name)
                        .or_else(|| self.find_const(&format!("formats/{owner}"), name))
                        .or_else(|| self.find_const_anywhere(name))
                        .unwrap_or_else(|| Val::Unknown(e.to_token_stream().to_string()))
                }
            },
            syn::Expr::Macro(e) => self.format_macro(&e.mac, env, module, depth),
            syn::Expr::Block(e) => {
                let mut scope = env.clone();
                self.block(&e.block, &mut scope, module, depth)
            }
            syn::Expr::Assign(e) => {
                let value = self.expr(&e.right, env, module, depth);
                if let syn::Expr::Path(p) = &*e.left
                    && let Some(ident) = p.path.get_ident()
                {
                    env.insert(ident.to_string(), value);
                }
                Val::Unknown("assignment".to_string())
            }
            syn::Expr::If(e) => {
                let mut bodies = vec![BranchBody::Block(&e.then_branch)];
                if let Some((_, otherwise)) = &e.else_branch {
                    bodies.push(BranchBody::Expr(otherwise));
                }
                self.branches(bodies, env, module, depth)
            }
            syn::Expr::Match(e) => {
                let bodies = e.arms.iter().map(|a| BranchBody::Expr(&a.body)).collect();
                self.branches(bodies, env, module, depth)
            }
            syn::Expr::Array(e) => {
                let mut items = Vec::new();
                for item in &e.elems {
                    match self.expr(item, env, module, depth) {
                        Val::Str(s) => items.push(s),
                        _ => return Val::Unknown(e.to_token_stream().to_string()),
                    }
                }
                Val::List(items)
            }
            syn::Expr::Closure(e) => Val::Closure(Box::new(e.clone())),
            syn::Expr::ForLoop(e) => self.for_loop(e, env, module, depth),
            syn::Expr::Call(e) => self.call(e, env, module, depth),
            syn::Expr::MethodCall(e) => self.method_call(e, env, module, depth),
            other => Val::Unknown(other.to_token_stream().to_string()),
        }
    }

    /// `for x in LIST { .. }`: the body once per item, in order. An assignment to a
    /// variable from outside the loop, such as `router = router.route(..)`, adds up
    /// across the items; the loop variable and a `let` in the body end with it.
    ///
    /// A loop over something else is an error if its body mounts anything,
    /// since skipping it would drop routes without a word.
    fn for_loop(&mut self, e: &syn::ExprForLoop, env: &mut Env, module: &str, depth: usize) -> Val {
        let iterable = self.expr(&e.expr, env, module, depth);
        let var = match &*e.pat {
            syn::Pat::Ident(p) => Some(p.ident.to_string()),
            _ => None,
        };
        match (iterable, var) {
            (Val::List(items), Some(var)) => {
                let declared = let_names(&e.body);
                for item in items {
                    let mut scope = env.clone();
                    scope.insert(var.clone(), Val::Str(item));
                    self.block(&e.body, &mut scope, module, depth);
                    for (name, value) in scope {
                        if name != var && !declared.contains(&name) && env.contains_key(&name) {
                            env.insert(name, value);
                        }
                    }
                }
            }
            (iterable, _) => {
                if mounts_routes(e.body.to_token_stream()) {
                    self.unresolved.insert(format!(
                        "{module}: for {} in {iterable:?}",
                        e.pat.to_token_stream()
                    ));
                }
            }
        }
        Val::Unknown("for".to_string())
    }

    /// Call a closure held in a variable: its body, with the arguments bound to its
    /// parameters, on a copy of the caller's variables (which is where a closure
    /// written in the same function finds what it captured).
    fn call_closure(
        &mut self,
        closure: &syn::ExprClosure,
        args: Vec<Val>,
        env: &Env,
        module: &str,
        depth: usize,
    ) -> Val {
        let mut scope = env.clone();
        for (input, value) in closure.inputs.iter().zip(args) {
            let pat = match input {
                syn::Pat::Type(t) => &*t.pat,
                other => other,
            };
            if let syn::Pat::Ident(p) = pat {
                scope.insert(p.ident.to_string(), value);
            }
        }
        self.expr(&closure.body, &mut scope, module, depth + 1)
    }

    /// `format!` with a literal, inline arguments and positional `{}` arguments.
    fn format_macro(&mut self, mac: &syn::Macro, env: &mut Env, module: &str, depth: usize) -> Val {
        let whole = || Val::Unknown(mac.to_token_stream().to_string());
        if !mac.path.is_ident("format") {
            return whole();
        }
        let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
        let Ok(parts) = mac.parse_body_with(parser) else {
            return whole();
        };
        let mut parts = parts.iter();
        let Some(Val::Str(mut text)) = parts.next().map(|e| self.expr(e, env, module, depth))
        else {
            return whole();
        };
        for part in parts {
            let Val::Str(value) = self.expr(part, env, module, depth) else {
                return whole();
            };
            text = text.replacen("{}", &value, 1);
        }
        for (name, value) in env.iter() {
            if let Val::Str(s) = value {
                text = text.replace(&format!("{{{name}}}"), s);
            }
        }
        // What's left inline can be a constant, such as `format!("/x{HOLDS_PATH}")`.
        for name in inline_names(&text) {
            if let Some(Val::Str(s)) = self
                .find_const(module, &name)
                .or_else(|| self.find_const_anywhere(&name))
            {
                text = text.replace(&format!("{{{name}}}"), &s);
            }
        }
        // A constant it couldn't find would stay as `{NAME}` and read as a path
        // parameter, so the route would be in the table under the wrong path.
        let missing: Vec<String> = inline_names(&text)
            .into_iter()
            .filter(|name| is_const_name(name))
            .collect();
        if !missing.is_empty() {
            self.unresolved.insert(format!(
                "{module}: format! {text:?} uses {}, which isn't a constant it can find",
                missing
                    .iter()
                    .map(|n| format!("{{{n}}}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            return Val::Unknown(mac.to_token_stream().to_string());
        }
        Val::Str(text)
    }

    fn find_const(&self, module: &str, name: &str) -> Option<Val> {
        self.modules.get(module)?.items.iter().find_map(|item| {
            let syn::Item::Const(c) = item else {
                return None;
            };
            if c.ident != name {
                return None;
            }
            const_value(&c.expr)
        })
    }

    /// The module a call or path names as `owner::`, seen from `module`: `self` is
    /// `module`, `super` its parent, and a child module of `module` wins over a
    /// handler module of the same name.
    fn resolve_module(&self, module: &str, owner: &str) -> String {
        match owner {
            "self" => module.to_string(),
            "super" => match module.rsplit_once('/') {
                Some((parent, _)) => parent.to_string(),
                None => module.to_string(),
            },
            _ => {
                let child = format!("{module}/{owner}");
                if self.modules.contains_key(&child) {
                    child
                } else {
                    owner.to_string()
                }
            }
        }
    }

    /// A constant named through a path this walk doesn't parse, such as a format's
    /// module outside `handlers`.
    fn find_const_anywhere(&self, name: &str) -> Option<Val> {
        let mut found = self.modules.keys().filter_map(|m| self.find_const(m, name));
        let first = found.next()?;
        found.next().is_none().then_some(first)
    }

    fn call(&mut self, e: &syn::ExprCall, env: &mut Env, module: &str, depth: usize) -> Val {
        let syn::Expr::Path(func) = &*e.func else {
            return Val::Unknown(e.to_token_stream().to_string());
        };
        let segments: Vec<String> = func
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        let name = segments.last().map(String::as_str).unwrap_or("");
        if let Some(method) = method_of(name) {
            return Val::Method(vec![method]);
        }
        if segments.iter().any(|s| s == "Router") && name == "new" {
            return Val::Router(Vec::new());
        }
        let target = if segments.len() >= 2 {
            self.resolve_module(module, &segments[segments.len() - 2])
        } else {
            module.to_string()
        };
        let args: Vec<Val> = e
            .args
            .iter()
            .map(|a| self.expr(a, env, module, depth))
            .collect();
        if segments.len() == 1
            && let Some(Val::Closure(closure)) = env.get(name).cloned()
        {
            return self.call_closure(&closure, args, env, module, depth);
        }
        match self.call_fn(&target, name, args, depth) {
            Some(value) => value,
            None => Val::Unknown(segments.join("::")),
        }
    }

    fn method_call(
        &mut self,
        e: &syn::ExprMethodCall,
        env: &mut Env,
        module: &str,
        depth: usize,
    ) -> Val {
        let name = e.method.to_string();
        let receiver = self.expr(&e.receiver, env, module, depth);
        let arg = |i: usize| e.args.iter().nth(i);
        match (&receiver, name.as_str()) {
            (Val::Router(existing), "route") => {
                let path = arg(0).map(|a| self.expr(a, env, module, depth));
                let handler = arg(1).map(|a| self.expr(a, env, module, depth));
                let mut routes = existing.clone();
                match (path, handler) {
                    (Some(Val::Str(path)), Some(Val::Method(methods))) => {
                        for method in methods {
                            routes.push(Route {
                                method,
                                path: path.clone(),
                                handler: module.to_string(),
                            });
                        }
                    }
                    (path, handler) => {
                        self.unresolved
                            .insert(format!("{module}: route {path:?} {handler:?}"));
                    }
                }
                Val::Router(routes)
            }
            (Val::Router(existing), "nest") => {
                let prefix = arg(0).map(|a| self.expr(a, env, module, depth));
                let inner = arg(1).map(|a| self.expr(a, env, module, depth));
                let mut routes = existing.clone();
                match (prefix, inner) {
                    (Some(Val::Str(prefix)), Some(Val::Router(inner))) => {
                        routes.extend(inner.into_iter().map(|mut r| {
                            r.path = format!("{prefix}{}", r.path);
                            r
                        }));
                    }
                    (prefix, inner) => {
                        self.unresolved
                            .insert(format!("{module}: nest {prefix:?} {inner:?}"));
                    }
                }
                Val::Router(routes)
            }
            (Val::Router(existing), "merge") => {
                let inner = arg(0).map(|a| self.expr(a, env, module, depth));
                let mut routes = existing.clone();
                match inner {
                    Some(Val::Router(inner)) => routes.extend(inner),
                    Some(Val::Unknown(what))
                        if IGNORED_MOUNTS.iter().any(|ok| what.contains(ok)) => {}
                    other => {
                        self.unresolved.insert(format!("{module}: merge {other:?}"));
                    }
                }
                Val::Router(routes)
            }
            (Val::Method(existing), _) if method_of(&name).is_some() => {
                let mut methods = existing.clone();
                methods.extend(method_of(&name));
                Val::Method(methods)
            }
            // `.layer`, `.route_layer`, `.with_state`, `.fallback`, `.url` and so on
            // change how a route behaves, not which routes there are.
            _ => match receiver {
                Val::Unknown(what) if name == "url" => Val::Unknown(what),
                other => other,
            },
        }
    }
}

/// Router methods that add a route or a handler. A loop whose body calls one of these
/// can't be skipped.
const MOUNT_METHODS: &[&str] = &[
    "route",
    "route_service",
    "nest",
    "nest_service",
    "merge",
    "fallback",
    "fallback_service",
];

/// Does this code call a method in [`MOUNT_METHODS`]? A method call is `.` and then
/// the name, so `router` or `self.routes` doesn't count and `.fallback(..)` does.
fn mounts_routes(tokens: proc_macro2::TokenStream) -> bool {
    let mut after_dot = false;
    for token in tokens {
        match token {
            proc_macro2::TokenTree::Group(g) => {
                if mounts_routes(g.stream()) {
                    return true;
                }
                after_dot = false;
            }
            proc_macro2::TokenTree::Punct(p) => after_dot = p.as_char() == '.',
            proc_macro2::TokenTree::Ident(i) => {
                if after_dot && MOUNT_METHODS.iter().any(|m| i == m) {
                    return true;
                }
                after_dot = false;
            }
            proc_macro2::TokenTree::Literal(_) => after_dot = false,
        }
    }
    false
}

/// The names a block's own `let` statements bind. They shadow, rather than change,
/// a variable of the same name outside the block.
fn let_names(block: &syn::Block) -> BTreeSet<String> {
    block
        .stmts
        .iter()
        .filter_map(|stmt| {
            let syn::Stmt::Local(local) = stmt else {
                return None;
            };
            match &local.pat {
                syn::Pat::Ident(p) => Some(p.ident.to_string()),
                syn::Pat::Type(t) => match &*t.pat {
                    syn::Pat::Ident(p) => Some(p.ident.to_string()),
                    _ => None,
                },
                _ => None,
            }
        })
        .collect()
}

/// A placeholder named like a constant: `{HOLDS_PATH}`, not `{v}`.
fn is_const_name(name: &str) -> bool {
    name.chars().any(|c| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// The `{name}` placeholders in a format string, in order.
fn inline_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        rest = &rest[start + 1..];
        let Some(end) = rest.find('}') else { break };
        let name = &rest[..end];
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            names.push(name.to_string());
        }
        rest = &rest[end + 1..];
    }
    names
}

/// A `const`'s value: a string literal, or a slice or array of them.
fn const_value(expr: &syn::Expr) -> Option<Val> {
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) => Some(Val::Str(s.value())),
        syn::Expr::Reference(r) => const_value(&r.expr),
        syn::Expr::Array(a) => a
            .elems
            .iter()
            .map(|item| match const_value(item)? {
                Val::Str(s) => Some(s),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .map(Val::List),
        _ => None,
    }
}

enum BranchBody<'a> {
    Block(&'a syn::Block),
    Expr(&'a syn::Expr),
}

fn dedup(routes: &mut Vec<Route>) {
    let mut seen = BTreeSet::new();
    routes.retain(|r| seen.insert((r.method.clone(), r.path.clone())));
}

fn parse(path: &Path) -> Result<syn::File> {
    let text =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    syn::parse_file(&text).with_context(|| format!("Failed to parse {}", path.display()))
}

/// The handler modules under `dir`, named by their path from `handlers`: `x.rs`
/// or `x/mod.rs` is `x`, and a child module in `x/` is `x/child`.
fn handler_files(dir: &Path, prefix: &str, files: &mut Vec<(String, PathBuf)>) -> Result<()> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("Failed to read {}", dir.display()))?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    entries.sort();
    for path in entries {
        let name = |stem: &std::ffi::OsStr| format!("{prefix}{}", stem.to_string_lossy());
        if path.extension().is_some_and(|e| e == "rs") {
            let stem = path.file_stem().unwrap_or_default();
            if stem != "mod" || prefix.is_empty() {
                files.push((name(stem), path.clone()));
            }
        } else if path.is_dir() {
            let module = name(path.file_name().unwrap_or_default());
            if path.join("mod.rs").exists() {
                files.push((module.clone(), path.join("mod.rs")));
            }
            handler_files(&path, &format!("{module}/"), files)?;
        }
    }
    Ok(())
}

/// Read the route table from a checkout of the backend.
pub fn extract(backend: &Path) -> Result<RouteTable> {
    let api = backend.join("backend/src/api");
    ensure!(
        api.join("routes.rs").exists(),
        "No backend/src/api/routes.rs under {}",
        backend.display()
    );
    let mut x = Extractor::default();
    x.modules
        .insert("routes".to_string(), parse(&api.join("routes.rs"))?);
    // Constants a route path is built from can live with the format's own code.
    for entry in fs::read_dir(backend.join("backend/src/formats"))
        .into_iter()
        .flatten()
    {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "rs") {
            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
            x.modules.insert(format!("formats/{stem}"), parse(&path)?);
        }
    }
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    handler_files(&api.join("handlers"), "", &mut files)?;
    for (name, path) in files {
        x.modules.insert(name, parse(&path)?);
    }

    let table = x
        .call_fn(
            "routes",
            "create_router",
            vec![Val::Unknown("state".to_string())],
            0,
        )
        .context("create_router not found in routes.rs")?;
    let Val::Router(raw) = table else {
        bail!("create_router didn't evaluate to a router: {table:?}");
    };
    ensure!(
        x.unresolved.is_empty(),
        "Couldn't resolve these mounts, so the table would be short:\n{}",
        x.unresolved.iter().cloned().collect::<Vec<_>>().join("\n")
    );

    let mut unique: BTreeMap<(String, String), Route> = BTreeMap::new();
    for route in raw {
        let path = normalize(&route.path);
        unique
            .entry((path.clone(), route.method.clone()))
            .or_insert(Route { path, ..route });
    }
    for (method, path, handler) in EXTRA_ROUTES {
        unique
            .entry((path.to_string(), method.to_string()))
            .or_insert(Route {
                method: method.to_string(),
                path: path.to_string(),
                handler: handler.to_string(),
            });
    }
    Ok(RouteTable {
        backend_version: backend_version(backend)?,
        routes: unique.into_values().collect(),
    })
}

/// The version in the backend's workspace manifest.
fn backend_version(backend: &Path) -> Result<String> {
    let manifest = fs::read_to_string(backend.join("Cargo.toml"))
        .with_context(|| format!("Failed to read {}/Cargo.toml", backend.display()))?;
    manifest
        .lines()
        .find_map(|line| {
            let value = line.trim().strip_prefix("version")?.trim_start();
            let value = value.strip_prefix('=')?.trim();
            Some(value.trim_matches('"').to_string())
        })
        .context("No version in the backend's Cargo.toml")
}

/// Pretty JSON with one route per line, so a regen's diff reads as a list of routes.
pub fn to_json(table: &RouteTable) -> String {
    let mut out = format!(
        "{{\n  \"backend_version\": {},\n  \"routes\": [\n",
        serde_json::Value::from(table.backend_version.clone())
    );
    let lines: Vec<String> = table
        .routes
        .iter()
        .map(|r| {
            format!(
                "    {{\"method\": {}, \"path\": {}, \"handler\": {}}}",
                serde_json::Value::from(r.method.clone()),
                serde_json::Value::from(r.path.clone()),
                serde_json::Value::from(r.handler.clone()),
            )
        })
        .collect();
    out.push_str(&lines.join(",\n"));
    out.push_str("\n  ]\n}\n");
    out
}

/// `xtask routes [--backend <dir>] [--check]`.
pub fn run(root: &Path, backend: Option<PathBuf>, check: bool) -> Result<()> {
    let backend = backend.unwrap_or_else(|| {
        root.parent()
            .expect("workspace has parent dir")
            .join("artifact-keeper")
    });
    let table = extract(&backend)?;
    let pin = fs::read_to_string(root.join("API_VERSION"))?
        .trim()
        .to_string();
    ensure!(
        table.backend_version == pin,
        "The backend at {} is {}, but API_VERSION is {pin}. Check out v{pin}.",
        backend.display(),
        table.backend_version
    );
    let wanted = to_json(&table);
    let file = root.join("ROUTES.json");
    if check {
        let committed = fs::read_to_string(&file).unwrap_or_default();
        if committed != wanted {
            let old: Vec<Route> = serde_json::from_str::<RouteTable>(&committed)
                .map(|t| t.routes)
                .unwrap_or_default();
            let key = |r: &Route| format!("{} {}", r.method, r.path);
            let was: BTreeSet<String> = old.iter().map(key).collect();
            let now: BTreeSet<String> = table.routes.iter().map(key).collect();
            for gone in was.difference(&now) {
                eprintln!("- {gone}");
            }
            for added in now.difference(&was) {
                eprintln!("+ {added}");
            }
            bail!(
                "ROUTES.json is out of date. Run `cargo run -p xtask -- routes` with the \
                 backend checked out at v{pin}."
            );
        }
        eprintln!("ROUTES.json is up to date: {} routes.", table.routes.len());
    } else {
        fs::write(&file, wanted)?;
        eprintln!("Wrote {}: {} routes.", file.display(), table.routes.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_writes_parameters_as_the_spec_does() {
        assert_eq!(normalize("/a/:id/b/*rest"), "/a/{id}/b/{rest}");
        assert_eq!(normalize("/a/{id}/{*rest}"), "/a/{id}/{rest}");
        assert_eq!(normalize("/npm/:k/@:scope/:p"), "/npm/{k}/@{scope}/{p}");
    }

    #[test]
    fn normalize_drops_a_trailing_slash() {
        assert_eq!(normalize("/api/v1/admin/banners/"), "/api/v1/admin/banners");
        assert_eq!(normalize("/v2/"), "/v2");
        assert_eq!(normalize("/"), "/");
    }

    #[test]
    fn shape_ignores_parameter_names() {
        assert_eq!(shape("/r/:key/x/"), shape("/r/{id}/x"));
        assert_ne!(shape("/r/{id}/x"), shape("/r/{id}/y"));
    }

    /// A small backend on disk, with the idioms the real one uses.
    fn sample(routes: &str, handler: &str) -> tempdir::Dir {
        let dir = tempdir::Dir::new();
        fs::create_dir_all(dir.0.join("backend/src/api/handlers")).unwrap();
        fs::write(
            dir.0.join("Cargo.toml"),
            "[workspace.package]\nversion = \"9.9.9\"\n",
        )
        .unwrap();
        fs::write(dir.0.join("backend/src/api/routes.rs"), routes).unwrap();
        fs::write(dir.0.join("backend/src/api/handlers/h.rs"), handler).unwrap();
        dir
    }

    mod tempdir {
        use std::path::PathBuf;
        pub struct Dir(pub PathBuf);
        impl Dir {
            pub fn new() -> Self {
                use std::sync::atomic::{AtomicU32, Ordering};
                static N: AtomicU32 = AtomicU32::new(0);
                let n = N.fetch_add(1, Ordering::Relaxed);
                let p =
                    std::env::temp_dir().join(format!("xtask-routes-{}-{n}", std::process::id()));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn keys(table: &RouteTable) -> Vec<String> {
        table
            .routes
            .iter()
            .filter(|r| r.handler != "swagger")
            .map(|r| format!("{} {}", r.method, r.path))
            .collect()
    }

    #[test]
    fn it_follows_nest_merge_branches_and_formatted_paths() {
        let dir = sample(
            r#"pub fn create_router(state: S) -> Router {
                let extra = if state.on { Router::new().nest("/ext", handlers::h::ext()) } else { Router::new() };
                let mut router = Router::new().route("/health", get(a));
                if state.swagger {
                    router = router.merge(SwaggerUi::new("/swagger-ui").url("/o", o));
                }
                #[cfg(test)]
                let router = router.route("/only-test", get(a));
                let router = router.nest("/api/v1", v1()).merge(extra);
                router.layer(l)
            }
            fn v1() -> Router<S> {
                Router::new().nest("/x", handlers::h::router().layer(y)).route("/both", get(a).post(b))
            }"#,
            r#"pub fn router() -> Router<S> {
                Router::new().route("/", get(a)).route("/:id", any(b)).merge(token("/t"))
            }
            pub fn ext() -> Router<S> { Router::new().route("/*p", get(a)) }
            fn token(t: &str) -> Router<S> { Router::new().route(&format!("/:k{t}/u"), post(a)) }
            #[cfg(test)]
            mod tests { fn router() -> Router<S> { Router::new().route("/nope", get(a)) } }"#,
        );
        let table = extract(&dir.0).unwrap();
        assert_eq!(table.backend_version, "9.9.9");
        let got = keys(&table);
        for want in [
            "GET /health",
            "GET /api/v1/x",
            "ANY /api/v1/x/{id}",
            "POST /api/v1/x/{k}/t/u",
            "GET /api/v1/both",
            "POST /api/v1/both",
            "GET /ext/{p}",
        ] {
            assert!(got.iter().any(|g| g == want), "{want} not in {got:#?}");
        }
        assert!(
            !got.iter()
                .any(|g| g.contains("nope") || g.contains("only-test")),
            "{got:#?}"
        );
    }

    #[test]
    fn it_reads_a_child_module_of_a_handler() {
        let dir = sample(
            r#"pub fn create_router(state: S) -> Router {
                Router::new().nest("/api/v1/jobs", handlers::h::jobs())
            }"#,
            r#"mod job;
            pub fn jobs() -> Router<S> { job::router() }
            fn more() -> Router<S> { Router::new().route(ROOT, post(b)) }
            const ROOT: &str = "/root";"#,
        );
        fs::create_dir_all(dir.0.join("backend/src/api/handlers/h")).unwrap();
        fs::write(
            dir.0.join("backend/src/api/handlers/h/job.rs"),
            r#"pub fn router() -> Router<S> {
                Router::new().route("/:id", get(a)).merge(super::more())
            }"#,
        )
        .unwrap();
        let table = extract(&dir.0).unwrap();
        let got = keys(&table);
        assert!(got.iter().any(|g| g == "GET /api/v1/jobs/{id}"), "{got:#?}");
        assert!(
            got.iter().any(|g| g == "POST /api/v1/jobs/root"),
            "{got:#?}"
        );
        let child = table.routes.iter().find(|r| r.path == "/api/v1/jobs/{id}");
        assert_eq!(child.unwrap().handler, "h/job");
    }

    #[test]
    fn it_runs_a_for_loop_over_a_constant_slice() {
        let dir = sample(
            r#"pub fn create_router(state: S) -> Router {
                Router::new().nest(handlers::h::MOUNT, handlers::h::router())
            }"#,
            r#"pub const MOUNT: &str = "/mcp";
            pub const VERSIONS: &[&str] = &["v0.1", "v0"];
            const HOLDS: &str = "/x/holds";
            pub fn router() -> Router<S> {
                let mut read = Router::new();
                for v in VERSIONS {
                    let p = |tail: &str| format!("/:repo/{v}{tail}");
                    read = read.route(&p("/servers"), get(a)).merge(extra(v));
                    for spelling in ["/:ns", "/:ns/:name"] {
                        read = read.route(&format!("/:repo/{v}/s{spelling}{HOLDS}"), get(a));
                    }
                }
                read.layer(l)
            }
            fn extra(api: &str) -> Router<S> {
                let p = |tail: &str| format!("/:repo/{api}{tail}");
                Router::new().route(&p("/ping"), get(a))
            }"#,
        );
        let mut got = keys(&extract(&dir.0).unwrap());
        got.sort();
        let mut want: Vec<String> = ["v0", "v0.1"]
            .iter()
            .flat_map(|v| {
                [
                    format!("GET /mcp/{{repo}}/{v}/ping"),
                    format!("GET /mcp/{{repo}}/{v}/s/{{ns}}/x/holds"),
                    format!("GET /mcp/{{repo}}/{v}/s/{{ns}}/{{name}}/x/holds"),
                    format!("GET /mcp/{{repo}}/{v}/servers"),
                ]
            })
            .collect();
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn a_for_loop_it_cannot_evaluate_is_an_error_when_it_mounts_routes() {
        let dir = sample(
            r#"pub fn create_router(state: S) -> Router {
                let mut r = Router::new();
                for v in state.versions() {
                    r = r.route(&format!("/{v}/x"), get(a));
                }
                for n in 0..3 { log(n); }
                r
            }"#,
            "",
        );
        let err = extract(&dir.0).unwrap_err().to_string();
        assert!(err.contains("Couldn't resolve"), "{err}");
        assert!(err.contains("for v in"), "{err}");
        assert!(!err.contains("for n in"), "{err}");
    }

    #[test]
    fn a_for_loop_body_that_only_sets_a_fallback_still_counts_as_mounting() {
        let dir = sample(
            r#"pub fn create_router(state: S) -> Router {
                let mut r = Router::new().route("/x", get(a));
                for v in state.versions() {
                    r = r.fallback(not_found);
                }
                for n in 0..3 {
                    let router_name = n;
                    log(router_name, merged, routes);
                }
                r
            }"#,
            "",
        );
        let err = extract(&dir.0).unwrap_err().to_string();
        assert!(err.contains("for v in"), "{err}");
        assert!(!err.contains("for n in"), "{err}");
    }

    #[test]
    fn mounts_routes_looks_for_method_calls_not_substrings() {
        let calls = |code: &str| mounts_routes(code.parse().unwrap());
        assert!(calls("r = r.route(\"/a\", get(x));"));
        assert!(calls("r = r.fallback(h);"));
        assert!(calls("{ if y { r = r.nest_service(\"/s\", svc); } }"));
        assert!(!calls(
            "let router = make(); log(router, routes, merge_count);"
        ));
        assert!(!calls("x.routed(); route(a);"));
    }

    #[test]
    fn a_let_in_a_for_loop_body_ends_with_the_loop() {
        let dir = sample(
            r#"pub fn create_router(state: S) -> Router {
                let p = |tail: &str| format!("/outer{tail}");
                let mut r = Router::new();
                for v in ["a", "b"] {
                    let p = |tail: &str| format!("/{v}{tail}");
                    let only_inside = "/gone";
                    r = r.route(&p("/in"), get(a));
                }
                let v = "/v";
                r.route(&p("/after"), get(a)).route(v, post(a))
            }"#,
            "",
        );
        let mut got = keys(&extract(&dir.0).unwrap());
        got.sort();
        assert_eq!(
            got,
            ["GET /a/in", "GET /b/in", "GET /outer/after", "POST /v"],
            "{got:#?}"
        );
    }

    #[test]
    fn a_let_in_a_for_loop_body_is_not_visible_after_it() {
        let dir = sample(
            r#"pub fn create_router(state: S) -> Router {
                let mut r = Router::new();
                for v in ["a"] {
                    let inner = "/inner";
                    r = r.route(&format!("/{v}"), get(a));
                }
                r.route(inner, get(a))
            }"#,
            "",
        );
        let err = extract(&dir.0).unwrap_err().to_string();
        assert!(err.contains("Couldn't resolve"), "{err}");
        assert!(err.contains("inner"), "{err}");
    }

    #[test]
    fn a_constant_placeholder_it_cannot_find_is_an_error() {
        let dir = sample(
            r#"pub fn create_router(state: S) -> Router {
                Router::new()
                    .route(&format!("/x{FOUND}"), get(a))
                    .route(&format!("/y{MISSING_PATH}"), get(a))
            }
            const FOUND: &str = "/found";"#,
            "",
        );
        let err = extract(&dir.0).unwrap_err().to_string();
        assert!(err.contains("Couldn't resolve"), "{err}");
        assert!(err.contains("{MISSING_PATH}"), "{err}");
        assert!(!err.contains("FOUND}"), "{err}");
    }

    #[test]
    fn is_const_name_is_upper_snake_case() {
        assert!(is_const_name("HOLDS_PATH"));
        assert!(is_const_name("V2"));
        assert!(!is_const_name("v"));
        assert!(!is_const_name("repo_key"));
        assert!(!is_const_name("_1"));
    }

    #[test]
    fn a_mount_it_cannot_resolve_is_an_error() {
        let dir = sample(
            r#"pub fn create_router(state: S) -> Router {
                Router::new().nest("/x", handlers::missing::router())
            }"#,
            "",
        );
        let err = extract(&dir.0).unwrap_err().to_string();
        assert!(err.contains("Couldn't resolve"), "{err}");
    }
}
