//! Where each agent keeps a plugin, what `ak` records next to it, and what the agent
//! has to be told afterwards.
//!
//! Everything here takes the home directory as an argument, so the tests never touch
//! the real one.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The agents `ak agent plugins install` can install for.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Harness {
    /// Claude Code
    Claude,
    /// Cursor
    Cursor,
    /// OpenAI Codex
    Codex,
    /// GitHub Copilot CLI and VS Code
    Vscode,
}

pub const ALL: &[Harness] = &[
    Harness::Claude,
    Harness::Cursor,
    Harness::Codex,
    Harness::Vscode,
];

impl Harness {
    pub fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Cursor => "cursor",
            Self::Codex => "codex",
            Self::Vscode => "vscode",
        }
    }

    /// Whether a plugin with these manifest tags is meant for this agent: the same rule
    /// that puts a plugin in the server's per-agent marketplace.
    pub fn accepts(self, tags: &[String]) -> bool {
        let has = |t: &str| tags.iter().any(|x| x == t);
        match self {
            Self::Claude => has("claude") || has("standard"),
            Self::Cursor => has("cursor") || has("standard"),
            Self::Codex => has("codex") || has("standard"),
            Self::Vscode => has("standard"),
        }
    }
}

impl std::fmt::Display for Harness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A repository key as one path component: it names a directory here.
pub fn check_repo_component(repo: &str) -> Result<(), String> {
    if repo.is_empty() || repo == "." || repo == ".." || repo.contains(['/', '\\', ':', '\0']) {
        return Err(format!(
            "`{repo}` can't be a repository key: it names a directory here"
        ));
    }
    Ok(())
}

/// The name of the marketplace `ak` keeps for a repository: `ak-<repo>`, with anything
/// Claude Code wouldn't take in a marketplace name made a `-`.
pub fn marketplace_name(repo: &str) -> String {
    let cleaned: String = repo
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let mut name = format!("ak-{cleaned}");
    while name.contains("..") {
        name = name.replace("..", ".");
    }
    name
}

/// Where one install goes, and the marketplace directory that lists it, if the agent
/// has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub dir: PathBuf,
    pub marketplace_dir: Option<PathBuf>,
}

/// Where an agent keeps a plugin installed from `repo`. `--path` puts it in
/// `<path>/<slug>` instead, with no marketplace.
pub fn location(
    harness: Harness,
    home: &Path,
    repo: &str,
    slug: &str,
    path: Option<&Path>,
) -> Location {
    if let Some(path) = path {
        return Location {
            dir: path.join(slug),
            marketplace_dir: None,
        };
    }
    match harness {
        Harness::Claude => {
            let market = home.join(".claude/plugins/local/ak").join(repo);
            Location {
                dir: market.join(slug),
                marketplace_dir: Some(market),
            }
        }
        Harness::Cursor => Location {
            dir: home.join(".cursor/plugins/local").join(slug),
            marketplace_dir: None,
        },
        Harness::Codex => {
            let market = home.join(".agents/plugins/local/ak").join(repo);
            Location {
                dir: market.join(slug),
                marketplace_dir: Some(market),
            }
        }
        Harness::Vscode => Location {
            dir: home
                .join(".copilot/installed-plugins")
                .join(marketplace_name(repo))
                .join(slug),
            marketplace_dir: None,
        },
    }
}

/// The marketplace file in a marketplace directory.
pub fn marketplace_file(harness: Harness, marketplace_dir: &Path) -> Option<PathBuf> {
    match harness {
        Harness::Claude => Some(marketplace_dir.join(".claude-plugin/marketplace.json")),
        Harness::Codex => Some(marketplace_dir.join(".agents/plugins/marketplace.json")),
        Harness::Cursor | Harness::Vscode => None,
    }
}

/// The directories to look in for installs, and how many levels down a plugin sits.
pub fn scan_roots(harness: Harness, home: &Path) -> (PathBuf, usize) {
    match harness {
        Harness::Claude => (home.join(".claude/plugins/local/ak"), 2),
        Harness::Cursor => (home.join(".cursor/plugins/local"), 1),
        Harness::Codex => (home.join(".agents/plugins/local/ak"), 2),
        Harness::Vscode => (home.join(".copilot/installed-plugins"), 2),
    }
}

pub const INFO_DIR: &str = ".ak";
pub const INFO_FILE: &str = "plugin-info.json";

/// What `ak` writes to `.ak/plugin-info.json` in each plugin it installs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginInfo {
    /// The instance's URL.
    pub instance: String,
    pub repo: String,
    pub slug: String,
    pub version: String,
    pub sha256: String,
    pub harness: Harness,
    pub installed_at: String,
}

impl PluginInfo {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(INFO_DIR).join(INFO_FILE)
    }

    pub fn write(&self, dir: &Path) -> Result<(), String> {
        let path = Self::path(dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Can't create {}: {e}", parent.display()))?;
        }
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        std::fs::write(&path, text).map_err(|e| format!("Can't write {}: {e}", path.display()))
    }

    pub fn read(dir: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(Self::path(dir)).ok()?;
        serde_json::from_str(&text).ok()
    }
}

/// An install found on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub dir: PathBuf,
    pub info: PluginInfo,
}

/// Every plugin `ak` installed under `root`, `depth` directories down, sorted by path.
/// A directory without `.ak/plugin-info.json` isn't one of ours and is left out.
pub fn scan(root: &Path, depth: usize) -> Vec<Installed> {
    let mut dirs = vec![root.to_path_buf()];
    for _ in 0..depth {
        let mut next = Vec::new();
        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let is_dir = std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir());
                let hidden = entry.file_name().to_string_lossy().starts_with('.');
                if is_dir && !hidden {
                    next.push(path);
                }
            }
        }
        dirs = next;
    }
    let mut found: Vec<Installed> = dirs
        .into_iter()
        .filter_map(|dir| PluginInfo::read(&dir).map(|info| Installed { dir, info }))
        .collect();
    found.sort_by(|a, b| a.dir.cmp(&b.dir));
    found
}

/// The installs to act on: under `--path` if given, else in each agent's own place.
pub fn find_installs(home: &Path, harnesses: &[Harness], path: Option<&Path>) -> Vec<Installed> {
    if let Some(path) = path {
        return scan(path, 1)
            .into_iter()
            .filter(|i| harnesses.contains(&i.info.harness))
            .collect();
    }
    let mut out = Vec::new();
    for harness in harnesses {
        let (root, depth) = scan_roots(*harness, home);
        out.extend(scan(&root, depth).into_iter().filter(|i| {
            // Copilot keeps its own installs next to ours, so only `ak-<repo>` is read.
            let ours = *harness != Harness::Vscode
                || i.dir
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|n| n.to_string_lossy().starts_with("ak-"));
            ours && i.info.harness == *harness
        }));
    }
    out
}

/// Claude Code's marketplace for `repo`, with `slug` in it at `./<slug>`. `existing` is
/// the file as it was, so other plugins from the same repository stay listed.
pub fn claude_marketplace(
    existing: Option<&Value>,
    repo: &str,
    instance: &str,
    slug: &str,
    version: &str,
    description: Option<&str>,
) -> Value {
    let mut entry = json!({
        "name": slug,
        "source": format!("./{slug}"),
        "version": version,
    });
    if let Some(description) = description {
        entry["description"] = json!(description);
    }
    let base = json!({
        "name": marketplace_name(repo),
        "owner": {"name": "Artifact Keeper"},
        "metadata": {
            "description": format!("Plugins installed by ak from the {repo} repository on {instance}"),
        },
        "plugins": [],
    });
    upsert(existing, base, slug, entry)
}

/// Codex's marketplace for `repo`, with `slug` in it as a local source.
pub fn codex_marketplace(existing: Option<&Value>, repo: &str, slug: &str) -> Value {
    let entry = json!({
        "name": slug,
        "source": {"source": "local", "path": format!("./{slug}")},
        "policy": {"installation": "AVAILABLE"},
    });
    let base = json!({
        "name": marketplace_name(repo),
        "interface": {"displayName": format!("Artifact Keeper: {repo}")},
        "plugins": [],
    });
    upsert(existing, base, slug, entry)
}

/// `existing` (or `base`) with the entry for `slug` replaced by `entry`, sorted by name.
fn upsert(existing: Option<&Value>, base: Value, slug: &str, entry: Value) -> Value {
    let mut doc = existing
        .filter(|d| d.get("plugins").is_some_and(Value::is_array))
        .cloned()
        .unwrap_or(base);
    let plugins = doc["plugins"].as_array_mut().expect("checked above");
    plugins.retain(|p| p.get("name").and_then(Value::as_str) != Some(slug));
    plugins.push(entry);
    plugins.sort_by(|a, b| {
        let name = |v: &Value| {
            v.get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        name(a).cmp(&name(b))
    });
    doc
}

/// A marketplace with `slug` taken out, or `None` if it wasn't listed.
pub fn without_plugin(doc: &Value, slug: &str) -> Option<Value> {
    let plugins = doc.get("plugins")?.as_array()?;
    if !plugins
        .iter()
        .any(|p| p.get("name").and_then(Value::as_str) == Some(slug))
    {
        return None;
    }
    let mut doc = doc.clone();
    if let Some(list) = doc["plugins"].as_array_mut() {
        list.retain(|p| p.get("name").and_then(Value::as_str) != Some(slug));
    }
    Some(doc)
}

/// A command for the agent's own CLI to run after an install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub program: &'static str,
    pub args: Vec<String>,
}

impl Step {
    fn new(program: &'static str, args: &[&str]) -> Self {
        Self {
            program,
            args: args.iter().map(|a| a.to_string()).collect(),
        }
    }

    /// The command as a person would type it.
    pub fn display(&self) -> String {
        let mut out = self.program.to_string();
        for arg in &self.args {
            out.push(' ');
            if arg.is_empty() || arg.contains(|c: char| c.is_whitespace() || "'\"$\\".contains(c)) {
                out.push('\'');
                out.push_str(&arg.replace('\'', "'\\''"));
                out.push('\'');
            } else {
                out.push_str(arg);
            }
        }
        out
    }
}

/// What has to happen after an install for the agent to load it: the commands, and a
/// note to print whether or not they ran. `known` says whether the marketplace was
/// already there, so it's updated rather than added.
pub fn post_steps(
    harness: Harness,
    location: &Location,
    repo: &str,
    slug: &str,
    known: bool,
) -> (Vec<Step>, Option<String>) {
    let market = marketplace_name(repo);
    let market_dir = location
        .marketplace_dir
        .as_ref()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    match harness {
        Harness::Claude => {
            let first = if known {
                Step::new("claude", &["plugin", "marketplace", "update", &market])
            } else {
                Step::new("claude", &["plugin", "marketplace", "add", &market_dir])
            };
            let install = format!("{slug}@{market}");
            (
                vec![first, Step::new("claude", &["plugin", "install", &install])],
                None,
            )
        }
        Harness::Cursor => (
            vec![],
            Some("Reload Cursor (Developer: Reload Window) to load it.".to_string()),
        ),
        Harness::Codex => {
            let steps = if known {
                vec![]
            } else {
                vec![Step::new(
                    "codex",
                    &["plugin", "marketplace", "add", &market_dir],
                )]
            };
            (steps, Some("Restart Codex to load it.".to_string()))
        }
        Harness::Vscode => {
            let dir = location.dir.display().to_string();
            (
                vec![Step::new("copilot", &["plugin", "install", &dir])],
                Some(
                    "In VS Code, run \"Chat: Manage Plugin Marketplaces\" and add this \
                     directory to load it there."
                        .to_string(),
                ),
            )
        }
    }
}

/// What to tell the agent after an uninstall, as commands to run by hand.
pub fn uninstall_hints(harness: Harness, repo: &str, slug: &str) -> Vec<String> {
    let market = marketplace_name(repo);
    match harness {
        Harness::Claude => vec![format!("claude plugin uninstall {slug}@{market}")],
        Harness::Vscode => vec![format!("copilot plugin uninstall {slug}")],
        Harness::Cursor => vec!["Reload Cursor (Developer: Reload Window)".to_string()],
        Harness::Codex => vec!["Restart Codex".to_string()],
    }
}

/// `program` on `path` (the value of `PATH`), as the shell would find it.
pub fn find_on_path(program: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    let path = path?;
    let names: Vec<String> = if cfg!(windows) {
        ["", ".exe", ".cmd", ".bat"]
            .iter()
            .map(|ext| format!("{program}{ext}"))
            .collect()
    } else {
        vec![program.to_string()]
    };
    std::env::split_paths(path).find_map(|dir| {
        names
            .iter()
            .map(|n| dir.join(n))
            .find(|candidate| is_runnable(candidate))
    })
}

#[cfg(unix)]
fn is_runnable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_runnable(path: &Path) -> bool {
    path.is_file()
}

/// How an installed version compares with the newest one on the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateStatus {
    Current,
    Behind,
    Ahead,
    Unknown,
}

impl UpdateStatus {
    pub fn name(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Behind => "behind",
            Self::Ahead => "ahead",
            Self::Unknown => "unknown",
        }
    }
}

pub fn compare(installed: &str, latest: Option<&str>) -> UpdateStatus {
    let (Ok(have), Some(Ok(newest))) = (
        semver::Version::parse(installed),
        latest.map(semver::Version::parse),
    ) else {
        return UpdateStatus::Unknown;
    };
    match have.cmp_precedence(&newest) {
        std::cmp::Ordering::Equal => UpdateStatus::Current,
        std::cmp::Ordering::Less => UpdateStatus::Behind,
        std::cmp::Ordering::Greater => UpdateStatus::Ahead,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn info(harness: Harness, slug: &str) -> PluginInfo {
        PluginInfo {
            instance: "https://ak.example.com".to_string(),
            repo: "plugins".to_string(),
            slug: slug.to_string(),
            version: "1.2.0".to_string(),
            sha256: "ab".repeat(32),
            harness,
            installed_at: "2026-11-03T18:00:00Z".to_string(),
        }
    }

    #[test]
    fn each_harness_has_its_place_under_home() {
        let home = Path::new("/home/u");
        let at = |h| location(h, home, "plugins", "demo", None);
        assert_eq!(
            at(Harness::Claude),
            Location {
                dir: home.join(".claude/plugins/local/ak/plugins/demo"),
                marketplace_dir: Some(home.join(".claude/plugins/local/ak/plugins")),
            }
        );
        assert_eq!(
            at(Harness::Cursor).dir,
            home.join(".cursor/plugins/local/demo")
        );
        assert_eq!(at(Harness::Cursor).marketplace_dir, None);
        assert_eq!(
            at(Harness::Codex),
            Location {
                dir: home.join(".agents/plugins/local/ak/plugins/demo"),
                marketplace_dir: Some(home.join(".agents/plugins/local/ak/plugins")),
            }
        );
        assert_eq!(
            at(Harness::Vscode).dir,
            home.join(".copilot/installed-plugins/ak-plugins/demo")
        );
        let custom = location(
            Harness::Claude,
            home,
            "plugins",
            "demo",
            Some(Path::new("/opt/p")),
        );
        assert_eq!(custom.dir, Path::new("/opt/p/demo"));
        assert_eq!(custom.marketplace_dir, None);

        let market = at(Harness::Claude).marketplace_dir.unwrap();
        assert_eq!(
            marketplace_file(Harness::Claude, &market).unwrap(),
            market.join(".claude-plugin/marketplace.json")
        );
        let market = at(Harness::Codex).marketplace_dir.unwrap();
        assert_eq!(
            marketplace_file(Harness::Codex, &market).unwrap(),
            market.join(".agents/plugins/marketplace.json")
        );
    }

    #[test]
    fn repository_keys_have_to_be_one_directory() {
        assert!(check_repo_component("plugins").is_ok());
        for bad in ["", ".", "..", "a/b", "a\\b"] {
            assert!(check_repo_component(bad).is_err(), "{bad}");
        }
        assert_eq!(marketplace_name("team plugins"), "ak-team-plugins");
        assert_eq!(marketplace_name("a..b"), "ak-a.b");
    }

    #[test]
    fn plugin_info_round_trips_with_the_fields_named_in_the_design() {
        let dir = TempDir::new().unwrap();
        let written = info(Harness::Codex, "demo");
        written.write(dir.path()).unwrap();
        let text = std::fs::read_to_string(dir.path().join(".ak/plugin-info.json")).unwrap();
        let raw: Value = serde_json::from_str(&text).unwrap();
        let keys: Vec<&str> = raw
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "instance",
                "repo",
                "slug",
                "version",
                "sha256",
                "harness",
                "installed_at"
            ]
        );
        assert_eq!(raw["harness"], "codex");
        assert_eq!(PluginInfo::read(dir.path()), Some(written));
        assert_eq!(PluginInfo::read(&dir.path().join("missing")), None);
    }

    #[test]
    fn scanning_finds_only_our_installs() {
        let home = TempDir::new().unwrap();
        let claude = location(Harness::Claude, home.path(), "plugins", "demo", None);
        info(Harness::Claude, "demo").write(&claude.dir).unwrap();
        let cursor = location(Harness::Cursor, home.path(), "plugins", "rules", None);
        info(Harness::Cursor, "rules").write(&cursor.dir).unwrap();
        // Someone else's Cursor plugin, with no record of ours.
        std::fs::create_dir_all(home.path().join(".cursor/plugins/local/theirs")).unwrap();

        let all = find_installs(home.path(), ALL, None);
        let slugs: Vec<&str> = all.iter().map(|i| i.info.slug.as_str()).collect();
        assert_eq!(slugs, ["demo", "rules"]);
        let only = find_installs(home.path(), &[Harness::Cursor], None);
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].dir, cursor.dir);

        let custom = TempDir::new().unwrap();
        info(Harness::Claude, "x")
            .write(&custom.path().join("x"))
            .unwrap();
        assert_eq!(
            find_installs(home.path(), ALL, Some(custom.path())).len(),
            1
        );
        assert!(find_installs(home.path(), &[Harness::Codex], Some(custom.path())).is_empty());
    }

    #[test]
    fn claude_marketplace_lists_relative_sources() {
        let doc = claude_marketplace(None, "plugins", "https://ak", "demo", "1.0.0", Some("Demo"));
        assert_eq!(
            doc,
            json!({
                "name": "ak-plugins",
                "owner": {"name": "Artifact Keeper"},
                "metadata": {"description": "Plugins installed by ak from the plugins repository on https://ak"},
                "plugins": [{"name": "demo", "source": "./demo", "version": "1.0.0", "description": "Demo"}],
            })
        );
        let doc = claude_marketplace(Some(&doc), "plugins", "https://ak", "alpha", "2.0.0", None);
        let doc = claude_marketplace(Some(&doc), "plugins", "https://ak", "demo", "1.1.0", None);
        let names: Vec<&str> = doc["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["alpha", "demo"]);
        assert_eq!(doc["plugins"][1]["version"], "1.1.0");
        for plugin in doc["plugins"].as_array().unwrap() {
            assert!(plugin["source"].as_str().unwrap().starts_with("./"));
        }

        let doc = without_plugin(&doc, "demo").unwrap();
        assert_eq!(doc["plugins"].as_array().unwrap().len(), 1);
        assert_eq!(without_plugin(&doc, "demo"), None);
    }

    #[test]
    fn codex_marketplace_entries_are_local_sources() {
        let doc = codex_marketplace(None, "plugins", "demo");
        assert_eq!(
            doc,
            json!({
                "name": "ak-plugins",
                "interface": {"displayName": "Artifact Keeper: plugins"},
                "plugins": [{
                    "name": "demo",
                    "source": {"source": "local", "path": "./demo"},
                    "policy": {"installation": "AVAILABLE"},
                }],
            })
        );
    }

    #[test]
    fn post_steps_name_the_marketplace_and_the_plugin() {
        let home = Path::new("/h");
        let claude = location(Harness::Claude, home, "plugins", "demo", None);
        let (steps, _) = post_steps(Harness::Claude, &claude, "plugins", "demo", false);
        let shown: Vec<String> = steps.iter().map(Step::display).collect();
        assert_eq!(
            shown,
            [
                "claude plugin marketplace add /h/.claude/plugins/local/ak/plugins",
                "claude plugin install demo@ak-plugins",
            ]
        );
        let (steps, _) = post_steps(Harness::Claude, &claude, "plugins", "demo", true);
        assert_eq!(
            steps[0].display(),
            "claude plugin marketplace update ak-plugins"
        );

        let codex = location(Harness::Codex, home, "plugins", "demo", None);
        let (steps, note) = post_steps(Harness::Codex, &codex, "plugins", "demo", false);
        assert_eq!(
            steps[0].display(),
            "codex plugin marketplace add /h/.agents/plugins/local/ak/plugins"
        );
        assert!(note.is_some());
        assert!(
            post_steps(Harness::Codex, &codex, "plugins", "demo", true)
                .0
                .is_empty()
        );

        let cursor = location(Harness::Cursor, home, "plugins", "demo", None);
        assert!(
            post_steps(Harness::Cursor, &cursor, "plugins", "demo", false)
                .0
                .is_empty()
        );

        let vscode = location(Harness::Vscode, home, "plugins", "demo", None);
        let (steps, note) = post_steps(Harness::Vscode, &vscode, "plugins", "demo", false);
        assert_eq!(
            steps[0].display(),
            "copilot plugin install /h/.copilot/installed-plugins/ak-plugins/demo"
        );
        assert!(note.unwrap().contains("Chat: Manage Plugin Marketplaces"));

        let spaced = Step::new("claude", &["plugin", "marketplace", "add", "/a b/c"]);
        assert_eq!(spaced.display(), "claude plugin marketplace add '/a b/c'");
    }

    #[test]
    fn harness_compatibility_follows_the_marketplace_membership() {
        let tags = |t: &[&str]| t.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(Harness::Claude.accepts(&tags(&["standard"])));
        assert!(Harness::Cursor.accepts(&tags(&["cursor"])));
        assert!(!Harness::Cursor.accepts(&tags(&["claude"])));
        assert!(Harness::Codex.accepts(&tags(&["standard"])));
        assert!(!Harness::Vscode.accepts(&tags(&["claude"])));
        assert!(Harness::Vscode.accepts(&tags(&["standard"])));
    }

    #[test]
    fn versions_compare_by_semver_precedence() {
        assert_eq!(compare("1.0.0", Some("1.0.0")), UpdateStatus::Current);
        assert_eq!(compare("1.0.0", Some("1.1.0")), UpdateStatus::Behind);
        assert_eq!(compare("2.0.0-rc.1", Some("2.0.0")), UpdateStatus::Behind);
        assert_eq!(compare("2.0.0", Some("1.9.9")), UpdateStatus::Ahead);
        assert_eq!(compare("1.0.0", None), UpdateStatus::Unknown);
        assert_eq!(compare("x", Some("1.0.0")), UpdateStatus::Unknown);
    }

    #[cfg(unix)]
    #[test]
    fn programs_are_found_on_the_given_path_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let bin = dir.path().join("claude");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(dir.path().join("codex"), "").unwrap();
        let path = std::env::join_paths([dir.path()]).unwrap();
        assert_eq!(find_on_path("claude", Some(&path)), Some(bin));
        assert_eq!(find_on_path("codex", Some(&path)), None, "not executable");
        assert_eq!(find_on_path("cursor", Some(&path)), None);
        assert_eq!(find_on_path("claude", None), None);
    }
}
