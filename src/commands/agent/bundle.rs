//! A plugin bundle on disk and as a zip: which manifests it has, what it's called, and
//! how it's packed and unpacked.
//!
//! The rules are the server's (section 4 of the Agent Plugins design), applied here so
//! a publish fails before it uploads, and an install refuses what it shouldn't unpack
//! even when the server let it through.

use std::collections::BTreeMap;
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The manifest markers, in the order that decides which one names the plugin.
pub const MARKERS: &[(&str, &str)] = &[
    ("claude", ".claude-plugin/plugin.json"),
    ("standard", "plugin.json"),
    ("cursor", ".cursor-plugin/plugin.json"),
    ("codex", ".codex-plugin/plugin.json"),
    ("gemini", "gemini-extension.json"),
];

/// A root `plugin.json` is an Agent Plugins Standard manifest only with this `$schema`.
pub const STANDARD_SCHEMA_PREFIX: &str = "https://agent-plugins.org/schemas/";

/// The longest slug the server takes.
pub const MAX_SLUG_LEN: usize = 64;

/// What an install unpacks at most, so a small zip can't fill the disk.
pub const MAX_UNPACKED_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 100_000;

/// One manifest found in a bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub harness: &'static str,
    /// Relative to the plugin root, with forward slashes.
    pub path: &'static str,
    pub json: Value,
}

impl Manifest {
    pub fn field(&self, key: &str) -> Option<&str> {
        self.json.get(key).and_then(Value::as_str)
    }
}

/// Is this the manifest for that marker? A root `plugin.json` counts only with the
/// Standard `$schema`, since other tools use the same file name.
fn qualifies(harness: &str, json: &Value) -> bool {
    harness != "standard"
        || json
            .get("$schema")
            .and_then(Value::as_str)
            .is_some_and(|s| s.starts_with(STANDARD_SCHEMA_PREFIX))
}

/// The manifests under `root`, in marker order. A manifest that isn't a JSON object
/// is an error, as the server would refuse it.
pub fn discover(root: &Path) -> Result<Vec<Manifest>, String> {
    let mut found = Vec::new();
    for (harness, path) in MARKERS {
        let file = root.join(path);
        let Ok(meta) = std::fs::symlink_metadata(&file) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let bytes =
            std::fs::read(&file).map_err(|e| format!("Can't read {}: {e}", file.display()))?;
        if let Some(manifest) = parse_manifest(harness, path, &bytes)? {
            found.push(manifest);
        }
    }
    Ok(found)
}

/// One marker file's bytes as a manifest, or `None` for a root `plugin.json` that
/// isn't a Standard one.
pub fn parse_manifest(
    harness: &'static str,
    path: &'static str,
    bytes: &[u8],
) -> Result<Option<Manifest>, String> {
    let json: Value = match serde_json::from_slice(bytes) {
        Ok(json) => json,
        // Some other tool's plugin.json needn't be JSON we can read.
        Err(_) if harness == "standard" => return Ok(None),
        Err(e) => return Err(format!("{path} isn't valid JSON: {e}")),
    };
    if !qualifies(harness, &json) {
        return Ok(None);
    }
    if !json.is_object() {
        return Err(format!("{path} isn't a JSON object"));
    }
    Ok(Some(Manifest {
        harness,
        path,
        json,
    }))
}

/// A slug the server takes: `^[a-z0-9][a-z0-9-]*$`, at most 64 characters.
pub fn validate_slug(slug: &str) -> Result<(), String> {
    let mut chars = slug.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !first_ok || !rest_ok {
        return Err(format!(
            "`{slug}` isn't a valid plugin name: use lowercase letters, digits and `-`, \
             starting with a letter or digit"
        ));
    }
    if slug.len() > MAX_SLUG_LEN {
        return Err(format!(
            "`{slug}` is {} characters long, and a plugin name can have at most {MAX_SLUG_LEN}",
            slug.len()
        ));
    }
    Ok(())
}

/// A strict SemVer 2.0 version: `1.2.3`, `2.0.0-rc.1`, never `v1.2` or `1.02.0`.
pub fn validate_version(version: &str) -> Result<semver::Version, String> {
    semver::Version::parse(version)
        .map_err(|e| format!("`{version}` isn't a SemVer version such as 1.2.0 or 2.0.0-rc.1: {e}"))
}

/// What a publish is about to send.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub slug: String,
    pub version: String,
    pub harnesses: Vec<&'static str>,
    /// Manifest path to its rewritten bytes, for a `--version` that changes it.
    pub overrides: BTreeMap<String, Vec<u8>>,
}

/// The plugin's name and version from its manifests and the flags, checked as the server
/// will check them.
///
/// The name is `--name`, or else the first manifest's `name`. The version is
/// `--version`, or else the first manifest's `version`, or else 1.0.0. With `--version`,
/// each manifest that has a `version` gets it rewritten in what's uploaded, so the
/// server's check that the manifest and the path agree passes.
pub fn identify(
    manifests: &[Manifest],
    name: Option<&str>,
    version: Option<&str>,
) -> Result<Identity, String> {
    if manifests.is_empty() {
        let markers: Vec<&str> = MARKERS.iter().map(|(_, p)| *p).collect();
        return Err(format!(
            "This isn't an agent plugin bundle: none of {} is there (a root plugin.json needs \
             an `$schema` under {STANDARD_SCHEMA_PREFIX})",
            markers.join(", ")
        ));
    }
    let slug = match name {
        Some(name) => name.to_string(),
        None => manifests
            .iter()
            .find_map(|m| m.field("name"))
            .map(str::to_string)
            .ok_or_else(|| {
                "No manifest has a `name`, so pass --name to say what the plugin is called"
                    .to_string()
            })?,
    };
    validate_slug(&slug)?;
    for manifest in manifests {
        if let Some(found) = manifest.field("name")
            && found != slug
        {
            return Err(format!(
                "{} names the plugin `{found}`, not `{slug}`. The server stores a plugin \
                 under one name, so its manifests have to agree with it",
                manifest.path
            ));
        }
    }

    let chosen = match version {
        Some(v) => v.to_string(),
        None => manifests
            .iter()
            .find_map(|m| m.field("version"))
            .unwrap_or("1.0.0")
            .to_string(),
    };
    validate_version(&chosen)?;

    let mut overrides = BTreeMap::new();
    for manifest in manifests {
        let Some(found) = manifest.field("version") else {
            continue;
        };
        if found == chosen {
            continue;
        }
        if version.is_none() {
            return Err(format!(
                "{} says version {found}, and the plugin's version is {chosen}. Make them \
                 agree, or pass --version to set it in every manifest: Claude Code reads the \
                 manifest's version first, so a stale one hides updates",
                manifest.path
            ));
        }
        overrides.insert(
            manifest.path.to_string(),
            rewrite_version(&manifest.json, &chosen),
        );
    }

    let mut harnesses: Vec<&'static str> = manifests.iter().map(|m| m.harness).collect();
    harnesses.dedup();
    Ok(Identity {
        slug,
        version: chosen,
        harnesses,
        overrides,
    })
}

/// A manifest with its `version` set, keeping every other field and their order.
pub fn rewrite_version(json: &Value, version: &str) -> Vec<u8> {
    let mut json = json.clone();
    if let Some(object) = json.as_object_mut() {
        object.insert("version".to_string(), Value::String(version.to_string()));
    }
    let mut out = serde_json::to_vec_pretty(&json).unwrap_or_default();
    out.push(b'\n');
    out
}

/// The files under `root` that go into the zip, sorted, with forward slashes. `.git`
/// and the `.ak` install record are left out. A symbolic link is refused: the zip
/// would hold a link to somewhere on this machine.
pub fn collect_files(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("Can't read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("Can't read {}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| format!("{} isn't a UTF-8 name", path.display()))?;
        if name == ".git" || (dir == root && name == ".ak") {
            continue;
        }
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("Can't read {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "{} is a symbolic link. A plugin zip can't hold links: copy the file in, or \
                 remove the link",
                path.display()
            ));
        }
        if meta.is_dir() {
            walk(root, &path, out)?;
        } else if meta.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            if relative.contains('\\') {
                return Err(format!(
                    "{} has a backslash in its name, which the server refuses",
                    path.display()
                ));
            }
            out.push((relative, path));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    false
}

/// The zip of `files`, with the plugin at its root. The same files make the same bytes:
/// entries are sorted and carry a fixed time and mode, so a rebuild has the same SHA-256.
pub fn build_zip(
    files: &[(String, PathBuf)],
    overrides: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, String> {
    use zip::write::SimpleFileOptions;
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, path) in files {
        let mode = if is_executable(path) { 0o755 } else { 0o644 };
        let options = SimpleFileOptions::DEFAULT
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(mode);
        let bytes = match overrides.get(name) {
            Some(bytes) => bytes.clone(),
            None => {
                std::fs::read(path).map_err(|e| format!("Can't read {}: {e}", path.display()))?
            }
        };
        writer
            .start_file(name.as_str(), options)
            .map_err(|e| format!("Can't add {name} to the zip: {e}"))?;
        writer
            .write_all(&bytes)
            .map_err(|e| format!("Can't add {name} to the zip: {e}"))?;
    }
    let cursor = writer
        .finish()
        .map_err(|e| format!("Can't finish the zip: {e}"))?;
    Ok(cursor.into_inner())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Why an entry name can't be unpacked, or `None` if it can.
pub fn unsafe_entry_name(name: &str) -> Option<&'static str> {
    if name.contains('\\') {
        return Some("has a backslash");
    }
    if name.starts_with('/') || name.contains(':') || Path::new(name).is_absolute() {
        return Some("is an absolute path");
    }
    if name.split('/').any(|part| part == "..") {
        return Some("climbs out with `..`");
    }
    if name.contains('\0') {
        return Some("has a NUL byte");
    }
    None
}

/// The part of every entry name that's the plugin root's: empty when the plugin is at
/// the top of the zip, `dir/` when it's one directory down. One directory down is taken
/// only when a manifest marker is there and not at the top, as Claude Code does.
pub fn detect_root(names: &[String]) -> String {
    // What archive tools add on their own doesn't count, as on the server.
    let names: Vec<String> = names
        .iter()
        .filter(|n| !is_archive_noise(n))
        .cloned()
        .collect();
    let at_top = |marker: &str| names.iter().any(|n| n == marker);
    if MARKERS.iter().any(|(_, m)| at_top(m)) {
        return String::new();
    }
    let mut tops = names
        .iter()
        .filter(|n| !n.is_empty())
        .map(|n| n.split('/').next().unwrap_or_default());
    let Some(first) = tops.next() else {
        return String::new();
    };
    let single = tops.all(|t| t == first) && names.iter().all(|n| n.contains('/'));
    let prefix = format!("{first}/");
    if single && MARKERS.iter().any(|(_, m)| at_top(&format!("{prefix}{m}"))) {
        prefix
    } else {
        String::new()
    }
}

/// `__MACOSX/` and `.DS_Store`, which macOS's archiver adds. Never unpacked.
pub fn is_archive_noise(name: &str) -> bool {
    name.starts_with("__MACOSX/") || name.rsplit('/').next() == Some(".DS_Store")
}

/// Unpack a plugin zip into `target`, which must not exist yet. Every entry is checked
/// before anything is written: a name that's absolute, has `..` or a backslash, or a
/// symbolic link refuses the whole zip. Returns the root prefix it stripped.
pub fn extract<R: Read + Seek>(reader: R, target: &Path) -> Result<String, String> {
    let mut archive =
        zip::ZipArchive::new(reader).map_err(|e| format!("The download isn't a zip: {e}"))?;
    if archive.len() > MAX_ENTRIES {
        return Err(format!(
            "The zip has {} entries, more than the {MAX_ENTRIES} an install unpacks",
            archive.len()
        ));
    }
    let mut names = Vec::with_capacity(archive.len());
    let mut total: u64 = 0;
    for i in 0..archive.len() {
        let entry = archive
            .by_index_raw(i)
            .map_err(|e| format!("Can't read the zip: {e}"))?;
        let name = entry
            .name()
            .map_err(|e| format!("Can't read an entry name: {e}"))?
            .to_string();
        if let Some(why) = unsafe_entry_name(&name) {
            return Err(format!(
                "The zip's entry `{name}` {why}, so nothing was unpacked"
            ));
        }
        if entry.is_symlink() {
            return Err(format!(
                "The zip's entry `{name}` is a symbolic link, so nothing was unpacked"
            ));
        }
        total = total.saturating_add(entry.size());
        names.push(name);
    }
    if total > MAX_UNPACKED_BYTES {
        return Err(format!(
            "The zip unpacks to {total} bytes, more than the {MAX_UNPACKED_BYTES} an install allows"
        ));
    }
    let root = detect_root(&names);

    std::fs::create_dir_all(target)
        .map_err(|e| format!("Can't create {}: {e}", target.display()))?;
    let mut written: u64 = 0;
    for (i, name) in names.iter().enumerate() {
        let Some(relative) = name.strip_prefix(root.as_str()) else {
            continue;
        };
        if relative.is_empty() || is_archive_noise(name) {
            continue;
        }
        let path = confined(target, relative)?;
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("Can't read `{name}`: {e}"))?;
        if entry.is_dir() {
            std::fs::create_dir_all(&path)
                .map_err(|e| format!("Can't create {}: {e}", path.display()))?;
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Can't create {}: {e}", parent.display()))?;
        }
        let mode = entry.unix_mode();
        let mut out = std::fs::File::create(&path)
            .map_err(|e| format!("Can't write {}: {e}", path.display()))?;
        // The sizes in the zip's directory can lie, so the bytes are counted too.
        let budget = MAX_UNPACKED_BYTES.saturating_sub(written);
        let copied = std::io::copy(&mut (&mut entry).take(budget + 1), &mut out)
            .map_err(|e| format!("Can't unpack `{name}`: {e}"))?;
        written += copied;
        if copied > budget {
            return Err(format!(
                "The zip unpacks to more than the {MAX_UNPACKED_BYTES} bytes an install allows"
            ));
        }
        set_mode(&path, mode);
    }
    Ok(root)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: Option<u32>) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(mode) = mode
        && mode & 0o111 != 0
    {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
    }
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: Option<u32>) {}

/// `relative` under `target`, made only of normal components. A second check after
/// [`unsafe_entry_name`]: nothing it returns can be outside `target`.
fn confined(target: &Path, relative: &str) -> Result<PathBuf, String> {
    let mut path = target.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            _ => {
                return Err(format!(
                    "The zip's entry `{relative}` points outside the plugin, so it wasn't unpacked"
                ));
            }
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;
    use tempfile::TempDir;

    fn write(root: &Path, path: &str, content: &str) {
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, content).unwrap();
    }

    fn zip_of(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, content) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::DEFAULT)
                .unwrap();
            writer.write_all(content.as_bytes()).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn discovers_each_marker_in_priority_order() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "gemini-extension.json", r#"{"name":"demo"}"#);
        write(
            dir.path(),
            ".codex-plugin/plugin.json",
            r#"{"name":"demo"}"#,
        );
        write(
            dir.path(),
            ".cursor-plugin/plugin.json",
            r#"{"name":"demo"}"#,
        );
        write(
            dir.path(),
            "plugin.json",
            r#"{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.json","name":"demo"}"#,
        );
        write(
            dir.path(),
            ".claude-plugin/plugin.json",
            r#"{"name":"demo"}"#,
        );
        let found = discover(dir.path()).unwrap();
        let tags: Vec<&str> = found.iter().map(|m| m.harness).collect();
        assert_eq!(tags, ["claude", "standard", "cursor", "codex", "gemini"]);
    }

    #[test]
    fn a_root_plugin_json_needs_the_standard_schema() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "plugin.json", r#"{"name":"demo"}"#);
        assert!(discover(dir.path()).unwrap().is_empty());
        write(dir.path(), "plugin.json", "not json");
        assert!(discover(dir.path()).unwrap().is_empty());
        write(
            dir.path(),
            "plugin.json",
            r#"{"$schema":"https://example.com/x.json","name":"demo"}"#,
        );
        assert!(discover(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn a_marker_that_isnt_an_object_is_refused() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".claude-plugin/plugin.json", "[1]");
        let e = discover(dir.path()).unwrap_err();
        assert!(e.contains("isn't a JSON object"), "{e}");
        write(dir.path(), ".claude-plugin/plugin.json", "{");
        let e = discover(dir.path()).unwrap_err();
        assert!(e.contains("isn't valid JSON"), "{e}");
    }

    #[test]
    fn slugs_follow_the_servers_rule() {
        for good in ["a", "deploy-tools", "0x", "a-b-c-1"] {
            assert!(validate_slug(good).is_ok(), "{good}");
        }
        for bad in ["", "-a", "A", "a_b", "a.b", "a/b", "é"] {
            assert!(validate_slug(bad).is_err(), "{bad}");
        }
        assert!(validate_slug(&"a".repeat(64)).is_ok());
        let e = validate_slug(&"a".repeat(65)).unwrap_err();
        assert!(e.contains("at most 64"), "{e}");
    }

    #[test]
    fn versions_are_strict_semver() {
        for good in ["1.0.0", "0.1.2", "2.0.0-rc.1", "1.2.3+build.5"] {
            assert!(validate_version(good).is_ok(), "{good}");
        }
        for bad in ["1", "1.2", "v1.2.3", "01.2.3", "1.2.3.4", "latest", ""] {
            assert!(validate_version(bad).is_err(), "{bad}");
        }
    }

    fn manifest(harness: &'static str, path: &'static str, json: Value) -> Manifest {
        Manifest {
            harness,
            path,
            json,
        }
    }

    #[test]
    fn identity_comes_from_the_first_manifest_then_flags() {
        let ms = vec![
            manifest(
                "claude",
                ".claude-plugin/plugin.json",
                json!({"name": "demo", "version": "1.2.0"}),
            ),
            manifest(
                "cursor",
                ".cursor-plugin/plugin.json",
                json!({"name": "demo"}),
            ),
        ];
        let id = identify(&ms, None, None).unwrap();
        assert_eq!(id.slug, "demo");
        assert_eq!(id.version, "1.2.0");
        assert_eq!(id.harnesses, ["claude", "cursor"]);
        assert!(id.overrides.is_empty());

        let none = vec![manifest(
            "cursor",
            ".cursor-plugin/plugin.json",
            json!({"name": "x"}),
        )];
        assert_eq!(identify(&none, None, None).unwrap().version, "1.0.0");

        let unnamed = vec![manifest("codex", ".codex-plugin/plugin.json", json!({}))];
        let e = identify(&unnamed, None, None).unwrap_err();
        assert!(e.contains("--name"), "{e}");
        assert_eq!(
            identify(&unnamed, Some("named"), None).unwrap().slug,
            "named"
        );

        let e = identify(&[], None, None).unwrap_err();
        assert!(e.contains("isn't an agent plugin bundle"), "{e}");
    }

    #[test]
    fn identity_refuses_what_the_server_would() {
        let ms = vec![
            manifest(
                "claude",
                ".claude-plugin/plugin.json",
                json!({"name": "demo", "version": "1.0.0"}),
            ),
            manifest(
                "codex",
                ".codex-plugin/plugin.json",
                json!({"name": "other"}),
            ),
        ];
        let e = identify(&ms, None, None).unwrap_err();
        assert!(
            e.contains(".codex-plugin/plugin.json names the plugin `other`"),
            "{e}"
        );

        let ms = vec![
            manifest(
                "claude",
                ".claude-plugin/plugin.json",
                json!({"version": "1.0.0"}),
            ),
            manifest(
                "codex",
                ".codex-plugin/plugin.json",
                json!({"version": "1.1.0"}),
            ),
        ];
        let e = identify(&ms, Some("demo"), None).unwrap_err();
        assert!(e.contains("says version 1.1.0"), "{e}");

        let ms = vec![manifest(
            "claude",
            ".claude-plugin/plugin.json",
            json!({"name": "Bad_Name"}),
        )];
        assert!(identify(&ms, None, None).is_err());
        let ms = vec![manifest(
            "claude",
            ".claude-plugin/plugin.json",
            json!({"name": "a", "version": "1.0"}),
        )];
        assert!(identify(&ms, None, None).is_err());
        assert!(identify(&ms, None, Some("v2")).is_err());
    }

    #[test]
    fn version_flag_rewrites_every_manifest_that_has_one() {
        let ms = vec![
            manifest(
                "claude",
                ".claude-plugin/plugin.json",
                json!({"name": "demo", "version": "1.0.0", "description": "d"}),
            ),
            manifest(
                "standard",
                "plugin.json",
                json!({"$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.json", "name": "demo", "version": "0.9.0"}),
            ),
            manifest(
                "cursor",
                ".cursor-plugin/plugin.json",
                json!({"name": "demo"}),
            ),
        ];
        let id = identify(&ms, None, Some("2.0.0")).unwrap();
        assert_eq!(id.version, "2.0.0");
        let keys: Vec<&str> = id.overrides.keys().map(String::as_str).collect();
        assert_eq!(keys, [".claude-plugin/plugin.json", "plugin.json"]);
        let claude: Value =
            serde_json::from_slice(&id.overrides[".claude-plugin/plugin.json"]).unwrap();
        assert_eq!(
            claude,
            json!({"name": "demo", "version": "2.0.0", "description": "d"})
        );
        // Field order is kept.
        let text = String::from_utf8(id.overrides["plugin.json"].clone()).unwrap();
        assert!(
            text.find("$schema").unwrap() < text.find("version").unwrap(),
            "{text}"
        );
    }

    #[test]
    fn the_zip_is_the_same_bytes_each_time_and_leaves_out_git() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            ".claude-plugin/plugin.json",
            r#"{"name":"demo"}"#,
        );
        write(dir.path(), "skills/b/SKILL.md", "b");
        write(dir.path(), "skills/a/SKILL.md", "a");
        write(dir.path(), ".git/HEAD", "ref");
        write(dir.path(), ".ak/plugin-info.json", "{}");
        write(dir.path(), "nested/.git/config", "x");
        let files = collect_files(dir.path()).unwrap();
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                ".claude-plugin/plugin.json",
                "skills/a/SKILL.md",
                "skills/b/SKILL.md"
            ]
        );

        let first = build_zip(&files, &BTreeMap::new()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(dir.path().join("skills/a/SKILL.md"), "a").unwrap();
        let second = build_zip(&collect_files(dir.path()).unwrap(), &BTreeMap::new()).unwrap();
        assert_eq!(sha256_hex(&first), sha256_hex(&second));

        let mut archive = zip::ZipArchive::new(Cursor::new(first)).unwrap();
        let in_zip: Vec<String> = archive
            .file_names()
            .map(|n| n.unwrap().into_owned())
            .collect();
        assert_eq!(in_zip, names);
        let mut text = String::new();
        archive
            .by_name("skills/b/SKILL.md")
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "b");
    }

    #[test]
    fn the_zip_carries_the_rewritten_manifest_and_the_directory_keeps_its_own() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            ".claude-plugin/plugin.json",
            r#"{"name":"demo","version":"1.0.0"}"#,
        );
        let ms = discover(dir.path()).unwrap();
        let id = identify(&ms, None, Some("3.1.0")).unwrap();
        let zip = build_zip(&collect_files(dir.path()).unwrap(), &id.overrides).unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(zip)).unwrap();
        let mut text = String::new();
        archive
            .by_name(".claude-plugin/plugin.json")
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap()["version"],
            "3.1.0"
        );
        let on_disk =
            std::fs::read_to_string(dir.path().join(".claude-plugin/plugin.json")).unwrap();
        assert_eq!(on_disk, r#"{"name":"demo","version":"1.0.0"}"#);
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_refused() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            ".claude-plugin/plugin.json",
            r#"{"name":"demo"}"#,
        );
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("passwd")).unwrap();
        let e = collect_files(dir.path()).unwrap_err();
        assert!(e.contains("symbolic link"), "{e}");
    }

    #[test]
    fn unsafe_names_are_named() {
        assert_eq!(unsafe_entry_name("a/../../b"), Some("climbs out with `..`"));
        assert_eq!(unsafe_entry_name("/etc/x"), Some("is an absolute path"));
        assert_eq!(unsafe_entry_name("C:/x"), Some("is an absolute path"));
        assert_eq!(unsafe_entry_name("a\\b"), Some("has a backslash"));
        assert_eq!(unsafe_entry_name("skills/a/SKILL.md"), None);
        assert_eq!(unsafe_entry_name("a..b/c"), None);
    }

    #[test]
    fn extraction_refuses_a_traversal_entry_and_writes_nothing() {
        let zip = zip_of(&[(".claude-plugin/plugin.json", "{}"), ("../escape.txt", "x")]);
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("out");
        let e = extract(Cursor::new(zip), &target).unwrap_err();
        assert!(e.contains("../escape.txt"), "{e}");
        assert!(!target.exists());
        assert!(!dir.path().join("escape.txt").exists());
    }

    #[test]
    fn extraction_refuses_a_symlink_entry() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .add_symlink(
                "link",
                "/etc/passwd",
                zip::write::SimpleFileOptions::DEFAULT,
            )
            .unwrap();
        let zip = writer.finish().unwrap().into_inner();
        let dir = TempDir::new().unwrap();
        let e = extract(Cursor::new(zip), &dir.path().join("out")).unwrap_err();
        assert!(e.contains("symbolic link"), "{e}");
    }

    #[test]
    fn extraction_strips_a_root_one_directory_down() {
        let zip = zip_of(&[
            ("demo/", ""),
            ("demo/.claude-plugin/plugin.json", r#"{"name":"demo"}"#),
            ("demo/skills/x/SKILL.md", "x"),
        ]);
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("out");
        assert_eq!(extract(Cursor::new(zip), &target).unwrap(), "demo/");
        assert!(target.join(".claude-plugin/plugin.json").is_file());
        assert_eq!(
            std::fs::read_to_string(target.join("skills/x/SKILL.md")).unwrap(),
            "x"
        );
    }

    #[test]
    fn a_plugin_with_only_a_component_directory_isnt_stripped() {
        // No marker one directory down, so `skills/` is the plugin's own directory.
        let names = vec![
            "skills/a/SKILL.md".to_string(),
            "skills/b/SKILL.md".to_string(),
        ];
        assert_eq!(detect_root(&names), "");
        let names = vec!["plugin.json".to_string(), "x/y".to_string()];
        assert_eq!(detect_root(&names), "");
        let names = vec!["a/.codex-plugin/plugin.json".to_string(), "b/x".to_string()];
        assert_eq!(detect_root(&names), "");
        let names = vec![
            "demo/.claude-plugin/plugin.json".to_string(),
            "__MACOSX/demo/._x".to_string(),
            ".DS_Store".to_string(),
        ];
        assert_eq!(detect_root(&names), "demo/");
    }

    #[test]
    fn extraction_at_the_top_keeps_every_path() {
        let zip = zip_of(&[(".cursor-plugin/plugin.json", "{}"), ("rules/a.mdc", "r")]);
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("out");
        assert_eq!(extract(Cursor::new(zip), &target).unwrap(), "");
        assert!(target.join("rules/a.mdc").is_file());
    }

    #[test]
    fn confined_refuses_anything_but_plain_parts() {
        let dir = TempDir::new().unwrap();
        assert!(confined(dir.path(), "a/./b").is_ok());
        assert!(confined(dir.path(), "a/../b").is_err());
        assert!(confined(dir.path(), "/a").is_err());
    }
}
