//! Put `ak setup`'s settings into a config file that may already hold other
//! people's: other registries, other tokens, comments. Only our keys change.
//!
//! Each function takes the file's text and returns the new text, and an empty
//! file gives what `setup` writes when there's no file, so a preview comes from
//! the same code with the placeholder for a token.

use toml_edit::{Array, DocumentMut, Item, Table, TableLike, value};

/// The name our registry goes by in Cargo's config.
const CARGO_REGISTRY: &str = "artifact-keeper";
const CARGO_TOKEN_PROVIDER: &str = "cargo:token";

/// New text for a file, and the keys in it that held a different value.
#[derive(Debug)]
pub(super) struct Merged {
    pub text: String,
    pub replaced: Vec<&'static str>,
}

fn parse_toml(existing: &str) -> Result<DocumentMut, String> {
    // No detail from the parser: it quotes the line, which can hold a token.
    existing.parse().map_err(|e: toml_edit::TomlError| {
        let line = e
            .span()
            .map_or(0, |span| existing[..span.start].lines().count().max(1));
        format!("it isn't valid TOML (near line {line})")
    })
}

/// The table at a path, made if it's missing. A parent that's only there to hold
/// the next table gets no header of its own.
fn toml_table<'a>(
    doc: &'a mut DocumentMut,
    path: &[&str],
) -> Result<&'a mut dyn TableLike, String> {
    let mut current: &mut dyn TableLike = doc.as_table_mut();
    for (depth, name) in path.iter().enumerate() {
        let item = current.entry(name).or_insert_with(|| {
            let mut table = Table::new();
            table.set_implicit(depth + 1 < path.len());
            Item::Table(table)
        });
        current = item
            .as_table_like_mut()
            .ok_or_else(|| format!("`{}` in it isn't a table", path[..=depth].join(".")))?;
    }
    Ok(current)
}

/// `config.toml`: our registry, as the default, with a provider that can read
/// `credentials.toml`.
pub(super) fn cargo_config(existing: &str, index: &str) -> Result<Merged, String> {
    let mut doc = parse_toml(existing)?;
    let mut replaced = Vec::new();

    toml_table(&mut doc, &["registries", CARGO_REGISTRY])?.insert("index", value(index));

    let registry = toml_table(&mut doc, &["registry"])?;
    if registry
        .get("default")
        .and_then(Item::as_str)
        .is_some_and(|old| old != CARGO_REGISTRY)
    {
        replaced.push("registry.default");
    }
    registry.insert("default", value(CARGO_REGISTRY));

    // Later entries are tried first, so one the user has is still there for the
    // registries `cargo:token` knows nothing about.
    match registry.get_mut("global-credential-providers") {
        None => {
            let mut providers = Array::new();
            providers.push(CARGO_TOKEN_PROVIDER);
            registry.insert("global-credential-providers", value(providers));
        }
        Some(item) => {
            let providers = item.as_array_mut().ok_or_else(|| {
                "`registry.global-credential-providers` in it isn't an array".to_string()
            })?;
            if !providers
                .iter()
                .any(|p| p.as_str() == Some(CARGO_TOKEN_PROVIDER))
            {
                providers.push(CARGO_TOKEN_PROVIDER);
            }
        }
    }

    Ok(Merged {
        text: doc.to_string(),
        replaced,
    })
}

/// `credentials.toml`: our registry's token. Any other token stays.
pub(super) fn cargo_credentials(existing: &str, token: &str) -> Result<String, String> {
    let mut doc = parse_toml(existing)?;
    toml_table(&mut doc, &["registries", CARGO_REGISTRY])?
        .insert("token", value(format!("Bearer {token}")));
    Ok(doc.to_string())
}

/// A file of lines, each with its own line ending as it was found.
struct Lines {
    lines: Vec<String>,
    eol: &'static str,
}

impl Lines {
    fn parse(text: &str) -> Self {
        Self {
            lines: text.split_inclusive('\n').map(str::to_string).collect(),
            eol: if text.contains("\r\n") { "\r\n" } else { "\n" },
        }
    }

    fn line(&self, text: &str) -> String {
        format!("{text}{}", self.eol)
    }

    fn insert(&mut self, at: usize, text: &str) {
        // The line before may be the last in the file, with no line ending.
        if let Some(before) = at.checked_sub(1).and_then(|i| self.lines.get_mut(i))
            && !before.ends_with('\n')
        {
            before.push_str(self.eol);
        }
        let line = self.line(text);
        self.lines.insert(at, line);
    }

    fn text(self) -> String {
        self.lines.concat()
    }
}

/// `.npmrc`: the default registry and that registry's token. Keys are line by
/// line, and a line starting `[` opens a section that holds what follows it, so
/// only the lines before the first section are the settings that count.
pub(super) fn npmrc(existing: &str, registry: &str, auth_key: &str, token: &str) -> Merged {
    let key_of = |line: &str| -> Option<String> {
        let line = line.trim();
        if line.starts_with(['#', ';', '[']) {
            return None;
        }
        Some(line.split_once('=')?.0.trim().to_string())
    };
    let top_level_end = |file: &Lines| {
        file.lines
            .iter()
            .position(|line| line.trim_start().starts_with('['))
            .unwrap_or(file.lines.len())
    };
    let mut file = Lines::parse(existing);
    let mut replaced = Vec::new();

    let old_registry = file.lines[..top_level_end(&file)]
        .iter()
        .rfind(|line| key_of(line).as_deref() == Some("registry"))
        .and_then(|line| line.split_once('='))
        .map(|(_, old)| old.trim().trim_matches(['"', '\'']).to_string());
    if old_registry.is_some_and(|old| old != registry) {
        replaced.push("registry");
    }

    for (key, new) in [
        ("registry", format!("registry={registry}")),
        (auth_key, format!("{auth_key}={token}")),
    ] {
        let end = top_level_end(&file);
        let newline = file.line(&new);
        let mut placed = false;
        let mut kept = Vec::with_capacity(file.lines.len());
        for (i, line) in file.lines.drain(..).enumerate() {
            if i >= end || key_of(&line).as_deref() != Some(key) {
                kept.push(line);
            } else if !placed {
                kept.push(newline.clone());
                placed = true;
            }
            // npm takes the last of a repeated key, so a later one has to go.
        }
        file.lines = kept;
        if !placed {
            let at = top_level_end(&file);
            file.insert(at, &new);
        }
    }

    Merged {
        text: file.text(),
        replaced,
    }
}

/// A section of a pip config, as Python's `configparser` reads it.
struct PipSection {
    name: String,
    header: usize,
    /// One past its last line.
    end: usize,
    options: Vec<PipOption>,
}

struct PipOption {
    /// Lowercase, with `-` for `_`, as pip reads it.
    key: String,
    start: usize,
    /// One past its last line. A value goes on over any more-indented lines, blank
    /// lines between them included.
    stop: usize,
}

/// Read a pip config the way pip does, or say why pip couldn't, in which case
/// there's no safe edit to make. Each case here makes pip refuse every command.
fn pip_sections(file: &Lines) -> Result<Vec<PipSection>, String> {
    let mut sections: Vec<PipSection> = Vec::new();
    // How far the current option's first line is indented.
    let mut indent = 0;
    for (i, line) in file.lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            continue;
        }
        let this_indent = line.len() - line.trim_start().len();
        if let Some(option) = sections.last_mut().and_then(|s| s.options.last_mut())
            && this_indent > indent
        {
            option.stop = i + 1;
            continue;
        }
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.find(']').map(|end| &rest[..end]))
            .filter(|name| !name.is_empty())
        {
            if sections.iter().any(|s| s.name == name) {
                return Err(format!("it has more than one [{name}] section"));
            }
            if let Some(last) = sections.last_mut() {
                last.end = i;
            }
            sections.push(PipSection {
                name: name.to_string(),
                header: i,
                end: file.lines.len(),
                options: Vec::new(),
            });
            indent = 0;
            continue;
        }
        let number = i + 1;
        let Some(section) = sections.last_mut() else {
            return Err(format!("line {number} is outside any section"));
        };
        let Some((key, _)) = trimmed.split_once(['=', ':']) else {
            return Err(format!("line {number} has no value"));
        };
        let key = key.trim().replace('_', "-").to_lowercase();
        if section.options.iter().any(|o| o.key == key) {
            return Err(format!("{key} appears twice in [{}]", section.name));
        }
        indent = this_indent;
        section.options.push(PipOption {
            key,
            start: i,
            stop: i + 1,
        });
    }
    Ok(sections)
}

fn pip_global(sections: &[PipSection]) -> Option<&PipSection> {
    sections.iter().find(|s| s.name == "global")
}

/// Where a new key goes in `[global]`: after its last line that isn't blank. Anything
/// indented straight after the new key would become part of its value, so it can't
/// go above the section's other keys, and it starts at the margin.
fn pip_insert_at(file: &Lines, section: &PipSection) -> usize {
    (section.header + 1..section.end)
        .rev()
        .find(|&i| !file.lines[i].trim().is_empty())
        .map_or(section.header + 1, |i| i + 1)
}

/// A URL with any password taken out, so a new token isn't a new index.
fn without_password(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return url.to_string();
    };
    let _ = parsed.set_password(None);
    parsed.to_string()
}

/// `pip.conf`: `index-url`, and `trusted-host` when plain HTTP needs it, in
/// `[global]`. Other keys and sections stay, `extra-index-url` among them. Fails if
/// pip couldn't read the result, or wouldn't use it.
pub(super) fn pip_conf(
    existing: &str,
    index_url: &str,
    trusted_host: Option<&str>,
) -> Result<Merged, String> {
    let mut file = Lines::parse(existing);
    let mut replaced = Vec::new();
    let sections = pip_sections(&file)?;

    // pip reads a command's own section over [global], so this wouldn't take effect.
    if let Some(section) = sections
        .iter()
        .find(|s| s.name != "global" && s.options.iter().any(|o| o.key == "index-url"))
    {
        return Err(format!(
            "index-url in its [{}] section would override [global]",
            section.name
        ));
    }

    if pip_global(&sections).is_none() {
        if !file.lines.is_empty() {
            let end = file.lines.len();
            file.insert(end, "");
        }
        let end = file.lines.len();
        file.insert(end, "[global]");
    }

    let sections = pip_sections(&file)?;
    let global = pip_global(&sections).expect("added above");
    if let Some(option) = global.options.iter().find(|o| o.key == "index-url") {
        let old = file.lines[option.start..option.stop].concat();
        let old = old.split_once(['=', ':']).map_or("", |(_, old)| old.trim());
        if without_password(old) != without_password(index_url) {
            replaced.push("index-url");
        }
        // At the same indent, or a line indented below it becomes part of its value.
        let first = &file.lines[option.start];
        let indent = &first[..first.len() - first.trim_start().len()];
        let line = file.line(&format!("{indent}index-url = {index_url}"));
        let (start, stop) = (option.start, option.stop);
        file.lines.splice(start..stop, [line]);
    } else {
        let at = pip_insert_at(&file, global);
        file.insert(at, &format!("index-url = {index_url}"));
    }

    if let Some(host) = trusted_host {
        let sections = pip_sections(&file)?;
        let global = pip_global(&sections).expect("added above");
        match global.options.iter().find(|o| o.key == "trusted-host") {
            Some(option) => {
                let values = file.lines[option.start..option.stop].concat();
                let values = values.split_once(['=', ':']).map_or("", |(_, rest)| rest);
                if !values.split_whitespace().any(|known| known == host) {
                    let first = &file.lines[option.start];
                    let indent = first.len() - first.trim_start().len();
                    let stop = option.stop;
                    file.insert(stop, &format!("{}{host}", " ".repeat(indent + 4)));
                }
            }
            None => {
                let at = pip_insert_at(&file, global);
                file.insert(at, &format!("trusted-host = {host}"));
            }
        }
    }

    Ok(Merged {
        text: file.text(),
        replaced,
    })
}

/// One entry of a `.netrc`, and the bytes it takes up.
struct NetrcEntry {
    /// `machine`'s value, or `None` for `default` and `macdef`.
    host: Option<String>,
    is_default: bool,
    start: usize,
    end: usize,
}

/// Read one word from `at`: to the closing quote if it opens with one, or else to the
/// next space. Which means it's up to the caller whether a word is a keyword: a
/// password can be `default`, `machine` or `#hash`.
fn netrc_word(text: &str, at: usize) -> Option<(&str, usize)> {
    let rest = &text[at..];
    let start = at + (rest.len() - rest.trim_start().len());
    let rest = &text[start..];
    if rest.is_empty() {
        return None;
    }
    let len = if let Some(quoted) = rest.strip_prefix('"') {
        quoted.find('"').map_or(rest.len(), |end| end + 2)
    } else {
        rest.find(char::is_whitespace).unwrap_or(rest.len())
    };
    Some((&text[start..start + len], start))
}

/// Read a `.netrc` by its grammar, or say why that isn't possible.
fn netrc_entries(text: &str) -> Result<Vec<NetrcEntry>, String> {
    let line_of = |at: usize| text[..at].lines().count().max(1);
    let mut entries = Vec::new();
    let mut at = 0;
    while let Some((word, start)) = netrc_word(text, at) {
        at = start + word.len();
        match word {
            // Where a keyword is expected, `#` starts a comment.
            _ if word.starts_with('#') => {
                at = start + text[start..].find('\n').unwrap_or(text.len() - start);
            }
            "machine" => {
                let (host, host_at) = netrc_word(text, at)
                    .ok_or_else(|| format!("line {} has no host after machine", line_of(start)))?;
                at = host_at + host.len();
                entries.push(NetrcEntry {
                    host: Some(host.trim_matches('"').to_string()),
                    is_default: false,
                    start,
                    end: at,
                });
            }
            "default" => entries.push(NetrcEntry {
                host: None,
                is_default: true,
                start,
                end: at,
            }),
            "login" | "password" | "account" => {
                let entry = entries
                    .last_mut()
                    .filter(|e| e.host.is_some() || e.is_default);
                let entry = entry.ok_or_else(|| {
                    format!("line {} has {word} outside an entry", line_of(start))
                })?;
                let (value, value_at) = netrc_word(text, at)
                    .ok_or_else(|| format!("line {} has no value after {word}", line_of(start)))?;
                at = value_at + value.len();
                entry.end = at;
            }
            "macdef" => {
                // Its name, then a body up to a blank line. The body can hold anything.
                let body = &text[at..];
                let end = at + body.find("\n\n").map_or(body.len(), |end| end + 2);
                entries.push(NetrcEntry {
                    host: None,
                    is_default: false,
                    start,
                    end,
                });
                at = end;
            }
            _ => {
                // Don't repeat the word: it could be a secret on a broken line.
                return Err(format!("line {} has something unexpected", line_of(start)));
            }
        }
    }
    Ok(entries)
}

/// `.netrc`: one entry for this host, in place of any there were. go and curl use
/// the first entry for a host, so adding a line after an old one would change
/// nothing. Every other host's entry stays, as do comments.
pub(super) fn netrc(existing: &str, host: &str, line: &str) -> Result<String, String> {
    let entries = netrc_entries(existing)?;
    let ours: Vec<&NetrcEntry> = entries
        .iter()
        .filter(|entry| entry.host.as_deref() == Some(host))
        .collect();

    let mut text = String::with_capacity(existing.len() + line.len() + 1);
    let mut copied = 0;
    for (i, entry) in ours.iter().enumerate() {
        text.push_str(&existing[copied..entry.start]);
        if i == 0 {
            text.push_str(line);
            text.push('\n');
        }
        // Its line ending goes with it, so a comment after it stays on its own line.
        copied = entry.end;
        if existing[copied..].starts_with("\r\n") {
            copied += 2;
        } else if existing[copied..].starts_with('\n') {
            copied += 1;
        }
    }
    text.push_str(&existing[copied..]);
    if ours.is_empty() {
        // `default` matches every host, and whatever follows it is never read.
        let at = entries
            .iter()
            .find(|entry| entry.is_default)
            .map_or(text.len(), |entry| entry.start);
        let mut new = format!("{line}\n");
        if at > 0 && !text[..at].ends_with('\n') {
            new.insert(0, '\n');
        }
        text.insert_str(at, &new);
    }
    Ok(text)
}

/// Whether a file is one `setup` wrote: its template, line for line, apart from
/// the URL and the token, which change between runs. Anything else has someone
/// else's work in it, even if `setup` wrote it first.
pub(super) fn is_generated(existing: &str, template: &str, url: &str, slot: &str) -> bool {
    let (found, expected): (Vec<_>, Vec<_>) =
        (existing.lines().collect(), template.lines().collect());
    found.len() == expected.len()
        && found.iter().zip(&expected).all(|(found, expected)| {
            match [url, slot]
                .into_iter()
                .find_map(|value| expected.split_once(value))
            {
                Some((before, after)) => {
                    found.len() >= before.len() + after.len()
                        && found.starts_with(before)
                        && found.ends_with(after)
                }
                None => found == expected,
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const INDEX: &str = "sparse+https://ak.test/cargo/r/";

    fn parsed(text: &str) -> toml::Table {
        text.parse().unwrap_or_else(|e| panic!("{e}\n{text}"))
    }

    #[test]
    fn cargo_config_from_nothing() {
        let merged = cargo_config("", INDEX).unwrap();
        assert_eq!(
            merged.text,
            format!(
                "[registries.artifact-keeper]\nindex = \"{INDEX}\"\n\n[registry]\n\
                 default = \"artifact-keeper\"\nglobal-credential-providers = [\"cargo:token\"]\n"
            )
        );
        assert!(merged.replaced.is_empty());
    }

    #[test]
    fn cargo_config_keeps_everything_else() {
        let existing = "# my comment\n[registries.corp]\nindex = \"sparse+https://corp.test/\" # theirs\n\n\
                        [net]\ngit-fetch-with-cli = true\n\n[source.crates-io]\nreplace-with = \"corp\"\n";
        let merged = cargo_config(existing, INDEX).unwrap();
        for kept in [
            "# my comment\n",
            "index = \"sparse+https://corp.test/\" # theirs\n",
            "git-fetch-with-cli = true\n",
            "replace-with = \"corp\"\n",
        ] {
            assert!(merged.text.contains(kept), "{kept}: {}", merged.text);
        }
        let toml = parsed(&merged.text);
        assert_eq!(
            toml["registries"]["artifact-keeper"]["index"].as_str(),
            Some(INDEX)
        );
        assert!(merged.replaced.is_empty());
    }

    #[test]
    fn cargo_config_says_when_it_changes_the_default() {
        let existing = "[registry]\ndefault = \"corp\"\n";
        let merged = cargo_config(existing, INDEX).unwrap();
        assert_eq!(merged.replaced, ["registry.default"]);
        assert_eq!(
            parsed(&merged.text)["registry"]["default"].as_str(),
            Some("artifact-keeper")
        );
    }

    #[test]
    fn cargo_config_keeps_other_credential_providers() {
        let existing = "[registry]\nglobal-credential-providers = [\"cargo:libsecret\"]\n";
        let text = cargo_config(existing, INDEX).unwrap().text;
        let providers = parsed(&text)["registry"]["global-credential-providers"].clone();
        let providers: Vec<_> = providers
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_string())
            .collect();
        assert_eq!(providers, ["cargo:libsecret", "cargo:token"]);

        let again = cargo_config(&text, INDEX).unwrap().text;
        assert_eq!(again, text, "a second run changed the file");
    }

    #[test]
    fn cargo_config_handles_other_shapes_of_the_same_tables() {
        for existing in [
            "registry.default = \"corp\"\n",
            "registries = { corp = { index = \"sparse+https://corp.test/\" } }\n",
        ] {
            let text = cargo_config(existing, INDEX).unwrap().text;
            let toml = parsed(&text);
            assert_eq!(
                toml["registries"]["artifact-keeper"]["index"].as_str(),
                Some(INDEX),
                "{text}"
            );
        }
    }

    #[test]
    fn cargo_files_that_cannot_be_merged_are_refused_without_quoting_them() {
        let err = cargo_credentials("[registry]\ntoken = \"secret-value\n", "t").unwrap_err();
        assert!(!err.contains("secret-value"), "{err}");
        assert!(err.contains("line 2"), "{err}");

        let err = cargo_config("registry = \"not a table\"\n", INDEX).unwrap_err();
        assert!(err.contains("`registry`"), "{err}");
    }

    #[test]
    fn cargo_credentials_keep_other_tokens() {
        let existing = "[registry]\ntoken = \"crates-io\"\n\n[registries.corp]\ntoken = \"corp\"\n\n\
                        [registries.artifact-keeper]\ntoken = \"Bearer old\"\n";
        let toml = parsed(&cargo_credentials(existing, "new").unwrap());
        assert_eq!(toml["registry"]["token"].as_str(), Some("crates-io"));
        assert_eq!(toml["registries"]["corp"]["token"].as_str(), Some("corp"));
        assert_eq!(
            toml["registries"]["artifact-keeper"]["token"].as_str(),
            Some("Bearer new")
        );
    }

    const NPM_URL: &str = "https://ak.test/npm/r/";
    const NPM_AUTH: &str = "//ak.test/npm/r/:_authToken";

    #[test]
    fn npmrc_from_nothing() {
        let merged = npmrc("", NPM_URL, NPM_AUTH, "tok");
        assert_eq!(merged.text, format!("registry={NPM_URL}\n{NPM_AUTH}=tok\n"));
        assert!(merged.replaced.is_empty());
    }

    #[test]
    fn npmrc_keeps_other_lines_and_replaces_ours_in_place() {
        let existing = "# mine\n@corp:registry=https://corp.test/\n//corp.test/:_authToken=corp\n\
                        registry = https://registry.npmjs.org/\nsave-exact=true\n";
        let merged = npmrc(existing, NPM_URL, NPM_AUTH, "tok");
        assert_eq!(
            merged.text,
            format!(
                "# mine\n@corp:registry=https://corp.test/\n//corp.test/:_authToken=corp\n\
                 registry={NPM_URL}\nsave-exact=true\n{NPM_AUTH}=tok\n"
            )
        );
        assert_eq!(merged.replaced, ["registry"]);
    }

    #[test]
    fn npmrc_a_second_run_changes_only_the_token() {
        let first = npmrc("save-exact=true\n", NPM_URL, NPM_AUTH, "one").text;
        let second = npmrc(&first, NPM_URL, NPM_AUTH, "two");
        assert_eq!(second.text, first.replace("=one", "=two"));
        assert!(second.replaced.is_empty());
    }

    #[test]
    fn npmrc_leaves_no_repeat_of_a_key_to_override_ours() {
        let text = npmrc("registry=a\nx=1\nregistry=b\n", NPM_URL, NPM_AUTH, "t").text;
        assert_eq!(text.matches("registry=").count(), 1, "{text}");
    }

    #[test]
    fn npmrc_adds_keys_outside_any_section() {
        let text = npmrc("a=1\n[section]\nb=2", NPM_URL, NPM_AUTH, "t").text;
        assert_eq!(
            text,
            format!("a=1\nregistry={NPM_URL}\n{NPM_AUTH}=t\n[section]\nb=2")
        );
    }

    #[test]
    fn npmrc_leaves_a_section_with_the_same_key_alone() {
        // npm reads this as `section.registry`, and it isn't the default registry.
        let existing = "a=1\n[section]\nregistry=https://theirs.test/\n";
        let merged = npmrc(existing, NPM_URL, NPM_AUTH, "t");
        assert_eq!(
            merged.text,
            format!(
                "a=1\nregistry={NPM_URL}\n{NPM_AUTH}=t\n[section]\nregistry=https://theirs.test/\n"
            )
        );
        assert!(merged.replaced.is_empty());
    }

    #[test]
    fn npmrc_reads_a_quoted_value() {
        let merged = npmrc(&format!("registry=\"{NPM_URL}\"\n"), NPM_URL, NPM_AUTH, "t");
        assert!(merged.replaced.is_empty());
    }

    #[test]
    fn npmrc_handles_a_last_line_with_no_ending_and_keeps_crlf() {
        assert_eq!(
            npmrc("a=1", NPM_URL, NPM_AUTH, "t").text,
            format!("a=1\nregistry={NPM_URL}\n{NPM_AUTH}=t\n")
        );
        assert_eq!(
            npmrc("a=1\r\n", NPM_URL, NPM_AUTH, "t").text,
            format!("a=1\r\nregistry={NPM_URL}\r\n{NPM_AUTH}=t\r\n")
        );
    }

    const PIP_URL: &str = "https://__token__:tok@ak.test/pypi/r/simple/";

    #[test]
    fn pip_from_nothing() {
        let merged = pip_conf("", PIP_URL, None).unwrap();
        assert_eq!(merged.text, format!("[global]\nindex-url = {PIP_URL}\n"));
        assert_eq!(
            pip_conf("", "http://ak.test/", Some("ak.test"))
                .unwrap()
                .text,
            "[global]\nindex-url = http://ak.test/\ntrusted-host = ak.test\n"
        );
    }

    #[test]
    fn pip_keeps_other_keys_and_sections() {
        let existing = "# mine\n[global]\ntimeout = 30\nindex_url = https://corp.test/simple/\n\
                        extra-index-url = https://u:corp-secret@other.test/simple/\n\n\
                        [install]\nno-deps = true\n";
        let merged = pip_conf(existing, PIP_URL, None).unwrap();
        assert_eq!(
            merged.text,
            format!(
                "# mine\n[global]\ntimeout = 30\nindex-url = {PIP_URL}\n\
                 extra-index-url = https://u:corp-secret@other.test/simple/\n\n\
                 [install]\nno-deps = true\n"
            )
        );
        assert_eq!(merged.replaced, ["index-url"]);
    }

    #[test]
    fn pip_a_new_token_is_not_a_new_index() {
        let first = pip_conf("", PIP_URL, None).unwrap().text;
        let second = pip_conf(&first, &PIP_URL.replace(":tok@", ":new@"), None).unwrap();
        assert!(second.replaced.is_empty());
        assert!(second.text.contains(":new@"));
        assert!(!second.text.contains(":tok@"));
    }

    #[test]
    fn pip_adds_global_when_there_is_none() {
        let existing = "[install]\nno-deps = true\n";
        assert_eq!(
            pip_conf(existing, PIP_URL, None).unwrap().text,
            format!("[install]\nno-deps = true\n\n[global]\nindex-url = {PIP_URL}\n")
        );
    }

    #[test]
    fn pip_finds_a_header_with_a_comment_after_it() {
        // A second [global] makes pip refuse every command.
        let text = pip_conf("[global] # mine\ntimeout = 3\n", PIP_URL, None)
            .unwrap()
            .text;
        assert_eq!(
            text,
            format!("[global] # mine\ntimeout = 3\nindex-url = {PIP_URL}\n")
        );
    }

    #[test]
    fn pip_doesnt_swallow_indented_keys_into_its_value() {
        let text = pip_conf(
            "[global]\n    timeout = 3\n    retries = 1\n",
            PIP_URL,
            None,
        )
        .unwrap()
        .text;
        assert_eq!(
            text,
            format!("[global]\n    timeout = 3\n    retries = 1\nindex-url = {PIP_URL}\n")
        );

        // Replaced in place, at its indent, for the same reason.
        let text = pip_conf(
            "[global]\n    index-url = https://a.test/\n    timeout = 3\n",
            PIP_URL,
            None,
        )
        .unwrap()
        .text;
        assert_eq!(
            text,
            format!("[global]\n    index-url = {PIP_URL}\n    timeout = 3\n")
        );
    }

    #[test]
    fn pip_keeps_trailing_blank_lines_outside_its_section() {
        let text = pip_conf(
            "[global]\ntimeout = 3\n\n[install]\nno-deps = true\n",
            PIP_URL,
            None,
        )
        .unwrap()
        .text;
        assert_eq!(
            text,
            format!("[global]\ntimeout = 3\nindex-url = {PIP_URL}\n\n[install]\nno-deps = true\n")
        );
    }

    #[test]
    fn pip_refuses_what_it_cant_safely_edit() {
        for (existing, reason) in [
            ("timeout = 3\n", "outside any section"),
            (
                "[global]\na = 1\n[global]\nb = 2\n",
                "more than one [global]",
            ),
            ("[global]\na = 1\na = 2\n", "appears twice"),
            ("[global]\njust words\n", "no value"),
            ("[install]\nindex-url = https://t.test/\n", "would override"),
        ] {
            let Err(err) = pip_conf(existing, PIP_URL, None) else {
                panic!("{existing:?} should be refused");
            };
            assert!(err.contains(reason), "{existing:?}: {err}");
        }
    }

    #[test]
    fn pip_replaces_a_value_that_spans_lines() {
        let existing = "[global]\nindex-url = https://a.test/\n    continued\ntimeout = 3\n";
        assert_eq!(
            pip_conf(existing, PIP_URL, None).unwrap().text,
            format!("[global]\nindex-url = {PIP_URL}\ntimeout = 3\n")
        );
    }

    #[test]
    fn pip_adds_to_trusted_hosts_rather_than_replacing_them() {
        let existing = "[global]\ntrusted-host = a.test\n    b.test\ntimeout = 3\n";
        let once = pip_conf(existing, "http://ak.test/", Some("ak.test"))
            .unwrap()
            .text;
        assert!(
            once.contains("trusted-host = a.test\n    b.test\n    ak.test\n"),
            "{once}"
        );
        let twice = pip_conf(&once, "http://ak.test/", Some("ak.test"))
            .unwrap()
            .text;
        assert_eq!(once, twice);
    }

    const NETRC_LINE: &str = "machine ak.test login __token__ password new";

    #[test]
    fn netrc_from_nothing() {
        assert_eq!(
            netrc("", "ak.test", NETRC_LINE).unwrap(),
            format!("{NETRC_LINE}\n")
        );
    }

    #[test]
    fn netrc_replaces_only_this_hosts_entry() {
        let existing = "# mine\nmachine a.test login u password p1\n\
                        machine ak.test login __token__ password old\n\
                        machine b.test login v password p2\n";
        assert_eq!(
            netrc(existing, "ak.test", NETRC_LINE).unwrap(),
            format!(
                "# mine\nmachine a.test login u password p1\n{NETRC_LINE}\n\
                 machine b.test login v password p2\n"
            )
        );
    }

    #[test]
    fn netrc_replaces_an_entry_on_several_lines_and_every_repeat() {
        let existing = "machine ak.test\n  login u\n  password old\nmachine b.test login v password p\n\
                        machine ak.test login w password older\n";
        assert_eq!(
            netrc(existing, "ak.test", NETRC_LINE).unwrap(),
            format!("{NETRC_LINE}\nmachine b.test login v password p\n")
        );
    }

    #[test]
    fn netrc_handles_entries_sharing_a_line() {
        let existing = "machine a.test login u password p machine ak.test login x password old machine b.test login v password q\n";
        let text = netrc(existing, "ak.test", NETRC_LINE).unwrap();
        assert!(text.contains("machine a.test login u password p"), "{text}");
        assert!(text.contains("machine b.test login v password q"), "{text}");
        assert!(text.contains(NETRC_LINE), "{text}");
        assert!(!text.contains("old"), "{text}");
    }

    #[test]
    fn netrc_keeps_a_comment_after_the_entry_it_replaces() {
        let existing =
            "machine ak.test login u password old\n# about b\nmachine b.test login v password p\n";
        assert_eq!(
            netrc(existing, "ak.test", NETRC_LINE).unwrap(),
            format!("{NETRC_LINE}\n# about b\nmachine b.test login v password p\n")
        );
    }

    #[test]
    fn netrc_goes_before_a_default_entry_which_ends_the_search() {
        let existing = "machine a.test login u password p\ndefault login d password dd\n";
        assert_eq!(
            netrc(existing, "ak.test", NETRC_LINE).unwrap(),
            format!(
                "machine a.test login u password p\n{NETRC_LINE}\ndefault login d password dd\n"
            )
        );
    }

    #[test]
    fn netrc_does_not_read_a_macro_body_or_a_comment_as_an_entry() {
        let existing = "# machine ak.test login c password comment\n\
                        macdef init\nmachine ak.test login m password macro\n\n\
                        machine b.test login v password p\n";
        let text = netrc(existing, "ak.test", NETRC_LINE).unwrap();
        assert!(text.contains("password comment"), "{text}");
        assert!(text.contains("password macro"), "{text}");
        assert!(text.ends_with(&format!("{NETRC_LINE}\n")), "{text}");
    }

    #[test]
    fn netrc_only_matches_the_whole_host() {
        let existing =
            "machine ak.test:8443 login u password p\nmachine xak.test login v password q\n";
        let text = netrc(existing, "ak.test", NETRC_LINE).unwrap();
        assert!(text.starts_with(existing), "{text}");
        assert!(text.contains(NETRC_LINE), "{text}");
    }

    #[test]
    fn netrc_doesnt_read_a_value_as_a_keyword() {
        // These all look like the start of something else.
        let existing = "machine a.test login default password machine\n\
                        machine b.test login macdef password #hash\n\
                        machine ak.test login login password default\n\
                        machine c.test login u password p\n";
        assert_eq!(
            netrc(existing, "ak.test", NETRC_LINE).unwrap(),
            format!(
                "machine a.test login default password machine\n\
                 machine b.test login macdef password #hash\n\
                 {NETRC_LINE}\n\
                 machine c.test login u password p\n"
            )
        );
    }

    #[test]
    fn netrc_a_password_equal_to_the_host_isnt_an_entry() {
        let existing = "machine a.test login machine password ak.test\n";
        let text = netrc(existing, "ak.test", NETRC_LINE).unwrap();
        assert_eq!(text, format!("{existing}{NETRC_LINE}\n"));
    }

    #[test]
    fn netrc_refuses_what_it_cant_read_without_quoting_it() {
        for existing in [
            "machine a.test login u password p secret-word\n",
            "login u password secret-word\n",
            "machine a.test login\n",
            "machine\n",
        ] {
            let err = netrc(existing, "ak.test", NETRC_LINE).unwrap_err();
            assert!(!err.contains("secret-word"), "{err}");
            assert!(err.contains("line 1"), "{err}");
        }
    }

    #[test]
    fn netrc_a_last_line_with_no_ending() {
        assert_eq!(
            netrc("machine a.test login u password p", "ak.test", NETRC_LINE).unwrap(),
            format!("machine a.test login u password p\n{NETRC_LINE}\n")
        );
    }

    #[test]
    fn is_generated_ignores_only_the_url_and_the_token() {
        let template = "<a>\n  <url>https://ak.test/r/</url>\n  <password>****</password>\n</a>\n";
        let same = |text| is_generated(text, template, "https://ak.test/r/", "****");

        assert!(same(template));
        assert!(same(
            "<a>\n  <url>https://old/x/</url>\n  <password>secret</password>\n</a>\n"
        ));
        assert!(!same(
            "<a>\n  <url>https://old/x/</url>\n  <password>s</password>\n  <b/>\n</a>\n"
        ));
        assert!(!same(
            "<a>\n  <mirror/>\n  <password>secret</password>\n</a>\n"
        ));
        assert!(!same("anything else"));
        assert!(!same(""));
    }
}
