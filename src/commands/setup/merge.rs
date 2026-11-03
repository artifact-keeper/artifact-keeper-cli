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
/// line, and a line starting `[` opens a section that holds what follows it.
pub(super) fn npmrc(existing: &str, registry: &str, auth_key: &str, token: &str) -> Merged {
    let key_of = |line: &str| -> Option<String> {
        let line = line.trim();
        if line.starts_with(['#', ';', '[']) {
            return None;
        }
        Some(line.split_once('=')?.0.trim().to_string())
    };
    let mut file = Lines::parse(existing);
    let mut replaced = Vec::new();

    let old_registry = file
        .lines
        .iter()
        .rfind(|line| key_of(line).as_deref() == Some("registry"))
        .and_then(|line| line.split_once('='))
        .map(|(_, old)| old.trim().to_string());
    if old_registry.is_some_and(|old| old != registry) {
        replaced.push("registry");
    }

    for (key, new) in [
        ("registry", format!("registry={registry}")),
        (auth_key, format!("{auth_key}={token}")),
    ] {
        let mut placed = false;
        let mut kept = Vec::with_capacity(file.lines.len());
        let newline = file.line(&new);
        for line in file.lines.drain(..) {
            if key_of(&line).as_deref() != Some(key) {
                kept.push(line);
            } else if !placed {
                kept.push(newline.clone());
                placed = true;
            }
            // npm takes the last of a repeated key, so a later one has to go.
        }
        file.lines = kept;
        if !placed {
            let at = file
                .lines
                .iter()
                .position(|line| line.trim_start().starts_with('['))
                .unwrap_or(file.lines.len());
            file.insert(at, &new);
        }
    }

    Merged {
        text: file.text(),
        replaced,
    }
}

/// The name of the key on a line of a pip config, which also takes `key: value`
/// and spells keys with `_` or `-`. A line that starts with a space continues the
/// value above it.
fn pip_key(line: &str) -> Option<String> {
    if line.starts_with([' ', '\t']) || line.trim_start().starts_with(['#', ';', '[']) {
        return None;
    }
    let (key, _) = line.split_once(['=', ':'])?;
    Some(key.trim().replace('_', "-").to_lowercase())
}

/// The lines of `[global]`: its header, and one past its last line.
fn pip_global(file: &Lines) -> Option<(usize, usize)> {
    let header = file
        .lines
        .iter()
        .position(|line| line.trim() == "[global]")?;
    let end = file.lines[header + 1..]
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .map_or(file.lines.len(), |i| header + 1 + i);
    Some((header, end))
}

/// The line of a key in `[global]`, and one past the lines continuing its value.
fn pip_value(file: &Lines, key: &str) -> Option<(usize, usize)> {
    let (header, end) = pip_global(file)?;
    let start = (header + 1..end).find(|&i| pip_key(&file.lines[i]).as_deref() == Some(key))?;
    let stop = (start + 1..end)
        .find(|&i| {
            let line = &file.lines[i];
            !line.starts_with([' ', '\t']) || line.trim().is_empty()
        })
        .unwrap_or(end);
    Some((start, stop))
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
/// `[global]`. Other keys and sections stay, `extra-index-url` among them.
pub(super) fn pip_conf(existing: &str, index_url: &str, trusted_host: Option<&str>) -> Merged {
    let mut file = Lines::parse(existing);
    let mut replaced = Vec::new();

    if pip_global(&file).is_none() {
        if !file.lines.is_empty() {
            let end = file.lines.len();
            file.insert(end, "");
        }
        let end = file.lines.len();
        file.insert(end, "[global]");
    }

    let new = format!("index-url = {index_url}");
    if let Some((start, stop)) = pip_value(&file, "index-url") {
        let old = file.lines[start..stop].concat();
        let old = old.split_once(['=', ':']).map_or("", |(_, old)| old.trim());
        if without_password(old) != without_password(index_url) {
            replaced.push("index-url");
        }
        let line = file.line(&new);
        file.lines.splice(start..stop, [line]);
    } else {
        let (header, _) = pip_global(&file).expect("added above");
        file.insert(header + 1, &new);
    }

    if let Some(host) = trusted_host {
        match pip_value(&file, "trusted-host") {
            Some((start, stop)) => {
                let values = file.lines[start..stop].concat();
                let values = values.split_once(['=', ':']).map_or("", |(_, rest)| rest);
                if !values.split_whitespace().any(|known| known == host) {
                    file.insert(stop, &format!("    {host}"));
                }
            }
            None => {
                let (start, _) = pip_value(&file, "index-url").expect("set above");
                file.insert(start + 1, &format!("trusted-host = {host}"));
            }
        }
    }

    Merged {
        text: file.text(),
        replaced,
    }
}

/// One token of a `.netrc` and where it starts. Comments and `macdef` bodies, which
/// can hold anything, aren't tokens.
fn netrc_tokens(text: &str) -> Vec<(usize, &str)> {
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let trimmed = rest.trim_start();
        at += rest.len() - trimmed.len();
        if trimmed.is_empty() {
            break;
        }
        if trimmed.starts_with('#') {
            at += trimmed.find('\n').unwrap_or(trimmed.len());
            continue;
        }
        let len = if let Some(quoted) = trimmed.strip_prefix('"') {
            quoted.find('"').map_or(trimmed.len(), |end| end + 2)
        } else {
            trimmed.find(char::is_whitespace).unwrap_or(trimmed.len())
        };
        let token = &trimmed[..len];
        tokens.push((at, token));
        at += len;
        if token == "macdef" {
            // The macro's name, then its body up to a blank line.
            let body = &text[at..];
            at += body.find("\n\n").map_or(body.len(), |end| end + 2);
            // Marks where the entry's text ends; the body is never read as tokens.
        }
    }
    tokens
}

/// `.netrc`: one entry for this host, in place of any there were. go and curl use
/// the first entry for a host, so adding a line after an old one would change
/// nothing. Every other host's entry stays, as do comments.
pub(super) fn netrc(existing: &str, host: &str, line: &str) -> String {
    let tokens = netrc_tokens(existing);
    let starts_entry = |token: &str| matches!(token, "machine" | "default" | "macdef");

    // The spans of this host's entries: from `machine host` to the next entry.
    let mut spans = Vec::new();
    for (i, (start, token)) in tokens.iter().enumerate() {
        if *token != "machine" || tokens.get(i + 1).map(|(_, name)| *name) != Some(host) {
            continue;
        }
        // To the end of its last field, so a comment after it stays.
        let fields = tokens[i + 2..]
            .iter()
            .take_while(|(_, token)| !starts_entry(token));
        let last = fields.last().map_or(&tokens[i + 1], |field| field);
        let mut end = last.0 + last.1.len();
        if existing[end..].starts_with("\r\n") {
            end += 2;
        } else if existing[end..].starts_with('\n') {
            end += 1;
        }
        spans.push((*start, end));
    }

    let mut text = String::with_capacity(existing.len() + line.len() + 1);
    let mut copied = 0;
    for (i, (start, end)) in spans.iter().enumerate() {
        text.push_str(&existing[copied..*start]);
        if i == 0 {
            text.push_str(line);
            text.push('\n');
        }
        copied = *end;
    }
    text.push_str(&existing[copied..]);
    if spans.is_empty() {
        // `default` matches every host, and whatever follows it is never read.
        let at = tokens
            .iter()
            .find(|(_, token)| *token == "default")
            .map_or(text.len(), |(start, _)| *start);
        let mut new = format!("{line}\n");
        if at > 0 && !text[..at].ends_with('\n') {
            new.insert(0, '\n');
        }
        text.insert_str(at, &new);
    }
    text
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
        let merged = pip_conf("", PIP_URL, None);
        assert_eq!(merged.text, format!("[global]\nindex-url = {PIP_URL}\n"));
        assert_eq!(
            pip_conf("", "http://ak.test/", Some("ak.test")).text,
            "[global]\nindex-url = http://ak.test/\ntrusted-host = ak.test\n"
        );
    }

    #[test]
    fn pip_keeps_other_keys_and_sections() {
        let existing = "# mine\n[global]\ntimeout = 30\nindex_url = https://corp.test/simple/\n\
                        extra-index-url = https://u:corp-secret@other.test/simple/\n\n\
                        [install]\nno-deps = true\n";
        let merged = pip_conf(existing, PIP_URL, None);
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
        let first = pip_conf("", PIP_URL, None).text;
        let second = pip_conf(&first, &PIP_URL.replace(":tok@", ":new@"), None);
        assert!(second.replaced.is_empty());
        assert!(second.text.contains(":new@"));
        assert!(!second.text.contains(":tok@"));
    }

    #[test]
    fn pip_adds_global_when_there_is_none_and_ignores_other_sections() {
        let existing = "[install]\nindex-url = https://theirs.test/\n";
        let text = pip_conf(existing, PIP_URL, None).text;
        assert_eq!(
            text,
            format!(
                "[install]\nindex-url = https://theirs.test/\n\n[global]\nindex-url = {PIP_URL}\n"
            )
        );
    }

    #[test]
    fn pip_replaces_a_value_that_spans_lines() {
        let existing = "[global]\nindex-url = https://a.test/\n    continued\ntimeout = 3\n";
        assert_eq!(
            pip_conf(existing, PIP_URL, None).text,
            format!("[global]\nindex-url = {PIP_URL}\ntimeout = 3\n")
        );
    }

    #[test]
    fn pip_adds_to_trusted_hosts_rather_than_replacing_them() {
        let existing = "[global]\ntrusted-host = a.test\n    b.test\ntimeout = 3\n";
        let once = pip_conf(existing, "http://ak.test/", Some("ak.test")).text;
        assert!(
            once.contains("trusted-host = a.test\n    b.test\n    ak.test\n"),
            "{once}"
        );
        let twice = pip_conf(&once, "http://ak.test/", Some("ak.test")).text;
        assert_eq!(once, twice);
    }

    const NETRC_LINE: &str = "machine ak.test login __token__ password new";

    #[test]
    fn netrc_from_nothing() {
        assert_eq!(netrc("", "ak.test", NETRC_LINE), format!("{NETRC_LINE}\n"));
    }

    #[test]
    fn netrc_replaces_only_this_hosts_entry() {
        let existing = "# mine\nmachine a.test login u password p1\n\
                        machine ak.test login __token__ password old\n\
                        machine b.test login v password p2\n";
        assert_eq!(
            netrc(existing, "ak.test", NETRC_LINE),
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
            netrc(existing, "ak.test", NETRC_LINE),
            format!("{NETRC_LINE}\nmachine b.test login v password p\n")
        );
    }

    #[test]
    fn netrc_handles_entries_sharing_a_line() {
        let existing = "machine a.test login u password p machine ak.test login x password old machine b.test login v password q\n";
        let text = netrc(existing, "ak.test", NETRC_LINE);
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
            netrc(existing, "ak.test", NETRC_LINE),
            format!("{NETRC_LINE}\n# about b\nmachine b.test login v password p\n")
        );
    }

    #[test]
    fn netrc_goes_before_a_default_entry_which_ends_the_search() {
        let existing = "machine a.test login u password p\ndefault login d password dd\n";
        assert_eq!(
            netrc(existing, "ak.test", NETRC_LINE),
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
        let text = netrc(existing, "ak.test", NETRC_LINE);
        assert!(text.contains("password comment"), "{text}");
        assert!(text.contains("password macro"), "{text}");
        assert!(text.ends_with(&format!("{NETRC_LINE}\n")), "{text}");
    }

    #[test]
    fn netrc_only_matches_the_whole_host() {
        let existing =
            "machine ak.test:8443 login u password p\nmachine xak.test login v password q\n";
        let text = netrc(existing, "ak.test", NETRC_LINE);
        assert!(text.starts_with(existing), "{text}");
        assert!(text.contains(NETRC_LINE), "{text}");
    }

    #[test]
    fn netrc_a_last_line_with_no_ending() {
        assert_eq!(
            netrc("machine a.test login u password p", "ak.test", NETRC_LINE),
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
