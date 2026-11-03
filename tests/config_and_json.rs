//! Where the output format and color come from, and that JSON keeps the server's key
//! order. Against a mock server, so a contract, not E2E: `e2e_config` has the same on
//! a real server.

use std::process::Output;

use assert_cmd::Command;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A valid `/health` body, with keys deliberately not in alphabetical order, at both
/// levels.
const BODY: &str = r#"{"version":"1.11.11","status":"healthy","demo_mode":false,"checks":{"storage":{"status":"healthy"},"database":{"status":"healthy"}}}"#;

struct Rig {
    server: MockServer,
    dir: TempDir,
}

impl Rig {
    async fn new(settings: &str) -> Self {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(BODY.as_bytes(), "application/json"),
            )
            .mount(&server)
            .await;
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "default_instance = \"t\"\n{settings}\n[instances.t]\nurl = \"{}\"\n",
                server.uri()
            ),
        )
        .unwrap();
        Self { server, dir }
    }

    fn ak(&self, envs: &[(&str, &str)], args: &[&str]) -> Output {
        Command::cargo_bin("ak")
            .unwrap()
            .env("AK_CONFIG_DIR", self.dir.path())
            .env("AK_TOKEN", "unused")
            .env("AK_CREDENTIAL_STORE", "file")
            .env_remove("AK_FORMAT")
            .env_remove("AK_COLOR")
            .env_remove("NO_COLOR")
            .env_remove("CLICOLOR_FORCE")
            .env_remove("AK_INSTANCE")
            .envs(envs.iter().copied())
            .args(args)
            .output()
            .unwrap()
    }

    /// The first non-space character on stdout says which format this was.
    fn format_of(&self, envs: &[(&str, &str)], args: &[&str]) -> String {
        let output = self.ak(envs, args);
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(output.status.success(), "{output:?}");
        text
    }
}

/// `config list` needs no server, and shows which format it was given.
const LIST: &[&str] = &["config", "list"];

fn is_json(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text.trim()).is_ok_and(|value| !value.is_string())
}

#[tokio::test]
async fn the_order_is_flag_then_env_then_config_then_default() {
    let yaml = Rig::new("output_format = \"yaml\"").await;

    let config = yaml.format_of(&[], LIST);
    assert!(!is_json(&config), "the config file says yaml: {config}");

    let env = yaml.format_of(&[("AK_FORMAT", "json")], LIST);
    assert!(is_json(&env), "AK_FORMAT beats the config: {env}");

    let flag = yaml.format_of(
        &[("AK_FORMAT", "yaml")],
        &["--format", "json", "config", "list"],
    );
    assert!(is_json(&flag), "--format beats AK_FORMAT: {flag}");

    let quiet = yaml.format_of(&[], &["-q", "config", "list"]);
    assert!(
        quiet.contains("output_format=yaml"),
        "-q beats the config: {quiet}"
    );

    let quiet_config = Rig::new("output_format = \"quiet\"").await;
    let text = quiet_config.format_of(&[], LIST);
    assert!(text.contains("output_format=quiet"), "{text}");

    let json = Rig::new("output_format = \"json\"").await;
    let text = json.format_of(&[("AK_FORMAT", "table")], LIST);
    assert!(
        !is_json(&text),
        "an explicit table stays one on a pipe: {text}"
    );
}

/// What a saved config file holds unless someone changed it, so auto-detection stays.
#[tokio::test]
async fn table_in_the_config_is_still_json_on_a_pipe() {
    let rig = Rig::new("output_format = \"table\"").await;
    let text = rig.format_of(&[], LIST);
    assert!(is_json(&text), "{text}");
}

#[tokio::test]
async fn a_config_file_that_says_json_gives_json_and_set_writes_it() {
    let rig = Rig::new("").await;
    let output = rig.ak(&[], &["config", "set", "output_format", "yaml"]);
    assert!(output.status.success(), "{output:?}");
    let saved = std::fs::read_to_string(rig.dir.path().join("config.toml")).unwrap();
    assert!(saved.contains("output_format = \"yaml\""), "{saved}");
}

/// Escape codes on stderr, from `ak doctor`, with no instances to reach. CLICOLOR_FORCE
/// stands in for a terminal.
fn doctor_is_colored(settings: &str, envs: &[(&str, &str)], args: &[&str]) -> bool {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("config.toml"), settings).unwrap();
    let output = Command::cargo_bin("ak")
        .unwrap()
        .env("AK_CONFIG_DIR", dir.path())
        .env("AK_CREDENTIAL_STORE", "file")
        .env_remove("AK_FORMAT")
        .env_remove("AK_COLOR")
        .env_remove("NO_COLOR")
        .env_remove("AK_INSTANCE")
        .envs(envs.iter().copied())
        .args(args)
        .arg("doctor")
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stderr).contains('\u{1b}')
}

#[test]
fn color_follows_flag_then_env_then_config() {
    let force = ("CLICOLOR_FORCE", "1");
    assert!(
        doctor_is_colored("", &[force], &[]),
        "forced on as a baseline"
    );

    assert!(!doctor_is_colored("color = \"never\"\n", &[force], &[]));
    assert!(doctor_is_colored("color = \"always\"\n", &[], &[]));

    assert!(doctor_is_colored(
        "color = \"never\"\n",
        &[("AK_COLOR", "always")],
        &[]
    ));
    assert!(!doctor_is_colored(
        "color = \"always\"\n",
        &[("AK_COLOR", "never")],
        &[]
    ));

    assert!(doctor_is_colored(
        "color = \"never\"\n",
        &[("AK_COLOR", "never")],
        &["--color", "always"]
    ));
    assert!(!doctor_is_colored(
        "color = \"always\"\n",
        &[("NO_COLOR", "1")],
        &[]
    ));
    assert!(doctor_is_colored(
        "",
        &[("NO_COLOR", "1")],
        &["--color", "always"]
    ));
}

#[tokio::test]
async fn yaml_keeps_the_servers_key_order() {
    let rig = Rig::new("").await;
    let text = rig.format_of(&[], &["--format", "yaml", "monitoring", "health"]);
    let (version, status) = (text.find("version").unwrap(), text.find("status").unwrap());
    assert!(version < status, "{text}");
}

/// Run under a pseudo-terminal with util-linux `script`, or None where it's missing.
#[cfg(target_os = "linux")]
fn on_a_terminal(rig: &Rig, args: &str) -> Option<String> {
    let ak = assert_cmd::cargo::cargo_bin("ak");
    let command = format!("{} {args}", ak.display());
    let output = std::process::Command::new("script")
        .args(["-qec", &command, "/dev/null"])
        .env("AK_CONFIG_DIR", rig.dir.path())
        .env("AK_TOKEN", "unused")
        .env("AK_CREDENTIAL_STORE", "file")
        .env("NO_COLOR", "1")
        .env_remove("AK_FORMAT")
        .env_remove("AK_INSTANCE")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n");
    assert!(output.status.success(), "{args}: {text}");
    Some(text)
}

#[cfg(target_os = "linux")]
fn assert_server_order_and_pretty(text: &str) {
    assert!(text.contains("  \"version\": "), "not pretty: {text:?}");
    let at = |key: &str| {
        text.find(key)
            .unwrap_or_else(|| panic!("no {key}: {text:?}"))
    };
    assert!(at("\"version\"") < at("\"status\""), "sorted: {text:?}");
    assert!(
        at("\"storage\"") < at("\"database\""),
        "nested keys sorted: {text:?}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn on_a_terminal_ak_api_is_pretty_in_server_order_with_a_newline() {
    let rig = Rig::new("").await;
    let Some(text) = on_a_terminal(&rig, "api GET /health") else {
        eprintln!("skipped: no script(1) here");
        return;
    };
    assert_server_order_and_pretty(&text);
    assert!(text.ends_with("}\n"), "{text:?}");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn on_a_terminal_a_commands_json_is_in_server_order() {
    let rig = Rig::new("").await;
    let Some(text) = on_a_terminal(&rig, "--format json monitoring health") else {
        eprintln!("skipped: no script(1) here");
        return;
    };
    assert_server_order_and_pretty(&text);
}

#[tokio::test]
async fn on_a_pipe_ak_api_is_the_bytes_as_received() {
    let rig = Rig::new("").await;
    let output = rig.ak(&[], &["api", "GET", "/health"]);
    assert_eq!(output.stdout, BODY.as_bytes());
}
