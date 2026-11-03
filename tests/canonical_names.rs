//! Each command has one name in help, and its old names still work. Against a mock
//! server, so a contract, not E2E.

use assert_cmd::Command;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ak(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("ak").expect("ak binary");
    cmd.env("AK_CONFIG_DIR", dir.path())
        .env("AK_TOKEN", "unused")
        .env("AK_CREDENTIAL_STORE", "file")
        .env_remove("AK_INSTANCE")
        .args(["--no-input", "--format", "json"]);
    cmd
}

/// A server that answers every request with the path it was asked for.
async fn echoing() -> (MockServer, TempDir) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(".*"))
        .respond_with(|request: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_json(json!({"asked": request.url.path()}))
        })
        .mount(&server)
        .await;
    let dir = TempDir::new().expect("temp dir");
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "default_instance = \"t\"\n[instances.t]\nurl = \"{}\"\n",
            server.uri()
        ),
    )
    .expect("write config");
    (server, dir)
}

fn help(args: &[&str]) -> String {
    let dir = TempDir::new().expect("temp dir");
    let output = ak(&dir).args(args).arg("--help").output().expect("run ak");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Whether a help text lists this command.
fn lists(help: &str, name: &str) -> bool {
    help.lines()
        .any(|line| line.trim_start().starts_with(&format!("{name} ")))
}

#[test]
fn old_names_are_hidden_and_new_names_are_shown() {
    let root = help(&[]);
    assert!(lists(&root, "catalog"), "{root}");
    assert!(!lists(&root, "packages"), "{root}");

    let artifact = help(&["artifact"]);
    assert!(lists(&artifact, "show"), "{artifact}");
    assert!(!lists(&artifact, "info"), "{artifact}");

    let admin = help(&["admin"]);
    assert!(lists(&admin, "stats"), "{admin}");
    assert!(!lists(&admin, "metrics"), "{admin}");

    let system = help(&["system"]);
    assert!(!lists(&system, "health"), "{system}");
    assert!(lists(&help(&["monitoring"]), "health"));

    let profile = help(&["profile"]);
    assert!(!lists(&profile, "show"), "{profile}");
    assert!(!lists(&profile, "tokens"), "{profile}");
    assert!(lists(&profile, "access-tokens"), "{profile}");

    let auth = help(&["auth"]);
    assert!(!lists(&auth, "revoke-token"), "{auth}");
    assert!(lists(&help(&["auth", "token"]), "revoke"));
}

#[tokio::test]
async fn an_old_name_asks_the_server_what_the_new_name_does() {
    let (_server, dir) = echoing().await;
    for (old, new) in [
        (&["admin", "metrics"][..], &["admin", "stats"][..]),
        (&["catalog", "list"], &["packages", "list"]),
    ] {
        let (old_out, new_out) = (
            ak(&dir).args(old).output().unwrap(),
            ak(&dir).args(new).output().unwrap(),
        );
        assert_eq!(old_out.stdout, new_out.stdout, "{old:?} and {new:?}");
    }
}

#[test]
fn version_is_on_the_root_alone() {
    let dir = TempDir::new().expect("temp dir");
    assert!(ak(&dir).arg("--version").output().unwrap().status.success());
    assert!(ak(&dir).arg("-V").output().unwrap().status.success());
    let output = ak(&dir).args(["repo", "--version"]).output().unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let output = ak(&dir)
        .args(["artifact", "pull", "r", "p", "--version", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}
