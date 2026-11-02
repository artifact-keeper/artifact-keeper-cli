//! `ak setup` handles the user's token for every package manager. This asserts
//! that the token reaches the config file or the child's stdin and never stdout,
//! stderr or another process's argv.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SENTINEL: &str = "sentinel-token-3f9a7c1e5b2d4860-do-not-print";

const SUBCOMMANDS: &[&str] = &[
    "npm", "pip", "cargo", "docker", "maven", "gradle", "go", "helm", "nuget", "yum", "apt",
];

struct Sandbox {
    _server: MockServer,
    dir: TempDir,
}

impl Sandbox {
    async fn new(list_status: u16) -> Self {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/repositories"))
            .respond_with(ResponseTemplate::new(list_status).set_body_json(json!({
                // The shape 1.11.10 returns, so the SDK's strict parsing accepts it.
                "items": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "key": "the-repo",
                    "name": "the-repo",
                    "format": "generic",
                    "repo_type": "local",
                    "visibility": "private",
                    "is_public": false,
                    "allow_anonymous_access": false,
                    "promotion_only": false,
                    "versioning_enabled": false,
                    "repodata_depth": 0,
                    "repodata_depth_editable": false,
                    "storage_backend": "filesystem",
                    "storage_used_bytes": 0,
                    "has_trusted_gpg_key": false,
                    "upstream_url_has_credentials": false,
                    "upstream_auth_configured": false,
                    "public_with_upstream_credentials": false,
                    "allow_public_with_upstream_credentials": false,
                    "curation_enabled": false,
                    "curation_default_action": "allow",
                    "created_at": "2026-01-15T12:00:00Z",
                    "updated_at": "2026-01-15T12:00:00Z"
                }],
                "pagination": {"page": 1, "per_page": 100, "total": 1, "total_pages": 1}
            })))
            .mount(&server)
            .await;

        let dir = TempDir::new().expect("temp dir");
        for sub in ["ak", "bin", "home", "work"] {
            std::fs::create_dir(dir.path().join(sub)).expect("mkdir");
        }
        std::fs::write(
            dir.path().join("ak/config.toml"),
            format!(
                "default_instance = \"t\"\n[instances.t]\nurl = \"{}\"\napi_version = \"v1\"\n",
                server.uri()
            ),
        )
        .expect("write config");
        Self {
            _server: server,
            dir,
        }
    }

    /// Put a program on PATH that records its argv and stdin, then exits `code`.
    fn stub(&self, name: &str, code: i32) {
        let bin = self.dir.path().join("bin");
        let script = bin.join(name);
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{0}/{1}.argv'\n/bin/cat >> '{0}/{1}.stdin'\nexit {2}\n",
                bin.display(),
                name,
                code
            ),
        )
        .expect("write stub");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("chmod stub");
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::cargo_bin("ak")
            .expect("ak binary")
            .env_clear()
            .env("PATH", self.path("bin"))
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("home/.config"))
            .env("CARGO_HOME", self.path("home/.cargo"))
            .env("AK_CONFIG_DIR", self.path("ak"))
            .env("AK_TOKEN", SENTINEL)
            .env("AK_CREDENTIAL_STORE", "file")
            .current_dir(self.path("work"))
            .args(["--no-input", "setup"])
            .args(args)
            .output()
            .expect("run ak")
    }
}

/// The assertion messages name the stream, not its content: on a failure the
/// content is exactly what mustn't reach a CI log, even for a test token.
fn assert_output_clean(output: &Output, what: &str) {
    for (name, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        let text = String::from_utf8_lossy(bytes);
        assert!(
            !text.contains(SENTINEL),
            "{what}: the token appears in {name}"
        );
        // A partial mask is still a leak.
        assert!(
            !text.contains(&SENTINEL[..12]) && !text.contains(&SENTINEL[SENTINEL.len() - 12..]),
            "{what}: part of the token appears in {name}"
        );
    }
}

fn assert_never_in_argv(sandbox: &Sandbox, program: &str, what: &str) {
    let argv = sandbox.path(&format!("bin/{program}.argv"));
    if let Ok(recorded) = std::fs::read_to_string(argv) {
        assert!(
            !recorded.contains(SENTINEL),
            "{what}: the token was passed to {program} on its command line"
        );
    }
}

fn read_stdin(sandbox: &Sandbox, program: &str) -> String {
    std::fs::read_to_string(sandbox.path(&format!("bin/{program}.stdin"))).unwrap_or_default()
}

fn assert_private_with_token(path: &Path, what: &str) {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{what}: can't read {}: {e}", path.display()));
    assert!(
        content.contains(SENTINEL),
        "{what}: token missing from file"
    );
    let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{what}: {} is {mode:o}", path.display());
}

#[tokio::test]
async fn no_subcommand_prints_the_token() {
    for sub in SUBCOMMANDS {
        let sandbox = Sandbox::new(200).await;
        sandbox.stub("docker", 0);
        sandbox.stub("helm", 0);
        sandbox.stub("sudo", 0);

        let explicit = sandbox.run(&[sub, "--repo", "the-repo"]);
        assert_output_clean(&explicit, &format!("setup {sub} --repo"));
        assert_eq!(explicit.status.code(), Some(0), "setup {sub} --repo");

        let detected = sandbox.run(&[sub]);
        assert_output_clean(&detected, &format!("setup {sub}"));
        assert_eq!(detected.status.code(), Some(0), "setup {sub}");

        for program in ["docker", "helm", "sudo"] {
            assert_never_in_argv(&sandbox, program, &format!("setup {sub}"));
        }
    }
}

#[tokio::test]
async fn a_failing_child_does_not_print_the_token() {
    for sub in ["docker", "helm"] {
        let sandbox = Sandbox::new(200).await;
        sandbox.stub(sub, 1);
        let output = sandbox.run(&[sub, "--repo", "the-repo"]);
        assert_output_clean(&output, &format!("setup {sub} with a failing client"));
        assert!(!output.status.success());
    }
}

#[tokio::test]
async fn a_missing_client_does_not_print_the_token() {
    for sub in ["docker", "helm"] {
        let sandbox = Sandbox::new(200).await;
        let output = sandbox.run(&[sub, "--repo", "the-repo"]);
        assert_output_clean(&output, &format!("setup {sub} with no client installed"));
        assert!(!output.status.success());
    }
}

#[tokio::test]
async fn a_server_error_does_not_print_the_token() {
    for sub in SUBCOMMANDS {
        let sandbox = Sandbox::new(500).await;
        let output = sandbox.run(&[sub]);
        assert_output_clean(&output, &format!("setup {sub} against a failing server"));
        assert!(!output.status.success());
    }
}

#[tokio::test]
async fn auto_does_not_print_the_token() {
    let sandbox = Sandbox::new(200).await;
    sandbox.stub("docker", 0);
    sandbox.stub("helm", 0);
    for marker in [
        "package.json",
        "pyproject.toml",
        "Cargo.toml",
        "Dockerfile",
        "pom.xml",
        "build.gradle",
        "go.mod",
        "app.csproj",
        "Chart.yaml",
    ] {
        std::fs::write(sandbox.path("work").join(marker), "").expect("write marker");
    }
    let output = sandbox.run(&["auto"]);
    assert_output_clean(&output, "setup auto");
    assert_eq!(output.status.code(), Some(0), "setup auto");
    assert_never_in_argv(&sandbox, "docker", "setup auto");
    assert_never_in_argv(&sandbox, "helm", "setup auto");
}

#[tokio::test]
async fn the_token_goes_where_it_is_needed_and_stays_private() {
    let sandbox = Sandbox::new(200).await;
    sandbox.stub("docker", 0);
    sandbox.stub("helm", 0);
    for sub in SUBCOMMANDS {
        let output = sandbox.run(&[sub, "--repo", "the-repo"]);
        assert_eq!(output.status.code(), Some(0), "setup {sub}");
    }

    for (file, what) in [
        ("home/.npmrc", "npm"),
        ("home/.config/pip/pip.conf", "pip"),
        ("home/.cargo/credentials.toml", "cargo"),
        ("home/.m2/settings.xml", "maven"),
        ("home/.gradle/init.d/artifact-keeper.gradle", "gradle"),
        ("home/.nuget/NuGet/NuGet.Config", "nuget"),
    ] {
        assert_private_with_token(&sandbox.path(file), what);
    }
    assert_eq!(read_stdin(&sandbox, "docker"), SENTINEL);
    assert_eq!(read_stdin(&sandbox, "helm"), SENTINEL);
}
