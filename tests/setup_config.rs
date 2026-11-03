//! What `ak setup` writes: URLs built from the routes the server really has,
//! and a credential that outlives the login. A real 1.11.10 backend and the real
//! clients checked these URLs; this keeps them from drifting.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::Output;

use assert_cmd::Command;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MINTED: &str = "minted-api-token-7c1e5b2d";

fn jwt_expiring_in(seconds: i64) -> String {
    let exp = chrono::Utc::now().timestamp() + seconds;
    let payload = URL_SAFE_NO_PAD.encode(json!({"exp": exp, "sub": "alice"}).to_string());
    format!("header.{payload}.sentinelsignature")
}

struct Sandbox {
    dir: TempDir,
    server: MockServer,
}

impl Sandbox {
    /// `url` overrides the instance URL when a test only looks at what's written.
    async fn new(url: Option<&str>) -> Self {
        let server = MockServer::start().await;
        let dir = TempDir::new().expect("temp dir");
        for sub in ["ak", "bin", "home"] {
            std::fs::create_dir(dir.path().join(sub)).expect("mkdir");
        }
        let url = url.map_or_else(|| server.uri(), str::to_string);
        std::fs::write(
            dir.path().join("ak/config.toml"),
            format!(
                "default_instance = \"t\"\n[instances.t]\nurl = \"{url}\"\napi_version = \"v1\"\nallow_insecure_http = true\n"
            ),
        )
        .expect("write config");
        Self { dir, server }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.path(rel)).unwrap_or_else(|e| panic!("can't read {rel}: {e}"))
    }

    fn run(&self, token: &str, args: &[&str]) -> Output {
        Command::cargo_bin("ak")
            .expect("ak binary")
            .env_clear()
            .env("PATH", self.path("bin"))
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("home/.config"))
            .env("CARGO_HOME", self.path("home/.cargo"))
            .env("AK_CONFIG_DIR", self.path("ak"))
            .env("AK_TOKEN", token)
            .env("AK_CREDENTIAL_STORE", "file")
            .current_dir(self.path("home"))
            .args(["--no-input", "setup"])
            .args(args)
            .output()
            .expect("run ak")
    }

    async fn mint_ok(&self) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/tokens"))
            .and(body_partial_json(json!({
                "name": "ak-setup-pip-r",
                "scopes": ["read:artifacts", "write:artifacts"],
                "expires_in_days": 90
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000007",
                "name": "ak-setup-pip-r",
                "token": MINTED,
                "expires_at": "2027-01-31T00:00:00Z",
                "policy_applied": false
            })))
            .expect(1)
            .mount(&self.server)
            .await;
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[tokio::test]
async fn config_files_point_at_the_servers_real_routes() {
    let sandbox = Sandbox::new(Some("http://ak.test:8080")).await;
    let token = "api-token-not-a-jwt";
    for sub in ["npm", "pip", "cargo", "maven", "gradle", "nuget"] {
        let output = sandbox.run(token, &[sub, "--repo", "r"]);
        assert_eq!(output.status.code(), Some(0), "setup {sub}");
    }

    let npmrc = sandbox.read("home/.npmrc");
    assert!(npmrc.contains("registry=http://ak.test:8080/npm/r/\n"));
    assert!(npmrc.contains("//ak.test:8080/npm/r/:_authToken=api-token-not-a-jwt\n"));

    let pip = sandbox.read("home/.config/pip/pip.conf");
    assert!(pip.contains(
        "index-url = http://__token__:api-token-not-a-jwt@ak.test:8080/pypi/r/simple/\n"
    ));
    assert!(pip.contains("trusted-host = ak.test:8080\n"));

    let cargo = sandbox.read("home/.cargo/config.toml");
    assert!(cargo.contains("index = \"sparse+http://ak.test:8080/cargo/r/\""));
    assert!(cargo.contains("global-credential-providers = [\"cargo:token\"]"));

    let maven = sandbox.read("home/.m2/settings.xml");
    assert!(maven.contains("<url>http://ak.test:8080/maven/r/</url>"));

    let gradle = sandbox.read("home/.gradle/init.d/artifact-keeper.gradle");
    assert!(gradle.contains("url = uri(\"http://ak.test:8080/maven/r/\")"));
    assert!(gradle.contains("allowInsecureProtocol = true"));

    let nuget = sandbox.read("home/.nuget/NuGet/NuGet.Config");
    assert!(nuget.contains("value=\"http://ak.test:8080/nuget/r/v3/index.json\""));
    assert!(nuget.contains("allowInsecureConnections=\"true\""));
}

#[tokio::test]
async fn https_instances_stay_https_with_no_insecure_settings() {
    let sandbox = Sandbox::new(Some("https://ak.test:8443")).await;
    let token = "api-token-not-a-jwt";
    for sub in ["pip", "gradle", "nuget"] {
        let output = sandbox.run(token, &[sub, "--repo", "r"]);
        assert_eq!(output.status.code(), Some(0), "setup {sub}");
    }
    let pip = sandbox.read("home/.config/pip/pip.conf");
    assert!(pip.contains("https://__token__:api-token-not-a-jwt@ak.test:8443/pypi/r/simple/"));
    assert!(!pip.contains("trusted-host"));
    assert!(
        !sandbox
            .read("home/.gradle/init.d/artifact-keeper.gradle")
            .contains("allowInsecure")
    );
    assert!(
        !sandbox
            .read("home/.nuget/NuGet/NuGet.Config")
            .contains("allowInsecure")
    );
}

#[tokio::test]
async fn printed_instructions_use_the_real_routes() {
    let sandbox = Sandbox::new(Some("http://ak.test:8080")).await;
    let token = "api-token-not-a-jwt";

    let yum = stderr(&sandbox.run(token, &["yum", "--repo", "r"]));
    assert!(yum.contains("baseurl=http://ak.test:8080/rpm/r/"), "{yum}");

    let apt = stderr(&sandbox.run(token, &["apt", "--repo", "r"]));
    assert!(
        apt.contains("deb [trusted=yes] http://ak.test:8080/debian/r/ stable main"),
        "{apt}"
    );
    assert!(apt.contains("machine http://ak.test:8080\n"), "{apt}");

    let go = stderr(&sandbox.run(token, &["go", "--repo", "r"]));
    assert!(
        go.contains("GOPROXY=\"http://ak.test:8080/go/r/,direct\""),
        "{go}"
    );
    assert!(go.contains("only sends credentials over HTTPS"), "{go}");
    assert!(!go.contains("machine "), "{go}");
    assert!(!go.contains("GONOSUMCHECK"), "{go}");

    let sandbox = Sandbox::new(Some("https://ak.test:8443")).await;
    let go = stderr(&sandbox.run(token, &["go", "--repo", "r"]));
    assert!(
        go.contains("machine ak.test:8443 login __token__ password ****"),
        "{go}"
    );
}

#[tokio::test]
async fn docker_logs_in_to_host_and_port() {
    let sandbox = Sandbox::new(Some("http://ak.test:8080")).await;
    let script = sandbox.path("bin/docker");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > '{}'\n/bin/cat > /dev/null\n",
            sandbox.path("docker.argv").display()
        ),
    )
    .expect("write stub");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let output = sandbox.run("api-token-not-a-jwt", &["docker", "--repo", "r"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        sandbox.read("docker.argv"),
        "login ak.test:8080 -u __token__ --password-stdin\n"
    );
}

#[tokio::test]
async fn a_login_token_is_swapped_for_an_api_token() {
    let sandbox = Sandbox::new(None).await;
    sandbox.mint_ok().await;
    let session = jwt_expiring_in(1800);

    let output = sandbox.run(&session, &["pip", "--repo", "r"]);
    assert_eq!(output.status.code(), Some(0));

    let pip = sandbox.read("home/.config/pip/pip.conf");
    assert!(pip.contains(MINTED), "the config should use the new token");
    assert!(
        !pip.contains(&session),
        "the login token must not be written"
    );

    let err = stderr(&output);
    assert!(
        err.contains("ak-setup-pip-r"),
        "the new token should be named"
    );
    assert!(
        err.contains("ak auth revoke-token 00000000-0000-0000-0000-000000000007"),
        "the user should be told how to revoke it"
    );
    for out in [&err, &String::from_utf8_lossy(&output.stdout).into_owned()] {
        assert!(!out.contains(MINTED), "the new token was printed");
        assert!(!out.contains(&session), "the login token was printed");
    }
}

#[tokio::test]
async fn no_file_writer_keeps_the_login_token() {
    let session = jwt_expiring_in(1800);
    for (sub, file) in [
        ("npm", "home/.npmrc"),
        ("pip", "home/.config/pip/pip.conf"),
        ("cargo", "home/.cargo/credentials.toml"),
        ("maven", "home/.m2/settings.xml"),
        ("gradle", "home/.gradle/init.d/artifact-keeper.gradle"),
        ("nuget", "home/.nuget/NuGet/NuGet.Config"),
    ] {
        let sandbox = Sandbox::new(None).await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000007",
                "name": "n",
                "token": MINTED,
                "policy_applied": false
            })))
            .expect(1)
            .mount(&sandbox.server)
            .await;
        let output = sandbox.run(&session, &[sub, "--repo", "r"]);
        assert_eq!(output.status.code(), Some(0), "setup {sub}");
        let written = sandbox.read(file);
        assert!(
            written.contains(MINTED),
            "setup {sub}: new token not in {file}"
        );
        assert!(
            !written.contains(&session),
            "setup {sub}: login token in {file}"
        );
    }
}

#[tokio::test]
async fn token_days_sets_the_lifetime() {
    let sandbox = Sandbox::new(None).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/tokens"))
        .and(body_partial_json(json!({"expires_in_days": 7})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "00000000-0000-0000-0000-000000000007",
            "name": "n",
            "token": MINTED,
            "policy_applied": false
        })))
        .expect(1)
        .mount(&sandbox.server)
        .await;

    let output = sandbox.run(
        &jwt_expiring_in(1800),
        &["pip", "--repo", "r", "--token-days", "7"],
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(sandbox.read("home/.config/pip/pip.conf").contains(MINTED));
}

#[tokio::test]
async fn session_token_flag_keeps_the_login_token_and_warns() {
    let sandbox = Sandbox::new(None).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/tokens"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&sandbox.server)
        .await;
    let session = jwt_expiring_in(1800);

    let output = sandbox.run(&session, &["pip", "--repo", "r", "--session-token"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(sandbox.read("home/.config/pip/pip.conf").contains(&session));
    let err = stderr(&output);
    assert!(err.contains("expires in about"), "{}", err.len());
    assert!(!err.contains(&session), "the login token was printed");
}

#[tokio::test]
async fn a_refused_mint_fails_and_writes_nothing() {
    let sandbox = Sandbox::new(None).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/tokens"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"message": "policy says no"})),
        )
        .mount(&sandbox.server)
        .await;
    let session = jwt_expiring_in(1800);

    for (tool, file) in [
        ("pip", "home/.config/pip/pip.conf"),
        ("npm", "home/.npmrc"),
        ("maven", "home/.m2/settings.xml"),
    ] {
        let output = sandbox.run(&session, &[tool, "--repo", "r"]);
        assert_eq!(output.status.code(), Some(1), "setup {tool}");
        assert!(!sandbox.path(file).exists(), "setup {tool} wrote {file}");
        let err = stderr(&output);
        assert!(
            err.contains("policy says no"),
            "the server's reason is missing"
        );
        assert!(err.contains("--session-token"), "the way out is missing");
        assert!(!err.contains(&session), "the login token was printed");
    }
}

/// Cargo's setup writes two files. The first must not be replaced when there's
/// no token for the second: that would lose what was in it, for nothing.
#[tokio::test]
async fn a_refused_mint_leaves_existing_cargo_files_alone() {
    let sandbox = Sandbox::new(None).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/tokens"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&sandbox.server)
        .await;
    let existing = "[registries.other]\nindex = \"sparse+https://other.test/\"\n";
    std::fs::create_dir_all(sandbox.path("home/.cargo")).unwrap();
    std::fs::write(sandbox.path("home/.cargo/config.toml"), existing).unwrap();

    let output = sandbox.run(&jwt_expiring_in(1800), &["cargo", "--repo", "r"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(sandbox.read("home/.cargo/config.toml"), existing);
    assert!(!sandbox.path("home/.cargo/config.bak").exists());
    assert!(!sandbox.path("home/.cargo/credentials.toml").exists());
}

/// What a user had before `setup` must still be somewhere after any number of
/// runs: a second run used to overwrite the backup with `setup`'s own file.
#[tokio::test]
async fn running_setup_twice_keeps_the_original_in_a_backup() {
    let sandbox = Sandbox::new(None).await;
    for (tool, file) in [
        ("npm", "home/.npmrc"),
        ("pip", "home/.config/pip/pip.conf"),
        ("cargo", "home/.cargo/config.toml"),
        ("cargo", "home/.cargo/credentials.toml"),
        ("maven", "home/.m2/settings.xml"),
        ("gradle", "home/.gradle/init.d/artifact-keeper.gradle"),
    ] {
        let original = format!("original of {file}\n");
        std::fs::create_dir_all(sandbox.path(file).parent().unwrap()).unwrap();
        std::fs::write(sandbox.path(file), &original).unwrap();

        // Two tokens, so the second run also replaces something different.
        for token in ["lasting-token-one", "lasting-token-two"] {
            let output = sandbox.run(token, &[tool, "--repo", "r"]);
            assert_eq!(output.status.code(), Some(0), "setup {tool}");
        }

        let dir = sandbox.path(file).parent().unwrap().to_path_buf();
        let survived = std::fs::read_dir(&dir).unwrap().any(|entry| {
            let path = entry.unwrap().path();
            path != sandbox.path(file)
                && std::fs::read_to_string(&path).is_ok_and(|text| text == original)
        });
        assert!(survived, "the original of {file} is gone");
    }
}

#[tokio::test]
async fn a_lasting_token_is_used_as_it_is() {
    let sandbox = Sandbox::new(None).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/tokens"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&sandbox.server)
        .await;

    for token in [
        "lasting-api-token".to_string(),
        jwt_expiring_in(30 * 86_400),
    ] {
        let output = sandbox.run(&token, &["pip", "--repo", "r"]);
        assert_eq!(output.status.code(), Some(0));
        assert!(sandbox.read("home/.config/pip/pip.conf").contains(&token));
    }
}

#[tokio::test]
async fn printing_instructions_creates_no_token() {
    let sandbox = Sandbox::new(None).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/tokens"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&sandbox.server)
        .await;
    let session = jwt_expiring_in(1800);
    for sub in ["go", "yum", "apt"] {
        let output = sandbox.run(&session, &[sub, "--repo", "r"]);
        assert_eq!(output.status.code(), Some(0), "setup {sub}");
    }
}
