use assert_cmd::Command;
use std::sync::{Once, OnceLock};
use std::time::Duration;

static INIT: Once = Once::new();

/// Cached auth token, shared across all tests in a binary.
static AUTH_TOKEN: OnceLock<String> = OnceLock::new();

/// Backend URL for E2E tests. Set via E2E_BACKEND_URL env var,
/// defaults to the Docker Compose stack port.
pub fn backend_url() -> String {
    std::env::var("E2E_BACKEND_URL").unwrap_or_else(|_| "http://localhost:8081".to_string())
}

/// Ensure backend is reachable. Called once per test binary.
pub fn ensure_backend() {
    INIT.call_once(|| {
        let url = format!("{}/health", backend_url());
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build HTTP client");

        let resp = client.get(&url).send();
        if resp.is_err() || !resp.unwrap().status().is_success() {
            panic!(
                "E2E backend not reachable at {}. Run tests/start-backend.sh first.",
                backend_url()
            );
        }
    });
}

/// The version the backend under test reports. The E2E tests also run against
/// the oldest supported server, so a test of something newer can ask for this.
#[allow(dead_code)]
pub fn server_version() -> String {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            ensure_backend();
            let health: serde_json::Value =
                reqwest::blocking::get(format!("{}/health", backend_url()))
                    .expect("Failed to read /health")
                    .json()
                    .expect("/health isn't JSON");
            health["version"]
                .as_str()
                .expect("/health has no version")
                .to_string()
        })
        .clone()
}

/// Whether the backend's minor is older than `major.minor`. A test that returns
/// early on this says so, so that a skip shows in the log with --nocapture.
#[allow(dead_code)]
pub fn server_older_than(major: u64, minor: u64, what: &str) -> bool {
    let version = server_version();
    let mut parts = version.split('.').map(|part| part.parse::<u64>().unwrap());
    let found = (parts.next().unwrap(), parts.next().unwrap());
    let older = found < (major, minor);
    if older {
        eprintln!("Skipping: server {version} has no {what}");
    }
    older
}

/// Ask until `ready` gives a value, for what the server finishes after it has answered,
/// such as recording a proxied download in its catalog. Panics after 30 seconds, naming
/// what it was waiting for.
#[allow(dead_code)]
pub fn wait_until<T>(what: &str, mut ready: impl FnMut() -> Option<T>) -> T {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(value) = ready() {
            return value;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "gave up waiting for {what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Login as admin and cache the token. Called once per test binary.
fn get_auth_token() -> &'static str {
    AUTH_TOKEN.get_or_init(|| {
        let url = backend_url();
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(format!("{url}/api/v1/auth/login"))
            .json(&serde_json::json!({
                "username": "admin",
                "password": "TestRunner!2026secure"
            }))
            .send()
            .expect("Login request failed");

        assert!(
            resp.status().is_success(),
            "Admin login failed: {}",
            resp.status()
        );

        let body: serde_json::Value = resp.json().expect("Failed to parse login response");
        body["access_token"]
            .as_str()
            .expect("No access_token in login response")
            .to_string()
    })
}

/// Store the token as `ak auth login` does, for the instance in the test config.
///
/// The harness doesn't use `AK_TOKEN`: when an assertion on a command fails,
/// assert_cmd prints the command with its environment, so the token would reach
/// the CI log.
fn write_credentials(config_dir: &std::path::Path, token: &str) {
    let credential = serde_json::json!({ "access_token": token, "refresh_token": null });
    let file = serde_json::json!({ "e2e": credential.to_string() });
    let path = config_dir.join("credentials.json");
    std::fs::write(&path, file.to_string()).expect("Failed to write test credentials");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("Failed to protect test credentials");
    }
}

/// Test environment with temp config dir and pre-authenticated CLI.
pub struct TestEnv {
    pub url: String,
    pub token: String,
    pub config_dir: tempfile::TempDir,
}

impl TestEnv {
    /// Create a test environment: write config pointing at the E2E backend,
    /// reuse the cached admin token, and return a ready-to-use env.
    pub fn setup() -> Self {
        ensure_backend();

        let url = backend_url();
        let token = get_auth_token().to_string();
        let config_dir = tempfile::TempDir::new().expect("Failed to create temp config dir");

        // Write config pointing at the test backend
        let config = format!(
            "default_instance = \"e2e\"\n\n[instances.e2e]\nurl = \"{url}\"\napi_version = \"v1\"\n"
        );
        std::fs::write(config_dir.path().join("config.toml"), config)
            .expect("Failed to write test config");
        write_credentials(config_dir.path(), &token);

        TestEnv {
            url,
            token,
            config_dir,
        }
    }

    /// Build an `ak` command pre-configured with the test environment.
    /// Uses the credentials file in the temp config dir, and --no-input --format json.
    pub fn ak_cmd(&self) -> Command {
        let mut cmd = self.bare_cmd();
        cmd.arg("--no-input").arg("--format").arg("json");
        cmd
    }

    /// Build an `ak` command with table output (for snapshot tests).
    pub fn ak_cmd_table(&self) -> Command {
        let mut cmd = self.bare_cmd();
        cmd.arg("--no-input");
        cmd
    }

    /// `ak` for this backend with no credentials at all. The returned directory
    /// holds its config, and has to outlive the command.
    #[allow(dead_code)]
    pub fn anonymous_cmd(&self) -> (Command, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("Failed to create temp config dir");
        std::fs::copy(
            self.config_dir.path().join("config.toml"),
            dir.path().join("config.toml"),
        )
        .expect("Failed to copy test config");
        let mut cmd = self.bare_cmd();
        cmd.env("AK_CONFIG_DIR", dir.path())
            .args(["--no-input", "--format", "json"]);
        (cmd, dir)
    }

    fn bare_cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("ak").expect("Failed to find ak binary");
        // A token already in this shell would win over the credentials file.
        cmd.env_remove("AK_TOKEN")
            .env("AK_CONFIG_DIR", self.config_dir.path())
            .env("AK_CREDENTIAL_STORE", "file");
        cmd
    }

    /// Make a raw HTTP request to the backend API.
    pub fn api_client(&self) -> reqwest::blocking::Client {
        reqwest::blocking::Client::new()
    }

    /// POST to a backend API endpoint with JSON body.
    pub fn api_post(&self, path: &str, body: &serde_json::Value) -> reqwest::blocking::Response {
        let url = format!("{}{}", self.url, path);
        self.api_client()
            .post(&url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .unwrap_or_else(|e| panic!("API POST failed: {e}"))
    }

    /// DELETE a backend API resource.
    pub fn api_delete(&self, path: &str) -> reqwest::blocking::Response {
        let url = format!("{}{}", self.url, path);
        self.api_client()
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .unwrap_or_else(|e| panic!("API DELETE failed: {e}"))
    }
}
