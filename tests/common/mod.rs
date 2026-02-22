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

/// Login as admin and cache the token. Called once per test binary.
fn get_auth_token() -> &'static str {
    AUTH_TOKEN.get_or_init(|| {
        let url = backend_url();
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(format!("{url}/api/v1/auth/login"))
            .json(&serde_json::json!({
                "username": "admin",
                "password": "admin123"
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

        TestEnv {
            url,
            token,
            config_dir,
        }
    }

    /// Build an `ak` command pre-configured with the test environment.
    /// Sets AK_CONFIG_DIR, AK_TOKEN, and --no-input --format json.
    pub fn ak_cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("ak").expect("Failed to find ak binary");
        cmd.env("AK_CONFIG_DIR", self.config_dir.path())
            .env("AK_TOKEN", &self.token)
            .arg("--no-input")
            .arg("--format")
            .arg("json");
        cmd
    }

    /// Build an `ak` command with table output (for snapshot tests).
    pub fn ak_cmd_table(&self) -> Command {
        let mut cmd = Command::cargo_bin("ak").expect("Failed to find ak binary");
        cmd.env("AK_CONFIG_DIR", self.config_dir.path())
            .env("AK_TOKEN", &self.token)
            .arg("--no-input");
        cmd
    }

    /// Make a raw HTTP request to the backend API.
    pub fn api_client(&self) -> reqwest::blocking::Client {
        reqwest::blocking::Client::new()
    }

    /// POST to a backend API endpoint with JSON body.
    pub fn api_post(&self, path: &str, body: &serde_json::Value) -> reqwest::blocking::Response {
        self.api_client()
            .post(format!("{}{}", self.url, path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .unwrap_or_else(|e| panic!("API POST {path} failed: {e}"))
    }

    /// DELETE a backend API resource.
    pub fn api_delete(&self, path: &str) -> reqwest::blocking::Response {
        self.api_client()
            .delete(format!("{}{}", self.url, path))
            .bearer_auth(&self.token)
            .send()
            .unwrap_or_else(|e| panic!("API DELETE {path} failed: {e}"))
    }
}
