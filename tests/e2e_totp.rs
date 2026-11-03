//! E2E tests for `ak totp`, and for logging in with a second factor. The codes are
//! computed here from the secret the real server hands out.

mod common;
#[path = "common/totp.rs"]
mod totp;

use assert_cmd::Command;
use serde_json::{Value, json};

const PASSWORD: &str = "E2e-TotpUser!2026-long";

/// A user of their own for each test, and an `ak` with a config and nothing stored.
struct User {
    env: common::TestEnv,
    name: String,
    id: String,
    home: tempfile::TempDir,
}

impl User {
    fn new(tag: &str) -> Self {
        Self::create(tag, &[])
    }

    fn create(tag: &str, flags: &[&str]) -> Self {
        let env = common::TestEnv::setup();
        let name = format!("e2e-totp-{tag}-{}", std::process::id());
        let output = env
            .ak_cmd()
            .args(["admin", "users", "create", &name])
            .args(["--email", &format!("{name}@example.com")])
            .args(flags)
            .arg("--password-stdin")
            .write_stdin(PASSWORD)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let created: Value = serde_json::from_slice(&output.stdout).unwrap();
        let id = created["user"]["id"].as_str().unwrap().to_string();
        let home = tempfile::TempDir::new().unwrap();
        std::fs::write(
            home.path().join("config.toml"),
            format!(
                "default_instance = \"e2e\"\n[instances.e2e]\nurl = \"{}\"\napi_version = \"v1\"\n",
                env.url
            ),
        )
        .unwrap();
        let user = Self {
            env,
            name,
            id,
            home,
        };
        user.login_ok();
        assert!(user.logged_in_as_user());
        user
    }

    /// The session `ak auth login` stored.
    fn stored_token(&self) -> String {
        let text = std::fs::read_to_string(self.home.path().join("credentials.json")).unwrap();
        let stored: Value = serde_json::from_str(&text).unwrap();
        let session: Value = serde_json::from_str(stored["e2e"].as_str().unwrap()).unwrap();
        session["access_token"].as_str().unwrap().to_string()
    }

    /// `ak` as this user: the only credentials are what `ak auth login` stored.
    fn ak(&self) -> Command {
        let mut cmd = Command::cargo_bin("ak").unwrap();
        cmd.env_remove("AK_TOKEN")
            .env_remove("AK_TOTP_CODE")
            .env_remove("AK_FORMAT")
            .env("AK_CONFIG_DIR", self.home.path())
            .env("AK_CREDENTIAL_STORE", "file")
            .args(["--no-input", "--format", "json"]);
        cmd
    }

    fn login(&self) -> Command {
        let mut cmd = self.ak();
        cmd.args([
            "auth",
            "login",
            "--username",
            &self.name,
            "--password-stdin",
        ])
        .write_stdin(PASSWORD);
        cmd
    }

    fn login_ok(&self) {
        let output = self.login().output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_no_secret(&output);
    }

    fn logged_in_as_user(&self) -> bool {
        let output = self.ak().args(["auth", "whoami"]).output().unwrap();
        output.status.success()
            && serde_json::from_slice::<Value>(&output.stdout).unwrap()["username"]
                == self.name.as_str()
    }

    fn logout(&self) {
        std::fs::remove_file(self.home.path().join("credentials.json")).unwrap();
    }

    /// Turn on TOTP for this user, and return the secret.
    fn enable_totp(&self) -> (String, Vec<String>) {
        let setup: Value =
            serde_json::from_slice(&self.ak().args(["totp", "setup"]).output().unwrap().stdout)
                .unwrap();
        let secret = setup["secret"].as_str().unwrap().to_string();
        assert!(
            setup["qr_code_url"]
                .as_str()
                .unwrap()
                .contains("otpauth://")
        );
        let output = self
            .ak()
            .args(["totp", "enable", "--code-stdin"])
            .write_stdin(totp::code(&secret))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let enabled: Value = serde_json::from_slice(&output.stdout).unwrap();
        let codes = enabled["backup_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_str().unwrap().to_string())
            .collect();
        (secret, codes)
    }
}

impl Drop for User {
    fn drop(&mut self) {
        let _ = self.env.api_delete(&format!("/api/v1/users/{}", self.id));
    }
}

fn assert_no_secret(output: &std::process::Output) {
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!all.contains(PASSWORD), "printed the password: {all}");
    assert!(!all.contains("eyJ"), "printed a token: {all}");
}

#[test]
#[ignore = "requires E2E backend"]
fn setup_enable_login_with_a_code_status_and_disable() {
    let user = User::new("life");
    let status: Value =
        serde_json::from_slice(&user.ak().args(["totp", "status"]).output().unwrap().stdout)
            .unwrap();
    assert_eq!(status["totp_enabled"], false);

    let (secret, backup_codes) = user.enable_totp();
    assert!(!backup_codes.is_empty());
    let status: Value =
        serde_json::from_slice(&user.ak().args(["totp", "status"]).output().unwrap().stdout)
            .unwrap();
    assert_eq!(status["totp_enabled"], true);

    // A password alone no longer logs in, and nothing's stored by trying.
    user.logout();
    let output = user.login().output().unwrap();
    assert!(!output.status.success());
    assert_no_secret(&output);
    assert!(!user.logged_in_as_user());

    // With the code, it does.
    let output = user
        .login()
        .env("AK_TOTP_CODE", totp::code(&secret))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_secret(&output);
    assert!(user.logged_in_as_user());

    // A wrong code is refused, and the password goes on stdin.
    let wrong = user
        .ak()
        .args(["totp", "disable", "--password-stdin", "--code", "000000"])
        .write_stdin(PASSWORD)
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert_no_secret(&wrong);

    let output = user
        .ak()
        .args(["totp", "disable", "--password-stdin"])
        .args(["--code", &totp::code(&secret)])
        .write_stdin(PASSWORD)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_secret(&output);

    user.logout();
    user.login_ok();
    assert!(user.logged_in_as_user());
}

#[test]
#[ignore = "requires E2E backend"]
fn a_ticket_from_login_finishes_with_verify_totp() {
    let user = User::new("ticket");
    let (secret, _) = user.enable_totp();
    user.logout();

    let output = user.login().arg("--print-totp-ticket").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ticket = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(!ticket.is_empty());
    assert!(!user.logged_in_as_user(), "a ticket isn't a login");

    let output = user
        .ak()
        .args(["auth", "verify-totp", &totp::code(&secret)])
        .arg("--totp-token-stdin")
        .write_stdin(ticket)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(user.logged_in_as_user());
}

/// Sets the TOTP policy and puts it back, whatever happens in the test. It's a global
/// setting, so these tests rely on the E2E tests running one at a time. The server
/// lets only an admin with TOTP on change it.
struct PolicyGuard {
    url: String,
    token: String,
}

impl PolicyGuard {
    fn set(&self, policy: &str) {
        let response = reqwest::blocking::Client::new()
            .put(format!("{}/api/v1/admin/settings/totp-policy", self.url))
            .bearer_auth(&self.token)
            .json(&json!({ "policy": policy }))
            .send()
            .unwrap();
        let status = response.status();
        let body = response.text().unwrap_or_default();
        assert!(status.is_success(), "{status}: {body}");
    }
}

impl Drop for PolicyGuard {
    fn drop(&mut self) {
        self.set("disabled");
    }
}

#[test]
#[ignore = "requires E2E backend"]
fn a_policy_that_requires_totp_is_met_with_enroll() {
    if common::server_older_than(1, 11, "TOTP enrollment policy") {
        return;
    }
    let admin = User::create("enroll-admin", &["--admin"]);
    admin.enable_totp();
    let guard = PolicyGuard {
        url: admin.env.url.clone(),
        token: admin.stored_token(),
    };
    let user = User::new("enroll");
    user.logout();
    guard.set("required_for_all");

    // Without the ticket flag it isn't a login, and nothing's stored.
    let output = user.login().output().unwrap();
    assert!(!output.status.success());
    assert_no_secret(&output);
    assert!(!user.logged_in_as_user());

    let output = user.login().arg("--print-totp-ticket").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ticket = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let output = user
        .ak()
        .args(["totp", "enroll", "setup", "--totp-token-stdin"])
        .write_stdin(ticket.clone())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let setup: Value = serde_json::from_slice(&output.stdout).unwrap();
    let secret = setup["secret"].as_str().unwrap();

    let output = user
        .ak()
        .args(["totp", "enroll", "complete", "--totp-token-stdin"])
        .args(["--code", &totp::code(secret)])
        .write_stdin(ticket)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_secret(&output);
    let done: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!done["backup_codes"].as_array().unwrap().is_empty());
    assert!(user.logged_in_as_user());
}

#[test]
fn codes_match_the_rfc_6238_vectors() {
    // RFC 6238 appendix B, SHA-1, last six digits.
    let key = b"12345678901234567890";
    assert_eq!(totp::code_for_key(key, 59), "287082");
    assert_eq!(totp::code_for_key(key, 1111111109), "081804");
    assert_eq!(totp::code_for_key(key, 2000000000), "279037");
    // RFC 4648's base32 test vector.
    assert_eq!(totp::key_of("MZXW6YTB"), b"fooba");
}
