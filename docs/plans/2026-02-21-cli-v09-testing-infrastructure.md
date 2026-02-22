# CLI v0.9 Testing Infrastructure Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add snapshot tests (insta), E2E integration tests against a real Docker Compose backend, and a CI pipeline for E2E to the CLI.

**Architecture:** Three test layers: (1) insta snapshot tests for output regression in existing `#[cfg(test)]` modules, (2) E2E integration tests in `tests/` using `assert_cmd` against a real backend stack, (3) CI pipeline with a separate `e2e` job that starts the Docker Compose stack. A shared `tests/common/` module handles backend health checks, auth, and test data seeding.

**Tech Stack:** Rust, insta (snapshot testing), assert_cmd + predicates (CLI testing), Docker Compose (backend + postgres + meilisearch), GitHub Actions

---

### Task 1: Add insta dependency and fix TOTP password leak

**Files:**
- Modify: `Cargo.toml:70-74` (add insta to dev-dependencies)
- Modify: `src/cli.rs:320` (remove `--password mypass` from after_help)
- Modify: `src/cli.rs:2287-2298` (update test to not use `--password` flag)

**Step 1: Add insta to dev-dependencies**

In `Cargo.toml`, add `insta` after the existing dev-dependencies:

```toml
[dev-dependencies]
assert_cmd = "2"
insta = { version = "1", features = ["yaml"] }
predicates = "3"
tempfile = "3"
wiremock = "0.6"
```

**Step 2: Fix TOTP after_help to remove plain-text password**

In `src/cli.rs`, change the Totp command's `after_help` (line ~320):

From:
```
after_help = "Examples:\n  ak totp setup\n  ak totp enable --code 123456\n  ak totp disable --password mypass --code 123456\n  ak totp status"
```

To:
```
after_help = "Examples:\n  ak totp setup\n  ak totp enable --code 123456\n  ak totp disable --code 123456\n  ak totp status"
```

**Step 3: Check if TOTP disable still accepts --password flag**

Read `src/commands/totp.rs` to check the `Disable` subcommand. If `--password` is still a clap arg, update the test accordingly. If interactive-only, remove `--password` from the test entirely:

In `src/cli.rs` test `parse_totp_disable` (~line 2287), change from:
```rust
fn parse_totp_disable() {
    let cli = parse(&[
        "ak",
        "totp",
        "disable",
        "--password",
        "mypass",
        "--code",
        "654321",
    ])
    .unwrap();
    assert!(matches!(cli.command, Command::Totp { .. }));
}
```

To (if `--password` was removed from the CLI):
```rust
fn parse_totp_disable() {
    let cli = parse(&["ak", "totp", "disable", "--code", "654321"]).unwrap();
    assert!(matches!(cli.command, Command::Totp { .. }));
}
```

Or if `--password` is still a clap arg but should use a placeholder:
```rust
fn parse_totp_disable() {
    let cli = parse(&[
        "ak",
        "totp",
        "disable",
        "--code",
        "654321",
    ])
    .unwrap();
    assert!(matches!(cli.command, Command::Totp { .. }));
}
```

**Step 4: Run tests to verify nothing breaks**

Run: `cargo test --workspace`
Expected: All existing tests pass

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/cli.rs
git commit -m "chore: add insta for snapshot testing, fix TOTP password leak"
```

---

### Task 2: Create Docker Compose stack for E2E tests

**Files:**
- Create: `tests/docker-compose.yml`
- Create: `tests/start-backend.sh`
- Create: `tests/stop-backend.sh`

**Step 1: Create the Docker Compose file**

Create `tests/docker-compose.yml`:

```yaml
# E2E test stack for artifact-keeper-cli.
# Ports are offset from the local dev stack to avoid conflicts.
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: artifact_registry_test
      POSTGRES_USER: registry
      POSTGRES_PASSWORD: registry
    ports:
      - "30433:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U registry -d artifact_registry_test"]
      interval: 2s
      timeout: 5s
      retries: 15

  meilisearch:
    image: getmeili/meilisearch:v1.12
    environment:
      MEILI_ENV: development
    ports:
      - "7701:7700"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7700/health"]
      interval: 2s
      timeout: 5s
      retries: 15

  backend:
    image: ghcr.io/artifact-keeper/artifact-keeper-backend:latest
    depends_on:
      postgres:
        condition: service_healthy
      meilisearch:
        condition: service_healthy
    environment:
      DATABASE_URL: "postgresql://registry:registry@postgres:5432/artifact_registry_test"
      MEILI_URL: "http://meilisearch:7700"
      ADMIN_PASSWORD: "admin123"
      JWT_SECRET: "e2e-test-secret-key-not-for-production"
    ports:
      - "8081:8080"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 3s
      timeout: 5s
      retries: 30
```

**Step 2: Create start-backend.sh**

Create `tests/start-backend.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

echo "Starting E2E test backend..."
docker compose -f "$COMPOSE_FILE" up -d

echo "Waiting for backend health check..."
for i in $(seq 1 60); do
    if curl -sf http://localhost:8081/health > /dev/null 2>&1; then
        echo "Backend is healthy (attempt $i)"
        exit 0
    fi
    sleep 2
done

echo "ERROR: Backend did not become healthy within 120 seconds"
docker compose -f "$COMPOSE_FILE" logs backend
exit 1
```

**Step 3: Create stop-backend.sh**

Create `tests/stop-backend.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

echo "Stopping E2E test backend..."
docker compose -f "$COMPOSE_FILE" down -v
```

**Step 4: Make scripts executable and test locally**

```bash
chmod +x tests/start-backend.sh tests/stop-backend.sh
```

**Step 5: Commit**

```bash
git add tests/docker-compose.yml tests/start-backend.sh tests/stop-backend.sh
git commit -m "feat(v0.9): add Docker Compose stack and scripts for E2E tests"
```

---

### Task 3: Create E2E test common module

**Files:**
- Create: `tests/common/mod.rs`

**Step 1: Write the shared E2E test helpers**

Create `tests/common/mod.rs`. This module provides helpers for all E2E test files. Each E2E test calls `setup()` which returns a `TestEnv` with the backend URL and a pre-configured `ak_cmd()` builder.

```rust
use assert_cmd::Command;
use std::sync::Once;
use std::time::Duration;

static INIT: Once = Once::new();

/// Backend URL for E2E tests. Set via E2E_BACKEND_URL env var,
/// defaults to the Docker Compose stack port.
pub fn backend_url() -> String {
    std::env::var("E2E_BACKEND_URL").unwrap_or_else(|_| "http://localhost:8081".to_string())
}

/// Ensure backend is reachable. Called once per test run.
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

/// Test environment with temp config dir and pre-authenticated CLI.
pub struct TestEnv {
    pub url: String,
    pub token: String,
    pub config_dir: tempfile::TempDir,
}

impl TestEnv {
    /// Create a test environment: write config pointing at the E2E backend,
    /// login as admin, and return a ready-to-use env.
    pub fn setup() -> Self {
        ensure_backend();

        let url = backend_url();
        let config_dir = tempfile::TempDir::new().expect("Failed to create temp config dir");

        // Write config pointing at the test backend
        let config = format!(
            "default_instance = \"e2e\"\n\n[instances.e2e]\nurl = \"{url}\"\napi_version = \"v1\"\n"
        );
        std::fs::write(config_dir.path().join("config.toml"), config)
            .expect("Failed to write test config");

        // Login to get a token
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
        let token = body["token"]
            .as_str()
            .expect("No token in login response")
            .to_string();

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
```

**Step 2: Add reqwest blocking feature to dev-dependencies**

In `Cargo.toml`, add `reqwest` with blocking feature to dev-dependencies:

```toml
[dev-dependencies]
assert_cmd = "2"
insta = { version = "1", features = ["yaml"] }
predicates = "3"
reqwest = { version = "0.13", features = ["blocking", "json"] }
tempfile = "3"
wiremock = "0.6"
```

Note: `reqwest` is already a regular dependency, but we need the `blocking` feature for E2E tests (integration tests run synchronous by default with `assert_cmd`).

**Step 3: Run compilation check**

Run: `cargo check --tests`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add tests/common/mod.rs Cargo.toml Cargo.lock
git commit -m "feat(v0.9): add E2E test common module with setup and helpers"
```

---

### Task 4: Add snapshot tests for core commands (auth, repo, artifact)

**Files:**
- Modify: `src/commands/auth.rs` (add snapshot tests in existing `#[cfg(test)]` module)
- Modify: `src/commands/repo.rs` (add snapshot tests)
- Modify: `src/commands/artifact.rs` (add snapshot tests)

**Step 1: Add snapshot tests to auth.rs**

In `src/commands/auth.rs`, inside the existing `mod tests {}` block, add snapshot tests after the existing wiremock tests. These use the existing `mock_setup` pattern but capture output with `insta::assert_yaml_snapshot!`:

```rust
    #[tokio::test]
    async fn snapshot_whoami_json() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        // Capture the output that would be printed
        let data = user_json();
        let output = crate::output::render(&data, &global.format, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("whoami_json", parsed);
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn snapshot_token_list_json() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let tokens = serde_json::json!([{
            "id": NIL_UUID,
            "name": "ci-deploy",
            "scopes": ["read", "write"],
            "created_at": "2026-01-15T12:00:00Z",
            "expires_at": null,
            "last_used_at": null
        }]);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&tokens))
            .mount(&server)
            .await;

        let output = crate::output::render(&tokens, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("token_list_json", parsed);
        crate::test_utils::teardown_env();
    }
```

**Step 2: Add snapshot tests to repo.rs**

Read `src/commands/repo.rs` to find the existing test module, then add similar snapshot tests for `repo list` and `repo show` JSON output using wiremock.

**Step 3: Add snapshot tests to artifact.rs**

In `src/commands/artifact.rs`, add snapshot tests for `artifact list` and `artifact search` JSON output in the existing test module.

**Step 4: Run tests and review snapshots**

Run: `cargo test --workspace`

First run creates snapshot files in `src/commands/snapshots/`. Review them:

Run: `cargo insta review`
Expected: Review and accept the new snapshots

**Step 5: Commit**

```bash
git add src/commands/auth.rs src/commands/repo.rs src/commands/artifact.rs src/commands/snapshots/
git commit -m "test(v0.9): add insta snapshot tests for auth, repo, and artifact commands"
```

---

### Task 5: Add snapshot tests for governance commands

**Files:**
- Modify: `src/commands/group.rs` (add snapshot tests)
- Modify: `src/commands/permission.rs` (add snapshot tests)
- Modify: `src/commands/approval.rs` (add snapshot tests)
- Modify: `src/commands/quality_gate.rs` (add snapshot tests)
- Modify: `src/commands/lifecycle.rs` (add snapshot tests)
- Modify: `src/commands/promotion.rs` (add snapshot tests)
- Modify: `src/commands/label.rs` (add snapshot tests)

Follow the same pattern as Task 4: mock API responses with wiremock, render output with `crate::output::render`, and snapshot with `insta::assert_yaml_snapshot!`. Focus on `list` and `show` subcommands for each module. One or two snapshots per module is sufficient.

**Step 1: Add snapshots for each governance command**

For each module, add 1-2 snapshot tests in the existing `mod tests` block using the wiremock + render + insta pattern.

**Step 2: Run and review**

Run: `cargo test --workspace && cargo insta review`

**Step 3: Commit**

```bash
git add src/commands/group.rs src/commands/permission.rs src/commands/approval.rs \
  src/commands/quality_gate.rs src/commands/lifecycle.rs src/commands/promotion.rs \
  src/commands/label.rs src/commands/snapshots/
git commit -m "test(v0.9): add insta snapshot tests for governance commands"
```

---

### Task 6: Add snapshot tests for security, federation, and admin commands

**Files:**
- Modify: `src/commands/scan.rs`
- Modify: `src/commands/sign.rs`
- Modify: `src/commands/sbom.rs`
- Modify: `src/commands/license.rs`
- Modify: `src/commands/dt.rs`
- Modify: `src/commands/peer.rs`
- Modify: `src/commands/webhook.rs`
- Modify: `src/commands/sync_policy.rs`
- Modify: `src/commands/admin.rs`
- Modify: `src/commands/analytics.rs`
- Modify: `src/commands/sso.rs`
- Modify: `src/commands/profile.rs`
- Modify: `src/commands/totp.rs`

Follow the same pattern as Tasks 4-5. One or two snapshots per module covering the primary `list`/`show` output.

**Step 1: Add snapshots for each command module**

**Step 2: Run and review**

Run: `cargo test --workspace && cargo insta review`

**Step 3: Commit**

```bash
git add src/commands/*.rs src/commands/snapshots/
git commit -m "test(v0.9): add insta snapshot tests for security, federation, and admin commands"
```

---

### Task 7: Write E2E tests for core commands (auth, repo, admin)

**Files:**
- Create: `tests/e2e_auth.rs`
- Create: `tests/e2e_repo.rs`
- Create: `tests/e2e_admin.rs`

These are integration tests that run the actual `ak` binary against the Docker Compose backend. They require `tests/start-backend.sh` to be run first.

**Step 1: Write e2e_auth.rs**

Create `tests/e2e_auth.rs`:

```rust
//! E2E tests for `ak auth` commands.
//!
//! Requires the E2E backend to be running:
//!   ./tests/start-backend.sh
//!   cargo test --test e2e_auth
//!   ./tests/stop-backend.sh

mod common;

use predicates::prelude::*;

#[test]
fn auth_whoami_shows_admin() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["auth", "whoami"])
        .assert()
        .success()
        .stdout(predicate::str::contains("admin"));
}

#[test]
fn auth_whoami_table_output() {
    let env = common::TestEnv::setup();
    env.ak_cmd_table()
        .args(["auth", "whoami"])
        .assert()
        .success()
        .stdout(predicate::str::contains("admin"));
}

#[test]
fn auth_token_lifecycle() {
    let env = common::TestEnv::setup();

    // Create a token
    let output = env
        .ak_cmd()
        .args(["auth", "token", "create"])
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("token") || stdout.contains("Token"));

    // List tokens
    env.ak_cmd()
        .args(["auth", "token", "list"])
        .assert()
        .success();
}
```

**Step 2: Write e2e_repo.rs**

Create `tests/e2e_repo.rs`:

```rust
//! E2E tests for `ak repo` commands.

mod common;

use predicates::prelude::*;

#[test]
fn repo_list_succeeds() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["repo", "list"])
        .assert()
        .success();
}

#[test]
fn repo_create_show_delete_lifecycle() {
    let env = common::TestEnv::setup();
    let repo_key = format!("e2e-test-{}", std::process::id());

    // Create
    env.ak_cmd()
        .args(["repo", "create", &repo_key, "--pkg-format", "generic", "--type", "local"])
        .assert()
        .success();

    // Show
    env.ak_cmd()
        .args(["repo", "show", &repo_key])
        .assert()
        .success()
        .stdout(predicate::str::contains(&repo_key));

    // Delete
    env.ak_cmd()
        .args(["repo", "delete", &repo_key, "--yes"])
        .assert()
        .success();
}
```

**Step 3: Write e2e_admin.rs**

Create `tests/e2e_admin.rs`:

```rust
//! E2E tests for `ak admin` commands.

mod common;

use predicates::prelude::*;

#[test]
fn admin_users_list() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["admin", "users", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("admin"));
}

#[test]
fn admin_stats() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["admin", "stats"])
        .assert()
        .success();
}

#[test]
fn admin_user_create_delete_lifecycle() {
    let env = common::TestEnv::setup();
    let username = format!("e2e-user-{}", std::process::id());

    // Create user via API (CLI create requires interactive password)
    let resp = env.api_post(
        "/api/v1/users",
        &serde_json::json!({
            "username": username,
            "email": format!("{username}@test.local"),
            "display_name": "E2E Test User",
            "password": "TestPass123!",
            "is_admin": false
        }),
    );
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().unwrap();
    let user_id = body["user"]["id"].as_str().unwrap().to_string();

    // Verify user shows in list
    env.ak_cmd()
        .args(["admin", "users", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&username));

    // Delete user
    env.api_delete(&format!("/api/v1/users/{user_id}"));
}
```

**Step 4: Run E2E tests (requires backend running)**

```bash
./tests/start-backend.sh
cargo test --test e2e_auth --test e2e_repo --test e2e_admin -- --test-threads=1
./tests/stop-backend.sh
```

Expected: All tests pass

**Step 5: Commit**

```bash
git add tests/e2e_auth.rs tests/e2e_repo.rs tests/e2e_admin.rs
git commit -m "test(v0.9): add E2E tests for auth, repo, and admin commands"
```

---

### Task 8: Write E2E tests for governance commands

**Files:**
- Create: `tests/e2e_group.rs`
- Create: `tests/e2e_permission.rs`
- Create: `tests/e2e_quality_gate.rs`
- Create: `tests/e2e_label.rs`

Follow the same pattern as Task 7. Each test file:
- Imports `mod common;`
- Creates `TestEnv::setup()`
- Tests CRUD lifecycle for the command group
- Cleans up created resources

Key tests per file:
- `e2e_group.rs`: list, create, show, add-member, remove-member, delete
- `e2e_permission.rs`: list, create, delete
- `e2e_quality_gate.rs`: list, create, show, delete
- `e2e_label.rs`: repo add, repo list, repo remove

**Step 1: Write each test file following the pattern from Task 7**

**Step 2: Run E2E tests**

```bash
cargo test --test 'e2e_*' -- --test-threads=1
```

**Step 3: Commit**

```bash
git add tests/e2e_group.rs tests/e2e_permission.rs tests/e2e_quality_gate.rs tests/e2e_label.rs
git commit -m "test(v0.9): add E2E tests for governance commands"
```

---

### Task 9: Write E2E tests for security and remaining commands

**Files:**
- Create: `tests/e2e_scan.rs`
- Create: `tests/e2e_analytics.rs`
- Create: `tests/e2e_profile.rs`
- Create: `tests/e2e_webhook.rs`
- Create: `tests/e2e_config.rs`

Focus on the commands that work against the basic backend setup (no external services like Dependency-Track, federation peers, or SSO providers required). Commands that need external services (dt, peer, sso, sign, sbom, license, replication, sync-policy, totp) get placeholder test files that skip if the service isn't available.

**Step 1: Write test files for commands that work against the basic backend**

- `e2e_scan.rs`: `scan list`, `scan dashboard` (read-only, no scanner needed)
- `e2e_analytics.rs`: `analytics downloads`, `analytics storage`, `analytics growth`
- `e2e_profile.rs`: `profile show`, `profile update`
- `e2e_webhook.rs`: CRUD lifecycle
- `e2e_config.rs`: `config list`, `config get`, `config set`, `config path`

**Step 2: Create placeholder files for service-dependent commands**

For each of: `e2e_sign.rs`, `e2e_sbom.rs`, `e2e_license.rs`, `e2e_dt.rs`, `e2e_peer.rs`, `e2e_sso.rs`, `e2e_sync_policy.rs`, `e2e_totp.rs`, `e2e_promotion.rs`, `e2e_approval.rs`, `e2e_lifecycle.rs`:

```rust
//! E2E tests for `ak <command>`.
//! These tests require additional services not in the basic Docker Compose stack.
//! They are skipped in CI unless the service is available.

mod common;

#[test]
#[ignore = "requires <service> - run with --ignored to include"]
fn placeholder() {
    let _env = common::TestEnv::setup();
    // TODO: Add tests when service is available in E2E stack
}
```

**Step 3: Run E2E tests**

```bash
cargo test --test 'e2e_*' -- --test-threads=1
```

**Step 4: Commit**

```bash
git add tests/e2e_*.rs
git commit -m "test(v0.9): add E2E tests for security, analytics, profile, webhook, and config"
```

---

### Task 10: Add E2E job to CI pipeline

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Add the e2e job**

In `.github/workflows/ci.yml`, add a new `e2e` job after the existing `test` job:

```yaml
  e2e:
    name: E2E Tests
    runs-on: ubuntu-latest
    needs: [check]
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_DB: artifact_registry_test
          POSTGRES_USER: registry
          POSTGRES_PASSWORD: registry
        ports:
          - 30433:5432
        options: >-
          --health-cmd "pg_isready -U registry -d artifact_registry_test"
          --health-interval 2s
          --health-timeout 5s
          --health-retries 15
      meilisearch:
        image: getmeili/meilisearch:v1.12
        env:
          MEILI_ENV: development
        ports:
          - 7701:7700
        options: >-
          --health-cmd "curl -f http://localhost:7700/health"
          --health-interval 2s
          --health-timeout 5s
          --health-retries 15
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Start backend
        run: |
          docker run -d --name e2e-backend \
            --network ${{ job.services.postgres.network }} \
            -e DATABASE_URL="postgresql://registry:registry@postgres:5432/artifact_registry_test" \
            -e MEILI_URL="http://meilisearch:7700" \
            -e ADMIN_PASSWORD="admin123" \
            -e JWT_SECRET="e2e-test-secret-key-not-for-production" \
            -p 8081:8080 \
            ghcr.io/artifact-keeper/artifact-keeper-backend:latest
      - name: Wait for backend
        run: |
          for i in $(seq 1 60); do
            if curl -sf http://localhost:8081/health > /dev/null 2>&1; then
              echo "Backend healthy after $i attempts"
              exit 0
            fi
            sleep 2
          done
          docker logs e2e-backend
          exit 1
      - name: Run E2E tests
        env:
          E2E_BACKEND_URL: http://localhost:8081
        run: cargo test --test 'e2e_*' -- --test-threads=1
      - name: Backend logs (on failure)
        if: failure()
        run: docker logs e2e-backend
```

**Step 2: Verify CI config is valid YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`

**Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(v0.9): add E2E test job with Docker Compose backend"
```

---

### Task 11: Update version, sonar config, and documentation

**Files:**
- Modify: `Cargo.toml:6` (bump version to 0.9.0)
- Modify: `sonar-project.properties` (exclude tests/ directory)
- Modify: `CHANGELOG.md` (add v0.9.0 entry)

**Step 1: Bump version**

In `Cargo.toml`, change `version = "0.8.0"` to `version = "0.9.0"`.

**Step 2: Update sonar config**

In `sonar-project.properties`, add the integration test directory to exclusions:

```properties
sonar.projectKey=artifact-keeper_artifact-keeper-cli
sonar.organization=artifact-keeper
sonar.sources=src
sonar.tests=src,tests
sonar.test.inclusions=**/*test*.rs,**/*tests*.rs,tests/**/*.rs
sonar.exclusions=target/**,sdk/**,**/tui.rs,tests/**
sonar.sourceEncoding=UTF-8
```

**Step 3: Add CHANGELOG entry**

Add a v0.9.0 section at the top of `CHANGELOG.md`:

```markdown
## v0.9.0 - Testing Infrastructure

### Added
- Snapshot tests using `insta` for JSON and table output regression detection across all command modules
- E2E integration test suite running against a real backend via Docker Compose
- Docker Compose stack (`tests/docker-compose.yml`) with backend, PostgreSQL, and Meilisearch
- Shared test helpers in `tests/common/` for E2E environment setup, auth, and API access
- CI pipeline job for automated E2E testing on every push and PR
- Start/stop scripts for local E2E test development

### Fixed
- Removed plain-text password from TOTP command examples
```

**Step 4: Run all tests one final time**

```bash
cargo test --workspace
```

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock sonar-project.properties CHANGELOG.md
git commit -m "chore: bump version to 0.9.0, update sonar config and changelog"
```
