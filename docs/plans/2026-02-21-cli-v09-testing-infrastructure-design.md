# CLI v0.9 Testing Infrastructure Design

**Date:** 2026-02-21
**Status:** Approved
**Scope:** artifact-keeper-cli

## Goal

Add comprehensive testing infrastructure to the CLI: snapshot tests for output regression detection, E2E integration tests against a real backend, and a CI pipeline that runs both layers automatically.

## Current State

- v0.8.0: 30+ command modules, ~200+ inline unit tests
- Dev deps: `assert_cmd`, `predicates`, `tempfile`, `wiremock`
- Tests are all inline `#[cfg(test)]` with wiremock for HTTP mocking
- No snapshot testing, no E2E tests against real backend, no docker-compose
- CI runs `cargo test --workspace` (unit + wiremock tests only)

## Design Decisions

- **Docker Compose for E2E**: Spin up real backend + postgres + meilisearch in CI. Most realistic testing.
- **Dedicated compose file**: Self-contained `tests/docker-compose.yml` in CLI repo. No cross-repo dependency. Pins backend image version.
- **All command groups covered**: One E2E test file per command group (~20 files). Comprehensive coverage.
- **JSON + Table snapshots**: Snapshot both `--format json` and default table output with `insta`. Catches formatting regressions without the fragility of snapshotting all formats.

## Architecture

Three testing layers:

### 1. Snapshot Tests (insta)

Catch output formatting regressions. Run against wiremock (fast, no infra). Added as inline `#[cfg(test)]` tests alongside existing unit tests.

- Add `insta` with `yaml` feature to dev-dependencies
- For each command group, add snapshot tests that mock backend responses with wiremock, run the handler, and compare output against stored snapshots
- Snapshot directory: `src/commands/snapshots/` (insta default convention)
- Cover both `--format json` and default table output per command

### 2. E2E Integration Tests

Run the compiled `ak` binary against a real backend via `assert_cmd`. Live in `tests/` (Rust integration test directory).

```
tests/
  common/
    mod.rs            # shared setup, teardown, seed data, helpers
  e2e_artifact.rs     # push, pull, list, info, delete, search, copy
  e2e_auth.rs         # login, logout, whoami, token
  e2e_repo.rs         # list, create, show, update, delete
  e2e_admin.rs        # users CRUD, audit, storage gc
  e2e_group.rs        # CRUD, add/remove members
  e2e_permission.rs   # create, list, delete rules
  e2e_scan.rs         # run, results, export
  e2e_analytics.rs    # downloads, storage, top-packages, growth
  e2e_service_account.rs
  e2e_quality_gate.rs
  e2e_lifecycle.rs
  e2e_promotion.rs
  e2e_approval.rs
  e2e_label.rs
  e2e_sign.rs
  e2e_sbom.rs
  e2e_license.rs
  e2e_profile.rs
  e2e_totp.rs
  e2e_sso.rs
  e2e_webhook.rs
  e2e_peer.rs
  e2e_replication.rs
  e2e_sync_policy.rs
```

Each test file:
- Calls `common::setup()` to get a configured test environment
- Runs `ak` subcommands via `assert_cmd::Command`
- Validates exit codes, stdout content, and side effects via API calls
- Cleans up created resources

### 3. Docker Compose Stack

Self-contained `tests/docker-compose.yml`:

```yaml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: artifact_registry_test
      POSTGRES_USER: registry
      POSTGRES_PASSWORD: registry
    ports:
      - "30433:5432"
    healthcheck: ...

  meilisearch:
    image: getmeili/meilisearch:v1.12
    ports:
      - "7701:7700"

  backend:
    image: ghcr.io/artifact-keeper/artifact-keeper-backend:latest
    depends_on:
      postgres: { condition: service_healthy }
    environment:
      DATABASE_URL: postgresql://registry:registry@postgres/artifact_registry_test
      MEILI_URL: http://meilisearch:7700
    ports:
      - "8081:8080"
    healthcheck: ...
```

Port offsets (30433, 7701, 8081) avoid conflicts with local dev stack.

### 4. Test Seeding Module

`tests/common/mod.rs` provides:

- `setup()` - Verify backend is healthy, configure CLI to point at test instance, create admin session
- `seed_repos()` - Create test repositories across formats (maven, npm, pypi, docker, generic)
- `seed_users()` - Create test users with various roles (admin, regular, inactive)
- `seed_groups()` - Create test groups with members
- `seed_artifacts()` - Push test artifacts to repos
- `cleanup()` - Best-effort removal of test data
- `ak_cmd()` - Helper that returns `assert_cmd::Command` pre-configured with test instance URL and auth token

### 5. CI Pipeline

New `e2e` job in `.github/workflows/ci.yml`:

```yaml
e2e:
  runs-on: ubuntu-latest
  needs: [check]
  services:
    postgres:
      image: postgres:16
      ...
    meilisearch:
      image: getmeili/meilisearch:v1.12
      ...
  steps:
    - Start backend container
    - Wait for health check
    - cargo test --test 'e2e_*'
```

Runs on push to main and PRs. Separate from the fast `test` job so unit tests are not blocked by infra startup time.

### 6. Scripts

- `tests/start-backend.sh` - Start docker-compose, poll health endpoint, exit on timeout
- `tests/stop-backend.sh` - Tear down docker-compose

For local development:
```bash
./tests/start-backend.sh
cargo test --test 'e2e_*'
./tests/stop-backend.sh
```

## What This Does NOT Include

- TUI panel tests (TUI is excluded from SonarCloud, snapshot testing terminal UI is unreliable)
- Performance benchmarks (out of scope for v0.9)
- Fuzz testing (possible v1.0 addition)
