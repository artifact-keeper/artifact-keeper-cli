# CLI v1.0 Stable Release - Design

## Goal

Ship v1.0.0 as the first stable release of the `ak` CLI. The CLI is feature-complete (29 commands, shell completions, man pages, error diagnostics, multi-platform release pipeline). This release fixes all open security findings and declares stability.

## Approach: Security-First Ship

Fix security issues first so 1.0.0 launches with a clean posture, then bump version and update release artifacts.

## Security Fixes

### 1. SonarCloud Action Injection (Dependabot High)

`SonarSource/sonarqube-scan-action` versions 4.0.0 through 5.x have an argument injection vulnerability. Bump from v5 to v6.0.0 in `.github/workflows/ci.yml`.

### 2. `lru` Crate Stacked Borrows (Dependabot Low)

The `lru` crate < 0.16.3 has an `IterMut` unsoundness issue. This is a transitive dependency. Run `cargo update -p lru` to pull in the patched version.

### 3. CodeQL Alerts (3 open)

Two `actions/missing-workflow-permissions` alerts in `ci.yml`: the `sonar` and `e2e` jobs lack explicit `permissions` blocks. Add `contents: read` (minimum required) to each.

One `rust/cleartext-logging` alert in `tests/common/mod.rs:136`: the `api_delete` panic message includes the URL path. This is test-only code and acceptable, but we can suppress it with a CodeQL inline comment to close the alert cleanly.

## Release Prep

### 4. Version Bump

Change `Cargo.toml` version from `0.9.0` to `1.0.0`. Run `cargo check` to verify the lock file updates.

### 5. CHANGELOG

Add a `v1.0.0` section to `CHANGELOG.md` documenting the stability milestone, referencing the security fixes and the testing infrastructure from v0.9.

### 6. README Final Pass

Verify install commands reference the correct version, badges are current, and the quick start section reflects the actual CLI behavior.

## Out of Scope

- No new features, commands, or flag changes
- No refactoring
- Man pages, shell completions, error handling, release pipeline are all already built
- CodeQL workflow was added in v0.9 (PR #58, pending merge)

## Success Criteria

- Zero open Dependabot alerts
- Zero open CodeQL alerts
- All CI checks green
- Version reads 1.0.0
- CHANGELOG and README are current
