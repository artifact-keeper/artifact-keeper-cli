# CLI v1.0 Stable Release Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship v1.0.0 with zero open security findings, declaring CLI stability.

**Architecture:** Fix Dependabot alerts (SonarCloud action, lru crate), resolve 3 CodeQL alerts in CI workflow and test helper, bump version, update CHANGELOG and README. No feature changes.

**Tech Stack:** GitHub Actions YAML, Rust (Cargo.toml/Cargo.lock), Markdown

---

### Task 1: Fix SonarCloud Action Injection (Dependabot High)

The `SonarSource/sonarqube-scan-action` v5 has an argument injection vulnerability. Bump to v6.

**Files:**
- Modify: `.github/workflows/ci.yml:71`

**Step 1: Update the action version**

In `.github/workflows/ci.yml`, change line 71 from:

```yaml
        uses: SonarSource/sonarqube-scan-action@v5
```

to:

```yaml
        uses: SonarSource/sonarqube-scan-action@v6
```

**Step 2: Verify the workflow is valid YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`
Expected: No output (valid YAML)

**Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "fix(ci): bump sonarqube-scan-action v5 to v6 (CVE fix)"
```

---

### Task 2: Add Workflow Permissions (CodeQL Alert)

Two CodeQL alerts flag missing `permissions` blocks on the `sonar` and `e2e` jobs. Without explicit permissions, jobs inherit overly broad defaults. Add minimal `contents: read` to each.

**Files:**
- Modify: `.github/workflows/ci.yml:62-66` (sonar job)
- Modify: `.github/workflows/ci.yml:88-91` (e2e job)

**Step 1: Add permissions to the sonar job**

After line 65 (`needs: [test]`), add:

```yaml
    permissions:
      contents: read
```

**Step 2: Add permissions to the e2e job**

After line 91 (`needs: [check]`), add:

```yaml
    permissions:
      contents: read
```

**Step 3: While we're here, add permissions to all other jobs too**

Add `permissions: { contents: read }` to `check`, `fmt`, `clippy`, `test`, and `build` jobs as well. This is best practice for least-privilege and prevents future CodeQL alerts.

**Step 4: Verify valid YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`
Expected: No output (valid YAML)

**Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "fix(ci): add explicit permissions to all workflow jobs"
```

---

### Task 3: Fix Cleartext Logging CodeQL Alert

CodeQL flags `tests/common/mod.rs:136` for logging sensitive data in the `api_delete` panic message. The URL path is included in the error string. This is test-only code, but we should handle it cleanly to close the alert.

**Files:**
- Modify: `tests/common/mod.rs:131-137`

**Step 1: Suppress the alert with a CodeQL inline comment**

Change the `api_delete` method from:

```rust
    pub fn api_delete(&self, path: &str) -> reqwest::blocking::Response {
        self.api_client()
            .delete(format!("{}{}", self.url, path))
            .bearer_auth(&self.token)
            .send()
            .unwrap_or_else(|e| panic!("API DELETE {path} failed: {e}"))
    }
```

to:

```rust
    pub fn api_delete(&self, path: &str) -> reqwest::blocking::Response {
        let url = format!("{}{}", self.url, path);
        self.api_client()
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .unwrap_or_else(|e| panic!("API DELETE failed: {e}")) // lgtm[rust/cleartext-logging]
    }
```

This removes the path from the panic message (the actual fix) and adds a suppression comment for any residual CodeQL matching.

**Step 2: Do the same for api_post**

Change `api_post` from:

```rust
    pub fn api_post(&self, path: &str, body: &serde_json::Value) -> reqwest::blocking::Response {
        self.api_client()
            .post(format!("{}{}", self.url, path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .unwrap_or_else(|e| panic!("API POST {path} failed: {e}"))
    }
```

to:

```rust
    pub fn api_post(&self, path: &str, body: &serde_json::Value) -> reqwest::blocking::Response {
        let url = format!("{}{}", self.url, path);
        self.api_client()
            .post(&url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .unwrap_or_else(|e| panic!("API POST failed: {e}"))
    }
```

**Step 3: Verify tests compile**

Run: `cargo test --workspace --lib --no-run`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add tests/common/mod.rs
git commit -m "fix: remove URL paths from test helper panic messages"
```

---

### Task 4: Update lru Dependency (Dependabot Low)

The `lru` crate at 0.12.5 has an unsoundness issue in `IterMut`. The fix is in 0.16.3+. This is a transitive dependency (pulled in by other crates), so `cargo update` should resolve it.

**Files:**
- Modify: `Cargo.lock` (via cargo update)

**Step 1: Update the lru crate**

Run: `cargo update -p lru`
Expected: Output shows lru updated from 0.12.5 to a version >= 0.16.3

**Step 2: If cargo update doesn't reach 0.16.3**

The `lru` crate is a transitive dependency. If `cargo update -p lru` can't reach 0.16.3 because a direct dependency pins an older version, check what depends on it:

Run: `cargo tree -i lru`

If a direct dependency pins a too-old lru, bump that dependency in `Cargo.toml`. If lru is pulled by progenitor-client (the SDK), check `sdk/Cargo.toml` too.

**Step 3: Verify build**

Run: `cargo check --workspace`
Expected: Compiles clean

**Step 4: Verify lru version in lockfile**

Run: `grep -A2 'name = "lru"' Cargo.lock`
Expected: version >= 0.16.3

**Step 5: Commit**

```bash
git add Cargo.lock
git commit -m "fix: update lru to fix IterMut unsoundness (Dependabot)"
```

If `Cargo.toml` or `sdk/Cargo.toml` was modified:

```bash
git add Cargo.toml Cargo.lock sdk/Cargo.toml
git commit -m "fix: bump dependencies to resolve lru unsoundness"
```

---

### Task 5: Version Bump to 1.0.0

**Files:**
- Modify: `Cargo.toml:6`

**Step 1: Bump the version**

In `Cargo.toml`, change line 6 from:

```toml
version = "0.9.0"
```

to:

```toml
version = "1.0.0"
```

**Step 2: Update lockfile**

Run: `cargo check --workspace`
Expected: Compiles clean, Cargo.lock updated with new version

**Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to 1.0.0"
```

---

### Task 6: Update CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

**Step 1: Add v1.0.0 section**

Insert the following after line 7 (below the header, above the 0.9.0 entry):

```markdown
## [1.0.0] - 2026-02-23

### Stable Release

First stable release of the Artifact Keeper CLI. The CLI is feature-complete with 29 top-level commands, 100+ subcommands, interactive TUI, multi-instance management, and multi-platform distribution.

### Security

- Bumped `SonarSource/sonarqube-scan-action` from v5 to v6 to fix argument injection vulnerability
- Updated `lru` transitive dependency to resolve `IterMut` unsoundness
- Added explicit `permissions` blocks to all CI workflow jobs (least-privilege)
- Added CodeQL workflow with exclusions for generated SDK code
- Removed URL paths from test helper error messages

### Changed

- Version bump from 0.9.0 to 1.0.0, declaring API and CLI flag stability
```

**Step 2: Add the version link at the bottom**

At the bottom of the file, add before the existing links:

```markdown
[1.0.0]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v1.0.0
```

**Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: add v1.0.0 CHANGELOG entry"
```

---

### Task 7: README Final Pass

Verify the README is current for 1.0. The README at `README.md` (171 lines) is already solid. Check these specific items:

**Files:**
- Modify: `README.md` (only if issues found)

**Step 1: Verify commands list is complete**

Cross-reference the Commands section (lines 79-93) against the actual CLI. The current list shows 12 commands but the CLI has 29 top-level commands. The README intentionally lists only the most common ones, which is fine. Verify the listed commands are accurate.

Run: `cargo run --quiet -- --help 2>/dev/null | head -50`

**Step 2: Check for version references**

Search README for any hardcoded version numbers that need updating:

Run: `grep -n '0\.\|v0\.' README.md`

If any references to 0.x versions exist, update them.

**Step 3: Verify install methods still work**

Skim the install section (lines 6-52) for correctness. No changes needed unless something is outdated.

**Step 4: Commit (only if changes made)**

```bash
git add README.md
git commit -m "docs: update README for v1.0.0"
```

If no changes needed, skip this commit.

---

### Task 8: Final Verification

**Step 1: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests pass (251+ unit tests + snapshot tests)

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings -A dead_code`
Expected: No warnings

**Step 3: Run fmt check**

Run: `cargo fmt --check`
Expected: No formatting issues

**Step 4: Verify version**

Run: `cargo run --quiet -- --version`
Expected: `ak 1.0.0`

**Step 5: Verify no remaining issues**

Check git status is clean and all commits are in order:

Run: `git log --oneline -10`

**Step 6: Commit any final fixes**

If any step above revealed issues, fix and commit them before completing.
