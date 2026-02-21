# v0.6 Security & Signing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 4 new command groups (sign, sbom, license, dt), enhance the existing scan command, and add a TUI security panel.

**Architecture:** Each new command module follows the established pattern: clap derive structs for parsing, async functions calling SDK builders, unified output rendering via `output::render()`. Shared helpers (`parse_uuid`, `confirm_action`, `print_page_info`) from `src/commands/helpers.rs` are reused. The TUI panel extends the existing ratatui Panel enum.

**Tech Stack:** Rust, clap 4 (derive), artifact-keeper-sdk (Progenitor-generated), comfy-table, ratatui, tokio

---

## Reference: SDK Traits & Key Types

The implementor must check the actual SDK types in `sdk/src/generated_sdk.rs` before writing code. The types below were verified at plan time but field names can drift.

**Traits used:**
- `ClientSigningExt` (10 methods) - key management, repo signing config
- `ClientSbomExt` (15 methods) - SBOM lifecycle, CVE tracking, license policies
- `ClientSecurityExt` (29 methods) - scanning, DT integration, policies, dashboard

**Critical type notes:**
- DT `project_uuid` params are `String`, NOT `uuid::Uuid` (the SDK passes them as path segments)
- `get_public_key()` and `get_repo_public_key()` return `ByteStream`, not a typed struct
- `revoke_key()` returns `serde_json::Map<String, serde_json::Value>`, not `SigningKeyPublic`
- `CreatePolicyRequest` is shared between `ClientSecurityExt::create_policy` and `ClientLifecycleExt::create_lifecycle_policy` (same struct, different endpoints)
- `UpdatePolicyRequest` has required fields (name, block_on_fail, block_unscanned, is_enabled, max_severity) - a "partial update" requires fetching the existing policy first
- `list_artifact_scans()` page/per_page are `i32`, whereas the existing `scan.rs` uses `i64` for `list_scans()`/`list_repo_scans()`

---

## Task 1: Set Up Worktree

**Files:** None (git operations only)

**Steps:**

1. Verify the `.worktrees` directory exists and is gitignored:
   ```bash
   git check-ignore .worktrees
   ```

2. Create the worktree:
   ```bash
   git worktree add .worktrees/v06-security -b feat/v06-security
   cd .worktrees/v06-security
   ```

3. Symlink the API spec for xtask (the worktree parent is `.worktrees/`, not the repo root):
   ```bash
   ls ../../artifact-keeper-api/openapi.json  # verify path
   # Only create symlink if not already present from v0.5
   ```

4. Verify the SDK is up-to-date and all 3 security traits exist:
   ```bash
   cargo run -p xtask -- generate --check
   grep -c "ClientSigningExt\|ClientSbomExt\|ClientSecurityExt" sdk/src/generated_sdk.rs
   ```
   Expected: 3 matches (one per trait)

5. Verify baseline tests pass:
   ```bash
   cargo test --workspace
   ```
   Expected: 286 tests pass (v0.5 baseline)

---

## Task 2: `ak sign` Command

**Files:**
- Create: `src/commands/sign.rs`
- Modify: `src/commands/mod.rs` (add `pub mod sign;`)
- Modify: `src/cli.rs` (add `Sign` variant to `Command` enum, wire execute, add tests)

**Subcommands to implement:**

| Subcommand | SDK Method | Key Details |
|------------|-----------|-------------|
| `key list [--repo UUID]` | `list_keys()` | Returns `KeyListResponse { keys, total }` |
| `key show <key-id>` | `get_key()` | Returns `SigningKeyPublic` |
| `key create <name> --algorithm <alg> --type <type> --repo <uuid>` | `create_key()` | Body: `CreateKeyPayload { name, algorithm, key_type, repository_id, uid_email, uid_name }` |
| `key delete <key-id> [--yes]` | `delete_key()` | Uses `confirm_action` helper |
| `key revoke <key-id>` | `revoke_key()` | Returns `serde_json::Map`, NOT `SigningKeyPublic` |
| `key rotate <key-id>` | `rotate_key()` | Returns `SigningKeyPublic` |
| `key export <key-id>` | `get_public_key()` | Returns `ByteStream` - print raw PEM to stdout |
| `config show <repo-id>` | `get_repo_signing_config()` | Returns `SigningConfigResponse` |
| `config update <repo-id> [flags]` | `update_repo_signing_config()` | Body: `UpdateSigningConfigPayload { require_signatures, sign_metadata, sign_packages, signing_key_id }` |
| `config export-key <repo-id>` | `get_repo_public_key()` | Returns `ByteStream` - print raw PEM to stdout |

**Implementation pattern:**

```rust
use artifact_keeper_sdk::ClientSigningExt;
use clap::Subcommand;

use super::client::client_for;
use super::helpers::{parse_uuid, parse_optional_uuid, confirm_action};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};
```

The `SignCommand` enum has two nested subcommand enums: `SignKeyCommand` and `SignConfigCommand`.

**ByteStream handling for key export:**
The `get_public_key()` and `get_repo_public_key()` methods return a byte stream. Use `into_inner()` to get the response, then read the bytes. The response body is PEM text - print directly to stdout. Check the actual return type in the SDK; if it's a wrapper, you may need `.into_inner()` or similar to extract the bytes. If the SDK returns a `reqwest::Response` or `Bytes`, use:
```rust
let resp = client.get_public_key().key_id(key_id).send().await.map_err(...)?;
let pem = resp.into_inner();
// Print to stdout - the PEM text
println!("{pem}");
```
If the type is opaque, check `sdk/src/generated_sdk.rs` for the actual `ByteStream` handling pattern.

**Table output for key list:**
Headers: `ID | NAME | ALGORITHM | TYPE | ACTIVE | REPO | FINGERPRINT`
Use `&key.id.to_string()[..8]` for short IDs.

**Detail output for key show:**
```
ID:            {full uuid}
Name:          {name}
Algorithm:     {algorithm}
Type:          {key_type}
Active:        {yes/no}
Fingerprint:   {fingerprint or "-"}
Repository:    {repository_id}
Created:       {created_at}
Expires:       {expires_at or "-"}
Public Key:    {first 40 chars of public_key_pem}...
```

**CLI tests (add to `src/cli.rs` #[cfg(test)] mod tests):**

```rust
#[test]
fn parse_sign_key_list() {
    parse(&["sign", "key", "list"]);
}

#[test]
fn parse_sign_key_list_with_repo() {
    parse(&["sign", "key", "list", "--repo", "00000000-0000-0000-0000-000000000000"]);
}

#[test]
fn parse_sign_key_create() {
    parse(&["sign", "key", "create", "my-key", "--algorithm", "ed25519", "--type", "signing", "--repo", "00000000-0000-0000-0000-000000000000"]);
}

#[test]
fn parse_sign_key_show() {
    parse(&["sign", "key", "show", "00000000-0000-0000-0000-000000000000"]);
}

#[test]
fn parse_sign_key_delete() {
    parse(&["sign", "key", "delete", "00000000-0000-0000-0000-000000000000", "--yes"]);
}

#[test]
fn parse_sign_key_revoke() {
    parse(&["sign", "key", "revoke", "00000000-0000-0000-0000-000000000000"]);
}

#[test]
fn parse_sign_key_rotate() {
    parse(&["sign", "key", "rotate", "00000000-0000-0000-0000-000000000000"]);
}

#[test]
fn parse_sign_key_export() {
    parse(&["sign", "key", "export", "00000000-0000-0000-0000-000000000000"]);
}

#[test]
fn parse_sign_config_show() {
    parse(&["sign", "config", "show", "00000000-0000-0000-0000-000000000000"]);
}

#[test]
fn parse_sign_config_update() {
    parse(&["sign", "config", "update", "00000000-0000-0000-0000-000000000000", "--require-signatures"]);
}
```

**Verification:**
```bash
cargo test --workspace --lib -- parse_sign
cargo clippy --workspace -- -D warnings -A dead_code
cargo fmt --check
```

**Commit:**
```bash
git add src/commands/sign.rs src/commands/mod.rs src/cli.rs
git commit -m "feat: add ak sign command (key list/show/create/delete/revoke/rotate/export, config show/update/export-key)"
```

---

## Task 3: `ak sbom` Command

**Files:**
- Create: `src/commands/sbom.rs`
- Modify: `src/commands/mod.rs` (add `pub mod sbom;`)
- Modify: `src/cli.rs` (add `Sbom` variant, wire execute, add tests)

**Subcommands to implement:**

| Subcommand | SDK Method | Key Details |
|------------|-----------|-------------|
| `generate <artifact-id> [--format spdx\|cyclonedx] [--force]` | `generate_sbom()` | Body: `GenerateSbomRequest { artifact_id, force_regenerate, format }` |
| `show <artifact-id>` | `get_sbom_by_artifact()` | Returns `SbomContentResponse` (has `content` JSON map) |
| `list [--repo UUID] [--format <fmt>]` | `list_sboms()` | Query: artifact_id, format, repository_id. Returns `Vec<SbomResponse>` |
| `get <sbom-id>` | `get_sbom()` | Returns `SbomContentResponse` |
| `delete <sbom-id> [--yes]` | `delete_sbom()` | Uses `confirm_action` helper |
| `components <sbom-id>` | `get_sbom_components()` | Returns `Vec<ComponentResponse>` |
| `export <sbom-id> --output <path> [--target-format <fmt>]` | `convert_sbom()` | Body: `ConvertSbomRequest { target_format }`. Write result to file. |
| `cve history <artifact-id>` | `get_cve_history()` | Returns `Vec<CveHistoryEntry>` |
| `cve trends [--days N] [--repo UUID]` | `get_cve_trends()` | Query: days, repository_id. Returns `CveTrends` |
| `cve update-status <cve-id> --status <status> --reason <reason>` | `update_cve_status()` | Body: `UpdateCveStatusRequest { status, reason }` |

**Structure:** `SbomCommand` enum with a nested `SbomCveCommand` subcommand enum for the `cve` group.

**Note on `sbom list`:** The `--format` flag here refers to SBOM format (spdx/cyclonedx), NOT output format. Use `--sbom-format` to avoid collision with the global `--format` flag, or name it `--spec` to be clear.

**Note on `sbom export`:** The `convert_sbom()` method returns a `SbomResponse` (not raw bytes). The converted content may be in the response's `content` field. Write the JSON content to the file path specified by `--output`. Use `std::fs::write()`.

**Table output for sbom list:**
Headers: `ID | ARTIFACT | FORMAT | COMPONENTS | LICENSES | GENERATED`
Fields from `SbomResponse`: id, artifact_id (short), format, component_count, license_count, generated_at

**Table output for cve history:**
Headers: `CVE | SEVERITY | COMPONENT | STATUS | CVSS | DISCOVERED`
Fields from `CveHistoryEntry`: cve_id, severity, affected_component, status, cvss_score, discovered_at

**CLI tests:** ~8-10 tests covering generate, show, list, export, delete, components, cve subcommands.

**Verification:**
```bash
cargo test --workspace --lib -- parse_sbom
cargo clippy --workspace -- -D warnings -A dead_code
```

**Commit:**
```bash
git commit -m "feat: add ak sbom command (generate, show, list, get, delete, components, export, cve history/trends/update-status)"
```

---

## Task 4: `ak license` Command

**Files:**
- Create: `src/commands/license.rs`
- Modify: `src/commands/mod.rs` (add `pub mod license;`)
- Modify: `src/cli.rs` (add `License` variant, wire execute, add tests)

**Subcommands to implement:**

| Subcommand | SDK Method | Key Details |
|------------|-----------|-------------|
| `policy list` | `list_license_policies()` | Returns `Vec<LicensePolicyResponse>` |
| `policy show <id>` | `get_license_policy()` | Returns `LicensePolicyResponse` |
| `policy create <name> --allowed <licenses> [--denied <licenses>] [--allow-unknown] [--action <action>]` | `upsert_license_policy()` | Body: `UpsertLicensePolicyRequest { name, allowed_licenses, denied_licenses, action, allow_unknown, description, is_enabled, repository_id }`. Note: `allowed_licenses` and `denied_licenses` are `Vec<String>` (required fields). |
| `policy delete <id> [--yes]` | `delete_license_policy()` | Uses `confirm_action` helper |
| `check --licenses <licenses> [--repo UUID]` | `check_license_compliance()` | Body: `CheckLicenseComplianceRequest { licenses, repository_id }`. Exit 1 if non-compliant. |

**Important:** The `--allowed` and `--denied` flags use `#[arg(long, value_delimiter = ',')]` for comma-separated SPDX identifiers. The `--licenses` flag on `check` uses the same pattern.

**LicensePolicyResponse fields** (verify in SDK): id, name, allowed_licenses, denied_licenses, action, allow_unknown, is_enabled, description, created_at, updated_at

**Table output for policy list:**
Headers: `ID | NAME | ACTION | ALLOW UNKNOWN | ENABLED | ALLOWED | DENIED`

**Compliance check output:**
```
COMPLIANT: All licenses pass policy checks.
```
or:
```
NON-COMPLIANT: License policy violations detected.
Violations:
  - MIT not in allowed list
Warnings:
  - Apache-2.0 is deprecated
```
Exit with code 1 if `!result.compliant` (for CI integration).

**CLI tests:** ~5 tests covering policy list, create, show, delete, and check.

**Verification:**
```bash
cargo test --workspace --lib -- parse_license
cargo clippy --workspace -- -D warnings -A dead_code
```

**Commit:**
```bash
git commit -m "feat: add ak license command (policy list/show/create/delete, check)"
```

---

## Task 5: `ak dt` Command (Dependency-Track)

**Files:**
- Create: `src/commands/dt.rs`
- Modify: `src/commands/mod.rs` (add `pub mod dt;`)
- Modify: `src/cli.rs` (add `Dt` variant with alias `dependency-track`, wire execute, add tests)

**Subcommands to implement:**

| Subcommand | SDK Method | Key Details |
|------------|-----------|-------------|
| `status` | `dt_status()` | Returns `DtStatusResponse` |
| `project list` | `list_projects()` | Returns `Vec<DtProject>` |
| `project show <uuid>` | `get_project()` | `project_uuid` is **String** not UUID |
| `project components <uuid>` | `get_project_components()` | Returns `Vec<DtComponent>` |
| `project findings <uuid> [--severity <sev>]` | `get_project_findings()` | Returns `Vec<DtFinding>` |
| `project violations <uuid>` | `get_project_violations()` | Returns `Vec<DtPolicyViolation>` |
| `project metrics <uuid>` | `get_project_metrics()` | Returns `DtProjectMetrics` |
| `project metrics-history <uuid> [--days N]` | `get_project_metrics_history()` | Query: days (i32). Returns `Vec<DtMetricsHistory>` |
| `metrics` | `get_portfolio_metrics()` | Returns `DtPortfolioMetrics` |
| `policies` | `list_dependency_track_policies()` | Returns `Vec<DtPolicyFull>` |
| `analyze --project <uuid> --vulnerability <uuid> --component <uuid> --state <state> [--justification] [--details] [--suppressed]` | `update_analysis()` | Body: `UpdateAnalysisBody { project_uuid, component_uuid, vulnerability_uuid, state, suppressed, justification, details }`. All UUID params are **String**. |

**Critical:** DT project UUIDs are `String` type in the SDK, NOT `uuid::Uuid`. Do NOT use `parse_uuid()` for these. Accept them as plain string arguments.

**Alias:** Register the command with `#[command(alias = "dependency-track")]` so both `ak dt` and `ak dependency-track` work.

**Structure:** `DtCommand` enum with a nested `DtProjectCommand` for the `project` subgroup.

**Table output for project list:**
Headers: `UUID | NAME | VERSION | LAST BOM IMPORT`
Fields from `DtProject`: uuid, name, version, last_bom_import (epoch timestamp - format as date), last_bom_import_format

**Detail output for project metrics:**
```
Critical:     {critical}
High:         {high}
Medium:       {medium}
Low:          {low}
Unassigned:   {unassigned}
Audited:      {findings_audited}/{findings_total}
```

**Portfolio metrics output (similar structure).**

**CLI tests:** ~10 tests covering status, project list/show/findings/metrics, metrics, policies, analyze.

**Verification:**
```bash
cargo test --workspace --lib -- parse_dt
cargo clippy --workspace -- -D warnings -A dead_code
```

**Commit:**
```bash
git commit -m "feat: add ak dt command (status, project list/show/components/findings/violations/metrics, portfolio metrics, policies, analyze)"
```

---

## Task 6: Enhanced `ak scan`

**Files:**
- Modify: `src/commands/scan.rs` (add new subcommands, refactor existing code to use helpers)

**New subcommands to add:**

| Subcommand | SDK Method | Key Details |
|------------|-----------|-------------|
| `dashboard` | `get_dashboard()` | Returns `SecurityDashboard` |
| `scores` | `get_all_scores()` | Returns `Vec<SecurityScore>` |
| `config list` | `list_scan_configs()` | Returns `Vec<ScanConfig>` |
| `finding ack <id> --reason <reason>` | `acknowledge_finding()` | Body: `AcknowledgeRequest { reason }` |
| `finding revoke <id>` | `revoke_acknowledgment()` | No body |
| `policy list` | `list_policies()` | Returns `Vec<PolicyResponse>` |
| `policy show <id>` | `get_policy()` | Returns `PolicyResponse` |
| `policy create <name> --max-severity <sev> [--block-on-fail] [--block-unscanned] [--repo UUID]` | `create_policy()` | Body: `CreatePolicyRequest` (same type as lifecycle) |
| `policy update <id> [flags]` | `update_policy()` | Body: `UpdatePolicyRequest` - required fields, so fetch first |
| `policy delete <id> [--yes]` | `delete_policy()` | Uses `confirm_action` |
| `security show <repo-key>` | `get_repo_security()` | Key is **String** (repo key, not UUID) |
| `security update <repo-key> [flags]` | `update_repo_security()` | Key is **String** |

**Refactoring existing code:**
1. Replace the UUID parsing in `show_findings` with `parse_uuid` from helpers
2. Add `use super::helpers::{parse_uuid, parse_optional_uuid, confirm_action};`
3. Move `format_severity`, `format_severity_count`, `truncate`, `parse_severity_filter` to remain in scan.rs (they're scan-specific)

**Structure change:** The existing `ScanCommand` enum gets new variants:
- `Dashboard`
- `Scores`
- `Config { command: ScanConfigCommand }` (nested)
- `Finding { command: ScanFindingCommand }` (nested)
- `Policy { command: ScanPolicyCommand }` (nested)
- `Security { command: ScanSecurityCommand }` (nested)

Keep the existing `Run`, `List`, `Show` variants.

**Dashboard output (table mode):**
```
Security Dashboard:
  Total Scans:           {total_scans}
  Total Findings:        {total_findings}
  Critical:              {critical_findings}
  High:                  {high_findings}
  Policy Violations:     {policy_violations_blocked}
  Repos with Scanning:   {repos_with_scanning}
  Grade A Repos:         {repos_grade_a}
  Grade F Repos:         {repos_grade_f}
```

**Scores table:**
Headers: `REPO | GRADE | CRITICAL | HIGH | MEDIUM | LOW | SCANNED | UNSCANNED | UPDATED`

**Policy update note:** `UpdatePolicyRequest` has required fields (name, block_on_fail, etc.), so the update command must first fetch the existing policy with `get_policy()`, merge in the user's changes, and send the full struct. This avoids the user having to re-specify every field.

**CLI tests:** ~10 tests covering dashboard, scores, finding ack/revoke, policy CRUD, security show/update.

**Verification:**
```bash
cargo test --workspace --lib -- parse_scan
cargo clippy --workspace -- -D warnings -A dead_code
```

**Commit:**
```bash
git commit -m "feat: enhance ak scan with dashboard, scores, finding management, policy CRUD, and security config"
```

---

## Task 7: TUI Security Panel

**Files:**
- Modify: `src/commands/tui.rs`
- Modify: `src/commands/scan.rs` (if moving severity formatting helpers to a shared location)

**Steps:**

1. **Add Panel::Security variant** to the `Panel` enum (line ~84):
   ```rust
   enum Panel {
       Instances,
       Repos,
       Artifacts,
       Security,
   }
   ```

2. **Add SecurityState** to the App struct. It needs:
   - `dashboard: Option<SecurityDashboard>` (from `get_dashboard()`)
   - `scans: Vec<ScanResult>` (from `list_scans()`)
   - `scan_list_state: ListState` (ratatui list state)
   - `selected_findings: Vec<Finding>` (from `list_findings()`)
   - `finding_list_state: ListState`
   - `showing_findings: bool` (drill-down state)

3. **Add SDK import:** `use artifact_keeper_sdk::ClientSecurityExt;`

4. **Keyboard handling:**
   - `4` key or Tab past Artifacts switches to Security panel
   - Enter on a scan drills into its findings
   - Esc goes back from findings to scan list
   - Up/Down navigates the lists
   - Tab cycles Instances -> Repos -> Artifacts -> Security -> Instances

5. **Lazy data loading:** When switching to the Security panel, if `dashboard` is None, fetch:
   - `get_dashboard()` for summary stats
   - `list_scans()` for recent scans list
   Cache in the App state. When drilling into a scan, fetch `list_findings()` for that scan.

6. **Draw function:** Add `draw_security_panel()`:
   - **Top area (3 rows):** Dashboard summary line: "Scans: {n} | Findings: {n} (C:{c} H:{h} M:{m} L:{l}) | Grade A: {n} Grade F: {n}"
   - **Main area:** List of scans with severity counts, color-coded
   - **Detail area (when drill-down):** List of findings for selected scan

7. **Color-coded severity:** Use the same color scheme as scan.rs:
   - CRITICAL: red + bold
   - HIGH: red
   - MEDIUM: yellow
   - LOW/INFO: dim

8. **Wire into draw_panels** and **handle_key_event**: Add the Security case to the match arms.

**Note:** The TUI file is ~1147 lines. This task adds ~200-250 lines. Be careful not to break existing panel logic.

**Verification:**
```bash
cargo build  # TUI code can't be unit tested easily, verify it compiles
cargo clippy --workspace -- -D warnings -A dead_code
```

**Commit:**
```bash
git commit -m "feat: add TUI security findings panel with dashboard, scan list, and finding drill-down"
```

---

## Task 8: Full Test Suite, Clippy, Format

**Steps:**

1. Run the full test suite:
   ```bash
   cargo test --workspace
   ```
   Expected: ~326+ tests pass (286 baseline + ~40 new)

2. Run clippy:
   ```bash
   cargo clippy --workspace -- -D warnings -A dead_code
   ```
   Fix any warnings (likely `too_many_arguments` on some functions - add `#[allow(clippy::too_many_arguments)]`).

3. Run format check:
   ```bash
   cargo fmt --check
   ```
   Fix any issues with `cargo fmt`.

4. Run release build:
   ```bash
   cargo build --release
   ```

5. Verify shell completions cover new commands:
   ```bash
   cargo run -- completion bash 2>/dev/null | grep -c "sign\|sbom\|license\|dt\|dependency-track"
   ```

6. Commit any fixes:
   ```bash
   git commit -m "chore: fix formatting and clippy warnings"
   ```

---

## Task 9: CHANGELOG and Version Bump

**Files:**
- Modify: `CHANGELOG.md` (add v0.6.0 section)
- Modify: `Cargo.toml` (bump version from 0.5.0 to 0.6.0)

**CHANGELOG entry:**

```markdown
## [0.6.0] - 2026-02-XX

### Added

- **Signing & key management** - `ak sign key list`, `show`, `create`, `delete`, `revoke`, `rotate`, `export` for managing signing keys; `ak sign config show/update/export-key` for repository signing configuration
- **SBOM operations** - `ak sbom generate`, `show`, `list`, `get`, `delete`, `components`, `export` for SBOM lifecycle; `ak sbom cve history/trends/update-status` for CVE tracking and triage
- **License compliance** - `ak license policy list`, `show`, `create`, `delete` for managing license policies; `ak license check` for CI-friendly compliance checking (exits non-zero on violations)
- **Dependency-Track integration** - `ak dt status`, `project list/show/components/findings/violations/metrics/metrics-history`, `metrics`, `policies`, `analyze` for vulnerability management (alias: `ak dependency-track`)
- **Enhanced scanning** - `ak scan dashboard` and `scores` for security overview; `ak scan finding ack/revoke` for finding triage; `ak scan policy list/show/create/update/delete` for scan policy management; `ak scan security show/update` for repository security config
- **TUI security panel** - new panel (press 4 or Tab) showing security dashboard, recent scans with drill-down into individual findings
```

**Commit:**
```bash
git add CHANGELOG.md Cargo.toml Cargo.lock
git commit -m "chore: prepare v0.6.0 release with security and signing features"
```
