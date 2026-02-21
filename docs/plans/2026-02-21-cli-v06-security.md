# CLI v0.6 Security & Signing Design

**Date:** 2026-02-21
**Status:** Approved
**Scope:** artifact-keeper-cli v0.6.0

## Goal

Add security and signing capabilities to the CLI: artifact signing with key management, SBOM generation and analysis, license compliance enforcement, Dependency-Track integration, enhanced scanning with policy management, and a TUI security findings panel.

## SDK Coverage

The generated SDK has 54 security methods across 3 extension traits:

| Trait | Methods | Covers |
|-------|---------|--------|
| ClientSigningExt | 10 | Key management, repo signing config |
| ClientSbomExt | 15 | SBOM lifecycle, CVE tracking, license policies |
| ClientSecurityExt | 29 | Scanning, findings, DT integration, policies, dashboard |

All endpoints already have type-safe SDK methods. The work is wiring them to clap commands with good UX.

## Design Decisions

- **`ak license` is a top-level command** rather than nested under `ak sbom`, because license compliance is a first-class concern for enterprises (legal teams manage it independently of SBOMs).
- **Key management nests under `ak sign key`** since signing keys and signing operations are tightly coupled and managed by the same persona.
- **`ak dt` as alias for `ak dependency-track`** keeps the commonly-used command short.
- **Enhanced `ak scan`** adds subcommands to the existing command rather than creating a new one.
- **TUI security panel** is a new panel (Panel::Security) accessible via number key or Tab cycling.
- **Shared helpers** (parse_uuid, confirm_action, print_page_info) from v0.5 are reused throughout.

## Command Groups

### 1. `ak sign` - Artifact Signing & Key Management

SDK trait: `ClientSigningExt`

#### Sign/Verify Operations

The SDK's signing trait focuses on key management and repo signing config rather than individual artifact sign/verify operations. The sign and verify commands will use the repo signing config and key endpoints.

#### Key Management (`ak sign key`)

```
ak sign key list [--repo <uuid>]
    List signing keys, optionally filtered by repository.
    SDK: list_keys() -> KeyListResponse { keys, total }

ak sign key show <key-id>
    Show key details (algorithm, fingerprint, active status, expiry).
    SDK: get_key() -> SigningKeyPublic

ak sign key create <name> --algorithm <alg> --type <type> --repo <uuid> [--uid-name <name>] [--uid-email <email>]
    Create a new signing key.
    SDK: create_key() -> SigningKeyPublic

ak sign key delete <key-id> [--yes]
    Delete a signing key (with confirmation).
    SDK: delete_key()

ak sign key revoke <key-id>
    Revoke a signing key (marks inactive, does not delete).
    SDK: revoke_key() -> SigningKeyPublic

ak sign key rotate <key-id>
    Rotate a signing key (creates new key, revokes old).
    SDK: rotate_key() -> SigningKeyPublic

ak sign key export <key-id>
    Export a key's public key in PEM format.
    SDK: get_public_key() -> PublicKeyPem
```

#### Repository Signing Config (`ak sign config`)

```
ak sign config show <repo-id>
    Show repository signing configuration.
    SDK: get_repo_signing_config() -> RepoSigningConfig

ak sign config update <repo-id> [flags]
    Update repository signing configuration.
    SDK: update_repo_signing_config() -> RepoSigningConfig

ak sign config export-key <repo-id>
    Export the repository's public key in PEM format.
    SDK: get_repo_public_key() -> PublicKeyPem
```

### 2. `ak sbom` - Software Bill of Materials

SDK trait: `ClientSbomExt`

```
ak sbom generate <artifact-id> [--format spdx|cyclonedx] [--force]
    Generate an SBOM for an artifact.
    SDK: generate_sbom() -> SbomResponse

ak sbom show <artifact-id>
    View SBOM content for an artifact.
    SDK: get_sbom_by_artifact() -> SbomContentResponse

ak sbom list [--repo <uuid>] [--format <fmt>]
    List all SBOMs, optionally filtered.
    SDK: list_sboms() -> Vec<SbomResponse>

ak sbom get <sbom-id>
    Get SBOM metadata by ID.
    SDK: get_sbom() -> SbomResponse

ak sbom delete <sbom-id> [--yes]
    Delete an SBOM (with confirmation).
    SDK: delete_sbom()

ak sbom components <sbom-id>
    List components in an SBOM (dependencies, licenses, versions).
    SDK: get_sbom_components() -> SbomComponents

ak sbom export <sbom-id> --output <path> [--target-format spdx-json|cyclonedx-json]
    Convert SBOM to a target format and write to file.
    SDK: convert_sbom() -> ConvertedSbom
```

#### CVE Tracking (`ak sbom cve`)

```
ak sbom cve history <artifact-id>
    Show CVE history for an artifact.
    SDK: get_cve_history() -> Vec<CveHistoryEntry>

ak sbom cve trends [--days <n>] [--repo <uuid>]
    Show CVE trends over time.
    SDK: get_cve_trends() -> CveTrends

ak sbom cve update-status <cve-id> --status <status> --reason <reason>
    Update triage status for a CVE.
    SDK: update_cve_status() -> CveStatusUpdate
```

### 3. `ak license` - License Compliance

SDK trait: `ClientSbomExt` (license policy endpoints)

#### Policy Management (`ak license policy`)

```
ak license policy list
    List all license policies.
    SDK: list_license_policies() -> Vec<LicensePolicyResponse>

ak license policy show <id>
    Show license policy details.
    SDK: get_license_policy() -> LicensePolicyResponse

ak license policy create <name> --allowed <licenses...> [--denied <licenses...>] [--allow-unknown] [--action <action>]
    Create a license policy. --allowed and --denied accept comma-separated SPDX identifiers.
    SDK: upsert_license_policy() -> LicensePolicyResponse

ak license policy delete <id> [--yes]
    Delete a license policy (with confirmation).
    SDK: delete_license_policy()
```

#### Compliance Check

```
ak license check --licenses <license1,license2,...> [--repo <uuid>]
    Check a set of licenses against policies. Exits non-zero if non-compliant (for CI).
    SDK: check_license_compliance() -> LicenseCheckResult { compliant, violations, warnings }
```

### 4. `ak dt` (alias: `ak dependency-track`) - Dependency-Track Integration

SDK trait: `ClientSecurityExt` (DT-prefixed endpoints)

```
ak dt status
    Check Dependency-Track connection status.
    SDK: dt_status() -> DtStatusResponse

ak dt project list
    List all DT projects.
    SDK: list_projects() -> Vec<DtProject>

ak dt project show <uuid>
    Show project details.
    SDK: get_project() -> DtProject

ak dt project components <uuid>
    List project components.
    SDK: get_project_components() -> Vec<DtComponent>

ak dt project findings <uuid> [--severity <sev>]
    List project findings (vulnerabilities), optionally filtered by severity.
    SDK: get_project_findings() -> Vec<DtFinding>

ak dt project violations <uuid>
    List policy violations for a project.
    SDK: get_project_violations() -> Vec<DtViolation>

ak dt project metrics <uuid>
    Show project security metrics.
    SDK: get_project_metrics() -> DtProjectMetrics

ak dt project metrics-history <uuid> [--days <n>]
    Show project metrics over time.
    SDK: get_project_metrics_history() -> Vec<DtMetricsHistory>

ak dt metrics
    Portfolio-wide security metrics.
    SDK: get_portfolio_metrics() -> DtPortfolioMetrics

ak dt policies
    List Dependency-Track policies.
    SDK: list_dependency_track_policies() -> Vec<DtPolicy>

ak dt analyze --project <uuid> --vulnerability <uuid> --component <uuid> --state <state> [--justification <text>] [--details <text>] [--suppressed]
    Triage a vulnerability finding.
    SDK: update_analysis() -> DtAnalysisResponse
```

### 5. Enhanced `ak scan`

SDK trait: `ClientSecurityExt`

New subcommands added to the existing `ak scan` command:

```
ak scan dashboard
    Show security dashboard overview (total scans, findings by severity, grades).
    SDK: get_dashboard() -> DashboardResponse

ak scan scores
    Show security scores for all repositories.
    SDK: get_all_scores() -> Vec<ScoreResponse>

ak scan config list
    List scan configurations.
    SDK: list_scan_configs() -> Vec<ScanConfigResponse>
```

#### Finding Management (`ak scan finding`)

```
ak scan finding ack <finding-id> --reason <reason>
    Acknowledge a finding (suppress from reports).
    SDK: acknowledge_finding() -> FindingResponse

ak scan finding revoke <finding-id>
    Revoke acknowledgment of a finding.
    SDK: revoke_acknowledgment() -> FindingResponse
```

#### Scan Policy Management (`ak scan policy`)

```
ak scan policy list
    List scan policies.
    SDK: list_policies() -> Vec<PolicyResponse>

ak scan policy show <id>
    Show scan policy details.
    SDK: get_policy() -> PolicyResponse

ak scan policy create <name> --max-severity <sev> [--block-on-fail] [--block-unscanned] [--repo <uuid>]
    Create a scan policy.
    SDK: create_policy() -> PolicyResponse

ak scan policy update <id> [--name <name>] [--max-severity <sev>] [--enabled <bool>]
    Update a scan policy.
    SDK: update_policy() -> PolicyResponse

ak scan policy delete <id> [--yes]
    Delete a scan policy (with confirmation).
    SDK: delete_policy()
```

#### Refactoring Existing Subcommands

- Refactor `ak scan show` to use `parse_uuid` from helpers module
- Add `--repo` flag support via `list_artifact_scans()` for artifact-specific scan listing
- Add security config endpoints: `ak scan security show <repo-key>`, `ak scan security update <repo-key>`

### 6. TUI: Security Findings Panel

Add `Panel::Security` to the existing TUI dashboard.

**Access:** Press `4` or cycle with Tab from the Artifacts panel.

**Layout:**
- Top section: Dashboard summary (total scans, findings by severity with color coding)
- Main section: Recent scans list (scrollable, shows scan ID, status, artifact, finding counts)
- Detail pane: Select a scan to view its findings (severity, CVE, component, fix version)

**Implementation:**
- Add `Panel::Security` variant to the Panel enum
- Add `SecurityState` struct to App state (scans list, selected scan findings, dashboard data)
- Fetch data lazily on panel switch using `get_dashboard()`, `list_scans()`, `list_findings()`
- Reuse `format_severity` color logic from scan.rs (move to a shared location)
- Keyboard: Enter to drill into scan findings, Esc to go back, severity filter keys

## Test Plan

Each command module gets parsing tests following the v0.5 pattern:

| Module | Estimated Tests |
|--------|----------------|
| sign.rs | 8-10 (key CRUD, config show/update, export) |
| sbom.rs | 8-10 (generate, show, list, export, cve subcommands) |
| license.rs | 4-5 (policy CRUD, compliance check) |
| dt.rs | 8-10 (status, project subcommands, analyze, metrics) |
| scan.rs (new) | 8-10 (dashboard, scores, finding ack/revoke, policy CRUD) |
| **Total** | ~38-45 new parsing tests |

## File Plan

New files:
- `src/commands/sign.rs` - Signing & key management
- `src/commands/sbom.rs` - SBOM operations
- `src/commands/license.rs` - License compliance
- `src/commands/dt.rs` - Dependency-Track integration

Modified files:
- `src/commands/scan.rs` - Add dashboard, scores, finding, policy subcommands
- `src/commands/tui.rs` - Add Security panel
- `src/commands/mod.rs` - Register new modules
- `src/cli.rs` - Add Command variants, wire execute(), add tests

## Estimated Scope

- ~4 new command modules, ~1 enhanced module, ~1 TUI panel addition
- ~46 new subcommands across all modules
- ~40 new parsing tests (targeting 326+ total)
- Net addition: ~2500-3000 lines of Rust
