# CLI Roadmap Design: v0.5 through v1.0

**Date:** 2026-02-21
**Status:** Approved
**Scope:** artifact-keeper-cli

## Goal

Bring the CLI to full feature parity with the web UI across governance, security, federation, and administration. The CLI should be the universal tool for developers, DevOps engineers, CI/CD pipelines, and platform administrators. Ship incrementally in tiered releases, each adding a coherent feature domain with unit tests, E2E integration tests, and TUI panel additions.

## Current State (v0.4.3)

- 13 top-level commands, 50+ subcommands, 8,745 lines of Rust
- 251 unit tests, zero integration tests
- Strong artifact operations (push/pull/search), package manager setup (11+ ecosystems), interactive TUI dashboard
- Generated SDK (66K lines from Progenitor/OpenAPI) covers all 250+ backend endpoints
- Distributed via 6 channels (GitHub, Homebrew, Snap, Docker, Cargo, curl installer)
- Backend has 73 API handler modules; CLI covers roughly one-third

## Design Decisions

- **Tiered releases by feature domain**: governance, security, federation, admin, testing, stable
- **Full test coverage**: Unit tests for CLI parsing + E2E integration tests against a real backend for every command
- **TUI grows**: Each feature tier adds a TUI panel for the new domain
- **SDK already exists**: The generated SDK has type-safe methods for every backend endpoint. Work is wiring SDK to clap commands with good UX.
- **Audience**: Everyone. Developers, DevOps, CI/CD, platform admins.

## Release Tiers

| Release | Theme | New Command Groups | TUI Addition |
|---------|-------|--------------------|--------------|
| v0.5 | Governance & Compliance | group, permission, service-account, promotion, approval, quality-gate, lifecycle, label | Approvals panel |
| v0.6 | Security & Signing | sign, sbom, license, dependency-track + enhanced scan | Security findings panel |
| v0.7 | Federation & Replication | peer, replication, sync-policy, webhook | Replication status panel |
| v0.8 | Admin & Analytics | analytics, sso, profile, totp + enhanced admin (audit, storage GC, telemetry) | Analytics panel |
| v0.9 | Testing Infrastructure | Integration test framework, snapshot tests, E2E suite, CI pipeline for E2E | - |
| v1.0 | Stable Release | Gap analysis, breaking changes cleanup, docs, shell completions | Full TUI overhaul |

## v0.5 - Governance & Compliance

### `ak group` - User group management
- `list` - List all groups
- `show <name>` - Group details with members
- `create <name> [--description]` - Create group
- `delete <name>` - Delete group (with confirmation)
- `add-member <group> <user>` - Add user to group
- `remove-member <group> <user>` - Remove user from group

### `ak permission` - Fine-grained permission rules
- `list [--repo] [--group] [--user]` - List rules
- `create --target <repo|group> --action <read|write|admin> --principal <user|group>` - Create rule
- `delete <id>` - Delete rule

### `ak service-account` - Non-human identities for CI/CD
- `list` - List accounts
- `create <name> [--description]` - Create account
- `delete <name>` - Delete account
- `token create <account> --name <name> --scopes <scopes> [--expires-in-days]` - Create token
- `token list <account>` - List tokens
- `token revoke <account> <token-id>` - Revoke token

### `ak promotion` - Move artifacts between repositories
- `promote <artifact> --from <repo> --to <repo> [--version]` - Promote artifact
- `rule list` - List promotion rules
- `rule create --from <repo> --to <repo> [--auto] [--quality-gate]` - Create rule
- `rule delete <id>` - Delete rule

### `ak approval` - Approval workflows for promotions
- `list [--status pending|approved|rejected]` - List approvals
- `show <id>` - Approval details
- `approve <id> [--comment]` - Approve
- `reject <id> [--comment]` - Reject

### `ak quality-gate` - Artifact quality enforcement
- `list` - List gates
- `show <id>` - Gate details with conditions
- `create <name> --max-critical <n> --max-high <n> [--action warn|block]` - Create gate
- `update <id> [flags]` - Update gate
- `delete <id>` - Delete gate
- `check <artifact> [--repo]` - Manually check artifact against gates

### `ak lifecycle` - Retention and cleanup policies
- `list` - List policies
- `show <id>` - Policy details
- `create <name> --type <max_age_days|max_versions|no_downloads_days|size_quota> --config <json>` - Create policy
- `delete <id>` - Delete policy
- `preview <id>` - Dry-run showing what would be cleaned up
- `execute <id>` - Run policy now

### `ak label` - Tag repos and artifacts
- `repo add <repo> <key=value>` - Add label to repo
- `repo remove <repo> <key>` - Remove label
- `repo list <repo>` - List labels on repo
- `artifact add <artifact> <key=value>` - Add label to artifact
- `artifact remove <artifact> <key>` - Remove label

### Enhanced `ak admin users`
- `update <username> --admin=true|false --email <email>` - Update user
- `reset-password <username>` - Reset password

### TUI: Approvals panel
- Accessible via hotkey from main dashboard
- Shows pending approvals with approve/reject actions inline

## v0.6 - Security & Signing

### `ak sign` - Artifact signing
- `<artifact> --repo <repo> [--key <path>] [--keyless]` - Sign an artifact
- `verify <artifact> --repo <repo> [--key <path>]` - Verify signature
- `list <artifact> --repo <repo>` - List signatures
- `delete <artifact> --repo <repo> <signature-id>` - Remove signature

### `ak sbom` - Software Bill of Materials
- `generate <artifact> --repo <repo> [--format spdx|cyclonedx]` - Generate SBOM
- `show <artifact> --repo <repo>` - View SBOM
- `export <artifact> --repo <repo> --output <path> [--format spdx-json|cyclonedx-json]` - Export to file
- `list --repo <repo>` - List artifacts with SBOMs

### `ak license` - License policy enforcement
- `policy list` - List license policies
- `policy create <name> --allowed <licenses...> [--blocked <licenses...>]` - Create policy
- `policy delete <id>` - Delete policy
- `check <artifact> --repo <repo>` - Check artifact licenses against policies

### `ak dependency-track` (alias: `ak dt`) - Dependency-Track integration
- `project list` - List DT projects
- `project show <uuid>` - Project details with risk score
- `finding list <project-uuid> [--severity critical|high|medium|low]` - List findings
- `sync <repo>` - Trigger DT sync for a repository

### Enhanced `ak scan`
- `run <artifact> --repo <repo> [--scanner trivy|grype|openscap]` - Add scanner selection
- `export <scan-id> --format sarif|json|csv --output <path>` - Export results
- `policy list` - List scan policies
- `policy create <name> --fail-on <severity> --scanner <scanner>` - Create policy

### TUI: Security findings panel
- Shows recent scan findings grouped by severity
- Drill-down to individual vulnerabilities

## v0.7 - Federation & Replication

### `ak peer` - Peer instance management
- `list` - List registered peers
- `show <id>` - Peer details (status, region, last sync)
- `register <name> --url <endpoint> --api-key <key> [--region]` - Register peer
- `unregister <id>` - Remove peer
- `test <id>` - Test connectivity
- `sync <id>` - Trigger sync

### `ak replication` - Replication rules
- `list [--peer <id>]` - List rules
- `show <id>` - Rule details
- `create --peer <id> --repo <repo> --mode push|pull|mirror [--schedule <cron>]` - Create rule
- `delete <id>` - Delete rule
- `trigger <id>` - Run replication now
- `status <id>` - Check last sync status

### `ak sync-policy` - Automated replication policies
- `list` - List policies
- `create <name> --source <repo> --target <peer:repo> --schedule <cron> [--filter <pattern>]` - Create
- `delete <id>` - Delete

### `ak webhook` - Event-driven integrations
- `list` - List webhooks
- `show <id>` - Details with delivery history
- `create <name> --url <url> --events <event1,event2,...> [--secret] [--repo]` - Create
- `delete <id>` - Delete
- `test <id>` - Send test event
- `enable <id>` / `disable <id>` - Toggle
- `deliveries <id>` - List recent deliveries

### TUI: Replication status panel
- Shows peer status (online/offline/syncing)
- Last sync times and replication health

## v0.8 - Admin & Analytics

### `ak analytics` - Usage and storage analytics
- `downloads [--repo] [--format] [--period 7d|30d|90d]` - Download stats
- `storage [--repo] [--format]` - Storage usage breakdown
- `top-packages [--limit 10] [--period 30d]` - Most downloaded packages
- `growth [--period 90d]` - Storage growth trend

### `ak sso` - SSO provider management
- `list` - List providers
- `show <id>` - Provider details
- `create oidc --name <name> --issuer <url> --client-id <id> --client-secret <secret>` - Add OIDC
- `create saml --name <name> --metadata-url <url>` - Add SAML
- `create ldap --name <name> --url <url> --base-dn <dn>` - Add LDAP
- `delete <id>` - Remove provider
- `test <id>` - Test connectivity

### `ak profile` - User profile management
- `show` - Current user profile
- `update --display-name <name> --email <email>` - Update profile
- `change-password` - Interactive password change

### `ak totp` - Two-factor authentication
- `enable` - Enable 2FA (shows QR code in terminal)
- `disable` - Disable 2FA
- `status` - Check 2FA status

### Enhanced `ak admin`
- `audit [--user] [--action] [--since]` - View audit log
- `storage gc [--dry-run]` - Run storage garbage collection
- `telemetry show` - View telemetry data
- `telemetry enable|disable` - Toggle telemetry

### TUI: Analytics panel
- ASCII charts for download trends and storage usage

## v0.9 - Testing Infrastructure

- **Integration test framework**: Docker-compose stack for E2E tests (shared pattern with artifact-keeper-web)
- **CLI output snapshot tests**: Using `insta` crate for table/JSON/YAML output validation
- **E2E test suite**: One integration test per command group against a real backend
- **CI pipeline update**: Add E2E test job that spins up backend stack
- **Test seeding**: Shared test data creation module

## v1.0 - Stable Release

- Gap analysis: verify every backend API endpoint has a CLI command
- Breaking changes cleanup: finalize command names, flag names, output formats
- Shell completion updates for all new commands
- Man page regeneration
- CHANGELOG and migration guide from v0.4 to v1.0
- CLI reference documentation on the Astro docs site
- Full TUI overhaul with all panels integrated

## Estimated Command Count

| Category | Current (v0.4.3) | After v1.0 |
|----------|-----------------|-----------|
| Top-level commands | 13 | 25+ |
| Leaf operations | 50+ | 150+ |
| TUI panels | 3 (instances, repos, artifacts) | 7+ (+ approvals, security, replication, analytics) |
| Unit tests | 251 | 500+ |
| E2E integration tests | 0 | 100+ |

## Architecture Notes

- All new commands follow the existing pattern: async fn in a command module, clap derive struct, SDK client call, unified output rendering
- New command modules go in `src/commands/` (one file per top-level command)
- The generated SDK already has typed methods for every backend endpoint; the work is wiring them to clap args with good UX
- TUI panels follow the existing ratatui pattern with keyboard navigation and drill-down
- E2E tests use the same docker-compose stack as the web frontend tests
