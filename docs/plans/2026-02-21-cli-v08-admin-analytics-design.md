# v0.8 Admin & Analytics Design

**Date:** 2026-02-21
**Status:** Approved
**Scope:** artifact-keeper-cli v0.8

## Goal

Add admin tooling and analytics commands covering SSO provider management, user profile/TOTP, telemetry, and usage analytics. Brings the CLI to near-complete backend API coverage.

## New Commands

### `ak analytics` (ClientAnalyticsExt, 7 subcommands)

| Subcommand | SDK Method | Description |
|------------|-----------|-------------|
| `downloads [--from] [--to]` | `get_download_trends` | Download trend over time |
| `storage` | `get_storage_breakdown` | Storage breakdown by repo |
| `growth [--from] [--to]` | `get_growth_summary` | Artifacts/storage/downloads growth |
| `storage-trend [--from] [--to]` | `get_storage_trend` | Storage trend over time |
| `top-stale [--days N] [--limit N]` | `get_stale_artifacts` | Stale artifacts (no recent downloads) |
| `repo-trend <id> [--from] [--to]` | `get_repository_trend` | Per-repo download trend |
| `snapshot` | `capture_snapshot` | Capture analytics snapshot |

Key types: DownloadTrend, GrowthSummary, StaleArtifact, RepositoryStorageBreakdown.

### `ak sso` (ClientSsoExt, 7 subcommands, 3 provider types)

Unified interface for LDAP, OIDC, and SAML providers.

| Subcommand | Description |
|------------|-------------|
| `list` | List all SSO providers (combined LDAP+OIDC+SAML) |
| `show <id>` | Provider details (auto-detects type) |
| `create ldap\|oidc\|saml <name> [flags]` | Create provider |
| `update <id> [flags]` | Update provider |
| `delete <id>` | Delete provider |
| `test <id>` | Test connectivity (LDAP only) |
| `toggle <id> --enable\|--disable` | Enable/disable provider |

Key types: LdapConfigResponse, OidcConfigResponse, SamlConfigResponse, LdapTestResult.

### `ak profile` (ClientUsersExt, 4 subcommands)

| Subcommand | SDK Method | Description |
|------------|-----------|-------------|
| `show` | `get_user` (self) | Current user profile |
| `update [--display-name] [--email]` | `update_user` | Update own profile |
| `change-password` | `change_password` | Change password |
| `tokens list\|create\|revoke` | `list_user_tokens`, etc. | Manage API tokens |

### `ak totp` (ClientAuthExt TOTP methods, 4 subcommands)

| Subcommand | SDK Method | Description |
|------------|-----------|-------------|
| `setup` | `setup_totp` | Start TOTP setup (secret + QR URL) |
| `enable --code CODE` | `enable_totp` | Verify code, enable, show backup codes |
| `disable --password PW --code CODE` | `disable_totp` | Disable TOTP |
| `status` | `get_user` (check totp_enabled) | Check TOTP status |

### Enhanced `ak admin` (ClientAdminExt + ClientTelemetryExt)

New subcommands added to existing admin.rs:

| Subcommand | SDK Method | Description |
|------------|-----------|-------------|
| `cleanup [--dry-run]` | `run_cleanup` | Storage garbage collection |
| `reindex` | `trigger_reindex` | Trigger search reindex |
| `stats` | `get_system_stats` | System statistics |
| `settings show` | `get_settings` | View admin settings |
| `settings update` | `update_settings` | Update settings |
| `telemetry show` | `get_telemetry_settings` | Telemetry settings |
| `telemetry update` | `update_telemetry_settings` | Update telemetry |
| `telemetry crashes` | `list_crashes` | List crash reports |
| `telemetry submit` | `submit_crashes` | Submit crash reports |

### TUI: Analytics Panel (hotkey 6)

- Storage breakdown by repository
- Growth summary stats
- Accessible via hotkey 6 and Tab cycling through all 6 panels

## Architecture

Same patterns as v0.5-v0.7: clap derive enums, async handlers, format helpers, wiremock tests. SSO uses a unified list view that merges all three provider types with a "type" column.

## Testing

Same three-tier strategy: parsing tests, format function tests, wiremock handler tests. Target 80%+ coverage on new code.
