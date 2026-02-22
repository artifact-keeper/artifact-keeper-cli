# v0.8 Admin & Analytics Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add analytics, SSO, profile, TOTP, and enhanced admin commands to bring the CLI to near-complete backend API coverage. Bump version to 0.8.0.

**Architecture:** Same pattern as v0.5-v0.7: clap derive enums in command modules, async handler functions calling the generated SDK, pure format helper functions for table/detail rendering, wiremock-based tests. Each command module is a single file in `src/commands/`. SSO uses a unified list view merging LDAP/OIDC/SAML providers. The existing `admin.rs` gets new subcommands for stats, reindex, settings, and telemetry.

**Tech Stack:** Rust, clap 4 (derive), artifact-keeper-sdk (Progenitor-generated), comfy-table, wiremock 0.6, ratatui (TUI)

---

## Task 1: `ak analytics` command module

**Files:**
- Create: `src/commands/analytics.rs`
- Modify: `src/commands/mod.rs` (add `pub mod analytics;`)
- Modify: `src/cli.rs` (add `Analytics` variant to `Command` enum, match arm, parsing tests)

**Context:**
- SDK trait: `ClientAnalyticsExt` (7 methods)
- Key types: `DownloadTrend` (date, download_count), `GrowthSummary` (9 fields), `StaleArtifact` (9 fields), `RepositoryStorageBreakdown` (7 fields)
- All methods use the builder pattern: `client.method().param(val).send().await`
- Import `ClientAnalyticsExt` from `artifact_keeper_sdk`
- Use `chrono::NaiveDate` for date fields in types
- `from`/`to` parameters are `Option<String>` on the SDK builders (formatted as date strings)

**Subcommands (7):**

```rust
#[derive(Subcommand)]
pub enum AnalyticsCommand {
    /// Show download trends over time
    Downloads {
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
    },
    /// Show storage breakdown by repository
    Storage,
    /// Show growth summary (artifacts, storage, downloads)
    Growth {
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
    },
    /// Show storage trend over time
    StorageTrend {
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
    },
    /// Show stale artifacts with no recent downloads
    TopStale {
        /// Minimum days since last download
        #[arg(long, default_value = "90")]
        days: i32,
        /// Maximum results to return
        #[arg(long, default_value = "20")]
        limit: i64,
    },
    /// Show download trend for a specific repository
    RepoTrend {
        /// Repository ID
        id: String,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
    },
    /// Capture an analytics snapshot
    Snapshot,
}
```

**Handler functions (7):** Each follows the pattern: `client_for(global)? -> spinner -> SDK call -> spinner.finish -> quiet check -> format -> print`.

**Format helpers (4 pure functions):**
- `format_downloads_table(items: &[DownloadTrend]) -> String` - Table: Date | Downloads
- `format_storage_table(items: &[RepositoryStorageBreakdown]) -> String` - Table: Repo | Format | Artifacts | Storage | Downloads | Last Upload
- `format_growth_detail(summary: &GrowthSummary) -> String` - Key-value detail view
- `format_stale_table(items: &[StaleArtifact]) -> String` - Table: Name | Repo | Size | Downloads | Days Stale | Last Downloaded

**Tests:**
- Parsing tests (~10): one per subcommand + variants with flags
- Format tests (~8): empty lists, populated data, edge cases
- Wiremock handler tests (~7): one per subcommand
- Target: 25+ tests

**CLI wiring in `src/cli.rs`:**
```rust
/// Usage analytics and storage insights
#[command(
    after_help = "Examples:\n  ak analytics downloads --from 2026-01-01\n  ak analytics storage\n  ak analytics growth\n  ak analytics top-stale --days 30 --limit 10"
)]
Analytics {
    #[command(subcommand)]
    command: commands::analytics::AnalyticsCommand,
},
```
Add match arm: `Command::Analytics { command } => command.execute(&global).await,`

**Commit message:** `feat(v0.8): add ak analytics command for usage insights`

---

## Task 2: `ak sso` command module

**Files:**
- Create: `src/commands/sso.rs`
- Modify: `src/commands/mod.rs` (add `pub mod sso;`)
- Modify: `src/cli.rs` (add `Sso` variant, match arm, parsing tests)

**Context:**
- SDK trait: `ClientSsoExt` (27 methods across LDAP/OIDC/SAML)
- The SDK has separate methods per provider type: `list_ldap()`, `list_oidc()`, `list_saml()`, `create_ldap()`, `create_oidc()`, `create_saml()`, etc.
- Key types: `LdapConfigResponse`, `OidcConfigResponse`, `SamlConfigResponse`, `LdapTestResult`
- The `list` subcommand should merge all three provider types into one unified table with a "Type" column
- `create` uses nested subcommands: `create ldap`, `create oidc`, `create saml`
- Provider show/update/delete/toggle need to try all three types (or use a `--type` flag). Recommendation: use `--type ldap|oidc|saml` flag to avoid trial-and-error.
- `toggle` uses `ToggleLdap`/`ToggleOidc`/`ToggleSaml` (each takes a body with `is_enabled: bool`)
- `test` is LDAP-only (`test_ldap`)

**Subcommands (7 + 3 create variants):**

```rust
#[derive(Subcommand)]
pub enum SsoCommand {
    /// List all SSO providers (LDAP, OIDC, SAML)
    List,
    /// Show SSO provider details
    Show {
        id: String,
        #[arg(long, value_parser = ["ldap", "oidc", "saml"])]
        r#type: String,
    },
    /// Create an SSO provider
    Create {
        #[command(subcommand)]
        command: SsoCreateCommand,
    },
    /// Update an SSO provider
    Update {
        id: String,
        #[arg(long, value_parser = ["ldap", "oidc", "saml"])]
        r#type: String,
        // update flags vary, use JSON body for simplicity
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Delete an SSO provider
    Delete {
        id: String,
        #[arg(long, value_parser = ["ldap", "oidc", "saml"])]
        r#type: String,
        #[arg(long)]
        yes: bool,
    },
    /// Test SSO provider connectivity (LDAP only)
    Test {
        id: String,
    },
    /// Enable or disable an SSO provider
    Toggle {
        id: String,
        #[arg(long, value_parser = ["ldap", "oidc", "saml"])]
        r#type: String,
        #[arg(long)]
        enable: bool,
    },
}

#[derive(Subcommand)]
pub enum SsoCreateCommand {
    /// Create LDAP provider
    Ldap {
        name: String,
        #[arg(long)]
        server_url: String,
        #[arg(long)]
        user_base_dn: String,
        #[arg(long)]
        bind_dn: Option<String>,
        #[arg(long)]
        bind_password: Option<String>,
        #[arg(long)]
        use_starttls: bool,
    },
    /// Create OIDC provider
    Oidc {
        name: String,
        #[arg(long)]
        issuer_url: String,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        client_secret: String,
        #[arg(long)]
        auto_create_users: bool,
    },
    /// Create SAML provider
    Saml {
        name: String,
        #[arg(long)]
        entity_id: String,
        #[arg(long)]
        sso_url: String,
        #[arg(long)]
        certificate: String,
        #[arg(long)]
        sign_requests: bool,
    },
}
```

**Handler functions (7):** `list_providers`, `show_provider`, `create_ldap_provider`, `create_oidc_provider`, `create_saml_provider`, `delete_provider`, `test_provider`, `toggle_provider`

**Format helpers (3):**
- `format_providers_table(ldap: &[LdapConfigResponse], oidc: &[OidcConfigResponse], saml: &[SamlConfigResponse]) -> String` - unified table with Type column
- `format_provider_detail_ldap(p: &LdapConfigResponse) -> String`
- `format_provider_detail_oidc(p: &OidcConfigResponse) -> String`
- `format_provider_detail_saml(p: &SamlConfigResponse) -> String`
- `format_test_result(r: &LdapTestResult) -> String`

**Tests:**
- Parsing tests (~12): each subcommand + create variants + flag combos
- Format tests (~10): empty, mixed providers, detail views per type
- Wiremock handler tests (~8): list (merges 3 calls), show, create ldap/oidc/saml, delete, test, toggle
- Target: 30+ tests

**CLI wiring in `src/cli.rs`:**
```rust
/// Manage SSO authentication providers (LDAP, OIDC, SAML)
#[command(
    after_help = "Examples:\n  ak sso list\n  ak sso show <id> --type oidc\n  ak sso create ldap corp-ldap --server-url ldaps://ldap.corp.com --user-base-dn ou=users,dc=corp\n  ak sso create oidc okta --issuer-url https://corp.okta.com --client-id abc --client-secret xyz\n  ak sso test <id>\n  ak sso toggle <id> --type ldap --enable"
)]
Sso {
    #[command(subcommand)]
    command: commands::sso::SsoCommand,
},
```

**Commit message:** `feat(v0.8): add ak sso command for SSO provider management`

---

## Task 3: `ak profile` command module

**Files:**
- Create: `src/commands/profile.rs`
- Modify: `src/commands/mod.rs` (add `pub mod profile;`)
- Modify: `src/cli.rs` (add `Profile` variant, match arm, parsing tests)

**Context:**
- SDK trait: `ClientUsersExt` (already imported in admin.rs)
- `profile show` needs the current user's ID. Use `client.whoami()` from `ClientAuthExt` to get it, then `client.get_user().id(user_id).send()`.
- `profile update` uses `client.update_user().id(user_id)` with optional fields
- `profile change-password` uses `client.change_password().id(user_id)` with old + new password body
- Token management: `list_user_tokens`, `create_user_api_token`, `revoke_user_api_token`
- Key types: `UserResponse` (id, username, email, display_name, is_admin, totp_enabled), `CreateApiTokenRequest`, `CreateApiTokenResponse`
- Import both `ClientUsersExt` and `ClientAuthExt`

**Subcommands (4, with token sub-subcommands):**

```rust
#[derive(Subcommand)]
pub enum ProfileCommand {
    /// Show your profile
    Show,
    /// Update your profile
    Update {
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        email: Option<String>,
    },
    /// Change your password
    ChangePassword,
    /// Manage your API tokens
    Tokens {
        #[command(subcommand)]
        command: TokenCommand,
    },
}

#[derive(Subcommand)]
pub enum TokenCommand {
    /// List your API tokens
    List,
    /// Create a new API token
    Create {
        /// Token name
        name: String,
        /// Comma-separated scopes
        #[arg(long)]
        scopes: String,
        /// Token expiration in days
        #[arg(long)]
        expires_in_days: Option<i64>,
    },
    /// Revoke an API token
    Revoke {
        /// Token ID
        id: String,
    },
}
```

**Handler functions (6):** `show_profile`, `update_profile`, `change_password`, `list_tokens`, `create_token`, `revoke_token`

**Note on `change_password`:** This should prompt interactively for old and new passwords using `dialoguer::Password` (already a dependency). In `--no-input` mode, print error.

**Format helpers (2):**
- `format_profile_detail(user: &UserResponse) -> String`
- `format_tokens_table(tokens: &[ApiTokenResponse]) -> String` - NOTE: check actual SDK type name for token list items

**Tests:**
- Parsing tests (~8): each subcommand + token variants
- Format tests (~4): profile detail, token table empty/populated
- Wiremock handler tests (~6): show, update, list tokens, create token, revoke token
- Target: 18+ tests

**CLI wiring in `src/cli.rs`:**
```rust
/// Manage your user profile and API tokens
#[command(
    after_help = "Examples:\n  ak profile show\n  ak profile update --display-name \"Alice Smith\"\n  ak profile change-password\n  ak profile tokens list\n  ak profile tokens create ci-token --scopes read,write"
)]
Profile {
    #[command(subcommand)]
    command: commands::profile::ProfileCommand,
},
```

**Commit message:** `feat(v0.8): add ak profile command for user profile management`

---

## Task 4: `ak totp` command module

**Files:**
- Create: `src/commands/totp.rs`
- Modify: `src/commands/mod.rs` (add `pub mod totp;`)
- Modify: `src/cli.rs` (add `Totp` variant, match arm, parsing tests)

**Context:**
- SDK trait: `ClientAuthExt` (4 TOTP methods: `setup_totp`, `enable_totp`, `disable_totp`, `verify_totp`)
- `setup_totp` returns `TotpSetupResponse` with `secret` and `qr_code_url` fields
- `enable_totp` takes `TotpCodeRequest { code }`, returns `TotpEnableResponse { backup_codes: Vec<String> }`
- `disable_totp` takes `TotpDisableRequest { password, code }`
- `status` is derived: call `whoami()` to get user ID, then `get_user()` to check `totp_enabled` field
- For `status`, import `ClientUsersExt` alongside `ClientAuthExt`
- The `setup` command should display the secret prominently and the QR URL for the user to open

**Subcommands (4):**

```rust
#[derive(Subcommand)]
pub enum TotpCommand {
    /// Set up TOTP (displays secret and QR code URL)
    Setup,
    /// Enable TOTP after verifying a code from your authenticator app
    Enable {
        /// TOTP code from your authenticator app
        #[arg(long)]
        code: String,
    },
    /// Disable TOTP
    Disable {
        /// Your account password
        #[arg(long)]
        password: String,
        /// Current TOTP code
        #[arg(long)]
        code: String,
    },
    /// Check if TOTP is enabled on your account
    Status,
}
```

**Handler functions (4):** `setup_totp`, `enable_totp`, `disable_totp`, `totp_status`

**Format helpers (2):**
- `format_setup_result(resp: &TotpSetupResponse) -> String` - Shows secret + QR URL prominently
- `format_backup_codes(resp: &TotpEnableResponse) -> String` - Lists backup codes with warning

**Tests:**
- Parsing tests (~5): each subcommand + flag variants
- Format tests (~4): setup result, backup codes empty/populated
- Wiremock handler tests (~4): setup, enable, disable, status
- Target: 13+ tests

**CLI wiring in `src/cli.rs`:**
```rust
/// Manage two-factor authentication (TOTP)
#[command(
    after_help = "Examples:\n  ak totp setup\n  ak totp enable --code 123456\n  ak totp disable --code 123456\n  ak totp status"
)]
Totp {
    #[command(subcommand)]
    command: commands::totp::TotpCommand,
},
```

**Commit message:** `feat(v0.8): add ak totp command for two-factor authentication`

---

## Task 5: Enhanced `ak admin` (add subcommands to existing module)

**Files:**
- Modify: `src/commands/admin.rs` (add new subcommands, handlers, format helpers, tests)
- Modify: `src/cli.rs` (add parsing tests for new subcommands)

**Context:**
- `admin.rs` already exists with BackupCommand, Cleanup, Metrics, UsersCommand, PluginsCommand
- SDK traits: `ClientAdminExt` (already imported), add `ClientTelemetryExt`
- New subcommands to add to `AdminCommand` enum: Reindex, Stats, Settings, Telemetry
- Key types: `TelemetrySettings` (enabled, include_logs, review_before_send, scrub_level), `CrashReport` (many fields), `CrashListResponse`
- `run_cleanup` is already wired as `Cleanup` subcommand; just verify it works
- The existing `Metrics` subcommand can be replaced/enhanced with `Stats` using `get_system_stats`
- Settings: `get_settings` / `update_settings` return/accept JSON
- Telemetry is a nested subcommand group

**New subcommands to add:**

```rust
// Add to AdminCommand enum:

/// Trigger search index rebuild
Reindex,

/// Show system statistics
Stats,

/// Manage server settings
Settings {
    #[command(subcommand)]
    command: SettingsCommand,
},

/// Manage telemetry and crash reporting
Telemetry {
    #[command(subcommand)]
    command: TelemetryCommand,
},
```

```rust
#[derive(Subcommand)]
pub enum SettingsCommand {
    /// Show current settings
    Show,
    /// Update settings (provide JSON body)
    Update {
        /// Settings JSON
        #[arg(long)]
        json: String,
    },
}

#[derive(Subcommand)]
pub enum TelemetryCommand {
    /// Show telemetry settings
    Show,
    /// Update telemetry settings
    Update {
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        include_logs: Option<bool>,
        #[arg(long)]
        review_before_send: Option<bool>,
        #[arg(long)]
        scrub_level: Option<String>,
    },
    /// List crash reports
    Crashes {
        #[arg(long)]
        pending: bool,
        #[arg(long, default_value = "1")]
        page: i32,
        #[arg(long, default_value = "20")]
        per_page: i32,
    },
    /// Submit crash reports
    Submit {
        /// Crash report IDs (comma-separated)
        ids: String,
    },
}
```

**Handler functions (7):** `reindex`, `system_stats`, `settings_show`, `settings_update`, `telemetry_show`, `telemetry_update`, `telemetry_crashes`, `telemetry_submit`

**Format helpers (3):**
- `format_telemetry_settings(s: &TelemetrySettings) -> String`
- `format_crashes_table(items: &[CrashReport]) -> String`
- `format_crash_detail(c: &CrashReport) -> String`

**Tests:**
- Parsing tests (~10): new subcommands in cli.rs
- Format tests (~6): telemetry settings, crash table, crash detail
- Wiremock handler tests (~8): reindex, stats, settings show/update, telemetry show/update, crashes, submit
- Target: 24+ tests

**Commit message:** `feat(v0.8): enhance ak admin with stats, settings, reindex, and telemetry`

---

## Task 6: TUI Analytics panel, version bump, final verification

**Files:**
- Modify: `src/commands/tui.rs` (add Analytics panel)
- Modify: `Cargo.toml` (version 0.7.0 -> 0.8.0)
- Modify: `src/cli.rs` (add any remaining parsing tests)

**TUI changes:**
- Add `Analytics` variant to `Panel` enum (after `Replication`)
- Add `AnalyticsState` struct: `storage: Vec<RepositoryStorageBreakdown>, growth: Option<GrowthSummary>, storage_list_state: ListState, loaded: bool`
- Add `analytics: AnalyticsState` field to `App`
- Add `load_analytics_data()` async method (fetches storage breakdown + growth summary)
- Import `ClientAnalyticsExt`, `RepositoryStorageBreakdown`, `GrowthSummary`
- Update `active_list_state_mut()` for Analytics
- Update `move_left()`, `move_right()` for Analytics
- Update Tab cycling: Replication -> Analytics -> Instances
- Add hotkey `6` for Analytics
- Add `draw_analytics_panel()`: left half = storage breakdown table, right half = growth summary detail
- Update draw(), status bar, help overlay, refresh, Enter/Esc handlers
- Follow exact same pattern as the Replication panel added in v0.7

**TUI tests:**
- Add tests for any new pure functions (analytics-related styles if any)

**Version bump:** `Cargo.toml` version field: `"0.7.0"` -> `"0.8.0"`

**Final verification:**
- `cargo fmt`
- `cargo clippy --workspace -- -D warnings -A dead_code`
- `cargo test --workspace` (expect 1,172+ existing + ~110 new = 1,280+ total)
- All passing, no warnings

**Commit message:** `feat(v0.8): add TUI analytics panel, version bump to 0.8.0`

---

## Summary

| Task | Module | New Tests | Key SDK Traits |
|------|--------|-----------|----------------|
| 1 | analytics.rs | ~25 | ClientAnalyticsExt |
| 2 | sso.rs | ~30 | ClientSsoExt |
| 3 | profile.rs | ~18 | ClientUsersExt, ClientAuthExt |
| 4 | totp.rs | ~13 | ClientAuthExt |
| 5 | admin.rs (enhanced) | ~24 | ClientAdminExt, ClientTelemetryExt |
| 6 | tui.rs + version | ~5 | ClientAnalyticsExt |
| **Total** | **5 modules** | **~115** | **6 traits** |

Expected final test count: ~1,287 (1,172 existing + ~115 new)
