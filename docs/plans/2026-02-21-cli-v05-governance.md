# CLI v0.5 Governance & Compliance - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 8 new command groups to the CLI (group, permission, service-account, promotion, approval, quality-gate, lifecycle, label) plus enhanced admin user management, bringing governance feature parity with the web UI.

**Architecture:** Each command group is a new module in `src/commands/` following the existing pattern: clap `#[derive(Subcommand)]` enum, `execute(&GlobalArgs)` dispatcher, individual async functions calling the generated SDK (Progenitor), and unified `output::render()` for table/JSON/YAML output. All SDK extension traits are already generated except service accounts.

**Tech Stack:** Rust, clap 4 (derive), artifact-keeper-sdk (Progenitor), comfy-table, miette, tokio

**Design doc:** `docs/plans/2026-02-21-cli-roadmap-design.md`

---

## Task 1: Regenerate SDK and verify governance traits

**Files:**
- Modify: `sdk/src/generated_sdk.rs` (regenerated, do not hand-edit)

The SDK may be stale. Regenerate it from the latest OpenAPI spec to ensure all governance traits are present.

**Step 1: Regenerate the SDK**

Run: `cd /Users/khan/ak/artifact-keeper-cli && cargo run -p xtask -- generate`
Expected: SDK regenerated successfully.

**Step 2: Verify governance traits exist**

Run: `grep "trait Client.*Ext" sdk/src/generated_sdk.rs | sort`

Verify these traits are present:
- `ClientGroupsExt`
- `ClientPermissionsExt`
- `ClientPromotionExt`
- `ClientApprovalExt`
- `ClientQualityExt`
- `ClientLifecycleExt`
- `ClientRepositoryLabelsExt`

If `ClientServiceAccountsExt` is missing, note it. Service account commands will use raw HTTP calls or we skip them for now.

**Step 3: Build to verify SDK compiles**

Run: `cargo build --workspace`
Expected: Build succeeds.

**Step 4: Commit if SDK changed**

```bash
git add sdk/src/generated_sdk.rs
git commit -m "chore: regenerate SDK from latest OpenAPI spec"
```

---

## Task 2: Add `ak group` command - clap structs and wiring

**Files:**
- Create: `src/commands/group.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`

**Step 1: Write CLI parsing tests in `src/cli.rs`**

Add to the existing `#[cfg(test)] mod tests` block at the bottom of `cli.rs`:

```rust
#[test]
fn parse_group_list() {
    let cli = parse(&["ak", "group", "list"]).unwrap();
    assert!(matches!(cli.command, Command::Group { .. }));
}

#[test]
fn parse_group_show() {
    let cli = parse(&["ak", "group", "show", "dev-team"]).unwrap();
    assert!(matches!(cli.command, Command::Group { .. }));
}

#[test]
fn parse_group_create() {
    let cli = parse(&["ak", "group", "create", "dev-team"]).unwrap();
    assert!(matches!(cli.command, Command::Group { .. }));
}

#[test]
fn parse_group_delete() {
    let cli = parse(&["ak", "group", "delete", "dev-team"]).unwrap();
    assert!(matches!(cli.command, Command::Group { .. }));
}

#[test]
fn parse_group_add_member() {
    let cli = parse(&["ak", "group", "add-member", "dev-team", "alice"]).unwrap();
    assert!(matches!(cli.command, Command::Group { .. }));
}

#[test]
fn parse_group_remove_member() {
    let cli = parse(&["ak", "group", "remove-member", "dev-team", "alice"]).unwrap();
    assert!(matches!(cli.command, Command::Group { .. }));
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib parse_group -- 2>&1 | head -20`
Expected: FAIL (Command::Group doesn't exist yet)

**Step 3: Create `src/commands/group.rs`**

```rust
use artifact_keeper_sdk::ClientGroupsExt;
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::{IntoDiagnostic, Result};

use super::client::client_for;
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum GroupCommand {
    /// List all groups
    List {
        /// Search by name
        #[arg(long)]
        search: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: i32,

        /// Results per page
        #[arg(long, default_value = "50")]
        per_page: i32,
    },

    /// Show group details
    Show {
        /// Group name or ID
        name: String,
    },

    /// Create a new group
    Create {
        /// Group name
        name: String,

        /// Description
        #[arg(long)]
        description: Option<String>,

        /// Auto-join new users to this group
        #[arg(long)]
        auto_join: bool,
    },

    /// Delete a group
    Delete {
        /// Group name or ID
        name: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Add a user to a group
    AddMember {
        /// Group name or ID
        group: String,

        /// Username or user ID to add
        user: String,
    },

    /// Remove a user from a group
    RemoveMember {
        /// Group name or ID
        group: String,

        /// Username or user ID to remove
        user: String,
    },
}

impl GroupCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { search, page, per_page } => list_groups(search.as_deref(), page, per_page, global).await,
            Self::Show { name } => show_group(&name, global).await,
            Self::Create { name, description, auto_join } => create_group(&name, description.as_deref(), auto_join, global).await,
            Self::Delete { name, yes } => delete_group(&name, yes, global).await,
            Self::AddMember { group, user } => add_member(&group, &user, global).await,
            Self::RemoveMember { group, user } => remove_member(&group, &user, global).await,
        }
    }
}

async fn list_groups(search: Option<&str>, page: i32, per_page: i32, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let sp = output::spinner("Fetching groups...");

    let mut req = client.list_groups().page(page as u32).per_page(per_page as u32);
    if let Some(s) = search {
        req = req.search(s);
    }
    let resp = req.send().await.into_diagnostic()?;
    sp.finish_and_clear();

    let groups = resp.into_inner();

    if matches!(global.format, OutputFormat::Table) {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL_CONDENSED);
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec!["ID", "Name", "Description", "Members", "Auto-Join"]);
        for g in &groups {
            table.add_row(vec![
                g.id.to_string(),
                g.name.clone(),
                g.description.clone().unwrap_or_default(),
                g.member_count.map(|c| c.to_string()).unwrap_or_default(),
                if g.auto_join.unwrap_or(false) { "Yes" } else { "No" }.to_string(),
            ]);
        }
        println!("{}", output::render(&groups, &global.format, Some(table.to_string())));
    } else {
        println!("{}", output::render(&groups, &global.format, None));
    }

    Ok(())
}

async fn show_group(name: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let sp = output::spinner("Fetching group...");
    let resp = client.get_group().id(name).send().await.into_diagnostic()?;
    sp.finish_and_clear();

    let group = resp.into_inner();
    println!("{}", output::render(&group, &global.format, None));
    Ok(())
}

async fn create_group(name: &str, description: Option<&str>, auto_join: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let sp = output::spinner("Creating group...");

    let mut body = serde_json::json!({
        "name": name,
        "auto_join": auto_join,
    });
    if let Some(desc) = description {
        body["description"] = serde_json::Value::String(desc.to_string());
    }

    let resp = client.create_group().body_map(|b| b).send().await.into_diagnostic()?;
    sp.finish_and_clear();

    let group = resp.into_inner();
    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", group.id);
    } else {
        println!("{}", output::render(&group, &global.format, None));
    }
    Ok(())
}

async fn delete_group(name: &str, yes: bool, global: &GlobalArgs) -> Result<()> {
    if !yes && !global.no_input {
        let confirm = dialoguer::Confirm::new()
            .with_prompt(format!("Delete group '{name}'?"))
            .default(false)
            .interact()
            .into_diagnostic()?;
        if !confirm {
            println!("Aborted.");
            return Ok(());
        }
    }

    let client = client_for(global)?;
    let sp = output::spinner("Deleting group...");
    client.delete_group().id(name).send().await.into_diagnostic()?;
    sp.finish_and_clear();

    println!("Group '{name}' deleted.");
    Ok(())
}

async fn add_member(group: &str, user: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let sp = output::spinner("Adding member...");
    client.add_members().id(group).body_map(|b| b).send().await.into_diagnostic()?;
    sp.finish_and_clear();

    println!("Added '{user}' to group '{group}'.");
    Ok(())
}

async fn remove_member(group: &str, user: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let sp = output::spinner("Removing member...");
    client.remove_members().id(group).body_map(|b| b).send().await.into_diagnostic()?;
    sp.finish_and_clear();

    println!("Removed '{user}' from group '{group}'.");
    Ok(())
}
```

**Step 4: Add module to `src/commands/mod.rs`**

Add this line: `pub mod group;`

**Step 5: Wire into `src/cli.rs`**

Add the `Group` variant to the `Command` enum:

```rust
/// Manage user groups
#[command(
    after_help = "Examples:\n  ak group list\n  ak group show dev-team\n  ak group create dev-team --description \"Development team\"\n  ak group add-member dev-team alice"
)]
Group {
    #[command(subcommand)]
    command: commands::group::GroupCommand,
},
```

Add the match arm in `execute()`:

```rust
Command::Group { command } => command.execute(&global).await,
```

**Step 6: Run tests**

Run: `cargo test --lib parse_group`
Expected: All 6 group parsing tests PASS.

**Step 7: Commit**

```bash
git add src/commands/group.rs src/commands/mod.rs src/cli.rs
git commit -m "feat: add ak group command (list, show, create, delete, add-member, remove-member)"
```

---

## Task 3: Add `ak permission` command

**Files:**
- Create: `src/commands/permission.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`

Follow the exact same pattern as Task 2. The command module structure:

```rust
#[derive(Subcommand)]
pub enum PermissionCommand {
    List {
        #[arg(long)] repo: Option<String>,
        #[arg(long)] group: Option<String>,
        #[arg(long)] user: Option<String>,
        #[arg(long, default_value = "1")] page: i32,
        #[arg(long, default_value = "50")] per_page: i32,
    },
    Create {
        #[arg(long)] target: String,       // repo key or group name
        #[arg(long)] target_type: String,  // "repository" or "group"
        #[arg(long)] action: String,       // "read", "write", "admin"
        #[arg(long)] principal: String,    // user or group name
        #[arg(long)] principal_type: String, // "user" or "group"
    },
    Delete { id: String },
}
```

SDK trait: `ClientPermissionsExt` (list_permissions, create_permission, delete_permission).

**Step 1: Write 3 parsing tests** (parse_permission_list, parse_permission_create, parse_permission_delete)

**Step 2: Run to verify they fail**

**Step 3: Implement module, wire into mod.rs and cli.rs**

**Step 4: Run tests, verify PASS**

**Step 5: Commit**

```bash
git commit -m "feat: add ak permission command (list, create, delete)"
```

---

## Task 4: Add `ak promotion` command

**Files:**
- Create: `src/commands/promotion.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`

```rust
#[derive(Subcommand)]
pub enum PromotionCommand {
    /// Promote an artifact from one repo to another
    Promote {
        /// Artifact path or ID
        artifact: String,
        #[arg(long)] from: String,
        #[arg(long)] to: String,
        #[arg(long)] version: Option<String>,
    },
    /// Manage promotion rules
    Rule {
        #[command(subcommand)]
        command: PromotionRuleCommand,
    },
    /// View promotion history
    History {
        /// Repository key
        #[arg(long)] repo: String,
        #[arg(long)] status: Option<String>,
        #[arg(long, default_value = "1")] page: i32,
        #[arg(long, default_value = "20")] per_page: i32,
    },
}

#[derive(Subcommand)]
pub enum PromotionRuleCommand {
    List { #[arg(long)] from: Option<String> },
    Create {
        #[arg(long)] from: String,
        #[arg(long)] to: String,
        #[arg(long)] auto: bool,
        #[arg(long)] quality_gate: Option<String>,
    },
    Delete { id: String },
}
```

SDK trait: `ClientPromotionExt` (promote_artifact, list_rules, create_rule, delete_rule, promotion_history).

**Step 1: Write 5 parsing tests** (promote, rule list, rule create, rule delete, history)

**Step 2: Implement, wire, test, commit**

```bash
git commit -m "feat: add ak promotion command (promote, rule list/create/delete, history)"
```

---

## Task 5: Add `ak approval` command

**Files:**
- Create: `src/commands/approval.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`

```rust
#[derive(Subcommand)]
pub enum ApprovalCommand {
    List {
        #[arg(long)] status: Option<String>, // pending, approved, rejected
        #[arg(long)] repo: Option<String>,
        #[arg(long, default_value = "1")] page: i32,
        #[arg(long, default_value = "20")] per_page: i32,
    },
    Show { id: String },
    Approve { id: String, #[arg(long)] comment: Option<String> },
    Reject { id: String, #[arg(long)] comment: Option<String> },
}
```

SDK trait: `ClientApprovalExt` (list_pending_approvals, list_approval_history, get_approval, approve_promotion, reject_promotion).

**Step 1: Write 4 parsing tests**

**Step 2: Implement, wire, test, commit**

```bash
git commit -m "feat: add ak approval command (list, show, approve, reject)"
```

---

## Task 6: Add `ak quality-gate` command

**Files:**
- Create: `src/commands/quality_gate.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`

```rust
#[derive(Subcommand)]
pub enum QualityGateCommand {
    List,
    Show { id: String },
    Create {
        name: String,
        #[arg(long)] max_critical: Option<i32>,
        #[arg(long)] max_high: Option<i32>,
        #[arg(long)] max_medium: Option<i32>,
        #[arg(long)] action: Option<String>, // "allow", "warn", "block"
        #[arg(long)] description: Option<String>,
        #[arg(long)] repo: Option<String>,
        #[arg(long, value_delimiter = ',')] required_checks: Vec<String>,
    },
    Update {
        id: String,
        #[arg(long)] name: Option<String>,
        #[arg(long)] max_critical: Option<i32>,
        #[arg(long)] max_high: Option<i32>,
        #[arg(long)] action: Option<String>,
    },
    Delete { id: String },
    /// Check an artifact against quality gates
    Check {
        /// Artifact ID
        artifact: String,
        #[arg(long)] repo: Option<String>,
    },
}
```

SDK trait: `ClientQualityExt` (list_gates, get_gate, create_gate, update_gate, delete_gate, evaluate_gate).

**Step 1: Write 6 parsing tests**

**Step 2: Implement, wire, test, commit**

```bash
git commit -m "feat: add ak quality-gate command (list, show, create, update, delete, check)"
```

---

## Task 7: Add `ak lifecycle` command

**Files:**
- Create: `src/commands/lifecycle.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`

```rust
#[derive(Subcommand)]
pub enum LifecycleCommand {
    List { #[arg(long)] repo: Option<String> },
    Show { id: String },
    Create {
        name: String,
        #[arg(long)] r#type: String,  // max_age_days, max_versions, no_downloads_days, size_quota
        #[arg(long)] config: String,  // JSON string: {"max_age_days": 30}
        #[arg(long)] repo: Option<String>,
        #[arg(long)] description: Option<String>,
        #[arg(long, default_value = "0")] priority: i32,
    },
    Delete { id: String },
    /// Preview what a policy would clean up (dry-run)
    Preview { id: String },
    /// Execute a policy now
    Execute { id: String },
}
```

SDK trait: `ClientLifecycleExt` (list_lifecycle_policies, get_lifecycle_policy, create_lifecycle_policy, delete_lifecycle_policy, preview_policy, execute_policy).

**Step 1: Write 6 parsing tests**

**Step 2: Implement, wire, test, commit**

```bash
git commit -m "feat: add ak lifecycle command (list, show, create, delete, preview, execute)"
```

---

## Task 8: Add `ak label` command

**Files:**
- Create: `src/commands/label.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`

```rust
#[derive(Subcommand)]
pub enum LabelCommand {
    /// Manage repository labels
    Repo {
        #[command(subcommand)]
        command: RepoLabelCommand,
    },
}

#[derive(Subcommand)]
pub enum RepoLabelCommand {
    /// List labels on a repository
    List { key: String },
    /// Add a label to a repository
    Add {
        /// Repository key
        key: String,
        /// Label in key=value format
        label: String,
    },
    /// Remove a label from a repository
    Remove {
        /// Repository key
        key: String,
        /// Label key to remove
        label_key: String,
    },
}
```

SDK trait: `ClientRepositoryLabelsExt` (list_repo_labels, add_repo_label, delete_repo_label).

**Step 1: Write 3 parsing tests** (label repo list, add, remove)

**Step 2: Implement, wire, test, commit**

```bash
git commit -m "feat: add ak label command (repo list, add, remove)"
```

---

## Task 9: Enhance `ak admin users` with update and reset-password

**Files:**
- Modify: `src/commands/admin.rs`

**Step 1: Write 2 parsing tests**

```rust
#[test]
fn parse_admin_users_update() {
    let cli = parse(&["ak", "admin", "users", "update", "alice", "--email", "alice@new.com"]).unwrap();
    assert!(matches!(cli.command, Command::Admin { .. }));
}

#[test]
fn parse_admin_users_reset_password() {
    let cli = parse(&["ak", "admin", "users", "reset-password", "alice"]).unwrap();
    assert!(matches!(cli.command, Command::Admin { .. }));
}
```

**Step 2: Add variants to `UsersCommand` enum in `admin.rs`**

```rust
/// Update a user's details
Update {
    /// Username or user ID
    username: String,
    #[arg(long)] email: Option<String>,
    #[arg(long)] display_name: Option<String>,
    #[arg(long)] admin: Option<bool>,
},
/// Reset a user's password
ResetPassword {
    /// Username or user ID
    username: String,
},
```

**Step 3: Implement the execute handlers**

Use `ClientUsersExt` for update and password reset.

**Step 4: Run tests, verify PASS, commit**

```bash
git add src/commands/admin.rs src/cli.rs
git commit -m "feat: add ak admin users update and reset-password subcommands"
```

---

## Task 10: Update shell completions and man pages

**Step 1: Verify completions generate without errors**

Run: `cargo run -- completion bash > /dev/null`
Expected: No errors. All new commands appear in completions.

**Step 2: Generate man pages**

Run: `cargo run -- man-pages /tmp/ak-man && ls /tmp/ak-man/*.1 | wc -l`
Expected: Man page count increased (should include group, permission, promotion, etc.).

**Step 3: Commit (nothing to commit, this is a verification step)**

---

## Task 11: Run full test suite and fix any issues

**Step 1: Run all unit tests**

Run: `cargo test --workspace`
Expected: All tests pass (251 existing + ~35 new parsing tests).

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings -A dead_code`
Expected: No warnings.

**Step 3: Run fmt**

Run: `cargo fmt --check`
Expected: No formatting issues.

**Step 4: Build release**

Run: `cargo build --release`
Expected: Build succeeds.

---

## Task 12: Update CHANGELOG and prepare v0.5.0

**Files:**
- Modify: `CHANGELOG.md`

**Step 1: Add v0.5.0 section to CHANGELOG**

Add at the top of CHANGELOG.md:

```markdown
## [0.5.0] - YYYY-MM-DD

### Added
- `ak group` command: manage user groups (list, show, create, delete, add-member, remove-member)
- `ak permission` command: manage fine-grained permission rules (list, create, delete)
- `ak promotion` command: promote artifacts between repos (promote, rule management, history)
- `ak approval` command: approval workflows (list, show, approve, reject)
- `ak quality-gate` command: artifact quality enforcement (list, show, create, update, delete, check)
- `ak lifecycle` command: retention and cleanup policies (list, show, create, delete, preview, execute)
- `ak label` command: tag repositories with key-value labels (list, add, remove)
- `ak admin users update`: update user details (email, display name, admin status)
- `ak admin users reset-password`: reset a user's password
```

**Step 2: Update version in Cargo.toml**

Change `version = "0.4.3"` to `version = "0.5.0"` in the root `Cargo.toml`.

**Step 3: Commit**

```bash
git add CHANGELOG.md Cargo.toml Cargo.lock
git commit -m "chore: prepare v0.5.0 release"
```

---

## Summary

| Task | What | New Tests | Files |
|------|------|-----------|-------|
| 1 | Regenerate SDK | 0 | sdk/ |
| 2 | `ak group` | 6 | group.rs, mod.rs, cli.rs |
| 3 | `ak permission` | 3 | permission.rs, mod.rs, cli.rs |
| 4 | `ak promotion` | 5 | promotion.rs, mod.rs, cli.rs |
| 5 | `ak approval` | 4 | approval.rs, mod.rs, cli.rs |
| 6 | `ak quality-gate` | 6 | quality_gate.rs, mod.rs, cli.rs |
| 7 | `ak lifecycle` | 6 | lifecycle.rs, mod.rs, cli.rs |
| 8 | `ak label` | 3 | label.rs, mod.rs, cli.rs |
| 9 | Enhanced `ak admin users` | 2 | admin.rs, cli.rs |
| 10 | Verify completions/man pages | 0 | (verification only) |
| 11 | Full test suite + lint | 0 | (verification only) |
| 12 | CHANGELOG + version bump | 0 | CHANGELOG.md, Cargo.toml |

**Total: 12 tasks, ~35 new parsing tests, 7 new command modules, ~2,500 lines of new Rust code.**

Note: The SDK builder API uses a fluent pattern (`client.list_groups().page(1).send().await`). The exact builder method names may differ from what's shown here. When implementing, check the generated SDK for the actual method signatures by running `grep "fn list_groups\|fn create_group" sdk/src/generated_sdk.rs` to find the correct names.
