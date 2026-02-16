# CLAUDE.md — artifact-keeper-cli

## Overview

`artifact-keeper-cli` is the official CLI/TUI for Artifact Keeper, an enterprise artifact registry. The binary is named `ak`.

## Build & Development Commands

```bash
# Build
cargo build

# Run
cargo run -- --help

# Lint
cargo fmt --check
cargo clippy --workspace

# Test
cargo test --workspace

# Release build (LTO, stripped)
cargo build --release
```

## Architecture

### Module Layout

```
src/
  main.rs              # Entry point (tokio async)
  cli.rs               # clap derive: Cli struct, Command enum, GlobalArgs
  error.rs             # miette diagnostics (AkError enum)
  output/mod.rs        # OutputFormat (table/json/yaml/quiet), render helpers
  config/
    mod.rs             # AppConfig (TOML), InstanceConfig, load/save
    instances.rs       # Instance management helpers (Issue #4)
    credentials.rs     # Keychain credential storage (Issue #5)
  commands/
    mod.rs             # Module declarations
    auth.rs            # login, logout, token, whoami, switch
    instance.rs        # add, remove, list, use, info
    repo.rs            # list, show, create, delete, browse
    artifact.rs        # push, pull, list, info, delete, search, copy
    setup/mod.rs       # auto-detect + per-ecosystem config (npm, pip, cargo, etc.)
    scan.rs            # run, list, show
    doctor.rs          # diagnostics
    admin.rs           # backup, cleanup, metrics, users, plugins
    config.rs          # get, set, list
    tui.rs             # TUI dashboard (ratatui)
    completion.rs      # shell completions (clap_complete)
```

### Key Patterns

- **GlobalArgs**: Shared options (format, instance, no_input) extracted from `Cli` before command dispatch to avoid borrow checker issues with partial moves
- **OutputFormat**: All commands use the `--format` flag (table/json/yaml/quiet) for output
- **Instance resolution**: flag `--instance` > config `default_instance` > error
- **Config path**: `$AK_CONFIG_DIR` or `~/.config/artifact-keeper/config.toml`
- **Error handling**: `miette::Result` throughout, `AkError` with diagnostic codes and help text
- **Async**: All commands are async via tokio

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `AK_FORMAT` | Default output format |
| `AK_INSTANCE` | Override default instance |
| `AK_NO_INPUT` | Disable interactive prompts |
| `AK_COLOR` | Color mode (auto/always/never) |
| `AK_CONFIG_DIR` | Override config directory |
| `AK_TOKEN` | API token (alternative to keychain) |
| `NO_COLOR` | Standard no-color flag |

## Git Conventions

- Branch naming: `feat/`, `fix/`, `chore/`, `docs/`
- Do NOT add Co-Authored-By lines to commit messages
- Do NOT include AI attribution in PR descriptions
- Squash merge preferred

## Related Repos

- `artifact-keeper/` — Backend (Rust/Axum)
- `artifact-keeper-api/` — OpenAPI spec + generated SDKs
- Rust SDK will be generated via Progenitor from the OpenAPI spec (Issue #3)
