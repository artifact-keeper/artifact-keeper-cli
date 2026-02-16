# Changelog

All notable changes to the Artifact Keeper CLI (`ak`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-02-16

### Fixed

- **Setup writes to home directory** — `ak setup npm` now writes `.npmrc` to `~/` and `ak setup nuget` writes `NuGet.Config` to `~/.nuget/NuGet/` instead of the project directory, preventing accidental token commits to git (#47)

## [0.4.0] - 2026-02-16

### Added

- **TUI global search** — press `s` to search across all repositories on the selected instance using the Meilisearch-powered `advanced_search` endpoint; results show artifact name, repository, format, version, and size with a faceted sidebar displaying format, repository, and content type distribution; Enter on a result navigates to that artifact in the 3-panel view (#45)

## [0.3.0] - 2026-02-16

### Fixed

- **TUI server status** — instances now show "online (N repos)" in green instead of incorrectly showing "offline"; health probe switched from broken `/health` endpoint to `list_repositories` (#43)
- **TUI keychain prompts** — credentials are cached in memory per instance, eliminating repeated macOS Keychain Access password dialogs on every navigation action (#43)

## [0.2.0] - 2026-02-16

### Added

- **Config commands** — `ak config list`, `get`, `set`, and `path` are now fully implemented with validation and table/json/yaml output (#41)

### Fixed

- **Release CI** — fixed nfpm version, download URL format, and redundant package rename step (#38, #39, #40)
- **DEB/RPM packages** — added Debian and RPM package builds (amd64, arm64/aarch64) via nfpm to release workflow
- **Homebrew tap** — automated formula generation and push to `artifact-keeper/homebrew-tap` on release

## [0.1.0] - 2026-02-16

Initial release of the Artifact Keeper CLI.

### Added

- **Multi-instance management** — add, remove, list, and switch between Artifact Keeper instances with `ak instance`
- **Authentication** — interactive login with username/password or token (similar to `gh auth login`), credential storage via OS keychain, logout, whoami, API token management
- **Repository operations** — list, show, create, delete, and browse repositories; public repos accessible without auth
- **Artifact operations** — push, pull, list, info, delete, search, and cross-instance copy with progress bars and streaming uploads/downloads
- **Setup wizards** — auto-detect and configure 11 package ecosystems (npm, pip, cargo, maven, gradle, nuget, go, docker, helm, cocoapods, swift)
- **Security scanning** — trigger and view vulnerability scans with `ak scan`
- **Admin commands** — backup management, storage cleanup, server metrics, user management, WASM plugin management
- **Doctor diagnostics** — check instance connectivity, authentication status, package manager configs, and CLI health
- **Interactive TUI** — full-screen dashboard with ratatui for browsing repos and artifacts
- **Output formats** — table (default for TTY), JSON, YAML, quiet mode; auto-detected via `--format` or `AK_FORMAT` env var
- **Shell completions** — bash, zsh, fish, PowerShell via `ak completion`
- **Man pages** — generate man pages for all commands via `ak man-pages`
- **Cross-instance copy** — bulk artifact migration between instances
- **Release CI** — GitHub Actions workflow builds binaries for Linux (x86_64, aarch64), macOS (x86_64, aarch64), and Windows (x86_64)
- **Distribution** — install script, Docker image, Snap package, Homebrew tap

### SDK

- Generated Rust SDK from the Artifact Keeper OpenAPI spec via Progenitor
- Covers 250+ API endpoints across all backend features
- OpenAPI 3.1 → 3.0 conversion handled automatically by the xtask

[0.4.1]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v0.4.1
[0.4.0]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v0.4.0
[0.3.0]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v0.3.0
[0.2.0]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v0.2.0
[0.1.0]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v0.1.0
