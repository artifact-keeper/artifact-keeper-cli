# ak — Artifact Keeper CLI

The official CLI/TUI for [Artifact Keeper](https://artifactkeeper.com), an enterprise artifact registry supporting 45+ package formats. Browse repositories, upload and download artifacts, run security scans, configure package managers, and more — all from your terminal.

## Installation

### Quick Install (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/artifact-keeper/artifact-keeper-cli/main/install.sh | sh
```

The installer auto-detects your OS and architecture, downloads the latest release binary, verifies its SHA-256 checksum, and installs to `/usr/local/bin` (or `~/.local/bin` if not writable).

### Homebrew (macOS/Linux)

```bash
brew install artifact-keeper/tap/ak
```

### Cargo (from source)

Requires Rust 1.85+:

```bash
cargo install artifact-keeper-cli
```

### Snap (Linux)

```bash
snap install ak --classic
```

### Docker

```bash
docker run --rm ghcr.io/artifact-keeper/ak:latest --help
```

### GitHub Releases

Pre-built binaries for every platform are available on the [Releases](https://github.com/artifact-keeper/artifact-keeper-cli/releases) page:

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `ak-linux-amd64` |
| Linux ARM64 | `ak-linux-arm64` |
| macOS x86_64 | `ak-darwin-amd64` |
| macOS ARM64 (Apple Silicon) | `ak-darwin-arm64` |
| Windows x86_64 | `ak-windows-amd64.exe` |

Each binary includes a `.sha256` checksum file for verification.

## Quick Start

```bash
# 1. Add your registry
ak instance add myserver https://registry.company.com

# 2. Log in
ak auth login

# 3. Browse repositories
ak repo list

# 4. Upload an artifact
ak artifact push my-repo ./package-1.0.tar.gz

# 5. Download an artifact
ak artifact pull my-repo org/pkg/1.0/pkg-1.0.jar

# 6. Configure your package managers automatically
ak setup auto
```

## Commands

```
ak instance   — Add, remove, and switch between registry instances
ak auth       — Log in, manage tokens, check identity
ak repo       — List, show, create, and delete repositories
ak artifact   — Push, pull, list, search, copy, and delete artifacts
ak setup      — Auto-configure npm, pip, cargo, docker, maven, gradle, go, helm, nuget, and more
ak scan       — Trigger security scans and view findings
ak admin      — Backups, cleanup, metrics, user management, plugins
ak migrate    — Bulk-copy artifacts between instances
ak doctor     — Diagnose configuration and connectivity issues
ak config     — Get/set CLI configuration values
ak tui        — Launch interactive TUI dashboard
ak completion — Generate shell completions (bash/zsh/fish/powershell)
ak man-pages  — Generate man pages for all commands
```

Run `ak <command> --help` for detailed usage and examples.

## Output Formats

Every command supports multiple output modes:

```bash
ak repo list                    # Table (default in terminals)
ak repo list --format json      # JSON (default when piped)
ak repo list --format yaml      # YAML
ak repo list -q                 # Quiet — IDs only, one per line
```

## Multi-Instance Support

Manage multiple Artifact Keeper servers with named contexts:

```bash
ak instance add prod https://registry.company.com
ak instance add staging https://staging.company.com
ak instance use prod

# Or per-command:
ak repo list --instance staging
```

## Shell Completions

```bash
# Bash
ak completion bash > ~/.bash_completion.d/ak

# Zsh
ak completion zsh > ~/.zfunc/_ak

# Fish
ak completion fish > ~/.config/fish/completions/ak.fish

# PowerShell
ak completion powershell > ak.ps1
```

## CI/CD Usage

```bash
export AK_INSTANCE=prod
export AK_TOKEN=your-api-token
export AK_NO_INPUT=1

ak artifact push my-repo ./build/output.tar.gz
```

See the [CI/CD Integration Guide](https://artifactkeeper.com/docs/guides/ci-cd/) for GitHub Actions, GitLab CI, and Jenkins examples.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AK_FORMAT` | Default output format (`table`, `json`, `yaml`, `quiet`) |
| `AK_INSTANCE` | Override default instance |
| `AK_TOKEN` | API token (alternative to keychain) |
| `AK_NO_INPUT` | Disable interactive prompts |
| `AK_COLOR` | Color mode (`auto`, `always`, `never`) |
| `AK_CONFIG_DIR` | Override config directory |
| `NO_COLOR` | Standard no-color flag |

## Documentation

- [CLI Reference](https://artifactkeeper.com/docs/reference/ak-cli/)
- [Quick Start Guide](https://artifactkeeper.com/docs/guides/cli-quickstart/)
- [CI/CD Integration](https://artifactkeeper.com/docs/guides/ci-cd/)
- [Full Documentation](https://artifactkeeper.com/docs/)

## License

MIT
