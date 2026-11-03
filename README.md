# ak: Artifact Keeper CLI

<p align="center">
  <img alt="Artifact Keeper" src="https://raw.githubusercontent.com/artifact-keeper/.github/main/brand/banners/github-readme_1600x600.png" width="100%">
</p>

The official CLI/TUI for [Artifact Keeper](https://artifactkeeper.com), an enterprise artifact registry supporting 45+ package formats. Browse repositories, upload and download artifacts, run security scans, configure package managers, and more, all from your terminal.

## Installation

### Quick Install (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/artifact-keeper/artifact-keeper-cli/main/install.sh | sh
```

The installer auto-detects your OS and architecture, downloads the latest release binary, verifies its SHA-256 checksum, and installs to `/usr/local/bin` (or `~/.local/bin` if not writable).

To choose the release or the directory, pass `--version` or `--install-dir`:

```bash
curl -fsSL https://raw.githubusercontent.com/artifact-keeper/artifact-keeper-cli/main/install.sh | sh -s -- --version v1.11.0 --install-dir ~/bin
```

Linux binaries and `.deb`/`.rpm` packages are statically linked against musl and have no glibc requirement, so they also run on Alpine and in distroless containers. The trade-off is that they don't use glibc's NSS: hostnames resolve through `/etc/hosts` and the DNS servers in `/etc/resolv.conf` only, so names that only LDAP or `systemd-resolved` NSS plugins can resolve won't work. Use a hostname that DNS can resolve, or add it to `/etc/hosts`.

### Homebrew (macOS/Linux)

```bash
brew install artifact-keeper/tap/ak
```

### From source

Requires Rust 1.88+:

```bash
cargo install --locked --git https://github.com/artifact-keeper/artifact-keeper-cli artifact-keeper-cli
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

Each binary includes a `.sha256` checksum file for integrity verification.

#### Verifying signatures

Release artifacts are also signed with [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
using [Sigstore keyless signing](https://docs.sigstore.dev/cosign/signing/overview/) — the signing
identity is the release workflow itself, authenticated via GitHub Actions OIDC, so there is no
long-lived signing key that can leak. Every artifact is published with a `.sig` (signature) and
`.pem` (signing certificate) file.

To verify authenticity (not just integrity) of a download, e.g. `ak-linux-amd64` from release `vX.Y.Z`:

```bash
cosign verify-blob \
  --certificate ak-linux-amd64.pem \
  --signature ak-linux-amd64.sig \
  --certificate-identity "https://github.com/artifact-keeper/artifact-keeper-cli/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ak-linux-amd64
```

A successful verification prints `Verified OK`. The `--certificate-identity` value pins the exact
workflow and tag that produced the signature; to accept any release tag from this repository's
release workflow, pass
`--certificate-identity-regexp '^https://github\.com/artifact-keeper/artifact-keeper-cli/\.github/workflows/release\.yml@refs/tags/v.*$'`
instead. The same command works for the `.deb`/`.rpm` packages and the completions/man-page
tarballs — substitute the file name.

## Supported Servers

The first two numbers of the `ak` version tell you the server version it's built for. The last number is the CLI's own and doesn't match the server's patch number, so `ak` 1.11.0 is built from API 1.11.11. New commands may ship in CLI patch releases (1.11.x).

A 1.11.x CLI supports servers on 1.10 and 1.11. Each `ak` minor supports the server minor it's built for and the one before. Other versions aren't tested, and `ak doctor` warns about them.

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

### Headless and SSO login

Requires Artifact Keeper backend 1.12.0 or newer.

On a host without a browser, or when the instance uses SSO, sign in with the
device authorization grant (RFC 8628) instead of a password:

```bash
ak auth login --oidc-device
```

The CLI prints a verification URL and a short code. Open the URL on any device
where you are already signed in to Artifact Keeper, enter the code, and approve
the request. The CLI polls at the server's interval, honours `slow_down`, and
stores the returned access and refresh tokens through the same credential store
as a password login. Tokens are never printed.

- `--scope <SCOPE>` requests specific AK scopes, repeatable or comma-separated
  (default: `read:artifacts`). `*`, `admin` and OIDC scopes (`openid`,
  `profile`, `email`) are refused: this is a plain Artifact Keeper grant, not
  an OIDC device flow.
- `--no-input` keeps the flow fully non-interactive; it never opens a browser
  and never prompts. Set `AK_NO_BROWSER=1` to suppress the browser launch
  without disabling prompts.
- `--device` is an alias for `--oidc-device`.

The server must have `DEVICE_AUTH_ENABLED=true`; otherwise, or on an older
backend, the command reports that device authorization isn't available. Use `ak auth logout` to clear the
stored credential.

## Commands

```
Core
  ak instance      Add, remove, and switch between registry instances
  ak auth          Log in, manage tokens, check identity
  ak repo          Manage repositories: members, upstream settings, storage, and more
  ak artifact      Push, pull, list, search, copy, and delete artifacts; revisions and upload sessions
  ak api           Send any HTTP request to the instance, with its auth and TLS settings
  ak pkg           Publish packages and use format APIs without the format's own client
  ak setup         Auto-configure npm, pip, cargo, docker, maven, gradle, go, helm, nuget, and more
  ak doctor        Diagnose configuration and connectivity issues
  ak config        Get/set CLI configuration values

Security & Compliance
  ak scan          Trigger security scans and view findings
  ak sign          Signing and key management
  ak sbom          Software Bill of Materials operations
  ak license       License compliance management
  ak quality-gate  Manage artifact quality gates
  ak quarantine    Hold, release, and reject quarantined artifacts
  ak totp          Manage two-factor authentication (TOTP)

Organization
  ak group         Manage user groups
  ak permission    Manage fine-grained permission rules
  ak profile       Manage your user profile and API tokens
  ak label         Tag repositories with key-value labels
  ak sso           Manage SSO authentication providers (LDAP, OIDC, SAML)

Workflow & Lifecycle
  ak promotion     Promote artifacts between repositories
  ak approval      Manage promotion approval workflows
  ak lifecycle     Manage lifecycle and retention policies
  ak migrate       Migrate artifacts between instances in bulk

Federation & Integration
  ak peer          Manage federation peer instances
  ak sync-policy   Manage sync policies for automated replication
  ak webhook       Manage webhooks for event-driven integrations
  ak dt            Dependency-Track integration
  ak analytics     Usage analytics and storage insights

Administration
  ak admin         Backup, cleanup, metrics, users, plugins, settings, audit log, downloads, trash, storage checks
  ak project       Projects: grouped repositories, members and a storage quota
  ak banner        System-wide maintenance and downtime banners
  ak search        Quick, checksum, recent, suggested and trending artifact searches
  ak events        Follow the server's stream of change events
  ak bundle        Offline bundles: format, manifest checks, export and import jobs
  ak environment   Stored lockfiles, and which of them contain a component
  ak image-build   Server-side container image builds and image inspection
  ak attestation   The publishers and keys this server trusts for attestations
  ak tui           Launch interactive TUI dashboard
  ak completion    Generate shell completions (bash/zsh/fish/powershell)
  ak man-pages     Generate man pages for all commands
```

Run `ak <command> --help` for detailed usage and examples.

## Output Formats

Every command supports multiple output modes:

```bash
ak repo list                    # Table (default in terminals)
ak repo list --format json      # JSON (default when piped)
ak repo list --format yaml      # YAML
ak repo list -q                 # Quiet: IDs only, one per line
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

## Custom CA Certificates

For instances behind a private or enterprise Certificate Authority (internal
registries, corporate TLS-inspection proxies), point the CLI at a PEM file
containing the CA certificate — or a bundle with multiple certificates:

```bash
# Per invocation
ak repo list --ca-cert /etc/ssl/corp-root-ca.pem

# Or via environment variable (e.g. in CI)
export AK_CA_CERT=/etc/ssl/corp-root-ca.pem
ak artifact push my-repo ./build/output.tar.gz
```

The certificate(s) are **added** to the default trust store; TLS verification
always remains enabled. There is intentionally no option to disable
certificate verification — use `--ca-cert` to trust your private CA instead.

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

`AK_NO_INPUT` and `--no-input` mean never prompt. They don't answer a prompt: `--yes` (`-y`) is the only consent. A destructive or security-decision command, such as `ak repo delete` or `ak quarantine release`, fails without it, with exit code 2, and sends nothing. Everything else runs without asking.

See the [CI/CD Integration Guide](https://artifactkeeper.com/docs/guides/ci-cd/) for GitHub Actions, GitLab CI, and Jenkins examples.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AK_FORMAT` | Default output format (`table`, `json`, `yaml`, `quiet`) |
| `AK_INSTANCE` | Override default instance |
| `AK_TOKEN` | API token (alternative to keychain) |
| `AK_NO_INPUT` | Never prompt, as `--no-input` does: `1`, `true` or `yes`. `0`, `false`, `no` or empty leave it off. Destructive and security-decision commands then need `--yes` |
| `AK_CA_CERT` | Path to a PEM file with additional root CA certificate(s) to trust (same as `--ca-cert`) |
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
