# Changelog

All notable changes to the Artifact Keeper CLI (`ak`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.11.0] - Unreleased

The CLI minor version now tracks the server API minor it's generated from. This
release is built for API 1.11.10 and supports servers on 1.11 and 1.10.

### Before you upgrade

These can change what you see, or break a script, coming from 1.2:

- **Version numbers and supported servers.** The first two numbers of the `ak` version tell you the server version; the last is the CLI's own and doesn't match the server's patch number. New commands may ship in CLI patch releases (1.11.x). A 1.11.x CLI supports servers on 1.10 and 1.11. Other servers aren't tested, and `ak doctor` warns about them.
- **Snap is gone.** The Snap package never published. Use the installer, Homebrew, the `.deb`/`.rpm` packages or the static binaries (#148).
- **Linux binaries are static musl builds**, and so are the `.deb`/`.rpm` packages that wrap them. They no longer need any particular glibc, but they also don't use glibc's NSS: names resolve through `/etc/hosts` and the DNS servers in `/etc/resolv.conf` only. A hostname that only an LDAP or `systemd-resolved` NSS plugin can resolve won't work (#178).
- **JSON and YAML changed on some commands.** `auth whoami`, `auth token list`, `repo`, `artifact`, `lifecycle`, `webhook` and `curation` commands (the full list is under Changed) print the server's response as sent. Lists are `{"items": [...], "pagination": {...}}` rather than a bare array, and fields use the API's names: `repo_type` rather than `type`, `is_public` rather than `public`, `is_admin` rather than `admin`. Scripts that read this output need updating. Table output is unchanged.
- **`ak lifecycle create` needs `--repo` or `--all-repos`, and fails with neither**, so scripts that pass neither have to add one. A policy is enabled as soon as it's created, and one made with `--all-repos` deletes artifacts across every repository when it runs.
- **`ak setup` creates a token.** When you're logged in with a session and agree to the write (`--no-input` counts as agreeing), it creates an API token named `ak-setup-<tool>-<repo>` that lasts 90 days, rather than writing your 30-minute login token. Each re-run adds another token and doesn't replace the last. See them with `ak auth token list` and revoke old ones with `ak auth revoke-token <id>`.
- **Secrets piped with `--no-input` need `--<flag>-stdin`.** With `--no-input` or `AK_NO_INPUT`, a secret you didn't give is no longer read from stdin, so `echo "$S" | ak --no-input webhook create ...` now gets no secret. Use `--secret-stdin`.
- **Device login needs backend 1.12.0**, which isn't released yet. On an older server, `ak auth login --oidc-device` says so and stops. `ak auth login` itself still asks for a password or takes `--token`.
- **Security decisions ask first.** `ak curation approve`, `block`, `bulk-approve`, `bulk-block`, `re-evaluate` and `version publish` now ask for confirmation. With no terminal, pass `--yes`, or set `--no-input` as with every other prompt.

### Added

- Curation commands, with every field the API has: `ak curation search <repo>`, `ak curation sync <repo>`, `ak curation version create <repo>`, `ak curation version publish <repo> <number>`, `ak curation rules --scope`, and `--rule-type`, `--config` and `--scope` on `ak curation create-rule` and `update-rule`. `sync` fails when the server reports that the upstream sync failed.
- `ak doctor` reports each server's version and warns when ak doesn't support it: older than the previous minor (upgrade the server) or newer than the minor ak is built for (upgrade ak).
- `ak quarantine hold <artifact-id> [--reason]` to quarantine an artifact immediately, blocking downloads until an admin releases or rejects it (#156). `--reason` is optional; the server records a default when it is omitted.
  Requires backend 1.7.0 or newer.
- `ak auth login --oidc-device` (`--device` alias) signs in with Artifact Keeper's RFC 8628 device authorization grant, for headless hosts and SSO-backed instances. Requires backend 1.12.0 or newer. The CLI prints the verification URL and user code, polls at the server's interval, honours `authorization_pending` and `slow_down`, reports `expired_token`, `access_denied` and `invalid_grant` clearly, and stores the returned access and refresh tokens through the existing credential store. `--scope` selects AK scopes (default `read:artifacts`); `--no-input` keeps the flow non-interactive and never opens a browser. Tokens are never printed (artifact-keeper#3462)
- `AK_CREDENTIAL_STORE=file` skips the OS keychain and keeps credentials in the 0600 credentials file.
- Every command that takes a repository ID also takes its key (#180): `sign`, `lifecycle`, `license`, `curation`, `quality-gate`, `promotion`, `sbom`, `scan policy`, `webhook`, `analytics repo-trend`, `peer subscription`, `service-account`, `admin ci-oidc`, and `permission` with a repository target. `quarantine` commands take `<repo-key>/<path>` as well as an artifact ID. `repo show`, `repo list`, `artifact info`, `artifact list` and `artifact search` now include `id` in JSON, and `repo show` shows it in the table.
- `ak api <METHOD> <path>` sends any HTTP request to the instance with its auth and TLS settings, so anything curl can do works here even without a first-class command: any method, repeatable `-H` and `-Q`, `--body` (JSON text, `@file`, `@-`), `--raw-body` (streamed), `--form` (multipart), `--urlencode`, `-o` (streamed), `--include`, `--head-only`, `--no-follow`, `--fail`, `--no-fail`, `--url`, `--anon` and `--max-time`. The instance's token goes only to the instance's own scheme, host and port. Run `ak api --help` for exit codes and examples.
- `ak project` manages projects and their members: `list`, `show`, `create`, `update`, `delete` and `members list|add|remove`. Every command takes a project's key or its ID.
- `ak banner` manages system-wide maintenance banners: `list`, `show`, `create`, `update` and `delete` for admins, and `active`, which needs no login. `update` changes only what you pass, and `--no-link-url`, `--no-starts-at` and `--no-ends-at` clear a field. Needs a 1.11 server, and on 1.10 says so.
- `ak repo create` and `ak repo update` can set every field in the 1.11 API: `--visibility`, `--project-id`, `--versioning-enabled`, `--repodata-depth`, `--custom-user-agent`, `--trusted-gpg-key`, `--curation-allow-unverified`, `--allow-public-with-upstream-credentials`, `--apt-origin`, `--apt-label`, `--apt-description`, `--apt-release-version`, `--npm-allowed-scopes`, `--npm-allowed-name-patterns`, `--npm-allow-unscoped`, `--npm-virtual-isolate-hosted-names`, `--oci-trusted-bearer-realms` and `--debian` (JSON). `create` also takes `--name`, `--allow-anonymous`, `--promotion-only`, `--quota-bytes`, `--index-upstream-url`, `--pypi-upstream-index-path`, `--format-key`, `--member`, `--storage-backend`, `--upstream-auth-type`, `--upstream-username`, `--upstream-password` and `--upstream-password-stdin`. `update` also takes `--upstream-url`, `--curation-enabled`, `--curation-default-action`, `--virtual-metadata-partial`, `--clear-project` and `--clear-trusted-gpg-key`.
- `ak repo allowlist get|set|delete` for the package allowlist of a virtual conda repository, `ak repo upstream-filter get|set|delete`, `ak repo egress-proxy get|set` and `ak repo npm-scope-policy get|set` for remote repositories, `ak repo capabilities`, `ak repo storage [--tree]` and `ak repo storage-gc`.
- `ak repo upstream-auth` takes `aws_ecr` and `aws_codeartifact` with `--aws` (JSON), `--allow-public-with-upstream-credentials` and `--password-stdin`. `ak repo list` takes `--project`.
- `ak artifact versions`, `ak artifact missing` (`--item path=sha256`, or `--from` with JSON or `sha256sum` output), `ak artifact package-analysis` and `ak artifact upload-session list|status|cancel`. `ak artifact show`, `metadata`, `stats` and `package-analysis` take `<repo-key>/<path>` as well as an ID.
- `ak artifact push` takes `--multipart`, `--version-label` and the upload session fields `--skip-if-present`, `--artifact-name`, `--artifact-version`, `--package-description`, `--package-metadata`, `--artifact-metadata`, `--artifact-metadata-format` and `--artifact-metadata-properties`. A session field makes the push chunked whatever the file's size.
- `ak artifact pull` and `ak artifact info` take `--version` for a revision of a versioned artifact. `ak artifact list` takes `--path-prefix`, `--group-by` (with a table for grouped results), `--cursor` and `--count`. `ak artifact search` takes `--name`, `--path`, `--version`, `--min-size`, `--max-size`, `--created-after`, `--created-before`, `--sort-by`, `--sort-order`, `--page` and `--per-page`, and the query is optional.
- `ak repo delete --wait` follows a background deletion to its end, and `--wait-timeout` limits how long it waits (default 30 minutes).
- Admin observability commands, with every filter the API has: `ak admin audit list`, `ak admin downloads list|by-ip|by-user`, `ak admin blast-radius artifact|cve [--accessible-users]`, `ak admin proxy-scan-verdict show|delete`, `ak admin npm-feed status`, `ak admin holds quarantine|summary`, `ak age-gate reopen` and `ak quality-gate checks --all`. On a 1.10 server, `admin holds` and `admin npm-feed` say they need 1.11, and `admin downloads --repo` or `--source` fail rather than print an unfiltered list, because 1.10 ignores those filters.
- Admin observability commands, with every filter the API has: `ak admin audit list`, `ak admin downloads list|by-ip|by-user`, `ak admin blast-radius artifact|cve [--accessible-users]`, `ak admin proxy-scan-verdict show|delete`, `ak admin npm-feed status`, `ak admin holds quarantine|summary`, `ak age-gate reopen` and `ak quality-gate checks --all`.
- `ak bundle` covers offline bundles: `format`, `validate-manifest`, `jobs list|show|items`, `export` and `import`. `validate-manifest` exits 1 for an invalid manifest. The 1.11.10 server answers 501 to `export` and `import`, and the command shows that message. Needs a 1.11 server, and on 1.10 says so.
- `ak environment` stores lockfiles and searches them: `ingest`, `list`, `show`, `delete`, `advisories`, `lookup <purl>` and `advisory-transitions`. Commands take an environment's name or its ID. Needs a 1.11 server, and on 1.10 says so.
- `ak image-build` builds container images on the server and inspects pushed ones: `list`, `show`, `log`, `create`, `render`, `settings`, `base-info` and `inspect`. A spec comes from flags (`--base-image`, `--apt`, `--pip`, `--conda`, `--env`, `--label`, `--user` and more), from `--spec` as JSON, or both. `render` checks a spec and prints the Containerfile without building. `create` needs a server with a builder configured.
- `ak bundle` covers offline bundles: `format`, `validate-manifest`, `jobs list|show|items`, `export` and `import`. `validate-manifest` exits 1 for an invalid manifest. The 1.11.10 server answers 501 to `export` and `import`, and the command shows that message. Needs a 1.11 server.
- `ak environment` stores lockfiles and searches them: `ingest`, `list`, `show`, `delete`, `advisories`, `lookup <purl>` and `advisory-transitions`. Commands take an environment's name or its ID. Needs a 1.11 server.
- `ak image-build` builds container images on the server and inspects pushed ones: `list`, `show`, `log`, `create`, `render`, `settings`, `base-info` and `inspect`. A spec comes from flags (`--base-image`, `--apt`, `--pip`, `--conda`, `--env`, `--label`, `--user` and more), from `--spec` as JSON, or both. `render` checks a spec and prints the Containerfile without building. `create` needs a server with a builder configured. Needs a 1.11 server.
- Admin settings and storage commands: `ak admin settings system|token-policy|totp-policy`, `ak admin storage-scrub run|findings`, `ak admin reindex-storage`, `ak admin trash list|restore` and `ak packages backfill`. `ak admin plugins install` also takes a local JSON manifest or ZIP file as well as a git URL. Operators also have `ak admin storage ledger-backfill` and `ak admin diag memory|heap-profile`, which aren't in the help. The `diag` routes exist only on a server built with its `profiling` feature. `admin settings system`, `storage-scrub`, `reindex-storage` and `trash` need a 1.11 server, and on 1.10 they say so.

### Changed

- Regenerated the SDK from the API 1.11.10 spec, adding the operations and fields new since 1.4.0. Two multipart operations (`POST /api/v1/plugins`, `POST /api/v1/plugins/install/zip`) remain outside the generated SDK.
- `ak lifecycle create` now requires `--repo` or the new `--all-repos`, and fails with neither, so **scripts that pass neither have to add one**. A policy is enabled as soon as it's created, so its reach is no longer implied by a missing flag. Omitting `--repo` used to mean every repository on a 1.10 server, and a dormant policy that never deleted anything on 1.11. `--all-repos` gives a policy for every repository on both. `ak lifecycle list` and `show` now show the scope. New `ak lifecycle create --disabled` creates a policy that doesn't run until `ak lifecycle update <id> --enabled`, and `ak lifecycle preview` works on it. An enabled policy can start deleting within about a minute, even with no `--cron-schedule`. `--disabled` needs a 1.11 server: 1.10 ignores it and would create a live policy, so it's refused there and nothing is created.
- `ak webhook rotate-secret` no longer shows a new secret, because the server no longer returns one. It shows the digest, and `--format quiet` prints the webhook ID.
- `ak quality-gate checks` now requires `--artifact`, as the API does.
- `ak scan scores`: the `UNSCANNED` column is now `OPEN`. It subtracted acknowledged findings from `total_findings`, which the server already counts as open findings only.
- `ak peer subscription list` shows each subscription's sync state, mode and last replication.
- `ak curation update-rule` changes only what you pass. An update used to turn a disabled rule back on and reset its engine, config, priority, architecture and version constraint, and it had to name the action, pattern and reason every time.
- `ak admin users role assign` warns that the role grants no repository access, since backend 1.11 deprecated the endpoint in favour of `ak permission create`.
- `ak lifecycle update` and `ak email-subscriptions subscribe` use the generated SDK instead of raw HTTP.
- `ak setup` no longer writes your 30-minute login token into permanent config files. It creates an API token named `ak-setup-<tool>-<repo>` with `read:artifacts` and `write:artifacts` that lasts 90 days (`--token-days`), and prints its ID and how to revoke it. `--session-token` keeps the old behavior with a warning. An API token in `AK_TOKEN` is used as it is. If the API token can't be created, such as when `--token-days` is outside the server's token policy, setup fails and writes nothing, rather than writing a config that starts returning 401 errors later. A backup of a replaced file never overwrites an earlier backup: the first is `<name>.bak`, then `<name>.bak.1` and so on, so a second run no longer loses what the file held before the first.
- `ak setup` no longer destroys other config. For npm, pip and Cargo it changes only its own keys in `.npmrc`, `pip.conf`, `config.toml` and `credentials.toml`, so other registries, tokens and comments stay, and it says if it replaced a value of yours such as the default registry. A Maven `settings.xml` or `NuGet.Config` that setup didn't write is left as it is: **setup exits 1** and prints what to add, and `--replace` replaces the file, keeping a backup. `setup auto` carries on with the other tools first. The Gradle init script and the yum and apt files are setup's own, so they're still replaced.
- `ak curation` prints the server's response for `--format json` and `yaml`, including an empty list. Bulk decisions and `re-evaluate` print the count the server sends.
- `ak artifact push` and `ak artifact copy` print the server's response for `--format json` and `yaml`. They printed nothing on stdout before.
- `ak repo members add|reorder`, `routing-rules`, `cache`, `pypi-tracks`, `tree`, `upstream-auth` and `test-upstream` print the server's response for `--format json` and `yaml`, including an empty list. `upstream-auth`, `test-upstream` and `routing-rules delete` use raw HTTP for this, because the spec gives those routes no response body and the SDK drops it.
- For `--format json` and `yaml`, these commands now print the response body as the server sent it, including fields this version of the CLI does not know: `auth whoami`, `auth token list`, `repo list|show|create|update|members list`, `artifact list|info|show|metadata|stats|search`, `lifecycle list|show|create|update`, `webhook list|show|create`. **This changes their JSON shape**: lists are `{"items": [...], "pagination": {...}}` rather than a bare array, and fields use the API names (`repo_type` rather than `type`, `is_public` rather than `public`, `is_admin` rather than `admin`). `size` and `storage_used` strings and `whoami`'s `instance` and `url` are gone from JSON, and an empty list prints the body rather than nothing. `admin`, `quality-gate`, `age-gate` and `packages` now do the same, so their JSON uses API field names (`is_enabled` rather than `enabled`, `size_bytes` with no `size` string), and `admin backup restore`, `admin plugins install`, `admin plugins install-zip` and `admin users reset-password` now print their response in JSON rather than nothing on stdout. Other commands keep their shape for now and move as their workstreams land. Table output is unchanged.

### Fixed

- `ak admin plugins list` and `show` no longer fail on a server with a plugin that has no config schema. The server sends null there although the API spec doesn't allow it.
- Virtual repositories show the size of their members in `ak repo list`, `ak repo show` and the TUI, rather than 0 (#181).
- The `ak lifecycle create` help names the right config key for `size_quota_bytes`: `quota_bytes`.
- `ak admin plugins install-local` explains that the server doesn't implement it and points to `install-zip`.
- `ak artifact push` now sends a detected `Content-Type` instead of always using `application/octet-stream`, so the server stores a meaningful `content_type` for each artifact. The type is guessed from the file extension via `mime_guess`, with overrides for extensions its database gets wrong (for example `.rpm` is `application/x-rpm` and `.deb` is `application/vnd.debian.binary-package`) and an `application/octet-stream` fallback for unknown types. A new `--content-type` flag sets the type explicitly. Applies to both the single-PUT and chunked-upload paths. This changes only the stored `content_type`, not how the server classifies or indexes packages (#185)
- Linux release binaries (and the `.deb`/`.rpm` packages that wrap them) are now fully static musl builds, so they run on any Linux distribution regardless of its glibc version: Debian 12, Ubuntu 22.04, RHEL/Alma/Rocky 8 and 9, Amazon Linux 2023, Alpine and distroless images. They were previously built on `ubuntu-latest` and required glibc 2.39. CI now fails if a dependency breaks static linking (#178)
- `ak admin storage-gc run` now always sends `dry_run` explicitly, so a live run posts `{"dry_run": false}` instead of an empty body. Companion to artifact-keeper#3619, which makes `dry_run` required on the storage-GC endpoint and rejects unknown fields (422)
- `ak setup` writes working URLs (#155). Package-manager endpoints are mounted at the server root, not under `/api/v1`. NuGet uses `/nuget/<repo>/v3/index.json`, apt uses `/debian/<repo>/`, and Cargo uses the sparse protocol. It no longer forces https on http instances, and `setup docker` keeps the port. For http instances it adds the setting each client needs (`allowInsecureProtocol`, `allowInsecureConnections`, `trusted-host`, a protocol on the apt `machine` line). `setup go` now says the go command will not send credentials over plain HTTP. `setup go` no longer suggests the nonexistent `GONOSUMCHECK`.
- Failed commands now show the status and the server's own message, such as `409 Conflict: Artifact is quarantined and pending security review`, instead of response headers or a debug dump of the response. The SDK has its own error type for this, and it holds no headers.
- `ak lifecycle create --repo` no longer creates a policy for every repository on a 1.10 server. It sent only `repository_ids`, which 1.10 ignores. If you created policies with `--repo` against 1.10 using a build of this release, check their scope with `ak lifecycle list`.
- `ak artifact info` fetches the exact path. It used to search and take the first match, so `a.bin` could show `dir/a.bin.old`.
- `ak doctor` no longer reports false problems: the repo count uses your credentials when it has them (it read "0 repos" on a private instance) and says "public" when it does not, a login token shows the minutes left rather than warning "expires in 0 days", and a package manager config that points at the instance but not at its real route (like one from an older `ak setup`) is a warning rather than "configured". It also recognises a pip config with credentials in its URL.
- A prompt with no terminal now says to pass `--yes` or `--no-input`, rather than failing with `IO error: not a terminal`. It goes by the error's type, so a server message containing those words is shown as it is.
- With `--no-input` or `AK_NO_INPUT`, a secret that was not given (such as `ak webhook create` without `--secret`) no longer waits on an open stdin. To pipe a secret with `--no-input`, use the command's `--<flag>-stdin`.
- `ak import source list`, `import job list` and `import job items` work against 1.11 and 1.10. The server wraps these lists in `{"items": [...]}` while the spec declares an array (artifact-keeper-api#46), so the SDK could not parse them. In JSON and YAML they print the body as received.
- `ak artifact copy <repo>/<path> <repo>/<other-path>` works. It sent the whole destination as the target repository, which got a 404. A destination with a different path now goes through a download and an upload, keeping the content type, because the server's promotion keeps the path.
- `ak artifact copy` finds the source by its exact path, rather than by search, where `a.bin` could copy `dir/a.bin.old`. It reports a promotion a policy refused as a failure, which it used to report as copied. Cross-instance copies keep the content type and honour `--instance`.
- `ak artifact pull` and cross-instance `copy` no longer stop at 30 seconds on a large artifact.
- `ak artifact push` resumes a session only for the same repository and path, and starts again if the session was cancelled or is gone, rather than failing.
- On a server before 1.11, `ak repo create`, `repo update` and `repo upstream-auth` refuse the flags it would accept and silently drop, before changing anything: `--visibility`, `--allow-public-with-upstream-credentials`, `--repodata-depth`, `--npm-virtual-isolate-hosted-names`, `--oci-trusted-bearer-realms`, and for `update` also `--upstream-url`, `--virtual-metadata-partial` and `--clear-project`. `ak artifact push --skip-if-present` does the same. `repo capabilities`, `repo allowlist`, `repo upstream-filter`, `artifact missing` and `artifact package-analysis` say they need 1.11, rather than repeating that server's `Repository not found`.
- `ak repo create --repo-type proxy` and `ak repo list --repo-type proxy` work. The API's word is `remote` and it rejected `proxy`, so `ak` now sends `remote` (#154).
- `ak repo delete` accepts the `202 Accepted` and job that backend 1.12 answers with, where it used to report failure on a delete the server had accepted. It prints the job ID, and `--format quiet` prints only that (#182).
- `ak repo create` no longer sends `is_public: false` when `--public` isn't given.

### Removed

- The Snap package. It never published: the store blocks classic confinement and the build got a bad version. Use the installer, Homebrew, the `.deb`/`.rpm` packages or the static binaries (#148)

### Release process

- `install.sh` takes `--version <tag>` and `--install-dir <dir>`.
- A tag now runs the tests, the SDK drift check and the E2E tests before anything builds, and it must match `Cargo.toml` and the changelog. Every release starts as a prerelease, and only becomes the latest after its published files pass: `install.sh`, the binary on Alpine, Ubuntu 22.04 and Debian 12, `cosign verify-blob`, the `.deb` on Ubuntu 22.04, the `.rpm` on Rocky Linux 9, and Homebrew on macOS. If any of those fails it stays a prerelease and an issue is opened.

### Security

- `ak` no longer follows a redirect that would send your token where it shouldn't go. reqwest kept `Authorization` on a redirect from https to plain http on the same host and port, and it sent the header to another host once that host redirected to itself. Both now fail with an error. Other redirects work as before, including one to presigned storage on another host, which gets no token.
- Updated `quinn-proto` to 0.11.19 (RUSTSEC-2026-0338/0340, RUSTSEC-2026-0339/0341/0342). `ak` doesn't compile `quinn-proto`, so it was never affected: this only clears `cargo audit` on `Cargo.lock`
- Updated `rustls` to 0.23.46 (RUSTSEC-2026-0285 handshake messages accepted across encryption levels, RUSTSEC-2026-0346 TLS secrets in `Debug` output, RUSTSEC-2026-0348 pre-authentication allocation, RUSTSEC-2026-0349 ServerHello downgrade)
- Updated `rustls-webpki` to 0.103.16 (RUSTSEC-2026-0382, distrusted intermediates accepted) and `webpki-root-certs` to 1.0.11 (RUSTSEC-2026-0383, distrusted emSign intermediates)
- Updated `tokio` to 1.54.1 (RUSTSEC-2026-0386, `AsyncFd` I/O-safety unsoundness)
- The patched `rustls`/`rustls-webpki` require `aws-lc-rs` >= 1.18 (now 1.19.0, with `aws-lc-sys` 0.47.0) and the patched `quinn-proto` requires `rand` 0.10, so those move too (`rand` 0.10 is only in `Cargo.lock` as well)
- `ak setup pip` no longer prints the access token to stderr (#207). `setup` previews are now built from templates that never hold the token, `setup helm` passes it on stdin instead of the command line, and config files and their backups are 0600 from the moment they exist. If you ran `ak setup pip` in a shared terminal or a CI job, treat that token as exposed.

## [1.2.0] - 2026-07-13

### Added

- `ak age-gate` command group (`get`, `set`, `reviews`, `review`, `approve`, `reject`) for remote-proxy publish-age cooldown (#95)
- `ak quarantine` command group (`status`, `release`, `reject` with a `purge` alias) for inspecting and resolving artifact quarantine holds (#102)
- `ak group update <id> <name> [--description]` to rename/redescribe a group
- `ak permission show <id>` and `ak permission update <id>` for reading and replacing permission rules
- `ak label repo set <key> <labels...>` to replace all labels on a repository in one call
- `ak lifecycle update <id>` (change name/enabled/priority/description/config/cron) and `ak lifecycle execute-all` to run every enabled policy
- `ak admin telemetry crash <id>` and `ak admin telemetry delete-crash <id>` for single crash-report inspection and removal
- `ak email-subscriptions` (alias `email-subs`) command group: `list`, `subscribe`, and `unsubscribe` for repository email notifications
- Security Audit CI job (`cargo audit`) so vulnerable dependencies fail pull requests instead of accumulating silently

### Security

- Updated `quinn-proto` to 0.11.15 (RUSTSEC-2026-0185, unbounded out-of-order stream reassembly, high severity)
- Updated `rustls-webpki` to 0.103.13 (RUSTSEC-2026-0098/0099 name-constraint bypasses, RUSTSEC-2026-0104 CRL-parsing panic)
- Updated `time` to 0.3.47 (RUSTSEC-2026-0009, stack exhaustion)

### Changed

- Regenerated the bundled SDK from the OpenAPI **v1.4.0** spec (#92, #78) — adds age-gate, CI-OIDC, repository-tokens, quarantine, and user self-service operations; SDK version tracks the API at `1.4.0`
- Bumped MSRV from 1.86.0 to 1.88.0 (required by `time` 0.3.47)

## [1.0.0] - 2026-02-23

### Stable Release

First stable release of the Artifact Keeper CLI. The CLI is feature-complete with 29 top-level commands, 100+ subcommands, interactive TUI, multi-instance management, and multi-platform distribution.

### Security

- Bumped `SonarSource/sonarqube-scan-action` from v5 to v6 to fix argument injection vulnerability
- Updated `lru` transitive dependency to 0.16.3 to resolve `IterMut` unsoundness
- Added explicit `permissions` blocks to all CI workflow jobs (least-privilege)
- Added CodeQL workflow with exclusions for generated SDK code
- Removed URL paths from test helper error messages

### Changed

- Bumped MSRV from 1.85.0 to 1.86.0
- Bumped `ratatui` from 0.29 to 0.30, `crossterm` from 0.28 to 0.29

## [0.9.0] - 2026-02-21

### Added

- Snapshot tests using `insta` for JSON and table output regression detection across all command modules (~40 snapshot tests)
- E2E integration test suite running against a real backend via Docker Compose (20+ test files covering auth, repo, admin, governance, analytics, webhook, and more)
- Docker Compose stack (`tests/docker-compose.yml`) with backend, PostgreSQL, and Meilisearch for local E2E development
- Shared test helpers in `tests/common/` for E2E environment setup, auth, and API access
- CI pipeline job for automated E2E testing on push to main and PRs
- Start/stop scripts (`tests/start-backend.sh`, `tests/stop-backend.sh`) for local E2E test development

### Fixed

- Removed plain-text password from TOTP command examples in CLI help text

## [0.6.0] - 2026-02-21

### Added

- **Signing and key management** - `ak sign key list`, `show`, `create`, `delete`, `revoke`, `rotate`, `export` for managing signing keys; `ak sign config show/update/export-key` for repository signing configuration
- **SBOM operations** - `ak sbom generate`, `show`, `list`, `get`, `delete`, `components`, `export` for SBOM lifecycle; `ak sbom cve history/trends/update-status` for CVE tracking and triage
- **License compliance** - `ak license policy list`, `show`, `create`, `delete` for managing license policies; `ak license check` for CI-friendly compliance checking (exits non-zero on violations)
- **Dependency-Track integration** - `ak dt status`, `project list/show/components/findings/violations/metrics/metrics-history`, `metrics`, `policies`, `analyze` for vulnerability management (alias: `ak dependency-track`)
- **Enhanced scanning** - `ak scan dashboard` and `scores` for security overview; `ak scan finding ack/revoke` for finding triage; `ak scan policy list/show/create/update/delete` for scan policy management; `ak scan security show/update` for repository security config
- **TUI security panel** - new panel (press 4 or Tab) showing security dashboard, recent scans with drill-down into individual findings

## [0.5.0] - 2026-02-21

### Added

- **Group management** — `ak group list`, `show`, `create`, `delete`, `add-member`, `remove-member` for managing user groups and membership
- **Permission management** — `ak permission list`, `create`, `delete` with filtering by target type and principal type for fine-grained access control
- **Promotion workflows** — `ak promotion promote` to move artifacts between repositories, `ak promotion rule list/create/delete` for automated promotion rules, `ak promotion history` to view promotion audit trail
- **Approval workflows** — `ak approval list`, `show`, `approve`, `reject` for promotion approval gates with optional notes
- **Quality gates** — `ak quality-gate list`, `show`, `create`, `update`, `delete`, `check` (alias: `ak qg`) for defining and evaluating artifact quality thresholds; `check` exits non-zero on failure for CI integration
- **Lifecycle policies** — `ak lifecycle list`, `show`, `create`, `delete`, `preview`, `execute` for managing security-based lifecycle policies with dry-run preview support
- **Repository labels** — `ak label repo list`, `add`, `remove` for tagging repositories with key=value labels
- **Admin user management** — `ak admin users update` (email, display name, admin/active flags) and `ak admin users reset-password` subcommands

## [0.4.2] - 2026-02-16

### Changed

- **Code cleanup** — removed dead code (unused fields, empty modules, unreachable branches), simplified match/if-let patterns, used `saturating_sub` and `#[derive(Default)]` where appropriate (#49)
- **Unit tests** — added 251 unit tests across all 13 CLI modules covering parsing, config, credentials, instance management, diagnostics, scan helpers, setup detection, error types, and output rendering; introduced shared test mutex to prevent env var races (#50)

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

[1.0.0]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v1.0.0
[0.5.0]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v0.5.0
[0.4.2]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v0.4.2
[0.4.1]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v0.4.1
[0.4.0]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v0.4.0
[0.3.0]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v0.3.0
[0.2.0]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v0.2.0
[0.1.0]: https://github.com/artifact-keeper/artifact-keeper-cli/releases/tag/v0.1.0
