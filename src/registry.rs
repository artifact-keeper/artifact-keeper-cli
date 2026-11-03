//! Which `ak` command covers which server route.
//!
//! This is the data behind the coverage gate (WS-G in the coverage plan). A route
//! is covered by a first-class command, or excluded with a reason and reachable
//! through `ak api`. The list is compiled in, so the gate reads what the binary
//! really has, and a test here checks that every `command` parses.
//!
//! # Adding an entry
//!
//! When you add or change a command, add a line per route it calls, in the group
//! for that command:
//!
//! ```text
//! covered("GET", "/api/v1/repositories/{key}", "repo show", &[]),
//! ```
//!
//! - `method` and `path` are as in the backend's route table: `{name}` for a path
//!   parameter, the same names as the OpenAPI spec.
//! - `command` is the path of subcommands, as typed after `ak`, with no arguments.
//! - `binds` lists every query and body field in the 1.11.10 schema that a flag or
//!   positional can set. Path parameters aren't listed. The gate will compare this
//!   with the schema, so leave out a field the command can't set. An empty list
//!   today means "not checked yet", not "there are none".
//!
//! For a route that shouldn't have a command, use `excluded(method, path, reason)`.
//! The reason is for a reviewer: say why a command adds nothing over `ak api`.
//!
//! A route with two commands gets two lines. The list doesn't need to be sorted
//! within a group. The gate, not this file's order, decides what's missing.

/// One route: covered by a command, or excluded with a reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Op {
    pub method: &'static str,
    pub path: &'static str,
    /// Subcommand path after `ak`. Empty for an excluded route.
    pub command: &'static str,
    /// Query and body fields a flag or positional can set.
    pub binds: &'static [&'static str],
    /// Why this route has no first-class command.
    pub excluded: Option<&'static str>,
}

const fn covered(
    method: &'static str,
    path: &'static str,
    command: &'static str,
    binds: &'static [&'static str],
) -> Op {
    Op {
        method,
        path,
        command,
        binds,
        excluded: None,
    }
}

const fn excluded(method: &'static str, path: &'static str, reason: &'static str) -> Op {
    Op {
        method,
        path,
        command: "",
        binds: &[],
        excluded: Some(reason),
    }
}

const IDP_CALLBACK: &str = "An identity provider sends a browser here with a code or an \
                            assertion. A CLI never starts this request";
const SSO_REDIRECT: &str = "A 302 to the identity provider, which the planned \
                            `auth login --sso` prints with --no-follow";
const WASM_PASSTHROUGH: &str = "A WASM plugin defines what this does, so `ak api` is the \
                                right interface";

const BANNER_FIELDS: &[&str] = &[
    "title",
    "message",
    "severity",
    "target",
    "link_url",
    "starts_at",
    "ends_at",
    "enabled",
];

/// The fields `repo create` and `repo update` share, plus the ones given.
macro_rules! repo_body_fields {
    ($($field:literal),*) => {
        &[
            "allow_anonymous_access",
            "allow_public_with_upstream_credentials",
            "apt_description",
            "apt_label",
            "apt_origin",
            "apt_release_version",
            "curation_allow_unverified",
            "custom_user_agent",
            "debian",
            "description",
            "index_upstream_url",
            "is_public",
            "key",
            "name",
            "npm_allow_unscoped",
            "npm_allowed_name_patterns",
            "npm_allowed_scopes",
            "npm_virtual_isolate_hosted_names",
            "oci_trusted_bearer_realms",
            "project_id",
            "promotion_only",
            "pypi_upstream_index_path",
            "quota_bytes",
            "repodata_depth",
            "trusted_gpg_key",
            "upstream_url",
            "versioning_enabled",
            "visibility",
            $($field),*
        ]
    };
}

/// Every route with a known place in the CLI. Workstreams add to this. It isn't
/// complete until the coverage gate says so.
pub static COMMANDS: &[Op] = &[
    // ---- auth ----
    covered(
        "POST",
        "/api/v1/auth/login",
        "auth login",
        &["username", "password"],
    ),
    covered("POST", "/api/v1/auth/logout", "auth logout", &[]),
    covered(
        "POST",
        "/api/v1/auth/refresh",
        "auth refresh",
        &["refresh_token"],
    ),
    covered("GET", "/api/v1/auth/me", "auth whoami", &[]),
    covered(
        "POST",
        "/api/v1/auth/tokens",
        "auth token create",
        &["name", "expires_in_days"],
    ),
    covered(
        "DELETE",
        "/api/v1/auth/tokens/{token_id}",
        "auth revoke-token",
        &[],
    ),
    // ---- repositories ----
    covered(
        "GET",
        "/api/v1/repositories",
        "repo list",
        &["page", "per_page", "format", "type", "q", "project"],
    ),
    covered(
        "POST",
        "/api/v1/repositories",
        "repo create",
        repo_body_fields!(
            "format",
            "format_key",
            "member_repos",
            "repo_type",
            "storage_backend",
            "upstream_auth_type",
            "upstream_password",
            "upstream_username"
        ),
    ),
    covered("GET", "/api/v1/repositories/{key}", "repo show", &[]),
    covered(
        "PATCH",
        "/api/v1/repositories/{key}",
        "repo update",
        repo_body_fields!(
            "curation_default_action",
            "curation_enabled",
            "quarantine_duration_minutes",
            "quarantine_enabled",
            "release_repository_key",
            "virtual_metadata_partial"
        ),
    ),
    covered("DELETE", "/api/v1/repositories/{key}", "repo delete", &[]),
    covered(
        "GET",
        "/api/v1/repositories/{key}/members",
        "repo members list",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/members",
        "repo members add",
        &["member_key", "priority"],
    ),
    covered(
        "PUT",
        "/api/v1/repositories/{key}/members",
        "repo members reorder",
        &["members"],
    ),
    covered(
        "DELETE",
        "/api/v1/repositories/{key}/members/{member_key}",
        "repo members remove",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/routing-rules",
        "repo routing-rules get",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/routing-rules",
        "repo routing-rules set",
        &["rules"],
    ),
    covered(
        "DELETE",
        "/api/v1/repositories/{key}/routing-rules",
        "repo routing-rules delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/cache-ttl",
        "repo cache get-ttl",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/repositories/{key}/cache-ttl",
        "repo cache set-ttl",
        &["cache_ttl_seconds"],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/cache/invalidate",
        "repo cache invalidate",
        &["path"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/pypi-tracks",
        "repo pypi-tracks list",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/repositories/{key}/pypi-tracks/{project}",
        "repo pypi-tracks set",
        &["tracks_url"],
    ),
    covered(
        "DELETE",
        "/api/v1/repositories/{key}/pypi-tracks/{project}",
        "repo pypi-tracks remove",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/repositories/{key}/upstream-auth",
        "repo upstream-auth",
        &[
            "allow_public_with_upstream_credentials",
            "auth_type",
            "aws",
            "password",
            "username",
        ],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/test-upstream",
        "repo test-upstream",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/tree",
        "repo tree",
        &["include_metadata", "path", "repository_key"],
    ),
    covered(
        "GET",
        "/api/v1/tree/content",
        "repo cat",
        &["max_bytes", "path", "repository_key"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/_/capabilities",
        "repo capabilities",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/allowlist",
        "repo allowlist get",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/repositories/{key}/allowlist",
        "repo allowlist set",
        &["enabled", "entries", "scope"],
    ),
    covered(
        "DELETE",
        "/api/v1/repositories/{key}/allowlist",
        "repo allowlist delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/upstream-filter",
        "repo upstream-filter get",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/repositories/{key}/upstream-filter",
        "repo upstream-filter set",
        &["exclude_patterns", "include_patterns"],
    ),
    covered(
        "DELETE",
        "/api/v1/repositories/{key}/upstream-filter",
        "repo upstream-filter delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/egress-proxy",
        "repo egress-proxy get",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/repositories/{key}/egress-proxy",
        "repo egress-proxy set",
        &["mode", "no_proxy", "proxy_url"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/npm-scope-policy",
        "repo npm-scope-policy get",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/repositories/{key}/npm-scope-policy",
        "repo npm-scope-policy set",
        &["allow_unscoped", "allowed_scopes"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/storage",
        "repo storage",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/storage/tree",
        "repo storage",
        &["depth", "limit", "prefix"],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/storage-gc",
        "repo storage-gc",
        &["dry_run"],
    ),
    // ---- artifacts ----
    covered(
        "GET",
        "/api/v1/repositories/{key}/artifacts",
        "artifact list",
        &[
            "count",
            "cursor",
            "group_by",
            "page",
            "path_prefix",
            "per_page",
            "q",
        ],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/artifacts",
        "artifact push",
        &["file", "path"],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/artifacts/{path}",
        "artifact push",
        &["file"],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/artifacts-missing",
        "artifact missing",
        &["items"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/versions/{path}",
        "artifact versions",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/artifacts/{id}/package-analysis",
        "artifact package-analysis",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/uploads",
        "artifact push",
        &[
            "artifact_metadata",
            "artifact_metadata_format",
            "artifact_metadata_properties",
            "artifact_name",
            "artifact_path",
            "artifact_version",
            "checksum_sha256",
            "chunk_size",
            "content_type",
            "package_description",
            "package_metadata",
            "repository_key",
            "skip_if_present",
            "total_size",
        ],
    ),
    covered(
        "PATCH",
        "/api/v1/uploads/{session_id}",
        "artifact push",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/uploads/{session_id}/complete",
        "artifact push",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/uploads/{session_id}",
        "artifact upload-session status",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/uploads/{session_id}",
        "artifact upload-session cancel",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/promotion/repositories/{key}/artifacts/{artifact_id}/promote",
        "artifact copy",
        &["notes", "skip_policy_check", "target_repository"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/artifacts/{path}",
        "artifact info",
        &["version"],
    ),
    covered(
        "PUT",
        "/api/v1/repositories/{key}/artifacts/{path}",
        "artifact push",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/repositories/{key}/artifacts/{path}",
        "artifact delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/download/{path}",
        "artifact pull",
        &["version"],
    ),
    covered("GET", "/api/v1/artifacts/{id}", "artifact show", &[]),
    covered(
        "GET",
        "/api/v1/artifacts/{id}/metadata",
        "artifact metadata",
        &[],
    ),
    covered("GET", "/api/v1/artifacts/{id}/stats", "artifact stats", &[]),
    covered(
        "GET",
        "/api/v1/search/advanced",
        "artifact search",
        &[
            "created_after",
            "created_before",
            "format",
            "max_size",
            "min_size",
            "name",
            "page",
            "path",
            "per_page",
            "query",
            "repository_key",
            "sort_by",
            "sort_order",
            "version",
        ],
    ),
    // ---- lifecycle ----
    covered(
        "GET",
        "/api/v1/admin/lifecycle",
        "lifecycle list",
        &["repository_id"],
    ),
    covered("POST", "/api/v1/admin/lifecycle", "lifecycle create", &[]),
    covered("GET", "/api/v1/admin/lifecycle/{id}", "lifecycle show", &[]),
    covered(
        "PATCH",
        "/api/v1/admin/lifecycle/{id}",
        "lifecycle update",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/admin/lifecycle/{id}",
        "lifecycle delete",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/admin/lifecycle/{id}/execute",
        "lifecycle execute",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/admin/lifecycle/{id}/preview",
        "lifecycle preview",
        &[],
    ),
    // ---- webhooks ----
    covered("GET", "/api/v1/webhooks", "webhook list", &[]),
    covered("POST", "/api/v1/webhooks", "webhook create", &[]),
    covered("GET", "/api/v1/webhooks/{id}", "webhook show", &[]),
    covered("DELETE", "/api/v1/webhooks/{id}", "webhook delete", &[]),
    covered(
        "POST",
        "/api/v1/webhooks/{id}/enable",
        "webhook enable",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/webhooks/{id}/disable",
        "webhook disable",
        &[],
    ),
    // ---- quarantine ----
    covered(
        "GET",
        "/api/v1/quarantine/{artifact_id}",
        "quarantine status",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/quarantine/{artifact_id}/quarantine",
        "quarantine hold",
        &["reason"],
    ),
    covered(
        "POST",
        "/api/v1/quarantine/{artifact_id}/release",
        "quarantine release",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/quarantine/{artifact_id}/reject",
        "quarantine reject",
        &["reason"],
    ),
    // ---- projects ----
    covered("GET", "/api/v1/projects", "project list", &[]),
    covered(
        "POST",
        "/api/v1/projects",
        "project create",
        &["key", "name", "description", "quota_bytes"],
    ),
    covered("GET", "/api/v1/projects/{id}", "project show", &[]),
    covered(
        "PUT",
        "/api/v1/projects/{id}",
        "project update",
        &["name", "description", "quota_bytes"],
    ),
    covered("DELETE", "/api/v1/projects/{id}", "project delete", &[]),
    covered(
        "GET",
        "/api/v1/projects/{id}/members",
        "project members list",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/projects/{id}/members",
        "project members add",
        &["principal_type", "principal_id", "actions"],
    ),
    covered(
        "DELETE",
        "/api/v1/projects/{id}/members",
        "project members remove",
        &["principal_type", "principal_id"],
    ),
    // ---- banners ----
    covered("GET", "/api/v1/banners", "banner active", &["target"]),
    covered("GET", "/api/v1/admin/banners", "banner list", &[]),
    covered(
        "POST",
        "/api/v1/admin/banners",
        "banner create",
        BANNER_FIELDS,
    ),
    covered("GET", "/api/v1/admin/banners/{id}", "banner show", &[]),
    covered(
        "PUT",
        "/api/v1/admin/banners/{id}",
        "banner update",
        BANNER_FIELDS,
    ),
    covered("DELETE", "/api/v1/admin/banners/{id}", "banner delete", &[]),
    // ---- admin observability ----
    covered(
        "GET",
        "/api/v1/admin/audit",
        "admin audit list",
        &[
            "user_id",
            "action",
            "resource_type",
            "resource_id",
            "correlation_id",
            "from",
            "to",
            "page",
            "per_page",
        ],
    ),
    covered(
        "GET",
        "/api/v1/admin/downloads",
        "admin downloads list",
        &[
            "artifact_id",
            "user_id",
            "ip",
            "from",
            "to",
            "source",
            "repository_id",
            "page",
            "per_page",
        ],
    ),
    covered(
        "GET",
        "/api/v1/admin/downloads/by-ip/{ip}",
        "admin downloads by-ip",
        &[
            "artifact_id",
            "source",
            "repository_id",
            "user_id",
            "from",
            "to",
            "page",
            "per_page",
        ],
    ),
    covered(
        "GET",
        "/api/v1/admin/downloads/by-user/{user_id}",
        "admin downloads by-user",
        &[
            "artifact_id",
            "source",
            "repository_id",
            "ip",
            "from",
            "to",
            "page",
            "per_page",
        ],
    ),
    covered(
        "GET",
        "/api/v1/admin/security/artifact/{artifact_id}/blast-radius",
        "admin blast-radius artifact",
        &["from", "to", "page", "per_page"],
    ),
    covered(
        "GET",
        "/api/v1/admin/security/artifact/{artifact_id}/accessible-users",
        "admin blast-radius artifact",
        &["repository_id", "page", "per_page"],
    ),
    covered(
        "GET",
        "/api/v1/admin/security/cve/{cve_id}/blast-radius",
        "admin blast-radius cve",
        &["from", "to", "page", "per_page"],
    ),
    covered(
        "GET",
        "/api/v1/admin/security/cve/{cve_id}/accessible-users",
        "admin blast-radius cve",
        &["repository_id", "page", "per_page"],
    ),
    covered(
        "GET",
        "/api/v1/admin/proxy-scan-verdicts/{digest}",
        "admin proxy-scan-verdict show",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/admin/proxy-scan-verdicts/{digest}",
        "admin proxy-scan-verdict delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/npm/upstream-feed/status",
        "admin npm-feed status",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/holds/quarantine",
        "admin holds quarantine",
        &["repository_key", "kind", "page", "per_page"],
    ),
    covered(
        "GET",
        "/api/v1/admin/holds/summary",
        "admin holds summary",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/admin/age-gate/reviews/{id}/reopen",
        "age-gate reopen",
        &["reason"],
    ),
    covered(
        "GET",
        "/api/v1/admin/quality-checks",
        "quality-gate checks",
        &["repository_id", "artifact_id", "status", "page", "per_page"],
    ),
    // ---- excluded: reachable with `ak api` ----
    excluded("GET", "/api/v1/auth/sso/oidc/{id}/callback", IDP_CALLBACK),
    excluded("GET", "/api/v1/auth/sso/oidc/callback", IDP_CALLBACK),
    excluded("POST", "/api/v1/auth/sso/saml/{id}/acs", IDP_CALLBACK),
    excluded("GET", "/api/v1/auth/sso/oidc/{id}/login", SSO_REDIRECT),
    excluded("GET", "/api/v1/auth/sso/saml/{id}/login", SSO_REDIRECT),
    excluded("ANY", "/ext/{format_key}/{repo_key}", WASM_PASSTHROUGH),
    excluded(
        "ANY",
        "/ext/{format_key}/{repo_key}/{path}",
        WASM_PASSTHROUGH,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::CommandFactory;

    const METHODS: &[&str] = &[
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "ANY",
    ];

    /// Walk the clap tree by subcommand name, the way a user would type it.
    fn resolves(path: &str) -> bool {
        let root = Cli::command();
        let mut current = &root;
        for name in path.split_whitespace() {
            match current.find_subcommand(name) {
                Some(next) => current = next,
                None => return false,
            }
        }
        true
    }

    #[test]
    fn every_command_parses() {
        let broken: Vec<_> = COMMANDS
            .iter()
            .filter(|op| op.excluded.is_none() && !resolves(op.command))
            .map(|op| format!("{} {} -> ak {}", op.method, op.path, op.command))
            .collect();
        assert!(broken.is_empty(), "no such command: {broken:#?}");
    }

    #[test]
    fn the_walk_rejects_a_command_that_does_not_exist() {
        assert!(resolves("repo show"));
        assert!(!resolves("repo no-such-command"));
        assert!(!resolves("no-such-group"));
    }

    #[test]
    fn every_entry_is_well_formed() {
        for op in COMMANDS {
            assert!(METHODS.contains(&op.method), "{op:?}");
            assert!(op.path.starts_with('/'), "{op:?}");
            match op.excluded {
                Some(reason) => {
                    assert!(
                        !reason.trim().is_empty(),
                        "an exclusion needs a reason: {op:?}"
                    );
                    assert!(
                        op.command.is_empty(),
                        "covered or excluded, not both: {op:?}"
                    );
                    assert!(op.binds.is_empty(), "{op:?}");
                }
                None => assert!(!op.command.is_empty(), "no command and no reason: {op:?}"),
            }
        }
    }

    #[test]
    fn no_entry_is_listed_twice() {
        let mut seen = std::collections::HashSet::new();
        for op in COMMANDS {
            assert!(
                seen.insert((op.method, op.path, op.command)),
                "listed twice: {op:?}"
            );
        }
    }
}
