//! Which `ak` command covers which server route.
//!
//! This is the data behind the coverage gate, `cargo run -p xtask -- coverage --check`.
//! A route is covered by a first-class command, or excluded with a reason and
//! reachable through `ak api`. The list is compiled in, so the gate reads what the
//! binary really has, through `ak __registry`. `tests/registry_contract.rs` runs each
//! line against a mock server and fails if the command doesn't do what the line says.
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
//! - `binds` lists every query and body field in the pinned API schema that a flag or
//!   positional can set. Path parameters aren't listed. The gate compares this with
//!   the schema, and `tests/registry_contract.rs` checks each one reaches the server,
//!   so leave out a field the command can't set.
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

/// A whole class of routes with no first-class command, from section 1 of the
/// coverage plan. The gate applies these after the lines in [`COMMANDS`], fails if one
/// matches no route, and prints how many each one takes out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassExclusion {
    pub name: &'static str,
    /// Methods it applies to. Empty means any.
    pub methods: &'static [&'static str],
    /// Path prefixes it applies to. A prefix matches whole segments.
    pub prefixes: &'static [&'static str],
    /// Path prefixes taken back out, because those routes do get a command.
    pub except: &'static [&'static str],
    pub reason: &'static str,
}

/// The URL prefix of each package-format wire protocol: `format_routes` in the
/// backend's `routes.rs`. `/v2` isn't here: OCI has its own classes.
pub const FORMAT_PREFIXES: &[&str] = &[
    "/alpine",
    "/ansible",
    "/api/cargo",
    "/api/helm",
    "/bazel",
    "/cargo",
    "/chef",
    "/cocoapods",
    "/composer",
    "/conan",
    "/conda",
    "/cran",
    "/debian",
    "/gems",
    "/general",
    "/go",
    "/helm",
    "/hex",
    "/huggingface",
    "/incus",
    "/ivy",
    "/jetbrains",
    "/lfs",
    "/lxc",
    "/maven",
    "/npm",
    "/nuget",
    "/pacman",
    "/proto",
    "/pub",
    "/puppet",
    "/pypi",
    "/rpm",
    "/swift",
    "/t",
    "/terraform",
    "/vscode",
];

pub static CLASS_EXCLUSIONS: &[ClassExclusion] = &[
    ClassExclusion {
        name: "format-get",
        methods: &["GET", "HEAD"],
        prefixes: FORMAT_PREFIXES,
        except: &[],
        reason: "A plain GET of a package-format wire route is what `ak api GET` already \
                 sends. A command per format GET would be a wrapper that adds nothing",
    },
    ClassExclusion {
        name: "oci-blob-upload",
        methods: &[],
        prefixes: &["/v2/{name}/blobs/uploads"],
        except: &[],
        reason: "The OCI blob upload session is a chunk protocol docker and oras implement. \
                 `ak api` can send any single step",
    },
    ClassExclusion {
        name: "oci-handshake",
        methods: &["GET", "POST"],
        prefixes: &["/v2"],
        except: &["/v2/_catalog", "/v2/{name}"],
        reason: "The version check and the token exchange are the handshake docker and oras do \
                 before any other call. `ak pkg oci` sends the instance's token on /v2 itself, so \
                 it never needs them, and `ak api` sends either one as it is",
    },
    ClassExclusion {
        name: "oci-blob-head",
        methods: &["HEAD"],
        prefixes: &["/v2/{name}/blobs/{digest}"],
        except: &[],
        reason: "A HEAD of a blob is a plain check that it exists, as for a package download. \
                 `ak api HEAD` already sends it, and a command would be a wrapper that adds nothing",
    },
];

/// A request field in the schema that no flag should set, and why. The gate counts
/// these apart from the fields that have a flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldOptOut {
    pub method: &'static str,
    pub path: &'static str,
    pub field: &'static str,
    pub reason: &'static str,
}

pub static FIELD_OPT_OUTS: &[FieldOptOut] = &[FieldOptOut {
    method: "GET",
    path: "/api/v1/repositories/{key}/security/scans",
    field: "repository_id",
    reason: "The route's key already picks the repository. `scan list --repo <uuid>` sends \
             this filter to the route that lists every repository's scans",
}];

const IDP_CALLBACK: &str = "An identity provider sends a browser here with a code or an \
                            assertion. A CLI never starts this request";
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
    covered(
        "POST",
        "/api/v1/auth/logout",
        "auth logout",
        &["refresh_token"],
    ),
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
        &["name", "expires_in_days", "scopes", "repo_selector"],
    ),
    covered(
        "DELETE",
        "/api/v1/auth/tokens/{token_id}",
        "auth token revoke",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/auth/ticket",
        "auth download-ticket",
        &["purpose", "resource_path"],
    ),
    covered(
        "POST",
        "/api/v1/auth/ci/token",
        "auth ci-exchange",
        &["provider_id"],
    ),
    covered(
        "POST",
        "/api/v1/auth/totp/verify",
        "auth verify-totp",
        &["code", "totp_token"],
    ),
    covered(
        "POST",
        "/api/v1/auth/sso/ldap/{id}/login",
        "auth login",
        &["username", "password"],
    ),
    covered(
        "GET",
        "/api/v1/auth/sso/oidc/{id}/login",
        "auth login",
        &["prompt"],
    ),
    covered("GET", "/api/v1/auth/sso/saml/{id}/login", "auth login", &[]),
    covered(
        "POST",
        "/api/v1/auth/sso/exchange",
        "auth sso-exchange",
        &["code"],
    ),
    // ---- totp ----
    covered("POST", "/api/v1/auth/totp/setup", "totp setup", &[]),
    covered("POST", "/api/v1/auth/totp/enable", "totp enable", &["code"]),
    covered(
        "POST",
        "/api/v1/auth/totp/disable",
        "totp disable",
        &["code", "password"],
    ),
    covered(
        "POST",
        "/api/v1/auth/totp/enroll/setup",
        "totp enroll setup",
        &["totp_token"],
    ),
    covered(
        "POST",
        "/api/v1/auth/totp/enroll/complete",
        "totp enroll complete",
        &["code", "totp_token"],
    ),
    // ---- search ----
    covered(
        "GET",
        "/api/v1/search/quick",
        "search quick",
        &["q", "limit", "types"],
    ),
    covered(
        "GET",
        "/api/v1/search/checksum",
        "search checksum",
        &["checksum", "algorithm"],
    ),
    covered(
        "GET",
        "/api/v1/search/suggest",
        "search suggest",
        &["prefix", "limit"],
    ),
    covered("GET", "/api/v1/search/recent", "search recent", &["limit"]),
    covered(
        "GET",
        "/api/v1/search/trending",
        "search trending",
        &["days", "limit"],
    ),
    // ---- events ----
    covered("GET", "/api/v1/events/stream", "events tail", &[]),
    // ---- profile and users ----
    covered("GET", "/api/v1/users/me", "profile whoami", &[]),
    covered(
        "POST",
        "/api/v1/users/me/password",
        "profile change-password",
        &["current_password", "new_password"],
    ),
    covered("GET", "/api/v1/users/me/tokens", "profile tokens list", &[]),
    covered(
        "POST",
        "/api/v1/users/me/tokens",
        "profile tokens create",
        &["name", "scopes", "expires_in_days"],
    ),
    covered(
        "DELETE",
        "/api/v1/users/me/tokens/{token_id}",
        "profile tokens revoke",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/profile/access-tokens",
        "profile access-tokens list",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/profile/access-tokens",
        "profile access-tokens create",
        &["name", "scopes", "expires_in_days"],
    ),
    covered(
        "DELETE",
        "/api/v1/profile/access-tokens/{token_id}",
        "profile access-tokens revoke",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/users",
        "admin users list",
        &[
            "search",
            "is_active",
            "is_admin",
            "is_service_account",
            "page",
            "per_page",
        ],
    ),
    covered(
        "POST",
        "/api/v1/users",
        "admin users create",
        &["username", "email", "display_name", "is_admin", "password"],
    ),
    covered(
        "POST",
        "/api/v1/users/{id}/password",
        "admin users set-password",
        &["current_password", "new_password"],
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
        "artifact show",
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
    covered(
        "POST",
        "/api/v1/admin/lifecycle",
        "lifecycle create",
        &[
            "applies_to_all",
            "config",
            "cron_schedule",
            "description",
            "enabled",
            "name",
            "policy_type",
            "priority",
            "repository_id",
            "repository_ids",
        ],
    ),
    covered("GET", "/api/v1/admin/lifecycle/{id}", "lifecycle show", &[]),
    covered(
        "PATCH",
        "/api/v1/admin/lifecycle/{id}",
        "lifecycle update",
        &[
            "applies_to_all",
            "config",
            "cron_schedule",
            "description",
            "enabled",
            "name",
            "priority",
            "repository_ids",
        ],
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
    covered(
        "POST",
        "/api/v1/admin/lifecycle/execute-all",
        "lifecycle execute-all",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/admin/lifecycle/{id}/repositories/{repository_id}",
        "lifecycle attach",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/admin/lifecycle/{id}/repositories/{repository_id}",
        "lifecycle detach",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/lifecycle/capabilities",
        "lifecycle capabilities",
        &[],
    ),
    // ---- webhooks ----
    covered(
        "GET",
        "/api/v1/webhooks",
        "webhook list",
        &["repository_id", "enabled", "page", "per_page"],
    ),
    covered(
        "POST",
        "/api/v1/webhooks",
        "webhook create",
        &[
            "event_schema_version",
            "events",
            "headers",
            "name",
            "payload_template",
            "repository_id",
            "secret",
            "signing_mode",
            "url",
        ],
    ),
    covered("GET", "/api/v1/webhooks/jwks", "webhook jwks", &[]),
    covered(
        "GET",
        "/api/v1/webhooks/{id}/deliveries",
        "webhook deliveries",
        &["status", "page", "per_page"],
    ),
    covered(
        "POST",
        "/api/v1/webhooks/{id}/deliveries/{delivery_id}/redeliver",
        "webhook redeliver",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/webhooks/{id}/rotate-secret",
        "webhook rotate-secret",
        &[],
    ),
    covered("POST", "/api/v1/webhooks/{id}/test", "webhook test", &[]),
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
    // ---- sso ----
    covered("GET", "/api/v1/admin/sso/ldap", "sso list", &[]),
    covered(
        "POST",
        "/api/v1/admin/sso/ldap",
        "sso create ldap",
        &[
            "admin_group_dn",
            "bind_dn",
            "bind_password",
            "ca_certificate",
            "display_name_attribute",
            "email_attribute",
            "group_base_dn",
            "group_filter",
            "groups_attribute",
            "insecure_skip_verify",
            "is_enabled",
            "name",
            "priority",
            "server_url",
            "use_starttls",
            "user_base_dn",
            "user_filter",
            "username_attribute",
        ],
    ),
    covered("GET", "/api/v1/admin/sso/ldap/{id}", "sso show", &[]),
    covered(
        "PUT",
        "/api/v1/admin/sso/ldap/{id}",
        "sso update ldap",
        &[
            "admin_group_dn",
            "bind_dn",
            "bind_password",
            "ca_certificate",
            "display_name_attribute",
            "email_attribute",
            "group_base_dn",
            "group_filter",
            "groups_attribute",
            "insecure_skip_verify",
            "is_enabled",
            "name",
            "priority",
            "server_url",
            "use_starttls",
            "user_base_dn",
            "user_filter",
            "username_attribute",
        ],
    ),
    covered("DELETE", "/api/v1/admin/sso/ldap/{id}", "sso delete", &[]),
    covered(
        "PATCH",
        "/api/v1/admin/sso/ldap/{id}/toggle",
        "sso toggle",
        &["enabled"],
    ),
    covered("GET", "/api/v1/admin/sso/oidc", "sso list", &[]),
    covered(
        "POST",
        "/api/v1/admin/sso/oidc",
        "sso create oidc",
        &[
            "admin_group",
            "allow_legacy_rsa_keys",
            "attribute_mapping",
            "auto_create_users",
            "client_id",
            "client_secret",
            "is_enabled",
            "issuer_url",
            "map_groups_to_groups",
            "name",
            "pkce_enabled",
            "scopes",
        ],
    ),
    covered("GET", "/api/v1/admin/sso/oidc/{id}", "sso show", &[]),
    covered(
        "PUT",
        "/api/v1/admin/sso/oidc/{id}",
        "sso update oidc",
        &[
            "admin_group",
            "allow_legacy_rsa_keys",
            "attribute_mapping",
            "auto_create_users",
            "client_id",
            "client_secret",
            "is_enabled",
            "issuer_url",
            "map_groups_to_groups",
            "name",
            "pkce_enabled",
            "scopes",
            "attribute_mapping_replace",
        ],
    ),
    covered("DELETE", "/api/v1/admin/sso/oidc/{id}", "sso delete", &[]),
    covered(
        "PATCH",
        "/api/v1/admin/sso/oidc/{id}/toggle",
        "sso toggle",
        &["enabled"],
    ),
    covered("GET", "/api/v1/admin/sso/saml", "sso list", &[]),
    covered(
        "POST",
        "/api/v1/admin/sso/saml",
        "sso create saml",
        &[
            "admin_group",
            "attribute_mapping",
            "certificate",
            "entity_id",
            "is_enabled",
            "map_groups_to_groups",
            "name",
            "name_id_format",
            "require_signed_assertions",
            "sign_requests",
            "slo_url",
            "slug",
            "sp_entity_id",
            "sso_url",
            "use_absolute_acs_url",
        ],
    ),
    covered("GET", "/api/v1/admin/sso/saml/{id}", "sso show", &[]),
    covered(
        "PUT",
        "/api/v1/admin/sso/saml/{id}",
        "sso update saml",
        &[
            "admin_group",
            "attribute_mapping",
            "certificate",
            "entity_id",
            "is_enabled",
            "map_groups_to_groups",
            "name",
            "name_id_format",
            "require_signed_assertions",
            "sign_requests",
            "slo_url",
            "slug",
            "sp_entity_id",
            "sso_url",
            "use_absolute_acs_url",
        ],
    ),
    covered("DELETE", "/api/v1/admin/sso/saml/{id}", "sso delete", &[]),
    covered(
        "PATCH",
        "/api/v1/admin/sso/saml/{id}/toggle",
        "sso toggle",
        &["enabled"],
    ),
    covered("POST", "/api/v1/admin/sso/ldap/{id}/test", "sso test", &[]),
    covered("GET", "/api/v1/admin/sso/providers", "sso providers", &[]),
    covered("GET", "/api/v1/auth/sso/providers", "sso providers", &[]),
    // ---- permissions ----
    covered(
        "GET",
        "/api/v1/permissions",
        "permission list",
        &[
            "principal_type",
            "principal_id",
            "target_type",
            "target_id",
            "page",
            "per_page",
        ],
    ),
    covered(
        "POST",
        "/api/v1/permissions",
        "permission create",
        &[
            "actions",
            "conditions",
            "principal_id",
            "principal_type",
            "target_id",
            "target_type",
        ],
    ),
    covered("GET", "/api/v1/permissions/{id}", "permission show", &[]),
    covered(
        "PUT",
        "/api/v1/permissions/{id}",
        "permission update",
        &[
            "actions",
            "conditions",
            "principal_id",
            "principal_type",
            "target_id",
            "target_type",
        ],
    ),
    covered(
        "DELETE",
        "/api/v1/permissions/{id}",
        "permission delete",
        &[],
    ),
    // ---- backups ----
    covered(
        "GET",
        "/api/v1/admin/backups",
        "admin backup list",
        &["status", "type", "page", "per_page"],
    ),
    covered(
        "POST",
        "/api/v1/admin/backups",
        "admin backup create",
        &[
            "exclude_repositories",
            "name",
            "repository_ids",
            "since",
            "type",
        ],
    ),
    covered("GET", "/api/v1/admin/backups/{id}", "admin backup get", &[]),
    covered(
        "DELETE",
        "/api/v1/admin/backups/{id}",
        "admin backup delete",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/admin/backups/{id}/cancel",
        "admin backup cancel",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/admin/backups/{id}/execute",
        "admin backup execute",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/admin/backups/{id}/restore",
        "admin backup restore",
        &[
            "allow_unverified_archive",
            "restore_artifacts",
            "restore_database",
            "target_repository_id",
        ],
    ),
    // ---- CI OIDC ----
    covered("GET", "/api/v1/admin/ci-oidc", "admin ci-oidc list", &[]),
    covered(
        "POST",
        "/api/v1/admin/ci-oidc",
        "admin ci-oidc create",
        &[
            "audience",
            "is_enabled",
            "issuer_url",
            "key_source",
            "name",
            "provider_type",
            "static_jwks",
        ],
    ),
    covered(
        "GET",
        "/api/v1/admin/ci-oidc/{id}",
        "admin ci-oidc get",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/admin/ci-oidc/{id}",
        "admin ci-oidc update",
        &[
            "audience",
            "is_enabled",
            "issuer_url",
            "key_source",
            "name",
            "provider_type",
            "static_jwks",
        ],
    ),
    covered(
        "DELETE",
        "/api/v1/admin/ci-oidc/{id}",
        "admin ci-oidc delete",
        &[],
    ),
    covered(
        "PATCH",
        "/api/v1/admin/ci-oidc/{id}/toggle",
        "admin ci-oidc toggle",
        &["enabled"],
    ),
    covered(
        "POST",
        "/api/v1/admin/ci-oidc/{id}/mappings",
        "admin ci-oidc mapping create",
        &[
            "allowed_repo_ids",
            "claim_filters",
            "group_binding_ids",
            "is_enabled",
            "name",
            "priority",
        ],
    ),
    covered(
        "PUT",
        "/api/v1/admin/ci-oidc/{id}/mappings/{mid}",
        "admin ci-oidc mapping update",
        &[
            "allowed_repo_ids",
            "claim_filters",
            "group_binding_ids",
            "is_enabled",
            "name",
            "priority",
        ],
    ),
    // ---- flags on other commands ----
    covered(
        "GET",
        "/api/v1/groups/{id}",
        "group show",
        &["member_limit", "member_offset"],
    ),
    covered(
        "GET",
        "/api/v1/peers",
        "peer list",
        &["status", "region", "page", "per_page"],
    ),
    covered(
        "POST",
        "/api/v1/peers",
        "peer register",
        &[
            "api_key",
            "cache_size_bytes",
            "endpoint_url",
            "name",
            "region",
            "sync_filter",
        ],
    ),
    covered(
        "GET",
        "/api/v1/peers/{id}/sync/tasks",
        "peer tasks",
        &["status", "region", "page", "per_page"],
    ),
    covered(
        "POST",
        "/api/v1/approval/{id}/approve",
        "approval approve",
        &["notes", "skip_policy_check"],
    ),
    covered(
        "POST",
        "/api/v1/approval/{id}/reject",
        "approval reject",
        &["notes", "skip_policy_check"],
    ),
    covered(
        "POST",
        "/api/v1/builds",
        "builds create",
        &[
            "agent",
            "build_number",
            "metadata",
            "name",
            "started_at",
            "vcs_branch",
            "vcs_message",
            "vcs_revision",
            "vcs_url",
        ],
    ),
    covered(
        "GET",
        "/api/v1/packages/{id}",
        "catalog show",
        &["repository_key"],
    ),
    covered(
        "POST",
        "/api/v1/promotion-rules",
        "promotion rule create",
        &[
            "allowed_licenses",
            "auto_promote",
            "is_enabled",
            "max_artifact_age_days",
            "max_cve_severity",
            "min_health_score",
            "min_staging_hours",
            "name",
            "require_signature",
            "source_repo_id",
            "target_repo_id",
        ],
    ),
    covered(
        "GET",
        "/api/v1/promotion/repositories/{key}/promotion-history",
        "promotion history",
        &["artifact_id", "status", "page", "per_page"],
    ),
    covered(
        "POST",
        "/api/v1/quality/gates",
        "quality-gate create",
        &[
            "action",
            "description",
            "enforce_on_download",
            "enforce_on_promotion",
            "max_critical_issues",
            "max_high_issues",
            "max_medium_issues",
            "min_health_score",
            "min_metadata_score",
            "min_quality_score",
            "min_security_score",
            "name",
            "repository_id",
            "required_checks",
        ],
    ),
    covered(
        "PUT",
        "/api/v1/quality/gates/{id}",
        "quality-gate update",
        &[
            "action",
            "description",
            "enforce_on_download",
            "enforce_on_promotion",
            "is_enabled",
            "max_critical_issues",
            "max_high_issues",
            "max_medium_issues",
            "min_health_score",
            "min_metadata_score",
            "min_quality_score",
            "min_security_score",
            "name",
            "required_checks",
        ],
    ),
    covered(
        "POST",
        "/api/v1/sync-policies",
        "sync-policy create",
        &[
            "artifact_filter",
            "description",
            "enabled",
            "filter",
            "name",
            "peer_selector",
            "precedence",
            "priority",
            "replication_mode",
            "repo_selector",
        ],
    ),
    covered(
        "PUT",
        "/api/v1/sync-policies/{id}",
        "sync-policy update",
        &[
            "artifact_filter",
            "description",
            "enabled",
            "name",
            "peer_selector",
            "precedence",
            "priority",
            "replication_mode",
            "repo_selector",
        ],
    ),
    covered(
        "POST",
        "/api/v1/sync-policies/preview",
        "sync-policy preview",
        &[
            "artifact_filter",
            "description",
            "enabled",
            "name",
            "peer_selector",
            "precedence",
            "priority",
            "replication_mode",
            "repo_selector",
        ],
    ),
    covered(
        "PUT",
        "/api/v1/repositories/{key}/age-gate",
        "age-gate set",
        &["enabled", "min_age_days", "mode"],
    ),
    covered(
        "POST",
        "/api/v1/admin/cleanup",
        "admin cleanup",
        &[
            "cleanup_audit_logs",
            "cleanup_old_backups",
            "cleanup_stale_peers",
            "cleanup_stale_uploads",
        ],
    ),
    covered(
        "GET",
        "/api/v1/plugins",
        "admin plugins list",
        &["status", "type"],
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
    // ---- curation ----
    covered(
        "GET",
        "/api/v1/curation/packages",
        "curation packages",
        &["staging_repo_id", "status", "limit", "offset"],
    ),
    covered(
        "GET",
        "/api/v1/curation/packages/{id}",
        "curation package",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/curation/packages/{id}/approve",
        "curation approve",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/curation/packages/{id}/block",
        "curation block",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/curation/packages/bulk-approve",
        "curation bulk-approve",
        &["ids", "reason"],
    ),
    covered(
        "POST",
        "/api/v1/curation/packages/bulk-block",
        "curation bulk-block",
        &["ids", "reason"],
    ),
    covered(
        "POST",
        "/api/v1/curation/packages/re-evaluate",
        "curation re-evaluate",
        &["staging_repo_id", "default_action"],
    ),
    covered(
        "GET",
        "/api/v1/curation/repos/{repo_key}/packages/search",
        "curation search",
        &["q", "arch", "status", "limit", "offset"],
    ),
    covered(
        "POST",
        "/api/v1/curation/repos/{repo_key}/sync",
        "curation sync",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/curation/repos/{repo_key}/versions",
        "curation version create",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/curation/repos/{repo_key}/versions/{n}/publish",
        "curation version publish",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/curation/rules",
        "curation rules",
        &["staging_repo_id", "scope"],
    ),
    covered(
        "POST",
        "/api/v1/curation/rules",
        "curation create-rule",
        &[
            "action",
            "architecture",
            "config",
            "package_pattern",
            "priority",
            "reason",
            "rule_type",
            "scope",
            "staging_repo_id",
            "version_constraint",
        ],
    ),
    covered("GET", "/api/v1/curation/rules/{id}", "curation rule", &[]),
    covered(
        "PUT",
        "/api/v1/curation/rules/{id}",
        "curation update-rule",
        &[
            "action",
            "architecture",
            "config",
            "enabled",
            "package_pattern",
            "priority",
            "reason",
            "rule_type",
            "version_constraint",
        ],
    ),
    covered(
        "DELETE",
        "/api/v1/curation/rules/{id}",
        "curation delete-rule",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/curation/stats",
        "curation stats",
        &["staging_repo_id"],
    ),
    // ---- scanning ----
    covered(
        "POST",
        "/api/v1/security/scan",
        "scan run",
        &["artifact_id", "bypass_dedup", "repository_id"],
    ),
    covered(
        "GET",
        "/api/v1/security/scans",
        "scan list",
        &[
            "repository_id",
            "artifact_id",
            "status",
            "scan_type",
            "page",
            "per_page",
        ],
    ),
    // `repository_id` is left out: the schema has it on this route too, but the key in
    // the path already names the repository, and `scan list --repo <id>` uses the
    // route above.
    covered(
        "GET",
        "/api/v1/repositories/{key}/security/scans",
        "scan list",
        &["artifact_id", "status", "scan_type", "page", "per_page"],
    ),
    covered("GET", "/api/v1/security/scans/{id}", "scan show", &[]),
    covered(
        "GET",
        "/api/v1/security/scans/{id}/findings",
        "scan show",
        &[
            "severity",
            "source",
            "cve_id",
            "finding_class",
            "page",
            "per_page",
        ],
    ),
    covered(
        "GET",
        "/api/v1/security/artifacts/{artifact_id}/scans",
        "scan artifact",
        &["status", "page", "per_page"],
    ),
    covered("GET", "/api/v1/security/dashboard", "scan dashboard", &[]),
    covered("GET", "/api/v1/security/scores", "scan scores", &[]),
    covered("GET", "/api/v1/security/configs", "scan config list", &[]),
    covered(
        "POST",
        "/api/v1/security/findings/{id}/acknowledge",
        "scan finding ack",
        &["reason"],
    ),
    covered(
        "DELETE",
        "/api/v1/security/findings/{id}/acknowledge",
        "scan finding revoke",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/security/findings/external",
        "scan finding ingest",
        &["artifact_id", "findings", "scanner", "scanner_version"],
    ),
    covered("GET", "/api/v1/security/policies", "scan policy list", &[]),
    covered(
        "POST",
        "/api/v1/security/policies",
        "scan policy create",
        &[
            "block_on_fail",
            "block_unscanned",
            "max_artifact_age_days",
            "max_severity",
            "min_staging_hours",
            "name",
            "predicates",
            "repository_id",
            "require_signature",
        ],
    ),
    covered(
        "GET",
        "/api/v1/security/policies/{id}",
        "scan policy show",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/security/policies/{id}",
        "scan policy update",
        &[
            "block_on_fail",
            "block_unscanned",
            "is_enabled",
            "max_artifact_age_days",
            "max_severity",
            "min_staging_hours",
            "name",
            "predicates",
            "require_signature",
        ],
    ),
    covered(
        "DELETE",
        "/api/v1/security/policies/{id}",
        "scan policy delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/security",
        "scan security show",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/repositories/{key}/security",
        "scan security update",
        &[
            "block_on_policy_violation",
            "proxy_scan_action",
            "scan_enabled",
            "scan_on_proxy",
            "scan_on_upload",
            "severity_threshold",
        ],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/security/proxy-scans",
        "scan proxy list",
        &["path", "page", "per_page"],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/security/proxy-scans/rescan",
        "scan proxy rescan",
        &["path"],
    ),
    covered(
        "POST",
        "/api/v1/quarantine/proxy-cache/{repo_key}/release",
        "quarantine release-proxy",
        &["path"],
    ),
    // ---- attestations ----
    covered(
        "GET",
        "/api/v1/attestations/policy",
        "attestation policy",
        &[],
    ),
    // ---- SBOM ----
    covered(
        "POST",
        "/api/v1/sbom",
        "sbom generate",
        &["artifact_id", "force_regenerate", "format"],
    ),
    covered(
        "GET",
        "/api/v1/sbom",
        "sbom list",
        &["artifact_id", "repository_id", "format"],
    ),
    covered(
        "GET",
        "/api/v1/sbom/by-artifact/{artifact_id}",
        "sbom show",
        &[],
    ),
    covered("GET", "/api/v1/sbom/{id}", "sbom get", &[]),
    covered("GET", "/api/v1/sbom/{id}", "sbom export", &[]),
    covered("DELETE", "/api/v1/sbom/{id}", "sbom delete", &[]),
    covered(
        "GET",
        "/api/v1/sbom/{id}/components",
        "sbom components",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/sbom/{id}/convert",
        "sbom export",
        &["target_format"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/security/proxy-sbom",
        "sbom proxy",
        &["path", "format"],
    ),
    covered(
        "POST",
        "/api/v1/sbom/environment",
        "sbom environment",
        &["filename", "format", "environment", "platform"],
    ),
    covered(
        "GET",
        "/api/v1/sbom/cve/history/{id}",
        "sbom cve history",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/sbom/cve/history/by-artifact/{artifact_id}",
        "sbom cve history-by-artifact",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/sbom/cve/history/by-cve/{cve_id}",
        "sbom cve history-by-cve",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/sbom/cve/trends",
        "sbom cve trends",
        &["repository_id", "days"],
    ),
    covered(
        "POST",
        "/api/v1/sbom/cve/status/{id}",
        "sbom cve update-status",
        &["status", "reason"],
    ),
    covered(
        "POST",
        "/api/v1/sbom/cve/status/by-artifact/{artifact_id}/by-cve/{cve_id}",
        "sbom cve update-status-by-artifact-cve",
        &["status", "reason"],
    ),
    // ---- signing ----
    covered(
        "GET",
        "/api/v1/signing/keys",
        "sign key list",
        &["repository_id"],
    ),
    covered(
        "POST",
        "/api/v1/signing/keys",
        "sign key create",
        &[
            "algorithm",
            "key_type",
            "name",
            "repository_id",
            "uid_email",
            "uid_name",
        ],
    ),
    covered("GET", "/api/v1/signing/keys/{key_id}", "sign key show", &[]),
    covered(
        "DELETE",
        "/api/v1/signing/keys/{key_id}",
        "sign key delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/signing/keys/{key_id}/public",
        "sign key export",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/signing/keys/{key_id}/revoke",
        "sign key revoke",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/signing/keys/{key_id}/rotate",
        "sign key rotate",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/signing/repositories/{repo_id}/config",
        "sign config show",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/signing/repositories/{repo_id}/config",
        "sign config update",
        &[
            "require_signatures",
            "sign_metadata",
            "sign_packages",
            "signing_key_id",
        ],
    ),
    covered(
        "GET",
        "/api/v1/signing/repositories/{repo_id}/public-key",
        "sign config export-key",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/signing/artifacts/{artifact_id}/sign",
        "sign artifact",
        &[],
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
    // ---- bundles ----
    covered("GET", "/api/v1/bundles/format", "bundle format", &[]),
    covered(
        "POST",
        "/api/v1/bundles/manifest/validate",
        "bundle validate-manifest",
        &[
            "format",
            "schema_version",
            "bundle_id",
            "created_at",
            "producer",
            "kind",
            "volume_set",
            "repositories",
            "items",
            "scan_evidence",
            "sequence",
            "signing",
        ],
    ),
    covered(
        "POST",
        "/api/v1/bundles/exports",
        "bundle export",
        &["repository_keys", "media_profile", "media_control_number"],
    ),
    covered("POST", "/api/v1/bundles/imports", "bundle import", &[]),
    covered(
        "GET",
        "/api/v1/bundles/jobs",
        "bundle jobs list",
        &["direction", "status", "page", "per_page"],
    ),
    covered("GET", "/api/v1/bundles/jobs/{id}", "bundle jobs show", &[]),
    covered(
        "GET",
        "/api/v1/bundles/jobs/{id}/items",
        "bundle jobs items",
        &["status", "page", "per_page"],
    ),
    // ---- environments ----
    covered(
        "POST",
        "/api/v1/repositories/{key}/environments",
        "environment ingest",
        &["filename", "name"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/environments",
        "environment list",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/environments/{id}",
        "environment show",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/repositories/{key}/environments/{id}",
        "environment delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/environments/{id}/advisories",
        "environment advisories",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/environments/lookup",
        "environment lookup",
        &["purl", "max_paths"],
    ),
    covered(
        "GET",
        "/api/v1/environments/advisory-transitions",
        "environment advisory-transitions",
        &["advisory", "kind", "since", "until", "limit"],
    ),
    // ---- image builds ----
    covered(
        "GET",
        "/api/v1/repositories/{key}/image-builds",
        "image-build list",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/image-builds",
        "image-build create",
        &["image", "tag", "spec"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/image-builds/{id}",
        "image-build show",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/image-builds/{id}/log",
        "image-build log",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/image-builds/render",
        "image-build render",
        &["spec"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/image-builds/settings",
        "image-build settings",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/image-builds/base-info",
        "image-build base-info",
        &["image"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/image-inspect",
        "image-build inspect",
        &["image", "reference"],
    ),
    // ---- admin settings and storage operations ----
    covered(
        "GET",
        "/api/v1/admin/settings/system",
        "admin settings system show",
        &[],
    ),
    covered(
        "PATCH",
        "/api/v1/admin/settings/system",
        "admin settings system update",
        &["guest_access_enabled"],
    ),
    covered(
        "GET",
        "/api/v1/admin/settings/token-policy",
        "admin settings token-policy show",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/admin/settings/token-policy",
        "admin settings token-policy set",
        &["policy"],
    ),
    covered(
        "GET",
        "/api/v1/admin/settings/totp-policy",
        "admin settings totp-policy show",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/admin/settings/totp-policy",
        "admin settings totp-policy set",
        &["policy"],
    ),
    covered(
        "POST",
        "/api/v1/admin/storage-scrub",
        "admin storage-scrub run",
        &["repair", "repository", "max_objects", "max_bytes"],
    ),
    covered(
        "GET",
        "/api/v1/admin/storage-scrub/findings",
        "admin storage-scrub findings",
        &["status", "limit"],
    ),
    covered(
        "POST",
        "/api/v1/admin/repositories/{key}/reindex-storage",
        "admin reindex-storage",
        &["dry_run", "limit"],
    ),
    covered(
        "POST",
        "/api/v1/admin/storage/ledger/backfill",
        "admin storage ledger-backfill",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/trash",
        "admin trash list",
        &["repository", "page", "per_page"],
    ),
    covered(
        "POST",
        "/api/v1/admin/trash/{id}/restore",
        "admin trash restore",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/admin/packages/backfill",
        "catalog backfill",
        &["repository_key"],
    ),
    covered("POST", "/api/v1/plugins", "admin plugins install", &[]),
    covered(
        "GET",
        "/api/v1/admin/memory-stats",
        "admin diag memory",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/heap-profile",
        "admin diag heap-profile",
        &["activate", "deactivate"],
    ),
    // ---- other commands over the same routes ----
    covered("GET", "/api/v1/auth/me", "auth token list", &[]),
    covered("GET", "/api/v1/users/{id}/tokens", "auth token list", &[]),
    covered(
        "GET",
        "/api/v1/repositories/{key}/artifacts",
        "repo browse",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/promotion/repositories/{key}/artifacts/{artifact_id}/promote",
        "promotion promote",
        &["notes", "skip_policy_check", "target_repository"],
    ),
    covered("GET", "/api/v1/auth/me", "profile update", &[]),
    covered(
        "PATCH",
        "/api/v1/users/{id}",
        "profile update",
        &["display_name", "email"],
    ),
    covered(
        "GET",
        "/api/v1/dependency-track/projects",
        "dt project show",
        &[],
    ),
    covered("GET", "/api/v1/admin/stats", "admin stats", &[]),
    covered("GET", "/api/v1/auth/me", "totp status", &[]),
    covered(
        "GET",
        "/api/v1/tree",
        "catalog tree",
        &["include_metadata", "path", "repository_key"],
    ),
    // ---- routes that aren't in the spec ----
    covered("GET", "/api/v1/openapi.json", "system openapi", &[]),
    covered("GET", "/swagger-ui", "system swagger-ui", &[]),
    covered("GET", "/swagger-ui/{path}", "system swagger-ui", &[]),
    covered("GET", "/healthz", "system healthz", &[]),
    covered("GET", "/ready", "system ready", &[]),
    covered(
        "POST",
        "/api/v1/admin/settings",
        "admin settings update",
        &[
            "allow_anonymous_download",
            "audit_retention_days",
            "backup_retention_count",
            "edge_stale_threshold_minutes",
            "environment",
            "max_upload_size_bytes",
            "retention_days",
            "storage_backend",
            "storage_path",
        ],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/email-subscriptions",
        "email-subscriptions subscribe",
        &["enabled", "event_types", "recipients"],
    ),
    // ---- admin ----
    covered(
        "DELETE",
        "/api/v1/admin/ci-oidc/{id}/mappings/{mid}",
        "admin ci-oidc mapping delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/ci-oidc/{id}/mappings/{mid}",
        "admin ci-oidc mapping get",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/ci-oidc/{id}/mappings",
        "admin ci-oidc mapping list",
        &[],
    ),
    covered(
        "PATCH",
        "/api/v1/admin/ci-oidc/{id}/mappings/{mid}/toggle",
        "admin ci-oidc mapping toggle",
        &["enabled"],
    ),
    covered(
        "POST",
        "/api/v1/formats/{format_key}/disable",
        "admin formats disable",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/formats/{format_key}/enable",
        "admin formats enable",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/formats",
        "admin formats list",
        &["enabled", "type"],
    ),
    covered(
        "GET",
        "/api/v1/formats/{format_key}",
        "admin formats show",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/formats/{format_key}/test",
        "admin formats test",
        &["base64", "content", "path"],
    ),
    covered(
        "POST",
        "/api/v1/instances",
        "admin instance create",
        &["api_key", "name", "url"],
    ),
    covered(
        "DELETE",
        "/api/v1/instances/{id}",
        "admin instance delete",
        &[],
    ),
    covered("GET", "/api/v1/instances", "admin instance list", &[]),
    covered(
        "DELETE",
        "/api/v1/instances/{id}/proxy/{path}",
        "admin instance proxy delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/instances/{id}/proxy/{path}",
        "admin instance proxy get",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/instances/{id}/proxy/{path}",
        "admin instance proxy post",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/instances/{id}/proxy/{path}",
        "admin instance proxy put",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/plugins/{id}/config",
        "admin plugins config get",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/plugins/{id}/config",
        "admin plugins config set",
        &["config"],
    ),
    covered(
        "POST",
        "/api/v1/plugins/{id}/disable",
        "admin plugins disable",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/plugins/{id}/enable",
        "admin plugins enable",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/plugins/{id}/events",
        "admin plugins events",
        &["limit"],
    ),
    covered(
        "POST",
        "/api/v1/plugins/install/git",
        "admin plugins install",
        &["ref", "url"],
    ),
    covered(
        "POST",
        "/api/v1/plugins/install/local",
        "admin plugins install-local",
        &["path"],
    ),
    covered(
        "POST",
        "/api/v1/plugins/install/zip",
        "admin plugins install-zip",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/plugins/{id}/reload",
        "admin plugins reload",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/plugins/{id}",
        "admin plugins remove",
        &[],
    ),
    covered("GET", "/api/v1/plugins/{id}", "admin plugins show", &[]),
    covered("POST", "/api/v1/admin/reindex", "admin reindex", &[]),
    covered(
        "POST",
        "/api/v1/admin/rescan-for-inventory",
        "admin rescan",
        &["limit"],
    ),
    covered(
        "POST",
        "/api/v1/admin/search/reindex",
        "admin search-reindex",
        &[],
    ),
    covered("GET", "/api/v1/admin/settings", "admin settings show", &[]),
    covered(
        "POST",
        "/api/v1/admin/smtp/test",
        "admin smtp-test",
        &["to"],
    ),
    covered(
        "GET",
        "/api/v1/admin/storage-backends",
        "admin storage-backends",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/storage-gc/oci-blob-report",
        "admin storage-gc oci-report",
        &["grace_hours"],
    ),
    covered(
        "POST",
        "/api/v1/admin/storage-gc",
        "admin storage-gc run",
        &["dry_run"],
    ),
    covered(
        "GET",
        "/api/v1/admin/telemetry/crashes/{id}",
        "admin telemetry crash",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/telemetry/crashes",
        "admin telemetry crashes",
        &["page", "per_page"],
    ),
    covered(
        "GET",
        "/api/v1/admin/telemetry/crashes/pending",
        "admin telemetry crashes",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/admin/telemetry/crashes/{id}",
        "admin telemetry delete-crash",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/telemetry/settings",
        "admin telemetry show",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/admin/telemetry/crashes/submit",
        "admin telemetry submit",
        &["ids"],
    ),
    covered(
        "POST",
        "/api/v1/admin/telemetry/settings",
        "admin telemetry update",
        &[
            "enabled",
            "include_logs",
            "review_before_send",
            "scrub_level",
        ],
    ),
    covered("DELETE", "/api/v1/users/{id}", "admin users delete", &[]),
    covered(
        "POST",
        "/api/v1/users/{id}/force-password-change",
        "admin users force-password-change",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/users/{id}/password/reset",
        "admin users reset-password",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/users/{id}/roles",
        "admin users role assign",
        &["role_id"],
    ),
    covered(
        "DELETE",
        "/api/v1/users/{id}/roles/{role_id}",
        "admin users role revoke",
        &[],
    ),
    covered("GET", "/api/v1/users/{id}/roles", "admin users roles", &[]),
    covered("GET", "/api/v1/users/{id}", "admin users show", &[]),
    covered(
        "POST",
        "/api/v1/users/{id}/tokens",
        "admin users tokens create",
        &["expires_in_days", "name", "scopes"],
    ),
    covered(
        "GET",
        "/api/v1/users/{id}/tokens",
        "admin users tokens list",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/users/{id}/tokens/{token_id}",
        "admin users tokens revoke",
        &[],
    ),
    covered(
        "PATCH",
        "/api/v1/users/{id}",
        "admin users update",
        &["display_name", "email", "is_active", "is_admin"],
    ),
    // ---- age-gate ----
    covered(
        "POST",
        "/api/v1/admin/age-gate/reviews/{id}/approve",
        "age-gate approve",
        &["reason"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/age-gate",
        "age-gate get",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/admin/age-gate/reviews/{id}/reject",
        "age-gate reject",
        &["reason"],
    ),
    covered(
        "GET",
        "/api/v1/admin/age-gate/reviews/{id}",
        "age-gate review",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/age-gate/reviews",
        "age-gate reviews",
        &["page", "per_page", "repository_key", "status"],
    ),
    // ---- analytics ----
    covered(
        "GET",
        "/api/v1/admin/analytics/downloads/trend",
        "analytics downloads",
        &["from", "to"],
    ),
    covered(
        "GET",
        "/api/v1/admin/analytics/storage/growth",
        "analytics growth",
        &["from", "to"],
    ),
    covered(
        "GET",
        "/api/v1/admin/analytics/repositories/{id}/trend",
        "analytics repo-trend",
        &["from", "to"],
    ),
    covered(
        "POST",
        "/api/v1/admin/analytics/snapshot",
        "analytics snapshot",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/analytics/storage/breakdown",
        "analytics storage",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/admin/analytics/storage/trend",
        "analytics storage-trend",
        &["from", "to"],
    ),
    covered(
        "GET",
        "/api/v1/admin/analytics/artifacts/stale",
        "analytics top-stale",
        &["days", "limit"],
    ),
    // ---- approval ----
    covered(
        "GET",
        "/api/v1/approval/history",
        "approval list",
        &["page", "per_page", "source_repository", "status"],
    ),
    covered(
        "GET",
        "/api/v1/approval/pending",
        "approval list",
        &["page", "per_page", "source_repository"],
    ),
    covered(
        "POST",
        "/api/v1/approval/request",
        "approval request",
        &[
            "artifact_id",
            "notes",
            "skip_policy_check",
            "source_repository",
            "target_repository",
        ],
    ),
    covered("GET", "/api/v1/approval/{id}", "approval show", &[]),
    // ---- auth ----
    covered("GET", "/api/v1/setup/status", "auth setup-status", &[]),
    // ---- builds ----
    covered(
        "POST",
        "/api/v1/builds/{id}/artifacts",
        "builds add-artifacts",
        &["artifacts"],
    ),
    covered(
        "GET",
        "/api/v1/builds/diff",
        "builds diff",
        &["build_a", "build_b"],
    ),
    covered(
        "GET",
        "/api/v1/builds",
        "builds list",
        &[
            "page",
            "per_page",
            "search",
            "sort_by",
            "sort_order",
            "status",
        ],
    ),
    covered("GET", "/api/v1/builds/{id}", "builds show", &[]),
    covered(
        "PUT",
        "/api/v1/builds/{id}",
        "builds update",
        &["finished_at", "status"],
    ),
    // ---- dt ----
    covered(
        "PUT",
        "/api/v1/dependency-track/analysis",
        "dt analyze",
        &[
            "component_uuid",
            "details",
            "justification",
            "project_uuid",
            "state",
            "suppressed",
            "vulnerability_uuid",
        ],
    ),
    covered(
        "GET",
        "/api/v1/dependency-track/metrics/portfolio",
        "dt metrics",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/dependency-track/policies",
        "dt policies",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/dependency-track/projects/{project_uuid}/components",
        "dt project components",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/dependency-track/projects/{project_uuid}/findings",
        "dt project findings",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/dependency-track/projects/{project_uuid}",
        "dt project get",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/dependency-track/projects",
        "dt project list",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/dependency-track/projects/{project_uuid}/metrics",
        "dt project metrics",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/dependency-track/projects/{project_uuid}/metrics/history",
        "dt project metrics-history",
        &["days"],
    ),
    covered(
        "GET",
        "/api/v1/dependency-track/projects/{project_uuid}/violations",
        "dt project violations",
        &[],
    ),
    covered("GET", "/api/v1/dependency-track/status", "dt status", &[]),
    // ---- email-subscriptions ----
    covered(
        "GET",
        "/api/v1/repositories/{key}/email-subscriptions",
        "email-subscriptions list",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/repositories/{key}/email-subscriptions/{subscription_id}",
        "email-subscriptions unsubscribe",
        &[],
    ),
    // ---- group ----
    covered(
        "POST",
        "/api/v1/groups/{id}/members",
        "group add-member",
        &["user_ids"],
    ),
    covered(
        "POST",
        "/api/v1/groups",
        "group create",
        &["description", "name"],
    ),
    covered("DELETE", "/api/v1/groups/{id}", "group delete", &[]),
    covered(
        "GET",
        "/api/v1/groups",
        "group list",
        &["page", "per_page", "search"],
    ),
    covered(
        "DELETE",
        "/api/v1/groups/{id}/members",
        "group remove-member",
        &["user_ids"],
    ),
    covered(
        "PUT",
        "/api/v1/groups/{id}",
        "group update",
        &["description", "name"],
    ),
    // ---- import ----
    covered(
        "GET",
        "/api/v1/migrations/{id}/assessment",
        "import assess result",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/migrations/{id}/assess",
        "import assess run",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/migrations/{id}/cancel",
        "import job cancel",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/migrations",
        "import job create",
        &["config", "job_type", "source_connection_id"],
    ),
    covered(
        "DELETE",
        "/api/v1/migrations/{id}",
        "import job delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/migrations/{id}/items",
        "import job items",
        &["item_type", "page", "per_page", "status"],
    ),
    covered(
        "GET",
        "/api/v1/migrations",
        "import job list",
        &["page", "per_page", "status"],
    ),
    covered(
        "POST",
        "/api/v1/migrations/{id}/pause",
        "import job pause",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/migrations/{id}/report",
        "import job report",
        &["format"],
    ),
    covered(
        "POST",
        "/api/v1/migrations/{id}/resume",
        "import job resume",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/migrations/{id}/start",
        "import job start",
        &[],
    ),
    covered("GET", "/api/v1/migrations/{id}", "import job status", &[]),
    covered(
        "GET",
        "/api/v1/migrations/{id}/stream",
        "import job stream",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/migrations/connections",
        "import source add",
        &["auth_type", "credentials", "name", "source_type", "url"],
    ),
    covered(
        "DELETE",
        "/api/v1/migrations/connections/{id}",
        "import source delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/migrations/connections",
        "import source list",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/migrations/connections/{id}/repositories",
        "import source repos",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/migrations/connections/{id}",
        "import source show",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/migrations/connections/{id}/test",
        "import source test",
        &[],
    ),
    // ---- label ----
    covered(
        "POST",
        "/api/v1/artifacts/{id}/labels/{label_key}",
        "label artifact add",
        &["value"],
    ),
    covered(
        "GET",
        "/api/v1/artifacts/{id}/labels",
        "label artifact list",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/artifacts/{id}/labels/{label_key}",
        "label artifact remove",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/artifacts/{id}/labels",
        "label artifact set",
        &["labels"],
    ),
    covered(
        "POST",
        "/api/v1/repositories/{key}/labels/{label_key}",
        "label repo add",
        &["value"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/labels",
        "label repo list",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/repositories/{key}/labels/{label_key}",
        "label repo remove",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/repositories/{key}/labels",
        "label repo set",
        &["labels"],
    ),
    // ---- license ----
    covered(
        "POST",
        "/api/v1/sbom/check-compliance",
        "license check",
        &["licenses", "repository_id"],
    ),
    covered(
        "POST",
        "/api/v1/sbom/license-policies",
        "license policy create",
        &[
            "action",
            "allow_unknown",
            "allowed_licenses",
            "denied_licenses",
            "description",
            "is_enabled",
            "name",
            "repository_id",
        ],
    ),
    covered(
        "DELETE",
        "/api/v1/sbom/license-policies/{id}",
        "license policy delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/sbom/license-policies",
        "license policy list",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/sbom/license-policies/{id}",
        "license policy show",
        &[],
    ),
    // ---- monitoring ----
    covered(
        "GET",
        "/api/v1/admin/monitoring/alerts",
        "monitoring alerts",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/admin/monitoring/check",
        "monitoring check",
        &[],
    ),
    covered("GET", "/health", "monitoring health", &[]),
    covered(
        "GET",
        "/api/v1/admin/monitoring/health-log",
        "monitoring health-log",
        &["limit", "service"],
    ),
    covered("GET", "/livez", "monitoring live", &[]),
    covered("GET", "/api/v1/admin/metrics", "monitoring metrics", &[]),
    covered("GET", "/readyz", "monitoring ready", &[]),
    covered(
        "POST",
        "/api/v1/admin/monitoring/alerts/suppress",
        "monitoring suppress",
        &["service_name", "until"],
    ),
    // ---- packages ----
    covered(
        "GET",
        "/api/v1/packages",
        "catalog list",
        &["format", "page", "per_page", "repository_key", "search"],
    ),
    covered(
        "GET",
        "/api/v1/packages/{id}/versions",
        "catalog versions",
        &[],
    ),
    // ---- peer ----
    covered(
        "POST",
        "/api/v1/peers/announce",
        "peer announce",
        &["api_key", "endpoint_url", "name", "peer_id"],
    ),
    covered(
        "GET",
        "/api/v1/peers/{id}/chunks/{artifact_id}/peers",
        "peer chunk peers",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/peers/{id}/chunks/{artifact_id}/scored-peers",
        "peer chunk scored-peers",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/peers/{id}/chunks/{artifact_id}",
        "peer chunk show",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/peers/{id}/chunks/{artifact_id}",
        "peer chunk update",
        &["chunk_bitmap", "total_chunks"],
    ),
    covered(
        "GET",
        "/api/v1/peers/{id}/connections/discover",
        "peer connection discover",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/peers/{id}/connections",
        "peer connection list",
        &["status"],
    ),
    covered(
        "POST",
        "/api/v1/peers/{id}/connections/{target_id}/unreachable",
        "peer connection unreachable",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/peers/{id}/heartbeat",
        "peer heartbeat",
        &["cache_used_bytes", "status"],
    ),
    covered("GET", "/api/v1/peers/identity", "peer identity", &[]),
    covered(
        "POST",
        "/api/v1/peers/{id}/labels/{label_key}",
        "peer label add",
        &["value"],
    ),
    covered(
        "DELETE",
        "/api/v1/peers/{id}/labels/{label_key}",
        "peer label delete",
        &[],
    ),
    covered("GET", "/api/v1/peers/{id}/labels", "peer label list", &[]),
    covered(
        "PUT",
        "/api/v1/peers/{id}/labels",
        "peer label set",
        &["labels"],
    ),
    covered(
        "PUT",
        "/api/v1/peers/{id}/network-profile",
        "peer network-profile",
        &[
            "concurrent_transfers_limit",
            "max_bandwidth_bps",
            "sync_window_end",
            "sync_window_start",
            "sync_window_timezone",
        ],
    ),
    covered("GET", "/api/v1/peers/{id}", "peer show", &[]),
    covered(
        "POST",
        "/api/v1/peers/{id}/repositories",
        "peer subscription assign",
        &[
            "replication_filter",
            "replication_mode",
            "replication_schedule",
            "repository_id",
            "sync_enabled",
        ],
    ),
    covered(
        "GET",
        "/api/v1/peers/{id}/repositories",
        "peer subscription list",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/peers/{id}/repositories/{repo_id}/sync",
        "peer subscription run",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/peers/{id}/repositories/{repo_id}",
        "peer subscription show",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/peers/{id}/repositories/{repo_id}",
        "peer subscription unassign",
        &[],
    ),
    covered("POST", "/api/v1/peers/{id}/sync", "peer sync", &[]),
    covered(
        "POST",
        "/api/v1/peers/{id}/connections/probe",
        "peer test",
        &["bandwidth_estimate_bps", "latency_ms", "target_peer_id"],
    ),
    covered(
        "POST",
        "/api/v1/peers/{id}/transfer/{session_id}/chunk/{chunk_index}/complete",
        "peer transfer chunk-complete",
        &["checksum", "source_peer_id"],
    ),
    covered(
        "POST",
        "/api/v1/peers/{id}/transfer/{session_id}/chunk/{chunk_index}/fail",
        "peer transfer chunk-fail",
        &["error"],
    ),
    covered(
        "POST",
        "/api/v1/peers/{id}/transfer/{session_id}/chunk/{chunk_index}/retry",
        "peer transfer chunk-retry",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/peers/{id}/transfer/{session_id}/complete",
        "peer transfer complete",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/peers/{id}/transfer/{session_id}/fail",
        "peer transfer fail",
        &["error"],
    ),
    covered(
        "POST",
        "/api/v1/peers/{id}/transfer/init",
        "peer transfer init",
        &["artifact_id", "chunk_size"],
    ),
    covered(
        "GET",
        "/api/v1/peers/{id}/transfer/{session_id}/chunks",
        "peer transfer manifest",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/peers/{id}/transfer/{session_id}",
        "peer transfer show",
        &[],
    ),
    covered("DELETE", "/api/v1/peers/{id}", "peer unregister", &[]),
    // ---- promotion ----
    covered(
        "POST",
        "/api/v1/promotion/repositories/{key}/promote",
        "promotion bulk-promote",
        &[
            "artifact_ids",
            "notes",
            "skip_policy_check",
            "target_repository",
        ],
    ),
    covered(
        "POST",
        "/api/v1/promotion/repositories/{key}/artifacts/{artifact_id}/reject",
        "promotion reject",
        &["notes", "reason"],
    ),
    covered(
        "GET",
        "/api/v1/promotion/repositories/{key}/release-target",
        "promotion release-target get",
        &[],
    ),
    covered(
        "PUT",
        "/api/v1/promotion/repositories/{key}/release-target",
        "promotion release-target set",
        &["release_repository_key"],
    ),
    covered(
        "DELETE",
        "/api/v1/promotion-rules/{id}",
        "promotion rule delete",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/promotion-rules/{id}/evaluate",
        "promotion rule evaluate",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/promotion-rules/{id}",
        "promotion rule get",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/promotion-rules",
        "promotion rule list",
        &["source_repo_id"],
    ),
    covered(
        "PUT",
        "/api/v1/promotion-rules/{id}",
        "promotion rule update",
        &[
            "allowed_licenses",
            "auto_promote",
            "is_enabled",
            "max_artifact_age_days",
            "max_cve_severity",
            "min_health_score",
            "min_staging_hours",
            "name",
            "require_signature",
        ],
    ),
    // ---- quality-gate ----
    covered(
        "GET",
        "/api/v1/quality/health/artifacts/{artifact_id}",
        "quality-gate artifact-health",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/quality/gates/evaluate/{artifact_id}",
        "quality-gate check",
        &["repository_id"],
    ),
    covered(
        "GET",
        "/api/v1/quality/checks/{id}/issues",
        "quality-gate check-issues",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/quality/checks/{id}",
        "quality-gate check-show",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/quality/checks/trigger",
        "quality-gate check-trigger",
        &["artifact_id", "repository_id"],
    ),
    covered(
        "GET",
        "/api/v1/quality/checks",
        "quality-gate checks",
        &["artifact_id"],
    ),
    covered(
        "DELETE",
        "/api/v1/quality/gates/{id}",
        "quality-gate delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/quality/health/dashboard",
        "quality-gate health-dashboard",
        &[],
    ),
    covered("GET", "/api/v1/quality/gates", "quality-gate list", &[]),
    covered(
        "GET",
        "/api/v1/quality/health/repositories/{key}",
        "quality-gate repo-health",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/quality/gates/{id}",
        "quality-gate show",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/quality/issues/{id}/suppress",
        "quality-gate suppress",
        &["reason"],
    ),
    covered(
        "DELETE",
        "/api/v1/quality/issues/{id}/suppress",
        "quality-gate unsuppress",
        &[],
    ),
    // ---- repo-token ----
    covered(
        "POST",
        "/api/v1/repositories/{key}/tokens",
        "repo-token create",
        &["description", "expires_in_days", "name", "scopes"],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/tokens",
        "repo-token list",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/repositories/{key}/tokens/{token_id}",
        "repo-token revoke",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/repositories/{key}/tokens/{token_id}",
        "repo-token show",
        &[],
    ),
    // ---- service-account ----
    covered(
        "POST",
        "/api/v1/service-accounts",
        "service-account create",
        &["description", "name"],
    ),
    covered(
        "DELETE",
        "/api/v1/service-accounts/{id}",
        "service-account delete",
        &[],
    ),
    covered(
        "GET",
        "/api/v1/service-accounts",
        "service-account list",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/service-accounts/repo-selector/preview",
        "service-account preview-selector",
        &["repo_selector"],
    ),
    covered(
        "GET",
        "/api/v1/service-accounts/{id}",
        "service-account show",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/service-accounts/{id}/tokens",
        "service-account token create",
        &[
            "description",
            "expires_in_days",
            "name",
            "repo_selector",
            "repository_ids",
            "scopes",
        ],
    ),
    covered(
        "GET",
        "/api/v1/service-accounts/{id}/tokens",
        "service-account token list",
        &[],
    ),
    covered(
        "DELETE",
        "/api/v1/service-accounts/{id}/tokens/{token_id}",
        "service-account token revoke",
        &[],
    ),
    covered(
        "PATCH",
        "/api/v1/service-accounts/{id}",
        "service-account update",
        &["display_name", "is_active"],
    ),
    // ---- sync-policy ----
    covered(
        "DELETE",
        "/api/v1/sync-policies/{id}",
        "sync-policy delete",
        &[],
    ),
    covered(
        "POST",
        "/api/v1/sync-policies/evaluate",
        "sync-policy evaluate",
        &[],
    ),
    covered("GET", "/api/v1/sync-policies", "sync-policy list", &[]),
    covered("GET", "/api/v1/sync-policies/{id}", "sync-policy show", &[]),
    covered(
        "POST",
        "/api/v1/sync-policies/{id}/toggle",
        "sync-policy toggle",
        &["enabled"],
    ),
    // ---- system ----
    covered("GET", "/api/v1/system/config", "system config", &[]),
    // ---- pkg: package-format helpers ----
    covered("POST", "/pypi/{repo_key}", "pkg pypi publish", &[]),
    covered("POST", "/pypi/{repo_key}/pypi", "pkg pypi xmlrpc", &[]),
    covered(
        "PUT",
        "/cargo/{repo_key}/api/v1/crates/new",
        "pkg cargo publish",
        &[],
    ),
    covered(
        "PUT",
        "/api/cargo/{repo_key}/api/v1/crates/new",
        "pkg cargo publish",
        &[],
    ),
    covered(
        "POST",
        "/helm/{repo_key}/api/charts",
        "pkg helm publish",
        &[],
    ),
    covered(
        "POST",
        "/api/helm/{repo_key}/charts",
        "pkg helm publish",
        &[],
    ),
    covered(
        "DELETE",
        "/helm/{repo_key}/api/charts/{name}/{version}",
        "pkg helm delete",
        &[],
    ),
    covered(
        "DELETE",
        "/api/helm/{repo_key}/charts/{name}/{version}",
        "pkg helm delete",
        &[],
    ),
    covered(
        "PUT",
        "/nuget/{repo_key}/api/v2/package",
        "pkg nuget publish",
        &[],
    ),
    covered("PUT", "/npm/{repo_key}/{package}", "pkg npm publish", &[]),
    covered(
        "PUT",
        "/npm/{repo_key}/@{scope}/{package}",
        "pkg npm publish",
        &[],
    ),
    covered(
        "PUT",
        "/npm/{repo_key}/-/package/{package}/dist-tags/{tag}",
        "pkg npm dist-tag set",
        &[],
    ),
    covered(
        "DELETE",
        "/npm/{repo_key}/-/package/{package}/dist-tags/{tag}",
        "pkg npm dist-tag rm",
        &[],
    ),
    covered(
        "PUT",
        "/npm/{repo_key}/{package}/-rev/{rev}",
        "pkg npm unpublish",
        &[],
    ),
    covered(
        "DELETE",
        "/npm/{repo_key}/{package}/-rev/{rev}",
        "pkg npm unpublish",
        &[],
    ),
    covered(
        "DELETE",
        "/npm/{repo_key}/{package}/-/{filename}/-rev/{rev}",
        "pkg npm unpublish",
        &[],
    ),
    covered(
        "PUT",
        "/npm/{repo_key}/@{scope}/{package}/-rev/{rev}",
        "pkg npm unpublish",
        &[],
    ),
    covered(
        "DELETE",
        "/npm/{repo_key}/@{scope}/{package}/-rev/{rev}",
        "pkg npm unpublish",
        &[],
    ),
    covered(
        "DELETE",
        "/npm/{repo_key}/@{scope}/{package}/-/{filename}/-rev/{rev}",
        "pkg npm unpublish",
        &[],
    ),
    covered(
        "PUT",
        "/npm/{repo_key}/@{scope}/{package}/{version}",
        "pkg npm unpublish",
        &[],
    ),
    covered(
        "DELETE",
        "/npm/{repo_key}/@{scope}/{package}/{version}",
        "pkg npm unpublish",
        &[],
    ),
    covered(
        "POST",
        "/npm/{repo_key}/-/npm/v1/security/advisories/bulk",
        "pkg npm audit",
        &[],
    ),
    covered(
        "POST",
        "/npm/{repo_key}/-/npm/v1/security/audits/quick",
        "pkg npm audit",
        &[],
    ),
    covered(
        "PUT",
        "/rpm/{repo_key}/packages/{path}",
        "pkg rpm publish",
        &[],
    ),
    covered("POST", "/rpm/{repo_key}/upload", "pkg rpm publish", &[]),
    covered(
        "PUT",
        "/rpm/{repo_key}/{upstream_path}",
        "pkg rpm publish",
        &[],
    ),
    covered(
        "PUT",
        "/debian/{repo_key}/pool/{component}/{path}",
        "pkg debian publish",
        &[],
    ),
    covered(
        "POST",
        "/debian/{repo_key}/upload",
        "pkg debian publish",
        &[],
    ),
    covered(
        "POST",
        "/alpine/{repo_key}/upload",
        "pkg alpine publish",
        &[],
    ),
    covered(
        "PUT",
        "/alpine/{repo_key}/{branch}/{repository}/{arch}/{filename}",
        "pkg alpine publish",
        &[],
    ),
    covered(
        "PUT",
        "/pacman/{repo_key}/{filename}",
        "pkg pacman publish",
        &[],
    ),
    covered(
        "DELETE",
        "/pacman/{repo_key}/{arch}/{filename}",
        "pkg pacman delete",
        &[],
    ),
    covered("POST", "/conda/{repo_key}/upload", "pkg conda publish", &[]),
    covered(
        "PUT",
        "/conda/{repo_key}/{subdir}/{filename}",
        "pkg conda publish",
        &[],
    ),
    covered(
        "POST",
        "/conda/t/{token}/{repo_key}/upload",
        "pkg conda publish",
        &[],
    ),
    covered(
        "PUT",
        "/conda/t/{token}/{repo_key}/{subdir}/{filename}",
        "pkg conda publish",
        &[],
    ),
    covered(
        "POST",
        "/t/{token}/conda/{repo_key}/upload",
        "pkg conda publish",
        &[],
    ),
    covered(
        "PUT",
        "/t/{token}/conda/{repo_key}/{subdir}/{filename}",
        "pkg conda publish",
        &[],
    ),
    covered(
        "PUT",
        "/conda/{repo_key}/{subdir}/{filename}/attestation",
        "pkg conda attest",
        &[],
    ),
    covered(
        "PUT",
        "/conda/t/{token}/{repo_key}/{subdir}/{filename}/attestation",
        "pkg conda attest",
        &[],
    ),
    covered(
        "PUT",
        "/t/{token}/conda/{repo_key}/{subdir}/{filename}/attestation",
        "pkg conda attest",
        &[],
    ),
    covered(
        "DELETE",
        "/conda/{repo_key}/{subdir}/{filename}",
        "pkg conda withdraw",
        &[],
    ),
    covered(
        "PUT",
        "/incus/{repo_key}/images/{product}/{version}/{filename}",
        "pkg incus publish",
        &[],
    ),
    covered(
        "POST",
        "/incus/{repo_key}/images/{product}/{version}/{filename}/uploads",
        "pkg incus publish",
        &[],
    ),
    covered(
        "PATCH",
        "/incus/{repo_key}/uploads/{uuid}",
        "pkg incus publish",
        &[],
    ),
    covered(
        "PUT",
        "/incus/{repo_key}/uploads/{uuid}",
        "pkg incus publish",
        &[],
    ),
    covered(
        "DELETE",
        "/incus/{repo_key}/images/{product}/{version}/{filename}",
        "pkg incus delete",
        &[],
    ),
    covered(
        "DELETE",
        "/incus/{repo_key}/uploads/{uuid}",
        "pkg incus upload-cancel",
        &[],
    ),
    covered(
        "PUT",
        "/lxc/{repo_key}/images/{product}/{version}/{filename}",
        "pkg lxc publish",
        &[],
    ),
    covered(
        "POST",
        "/lxc/{repo_key}/images/{product}/{version}/{filename}/uploads",
        "pkg lxc publish",
        &[],
    ),
    covered(
        "PATCH",
        "/lxc/{repo_key}/uploads/{uuid}",
        "pkg lxc publish",
        &[],
    ),
    covered(
        "PUT",
        "/lxc/{repo_key}/uploads/{uuid}",
        "pkg lxc publish",
        &[],
    ),
    covered(
        "DELETE",
        "/lxc/{repo_key}/images/{product}/{version}/{filename}",
        "pkg lxc delete",
        &[],
    ),
    covered(
        "DELETE",
        "/lxc/{repo_key}/uploads/{uuid}",
        "pkg lxc upload-cancel",
        &[],
    ),
    covered("PUT", "/maven/{repo_key}/{path}", "pkg maven publish", &[]),
    covered("PUT", "/ivy/{repo_key}/{path}", "pkg ivy publish", &[]),
    covered("PUT", "/bazel/{repo_key}/{path}", "pkg bazel publish", &[]),
    covered("PUT", "/go/{repo_key}/{path}", "pkg go publish", &[]),
    covered(
        "POST",
        "/gems/{repo_key}/api/v1/gems",
        "pkg gems publish",
        &[],
    ),
    covered(
        "POST",
        "/composer/{repo_key}/api/packages",
        "pkg composer publish",
        &[],
    ),
    covered(
        "PUT",
        "/composer/{repo_key}/api/packages",
        "pkg composer publish",
        &[],
    ),
    covered(
        "PUT",
        "/cran/{repo_key}/src/contrib/{filename}",
        "pkg cran publish",
        &[],
    ),
    covered("POST", "/hex/{repo_key}/publish", "pkg hex publish", &[]),
    covered(
        "POST",
        "/pub/{repo_key}/api/packages/versions/newUpload",
        "pkg pub publish",
        &[],
    ),
    covered(
        "PUT",
        "/terraform/{repo_key}/v1/modules/{namespace}/{name}/{provider}/{version}",
        "pkg terraform publish-module",
        &[],
    ),
    covered(
        "PUT",
        "/terraform/{repo_key}/v1/providers/{namespace}/{type_name}/{version}/{os}/{arch}",
        "pkg terraform publish-provider",
        &[],
    ),
    covered(
        "POST",
        "/ansible/{repo_key}/api/v3/artifacts/collections",
        "pkg ansible publish",
        &[],
    ),
    covered(
        "POST",
        "/chef/{repo_key}/api/v1/cookbooks",
        "pkg chef publish",
        &[],
    ),
    covered(
        "POST",
        "/puppet/{repo_key}/v3/releases",
        "pkg puppet publish",
        &[],
    ),
    covered(
        "POST",
        "/cocoapods/{repo_key}/pods",
        "pkg cocoapods publish",
        &[],
    ),
    covered(
        "POST",
        "/jetbrains/{repo_key}/plugin/uploadPlugin",
        "pkg jetbrains publish",
        &[],
    ),
    covered(
        "POST",
        "/vscode/{repo_key}/api/extensions",
        "pkg vscode publish",
        &[],
    ),
    covered(
        "POST",
        "/vscode/{repo_key}/gallery/extensionquery",
        "pkg vscode query",
        &[],
    ),
    covered(
        "POST",
        "/huggingface/{repo_key}/api/models/{model_id}/upload/{revision}",
        "pkg huggingface upload",
        &[],
    ),
    covered(
        "POST",
        "/huggingface/{repo_key}/api/models/{namespace}/{name}/upload/{revision}",
        "pkg huggingface upload",
        &[],
    ),
    covered(
        "PUT",
        "/swift/{repo_key}/{scope}/{name}/{version_path}",
        "pkg swift publish",
        &[],
    ),
    covered(
        "POST",
        "/lfs/{repo_key}/objects/batch",
        "pkg lfs upload",
        &[],
    ),
    covered(
        "PUT",
        "/lfs/{repo_key}/objects/{oid}",
        "pkg lfs upload",
        &[],
    ),
    covered("POST", "/lfs/{repo_key}/verify", "pkg lfs upload", &[]),
    covered("POST", "/lfs/{repo_key}/locks", "pkg lfs lock", &[]),
    covered(
        "POST",
        "/lfs/{repo_key}/locks/verify",
        "pkg lfs locks-verify",
        &[],
    ),
    covered(
        "POST",
        "/lfs/{repo_key}/locks/{lock_id}/unlock",
        "pkg lfs unlock",
        &[],
    ),
    covered(
        "POST",
        "/conan/{repo_key}/v2/users/authenticate",
        "pkg conan authenticate",
        &[],
    ),
    covered(
        "PUT",
        "/conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{revision}/files/{file_path}",
        "pkg conan upload",
        &[],
    ),
    covered(
        "PUT",
        "/conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{revision}/packages/{package_id}/revisions/{pkg_revision}/files/{file_path}",
        "pkg conan upload",
        &[],
    ),
    covered(
        "DELETE",
        "/conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}",
        "pkg conan remove",
        &[],
    ),
    covered(
        "DELETE",
        "/conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{revision}",
        "pkg conan remove",
        &[],
    ),
    covered(
        "DELETE",
        "/conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{revision}/packages",
        "pkg conan remove",
        &[],
    ),
    covered(
        "DELETE",
        "/conan/{repo_key}/v2/conans/{name}/{version}/{user}/{channel}/revisions/{revision}/packages/{package_id}/revisions/{pkg_revision}",
        "pkg conan remove",
        &[],
    ),
    covered(
        "POST",
        "/proto/{repo_key}/buf.registry.module.v1beta1.UploadService/Upload",
        "pkg proto publish",
        &[],
    ),
    covered(
        "POST",
        "/proto/{repo_key}/buf.registry.module.v1.CommitService/GetCommits",
        "pkg proto call",
        &[],
    ),
    covered(
        "POST",
        "/proto/{repo_key}/buf.registry.module.v1.CommitService/ListCommits",
        "pkg proto call",
        &[],
    ),
    covered(
        "POST",
        "/proto/{repo_key}/buf.registry.module.v1.GraphService/GetGraph",
        "pkg proto call",
        &[],
    ),
    covered(
        "POST",
        "/proto/{repo_key}/buf.registry.module.v1.LabelService/CreateOrUpdateLabels",
        "pkg proto call",
        &[],
    ),
    covered(
        "POST",
        "/proto/{repo_key}/buf.registry.module.v1.LabelService/GetLabels",
        "pkg proto call",
        &[],
    ),
    covered(
        "POST",
        "/proto/{repo_key}/buf.registry.module.v1.ModuleService/CreateModules",
        "pkg proto call",
        &[],
    ),
    covered(
        "POST",
        "/proto/{repo_key}/buf.registry.module.v1.ModuleService/GetModules",
        "pkg proto call",
        &[],
    ),
    covered(
        "POST",
        "/proto/{repo_key}/buf.registry.module.v1.ResourceService/GetResources",
        "pkg proto call",
        &[],
    ),
    covered(
        "POST",
        "/proto/{repo_key}/buf.registry.module.v1beta1.DownloadService/Download",
        "pkg proto call",
        &[],
    ),
    covered("GET", "/v2/_catalog", "pkg oci catalog", &[]),
    covered("GET", "/v2/{name}/tags/list", "pkg oci tags", &[]),
    covered(
        "GET",
        "/v2/{name}/manifests/{reference}",
        "pkg oci manifest get",
        &[],
    ),
    covered(
        "HEAD",
        "/v2/{name}/manifests/{reference}",
        "pkg oci manifest head",
        &[],
    ),
    covered(
        "PUT",
        "/v2/{name}/manifests/{reference}",
        "pkg oci manifest put",
        &[],
    ),
    covered(
        "DELETE",
        "/v2/{name}/manifests/{reference}",
        "pkg oci manifest delete",
        &[],
    ),
    covered("GET", "/v2/{name}/blobs/{digest}", "pkg oci blob get", &[]),
    covered(
        "GET",
        "/v2/{name}/referrers/{digest}",
        "pkg oci referrers",
        &[],
    ),
    // ---- excluded: reachable with `ak api` ----
    excluded("GET", "/api/v1/auth/sso/oidc/{id}/callback", IDP_CALLBACK),
    excluded("GET", "/api/v1/auth/sso/oidc/callback", IDP_CALLBACK),
    excluded("POST", "/api/v1/auth/sso/saml/{id}/acs", IDP_CALLBACK),
    excluded("ANY", "/ext/{format_key}/{repo_key}", WASM_PASSTHROUGH),
    excluded(
        "ANY",
        "/ext/{format_key}/{repo_key}/{path}",
        WASM_PASSTHROUGH,
    ),
];

/// Everything `ak __registry` prints: the lines above, and every leaf command with
/// its arguments, read from clap. The gate and `tests/registry_contract.rs` read
/// this, so they see what the binary really has.
pub fn dump() -> serde_json::Value {
    use clap::CommandFactory;

    let commands: Vec<_> = COMMANDS
        .iter()
        .map(|op| {
            serde_json::json!({
                "method": op.method,
                "path": op.path,
                "command": op.command,
                "binds": op.binds,
                "excluded": op.excluded,
            })
        })
        .collect();
    let classes: Vec<_> = CLASS_EXCLUSIONS
        .iter()
        .map(|class| {
            serde_json::json!({
                "name": class.name,
                "methods": class.methods,
                "prefixes": class.prefixes,
                "except": class.except,
                "reason": class.reason,
            })
        })
        .collect();
    let mut leaves = Vec::new();
    let root = crate::cli::Cli::command();
    for sub in root.get_subcommands() {
        collect_leaves(sub, sub.get_name(), &mut leaves);
    }
    serde_json::json!({
        "commands": commands,
        "class_exclusions": classes,
        "field_opt_outs": FIELD_OPT_OUTS
            .iter()
            .map(|out| {
                serde_json::json!({
                    "method": out.method,
                    "path": out.path,
                    "field": out.field,
                    "reason": out.reason,
                })
            })
            .collect::<Vec<_>>(),
        "leaves": leaves,
    })
}

pub fn print_dump() {
    println!("{}", dump());
}

fn collect_leaves(cmd: &clap::Command, path: &str, out: &mut Vec<serde_json::Value>) {
    if cmd.get_name() == "help" || cmd.get_name() == "__registry" {
        return;
    }
    let subs: Vec<_> = cmd
        .get_subcommands()
        .filter(|sub| sub.get_name() != "help")
        .collect();
    if subs.is_empty() || !cmd.is_subcommand_required_set() {
        let args: Vec<_> = cmd
            .get_arguments()
            .filter(|a| !a.is_global_set() && !a.is_hide_set())
            .filter(|a| {
                !matches!(
                    a.get_action(),
                    clap::ArgAction::Help
                        | clap::ArgAction::HelpShort
                        | clap::ArgAction::HelpLong
                        | clap::ArgAction::Version
                )
            })
            .map(describe_arg)
            .collect();
        if subs.is_empty() || !args.is_empty() {
            out.push(serde_json::json!({ "command": path, "args": args }));
        }
    }
    for sub in subs {
        collect_leaves(sub, &format!("{path} {}", sub.get_name()), out);
    }
}

fn describe_arg(arg: &clap::Arg) -> serde_json::Value {
    use clap::builder::ValueParser;
    use clap::value_parser;

    let id = arg.get_value_parser().type_id();
    let is_int = [
        ValueParser::from(value_parser!(u8)).type_id(),
        ValueParser::from(value_parser!(u16)).type_id(),
        ValueParser::from(value_parser!(u32)).type_id(),
        ValueParser::from(value_parser!(u64)).type_id(),
        ValueParser::from(value_parser!(i32)).type_id(),
        ValueParser::from(value_parser!(i64)).type_id(),
        ValueParser::new(clap::builder::RangedU64ValueParser::<usize>::new()).type_id(),
    ]
    .contains(&id);
    let kind = if !arg.get_action().takes_values() {
        "flag"
    } else if id == ValueParser::path_buf().type_id() {
        "path"
    } else if is_int {
        "int"
    } else if id == ValueParser::bool().type_id() {
        "bool"
    } else {
        "string"
    };
    let values: Vec<String> = arg
        .get_possible_values()
        .iter()
        .map(|v| v.get_name().to_string())
        .collect();
    serde_json::json!({
        "id": arg.get_id().as_str(),
        "long": arg.get_long(),
        "positional": arg.is_positional(),
        "required": arg.is_required_set(),
        "kind": kind,
        "values": values,
    })
}

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
