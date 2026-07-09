use artifact_keeper_sdk::ClientSsoExt;
use artifact_keeper_sdk::types::{
    CreateLdapConfigRequest, CreateOidcConfigRequest, CreateSamlConfigRequest, LdapConfigResponse,
    LdapTestResult, OidcConfigResponse, SamlConfigResponse, SsoProviderInfo, ToggleRequest,
    UpdateLdapConfigRequest, UpdateOidcConfigRequest, UpdateSamlConfigRequest,
};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::{
    confirm_action, emit_mutation, new_table, parse_uuid, resolve_secret, sdk_err, short_id,
};
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum SsoCommand {
    /// List all SSO providers (LDAP, OIDC, SAML)
    List,

    /// Show SSO provider details
    Show {
        /// Provider ID
        id: String,

        /// Provider type
        #[arg(long, value_parser = ["ldap", "oidc", "saml"])]
        r#type: String,
    },

    /// Create an SSO provider
    Create {
        #[command(subcommand)]
        command: SsoCreateCommand,
    },

    /// Delete an SSO provider
    Delete {
        /// Provider ID
        id: String,

        /// Provider type
        #[arg(long, value_parser = ["ldap", "oidc", "saml"])]
        r#type: String,

        /// Skip confirmation
        #[arg(long)]
        yes: bool,
    },

    /// Test SSO provider connectivity (LDAP only)
    Test {
        /// Provider ID
        id: String,

        /// Provider type (only 'ldap' supports connectivity testing)
        #[arg(long, value_parser = ["ldap", "oidc", "saml"], default_value = "ldap")]
        r#type: String,
    },

    /// Enable or disable an SSO provider
    Toggle {
        /// Provider ID
        id: String,

        /// Provider type
        #[arg(long, value_parser = ["ldap", "oidc", "saml"])]
        r#type: String,

        /// Enable the provider
        #[arg(long)]
        enable: bool,
    },

    /// Update an SSO provider configuration (partial; only supplied fields change)
    Update {
        #[command(subcommand)]
        command: Box<SsoUpdateCommand>,
    },

    /// List enabled SSO providers as offered at the login screen
    ///
    /// By default queries the authenticated admin view
    /// (`GET /admin/sso/providers`). Pass `--public` to query the
    /// unauthenticated discovery endpoint (`GET /auth/sso/providers`),
    /// i.e. exactly what an anonymous user sees on the login page.
    Providers {
        /// Query the public (unauthenticated) discovery endpoint instead
        #[arg(long)]
        public: bool,
    },
}

#[derive(Subcommand)]
pub enum SsoUpdateCommand {
    /// Update an LDAP provider
    Ldap {
        /// Provider ID
        id: String,

        #[arg(long)]
        name: Option<String>,

        #[arg(long)]
        server_url: Option<String>,

        #[arg(long)]
        user_base_dn: Option<String>,

        #[arg(long)]
        user_filter: Option<String>,

        #[arg(long)]
        username_attribute: Option<String>,

        #[arg(long)]
        email_attribute: Option<String>,

        #[arg(long)]
        display_name_attribute: Option<String>,

        #[arg(long)]
        groups_attribute: Option<String>,

        #[arg(long)]
        bind_dn: Option<String>,

        /// New bind password (omit to keep the existing one)
        #[arg(long)]
        bind_password: Option<String>,

        /// Read the new bind password from stdin (avoids exposing it on the
        /// command line)
        #[arg(long)]
        bind_password_stdin: bool,

        #[arg(long)]
        group_base_dn: Option<String>,

        #[arg(long)]
        group_filter: Option<String>,

        #[arg(long)]
        admin_group_dn: Option<String>,

        /// Use StartTLS (true/false)
        #[arg(long)]
        use_starttls: Option<bool>,

        #[arg(long)]
        priority: Option<i32>,

        /// Enable or disable the provider (true/false)
        #[arg(long)]
        is_enabled: Option<bool>,
    },

    /// Update an OIDC provider
    Oidc {
        /// Provider ID
        id: String,

        #[arg(long)]
        name: Option<String>,

        #[arg(long)]
        issuer_url: Option<String>,

        #[arg(long)]
        client_id: Option<String>,

        /// New client secret (omit to keep the existing one)
        #[arg(long)]
        client_secret: Option<String>,

        /// Read the new client secret from stdin (avoids exposing it on the
        /// command line)
        #[arg(long)]
        client_secret_stdin: bool,

        /// Auto-provision users on first login (true/false)
        #[arg(long)]
        auto_create_users: Option<bool>,

        /// Requested OIDC scopes (repeatable; replaces the existing scope set)
        #[arg(long = "scope")]
        scope: Vec<String>,

        /// Accept legacy RSA signing keys (true/false)
        #[arg(long)]
        allow_legacy_rsa_keys: Option<bool>,

        /// Map IdP groups onto local groups (true/false)
        #[arg(long)]
        map_groups_to_groups: Option<bool>,

        /// Enable PKCE (true/false)
        #[arg(long)]
        pkce_enabled: Option<bool>,

        /// Enable or disable the provider (true/false)
        #[arg(long)]
        is_enabled: Option<bool>,
    },

    /// Update a SAML provider
    Saml {
        /// Provider ID
        id: String,

        #[arg(long)]
        name: Option<String>,

        #[arg(long)]
        entity_id: Option<String>,

        #[arg(long)]
        sso_url: Option<String>,

        #[arg(long)]
        certificate: Option<String>,

        #[arg(long)]
        sp_entity_id: Option<String>,

        #[arg(long)]
        slo_url: Option<String>,

        #[arg(long)]
        name_id_format: Option<String>,

        #[arg(long)]
        admin_group: Option<String>,

        /// Sign authentication requests (true/false)
        #[arg(long)]
        sign_requests: Option<bool>,

        /// Require signed assertions (true/false)
        #[arg(long)]
        require_signed_assertions: Option<bool>,

        /// Use an absolute ACS URL (true/false)
        #[arg(long)]
        use_absolute_acs_url: Option<bool>,

        /// Enable or disable the provider (true/false)
        #[arg(long)]
        is_enabled: Option<bool>,
    },
}

#[derive(Subcommand)]
pub enum SsoCreateCommand {
    /// Create LDAP provider
    Ldap {
        /// Provider name
        name: String,

        #[arg(long)]
        server_url: String,

        #[arg(long)]
        user_base_dn: String,

        #[arg(long)]
        bind_dn: Option<String>,

        /// Bind password (omit to enter interactively, or pipe it to stdin)
        #[arg(long, env = "AK_LDAP_BIND_PASSWORD", hide_env_values = true)]
        bind_password: Option<String>,

        /// Read the bind password from stdin (avoids exposing it on the
        /// command line)
        #[arg(long)]
        bind_password_stdin: bool,

        #[arg(long)]
        use_starttls: bool,
    },

    /// Create OIDC provider
    Oidc {
        /// Provider name
        name: String,

        #[arg(long)]
        issuer_url: String,

        #[arg(long)]
        client_id: String,

        /// Client secret (omit to enter interactively, or pipe it to stdin)
        #[arg(long, env = "AK_SSO_CLIENT_SECRET", hide_env_values = true)]
        client_secret: Option<String>,

        /// Read the client secret from stdin (avoids exposing it on the
        /// command line)
        #[arg(long)]
        client_secret_stdin: bool,

        #[arg(long)]
        auto_create_users: bool,
    },

    /// Create SAML provider
    Saml {
        /// Provider name
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

impl SsoCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List => list_providers(global).await,
            Self::Show { id, r#type } => show_provider(&id, &r#type, global).await,
            Self::Create { command } => match command {
                SsoCreateCommand::Ldap {
                    name,
                    server_url,
                    user_base_dn,
                    bind_dn,
                    bind_password,
                    bind_password_stdin,
                    use_starttls,
                } => {
                    // Resolve the bind password off the command line; only
                    // prompt when a bind DN was given (anonymous binds need
                    // no password).
                    let bind_password = resolve_secret(
                        bind_password,
                        bind_password_stdin,
                        "--bind-password",
                        bind_dn.as_ref().map(|_| "LDAP bind password"),
                        global.no_input,
                    )?;
                    create_ldap(
                        &name,
                        &server_url,
                        &user_base_dn,
                        bind_dn.as_deref(),
                        bind_password.as_deref(),
                        use_starttls,
                        global,
                    )
                    .await
                }
                SsoCreateCommand::Oidc {
                    name,
                    issuer_url,
                    client_id,
                    client_secret,
                    client_secret_stdin,
                    auto_create_users,
                } => {
                    // Resolve the client secret off the command line: stdin /
                    // env var / no-echo prompt on a TTY.
                    let client_secret = resolve_secret(
                        client_secret,
                        client_secret_stdin,
                        "--client-secret",
                        Some("OIDC client secret"),
                        global.no_input,
                    )?;
                    create_oidc(
                        &name,
                        &issuer_url,
                        &client_id,
                        client_secret,
                        auto_create_users,
                        global,
                    )
                    .await
                }
                SsoCreateCommand::Saml {
                    name,
                    entity_id,
                    sso_url,
                    certificate,
                    sign_requests,
                } => {
                    create_saml(
                        &name,
                        &entity_id,
                        &sso_url,
                        &certificate,
                        sign_requests,
                        global,
                    )
                    .await
                }
            },
            Self::Delete { id, r#type, yes } => delete_provider(&id, &r#type, yes, global).await,
            Self::Test { id, r#type } => test_provider(&id, &r#type, global).await,
            Self::Toggle { id, r#type, enable } => {
                toggle_provider(&id, &r#type, enable, global).await
            }
            Self::Update { command } => command.execute(global).await, // Box<SsoUpdateCommand> derefs to call execute
            Self::Providers { public } => list_enabled_providers(public, global).await,
        }
    }
}

impl SsoUpdateCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            SsoUpdateCommand::Ldap {
                id,
                name,
                server_url,
                user_base_dn,
                user_filter,
                username_attribute,
                email_attribute,
                display_name_attribute,
                groups_attribute,
                bind_dn,
                bind_password,
                bind_password_stdin,
                group_base_dn,
                group_filter,
                admin_group_dn,
                use_starttls,
                priority,
                is_enabled,
            } => {
                // No prompt fallback on update: an omitted password means
                // "keep the existing one".
                let bind_password = resolve_secret(
                    bind_password,
                    bind_password_stdin,
                    "--bind-password",
                    None,
                    global.no_input,
                )?;
                let body = UpdateLdapConfigRequest {
                    name,
                    server_url,
                    user_base_dn,
                    user_filter,
                    username_attribute,
                    email_attribute,
                    display_name_attribute,
                    groups_attribute,
                    bind_dn,
                    bind_password,
                    group_base_dn,
                    group_filter,
                    admin_group_dn,
                    use_starttls,
                    priority,
                    is_enabled,
                };
                update_ldap(&id, body, global).await
            }
            SsoUpdateCommand::Oidc {
                id,
                name,
                issuer_url,
                client_id,
                client_secret,
                client_secret_stdin,
                auto_create_users,
                scope,
                allow_legacy_rsa_keys,
                map_groups_to_groups,
                pkce_enabled,
                is_enabled,
            } => {
                // No prompt fallback on update: an omitted secret means
                // "keep the existing one".
                let client_secret = resolve_secret(
                    client_secret,
                    client_secret_stdin,
                    "--client-secret",
                    None,
                    global.no_input,
                )?;
                let body = UpdateOidcConfigRequest {
                    name,
                    issuer_url,
                    client_id,
                    client_secret,
                    auto_create_users,
                    scopes: if scope.is_empty() { None } else { Some(scope) },
                    attribute_mapping: None,
                    attribute_mapping_replace: None,
                    allow_legacy_rsa_keys,
                    map_groups_to_groups,
                    pkce_enabled,
                    is_enabled,
                };
                update_oidc(&id, body, global).await
            }
            SsoUpdateCommand::Saml {
                id,
                name,
                entity_id,
                sso_url,
                certificate,
                sp_entity_id,
                slo_url,
                name_id_format,
                admin_group,
                sign_requests,
                require_signed_assertions,
                use_absolute_acs_url,
                is_enabled,
            } => {
                let body = UpdateSamlConfigRequest {
                    name,
                    entity_id,
                    sso_url,
                    certificate,
                    sp_entity_id,
                    slo_url,
                    name_id_format,
                    admin_group,
                    attribute_mapping: None,
                    sign_requests,
                    require_signed_assertions,
                    use_absolute_acs_url,
                    is_enabled,
                };
                update_saml(&id, body, global).await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Handler functions
// ---------------------------------------------------------------------------

async fn list_providers(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching SSO providers...");

    // Fetch all three provider types, tolerating individual failures.
    let ldap = client.list_ldap().send().await.map(|r| r.into_inner());
    let oidc = client.list_oidc().send().await.map(|r| r.into_inner());
    let saml = client.list_saml().send().await.map(|r| r.into_inner());

    spinner.finish_and_clear();

    let ldap_list = ldap.unwrap_or_default();
    let oidc_list = oidc.unwrap_or_default();
    let saml_list = saml.unwrap_or_default();

    if ldap_list.is_empty() && oidc_list.is_empty() && saml_list.is_empty() {
        eprintln!("No SSO providers found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &ldap_list {
            println!("{}", p.id);
        }
        for p in &oidc_list {
            println!("{}", p.id);
        }
        for p in &saml_list {
            println!("{}", p.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_providers_table(&ldap_list, &oidc_list, &saml_list);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_provider(id: &str, provider_type: &str, global: &GlobalArgs) -> Result<()> {
    let provider_id = parse_uuid(id, "provider")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching provider...");

    match provider_type {
        "ldap" => {
            let resp = client
                .get_ldap()
                .id(provider_id)
                .send()
                .await
                .map_err(|e| sdk_err("get LDAP provider", e))?;
            spinner.finish_and_clear();
            let p = resp.into_inner();
            let (info, table_str) = format_ldap_detail(&p);
            println!("{}", output::render(&info, &global.format, Some(table_str)));
        }
        "oidc" => {
            let resp = client
                .get_oidc()
                .id(provider_id)
                .send()
                .await
                .map_err(|e| sdk_err("get OIDC provider", e))?;
            spinner.finish_and_clear();
            let p = resp.into_inner();
            let (info, table_str) = format_oidc_detail(&p);
            println!("{}", output::render(&info, &global.format, Some(table_str)));
        }
        "saml" => {
            let resp = client
                .get_saml()
                .id(provider_id)
                .send()
                .await
                .map_err(|e| sdk_err("get SAML provider", e))?;
            spinner.finish_and_clear();
            let p = resp.into_inner();
            let (info, table_str) = format_saml_detail(&p);
            println!("{}", output::render(&info, &global.format, Some(table_str)));
        }
        _ => unreachable!("clap validates provider type"),
    }

    Ok(())
}

async fn create_ldap(
    name: &str,
    server_url: &str,
    user_base_dn: &str,
    bind_dn: Option<&str>,
    bind_password: Option<&str>,
    use_starttls: bool,
    global: &GlobalArgs,
) -> Result<()> {
    // Secret resolution (prompt/stdin/env) happens at the dispatch layer via
    // `resolve_secret`; by the time we get here the password is final.
    let bind_password = bind_password.map(|s| s.to_string());

    let client = client_for(global)?;
    let spinner = output::spinner("Creating LDAP provider...");

    let body = CreateLdapConfigRequest {
        name: name.to_string(),
        server_url: server_url.to_string(),
        user_base_dn: user_base_dn.to_string(),
        bind_dn: bind_dn.map(|s| s.to_string()),
        bind_password,
        use_starttls: Some(use_starttls),
        user_filter: None,
        username_attribute: None,
        email_attribute: None,
        display_name_attribute: None,
        groups_attribute: None,
        group_base_dn: None,
        group_filter: None,
        admin_group_dn: None,
        is_enabled: None,
        priority: None,
    };

    let resp = client
        .create_ldap()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create LDAP provider", e))?;

    spinner.finish_and_clear();
    let p = resp.into_inner();

    emit_mutation(
        &p,
        &p.id.to_string(),
        &format!("LDAP provider '{}' created (ID: {}).", p.name, p.id),
        global,
    );
    Ok(())
}

async fn create_oidc(
    name: &str,
    issuer_url: &str,
    client_id: &str,
    client_secret: Option<String>,
    auto_create_users: bool,
    global: &GlobalArgs,
) -> Result<()> {
    // Secret resolution (prompt/stdin/env) happens at the dispatch layer via
    // `resolve_secret`; here the secret only needs to be present.
    let client_secret = client_secret.ok_or_else(|| {
        AkError::ConfigError(
            "OIDC client secret is required. Provide --client-secret, pipe it to \
             --client-secret-stdin, or set AK_SSO_CLIENT_SECRET."
                .to_string(),
        )
    })?;

    let client = client_for(global)?;
    let spinner = output::spinner("Creating OIDC provider...");

    let body = CreateOidcConfigRequest {
        name: name.to_string(),
        issuer_url: issuer_url.to_string(),
        client_id: client_id.to_string(),
        client_secret,
        auto_create_users: Some(auto_create_users),
        scopes: None,
        attribute_mapping: None,
        is_enabled: None,
        allow_legacy_rsa_keys: None,
        map_groups_to_groups: None,
        pkce_enabled: None,
    };

    let resp = client
        .create_oidc()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create OIDC provider", e))?;

    spinner.finish_and_clear();
    let p = resp.into_inner();

    emit_mutation(
        &p,
        &p.id.to_string(),
        &format!("OIDC provider '{}' created (ID: {}).", p.name, p.id),
        global,
    );
    Ok(())
}

async fn create_saml(
    name: &str,
    entity_id: &str,
    sso_url: &str,
    certificate: &str,
    sign_requests: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Creating SAML provider...");

    let body = CreateSamlConfigRequest {
        name: name.to_string(),
        entity_id: entity_id.to_string(),
        sso_url: sso_url.to_string(),
        certificate: certificate.to_string(),
        sign_requests: Some(sign_requests),
        sp_entity_id: None,
        slo_url: None,
        attribute_mapping: None,
        name_id_format: None,
        require_signed_assertions: None,
        admin_group: None,
        is_enabled: None,
        use_absolute_acs_url: None,
    };

    let resp = client
        .create_saml()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create SAML provider", e))?;

    spinner.finish_and_clear();
    let p = resp.into_inner();

    emit_mutation(
        &p,
        &p.id.to_string(),
        &format!("SAML provider '{}' created (ID: {}).", p.name, p.id),
        global,
    );
    Ok(())
}

async fn delete_provider(
    id: &str,
    provider_type: &str,
    skip_confirm: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let provider_id = parse_uuid(id, "provider")?;

    if !confirm_action(
        &format!("Delete {provider_type} provider {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting provider...");

    match provider_type {
        "ldap" => {
            client
                .delete_ldap()
                .id(provider_id)
                .send()
                .await
                .map_err(|e| sdk_err("delete LDAP provider", e))?;
        }
        "oidc" => {
            client
                .delete_oidc()
                .id(provider_id)
                .send()
                .await
                .map_err(|e| sdk_err("delete OIDC provider", e))?;
        }
        "saml" => {
            client
                .delete_saml()
                .id(provider_id)
                .send()
                .await
                .map_err(|e| sdk_err("delete SAML provider", e))?;
        }
        _ => unreachable!("clap validates provider type"),
    }

    spinner.finish_and_clear();
    emit_mutation(
        &serde_json::json!({ "id": id, "status": "deleted" }),
        id,
        &format!("Provider {id} deleted."),
        global,
    );

    Ok(())
}

async fn test_provider(id: &str, provider_type: &str, global: &GlobalArgs) -> Result<()> {
    let provider_id = parse_uuid(id, "provider")?;

    // The backend only exposes a connectivity-test endpoint for LDAP providers
    // (`POST /admin/sso/ldap/{id}/test`); OIDC/SAML have no test route. Reject
    // those up front with a clear message instead of hitting the LDAP endpoint
    // (which would 404 for a non-LDAP provider id).
    if provider_type != "ldap" {
        return Err(AkError::ConfigError(format!(
            "Connectivity testing is only supported for LDAP providers, not '{provider_type}'. \
             OIDC/SAML providers are validated at login time."
        ))
        .into());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Testing LDAP connectivity...");

    let resp = client
        .test_ldap()
        .id(provider_id)
        .send()
        .await
        .map_err(|e| sdk_err("test LDAP provider", e))?;

    spinner.finish_and_clear();
    let result = resp.into_inner();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", if result.success { "ok" } else { "fail" });
        return Ok(());
    }

    let (info, table_str) = format_test_result(&result);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn toggle_provider(
    id: &str,
    provider_type: &str,
    enable: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let provider_id = parse_uuid(id, "provider")?;

    let client = client_for(global)?;
    let action = if enable { "Enabling" } else { "Disabling" };
    let spinner = output::spinner(&format!("{action} provider..."));

    let body = ToggleRequest { enabled: enable };

    match provider_type {
        "ldap" => {
            client
                .toggle_ldap()
                .id(provider_id)
                .body(body)
                .send()
                .await
                .map_err(|e| sdk_err("toggle LDAP provider", e))?;
        }
        "oidc" => {
            client
                .toggle_oidc()
                .id(provider_id)
                .body(body)
                .send()
                .await
                .map_err(|e| sdk_err("toggle OIDC provider", e))?;
        }
        "saml" => {
            client
                .toggle_saml()
                .id(provider_id)
                .body(body)
                .send()
                .await
                .map_err(|e| sdk_err("toggle SAML provider", e))?;
        }
        _ => unreachable!("clap validates provider type"),
    }

    spinner.finish_and_clear();
    let state = if enable { "enabled" } else { "disabled" };
    eprintln!("Provider {id} {state}.");

    Ok(())
}

async fn update_ldap(id: &str, body: UpdateLdapConfigRequest, global: &GlobalArgs) -> Result<()> {
    let provider_id = parse_uuid(id, "provider")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Updating LDAP provider...");

    let resp = client
        .update_ldap()
        .id(provider_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update LDAP provider", e))?;

    spinner.finish_and_clear();
    let p = resp.into_inner();
    emit_mutation(
        &p,
        &p.id.to_string(),
        &format!("LDAP provider '{}' updated (ID: {}).", p.name, p.id),
        global,
    );
    Ok(())
}

async fn update_oidc(id: &str, body: UpdateOidcConfigRequest, global: &GlobalArgs) -> Result<()> {
    let provider_id = parse_uuid(id, "provider")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Updating OIDC provider...");

    let resp = client
        .update_oidc()
        .id(provider_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update OIDC provider", e))?;

    spinner.finish_and_clear();
    let p = resp.into_inner();
    emit_mutation(
        &p,
        &p.id.to_string(),
        &format!("OIDC provider '{}' updated (ID: {}).", p.name, p.id),
        global,
    );
    Ok(())
}

async fn update_saml(id: &str, body: UpdateSamlConfigRequest, global: &GlobalArgs) -> Result<()> {
    let provider_id = parse_uuid(id, "provider")?;
    let client = client_for(global)?;
    let spinner = output::spinner("Updating SAML provider...");

    let resp = client
        .update_saml()
        .id(provider_id)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update SAML provider", e))?;

    spinner.finish_and_clear();
    let p = resp.into_inner();
    emit_mutation(
        &p,
        &p.id.to_string(),
        &format!("SAML provider '{}' updated (ID: {}).", p.name, p.id),
        global,
    );
    Ok(())
}

async fn list_enabled_providers(public: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching enabled SSO providers...");

    let providers = if public {
        client
            .list_providers()
            .send()
            .await
            .map_err(|e| sdk_err("list public SSO providers", e))?
            .into_inner()
    } else {
        client
            .list_sso_providers_admin()
            .send()
            .await
            .map_err(|e| sdk_err("list SSO providers", e))?
            .into_inner()
    };

    spinner.finish_and_clear();

    if providers.is_empty() {
        eprintln!("No enabled SSO providers.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for p in &providers {
            println!("{}", p.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_provider_infos(&providers);
    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_provider_infos(providers: &[SsoProviderInfo]) -> (Vec<Value>, String) {
    let entries: Vec<Value> = providers
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_string(),
                "name": p.name,
                "type": p.provider_type,
                "login_url": p.login_url,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec!["ID", "NAME", "TYPE", "LOGIN URL"]);
        for p in providers {
            let id_short = short_id(&p.id);
            table.add_row(vec![&id_short, &p.name, &p.provider_type, &p.login_url]);
        }
        table.to_string()
    };

    (entries, table_str)
}

fn format_providers_table(
    ldap: &[LdapConfigResponse],
    oidc: &[OidcConfigResponse],
    saml: &[SamlConfigResponse],
) -> (Vec<Value>, String) {
    let mut entries = Vec::new();

    for p in ldap {
        entries.push(serde_json::json!({
            "id": p.id.to_string(),
            "name": p.name,
            "type": "LDAP",
            "enabled": p.is_enabled,
            "url": p.server_url,
            "created_at": p.created_at.to_rfc3339(),
        }));
    }
    for p in oidc {
        entries.push(serde_json::json!({
            "id": p.id.to_string(),
            "name": p.name,
            "type": "OIDC",
            "enabled": p.is_enabled,
            "url": p.issuer_url,
            "created_at": p.created_at.to_rfc3339(),
        }));
    }
    for p in saml {
        entries.push(serde_json::json!({
            "id": p.id.to_string(),
            "name": p.name,
            "type": "SAML",
            "enabled": p.is_enabled,
            "url": p.sso_url,
            "created_at": p.created_at.to_rfc3339(),
        }));
    }

    let table_str = {
        let mut table = new_table(vec![
            "ID",
            "NAME",
            "TYPE",
            "ENABLED",
            "URL/ISSUER",
            "CREATED",
        ]);

        for p in ldap {
            let id_short = short_id(&p.id);
            let enabled = if p.is_enabled { "yes" } else { "no" };
            let created = p.created_at.format("%Y-%m-%d").to_string();
            table.add_row(vec![
                &id_short,
                &p.name,
                "LDAP",
                enabled,
                &p.server_url,
                &created,
            ]);
        }
        for p in oidc {
            let id_short = short_id(&p.id);
            let enabled = if p.is_enabled { "yes" } else { "no" };
            let created = p.created_at.format("%Y-%m-%d").to_string();
            table.add_row(vec![
                &id_short,
                &p.name,
                "OIDC",
                enabled,
                &p.issuer_url,
                &created,
            ]);
        }
        for p in saml {
            let id_short = short_id(&p.id);
            let enabled = if p.is_enabled { "yes" } else { "no" };
            let created = p.created_at.format("%Y-%m-%d").to_string();
            table.add_row(vec![
                &id_short, &p.name, "SAML", enabled, &p.sso_url, &created,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_ldap_detail(p: &LdapConfigResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": p.id.to_string(),
        "name": p.name,
        "type": "LDAP",
        "server_url": p.server_url,
        "user_base_dn": p.user_base_dn,
        "user_filter": p.user_filter,
        "username_attribute": p.username_attribute,
        "email_attribute": p.email_attribute,
        "display_name_attribute": p.display_name_attribute,
        "groups_attribute": p.groups_attribute,
        "bind_dn": p.bind_dn.as_deref().unwrap_or("-"),
        "has_bind_password": p.has_bind_password,
        "group_base_dn": p.group_base_dn.as_deref().unwrap_or("-"),
        "group_filter": p.group_filter.as_deref().unwrap_or("-"),
        "admin_group_dn": p.admin_group_dn.as_deref().unwrap_or("-"),
        "use_starttls": p.use_starttls,
        "is_enabled": p.is_enabled,
        "priority": p.priority,
        "created_at": p.created_at.to_rfc3339(),
        "updated_at": p.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:                    {}\n\
         Name:                  {}\n\
         Type:                  LDAP\n\
         Server URL:            {}\n\
         User Base DN:          {}\n\
         User Filter:           {}\n\
         Username Attribute:    {}\n\
         Email Attribute:       {}\n\
         Display Name Attr:     {}\n\
         Groups Attribute:      {}\n\
         Bind DN:               {}\n\
         Has Bind Password:     {}\n\
         Group Base DN:         {}\n\
         Group Filter:          {}\n\
         Admin Group DN:        {}\n\
         Use StartTLS:          {}\n\
         Enabled:               {}\n\
         Priority:              {}\n\
         Created:               {}\n\
         Updated:               {}",
        p.id,
        p.name,
        p.server_url,
        p.user_base_dn,
        p.user_filter,
        p.username_attribute,
        p.email_attribute,
        p.display_name_attribute,
        p.groups_attribute,
        p.bind_dn.as_deref().unwrap_or("-"),
        if p.has_bind_password { "yes" } else { "no" },
        p.group_base_dn.as_deref().unwrap_or("-"),
        p.group_filter.as_deref().unwrap_or("-"),
        p.admin_group_dn.as_deref().unwrap_or("-"),
        if p.use_starttls { "yes" } else { "no" },
        if p.is_enabled { "yes" } else { "no" },
        p.priority,
        p.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        p.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    (info, table_str)
}

fn format_oidc_detail(p: &OidcConfigResponse) -> (Value, String) {
    let scopes_str = if p.scopes.is_empty() {
        "-".to_string()
    } else {
        p.scopes.join(", ")
    };

    let info = serde_json::json!({
        "id": p.id.to_string(),
        "name": p.name,
        "type": "OIDC",
        "issuer_url": p.issuer_url,
        "client_id": p.client_id,
        "has_secret": p.has_secret,
        "scopes": p.scopes,
        "attribute_mapping": p.attribute_mapping,
        "auto_create_users": p.auto_create_users,
        "is_enabled": p.is_enabled,
        "created_at": p.created_at.to_rfc3339(),
        "updated_at": p.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:                {}\n\
         Name:              {}\n\
         Type:              OIDC\n\
         Issuer URL:        {}\n\
         Client ID:         {}\n\
         Has Secret:        {}\n\
         Scopes:            {}\n\
         Auto Create Users: {}\n\
         Enabled:           {}\n\
         Created:           {}\n\
         Updated:           {}",
        p.id,
        p.name,
        p.issuer_url,
        p.client_id,
        if p.has_secret { "yes" } else { "no" },
        scopes_str,
        if p.auto_create_users { "yes" } else { "no" },
        if p.is_enabled { "yes" } else { "no" },
        p.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        p.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    (info, table_str)
}

fn format_saml_detail(p: &SamlConfigResponse) -> (Value, String) {
    let info = serde_json::json!({
        "id": p.id.to_string(),
        "name": p.name,
        "type": "SAML",
        "entity_id": p.entity_id,
        "sso_url": p.sso_url,
        "sp_entity_id": p.sp_entity_id,
        "slo_url": p.slo_url.as_deref().unwrap_or("-"),
        "has_certificate": p.has_certificate,
        "attribute_mapping": p.attribute_mapping,
        "name_id_format": p.name_id_format,
        "sign_requests": p.sign_requests,
        "require_signed_assertions": p.require_signed_assertions,
        "admin_group": p.admin_group.as_deref().unwrap_or("-"),
        "is_enabled": p.is_enabled,
        "created_at": p.created_at.to_rfc3339(),
        "updated_at": p.updated_at.to_rfc3339(),
    });

    let table_str = format!(
        "ID:                        {}\n\
         Name:                      {}\n\
         Type:                      SAML\n\
         Entity ID:                 {}\n\
         SSO URL:                   {}\n\
         SP Entity ID:              {}\n\
         SLO URL:                   {}\n\
         Has Certificate:           {}\n\
         Name ID Format:            {}\n\
         Sign Requests:             {}\n\
         Require Signed Assertions: {}\n\
         Admin Group:               {}\n\
         Enabled:                   {}\n\
         Created:                   {}\n\
         Updated:                   {}",
        p.id,
        p.name,
        p.entity_id,
        p.sso_url,
        p.sp_entity_id,
        p.slo_url.as_deref().unwrap_or("-"),
        if p.has_certificate { "yes" } else { "no" },
        p.name_id_format,
        if p.sign_requests { "yes" } else { "no" },
        if p.require_signed_assertions {
            "yes"
        } else {
            "no"
        },
        p.admin_group.as_deref().unwrap_or("-"),
        if p.is_enabled { "yes" } else { "no" },
        p.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        p.updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );

    (info, table_str)
}

fn format_test_result(r: &LdapTestResult) -> (Value, String) {
    let info = serde_json::json!({
        "success": r.success,
        "message": r.message,
        "response_time_ms": r.response_time_ms,
    });

    let status = if r.success { "PASS" } else { "FAIL" };
    let table_str = format!(
        "Result:        {}\n\
         Message:       {}\n\
         Response Time: {} ms",
        status, r.message, r.response_time_ms,
    );

    (info, table_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: SsoCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> std::result::Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- Parsing tests ----

    #[test]
    fn parse_list() {
        let cli = parse(&["test", "list"]);
        assert!(matches!(cli.command, SsoCommand::List));
    }

    #[test]
    fn parse_show_ldap() {
        let cli = parse(&["test", "show", "some-id", "--type", "ldap"]);
        if let SsoCommand::Show { id, r#type } = cli.command {
            assert_eq!(id, "some-id");
            assert_eq!(r#type, "ldap");
        } else {
            panic!("Expected Show");
        }
    }

    #[test]
    fn parse_show_oidc() {
        let cli = parse(&["test", "show", "some-id", "--type", "oidc"]);
        if let SsoCommand::Show { id, r#type } = cli.command {
            assert_eq!(id, "some-id");
            assert_eq!(r#type, "oidc");
        } else {
            panic!("Expected Show");
        }
    }

    #[test]
    fn parse_show_saml() {
        let cli = parse(&["test", "show", "some-id", "--type", "saml"]);
        if let SsoCommand::Show { id, r#type } = cli.command {
            assert_eq!(id, "some-id");
            assert_eq!(r#type, "saml");
        } else {
            panic!("Expected Show");
        }
    }

    #[test]
    fn parse_show_invalid_type() {
        let result = try_parse(&["test", "show", "some-id", "--type", "kerberos"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_show_missing_type() {
        let result = try_parse(&["test", "show", "some-id"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_create_ldap() {
        let cli = parse(&[
            "test",
            "create",
            "ldap",
            "corp-ldap",
            "--server-url",
            "ldaps://ldap.corp.com",
            "--user-base-dn",
            "ou=users,dc=corp",
        ]);
        if let SsoCommand::Create {
            command:
                SsoCreateCommand::Ldap {
                    name,
                    server_url,
                    user_base_dn,
                    bind_dn,
                    bind_password,
                    bind_password_stdin,
                    use_starttls,
                },
        } = cli.command
        {
            assert_eq!(name, "corp-ldap");
            assert_eq!(server_url, "ldaps://ldap.corp.com");
            assert_eq!(user_base_dn, "ou=users,dc=corp");
            assert!(bind_dn.is_none());
            assert!(bind_password.is_none());
            assert!(!bind_password_stdin);
            assert!(!use_starttls);
        } else {
            panic!("Expected Create Ldap");
        }
    }

    #[test]
    fn parse_create_ldap_bind_password_stdin() {
        let cli = parse(&[
            "test",
            "create",
            "ldap",
            "corp-ldap",
            "--server-url",
            "ldaps://ldap.corp.com",
            "--user-base-dn",
            "ou=users,dc=corp",
            "--bind-dn",
            "cn=admin,dc=corp",
            "--bind-password-stdin",
        ]);
        if let SsoCommand::Create {
            command:
                SsoCreateCommand::Ldap {
                    bind_password,
                    bind_password_stdin,
                    ..
                },
        } = cli.command
        {
            assert!(bind_password.is_none());
            assert!(bind_password_stdin);
        } else {
            panic!("Expected Create Ldap");
        }
    }

    #[test]
    fn parse_create_ldap_with_bind() {
        let cli = parse(&[
            "test",
            "create",
            "ldap",
            "corp-ldap",
            "--server-url",
            "ldap://ldap.corp.com",
            "--user-base-dn",
            "ou=users,dc=corp",
            "--bind-dn",
            "cn=admin,dc=corp",
            "--bind-password",
            "secret",
            "--use-starttls",
        ]);
        if let SsoCommand::Create {
            command:
                SsoCreateCommand::Ldap {
                    name,
                    bind_dn,
                    bind_password,
                    use_starttls,
                    ..
                },
        } = cli.command
        {
            assert_eq!(name, "corp-ldap");
            assert_eq!(bind_dn.unwrap(), "cn=admin,dc=corp");
            assert_eq!(bind_password.unwrap(), "secret");
            assert!(use_starttls);
        } else {
            panic!("Expected Create Ldap with bind options");
        }
    }

    #[test]
    fn parse_create_oidc() {
        let cli = parse(&[
            "test",
            "create",
            "oidc",
            "okta-sso",
            "--issuer-url",
            "https://company.okta.com",
            "--client-id",
            "abc123",
            "--client-secret",
            "secret456",
        ]);
        if let SsoCommand::Create {
            command:
                SsoCreateCommand::Oidc {
                    name,
                    issuer_url,
                    client_id,
                    client_secret,
                    client_secret_stdin,
                    auto_create_users,
                },
        } = cli.command
        {
            assert_eq!(name, "okta-sso");
            assert_eq!(issuer_url, "https://company.okta.com");
            assert_eq!(client_id, "abc123");
            assert_eq!(client_secret.unwrap(), "secret456");
            assert!(!client_secret_stdin);
            assert!(!auto_create_users);
        } else {
            panic!("Expected Create Oidc");
        }
    }

    #[test]
    fn parse_create_oidc_client_secret_stdin() {
        let cli = parse(&[
            "test",
            "create",
            "oidc",
            "okta-sso",
            "--issuer-url",
            "https://company.okta.com",
            "--client-id",
            "abc123",
            "--client-secret-stdin",
        ]);
        if let SsoCommand::Create {
            command:
                SsoCreateCommand::Oidc {
                    client_secret,
                    client_secret_stdin,
                    ..
                },
        } = cli.command
        {
            assert!(client_secret.is_none());
            assert!(client_secret_stdin);
        } else {
            panic!("Expected Create Oidc");
        }
    }

    #[test]
    fn parse_update_oidc_client_secret_stdin() {
        let cli = parse(&[
            "test",
            "update",
            "oidc",
            "00000000-0000-0000-0000-000000000001",
            "--client-secret-stdin",
        ]);
        if let SsoCommand::Update { command } = cli.command {
            if let SsoUpdateCommand::Oidc {
                client_secret,
                client_secret_stdin,
                ..
            } = *command
            {
                assert!(client_secret.is_none());
                assert!(client_secret_stdin);
            } else {
                panic!("Expected Update Oidc");
            }
        } else {
            panic!("Expected Update");
        }
    }

    #[test]
    fn parse_update_ldap_bind_password_stdin() {
        let cli = parse(&[
            "test",
            "update",
            "ldap",
            "00000000-0000-0000-0000-000000000001",
            "--bind-password-stdin",
        ]);
        if let SsoCommand::Update { command } = cli.command {
            if let SsoUpdateCommand::Ldap {
                bind_password,
                bind_password_stdin,
                ..
            } = *command
            {
                assert!(bind_password.is_none());
                assert!(bind_password_stdin);
            } else {
                panic!("Expected Update Ldap");
            }
        } else {
            panic!("Expected Update");
        }
    }

    #[test]
    fn parse_create_saml() {
        let cli = parse(&[
            "test",
            "create",
            "saml",
            "azure-ad",
            "--entity-id",
            "https://sts.windows.net/tenant-id",
            "--sso-url",
            "https://login.microsoftonline.com/tenant-id/saml2",
            "--certificate",
            "MIIC...",
        ]);
        if let SsoCommand::Create {
            command:
                SsoCreateCommand::Saml {
                    name,
                    entity_id,
                    sso_url,
                    certificate,
                    sign_requests,
                },
        } = cli.command
        {
            assert_eq!(name, "azure-ad");
            assert_eq!(entity_id, "https://sts.windows.net/tenant-id");
            assert_eq!(sso_url, "https://login.microsoftonline.com/tenant-id/saml2");
            assert_eq!(certificate, "MIIC...");
            assert!(!sign_requests);
        } else {
            panic!("Expected Create Saml");
        }
    }

    #[test]
    fn parse_delete() {
        let cli = parse(&["test", "delete", "some-id", "--type", "ldap"]);
        if let SsoCommand::Delete { id, r#type, yes } = cli.command {
            assert_eq!(id, "some-id");
            assert_eq!(r#type, "ldap");
            assert!(!yes);
        } else {
            panic!("Expected Delete");
        }
    }

    #[test]
    fn parse_delete_with_yes() {
        let cli = parse(&["test", "delete", "some-id", "--type", "oidc", "--yes"]);
        if let SsoCommand::Delete { id, r#type, yes } = cli.command {
            assert_eq!(id, "some-id");
            assert_eq!(r#type, "oidc");
            assert!(yes);
        } else {
            panic!("Expected Delete with --yes");
        }
    }

    #[test]
    fn parse_test() {
        let cli = parse(&["test", "test", "some-id"]);
        if let SsoCommand::Test { id, r#type } = cli.command {
            assert_eq!(id, "some-id");
            assert_eq!(r#type, "ldap");
        } else {
            panic!("Expected Test");
        }
    }

    #[test]
    fn parse_test_with_type() {
        let cli = parse(&["test", "test", "some-id", "--type", "oidc"]);
        if let SsoCommand::Test { id, r#type } = cli.command {
            assert_eq!(id, "some-id");
            assert_eq!(r#type, "oidc");
        } else {
            panic!("Expected Test");
        }
    }

    #[test]
    fn parse_test_missing_id() {
        let result = try_parse(&["test", "test"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_toggle_enable() {
        let cli = parse(&["test", "toggle", "some-id", "--type", "ldap", "--enable"]);
        if let SsoCommand::Toggle { id, r#type, enable } = cli.command {
            assert_eq!(id, "some-id");
            assert_eq!(r#type, "ldap");
            assert!(enable);
        } else {
            panic!("Expected Toggle");
        }
    }

    #[test]
    fn parse_toggle_disable() {
        let cli = parse(&["test", "toggle", "some-id", "--type", "saml"]);
        if let SsoCommand::Toggle { id, r#type, enable } = cli.command {
            assert_eq!(id, "some-id");
            assert_eq!(r#type, "saml");
            assert!(!enable);
        } else {
            panic!("Expected Toggle without --enable");
        }
    }

    // ---- Format function tests ----

    use chrono::Utc;
    use uuid::Uuid;

    fn make_ldap(name: &str, enabled: bool) -> LdapConfigResponse {
        LdapConfigResponse {
            id: Uuid::nil(),
            name: name.to_string(),
            server_url: "ldaps://ldap.example.com".to_string(),
            user_base_dn: "ou=users,dc=example".to_string(),
            user_filter: "(objectClass=person)".to_string(),
            username_attribute: "uid".to_string(),
            email_attribute: "mail".to_string(),
            display_name_attribute: "cn".to_string(),
            groups_attribute: "memberOf".to_string(),
            bind_dn: Some("cn=admin,dc=example".to_string()),
            has_bind_password: true,
            group_base_dn: Some("ou=groups,dc=example".to_string()),
            group_filter: None,
            admin_group_dn: None,
            use_starttls: false,
            is_enabled: enabled,
            priority: 10,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_oidc(name: &str, enabled: bool) -> OidcConfigResponse {
        OidcConfigResponse {
            id: Uuid::nil(),
            name: name.to_string(),
            issuer_url: "https://auth.example.com".to_string(),
            client_id: "client-123".to_string(),
            has_secret: true,
            scopes: vec!["openid".to_string(), "profile".to_string()],
            attribute_mapping: serde_json::Map::new(),
            auto_create_users: true,
            allow_legacy_rsa_keys: false,
            map_groups_to_groups: false,
            pkce_enabled: true,
            is_enabled: enabled,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_saml(name: &str, enabled: bool) -> SamlConfigResponse {
        SamlConfigResponse {
            id: Uuid::nil(),
            name: name.to_string(),
            entity_id: "https://idp.example.com".to_string(),
            sso_url: "https://idp.example.com/sso".to_string(),
            sp_entity_id: "https://sp.example.com".to_string(),
            slo_url: Some("https://idp.example.com/slo".to_string()),
            has_certificate: true,
            attribute_mapping: serde_json::Map::new(),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            sign_requests: true,
            require_signed_assertions: true,
            admin_group: Some("admins".to_string()),
            use_absolute_acs_url: false,
            is_enabled: enabled,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // ---- format_providers_table ----

    #[test]
    fn format_providers_table_empty() {
        let (entries, table_str) = format_providers_table(&[], &[], &[]);
        assert!(entries.is_empty());
        assert!(table_str.contains("NAME"));
        assert!(table_str.contains("TYPE"));
    }

    #[test]
    fn format_providers_table_ldap_only() {
        let ldap = vec![make_ldap("corp-ldap", true)];
        let (entries, table_str) = format_providers_table(&ldap, &[], &[]);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["type"], "LDAP");
        assert_eq!(entries[0]["name"], "corp-ldap");
        assert!(table_str.contains("LDAP"));
        assert!(table_str.contains("corp-ldap"));
    }

    #[test]
    fn format_providers_table_mixed() {
        let ldap = vec![make_ldap("corp-ldap", true)];
        let oidc = vec![make_oidc("okta", false)];
        let saml = vec![make_saml("azure-ad", true)];
        let (entries, table_str) = format_providers_table(&ldap, &oidc, &saml);

        assert_eq!(entries.len(), 3);
        assert!(table_str.contains("LDAP"));
        assert!(table_str.contains("OIDC"));
        assert!(table_str.contains("SAML"));
        assert!(table_str.contains("corp-ldap"));
        assert!(table_str.contains("okta"));
        assert!(table_str.contains("azure-ad"));
    }

    #[test]
    fn format_providers_table_enabled_disabled() {
        let ldap = vec![make_ldap("enabled-ldap", true)];
        let oidc = vec![make_oidc("disabled-oidc", false)];
        let (entries, table_str) = format_providers_table(&ldap, &oidc, &[]);

        assert_eq!(entries[0]["enabled"], true);
        assert_eq!(entries[1]["enabled"], false);
        assert!(table_str.contains("yes"));
        assert!(table_str.contains("no"));
    }

    // ---- format_ldap_detail ----

    #[test]
    fn format_ldap_detail_full() {
        let p = make_ldap("detail-ldap", true);
        let (info, table_str) = format_ldap_detail(&p);

        assert_eq!(info["name"], "detail-ldap");
        assert_eq!(info["type"], "LDAP");
        assert_eq!(info["server_url"], "ldaps://ldap.example.com");
        assert_eq!(info["is_enabled"], true);
        assert_eq!(info["priority"], 10);

        assert!(table_str.contains("detail-ldap"));
        assert!(table_str.contains("LDAP"));
        assert!(table_str.contains("ldaps://ldap.example.com"));
        assert!(table_str.contains("ou=users,dc=example"));
        assert!(table_str.contains("cn=admin,dc=example"));
    }

    #[test]
    fn format_ldap_detail_no_bind() {
        let mut p = make_ldap("no-bind", false);
        p.bind_dn = None;
        p.has_bind_password = false;
        let (info, table_str) = format_ldap_detail(&p);

        assert_eq!(info["bind_dn"], "-");
        assert!(table_str.contains("Bind DN:"));
    }

    // ---- format_oidc_detail ----

    #[test]
    fn format_oidc_detail_full() {
        let p = make_oidc("detail-oidc", true);
        let (info, table_str) = format_oidc_detail(&p);

        assert_eq!(info["name"], "detail-oidc");
        assert_eq!(info["type"], "OIDC");
        assert_eq!(info["issuer_url"], "https://auth.example.com");
        assert_eq!(info["auto_create_users"], true);

        assert!(table_str.contains("detail-oidc"));
        assert!(table_str.contains("OIDC"));
        assert!(table_str.contains("https://auth.example.com"));
        assert!(table_str.contains("openid, profile"));
    }

    #[test]
    fn format_oidc_detail_empty_scopes() {
        let mut p = make_oidc("no-scopes", true);
        p.scopes = vec![];
        let (_, table_str) = format_oidc_detail(&p);

        assert!(table_str.contains("Scopes:"));
        // Should show "-" for empty scopes
        assert!(table_str.contains("-"));
    }

    // ---- format_saml_detail ----

    #[test]
    fn format_saml_detail_full() {
        let p = make_saml("detail-saml", true);
        let (info, table_str) = format_saml_detail(&p);

        assert_eq!(info["name"], "detail-saml");
        assert_eq!(info["type"], "SAML");
        assert_eq!(info["entity_id"], "https://idp.example.com");
        assert_eq!(info["sign_requests"], true);
        assert_eq!(info["require_signed_assertions"], true);

        assert!(table_str.contains("detail-saml"));
        assert!(table_str.contains("SAML"));
        assert!(table_str.contains("https://idp.example.com/sso"));
        assert!(table_str.contains("https://idp.example.com/slo"));
    }

    #[test]
    fn format_saml_detail_no_slo() {
        let mut p = make_saml("no-slo", true);
        p.slo_url = None;
        p.admin_group = None;
        let (info, table_str) = format_saml_detail(&p);

        assert_eq!(info["slo_url"], "-");
        assert_eq!(info["admin_group"], "-");
        assert!(table_str.contains("SLO URL:"));
    }

    // ---- format_test_result ----

    #[test]
    fn format_test_result_success() {
        let r = LdapTestResult {
            success: true,
            message: "Connection successful".to_string(),
            response_time_ms: 42,
        };
        let (info, table_str) = format_test_result(&r);

        assert_eq!(info["success"], true);
        assert_eq!(info["message"], "Connection successful");
        assert_eq!(info["response_time_ms"], 42);

        assert!(table_str.contains("PASS"));
        assert!(table_str.contains("Connection successful"));
        assert!(table_str.contains("42 ms"));
    }

    #[test]
    fn format_test_result_failure() {
        let r = LdapTestResult {
            success: false,
            message: "Connection refused".to_string(),
            response_time_ms: 5000,
        };
        let (info, table_str) = format_test_result(&r);

        assert_eq!(info["success"], false);
        assert!(table_str.contains("FAIL"));
        assert!(table_str.contains("Connection refused"));
        assert!(table_str.contains("5000 ms"));
    }

    // ---- wiremock handler tests ----

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn ldap_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "corp-ldap",
            "server_url": "ldaps://ldap.corp.com",
            "user_base_dn": "ou=users,dc=corp",
            "user_filter": "(objectClass=person)",
            "username_attribute": "uid",
            "email_attribute": "mail",
            "display_name_attribute": "cn",
            "groups_attribute": "memberOf",
            "bind_dn": "cn=admin,dc=corp",
            "has_bind_password": true,
            "group_base_dn": "ou=groups,dc=corp",
            "group_filter": null,
            "admin_group_dn": null,
            "use_starttls": false,
            "is_enabled": true,
            "priority": 10,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    fn oidc_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "okta-sso",
            "issuer_url": "https://company.okta.com",
            "client_id": "abc123",
            "has_secret": true,
            "scopes": ["openid", "profile"],
            "attribute_mapping": {},
            "auto_create_users": true,
            "allow_legacy_rsa_keys": false,
            "map_groups_to_groups": false,
            "pkce_enabled": true,
            "is_enabled": true,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    fn saml_json() -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": "azure-ad",
            "entity_id": "https://sts.windows.net/tenant-id",
            "sso_url": "https://login.microsoftonline.com/tenant-id/saml2",
            "sp_entity_id": "https://sp.example.com",
            "slo_url": "https://login.microsoftonline.com/tenant-id/saml2/logout",
            "has_certificate": true,
            "attribute_mapping": {},
            "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "sign_requests": true,
            "require_signed_assertions": true,
            "admin_group": "admins",
            "use_absolute_acs_url": false,
            "is_enabled": true,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    fn test_result_json() -> serde_json::Value {
        json!({
            "success": true,
            "message": "Connection successful",
            "response_time_ms": 42
        })
    }

    #[tokio::test]
    async fn handler_list_providers_merged() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/sso/ldap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([ldap_json()])))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/sso/oidc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([oidc_json()])))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/sso/saml"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([saml_json()])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_providers(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_providers_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/sso/ldap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/sso/oidc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/sso/saml"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_providers(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_ldap() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/admin/sso/ldap/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(ldap_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = show_provider(NIL_UUID, "ldap", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_ldap() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/sso/ldap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ldap_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_ldap(
            "corp-ldap",
            "ldaps://ldap.corp.com",
            "ou=users,dc=corp",
            Some("cn=admin,dc=corp"),
            Some("secret"),
            false,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_oidc() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/sso/oidc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(oidc_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_oidc(
            "okta-sso",
            "https://company.okta.com",
            "abc123",
            Some("secret456".into()),
            true,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_saml() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/admin/sso/saml"))
            .respond_with(ResponseTemplate::new(200).set_body_json(saml_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = create_saml(
            "azure-ad",
            "https://sts.windows.net/tenant-id",
            "https://login.microsoftonline.com/tenant-id/saml2",
            "MIIC...",
            true,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_provider() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/admin/sso/ldap/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = delete_provider(NIL_UUID, "ldap", true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_test_provider() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path(format!("/api/v1/admin/sso/ldap/{NIL_UUID}/test")))
            .respond_with(ResponseTemplate::new(200).set_body_json(test_result_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = test_provider(NIL_UUID, "ldap", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_test_provider_non_ldap_rejected() {
        // OIDC/SAML have no backend test endpoint; the CLI should reject early
        // rather than hitting the LDAP route.
        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        assert!(test_provider(NIL_UUID, "oidc", &global).await.is_err());
        assert!(test_provider(NIL_UUID, "saml", &global).await.is_err());
    }

    #[tokio::test]
    async fn handler_toggle_provider() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/admin/sso/oidc/{NIL_UUID}/toggle")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = toggle_provider(NIL_UUID, "oidc", true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- update / providers parse tests ----

    #[test]
    fn parse_update_oidc() {
        let cli = parse(&[
            "test",
            "update",
            "oidc",
            "some-id",
            "--issuer-url",
            "https://new.okta.com",
            "--auto-create-users",
            "true",
            "--scope",
            "openid",
            "--scope",
            "profile",
        ]);
        let SsoCommand::Update { command } = cli.command else {
            panic!("Expected Update");
        };
        if let SsoUpdateCommand::Oidc {
            id,
            issuer_url,
            auto_create_users,
            scope,
            client_id,
            ..
        } = *command
        {
            assert_eq!(id, "some-id");
            assert_eq!(issuer_url.unwrap(), "https://new.okta.com");
            assert_eq!(auto_create_users, Some(true));
            assert_eq!(scope, vec!["openid", "profile"]);
            // Unmentioned fields stay None so they are not clobbered.
            assert!(client_id.is_none());
        } else {
            panic!("Expected Update Oidc");
        }
    }

    #[test]
    fn parse_update_ldap_partial() {
        let cli = parse(&[
            "test",
            "update",
            "ldap",
            "some-id",
            "--priority",
            "5",
            "--is-enabled",
            "false",
        ]);
        let SsoCommand::Update { command } = cli.command else {
            panic!("Expected Update");
        };
        if let SsoUpdateCommand::Ldap {
            id,
            priority,
            is_enabled,
            server_url,
            ..
        } = *command
        {
            assert_eq!(id, "some-id");
            assert_eq!(priority, Some(5));
            assert_eq!(is_enabled, Some(false));
            assert!(server_url.is_none());
        } else {
            panic!("Expected Update Ldap");
        }
    }

    #[test]
    fn parse_update_saml() {
        let cli = parse(&[
            "test",
            "update",
            "saml",
            "some-id",
            "--sso-url",
            "https://idp/sso",
            "--sign-requests",
            "true",
        ]);
        let SsoCommand::Update { command } = cli.command else {
            panic!("Expected Update");
        };
        if let SsoUpdateCommand::Saml {
            id,
            sso_url,
            sign_requests,
            entity_id,
            ..
        } = *command
        {
            assert_eq!(id, "some-id");
            assert_eq!(sso_url.unwrap(), "https://idp/sso");
            assert_eq!(sign_requests, Some(true));
            assert!(entity_id.is_none());
        } else {
            panic!("Expected Update Saml");
        }
    }

    #[test]
    fn parse_providers_default_admin() {
        let cli = parse(&["test", "providers"]);
        if let SsoCommand::Providers { public } = cli.command {
            assert!(!public);
        } else {
            panic!("Expected Providers");
        }
    }

    #[test]
    fn parse_providers_public() {
        let cli = parse(&["test", "providers", "--public"]);
        if let SsoCommand::Providers { public } = cli.command {
            assert!(public);
        } else {
            panic!("Expected Providers --public");
        }
    }

    // ---- format_provider_infos ----

    fn make_provider_info(name: &str, ptype: &str) -> SsoProviderInfo {
        SsoProviderInfo {
            id: Uuid::nil(),
            name: name.to_string(),
            provider_type: ptype.to_string(),
            login_url: format!("/api/v1/auth/sso/{ptype}/{NIL_UUID}/login"),
        }
    }

    #[test]
    fn format_provider_infos_renders() {
        let providers = vec![
            make_provider_info("okta", "oidc"),
            make_provider_info("azure", "saml"),
        ];
        let (entries, table_str) = format_provider_infos(&providers);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["name"], "okta");
        assert_eq!(entries[0]["type"], "oidc");
        assert!(table_str.contains("okta"));
        assert!(table_str.contains("azure"));
        assert!(table_str.contains("LOGIN URL"));
    }

    // ---- update / providers handler tests ----

    fn provider_info_json(name: &str, ptype: &str) -> serde_json::Value {
        json!({
            "id": NIL_UUID,
            "name": name,
            "provider_type": ptype,
            "login_url": format!("/api/v1/auth/sso/{ptype}/{NIL_UUID}/login"),
        })
    }

    #[tokio::test]
    async fn handler_update_oidc() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/admin/sso/oidc/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(oidc_json()))
            .mount(&server)
            .await;

        let body = UpdateOidcConfigRequest {
            name: None,
            issuer_url: Some("https://new.okta.com".to_string()),
            client_id: None,
            client_secret: None,
            auto_create_users: Some(true),
            scopes: Some(vec!["openid".to_string()]),
            attribute_mapping: None,
            attribute_mapping_replace: None,
            allow_legacy_rsa_keys: None,
            map_groups_to_groups: None,
            pkce_enabled: None,
            is_enabled: None,
        };

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = update_oidc(NIL_UUID, body, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_ldap() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/admin/sso/ldap/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(ldap_json()))
            .mount(&server)
            .await;

        let body = UpdateLdapConfigRequest {
            name: None,
            server_url: None,
            user_base_dn: None,
            user_filter: None,
            username_attribute: None,
            email_attribute: None,
            display_name_attribute: None,
            groups_attribute: None,
            bind_dn: None,
            bind_password: None,
            group_base_dn: None,
            group_filter: None,
            admin_group_dn: None,
            use_starttls: None,
            priority: Some(5),
            is_enabled: Some(false),
        };

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = update_ldap(NIL_UUID, body, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_saml() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("PUT"))
            .and(path(format!("/api/v1/admin/sso/saml/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(saml_json()))
            .mount(&server)
            .await;

        let body = UpdateSamlConfigRequest {
            name: None,
            entity_id: None,
            sso_url: Some("https://idp/sso".to_string()),
            certificate: None,
            sp_entity_id: None,
            slo_url: None,
            name_id_format: None,
            admin_group: None,
            attribute_mapping: None,
            sign_requests: Some(true),
            require_signed_assertions: None,
            use_absolute_acs_url: None,
            is_enabled: None,
        };

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Quiet);
        let result = update_saml(NIL_UUID, body, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_enabled_providers_admin() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/sso/providers"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([provider_info_json("okta", "oidc")])),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_enabled_providers(false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_enabled_providers_public() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/sso/providers"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([provider_info_json("azure", "saml")])),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_enabled_providers(true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_enabled_providers_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/admin/sso/providers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = list_enabled_providers(false, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_sso_ldap_json() {
        let data = ldap_json();
        let output = crate::output::render(&data, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("sso_ldap_json", parsed);
    }

    #[test]
    fn snapshot_sso_oidc_json() {
        let data = oidc_json();
        let output = crate::output::render(&data, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("sso_oidc_json", parsed);
    }
}
