use artifact_keeper_sdk::{ClientAuthExt, ClientSsoExt, ClientUsersExt};
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::{IntoDiagnostic, Result};

use super::client::{anon_client, authenticated_client, build_client, client_for};
use super::helpers::{
    guard_flags, parse_json_arg, parse_uuid, raw_err, require_secret, resolve_secret, sdk_err,
};
use crate::cli::GlobalArgs;
use crate::config::credentials::{
    StoredCredential, delete_credential, get_credential, store_credential,
};
use crate::config::{AppConfig, InstanceConfig};
use crate::error::AkError;
use crate::output::{self, OutputFormat};
use crate::transport;

#[derive(clap::Args)]
pub struct LoginArgs {
    /// Instance URL (uses default instance if omitted)
    url: Option<String>,

    /// Skip interactive prompt and go straight to token authentication
    #[arg(long, conflicts_with_all = ["oidc_device", "sso", "username"])]
    token: bool,

    /// Read the token from stdin rather than asking for it
    #[arg(long, conflicts_with_all = ["token", "oidc_device", "sso", "username", "totp_code_stdin"])]
    token_stdin: bool,

    /// Sign in with the RFC 8628 device authorization grant instead of
    /// prompting for a password or token. Prints a verification URL and a
    /// short user code, then polls until the user approves it. Works
    /// headlessly and with SSO-backed instances. Requires backend 1.12.0+.
    #[arg(long = "oidc-device", visible_alias = "device", conflicts_with_all = ["sso", "username"])]
    oidc_device: bool,

    /// AK scopes to request with --oidc-device (repeatable, or
    /// comma-separated). Defaults to `read:artifacts`.
    #[arg(long, value_delimiter = ',', requires = "oidc_device")]
    scope: Vec<String>,

    /// Sign in through an SSO provider, as `ldap:<id>`, `oidc:<id>` or `saml:<id>`.
    /// `ak sso providers` lists them. LDAP takes a username and password here. OIDC
    /// and SAML print a URL to open in a browser, which ends at a callback URL with
    /// a code to give to this command or to `ak auth sso-exchange`. An instance
    /// serving the web UI redeems that code on the callback page, and it works only
    /// once: use an API token or, on 1.12, --oidc-device there
    #[arg(long, value_name = "TYPE:ID")]
    sso: Option<String>,

    /// The OIDC `prompt` value to send to the identity provider
    #[arg(long, requires = "sso")]
    prompt: Option<String>,

    /// Username. With this there's no menu of login methods
    #[arg(long)]
    username: Option<String>,

    /// Read the password from stdin rather than asking for it
    #[arg(long, requires = "username", conflicts_with = "totp_code_stdin")]
    password_stdin: bool,

    /// The TOTP code, if the account has two-factor login. Without it you're asked
    #[arg(long, env = "AK_TOTP_CODE", hide_env_values = true)]
    totp_code: Option<String>,

    /// Read the TOTP code from stdin
    #[arg(long)]
    totp_code_stdin: bool,

    /// If the server asks for a TOTP code or for TOTP enrollment, print its one-time
    /// ticket on stdout and stop, without logging in. Finish with `ak auth verify-totp`
    /// or `ak totp enroll`
    #[arg(long)]
    print_totp_ticket: bool,
}

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Log in to an Artifact Keeper instance. The session is stored and never printed
    #[command(
        after_help = "Examples:\n  ak auth login\n  ak auth login --username alice --password-stdin < secret-file\n  ak auth login --token-stdin < token-file\n  ak auth login --sso ldap:<provider-id> --username alice\n  ak auth login --sso oidc:<provider-id>"
    )]
    Login(Box<LoginArgs>),

    /// Log out and remove stored credentials
    Logout {
        /// Instance to log out from (uses default if omitted)
        instance: Option<String>,
    },

    /// Manage API tokens
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },

    /// Show current authenticated user and instance
    Whoami,

    /// Refresh the stored access token using the saved refresh token
    Refresh {
        /// Instance to refresh (uses default if omitted)
        instance: Option<String>,
    },

    /// Revoke an API token by ID
    RevokeToken {
        /// ID of the API token to revoke
        id: String,
    },

    /// Verify a TOTP code to complete two-factor login
    VerifyTotp {
        /// The code from your authenticator app. Omit it to use --code-stdin or a
        /// prompt
        code: Option<String>,

        /// Read the code from stdin
        #[arg(long)]
        code_stdin: bool,

        /// The one-time ticket from `ak auth login --print-totp-ticket`
        #[arg(long, env = "AK_TOTP_TOKEN", hide_env_values = true)]
        totp_token: Option<String>,

        /// Read the ticket from stdin
        #[arg(long, conflicts_with = "code_stdin")]
        totp_token_stdin: bool,
    },

    /// Finish an OIDC or SAML login: trade the code from the callback URL for a session
    SsoExchange {
        /// The exchange code, or the whole callback URL
        #[arg(long, env = "AK_SSO_CODE", hide_env_values = true)]
        code: Option<String>,

        /// Read the code or the URL from stdin
        #[arg(long)]
        code_stdin: bool,
    },

    /// Create a short-lived, single-use download ticket for a resource
    DownloadTicket {
        /// Resource path the ticket should grant access to
        resource_path: String,

        /// Purpose of the ticket
        #[arg(long, default_value = "download")]
        purpose: String,
    },

    /// Exchange a CI-issued OIDC JWT for an Artifact Keeper access token
    CiExchange {
        /// The pre-configured CI OIDC provider ID (UUID)
        #[arg(long)]
        provider_id: String,

        /// The OIDC JWT to exchange (falls back to the AK_CI_JWT env var)
        #[arg(long, env = "AK_CI_JWT", hide_env_values = true)]
        jwt: Option<String>,

        /// Read the OIDC JWT from stdin (avoids exposing it on the command
        /// line)
        #[arg(long)]
        jwt_stdin: bool,
    },

    /// Show whether initial setup (password change) is required
    SetupStatus,
}

#[derive(Subcommand)]
pub enum TokenCommand {
    /// Create a new API token
    Create {
        /// Token name/description
        #[arg(long)]
        description: Option<String>,

        /// Expiration in days
        #[arg(long, default_value = "90")]
        expires_in: u32,

        /// Scope to grant (repeatable, or comma-separated). Defaults to `*`, all of
        /// your own access
        #[arg(long = "scope", value_delimiter = ',')]
        scopes: Vec<String>,

        /// Restrict the token to the repositories this selector matches: JSON text,
        /// @file or @-. It only ever narrows your own access
        #[arg(long)]
        repo_selector: Option<String>,
    },

    /// List active API tokens
    List,
}

impl AuthCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Login(args) => {
                if args.oidc_device {
                    login_with_device(args.url.as_deref(), &args.scope, global).await
                } else {
                    login(&args, global).await
                }
            }
            Self::Logout { instance } => logout(instance.as_deref(), global).await,
            Self::Token { command } => match command {
                TokenCommand::Create {
                    description,
                    expires_in,
                    scopes,
                    repo_selector,
                } => {
                    let repo_selector = repo_selector
                        .map(|value| parse_json_arg(&value, "--repo-selector"))
                        .transpose()?;
                    // 1.10.2 honours a selector. 1.10.1 drops it and makes a token with
                    // all of your access, which is the opposite of what was asked.
                    if repo_selector.is_some()
                        && let Some(version) =
                            guard_flags("--repo-selector", (1, 10, 2), global).await
                    {
                        return Err(AkError::ServerError(format!(
                            "--repo-selector needs a server on 1.10.2 or newer. This one is \
                             {version}, which would ignore it and make a token with all of \
                             your access. Nothing was changed."
                        ))
                        .into());
                    }
                    token_create(
                        description.as_deref(),
                        expires_in,
                        scopes,
                        repo_selector,
                        global,
                    )
                    .await
                }
                TokenCommand::List => token_list(global).await,
            },
            Self::Whoami => whoami(global).await,
            Self::Refresh { instance } => refresh(instance.as_deref(), global).await,
            Self::RevokeToken { id } => revoke_token(&id, global).await,
            Self::VerifyTotp {
                code,
                code_stdin,
                totp_token,
                totp_token_stdin,
            } => {
                let totp_token = require_secret(
                    resolve_secret(
                        totp_token,
                        totp_token_stdin,
                        "--totp-token",
                        None,
                        global.no_input,
                    )?,
                    "The one-time TOTP ticket",
                    "--totp-token-stdin or AK_TOTP_TOKEN",
                )?;
                let code = totp_code(code, code_stdin, "--code", "--code-stdin", global)?;
                verify_totp(&code, &totp_token, global).await
            }
            Self::SsoExchange { code, code_stdin } => {
                let code = require_secret(
                    resolve_secret(
                        code,
                        code_stdin,
                        "--code",
                        Some("Exchange code"),
                        global.no_input,
                    )?,
                    "The exchange code",
                    "--code-stdin or AK_SSO_CODE",
                )?;
                sso_exchange(&code, global).await
            }
            Self::DownloadTicket {
                resource_path,
                purpose,
            } => download_ticket(&resource_path, &purpose, global).await,
            Self::CiExchange {
                provider_id,
                jwt,
                jwt_stdin,
            } => {
                // Resolve the JWT off the command line: --jwt-stdin / piped
                // stdin / AK_CI_JWT / no-echo prompt on a TTY.
                let jwt =
                    resolve_secret(jwt, jwt_stdin, "--jwt", Some("OIDC JWT"), global.no_input)?;
                ci_exchange(&provider_id, jwt.as_deref(), global).await
            }
            Self::SetupStatus => setup_status(global).await,
        }
    }
}

/// Resolve the instance named by `--url` (if given) or the configured
/// default/`--instance`. Shared by the password, token and device login paths.
fn resolve_login_instance(
    url: Option<&str>,
    global: &GlobalArgs,
) -> Result<(String, InstanceConfig)> {
    let config = AppConfig::load()?;
    if let Some(url) = url {
        let (name, instance) = config
            .instances
            .iter()
            .find(|(_, instance)| instance.url == url)
            .ok_or_else(|| {
                AkError::ConfigError(format!(
                    "No instance configured with URL '{url}'. Run `ak instance add <name> {url}` first."
                ))
            })?;
        return Ok((name.to_string(), instance.clone()));
    }
    let (name, instance) = config.resolve_instance(global.instance.as_deref())?;
    Ok((name.to_string(), instance.clone()))
}

async fn login(args: &LoginArgs, global: &GlobalArgs) -> Result<()> {
    let (instance_name, instance) = resolve_login_instance(args.url.as_deref(), global)?;

    if let Some(sso) = &args.sso {
        return match parse_sso(sso)? {
            (SsoKind::Ldap, id) => {
                login_with_ldap(&instance_name, &instance, id, args, global).await
            }
            (kind, id) => {
                login_with_browser(&instance_name, &instance, kind, id, args, global).await
            }
        };
    }
    if args.token_stdin {
        let token = require_secret(
            resolve_secret(None, true, "--token", None, global.no_input)?,
            "The token",
            "--token-stdin",
        )?;
        return store_token(&instance_name, &instance, token).await;
    }
    if args.username.is_some() {
        return login_with_password(&instance_name, &instance, args, global).await;
    }

    if global.no_input {
        let hint = if args.token {
            "Cannot prompt for token in non-interactive mode. Use `--token-stdin` or set AK_TOKEN."
        } else {
            "Cannot prompt for credentials in non-interactive mode. Use `--username` with \
             `--password-stdin`, `--token-stdin`, or set AK_TOKEN."
        };
        return Err(AkError::ConfigError(hint.into()).into());
    }

    // If --token flag was explicitly passed, go straight to token flow
    if args.token {
        return login_with_token(&instance_name, &instance).await;
    }

    // Interactive: let user choose how to authenticate
    eprintln!("Logging in to '{}' ({})\n", instance_name, instance.url);

    // Surface the cleartext risk before the user types anything.
    transport::warn_if_insecure(&instance_name, &instance);

    let methods = &[
        "Login with username and password",
        "Paste an authentication token",
    ];
    let selection = dialoguer::Select::new()
        .with_prompt("How would you like to authenticate?")
        .items(methods)
        .default(0)
        .interact()
        .into_diagnostic()?;

    match selection {
        0 => login_with_password(&instance_name, &instance, args, global).await,
        1 => login_with_token(&instance_name, &instance).await,
        _ => unreachable!(),
    }
}

/// Sign in with the server's RFC 8628 device authorization grant.
///
/// `--no-input` is not an error here: the flow never prompts. It prints the
/// verification URL and user code, and the user approves on a second device.
async fn login_with_device(
    url: Option<&str>,
    scopes: &[String],
    global: &GlobalArgs,
) -> Result<()> {
    let (instance_name, instance) = resolve_login_instance(url, global)?;
    crate::commands::device_flow::login(&instance_name, &instance, scopes, global).await
}

async fn login_with_token(instance_name: &str, instance: &InstanceConfig) -> Result<()> {
    eprintln!(
        "Paste your API token for '{instance_name}' ({}):",
        instance.url
    );
    let token = dialoguer::Password::new()
        .with_prompt("Token")
        .interact()
        .into_diagnostic()?;
    store_token(instance_name, instance, token).await
}

/// Check a token with the server, and keep it only if the server takes it.
async fn store_token(instance_name: &str, instance: &InstanceConfig, token: String) -> Result<()> {
    let cred = StoredCredential {
        access_token: token.trim().to_string(),
        refresh_token: None,
    };

    let client = build_client(instance_name, instance, Some(&cred))?;
    let resp = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("Token validation failed: {e}")))?;

    store_credential(instance_name, &cred)?;
    eprintln!(
        "Logged in to '{instance_name}' as {} ({})",
        resp.username, resp.email
    );
    Ok(())
}

/// A password sent over plaintext HTTP to a non-loopback host is readable by any
/// on-path observer. Refuse unless the user explicitly opted in (`ak instance add
/// --insecure-http` or AK_ALLOW_INSECURE_HTTP=1). Loopback (localhost/127.0.0.1/::1)
/// is exempt: plain HTTP is the normal local development setup.
fn refuse_cleartext_password(instance: &InstanceConfig) -> Result<()> {
    if transport::classify_url(&instance.url) == transport::TransportSecurity::HttpRemote
        && !transport::insecure_http_allowed(instance)
    {
        return Err(AkError::InsecureTransport(instance.url.clone()).into());
    }
    Ok(())
}

/// The username and password for a login, from the flags or by asking.
fn login_credentials(args: &LoginArgs, global: &GlobalArgs) -> Result<(String, String)> {
    let username = match &args.username {
        Some(username) => username.clone(),
        None if global.no_input => {
            return Err(AkError::ConfigError(
                "Cannot prompt for a username in non-interactive mode. Use `--username` with \
                 `--password-stdin`."
                    .into(),
            )
            .into());
        }
        None => dialoguer::Input::new()
            .with_prompt("Username")
            .interact_text()
            .into_diagnostic()?,
    };
    let password = require_secret(
        resolve_secret(
            None,
            args.password_stdin,
            "--password",
            Some("Password"),
            global.no_input,
        )?,
        "The password",
        "--password-stdin",
    )?;
    Ok((username, password))
}

async fn login_with_password(
    instance_name: &str,
    instance: &InstanceConfig,
    args: &LoginArgs,
    global: &GlobalArgs,
) -> Result<()> {
    refuse_cleartext_password(instance)?;
    let (username, password) = login_credentials(args, global)?;

    let anon_client = anon_client(&instance.url)?;

    let body = artifact_keeper_sdk::types::LoginRequest {
        username: username.clone(),
        password,
    };

    let resp = anon_client
        .login()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("Login failed: {e}")))?
        .into_inner();

    // A server that wants a TOTP step first sends empty tokens, which must never be
    // stored as a session.
    if let Some(ticket) = resp.totp_token.as_deref() {
        if resp.totp_enrollment_required == Some(true) {
            return enroll_during_login(instance_name, instance, ticket, args, global).await;
        }
        if resp.totp_required == Some(true) {
            return challenge_during_login(instance_name, instance, ticket, args, global).await;
        }
    }
    if resp.access_token.is_empty() {
        return Err(AkError::NotAuthenticated(
            "The server accepted the password but sent no session. Check `ak doctor`.".into(),
        )
        .into());
    }

    store_session(
        instance_name,
        resp.access_token,
        resp.refresh_token,
        resp.must_change_password,
    )?;
    eprintln!("Logged in to '{instance_name}' as {username}");
    Ok(())
}

/// Keep a new session and say what the user must do about it. The tokens are never
/// printed: to get one for a script, create an API token.
fn store_session(
    instance_name: &str,
    access_token: String,
    refresh_token: String,
    must_change_password: bool,
) -> Result<()> {
    // Empty tokens can arrive with a 200, such as when another step is needed first.
    // Stored, they'd read as logged in, and every command would then get a 401.
    if access_token.trim().is_empty() {
        return Err(AkError::NotAuthenticated(
            "The server accepted the login but sent no session token. Check `ak doctor`.".into(),
        )
        .into());
    }
    let cred = StoredCredential {
        access_token,
        refresh_token: Some(refresh_token),
    };
    store_credential(instance_name, &cred)?;
    if must_change_password {
        eprintln!("Warning: You must change your password. Run `ak profile change-password`.");
    }
    Ok(())
}

/// A TOTP code from the flag, stdin or a prompt that doesn't echo it.
fn totp_code(
    value: Option<String>,
    from_stdin: bool,
    flag: &str,
    stdin_flag: &str,
    global: &GlobalArgs,
) -> Result<String> {
    require_secret(
        resolve_secret(value, from_stdin, flag, Some("TOTP code"), global.no_input)?,
        "The TOTP code",
        stdin_flag,
    )
}

/// Print a one-time ticket for the user to finish the login with, if they asked.
fn ticket_requested(ticket: &str, next: &str, args: &LoginArgs) -> bool {
    if args.print_totp_ticket {
        println!("{ticket}");
        eprintln!("Not logged in yet. Finish with `{next}`.");
    }
    args.print_totp_ticket
}

async fn challenge_during_login(
    instance_name: &str,
    instance: &InstanceConfig,
    ticket: &str,
    args: &LoginArgs,
    global: &GlobalArgs,
) -> Result<()> {
    if ticket_requested(ticket, "ak auth verify-totp --totp-token-stdin", args) {
        return Ok(());
    }
    let code = totp_code(
        args.totp_code.clone(),
        args.totp_code_stdin,
        "--totp-code",
        "--totp-code-stdin, AK_TOTP_CODE or --print-totp-ticket",
        global,
    )?;
    complete_totp(instance_name, instance, &code, ticket).await
}

/// The server's policy wants this user on TOTP before it gives them a session.
async fn enroll_during_login(
    instance_name: &str,
    instance: &InstanceConfig,
    ticket: &str,
    args: &LoginArgs,
    global: &GlobalArgs,
) -> Result<()> {
    if ticket_requested(ticket, "ak totp enroll setup --totp-token-stdin", args) {
        return Ok(());
    }
    if global.no_input {
        return Err(AkError::ConfigError(
            "This server requires you to set up TOTP before logging in. Use \
             --print-totp-ticket and `ak totp enroll`, or run this at a terminal."
                .into(),
        )
        .into());
    }
    let client = anon_client(&instance.url)?;
    eprintln!("This server requires two-factor login, so set it up now.");
    let setup = super::totp::enroll_setup_request(&client, ticket).await?;
    eprintln!(
        "TOTP secret:  {}\nQR code URL:  {}\n",
        setup.secret, setup.qr_code_url
    );
    let code = totp_code(
        args.totp_code.clone(),
        args.totp_code_stdin,
        "--totp-code",
        "--totp-code-stdin or AK_TOTP_CODE",
        global,
    )?;
    let done = super::totp::enroll_complete_request(&client, ticket, &code).await?;
    store_session(
        instance_name,
        done.access_token.clone(),
        done.refresh_token.clone(),
        done.must_change_password,
    )?;
    eprintln!("Two-factor login is on, and you're logged in to '{instance_name}'.");
    eprintln!("Backup codes (save these somewhere safe; each works once):");
    for code in &done.backup_codes {
        eprintln!("  {code}");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SsoKind {
    Ldap,
    Oidc,
    Saml,
}

impl SsoKind {
    fn route(self) -> &'static str {
        match self {
            Self::Ldap => "ldap",
            Self::Oidc => "oidc",
            Self::Saml => "saml",
        }
    }
}

fn parse_sso(value: &str) -> Result<(SsoKind, uuid::Uuid)> {
    let wrong = || {
        AkError::ConfigError(format!(
            "--sso: '{value}' isn't `ldap:<id>`, `oidc:<id>` or `saml:<id>`. Run `ak sso \
             providers` to see them."
        ))
    };
    let (kind, id) = value.split_once(':').ok_or_else(wrong)?;
    let kind = match kind {
        "ldap" => SsoKind::Ldap,
        "oidc" => SsoKind::Oidc,
        "saml" => SsoKind::Saml,
        _ => return Err(wrong().into()),
    };
    Ok((kind, parse_uuid(id, "SSO provider")?))
}

/// What `POST /auth/sso/ldap/{id}/login` sends back. The spec gives this response no
/// schema, so the SDK can't return it.
#[derive(serde::Deserialize)]
struct LdapSession {
    access_token: String,
    refresh_token: String,
}

async fn login_with_ldap(
    instance_name: &str,
    instance: &InstanceConfig,
    provider: uuid::Uuid,
    args: &LoginArgs,
    global: &GlobalArgs,
) -> Result<()> {
    refuse_cleartext_password(instance)?;
    let (username, password) = login_credentials(args, global)?;

    // Not the SDK, which drops this route's response. The body holds a password, and a
    // 307 would resend it wherever it points.
    let builder = super::client::raw_http_client_builder(reqwest::redirect::Policy::none());
    let http = transport::apply_custom_ca(builder)?
        .build()
        .into_diagnostic()?;
    let url = format!(
        "{}/api/v1/auth/sso/ldap/{provider}/login",
        instance.url.trim_end_matches('/')
    );
    let resp = http
        .post(&url)
        .timeout(std::time::Duration::from_secs(30))
        .json(&artifact_keeper_sdk::types::LdapLoginRequest {
            username: username.clone(),
            password,
        })
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("LDAP login failed: {e}")))?;
    let status = resp.status();
    let bytes = resp.bytes().await.into_diagnostic()?;
    if !status.is_success() {
        let body = String::from_utf8_lossy(&bytes);
        return Err(raw_err("LDAP login failed", status, &body).into());
    }
    let session: LdapSession = serde_json::from_slice(&bytes)
        .map_err(|_| AkError::NotAuthenticated("LDAP login: the server sent no session".into()))?;
    store_session(
        instance_name,
        session.access_token,
        session.refresh_token,
        false,
    )?;
    eprintln!("Logged in to '{instance_name}' as {username}");
    Ok(())
}

/// Where the server sends a browser to sign in with this provider. It answers with
/// a redirect, which here is the answer rather than something to follow.
async fn sso_login_url(
    instance: &InstanceConfig,
    kind: SsoKind,
    provider: uuid::Uuid,
    prompt: Option<&str>,
) -> Result<String> {
    let builder = super::client::raw_http_client_builder(reqwest::redirect::Policy::none());
    let http = transport::apply_custom_ca(builder)?
        .build()
        .into_diagnostic()?;
    let url = format!(
        "{}/api/v1/auth/sso/{}/{provider}/login",
        instance.url.trim_end_matches('/'),
        kind.route()
    );
    let mut req = http.get(&url).timeout(std::time::Duration::from_secs(30));
    if let Some(prompt) = prompt {
        req = req.query(&[("prompt", prompt)]);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("start the SSO login", e))?;
    let status = resp.status();
    if !status.is_redirection() {
        let body = resp.text().await.unwrap_or_default();
        return Err(raw_err("Failed to start the SSO login", status, &body).into());
    }
    resp.headers()
        .get(reqwest::header::LOCATION)
        .and_then(|location| location.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| {
            AkError::ServerError(format!(
                "Failed to start the SSO login: {status} with no Location"
            ))
            .into()
        })
}

async fn login_with_browser(
    instance_name: &str,
    instance: &InstanceConfig,
    kind: SsoKind,
    provider: uuid::Uuid,
    args: &LoginArgs,
    global: &GlobalArgs,
) -> Result<()> {
    if kind == SsoKind::Saml && args.prompt.is_some() {
        return Err(AkError::ConfigError("--prompt is for OIDC only.".into()).into());
    }
    let login_url = sso_login_url(instance, kind, provider, args.prompt.as_deref()).await?;
    let info = serde_json::json!({
        "login_url": login_url,
        "provider_type": kind.route(),
        "provider_id": provider,
    });
    match global.format {
        OutputFormat::Quiet => println!("{login_url}"),
        OutputFormat::Json | OutputFormat::Yaml => {
            println!("{}", output::render(&info, &global.format, None));
        }
        OutputFormat::Table => {
            eprintln!("Open this URL in a browser and sign in:\n\n{login_url}\n")
        }
    }

    let at_terminal = std::io::IsTerminal::is_terminal(&std::io::stdin());
    if global.no_input || !at_terminal {
        eprintln!(
            "It ends at a URL with a `code`. Finish with `ak auth sso-exchange --code-stdin`."
        );
        return Ok(());
    }
    eprintln!("It ends at a URL with a `code`. Paste that URL or the code here.");
    let code = dialoguer::Password::new()
        .with_prompt("Code")
        .interact()
        .map_err(|e| super::helpers::prompt_err("Failed to read the code", e))?;
    exchange_and_store(instance_name, instance, &code).await
}

/// The code in a callback URL, or the value itself if it isn't a URL with one.
fn exchange_code_from(value: &str) -> String {
    let value = value.trim();
    reqwest::Url::parse(value)
        .ok()
        .and_then(|url| {
            url.query_pairs()
                .find(|(name, _)| name == "code")
                .map(|(_, code)| code.into_owned())
        })
        .or_else(|| {
            let query = value.split_once('?')?.1;
            let (_, code) = query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(name, _)| *name == "code")?;
            Some(code.to_string())
        })
        .unwrap_or_else(|| value.to_string())
}

async fn exchange_and_store(
    instance_name: &str,
    instance: &InstanceConfig,
    code: &str,
) -> Result<()> {
    let client = anon_client(&instance.url)?;
    let body = artifact_keeper_sdk::types::ExchangeCodeRequest {
        code: exchange_code_from(code),
    };
    let resp = client
        .exchange_code()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("SSO exchange failed: {e}")))?
        .into_inner();
    store_session(instance_name, resp.access_token, resp.refresh_token, false)?;
    eprintln!("Logged in to '{instance_name}'.");
    Ok(())
}

async fn sso_exchange(code: &str, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (instance_name, instance) = config.resolve_instance(global.instance.as_deref())?;
    exchange_and_store(instance_name, instance, code).await
}

async fn logout(instance: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (instance_name, instance_cfg) =
        config.resolve_instance(instance.or(global.instance.as_deref()))?;
    let instance_name = instance_name.to_string();

    // Best-effort server-side session invalidation. Never block a local logout
    // on it — if the token is already invalid or the server is unreachable we
    // still want to clear the local credential.
    if let Ok(cred) = get_credential(&instance_name)
        && let Ok(client) = build_client(&instance_name, instance_cfg, Some(&cred))
    {
        let body = artifact_keeper_sdk::types::RefreshTokenRequest {
            refresh_token: cred.refresh_token.clone(),
        };
        if let Err(e) = client.logout().body(body).send().await {
            eprintln!(
                "Warning: server-side logout failed ({e}); clearing local credentials anyway."
            );
        }
    }

    delete_credential(&instance_name)?;
    eprintln!("Logged out from '{instance_name}'.");
    Ok(())
}

async fn refresh(instance: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (instance_name, instance_cfg) =
        config.resolve_instance(instance.or(global.instance.as_deref()))?;
    let instance_name = instance_name.to_string();

    let cred = get_credential(&instance_name)?;
    let refresh_token = cred.refresh_token.clone().ok_or_else(|| {
        AkError::NotAuthenticated(format!(
            "No refresh token stored for '{instance_name}'. Log in with username/password \
             (`ak auth login`) to obtain one."
        ))
    })?;

    let client = build_client(&instance_name, instance_cfg, Some(&cred))?;
    let body = artifact_keeper_sdk::types::RefreshTokenRequest {
        refresh_token: Some(refresh_token),
    };

    let resp = client
        .refresh_token()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("Token refresh failed: {e}")))?;

    if resp.access_token.trim().is_empty() {
        return Err(AkError::NotAuthenticated(
            "The server refreshed the session but sent no token. Your stored login is unchanged."
                .into(),
        )
        .into());
    }

    let new_cred = StoredCredential {
        access_token: resp.access_token.clone(),
        refresh_token: Some(resp.refresh_token.clone()),
    };
    store_credential(&instance_name, &new_cred)?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.access_token);
        return Ok(());
    }

    // Not the server's body: it holds the new tokens, which were just stored. `--format
    // quiet` is the one way to ask for the token itself.
    let info = serde_json::json!({
        "instance": instance_name,
        "expires_in": resp.expires_in,
        "token_type": resp.token_type,
    });

    let table_str = format!(
        "Access token refreshed for '{instance_name}'.\n\
         Expires in: {} seconds\n\
         Token type: {}",
        resp.expires_in, resp.token_type,
    );

    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

async fn revoke_token(id: &str, global: &GlobalArgs) -> Result<()> {
    let token_id = parse_uuid(id, "token")?;

    let client = client_for(global)?;
    client
        .revoke_api_token()
        .token_id(token_id)
        .send()
        .await
        .map_err(|e| sdk_err("revoke API token", e))?;

    eprintln!("API token {id} revoked.");
    Ok(())
}

async fn verify_totp(code: &str, totp_token: &str, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (instance_name, instance_cfg) = config.resolve_instance(global.instance.as_deref())?;
    complete_totp(instance_name, instance_cfg, code, totp_token).await
}

/// Trade a TOTP code and its login ticket for a session, and keep it.
async fn complete_totp(
    instance_name: &str,
    instance: &InstanceConfig,
    code: &str,
    totp_token: &str,
) -> Result<()> {
    let anon_client = anon_client(&instance.url)?;
    let body = artifact_keeper_sdk::types::TotpVerifyRequest {
        code: code.to_string(),
        totp_token: totp_token.to_string(),
    };

    let resp = anon_client
        .verify_totp()
        .body(body)
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("TOTP verification failed: {e}")))?
        .into_inner();

    store_session(
        instance_name,
        resp.access_token,
        resp.refresh_token,
        resp.must_change_password,
    )?;
    eprintln!("Two-factor verification succeeded; logged in to '{instance_name}'.");
    Ok(())
}

async fn download_ticket(resource_path: &str, purpose: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let body = artifact_keeper_sdk::types::CreateTicketRequest {
        purpose: purpose.to_string(),
        resource_path: Some(resource_path.to_string()),
    };

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.create_download_ticket().body(body).send()).await;
    let resp = resp.map_err(|e| sdk_err("create download ticket", e))?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.ticket);
        return Ok(());
    }

    let info = serde_json::json!({
        "ticket": resp.ticket,
        "expires_in": resp.expires_in,
        "resource_path": resource_path,
    });

    let table_str = format!(
        "Download ticket created (single-use, expires in {} seconds):\n\
         {}\n\n\
         Note: this value grants access to '{}'. Consume it immediately and never log \
         or share the URL that contains it.",
        resp.expires_in, resp.ticket, resource_path,
    );

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );
    Ok(())
}

async fn ci_exchange(provider_id: &str, jwt: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let provider = parse_uuid(provider_id, "provider")?;
    let jwt = jwt.ok_or_else(|| {
        AkError::ConfigError(
            "No OIDC JWT provided. Pipe it to --jwt-stdin, set AK_CI_JWT, or pass --jwt <token>."
                .into(),
        )
    })?;

    let config = AppConfig::load()?;
    let (instance_name, instance_cfg) = config.resolve_instance(global.instance.as_deref())?;
    let instance_name = instance_name.to_string();

    // The CI-issued JWT must be presented as the Bearer token on the exchange request.
    let jwt_cred = StoredCredential {
        access_token: jwt.to_string(),
        refresh_token: None,
    };
    let client = build_client(&instance_name, instance_cfg, Some(&jwt_cred))?;

    let body = artifact_keeper_sdk::types::CiTokenRequest {
        provider_id: Some(provider),
    };

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.exchange_ci_token().body(body).send()).await;
    let resp =
        resp.map_err(|e| AkError::NotAuthenticated(format!("CI token exchange failed: {e}")))?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.access_token);
        return Ok(());
    }

    let info = serde_json::json!({
        "access_token": resp.access_token,
        "token_type": resp.token_type,
        "expires_in": resp.expires_in,
        "username": resp.username,
    });

    let table_str = format!(
        "Exchanged CI OIDC token for an access token (user: {}).\n\
         Token type:   {}\n\
         Expires in:   {} seconds\n\
         Access token: {}",
        resp.username, resp.token_type, resp.expires_in, resp.access_token,
    );

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );
    Ok(())
}

async fn setup_status(global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (_instance_name, instance_cfg) = config.resolve_instance(global.instance.as_deref())?;

    // Setup status is a pre-auth endpoint; no credentials required.
    let client = anon_client(&instance_cfg.url)?;

    let (resp, raw) = artifact_keeper_sdk::raw::capture(client.setup_status().send()).await;
    let resp = resp.map_err(|e| sdk_err("get setup status", e))?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.setup_required);
        return Ok(());
    }

    let info = serde_json::json!({
        "setup_required": resp.setup_required,
    });

    let table_str = format!(
        "Initial setup required: {}",
        if resp.setup_required { "yes" } else { "no" },
    );

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );
    Ok(())
}

async fn whoami(global: &GlobalArgs) -> Result<()> {
    let (instance_name, instance, client) = authenticated_client(global)?;

    let (user, raw) = artifact_keeper_sdk::raw::capture(client.get_current_user().send()).await;
    let user =
        user.map_err(|e| AkError::NotAuthenticated(format!("Failed to get user info: {e}")))?;

    let info = serde_json::json!({
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "admin": user.is_admin,
        "totp_enabled": user.totp_enabled,
        "instance": instance_name,
        "url": instance.url,
    });

    let table_str = format!(
        "Username:     {}\n\
         Email:        {}\n\
         Display Name: {}\n\
         Admin:        {}\n\
         TOTP:         {}\n\
         Instance:     {} ({})",
        user.username,
        user.email,
        user.display_name.as_deref().unwrap_or("-"),
        if user.is_admin { "yes" } else { "no" },
        if user.totp_enabled {
            "enabled"
        } else {
            "disabled"
        },
        instance_name,
        instance.url,
    );

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn token_create(
    description: Option<&str>,
    expires_in: u32,
    scopes: Vec<String>,
    repo_selector: Option<serde_json::Map<String, serde_json::Value>>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;

    let default_name = format!("ak-cli-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let name = match description {
        Some(desc) => desc.to_string(),
        None if global.no_input => default_name,
        None => dialoguer::Input::new()
            .with_prompt("Token name")
            .default(default_name)
            .interact_text()
            .into_diagnostic()?,
    };

    let body = artifact_keeper_sdk::types::CreateApiTokenRequest {
        name,
        scopes: if scopes.is_empty() {
            vec!["*".to_string()]
        } else {
            scopes
        },
        expires_in_days: Some(i64::from(expires_in)),
        repo_selector,
    };

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.create_api_token().body(body).send()).await;
    let resp = resp.map_err(|e| AkError::ServerError(format!("Failed to create token: {e}")))?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", resp.token);
        return Ok(());
    }

    let info = serde_json::json!({
        "id": resp.id.to_string(),
        "name": resp.name,
        "token": resp.token,
    });

    let table_str = format!(
        "Token created successfully!\n\n\
         ID:    {}\n\
         Name:  {}\n\
         Token: {}\n\n\
         Save this token — it won't be shown again.",
        resp.id, resp.name, resp.token,
    );

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

fn format_optional_date(date: Option<chrono::DateTime<chrono::Utc>>, fmt: &str) -> String {
    date.map(|d| d.format(fmt).to_string())
        .unwrap_or_else(|| "never".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- format_optional_date ----

    #[test]
    fn format_optional_date_none() {
        let result = format_optional_date(None, "%Y-%m-%d");
        assert_eq!(result, "never");
    }

    #[test]
    fn format_optional_date_some() {
        use chrono::TimeZone;
        let date = chrono::Utc
            .with_ymd_and_hms(2026, 1, 15, 12, 30, 0)
            .unwrap();
        let result = format_optional_date(Some(date), "%Y-%m-%d");
        assert_eq!(result, "2026-01-15");
    }

    #[test]
    fn format_optional_date_rfc3339() {
        use chrono::TimeZone;
        let date = chrono::Utc
            .with_ymd_and_hms(2026, 1, 15, 12, 30, 0)
            .unwrap();
        let result = format_optional_date(Some(date), "%+");
        assert!(result.contains("2026-01-15"));
    }

    // ---- wiremock handler tests ----

    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, ResponseTemplate};

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    fn user_json() -> serde_json::Value {
        serde_json::json!({
            "id": NIL_UUID,
            "username": "alice",
            "email": "alice@example.com",
            "display_name": "Alice",
            "is_admin": false,
            "totp_enabled": false,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    #[tokio::test]
    async fn handler_whoami_json() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = whoami(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_create_json() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "name": "ak-cli-test",
                "token": "ak_test_abcdef1234567890",
                "token_prefix": "ak_test_",
                "scopes": ["*"],
                "created_at": "2026-01-15T12:00:00Z",
                "expires_at": "2026-04-15T12:00:00Z",
                "policy_applied": false
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = token_create(Some("test token"), 90, Vec::new(), None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_create_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "name": "ak-cli-test",
                "token": "ak_test_abcdef1234567890",
                "token_prefix": "ak_test_",
                "scopes": ["*"],
                "created_at": "2026-01-15T12:00:00Z",
                "expires_at": "2026-04-15T12:00:00Z",
                "policy_applied": false
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = token_create(Some("test token"), 90, Vec::new(), None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_list_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        // token_list calls get_current_user first, then list_user_tokens
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/users/{NIL_UUID}/tokens")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": []
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = token_list(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_list_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/users/{NIL_UUID}/tokens")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{
                    "id": NIL_UUID,
                    "name": "my-token",
                    "token_prefix": "ak_xxxx_",
                    "scopes": ["*"],
                    "created_at": "2026-01-15T12:00:00Z",
                    "expires_at": "2026-04-15T12:00:00Z",
                    "last_used_at": null
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = token_list(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_token_list_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/api/v1/users/{NIL_UUID}/tokens")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [{
                    "id": NIL_UUID,
                    "name": "my-token",
                    "token_prefix": "ak_xxxx_",
                    "scopes": ["*"],
                    "created_at": "2026-01-15T12:00:00Z",
                    "expires_at": null,
                    "last_used_at": null
                }]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = token_list(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_login_no_input_returns_error() {
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Json);
        // no_input=true should produce an error for login
        let AuthCommand::Login(args) = parse_auth(&["auth", "login"]) else {
            panic!("expected Login");
        };
        let result = login(&args, &global).await;
        assert!(result.is_err());
        crate::test_utils::teardown_env();
    }

    // ---- parsing tests for new subcommands ----

    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: AuthCommand,
    }

    fn parse_auth(args: &[&str]) -> AuthCommand {
        TestCli::try_parse_from(args).unwrap().command
    }

    #[test]
    fn parse_refresh_default() {
        match parse_auth(&["auth", "refresh"]) {
            AuthCommand::Refresh { instance } => assert!(instance.is_none()),
            _ => panic!("expected Refresh"),
        }
    }

    #[test]
    fn parse_login_oidc_device() {
        match parse_auth(&["auth", "login", "--oidc-device"]) {
            AuthCommand::Login(args) => {
                assert!(args.oidc_device);
                assert!(!args.token);
                assert!(args.scope.is_empty());
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn parse_login_device_alias() {
        match parse_auth(&["auth", "login", "--device"]) {
            AuthCommand::Login(args) => assert!(args.oidc_device),
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn parse_login_device_scopes() {
        match parse_auth(&[
            "auth",
            "login",
            "--oidc-device",
            "--scope",
            "read:artifacts,write:artifacts",
            "--scope",
            "delete:artifacts",
        ]) {
            AuthCommand::Login(args) => {
                assert!(args.oidc_device);
                assert_eq!(
                    args.scope,
                    vec!["read:artifacts", "write:artifacts", "delete:artifacts"]
                );
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn parse_login_token_and_device_conflict() {
        assert!(TestCli::try_parse_from(["auth", "login", "--token", "--oidc-device"]).is_err());
    }

    #[test]
    fn parse_login_scope_requires_device() {
        assert!(TestCli::try_parse_from(["auth", "login", "--scope", "read:artifacts"]).is_err());
    }

    #[test]
    fn parse_revoke_token() {
        match parse_auth(&["auth", "revoke-token", "abc-123"]) {
            AuthCommand::RevokeToken { id } => assert_eq!(id, "abc-123"),
            _ => panic!("expected RevokeToken"),
        }
    }

    #[test]
    fn parse_revoke_token_missing_id() {
        assert!(TestCli::try_parse_from(["auth", "revoke-token"]).is_err());
    }

    #[test]
    fn parse_verify_totp() {
        match parse_auth(&["auth", "verify-totp", "123456", "--totp-token", "tok"]) {
            AuthCommand::VerifyTotp {
                code, totp_token, ..
            } => {
                assert_eq!(code.as_deref(), Some("123456"));
                assert_eq!(totp_token.as_deref(), Some("tok"));
            }
            _ => panic!("expected VerifyTotp"),
        }
    }

    #[test]
    fn verify_totp_can_read_either_secret_from_stdin_but_not_both() {
        assert!(
            TestCli::try_parse_from(["auth", "verify-totp", "--code-stdin", "--totp-token-stdin"])
                .is_err()
        );
    }

    #[test]
    fn sso_login_names_a_type_and_a_provider() {
        let id = "00000000-0000-0000-0000-000000000001";
        assert_eq!(parse_sso(&format!("ldap:{id}")).unwrap().0, SsoKind::Ldap);
        assert_eq!(parse_sso(&format!("oidc:{id}")).unwrap().0, SsoKind::Oidc);
        assert_eq!(parse_sso(&format!("saml:{id}")).unwrap().0, SsoKind::Saml);
        assert!(parse_sso(id).is_err());
        assert!(parse_sso(&format!("github:{id}")).is_err());
        assert!(parse_sso("ldap:corp").is_err());
    }

    #[test]
    fn parse_download_ticket_default_purpose() {
        match parse_auth(&["auth", "download-ticket", "npm-local/left-pad/1.0.0"]) {
            AuthCommand::DownloadTicket {
                resource_path,
                purpose,
            } => {
                assert_eq!(resource_path, "npm-local/left-pad/1.0.0");
                assert_eq!(purpose, "download");
            }
            _ => panic!("expected DownloadTicket"),
        }
    }

    #[test]
    fn parse_ci_exchange() {
        match parse_auth(&[
            "auth",
            "ci-exchange",
            "--provider-id",
            "00000000-0000-0000-0000-000000000000",
            "--jwt",
            "ey.jwt.here",
        ]) {
            AuthCommand::CiExchange {
                provider_id,
                jwt,
                jwt_stdin,
            } => {
                assert_eq!(provider_id, "00000000-0000-0000-0000-000000000000");
                assert_eq!(jwt.as_deref(), Some("ey.jwt.here"));
                assert!(!jwt_stdin);
            }
            _ => panic!("expected CiExchange"),
        }
    }

    #[test]
    fn parse_ci_exchange_jwt_stdin() {
        match parse_auth(&[
            "auth",
            "ci-exchange",
            "--provider-id",
            "00000000-0000-0000-0000-000000000000",
            "--jwt-stdin",
        ]) {
            AuthCommand::CiExchange { jwt_stdin, .. } => {
                assert!(jwt_stdin);
            }
            _ => panic!("expected CiExchange"),
        }
    }

    #[test]
    fn parse_setup_status() {
        assert!(matches!(
            parse_auth(&["auth", "setup-status"]),
            AuthCommand::SetupStatus
        ));
    }

    // ---- wiremock handler tests for new operations ----

    fn login_response_json() -> serde_json::Value {
        serde_json::json!({
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "must_change_password": false
        })
    }

    #[tokio::test]
    async fn handler_logout_calls_server_then_clears() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/logout"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = logout(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_logout_succeeds_when_server_errors() {
        // No mock mounted for /logout -> server returns 404; logout must still succeed.
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = logout(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_refresh_no_token_errors() {
        // setup_env sets AK_TOKEN (access only, no refresh) -> refresh must error.
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = refresh(None, &global).await;
        assert!(result.is_err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_refresh_happy_path() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        // Drop AK_TOKEN so the stored file credential (with a refresh token) is used.
        unsafe { std::env::remove_var("AK_TOKEN") };
        // A keyring entry left by another test would win over the file below.
        delete_credential("test").expect("clear test credential");
        let cred = serde_json::json!({
            "access_token": "old_access",
            "refresh_token": "old_refresh"
        })
        .to_string();
        let mut all = std::collections::HashMap::new();
        all.insert("test".to_string(), cred);
        std::fs::write(
            tmp.path().join("credentials.json"),
            serde_json::to_string(&all).unwrap(),
        )
        .unwrap();

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/refresh"))
            // A device-login credential has exactly this shape: an access
            // token plus the refresh token the grant returned.
            .and(body_string_contains("old_refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(login_response_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = refresh(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_revoke_token() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/auth/tokens/{NIL_UUID}")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = revoke_token(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_revoke_token_bad_uuid() {
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = revoke_token("not-a-uuid", &global).await;
        assert!(result.is_err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_verify_totp() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/totp/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(login_response_json()))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = verify_totp("123456", "totp-token", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_download_ticket() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/ticket"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ticket": "tkt_abc123",
                "expires_in": 30
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = download_ticket("npm-local/left-pad/1.0.0", "download", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_download_ticket_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/ticket"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ticket": "tkt_abc123",
                "expires_in": 30
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = download_ticket("some/path", "download", &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_ci_exchange() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/ci/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ci_access_token",
                "token_type": "Bearer",
                "expires_in": 900,
                "username": "ci-runner"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = ci_exchange(NIL_UUID, Some("ey.jwt.here"), &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_ci_exchange_missing_jwt() {
        let (_server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = ci_exchange(NIL_UUID, None, &global).await;
        assert!(result.is_err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_setup_status() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/setup/status"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "setup_required": false })),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = setup_status(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_setup_status_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/setup/status"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "setup_required": true })),
            )
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = setup_status(&global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_whoami_json() {
        let data = user_json();
        let output = crate::output::render(&data, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("auth_whoami_json", parsed);
    }

    #[test]
    fn snapshot_token_list_json() {
        let tokens = serde_json::json!([{
            "id": NIL_UUID,
            "name": "ci-deploy",
            "prefix": "ak_xxxx_",
            "scopes": "read, write",
            "created_at": "2026-01-15T12:00:00+00:00",
            "expires_at": "never",
            "last_used": "never"
        }]);
        let output = crate::output::render(&tokens, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("auth_token_list_json", parsed);
    }
}

async fn token_list(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let user = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| AkError::NotAuthenticated(format!("Failed to get user info: {e}")))?;

    let (tokens, raw) =
        artifact_keeper_sdk::raw::capture(client.list_user_tokens().id(user.id).send()).await;
    let tokens = tokens.map_err(|e| AkError::ServerError(format!("Failed to list tokens: {e}")))?;

    if tokens.items.is_empty() && !output::is_machine_format(&global.format) {
        eprintln!("No API tokens found. Run `ak auth token create` to create one.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for t in &tokens.items {
            println!("{}", t.id);
        }
        return Ok(());
    }

    let entries: Vec<_> = tokens
        .items
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id.to_string(),
                "name": t.name,
                "prefix": t.token_prefix,
                "scopes": t.scopes.join(", "),
                "created_at": t.created_at.to_rfc3339(),
                "expires_at": format_optional_date(t.expires_at, "%+"),
                "last_used": format_optional_date(t.last_used_at, "%+"),
            })
        })
        .collect();

    let mut table = Table::new();
    table
        .load_style(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "ID",
            "NAME",
            "PREFIX",
            "SCOPES",
            "CREATED",
            "EXPIRES",
            "LAST USED",
        ]);

    for t in &tokens.items {
        table.add_row(vec![
            &t.id.to_string()[..8],
            &t.name,
            &t.token_prefix,
            &t.scopes.join(", "),
            &t.created_at.format("%Y-%m-%d").to_string(),
            &format_optional_date(t.expires_at, "%Y-%m-%d"),
            &format_optional_date(t.last_used_at, "%Y-%m-%d"),
        ]);
    }

    let table_str = table.to_string();

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    Ok(())
}
