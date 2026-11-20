use artifact_keeper_sdk::{ClientAuthExt, ClientSsoExt, ClientSystemExt, ClientUsersExt};
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use miette::{IntoDiagnostic, Result};

use super::client::{anon_client, authenticated_client, build_client, client_for};
use super::helpers::{
    PromptResult, parse_json_arg, parse_uuid, raw_err, require_secret, resolve_secret, sdk_err,
};
use crate::cli::GlobalArgs;
use crate::config::credentials::{
    StoredCredential, delete_credential, get_credential, store_credential,
};
use crate::config::{AppConfig, InstanceConfig, sso_binding};
use crate::error::AkError;
use crate::output::{self, OutputFormat};
use crate::transport;

#[derive(clap::Args)]
pub struct LoginArgs {
    /// Instance URL. Adds the instance if it's new, named from its host (uses the
    /// default instance if omitted)
    url: Option<String>,

    /// Skip interactive prompt and go straight to token authentication
    #[arg(long, conflicts_with_all = ["device", "password", "sso", "username"])]
    token: bool,

    /// Read the token from stdin rather than asking for it
    #[arg(long, conflicts_with_all = ["token", "device", "password", "sso", "username", "totp_code_stdin"])]
    token_stdin: bool,

    /// Sign in with the RFC 8628 device authorization grant: print a verification
    /// URL and a short code, open the browser if there's one, and wait for the
    /// approval. Works headlessly and with SSO-backed instances. Needs server 1.12.
    /// At a terminal this is already the default when the server offers it
    #[arg(
        long = "device",
        alias = "oidc-device",
        conflicts_with_all = ["password", "sso", "username"]
    )]
    device: bool,

    /// Sign in with a username and password, even where the server offers browser
    /// sign-in, which `ak auth login` at a terminal would otherwise use
    #[arg(long, conflicts_with_all = ["device", "sso"])]
    password: bool,

    /// AK scopes to request with device sign-in (repeatable, or comma-separated).
    /// Implies --device. `--device` alone asks for `read:artifacts`, and a bare login
    /// at a terminal for every non-admin scope
    #[arg(
        long,
        value_delimiter = ',',
        conflicts_with_all = ["password", "sso", "token", "token_stdin", "username"]
    )]
    scope: Vec<String>,

    /// Sign in through an SSO provider, as `ldap:<id>`, `oidc:<id>` or `saml:<id>`.
    /// `ak sso providers` lists them. LDAP takes a username and password here. OIDC
    /// and SAML print a URL to open in a browser, which ends on a page showing a code
    /// to give to this command or, on this machine, to `ak auth sso-exchange`. The
    /// code works for a minute. Servers before 1.12 end at a callback URL with a `code`
    /// instead, and one serving the web UI redeems it on that page, where it works
    /// only once: use an API token there
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
        long_about = "Log in to an Artifact Keeper instance. The session is stored and never printed.\n\nAt a terminal, on a server that offers browser sign-in (device authorization, 1.12), this prints a code, opens the browser and waits for you to approve it there. That session can read and write artifacts and repositories; admin-only work needs --password or an API token. Pass --password for a username and password instead, or --token for an API token. Without a terminal, or on a server without browser sign-in, it asks for a password or a token as before.",
        after_help = "Examples:\n  ak auth login\n  ak auth login --password\n  ak auth login --device --scope read:artifacts,write:artifacts\n  ak auth login --username alice --password-stdin < secret-file\n  ak auth login --token-stdin < token-file\n  ak auth login --sso ldap:<provider-id> --username alice\n  ak auth login --sso oidc:<provider-id>"
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

    /// Revoke an API token by ID. Use `ak auth token revoke`
    #[command(hide = true)]
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

    /// Finish an OIDC or SAML login: trade the code the browser shows (or the code in
    /// the callback URL) for a session
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

    /// Revoke an API token by ID
    Revoke {
        /// ID of the API token to revoke
        id: String,
    },
}

impl AuthCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Login(args) => login(&args, global).await,
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
                TokenCommand::Revoke { id } => revoke_token(&id, global).await,
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

/// The instance a login is for, and whether it's new and has to be saved.
struct LoginTarget {
    name: String,
    instance: InstanceConfig,
    is_new: bool,
}

/// The instance named by the URL argument or a URL in `--instance`, or else the
/// configured one. A URL no instance has makes a new instance, named from its host.
/// Shared by the password, token and device login paths.
fn resolve_login_target(url: Option<&str>, global: &GlobalArgs) -> Result<LoginTarget> {
    let config = AppConfig::load()?;
    let url = url.or(global
        .instance
        .as_deref()
        .filter(|value| crate::config::is_instance_url(value)));
    let Some(url) = url else {
        let (name, instance) = config.resolve_instance(global.instance.as_deref())?;
        return Ok(LoginTarget {
            name: name.to_string(),
            instance: instance.clone(),
            is_new: false,
        });
    };
    let url = crate::config::normalize_instance_url(url)?;
    if let Some((name, instance)) = config.instance_at(&url) {
        return Ok(LoginTarget {
            name: name.to_string(),
            instance: instance.clone(),
            is_new: false,
        });
    }
    Ok(LoginTarget {
        name: config.name_for_url(&url),
        instance: InstanceConfig {
            url,
            api_version: "v1".to_string(),
            allow_insecure_http: false,
        },
        is_new: true,
    })
}

/// Keep the instance a login just succeeded on. Only now, so a mistyped URL doesn't
/// stay behind and become the default.
fn save_new_instance(target: &LoginTarget) -> Result<()> {
    let mut config = AppConfig::load()?;
    let is_first = config.instances.is_empty();
    config
        .instances
        .insert(target.name.clone(), target.instance.clone());
    if is_first || config.default_instance.is_none() {
        config.default_instance = Some(target.name.clone());
        eprintln!(
            "Added instance '{}' at {} (set as default)",
            target.name, target.instance.url
        );
    } else {
        eprintln!(
            "Added instance '{}' at {}. Run `ak instance use {}` to make it the default.",
            target.name, target.instance.url, target.name
        );
    }
    config.save()
}

async fn login(args: &LoginArgs, global: &GlobalArgs) -> Result<()> {
    let target = resolve_login_target(args.url.as_deref(), global)?;
    // Before choosing a method, so the refusal isn't followed by a fallback that
    // would be refused too.
    transport::require_secure_transport(&target.name, &target.instance)?;
    let at_terminal = std::io::IsTerminal::is_terminal(&std::io::stdin());
    match login_method(args, global.no_input, at_terminal) {
        LoginMethod::Device => device_login(&target, args, global, true).await?,
        LoginMethod::DeviceIfOffered if server_offers_device_login(&target.instance).await => {
            eprintln!("{}\n", default_device_notice(&target.name));
            device_login(&target, args, global, false).await?
        }
        LoginMethod::DeviceIfOffered | LoginMethod::Other => {
            login_to(&target.name, &target.instance, args, global).await?
        }
    }
    if target.is_new {
        save_new_instance(&target)?;
    }
    Ok(())
}

/// Sign in with the device grant. If the server can't start one (a 429 or 503, a
/// proxy that blocks the route, no answer), nothing has been shown yet: a login that
/// chose it by default goes on to the password or token prompt, and one asked for
/// with `--device` fails and says how to sign in another way.
async fn device_login(
    target: &LoginTarget,
    args: &LoginArgs,
    global: &GlobalArgs,
    explicit: bool,
) -> Result<()> {
    use crate::commands::device_flow;

    let scopes = device_scopes(args);
    match device_flow::start(&target.name, &target.instance, &scopes).await {
        Ok(started) => {
            device_flow::finish(&target.name, &target.instance, started, global, None).await
        }
        Err(error) if !explicit => {
            let reason = error.to_string().replace(['\n', '\r'], " ");
            eprintln!(
                "Browser sign-in couldn't start ({reason}). Signing in with a password or \
                 token instead."
            );
            login_to(&target.name, &target.instance, args, global).await
        }
        Err(error) => Err(error.wrap_err(
            "Device sign-in couldn't start. `ak auth login --password` signs in with a \
             username and password instead, and `--token` with an API token",
        )),
    }
}

/// The scopes a device login asks for. A bare login asks for the non-admin ceiling,
/// so pushing works. `--device` and `--scope` keep to what's asked for, and
/// `read:artifacts` if nothing is: a headless host gets the least unless asked.
fn device_scopes(args: &LoginArgs) -> Vec<String> {
    if args.device || !args.scope.is_empty() {
        return args.scope.clone();
    }
    crate::commands::device_flow::DEFAULT_LOGIN_SCOPES
        .iter()
        .map(|scope| scope.to_string())
        .collect()
}

/// What a bare `ak auth login` says before it signs in through the browser.
fn default_device_notice(instance_name: &str) -> String {
    format!(
        "Signing in to '{instance_name}' in the browser, to read and write artifacts and \
         repositories ({}). Admin-only work, such as deleting, promoting or `ak admin`, needs \
         `ak auth login --password` or an API token.",
        crate::commands::device_flow::DEFAULT_LOGIN_SCOPES.join(" ")
    )
}

/// A 403 to a session from the browser (device) sign-in, explained: the session holds
/// only the scopes it was approved for, so a refusal for scope, or for admin to an
/// admin account, is the session's doing and not the account's. Other failures, and
/// any credential that isn't such a session, pass through unchanged.
pub(crate) fn explain_scoped_session(
    error: miette::Report,
    instance: Option<&str>,
) -> miette::Report {
    let message = match error.downcast_ref::<AkError>().or_else(|| {
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<AkError>())
    }) {
        Some(AkError::Forbidden(message)) => message.clone(),
        _ => return error,
    };
    // A token in AK_TOKEN is used ahead of a login, and isn't one.
    if std::env::var_os("AK_TOKEN").is_some() {
        return error;
    }
    let claims = AppConfig::load().ok().and_then(|config| {
        let (name, _) = config.resolve_instance(instance).ok()?;
        let credential = get_credential(name).ok()?;
        super::helpers::decode_jwt_claims(&credential.access_token)
    });
    match claims.and_then(|claims| scoped_session_refusal(&message, &claims)) {
        Some(scopes) => AkError::ScopedSession { message, scopes }.into(),
        None => error,
    }
}

/// The session's scopes, if `message` is a refusal that its scope list explains.
fn scoped_session_refusal(message: &str, claims: &serde_json::Value) -> Option<String> {
    let scopes: Vec<&str> = claims
        .get("scopes")?
        .as_array()?
        .iter()
        .filter_map(|scope| scope.as_str())
        .collect();
    let is_admin = claims.get("is_admin").and_then(|v| v.as_bool()) == Some(true);
    let for_scope = message.contains("does not have required scope");
    let for_admin = is_admin && message.contains("Admin access required");
    (for_scope || for_admin).then(|| scopes.join(" "))
}

/// How a login was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginMethod {
    /// `--device` or `--scope`.
    Device,
    /// A bare `ak auth login` at a terminal: the device grant if the server offers
    /// it, and the old menu if not.
    DeviceIfOffered,
    /// Whatever the other flags say, or the old menu.
    Other,
}

/// Device sign-in is the default only at a terminal with nothing else asked for: no
/// password, token or SSO flag, and prompts allowed. Without a terminal, `ak auth
/// login` does what it always did, so scripts don't change.
fn login_method(args: &LoginArgs, no_input: bool, at_terminal: bool) -> LoginMethod {
    if args.device || !args.scope.is_empty() {
        return LoginMethod::Device;
    }
    let chose_another = args.password
        || args.token
        || args.token_stdin
        || args.sso.is_some()
        || args.username.is_some();
    if chose_another || no_input || !at_terminal {
        return LoginMethod::Other;
    }
    LoginMethod::DeviceIfOffered
}

/// Whether the server says device sign-in is on (`AuthConfig.device_authorization_enabled`,
/// new in 1.12). Anything else, a 1.11 server that doesn't send it, an error or an
/// answer slower than 3 seconds, means no, and the login goes the old way.
async fn server_offers_device_login(instance: &InstanceConfig) -> bool {
    let Ok(client) = anon_client(&instance.url) else {
        return false;
    };
    let config = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        client.get_system_config().send(),
    )
    .await;
    matches!(
        config,
        Ok(Ok(config)) if config.auth.device_authorization_enabled == Some(true)
    )
}

async fn login_to(
    instance_name: &str,
    instance: &InstanceConfig,
    args: &LoginArgs,
    global: &GlobalArgs,
) -> Result<()> {
    // Every way in sends a secret: a password, a token or a one-time code. Refuse
    // plain HTTP to a remote host before asking for any of them.
    transport::require_secure_transport(instance_name, instance)?;
    if let Some(sso) = &args.sso {
        return match parse_sso(sso)? {
            (SsoKind::Ldap, id) => login_with_ldap(instance_name, instance, id, args, global).await,
            (kind, id) => login_with_browser(instance_name, instance, kind, id, args, global).await,
        };
    }
    if args.token_stdin {
        let token = require_secret(
            resolve_secret(None, true, "--token", None, global.no_input)?,
            "The token",
            "--token-stdin",
        )?;
        return store_token(instance_name, instance, token).await;
    }
    if args.username.is_some() || (args.password && !global.no_input) {
        return login_with_password(instance_name, instance, args, global).await;
    }

    if global.no_input {
        let hint = if args.token {
            "Cannot prompt for token in non-interactive mode. Use `--token-stdin` or set AK_TOKEN."
        } else {
            "Cannot prompt for credentials in non-interactive mode. Use `--username` with \
             `--password-stdin`, `--token-stdin`, or set AK_TOKEN."
        };
        return Err(AkError::Usage(hint.into()).into());
    }

    // If --token flag was explicitly passed, go straight to token flow
    if args.token {
        return login_with_token(instance_name, instance).await;
    }

    // Interactive: let user choose how to authenticate
    eprintln!("Logging in to '{}' ({})\n", instance_name, instance.url);

    let methods = &[
        "Login with username and password",
        "Paste an authentication token",
    ];
    let selection = dialoguer::Select::new()
        .with_prompt("How would you like to authenticate?")
        .items(methods)
        .default(0)
        .interact()
        .prompt_diagnostic()?;

    match selection {
        0 => login_with_password(instance_name, instance, args, global).await,
        1 => login_with_token(instance_name, instance).await,
        _ => unreachable!(),
    }
}

async fn login_with_token(instance_name: &str, instance: &InstanceConfig) -> Result<()> {
    eprintln!(
        "Paste your API token for '{instance_name}' ({}):",
        instance.url
    );
    let token = dialoguer::Password::new()
        .with_prompt("Token")
        .interact()
        .prompt_diagnostic()?;
    store_token(instance_name, instance, token).await
}

/// Check a token with the server, and keep it only if the server takes it.
async fn store_token(instance_name: &str, instance: &InstanceConfig, token: String) -> Result<()> {
    let cred = StoredCredential {
        access_token: token.trim().to_string(),
        refresh_token: None,
    };

    let client = build_client(instance_name, instance, Some(&cred))?;
    let resp = client.get_current_user().send().await.map_err(|e| {
        crate::commands::helpers::classified(format!("Token validation failed: {e}"), &e)
    })?;

    store_credential(instance_name, &cred)?;
    eprintln!(
        "Logged in to '{instance_name}' as {} ({})",
        resp.username, resp.email
    );
    Ok(())
}

/// A password sent over plaintext HTTP to a non-loopback host is readable by any
/// on-path observer. Refuse unless the user explicitly opted in (`ak instance add|update
/// --insecure-http` or AK_ALLOW_INSECURE_HTTP=1). Loopback (localhost/127.0.0.1/::1)
/// is exempt: plain HTTP is the normal local development setup.
fn refuse_cleartext_password(instance_name: &str, instance: &InstanceConfig) -> Result<()> {
    Ok(transport::require_secure_transport(
        instance_name,
        instance,
    )?)
}

/// The username and password for a login, from the flags or by asking.
fn login_credentials(args: &LoginArgs, global: &GlobalArgs) -> Result<(String, String)> {
    let username = match &args.username {
        Some(username) => username.clone(),
        None if global.no_input => {
            return Err(AkError::Usage(
                "Cannot prompt for a username in non-interactive mode. Use `--username` with \
                 `--password-stdin`."
                    .into(),
            )
            .into());
        }
        None => dialoguer::Input::new()
            .with_prompt("Username")
            .interact_text()
            .prompt_diagnostic()?,
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
    refuse_cleartext_password(instance_name, instance)?;
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
        .map_err(|e| crate::commands::helpers::classified(format!("Login failed: {e}"), &e))?
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
        return Err(AkError::Usage(
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
        AkError::Usage(format!(
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
    refuse_cleartext_password(instance_name, instance)?;
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
        .map_err(|e| crate::commands::helpers::classified(format!("LDAP login failed: {e}"), &e))?;
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

/// A browser login the server has started: where to send the browser, and the
/// cookie that binds the login to this client (none from servers before 1.12).
struct BrowserLogin {
    url: String,
    binding: Option<String>,
}

/// Where the server sends a browser to sign in with this provider. It answers with
/// a redirect, which here is the answer rather than something to follow.
///
/// `client=cli` asks a 1.12 server for the command-line mode: the browser ends on a
/// page showing the code rather than being signed in, and the code is redeemed only
/// with the binding cookie this response sets. Older servers ignore it.
async fn sso_login_url(
    instance: &InstanceConfig,
    kind: SsoKind,
    provider: uuid::Uuid,
    prompt: Option<&str>,
) -> Result<BrowserLogin> {
    let builder = super::client::raw_http_client_builder(reqwest::redirect::Policy::none());
    let http = transport::apply_custom_ca(builder)?
        .build()
        .into_diagnostic()?;
    let url = format!(
        "{}/api/v1/auth/sso/{}/{provider}/login?client=cli",
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
    let url = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|location| location.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| {
            AkError::ServerError(format!(
                "Failed to start the SSO login: {status} with no Location"
            ))
        })?;
    let binding = sso_binding::from_set_cookie(
        resp.headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    );
    Ok(BrowserLogin { url, binding })
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
        return Err(AkError::Usage("--prompt is for OIDC only.".into()).into());
    }
    let BrowserLogin {
        url: login_url,
        binding,
    } = sso_login_url(instance, kind, provider, args.prompt.as_deref()).await?;
    // For `ak auth sso-exchange`, which may run in another process.
    sso_binding::store(instance_name, binding.as_deref())?;
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
            "It ends on a page showing a code (on servers before 1.12, at a URL with a \
             `code`). Finish right away with `ak auth sso-exchange --code-stdin`."
        );
        return Ok(());
    }
    eprintln!(
        "It ends on a page showing a code (on servers before 1.12, at a URL with a `code`). \
         Paste the code or that URL here."
    );
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
    // The code redeems for a session, so it's a credential too.
    transport::require_secure_transport(instance_name, instance)?;
    // The binding cookie from `ak auth login --sso`, which a 1.12 server needs to
    // redeem the code. None from older servers, and then no Cookie is sent.
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(cookie) = sso_binding::load(instance_name)
        && let Ok(value) = reqwest::header::HeaderValue::from_str(&cookie)
    {
        headers.insert(reqwest::header::COOKIE, value);
    }
    let client = super::client::anon_client_with_headers(&instance.url, headers)?;
    let body = artifact_keeper_sdk::types::ExchangeCodeRequest {
        code: exchange_code_from(code),
    };
    let resp = client
        .exchange_code()
        .body(body)
        .send()
        .await
        .map_err(|e| crate::commands::helpers::classified(format!("SSO exchange failed: {e}"), &e))?
        .into_inner();
    store_session(instance_name, resp.access_token, resp.refresh_token, false)?;
    // The cookie is spent. A failure here leaves a file that expires on its own.
    let _ = sso_binding::remove(instance_name);
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
        .map_err(|e| {
            crate::commands::helpers::classified(format!("Token refresh failed: {e}"), &e)
        })?;

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
    // The ticket and code redeem for a session.
    transport::require_secure_transport(instance_name, instance)?;
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
        .map_err(|e| {
            crate::commands::helpers::classified(format!("TOTP verification failed: {e}"), &e)
        })?
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
        AkError::Usage(
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
    let resp = resp.map_err(|e| {
        crate::commands::helpers::classified(format!("CI token exchange failed: {e}"), &e)
    })?;

    // On GitHub Actions, have the runner mask the token in everything the job prints
    // from here on, in any format. A pipe with no --format gets JSON, which holds it.
    // Table output doesn't print it, so it isn't written out there at all.
    if !matches!(global.format, OutputFormat::Table)
        && let Some(command) = github_mask_command(&resp.access_token)
    {
        use std::io::Write;
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "{command}");
        let _ = stderr.flush();
    }

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

    let table_str = ci_exchange_table(
        &resp.username,
        &resp.token_type,
        resp.expires_in,
        &resp.access_token,
    );

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );
    Ok(())
}

/// The table `ak auth ci-exchange` prints. It shows only the start of the token: a
/// CI step that runs the exchange without `-q` or `--format json` is showing it to the
/// job log, not capturing it.
fn ci_exchange_table(username: &str, token_type: &str, expires_in: i64, token: &str) -> String {
    format!(
        "Exchanged CI OIDC token for an access token (user: {username}).\n\
         Token type:   {token_type}\n\
         Expires in:   {expires_in} seconds\n\
         Access token: {} (hidden: -q prints only the token, --format json the whole response)",
        masked_token(token),
    )
}

/// The first four characters of a token and an ellipsis, or only the ellipsis for a
/// token too short to show any of.
fn masked_token(token: &str) -> String {
    const SHOWN: usize = 4;
    if token.chars().count() <= SHOWN * 3 {
        return "…".to_string();
    }
    let start: String = token.chars().take(SHOWN).collect();
    format!("{start}…")
}

/// The `::add-mask::` workflow command for a token, when running on GitHub Actions.
/// It goes to stderr, which the runner reads commands from too, so `-q` and JSON
/// output on stdout stay as they were.
fn github_mask_command(token: &str) -> Option<String> {
    let on_github = std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true");
    github_mask_command_for(token, on_github)
}

fn github_mask_command_for(token: &str, on_github: bool) -> Option<String> {
    if !on_github || token.is_empty() {
        return None;
    }
    // The runner unescapes these in a command's value.
    let escaped = token
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A");
    Some(format!("::add-mask::{escaped}"))
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

pub(crate) async fn whoami(global: &GlobalArgs) -> Result<()> {
    let (instance_name, instance, client) = authenticated_client(global)?;

    let (user, raw) = artifact_keeper_sdk::raw::capture(client.get_current_user().send()).await;
    let user = user.map_err(|e| crate::commands::helpers::sdk_err("get user info", e))?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", user.id);
        return Ok(());
    }

    let info = serde_json::json!({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "admin": user.is_admin,
        "totp_enabled": user.totp_enabled,
        "instance": instance_name,
        "url": instance.url,
    });

    let table_str = format!(
        "ID:           {}\n\
         Username:     {}\n\
         Email:        {}\n\
         Display Name: {}\n\
         Admin:        {}\n\
         TOTP:         {}\n\
         Instance:     {} ({})",
        user.id,
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
            .prompt_diagnostic()?,
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
    let resp = resp.map_err(|e| crate::commands::helpers::sdk_err("create token", e))?;

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

async fn token_list(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;

    let user = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| crate::commands::helpers::sdk_err("get user info", e))?;

    let (tokens, raw) =
        artifact_keeper_sdk::raw::capture(client.list_user_tokens().id(user.id).send()).await;
    let tokens = tokens.map_err(|e| crate::commands::helpers::sdk_err("list tokens", e))?;

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
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
    fn parse_login_device() {
        match parse_auth(&["auth", "login", "--device"]) {
            AuthCommand::Login(args) => {
                assert!(args.device);
                assert!(!args.token);
                assert!(!args.password);
                assert!(args.scope.is_empty());
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn parse_login_oidc_device_is_still_accepted() {
        match parse_auth(&["auth", "login", "--oidc-device"]) {
            AuthCommand::Login(args) => assert!(args.device),
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn parse_login_device_scopes() {
        match parse_auth(&[
            "auth",
            "login",
            "--device",
            "--scope",
            "read:artifacts,write:artifacts",
            "--scope",
            "delete:artifacts",
        ]) {
            AuthCommand::Login(args) => {
                assert!(args.device);
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
        assert!(TestCli::try_parse_from(["auth", "login", "--token", "--device"]).is_err());
    }

    #[test]
    fn parse_login_password_conflicts_with_device_token_and_scope() {
        for other in [
            &["--device"][..],
            &["--token"],
            &["--scope", "read:artifacts"],
        ] {
            let mut argv = vec!["auth", "login", "--password"];
            argv.extend_from_slice(other);
            assert!(TestCli::try_parse_from(argv).is_err(), "{other:?}");
        }
    }

    fn login_args(argv: &[&str]) -> LoginArgs {
        let mut full = vec!["auth", "login"];
        full.extend_from_slice(argv);
        match parse_auth(&full) {
            AuthCommand::Login(args) => *args,
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn a_bare_login_at_a_terminal_asks_the_server_about_device_sign_in() {
        assert_eq!(
            login_method(&login_args(&[]), false, true),
            LoginMethod::DeviceIfOffered
        );
    }

    #[test]
    fn without_a_terminal_or_with_no_input_a_bare_login_is_unchanged() {
        assert_eq!(
            login_method(&login_args(&[]), false, false),
            LoginMethod::Other
        );
        assert_eq!(
            login_method(&login_args(&[]), true, true),
            LoginMethod::Other
        );
    }

    #[test]
    fn any_other_method_flag_skips_device_sign_in() {
        for argv in [
            &["--password"][..],
            &["--token"],
            &["--token-stdin"],
            &["--username", "alice"],
            &["--sso", "oidc:00000000-0000-4000-8000-000000000001"],
        ] {
            assert_eq!(
                login_method(&login_args(argv), false, true),
                LoginMethod::Other,
                "{argv:?}"
            );
        }
    }

    #[test]
    fn device_and_scope_ask_for_device_sign_in_anywhere() {
        for argv in [&["--device"][..], &["--scope", "write:artifacts"]] {
            assert_eq!(
                login_method(&login_args(argv), true, false),
                LoginMethod::Device,
                "{argv:?}"
            );
        }
    }

    #[test]
    fn a_bare_login_asks_for_the_non_admin_ceiling() {
        let scopes = device_scopes(&login_args(&[]));
        for scope in ["read:artifacts", "write:artifacts", "write:repositories"] {
            assert!(scopes.iter().any(|s| s == scope), "{scope}: {scopes:?}");
        }
        // Never what the device grant refuses, nor what only an admin can grant.
        for refused in [
            "*",
            "admin",
            "delete:artifacts",
            "delete:repositories",
            "promote:artifacts",
            "trigger:sync",
            "write:users",
            "write:findings",
            "mcp:introspect",
        ] {
            assert!(!scopes.iter().any(|s| s == refused), "{refused}");
        }
        assert!(crate::commands::device_flow::normalize_scopes(&scopes).is_ok());
    }

    #[test]
    fn device_and_scope_keep_to_what_is_asked_for() {
        // `--device` alone: the device flow's own default, read:artifacts.
        assert!(device_scopes(&login_args(&["--device"])).is_empty());
        assert_eq!(
            device_scopes(&login_args(&["--scope", "read:artifacts"])),
            vec!["read:artifacts"]
        );
    }

    #[test]
    fn the_default_notice_names_the_scopes_and_the_way_to_full_access() {
        let notice = default_device_notice("prod");
        assert!(notice.contains("write:artifacts"), "{notice}");
        assert!(notice.contains("ak auth login --password"), "{notice}");
    }

    #[test]
    fn a_scope_refusal_to_a_device_session_is_explained() {
        let claims = serde_json::json!({
            "is_admin": false,
            "scopes": ["read:artifacts", "write:artifacts"],
        });
        assert_eq!(
            scoped_session_refusal(
                "Failed to delete artifact: 403 Forbidden: Token does not have required \
                 scope: delete",
                &claims
            )
            .as_deref(),
            Some("read:artifacts write:artifacts")
        );
        // A non-admin's account can't do admin work whatever the session.
        assert_eq!(
            scoped_session_refusal("403 Forbidden: Admin access required", &claims),
            None
        );
    }

    #[test]
    fn an_admin_refused_admin_work_on_a_device_session_is_explained() {
        let claims = serde_json::json!({ "is_admin": true, "scopes": ["read:artifacts"] });
        assert_eq!(
            scoped_session_refusal("403 Forbidden: Admin access required", &claims).as_deref(),
            Some("read:artifacts")
        );
    }

    #[test]
    fn a_password_session_is_not_explained() {
        // No `scopes` claim: action-unrestricted.
        let claims = serde_json::json!({ "is_admin": true });
        assert_eq!(
            scoped_session_refusal("403 Forbidden: Admin access required", &claims),
            None
        );
    }

    fn target_at(url: String) -> LoginTarget {
        LoginTarget {
            name: "t".into(),
            instance: InstanceConfig {
                url,
                api_version: "v1".into(),
                allow_insecure_http: false,
            },
            is_new: false,
        }
    }

    async fn device_code_answers(status: u16) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/device/code"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "error": "temporarily_unavailable",
                    "error_description": "try later"
                })),
            )
            .expect(1)
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn a_default_device_login_that_cant_start_falls_back_to_the_old_prompt() {
        let server = device_code_answers(503).await;
        let global = crate::test_utils::test_global(OutputFormat::Table);
        // With --no-input the old prompt can't ask, so reaching it is this usage error
        // rather than the device error.
        let err = device_login(&target_at(server.uri()), &login_args(&[]), &global, false)
            .await
            .unwrap_err();
        let shown = format!("{err:?}");
        assert!(shown.contains("Cannot prompt for credentials"), "{shown}");
        assert!(!shown.contains("temporarily_unavailable"), "{shown}");
    }

    #[tokio::test]
    async fn a_default_device_login_with_no_answer_falls_back_too() {
        // Nothing listens on a port a dropped server had.
        let url = {
            let server = MockServer::start().await;
            server.uri()
        };
        let global = crate::test_utils::test_global(OutputFormat::Table);
        let err = device_login(&target_at(url), &login_args(&[]), &global, false)
            .await
            .unwrap_err();
        let shown = format!("{err:?}");
        assert!(shown.contains("Cannot prompt for credentials"), "{shown}");
    }

    #[tokio::test]
    async fn an_explicit_device_login_that_cant_start_fails_and_mentions_password() {
        let server = device_code_answers(429).await;
        let global = crate::test_utils::test_global(OutputFormat::Table);
        let err = device_login(
            &target_at(server.uri()),
            &login_args(&["--device"]),
            &global,
            true,
        )
        .await
        .unwrap_err();
        let shown = format!("{err:?}");
        assert!(shown.contains("ak auth login --password"), "{shown}");
        assert!(shown.contains("temporarily_unavailable"), "{shown}");
    }

    async fn config_server(auth: serde_json::Value) -> (MockServer, InstanceConfig) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/system/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "max_upload_size_bytes": 1,
                "demo_mode": false,
                "guest_access_enabled": false,
                "auth": auth,
            })))
            .mount(&server)
            .await;
        let instance = InstanceConfig {
            url: server.uri(),
            api_version: "v1".into(),
            allow_insecure_http: false,
        };
        (server, instance)
    }

    fn auth_config(device: Option<bool>) -> serde_json::Value {
        let mut auth = serde_json::json!({
            "ldap_enabled": false,
            "local_login_enabled": true,
            "oidc_enabled": false,
            "silent_sso_enabled": false,
            "sso_enabled": false,
        });
        if let Some(device) = device {
            auth["device_authorization_enabled"] = device.into();
        }
        auth
    }

    #[tokio::test]
    async fn a_server_advertising_device_authorization_offers_it() {
        let (_server, instance) = config_server(auth_config(Some(true))).await;
        assert!(server_offers_device_login(&instance).await);
    }

    #[tokio::test]
    async fn a_server_with_it_off_or_a_1_11_server_does_not() {
        let (_server, instance) = config_server(auth_config(Some(false))).await;
        assert!(!server_offers_device_login(&instance).await);
        // 1.11 doesn't send the field at all.
        let (_server, instance) = config_server(auth_config(None)).await;
        assert!(!server_offers_device_login(&instance).await);
    }

    #[tokio::test]
    async fn a_server_that_fails_the_config_request_does_not() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/system/config"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let instance = InstanceConfig {
            url: server.uri(),
            api_version: "v1".into(),
            allow_insecure_http: false,
        };
        assert!(!server_offers_device_login(&instance).await);
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
        // Not an ::add-mask:: line in this repo's own CI log.
        unsafe { std::env::remove_var("GITHUB_ACTIONS") };

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

    #[test]
    fn ci_exchange_table_shows_only_the_start_of_the_token() {
        let table = ci_exchange_table(
            "ci-runner",
            "Bearer",
            900,
            "eyJhbGciOiJIUzI1NiJ9.payload.sig",
        );
        assert!(!table.contains("eyJhbGciOiJIUzI1NiJ9"), "{table}");
        assert!(
            table.contains("Access token: eyJh… (hidden: -q prints"),
            "{table}"
        );
        assert!(table.contains("--format json"), "{table}");
    }

    #[test]
    fn masked_token_shows_four_characters_of_a_long_token_and_none_of_a_short_one() {
        assert_eq!(masked_token("abcdefghijklmnop"), "abcd…");
        assert_eq!(masked_token("abcdefghijkl"), "…");
        assert_eq!(masked_token(""), "…");
        // Characters, not bytes.
        assert_eq!(masked_token("ééééééééééééé"), "éééé…");
    }

    #[test]
    fn github_mask_command_only_on_github_actions() {
        assert_eq!(github_mask_command_for("tok", false), None);
        assert_eq!(github_mask_command_for("", true), None);
        assert_eq!(
            github_mask_command_for("tok", true).as_deref(),
            Some("::add-mask::tok")
        );
        // The runner unescapes these, so the mask matches the token as printed.
        assert_eq!(
            github_mask_command_for("a%b\r\nc", true).as_deref(),
            Some("::add-mask::a%25b%0D%0Ac")
        );
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
