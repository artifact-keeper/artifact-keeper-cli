//! Device authorization login (RFC 8628).
//!
//! Artifact Keeper exposes a plain AK device authorization grant at
//! `POST /api/v1/auth/device/{code,token}`. It is deliberately **not** an
//! OIDC device flow: the user approves the code from an existing Artifact
//! Keeper browser session (local, LDAP, OIDC or SAML), and the CLI receives
//! AK-native access and refresh tokens. See the server's
//! `docs/device-authorization.md`.
//!
//! This module owns the wire protocol and the polling state machine. The
//! command layer only resolves the instance and reports the result.

use std::time::{Duration, Instant};

use artifact_keeper_sdk::ClientAuthExt;
use miette::{IntoDiagnostic, Result};
use serde::Deserialize;

use crate::cli::GlobalArgs;
use crate::config::InstanceConfig;
use crate::config::credentials::{StoredCredential, store_credential};
use crate::error::AkError;
use crate::output::OutputFormat;
use crate::transport;

/// RFC 8628 §3.4 `grant_type`.
pub(crate) const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Scope the server applies when the client names none. Kept in sync with
/// the backend's `DEFAULT_DEVICE_SCOPE`.
pub(crate) const DEFAULT_SCOPE: &str = "read:artifacts";

/// Unregistered public-client identifier. RFC 8628 §3.1 requires the same
/// value on the authorization request and every token poll.
pub(crate) const CLIENT_ID: &str = "ak-cli";

/// Environment variable that suppresses the best-effort browser launch.
pub(crate) const NO_BROWSER_ENV: &str = "AK_NO_BROWSER";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// RFC 8628 §3.5: every `slow_down` adds five seconds to the interval.
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);
/// The server caps its own interval at 60 seconds; do the same locally.
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(60);
/// Extra attempts for transient transport/5xx failures before giving up.
const MAX_TRANSPORT_RETRIES: u32 = 3;

/// RFC 8628 §3.2 device authorization response.
#[derive(Clone, Deserialize)]
pub(crate) struct DeviceCodeResponse {
    pub(crate) device_code: String,
    pub(crate) user_code: String,
    pub(crate) verification_uri: String,
    #[serde(default = "default_expires_in")]
    pub(crate) expires_in: u64,
    #[serde(default = "default_interval")]
    pub(crate) interval: u64,
}

/// RFC 6749 §5.1 token response.
#[derive(Clone, Deserialize)]
pub(crate) struct TokenResponse {
    pub(crate) access_token: String,
    #[serde(default)]
    pub(crate) token_type: String,
    #[serde(default)]
    pub(crate) expires_in: u64,
    #[serde(default)]
    pub(crate) refresh_token: Option<String>,
    #[serde(default)]
    pub(crate) scope: String,
}

/// Never render token material, even if a future error path formats a
/// [`TokenResponse`] with `{:?}`.
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[redacted]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("scope", &self.scope)
            .finish()
    }
}

/// RFC 6749 §5.2 error response, shared by both public device endpoints.
#[derive(Deserialize)]
struct OAuthErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_description: String,
}

fn default_expires_in() -> u64 {
    600
}

fn default_interval() -> u64 {
    5
}

/// How long to wait between token polls, and when to stop.
///
/// Production values come from the server's `interval` / `expires_in`.
/// Tests override them so the state machine runs in milliseconds.
#[derive(Debug, Clone)]
pub(crate) struct PollPolicy {
    pub(crate) interval: Duration,
    pub(crate) max_interval: Duration,
    pub(crate) deadline: Duration,
    pub(crate) slow_down_step: Duration,
    pub(crate) max_transport_retries: u32,
}

impl PollPolicy {
    pub(crate) fn from_server(interval_secs: u64, expires_in_secs: u64) -> Self {
        Self {
            interval: Duration::from_secs(interval_secs.max(1)),
            max_interval: MAX_POLL_INTERVAL,
            deadline: Duration::from_secs(expires_in_secs.max(1)),
            slow_down_step: SLOW_DOWN_STEP,
            max_transport_retries: MAX_TRANSPORT_RETRIES,
        }
    }

    /// RFC 8628 §3.5: increase the interval by five seconds for this and all
    /// subsequent polls, up to the server's cap.
    pub(crate) fn on_slow_down(&mut self) {
        self.interval = (self.interval + self.slow_down_step).min(self.max_interval);
    }
}

/// What a token-endpoint response means to the poll loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PollResult {
    Success(TokenResponse),
    Pending,
    SlowDown,
    Denied,
    Expired,
    InvalidGrant,
    Transient {
        status: u16,
        message: String,
    },
    Fatal {
        status: u16,
        error: String,
        description: String,
    },
}

impl PartialEq for TokenResponse {
    fn eq(&self, other: &Self) -> bool {
        self.access_token == other.access_token
            && self.token_type == other.token_type
            && self.expires_in == other.expires_in
            && self.refresh_token == other.refresh_token
            && self.scope == other.scope
    }
}

impl Eq for TokenResponse {}

/// Classify one token-endpoint response. Pure, so every RFC 8628 branch is
/// testable without a server.
pub(crate) fn classify_poll(status: u16, body: &str) -> PollResult {
    if (200..300).contains(&status) {
        return match serde_json::from_str::<TokenResponse>(body) {
            Ok(tokens) if !tokens.access_token.is_empty() => PollResult::Success(tokens),
            _ => PollResult::Fatal {
                status,
                error: "invalid_response".into(),
                description: "the server returned a success status without a usable token response"
                    .into(),
            },
        };
    }

    let parsed: Option<OAuthErrorBody> = serde_json::from_str(body).ok();
    let error = parsed.as_ref().map(|e| e.error.as_str()).unwrap_or("");
    let description = parsed
        .as_ref()
        .map(|e| e.error_description.as_str())
        .unwrap_or("");

    match error {
        "authorization_pending" => PollResult::Pending,
        "slow_down" => PollResult::SlowDown,
        "access_denied" => PollResult::Denied,
        "expired_token" => PollResult::Expired,
        "invalid_grant" => PollResult::InvalidGrant,
        _ if status >= 500 || status == 429 => PollResult::Transient {
            status,
            message: if description.is_empty() {
                format!("HTTP {status}")
            } else {
                description.to_string()
            },
        },
        _ => PollResult::Fatal {
            status,
            error: if error.is_empty() {
                format!("http_{status}")
            } else {
                error.to_string()
            },
            description: description.to_string(),
        },
    }
}

/// Normalise `--scope` values into the space-delimited list the server wants.
///
/// Rejects `*`, `admin` and the OIDC scopes locally: the server refuses them,
/// and a local error is clearer than a round trip. Unknown AK scopes are left
/// to the server so the CLI does not need a copy of its scope registry.
pub(crate) fn normalize_scopes(requested: &[String]) -> Result<Vec<String>> {
    let mut scopes: Vec<String> = Vec::new();
    for raw in requested {
        for part in raw.split([',', ' ', '\t', '\n']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part == "*" || part == "admin" {
                return Err(AkError::ConfigError(
                    "the device grant cannot request '*' or 'admin'; ask for specific scopes such \
                     as read:artifacts or write:artifacts"
                        .into(),
                )
                .into());
            }
            if matches!(part, "openid" | "profile" | "email") {
                return Err(AkError::ConfigError(format!(
                    "scope '{part}' is an OIDC scope and is not available: Artifact Keeper's \
                     device grant issues AK-native tokens, not an id_token"
                ))
                .into());
            }
            if !scopes.iter().any(|existing| existing == part) {
                scopes.push(part.to_string());
            }
        }
    }
    if scopes.is_empty() {
        scopes.push(DEFAULT_SCOPE.to_string());
    }
    Ok(scopes)
}

/// The text shown before polling. Never includes the `device_code`.
pub(crate) fn prompt_text(code: &DeviceCodeResponse) -> String {
    format!(
        "To sign in, open {uri}\nand enter the code: {user_code}\n\n\
         Waiting for approval (expires in {} minutes)…",
        code.expires_in.div_ceil(60),
        uri = code.verification_uri,
        user_code = code.user_code,
    )
}

/// Whether this invocation should try to launch a browser.
///
/// Headless runs (`--no-input`, no TTY, CI, `AK_NO_BROWSER`) never do; the
/// printed URL and code are the fallback.
fn should_open_browser(no_input: bool) -> bool {
    if no_input || std::env::var_os(NO_BROWSER_ENV).is_some() {
        return false;
    }
    if std::env::var_os("CI").is_some() {
        return false;
    }
    std::io::IsTerminal::is_terminal(&std::io::stderr())
}

/// Best-effort browser launch. Failure is not an error: the URL was printed.
fn try_open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = std::process::Command::new("open");
        command.arg(url);
        command
    };

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", "start", ""]).arg(url);
        command
    };

    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(url);
        command
    };

    command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn device_endpoint(instance: &InstanceConfig, leaf: &str) -> String {
    let version = if instance.api_version.trim_matches('/').is_empty() {
        "v1"
    } else {
        instance.api_version.trim_matches('/')
    };
    format!(
        "{}/api/{version}/auth/device/{leaf}",
        instance.url.trim_end_matches('/')
    )
}

fn build_http_client() -> Result<reqwest::Client> {
    let builder = reqwest::ClientBuilder::new()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT);
    transport::apply_custom_ca(builder)?
        .build()
        .into_diagnostic()
}

fn oauth_failure(status: u16, body: &str, context: &str) -> AkError {
    if status == 404 {
        return AkError::ServerError(
            "device authorization is not enabled on this instance (HTTP 404); ask the \
             administrator to set DEVICE_AUTH_ENABLED=true"
                .into(),
        );
    }
    let parsed: Option<OAuthErrorBody> = serde_json::from_str(body).ok();
    match parsed {
        Some(error) if !error.error.is_empty() => {
            let detail = if error.error_description.is_empty() {
                error.error
            } else {
                format!("{}: {}", error.error, error.error_description)
            };
            AkError::ServerError(format!("{context} failed: {detail}"))
        }
        _ => AkError::ServerError(format!("{context} failed with HTTP {status}")),
    }
}

/// Start a device authorization flow.
pub(crate) async fn request_device_code(
    client: &reqwest::Client,
    code_url: &str,
    client_id: &str,
    scope: &str,
) -> Result<DeviceCodeResponse> {
    let response = client
        .post(code_url)
        .form(&[("client_id", client_id), ("scope", scope)])
        .send()
        .await
        .map_err(|error| {
            AkError::NetworkError(format!("device authorization request failed: {error}"))
        })?;

    let status = response.status().as_u16();
    let body = response.text().await.map_err(|error| {
        AkError::NetworkError(format!(
            "reading the device authorization response failed: {error}"
        ))
    })?;

    if !(200..300).contains(&status) {
        return Err(oauth_failure(status, &body, "device authorization request").into());
    }

    let code: DeviceCodeResponse = serde_json::from_str(&body).map_err(|error| {
        AkError::ServerError(format!(
            "device authorization request returned an invalid response: {error}"
        ))
    })?;

    if code.device_code.is_empty() || code.user_code.is_empty() || code.verification_uri.is_empty()
    {
        return Err(AkError::ServerError(
            "device authorization request returned an incomplete response".into(),
        )
        .into());
    }

    Ok(code)
}

/// Poll the token endpoint until the user decides, the code expires, or a
/// transient failure exhausts its retries.
pub(crate) async fn poll_for_tokens(
    client: &reqwest::Client,
    token_url: &str,
    code: &DeviceCodeResponse,
    client_id: &str,
    mut policy: PollPolicy,
) -> Result<TokenResponse> {
    let started = Instant::now();
    let mut transient_failures = 0u32;

    loop {
        if started.elapsed() >= policy.deadline {
            return Err(timed_out(&policy));
        }

        // RFC 8628 §3.5: wait the interval before *each* poll, including the
        // first one after the authorization request.
        tokio::time::sleep(policy.interval).await;
        if started.elapsed() >= policy.deadline {
            return Err(timed_out(&policy));
        }

        let response = client
            .post(token_url)
            .form(&[
                ("grant_type", DEVICE_GRANT_TYPE),
                ("device_code", code.device_code.as_str()),
                ("client_id", client_id),
            ])
            .send()
            .await;

        let response = match response {
            Ok(response) => response,
            Err(error) => {
                transient_failures += 1;
                if transient_failures > policy.max_transport_retries {
                    return Err(AkError::NetworkError(format!(
                        "device authorization polling failed after {transient_failures} attempt(s): \
                         {error}"
                    ))
                    .into());
                }
                backoff(&policy, transient_failures).await;
                continue;
            }
        };

        let status = response.status().as_u16();
        let body = match response.text().await {
            Ok(body) => body,
            Err(error) => {
                transient_failures += 1;
                if transient_failures > policy.max_transport_retries {
                    return Err(AkError::NetworkError(format!(
                        "reading the device token response failed after {transient_failures} \
                         attempt(s): {error}"
                    ))
                    .into());
                }
                backoff(&policy, transient_failures).await;
                continue;
            }
        };

        match classify_poll(status, &body) {
            PollResult::Success(tokens) => return Ok(tokens),
            PollResult::Pending => transient_failures = 0,
            PollResult::SlowDown => {
                // A slow_down is a successful exchange: the server is healthy,
                // we simply polled too fast.
                transient_failures = 0;
                policy.on_slow_down();
            }
            PollResult::Denied => {
                return Err(AkError::NotAuthenticated(
                    "the device authorization request was denied; run `ak auth login \
                     --oidc-device` again if this was a mistake"
                        .into(),
                )
                .into());
            }
            PollResult::Expired => {
                return Err(AkError::NotAuthenticated(
                    "the device code expired before it was approved; run `ak auth login \
                     --oidc-device` again"
                        .into(),
                )
                .into());
            }
            PollResult::InvalidGrant => {
                return Err(AkError::NotAuthenticated(
                    "the device code is invalid, was issued to another client, or has already \
                     been used; run `ak auth login --oidc-device` again"
                        .into(),
                )
                .into());
            }
            PollResult::Transient { status, message } => {
                transient_failures += 1;
                if transient_failures > policy.max_transport_retries {
                    return Err(AkError::ServerError(format!(
                        "device authorization polling failed after {transient_failures} attempt(s): \
                         HTTP {status} {message}"
                    ))
                    .into());
                }
                backoff(&policy, transient_failures).await;
            }
            PollResult::Fatal {
                status,
                error,
                description,
            } => {
                return Err(oauth_failure(
                    status,
                    &serde_json::json!({
                        "error": error,
                        "error_description": description,
                    })
                    .to_string(),
                    "device authorization polling",
                )
                .into());
            }
        }
    }
}

fn timed_out(policy: &PollPolicy) -> miette::Report {
    AkError::NotAuthenticated(format!(
        "timed out after {} seconds waiting for the device authorization to be approved; run \
         `ak auth login --oidc-device` again",
        policy.deadline.as_secs().max(1)
    ))
    .into()
}

async fn backoff(policy: &PollPolicy, failures: u32) {
    let factor = 1u32 << failures.saturating_sub(1).min(31);
    tokio::time::sleep(policy.interval.saturating_mul(factor)).await;
}

/// Run the full flow and store the resulting credential.
pub(crate) async fn login(
    instance_name: &str,
    instance: &InstanceConfig,
    requested_scopes: &[String],
    global: &GlobalArgs,
) -> Result<()> {
    login_with_policy(instance_name, instance, requested_scopes, global, None).await
}

async fn login_with_policy(
    instance_name: &str,
    instance: &InstanceConfig,
    requested_scopes: &[String],
    global: &GlobalArgs,
    policy: Option<PollPolicy>,
) -> Result<()> {
    // The device code is a bearer-like secret: it redeems for a refreshable
    // session. Refuse plaintext HTTP to a remote host for the same reason
    // password login does.
    if transport::classify_url(&instance.url) == transport::TransportSecurity::HttpRemote
        && !transport::insecure_http_allowed(instance)
    {
        return Err(AkError::InsecureTransport(instance.url.clone()).into());
    }
    transport::warn_if_insecure(instance_name, instance);

    let scopes = normalize_scopes(requested_scopes)?;
    let scope = scopes.join(" ");
    let client = build_http_client()?;

    let code = request_device_code(
        &client,
        &device_endpoint(instance, "code"),
        CLIENT_ID,
        &scope,
    )
    .await?;

    eprintln!("{}", prompt_text(&code));
    if should_open_browser(global.no_input) {
        let _ = try_open_browser(&code.verification_uri);
    }

    let policy = policy.unwrap_or_else(|| PollPolicy::from_server(code.interval, code.expires_in));
    let tokens = poll_for_tokens(
        &client,
        &device_endpoint(instance, "token"),
        &code,
        CLIENT_ID,
        policy,
    )
    .await?;

    let credential = StoredCredential {
        access_token: tokens.access_token.clone(),
        refresh_token: tokens
            .refresh_token
            .clone()
            .filter(|token| !token.is_empty()),
    };

    // Confirm the account before persisting anything, mirroring
    // `login_with_token`: a token the server will not accept must not replace
    // a working credential.
    let sdk_client =
        crate::commands::client::build_client(instance_name, instance, Some(&credential))?;
    let user = sdk_client
        .get_current_user()
        .send()
        .await
        .map_err(|error| {
            AkError::NotAuthenticated(format!(
                "device authorization succeeded but confirming the account failed: {error}"
            ))
        })?;

    store_credential(instance_name, &credential)?;

    if !matches!(global.format, OutputFormat::Quiet) {
        eprintln!(
            "Logged in to '{instance_name}' as {} ({})",
            user.username, user.email
        );
        if !tokens.scope.is_empty() {
            eprintln!("Granted scopes: {}", tokens.scope);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::config::credentials::get_credential;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_policy() -> PollPolicy {
        PollPolicy {
            interval: Duration::from_millis(5),
            max_interval: Duration::from_millis(200),
            deadline: Duration::from_secs(2),
            slow_down_step: Duration::from_millis(5),
            max_transport_retries: 1,
        }
    }

    fn code_json(server: &MockServer) -> serde_json::Value {
        json!({
            "device_code": "device-secret-code",
            "user_code": "BCDF-GHJK",
            "verification_uri": format!("{}/device", server.uri()),
            "expires_in": 60,
            "interval": 0
        })
    }

    fn token_json() -> serde_json::Value {
        json!({
            "access_token": "device-access-token",
            "token_type": "Bearer",
            "expires_in": 1800,
            "refresh_token": "device-refresh-token",
            "scope": "read:artifacts"
        })
    }

    fn user_json() -> serde_json::Value {
        json!({
            "id": "00000000-0000-0000-0000-000000000000",
            "username": "alice",
            "email": "alice@example.com",
            "display_name": "Alice",
            "is_admin": false,
            "totp_enabled": false,
            "created_at": "2026-01-15T12:00:00Z",
            "updated_at": "2026-01-15T12:00:00Z"
        })
    }

    async fn mount_code(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/device/code"))
            .and(body_string_contains("client_id=ak-cli"))
            .respond_with(ResponseTemplate::new(200).set_body_json(code_json(server)))
            .mount(server)
            .await;
    }

    async fn mount_poll(server: &MockServer, status: u16, body: serde_json::Value, priority: u8) {
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/device/token"))
            .and(body_string_contains("device_code=device-secret-code"))
            .and(body_string_contains("client_id=ak-cli"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .with_priority(priority)
            .up_to_n_times(1)
            .mount(server)
            .await;
    }

    async fn mount_me(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(user_json()))
            .mount(server)
            .await;
    }

    /// Use a process-unique credential-store key so these tests never touch
    /// the `test` entry the other auth tests read from the OS keychain.
    async fn instance_and_global() -> (String, InstanceConfig, GlobalArgs) {
        let config = AppConfig::load().expect("config");
        let (_, instance) = config.resolve_instance(Some("test")).expect("instance");
        (
            format!("device-test-{}", std::process::id()),
            instance.clone(),
            crate::test_utils::test_global(OutputFormat::Json),
        )
    }

    #[test]
    fn default_scope_is_read_artifacts() {
        assert_eq!(normalize_scopes(&[]).unwrap(), vec![DEFAULT_SCOPE]);
    }

    #[test]
    fn scopes_are_split_deduped_and_trimmed() {
        let scopes = normalize_scopes(&[
            "read:artifacts, write:artifacts".into(),
            "read:artifacts".into(),
            "  delete:artifacts  ".into(),
        ])
        .unwrap();
        assert_eq!(
            scopes,
            vec!["read:artifacts", "write:artifacts", "delete:artifacts"]
        );
    }

    #[test]
    fn wildcard_and_admin_scopes_are_refused_locally() {
        for scope in ["*", "admin", "read:artifacts,*"] {
            let error = normalize_scopes(&[scope.into()]).unwrap_err().to_string();
            assert!(error.contains("cannot request"), "{scope}: {error}");
        }
    }

    #[test]
    fn oidc_scopes_are_refused_with_an_explanation() {
        for scope in ["openid", "profile", "email"] {
            let error = normalize_scopes(&[scope.into()]).unwrap_err().to_string();
            assert!(error.contains("OIDC scope"), "{scope}: {error}");
        }
    }

    #[test]
    fn pending_and_slow_down_are_not_errors() {
        assert_eq!(
            classify_poll(400, r#"{"error":"authorization_pending"}"#),
            PollResult::Pending
        );
        assert_eq!(
            classify_poll(400, r#"{"error":"slow_down"}"#),
            PollResult::SlowDown
        );
    }

    #[test]
    fn terminal_oauth_errors_are_classified() {
        assert_eq!(
            classify_poll(400, r#"{"error":"access_denied"}"#),
            PollResult::Denied
        );
        assert_eq!(
            classify_poll(400, r#"{"error":"expired_token"}"#),
            PollResult::Expired
        );
        assert_eq!(
            classify_poll(400, r#"{"error":"invalid_grant"}"#),
            PollResult::InvalidGrant
        );
    }

    #[test]
    fn server_errors_are_transient_and_unknown_400s_are_fatal() {
        assert!(matches!(
            classify_poll(503, "upstream unavailable"),
            PollResult::Transient { status: 503, .. }
        ));
        assert!(matches!(
            classify_poll(400, r#"{"error":"invalid_scope"}"#),
            PollResult::Fatal { status: 400, .. }
        ));
    }

    #[test]
    fn a_success_status_without_a_token_is_fatal() {
        assert!(matches!(classify_poll(200, "{}"), PollResult::Fatal { .. }));
    }

    #[test]
    fn slow_down_grows_the_interval_by_five_seconds() {
        let mut policy = PollPolicy::from_server(5, 600);
        policy.on_slow_down();
        assert_eq!(policy.interval, Duration::from_secs(10));
        for _ in 0..20 {
            policy.on_slow_down();
        }
        assert_eq!(policy.interval, Duration::from_secs(60));
    }

    #[test]
    fn prompt_shows_the_url_and_code_but_never_the_device_code() {
        let code = DeviceCodeResponse {
            device_code: "super-secret-device-code".into(),
            user_code: "BCDF-GHJK".into(),
            verification_uri: "https://registry.example.com/device".into(),
            expires_in: 600,
            interval: 5,
        };
        let prompt = prompt_text(&code);
        assert!(prompt.contains("https://registry.example.com/device"));
        assert!(prompt.contains("BCDF-GHJK"));
        assert!(!prompt.contains("super-secret-device-code"));
    }

    #[tokio::test]
    async fn pending_then_success_stores_access_and_refresh_tokens() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mount_code(&server).await;
        mount_poll(
            &server,
            400,
            json!({"error": "authorization_pending", "error_description": "wait"}),
            1,
        )
        .await;
        mount_poll(&server, 200, token_json(), 2).await;
        mount_me(&server).await;

        let (name, instance, global) = instance_and_global().await;
        let result = login_with_policy(&name, &instance, &[], &global, Some(test_policy())).await;
        assert!(result.is_ok(), "{:?}", result.err());

        unsafe { std::env::remove_var("AK_TOKEN") };
        let credential = get_credential(&name).expect("stored credential");
        assert_eq!(credential.access_token, "device-access-token");
        assert_eq!(
            credential.refresh_token.as_deref(),
            Some("device-refresh-token")
        );

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn slow_down_then_success_completes() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mount_code(&server).await;
        mount_poll(
            &server,
            400,
            json!({"error": "slow_down", "error_description": "too fast"}),
            1,
        )
        .await;
        mount_poll(&server, 200, token_json(), 2).await;
        mount_me(&server).await;

        let (name, instance, global) = instance_and_global().await;
        let result = login_with_policy(&name, &instance, &[], &global, Some(test_policy())).await;
        assert!(result.is_ok(), "{:?}", result.err());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn denial_is_a_clear_error() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mount_code(&server).await;
        mount_poll(
            &server,
            400,
            json!({"error": "access_denied", "error_description": "no"}),
            1,
        )
        .await;

        let (name, instance, global) = instance_and_global().await;
        let error = login_with_policy(&name, &instance, &[], &global, Some(test_policy()))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("denied"), "{error}");
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn expired_token_is_a_clear_error() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mount_code(&server).await;
        mount_poll(
            &server,
            400,
            json!({"error": "expired_token", "error_description": "expired"}),
            1,
        )
        .await;

        let (name, instance, global) = instance_and_global().await;
        let error = login_with_policy(&name, &instance, &[], &global, Some(test_policy()))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("expired"), "{error}");
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn local_deadline_stops_a_pending_flow() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mount_code(&server).await;
        // Deliberately not limited: the flow must keep polling until its own
        // deadline rather than treat a second poll as a fresh mock miss.
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/device/token"))
            .and(body_string_contains("device_code=device-secret-code"))
            .respond_with(ResponseTemplate::new(400).set_body_json(
                json!({"error": "authorization_pending", "error_description": "wait"}),
            ))
            .mount(&server)
            .await;

        let (name, instance, global) = instance_and_global().await;
        let mut policy = test_policy();
        policy.deadline = Duration::from_millis(30);
        let error = login_with_policy(&name, &instance, &[], &global, Some(policy))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("timed out"), "{error}");
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn reused_or_unknown_code_is_a_clear_error() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        mount_code(&server).await;
        mount_poll(
            &server,
            400,
            json!({"error": "invalid_grant", "error_description": "used"}),
            1,
        )
        .await;

        let (name, instance, global) = instance_and_global().await;
        let error = login_with_policy(&name, &instance, &[], &global, Some(test_policy()))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("already"), "{error}");
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn a_disabled_server_explains_the_404() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/device/code"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let (name, instance, global) = instance_and_global().await;
        let error = login_with_policy(&name, &instance, &[], &global, Some(test_policy()))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("DEVICE_AUTH_ENABLED"), "{error}");
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn network_failure_is_reported() {
        let client = reqwest::Client::new();
        let code = DeviceCodeResponse {
            device_code: "device-secret-code".into(),
            user_code: "BCDF-GHJK".into(),
            verification_uri: "http://127.0.0.1:1/device".into(),
            expires_in: 60,
            interval: 0,
        };
        let mut policy = test_policy();
        policy.max_transport_retries = 0;
        let error = poll_for_tokens(
            &client,
            "http://127.0.0.1:1/api/v1/auth/device/token",
            &code,
            CLIENT_ID,
            policy,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("Network error"), "{error}");
    }

    #[tokio::test]
    async fn repeated_server_errors_exhaust_their_retries() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/device/token"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&server)
            .await;

        let client = build_http_client().expect("client");
        let code = DeviceCodeResponse {
            device_code: "device-secret-code".into(),
            user_code: "BCDF-GHJK".into(),
            verification_uri: "https://registry.example.com/device".into(),
            expires_in: 60,
            interval: 0,
        };
        let mut policy = test_policy();
        policy.max_transport_retries = 1;
        let error = poll_for_tokens(
            &client,
            &format!("{}/api/v1/auth/device/token", server.uri()),
            &code,
            CLIENT_ID,
            policy,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("HTTP 503"), "{error}");
        crate::test_utils::teardown_env();
    }

    #[test]
    fn headless_and_ci_runs_do_not_open_a_browser() {
        assert!(!should_open_browser(true));
    }
}
