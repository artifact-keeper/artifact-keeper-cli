use artifact_keeper_sdk::ClientAuthExt;
use artifact_keeper_sdk::types::{
    TotpCodeRequest, TotpDisableRequest, TotpEnableResponse, TotpEnrollCompleteRequest,
    TotpEnrollCompleteResponse, TotpEnrollSetupRequest, TotpSetupResponse,
};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::{anon_client, client_for};
use super::helpers::{require_secret, resolve_secret, sdk_err};
use crate::cli::GlobalArgs;
use crate::config::AppConfig;
use crate::config::credentials::{StoredCredential, store_credential};
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum TotpCommand {
    /// Set up TOTP (displays secret and QR code URL)
    Setup,

    /// Enable TOTP after verifying authenticator code
    Enable {
        /// Six-digit code from your authenticator app (omit to use --code-stdin or a
        /// prompt)
        #[arg(long)]
        code: Option<String>,

        /// Read the code from stdin
        #[arg(long)]
        code_stdin: bool,
    },

    /// Disable TOTP (requires password and current code)
    Disable {
        /// Account password. Prefer --password-stdin, AK_PASSWORD or the prompt, which
        /// keep it out of shell history
        #[arg(long, env = "AK_PASSWORD", hide_env_values = true)]
        password: Option<String>,

        /// Read the password from stdin
        #[arg(long, conflicts_with = "code_stdin")]
        password_stdin: bool,

        /// Six-digit code from your authenticator app (omit to use --code-stdin or a
        /// prompt)
        #[arg(long)]
        code: Option<String>,

        /// Read the code from stdin
        #[arg(long)]
        code_stdin: bool,
    },

    /// Check whether TOTP is currently enabled
    Status,

    /// Set up TOTP during a login, when the server's policy requires it before you
    /// get a session. The ticket comes from `ak auth login --print-totp-ticket`
    Enroll {
        #[command(subcommand)]
        command: EnrollCommand,
    },
}

#[derive(Subcommand)]
pub enum EnrollCommand {
    /// Start: prints the secret to add to your authenticator app
    Setup {
        #[command(flatten)]
        ticket: TicketArgs,
    },

    /// Finish with a code from the app: logs you in and prints your backup codes
    Complete {
        #[command(flatten)]
        ticket: TicketArgs,

        /// Six-digit code from your authenticator app (omit to use a prompt)
        #[arg(long)]
        code: Option<String>,

        /// Read the code from stdin
        #[arg(long, conflicts_with = "totp_token_stdin")]
        code_stdin: bool,
    },
}

#[derive(clap::Args)]
pub struct TicketArgs {
    /// The one-time ticket. Prefer --totp-token-stdin or AK_TOTP_TOKEN
    #[arg(long, env = "AK_TOTP_TOKEN", hide_env_values = true)]
    totp_token: Option<String>,

    /// Read the ticket from stdin
    #[arg(long)]
    totp_token_stdin: bool,
}

impl TicketArgs {
    fn resolve(self, global: &GlobalArgs) -> Result<String> {
        require_secret(
            resolve_secret(
                self.totp_token,
                self.totp_token_stdin,
                "--totp-token",
                None,
                global.no_input,
            )?,
            "The one-time ticket",
            "--totp-token-stdin or AK_TOTP_TOKEN",
        )
    }
}

fn resolve_code(code: Option<String>, from_stdin: bool, global: &GlobalArgs) -> Result<String> {
    require_secret(
        resolve_secret(
            code,
            from_stdin,
            "--code",
            Some("TOTP code"),
            global.no_input,
        )?,
        "The TOTP code",
        "--code-stdin",
    )
}

impl TotpCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Setup => setup(global).await,
            Self::Enable { code, code_stdin } => {
                let code = resolve_code(code, code_stdin, global)?;
                enable(&code, global).await
            }
            Self::Disable {
                password,
                password_stdin,
                code,
                code_stdin,
            } => {
                let password = require_secret(
                    resolve_secret(
                        password,
                        password_stdin,
                        "--password",
                        Some("Account password"),
                        global.no_input,
                    )?,
                    "The account password",
                    "--password-stdin or AK_PASSWORD",
                )?;
                let code = resolve_code(code, code_stdin, global)?;
                disable(password, code, global).await
            }
            Self::Status => status(global).await,
            Self::Enroll { command } => match command {
                EnrollCommand::Setup { ticket } => {
                    let ticket = ticket.resolve(global)?;
                    enroll_setup(&ticket, global).await
                }
                EnrollCommand::Complete {
                    ticket,
                    code,
                    code_stdin,
                } => {
                    let ticket = ticket.resolve(global)?;
                    let code = resolve_code(code, code_stdin, global)?;
                    enroll_complete(&ticket, &code, global).await
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Handler functions
// ---------------------------------------------------------------------------

async fn setup(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Setting up TOTP...");

    let (resp, raw) = artifact_keeper_sdk::raw::capture(client.setup_totp().send()).await;
    let result = resp.map_err(|e| sdk_err("set up TOTP", e))?.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", result.secret);
        return Ok(());
    }

    let (info, table_str) = format_setup_result(&result);
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn enable(code: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Enabling TOTP...");

    let body = TotpCodeRequest {
        code: code.to_string(),
    };

    let (resp, raw) =
        artifact_keeper_sdk::raw::capture(client.enable_totp().body(body).send()).await;
    let result = resp.map_err(|e| sdk_err("enable TOTP", e))?.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        for bc in &result.backup_codes {
            println!("{bc}");
        }
        return Ok(());
    }

    let (info, table_str) = format_backup_codes(&result);
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn disable(password: String, code: String, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Disabling TOTP...");

    let body = TotpDisableRequest { password, code };

    client
        .disable_totp()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("disable TOTP", e))?;
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        return Ok(());
    }

    let info = serde_json::json!({ "totp_disabled": true });
    let table_str = "TOTP has been disabled for your account.".to_string();
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn status(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Checking TOTP status...");

    let (user, raw) = artifact_keeper_sdk::raw::capture(client.get_current_user().send()).await;
    let user = user
        .map_err(|e| sdk_err("get current user", e))?
        .into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!(
            "{}",
            if user.totp_enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        return Ok(());
    }

    let info = serde_json::json!({
        "username": user.username,
        "totp_enabled": user.totp_enabled,
    });

    let status_text = if user.totp_enabled {
        "enabled"
    } else {
        "disabled"
    };
    let table_str = format!("User:   {}\nTOTP:   {}", user.username, status_text,);

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

/// `POST /auth/totp/enroll/setup`. The ticket in the body is the only credential.
pub(crate) async fn enroll_setup_request(
    client: &artifact_keeper_sdk::Client,
    ticket: &str,
) -> Result<TotpSetupResponse> {
    let body = TotpEnrollSetupRequest {
        totp_token: ticket.to_string(),
    };
    let resp = client
        .enroll_setup()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("start TOTP enrollment", e))?;
    Ok(resp.into_inner())
}

/// `POST /auth/totp/enroll/complete`. The ticket in the body is the only credential.
pub(crate) async fn enroll_complete_request(
    client: &artifact_keeper_sdk::Client,
    ticket: &str,
    code: &str,
) -> Result<TotpEnrollCompleteResponse> {
    let body = TotpEnrollCompleteRequest {
        totp_token: ticket.to_string(),
        code: code.to_string(),
    };
    let resp = client
        .enroll_complete()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("complete TOTP enrollment", e))?;
    Ok(resp.into_inner())
}

async fn enroll_setup(ticket: &str, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (_, instance) = config.resolve_instance(global.instance.as_deref())?;
    let result = enroll_setup_request(&anon_client(&instance.url)?, ticket).await?;

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", result.secret);
        return Ok(());
    }
    let (info, _) = format_setup_result(&result);
    let table_str = format!(
        "TOTP Secret:    {}\n\
         QR Code URL:    {}\n\n\
         Add this secret to your authenticator app, then run:\n  \
         ak totp enroll complete --totp-token-stdin --code <code>",
        result.secret, result.qr_code_url,
    );
    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

async fn enroll_complete(ticket: &str, code: &str, global: &GlobalArgs) -> Result<()> {
    let config = AppConfig::load()?;
    let (instance_name, instance) = config.resolve_instance(global.instance.as_deref())?;
    let done = enroll_complete_request(&anon_client(&instance.url)?, ticket, code).await?;

    store_credential(
        instance_name,
        &StoredCredential {
            access_token: done.access_token.clone(),
            refresh_token: Some(done.refresh_token.clone()),
        },
    )?;
    eprintln!("Two-factor login is on, and you're logged in to '{instance_name}'.");

    if matches!(global.format, OutputFormat::Quiet) {
        for code in &done.backup_codes {
            println!("{code}");
        }
        return Ok(());
    }
    // Not the server's body: it holds the session tokens, which were just stored.
    let info = serde_json::json!({
        "backup_codes": done.backup_codes,
        "must_change_password": done.must_change_password,
    });
    let (_, table_str) = format_backup_codes(&TotpEnableResponse {
        backup_codes: done.backup_codes.clone(),
    });
    println!("{}", output::render(&info, &global.format, Some(table_str)));
    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_setup_result(resp: &TotpSetupResponse) -> (Value, String) {
    let info = serde_json::json!({
        "secret": resp.secret,
        "qr_code_url": resp.qr_code_url,
    });

    let table_str = format!(
        "TOTP Secret:    {}\n\
         QR Code URL:    {}\n\n\
         Add this secret to your authenticator app, then run:\n  \
         ak totp enable --code <code>",
        resp.secret, resp.qr_code_url,
    );

    (info, table_str)
}

fn format_backup_codes(resp: &TotpEnableResponse) -> (Value, String) {
    let info = serde_json::json!({
        "totp_enabled": true,
        "backup_codes": resp.backup_codes,
    });

    let table_str = if resp.backup_codes.is_empty() {
        "TOTP is now enabled. No backup codes were generated.".to_string()
    } else {
        let codes: Vec<String> = resp.backup_codes.iter().map(|c| format!("  {c}")).collect();
        format!(
            "TOTP is now enabled.\n\n\
             Backup codes (save these somewhere safe):\n{}\n\n\
             Each code can only be used once.",
            codes.join("\n"),
        )
    };

    (info, table_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: TotpCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    // ---- Parsing tests ----

    #[test]
    fn parse_setup() {
        let cli = parse(&["test", "setup"]);
        assert!(matches!(cli.command, TotpCommand::Setup));
    }

    #[test]
    fn parse_enable() {
        let cli = parse(&["test", "enable", "--code", "123456"]);
        if let TotpCommand::Enable { code, .. } = cli.command {
            assert_eq!(code.as_deref(), Some("123456"));
        } else {
            panic!("Expected Enable");
        }
    }

    #[test]
    fn parse_disable() {
        let cli = parse(&[
            "test",
            "disable",
            "--password",
            "placeholder",
            "--code",
            "654321",
        ]);
        if let TotpCommand::Disable { password, code, .. } = cli.command {
            assert_eq!(password.unwrap(), "placeholder");
            assert_eq!(code.unwrap(), "654321");
        } else {
            panic!("Expected Disable");
        }
    }

    #[test]
    fn parse_status() {
        let cli = parse(&["test", "status"]);
        assert!(matches!(cli.command, TotpCommand::Status));
    }

    #[test]
    fn parse_enable_takes_the_code_from_stdin() {
        let cli = parse(&["test", "enable", "--code-stdin"]);
        assert!(matches!(
            cli.command,
            TotpCommand::Enable {
                code: None,
                code_stdin: true
            }
        ));
    }

    #[test]
    fn parse_disable_cannot_read_both_secrets_from_stdin() {
        let result =
            TestCli::try_parse_from(["test", "disable", "--password-stdin", "--code-stdin"]);
        assert!(result.is_err());
    }

    // ---- Format function tests ----

    #[test]
    fn format_setup_result_displays_secret_and_url() {
        let resp = TotpSetupResponse {
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            qr_code_url: "otpauth://totp/AK:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AK"
                .to_string(),
        };
        let (info, table_str) = format_setup_result(&resp);

        assert_eq!(info["secret"], "JBSWY3DPEHPK3PXP");
        assert_eq!(
            info["qr_code_url"],
            "otpauth://totp/AK:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AK"
        );

        assert!(table_str.contains("JBSWY3DPEHPK3PXP"));
        assert!(table_str.contains("otpauth://"));
        assert!(table_str.contains("ak totp enable --code"));
    }

    #[test]
    fn format_backup_codes_populated() {
        let resp = TotpEnableResponse {
            backup_codes: vec![
                "abc123".to_string(),
                "def456".to_string(),
                "ghi789".to_string(),
            ],
        };
        let (info, table_str) = format_backup_codes(&resp);

        assert_eq!(info["totp_enabled"], true);
        assert_eq!(info["backup_codes"].as_array().unwrap().len(), 3);

        assert!(table_str.contains("TOTP is now enabled"));
        assert!(table_str.contains("abc123"));
        assert!(table_str.contains("def456"));
        assert!(table_str.contains("ghi789"));
        assert!(table_str.contains("save these somewhere safe"));
    }

    #[test]
    fn format_backup_codes_empty() {
        let resp = TotpEnableResponse {
            backup_codes: vec![],
        };
        let (info, table_str) = format_backup_codes(&resp);

        assert_eq!(info["totp_enabled"], true);
        assert!(info["backup_codes"].as_array().unwrap().is_empty());

        assert!(table_str.contains("No backup codes were generated"));
    }

    #[test]
    fn format_setup_result_json_keys() {
        let resp = TotpSetupResponse {
            secret: "SECRET".to_string(),
            qr_code_url: "https://example.com/qr".to_string(),
        };
        let (info, _) = format_setup_result(&resp);

        // Verify both JSON keys exist
        assert!(info.get("secret").is_some());
        assert!(info.get("qr_code_url").is_some());
    }

    // ---- wiremock handler tests ----

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    #[tokio::test]
    async fn handler_setup() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/totp/setup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "secret": "JBSWY3DPEHPK3PXP",
                "qr_code_url": "otpauth://totp/AK:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AK"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = setup(&global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_enable() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/totp/enable"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "backup_codes": ["abc123", "def456", "ghi789"]
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = enable("123456", &global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_status() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/auth/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "username": "alice",
                "email": "alice@example.com",
                "display_name": "Alice",
                "is_admin": false,
                "totp_enabled": true
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = status(&global).await;
        assert!(result.is_ok());

        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_totp_setup_json() {
        let data = json!({
            "secret": "JBSWY3DPEHPK3PXP",
            "qr_code_url": "otpauth://totp/AK:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AK"
        });
        let output = crate::output::render(&data, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("totp_setup_json", parsed);
    }
}
