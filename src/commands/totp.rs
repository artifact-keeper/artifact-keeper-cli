use artifact_keeper_sdk::ClientAuthExt;
use artifact_keeper_sdk::types::{
    TotpCodeRequest, TotpDisableRequest, TotpEnableResponse, TotpSetupResponse,
};
use clap::Subcommand;
use miette::Result;
use serde_json::Value;

use super::client::client_for;
use super::helpers::sdk_err;
use crate::cli::GlobalArgs;
use crate::error::AkError;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum TotpCommand {
    /// Set up TOTP (displays secret and QR code URL)
    Setup,

    /// Enable TOTP after verifying authenticator code
    Enable {
        /// Six-digit code from your authenticator app
        #[arg(long)]
        code: String,
    },

    /// Disable TOTP (requires password and current code)
    Disable {
        /// Account password (omit to enter interactively)
        #[arg(long)]
        password: Option<String>,

        /// Six-digit code from your authenticator app (omit to enter interactively)
        #[arg(long)]
        code: Option<String>,
    },

    /// Check whether TOTP is currently enabled
    Status,
}

impl TotpCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Setup => setup(global).await,
            Self::Enable { code } => enable(&code, global).await,
            Self::Disable { password, code } => disable(password, code, global).await,
            Self::Status => status(global).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Handler functions
// ---------------------------------------------------------------------------

async fn setup(global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Setting up TOTP...");

    let resp = client
        .setup_totp()
        .send()
        .await
        .map_err(|e| sdk_err("set up TOTP", e))?;
    let result = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", result.secret);
        return Ok(());
    }

    let (info, table_str) = format_setup_result(&result);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn enable(code: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Enabling TOTP...");

    let body = TotpCodeRequest {
        code: code.to_string(),
    };

    let resp = client
        .enable_totp()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("enable TOTP", e))?;
    let result = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        for bc in &result.backup_codes {
            println!("{bc}");
        }
        return Ok(());
    }

    let (info, table_str) = format_backup_codes(&result);
    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn disable(
    password: Option<String>,
    code: Option<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let password = match password {
        Some(p) => p,
        None => {
            if global.no_input {
                return Err(AkError::ConfigError(
                    "TOTP disable requires interactive input. Provide --password and --code, or remove --no-input.".to_string(),
                ).into());
            }
            dialoguer::Password::new()
                .with_prompt("Account password")
                .interact()
                .map_err(|e| AkError::ConfigError(format!("Failed to read password: {e}")))?
        }
    };

    let code = match code {
        Some(c) => c,
        None => {
            if global.no_input {
                return Err(AkError::ConfigError(
                    "TOTP disable requires interactive input. Provide --password and --code, or remove --no-input.".to_string(),
                ).into());
            }
            dialoguer::Input::new()
                .with_prompt("TOTP code")
                .interact_text()
                .map_err(|e| AkError::ConfigError(format!("Failed to read code: {e}")))?
        }
    };

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

    let user = client
        .get_current_user()
        .send()
        .await
        .map_err(|e| sdk_err("get current user", e))?;
    let user = user.into_inner();
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
        if let TotpCommand::Enable { code } = cli.command {
            assert_eq!(code, "123456");
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
        if let TotpCommand::Disable { password, code } = cli.command {
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
    fn parse_enable_missing_code() {
        let result = TestCli::try_parse_from(&["test", "enable"]);
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
    async fn handler_disable() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/totp/disable"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(crate::output::OutputFormat::Json);
        let result = disable(Some("mypassword".into()), Some("654321".into()), &global).await;
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
