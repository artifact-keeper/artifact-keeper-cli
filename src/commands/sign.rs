use artifact_keeper_sdk::ClientSigningExt;
use artifact_keeper_sdk::types::{SigningConfigResponse, SigningKeyPublic};
use clap::Subcommand;
use futures::StreamExt;
use miette::{IntoDiagnostic, Result};
use serde_json::Value;

use super::client::client_for;
use super::helpers::{
    confirm_action, new_table, parse_optional_uuid, parse_uuid, sdk_err, short_id,
};
use crate::cli::GlobalArgs;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum SignCommand {
    /// Manage signing keys
    #[command(subcommand)]
    Key(SignKeyCommand),

    /// Manage repository signing configuration
    #[command(subcommand)]
    Config(SignConfigCommand),
}

#[derive(Subcommand)]
pub enum SignKeyCommand {
    /// List all signing keys
    List {
        /// Filter by repository ID
        #[arg(long)]
        repo: Option<String>,
    },

    /// Show signing key details
    Show {
        /// Signing key ID
        id: String,
    },

    /// Create a new signing key
    Create {
        /// Key name
        name: String,

        /// Algorithm (e.g. ed25519, rsa-4096, ecdsa-p256)
        #[arg(long)]
        algorithm: String,

        /// Key type (e.g. signing, encryption)
        #[arg(long = "type")]
        key_type: String,

        /// Repository ID to associate with this key
        #[arg(long)]
        repo: String,

        /// UID email for the key
        #[arg(long)]
        uid_email: Option<String>,

        /// UID name for the key
        #[arg(long)]
        uid_name: Option<String>,
    },

    /// Delete a signing key
    Delete {
        /// Signing key ID
        id: String,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },

    /// Revoke (deactivate) a signing key
    Revoke {
        /// Signing key ID
        id: String,
    },

    /// Rotate a signing key (generates new key, deactivates old)
    Rotate {
        /// Signing key ID to rotate
        id: String,
    },

    /// Export the public key in PEM format
    Export {
        /// Signing key ID
        id: String,
    },
}

#[derive(Subcommand)]
pub enum SignConfigCommand {
    /// Show signing configuration for a repository
    Show {
        /// Repository ID
        repo_id: String,
    },

    /// Update signing configuration for a repository
    Update {
        /// Repository ID
        repo_id: String,

        /// Require signatures on all uploads
        #[arg(long)]
        require_signatures: bool,

        /// Sign package metadata
        #[arg(long)]
        sign_metadata: bool,

        /// Sign packages
        #[arg(long)]
        sign_packages: bool,

        /// Signing key ID to use
        #[arg(long)]
        signing_key_id: Option<String>,
    },

    /// Export the repository's public key in PEM format
    ExportKey {
        /// Repository ID
        repo_id: String,
    },
}

impl SignCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Key(cmd) => cmd.execute(global).await,
            Self::Config(cmd) => cmd.execute(global).await,
        }
    }
}

impl SignKeyCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::List { repo } => list_keys(repo.as_deref(), global).await,
            Self::Show { id } => show_key(&id, global).await,
            Self::Create {
                name,
                algorithm,
                key_type,
                repo,
                uid_email,
                uid_name,
            } => {
                create_key(
                    &name,
                    &algorithm,
                    &key_type,
                    &repo,
                    uid_email.as_deref(),
                    uid_name.as_deref(),
                    global,
                )
                .await
            }
            Self::Delete { id, yes } => delete_key(&id, yes, global).await,
            Self::Revoke { id } => revoke_key(&id, global).await,
            Self::Rotate { id } => rotate_key(&id, global).await,
            Self::Export { id } => export_key(&id, global).await,
        }
    }
}

impl SignConfigCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Show { repo_id } => show_config(&repo_id, global).await,
            Self::Update {
                repo_id,
                require_signatures,
                sign_metadata,
                sign_packages,
                signing_key_id,
            } => {
                update_config(
                    &repo_id,
                    require_signatures,
                    sign_metadata,
                    sign_packages,
                    signing_key_id.as_deref(),
                    global,
                )
                .await
            }
            Self::ExportKey { repo_id } => export_repo_key(&repo_id, global).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Key handlers
// ---------------------------------------------------------------------------

async fn list_keys(repo: Option<&str>, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let spinner = output::spinner("Fetching signing keys...");

    let repo_id = parse_optional_uuid(repo, "repository")?;

    let mut req = client.list_keys();
    if let Some(rid) = repo_id {
        req = req.repository_id(rid);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| sdk_err("list signing keys", e))?;

    let resp = resp.into_inner();
    spinner.finish_and_clear();

    if resp.keys.is_empty() {
        eprintln!("No signing keys found.");
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Quiet) {
        for key in &resp.keys {
            println!("{}", key.id);
        }
        return Ok(());
    }

    let (entries, table_str) = format_keys_table(&resp.keys);

    println!(
        "{}",
        output::render(&entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_key(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let key_id = parse_uuid(id, "signing key")?;

    let spinner = output::spinner("Fetching signing key...");
    let key = client
        .get_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|e| sdk_err("get signing key", e))?;

    let key = key.into_inner();
    spinner.finish_and_clear();

    let (info, table_str) = format_key_detail(&key);

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn create_key(
    name: &str,
    algorithm: &str,
    key_type: &str,
    repo: &str,
    uid_email: Option<&str>,
    uid_name: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let repo_id = parse_uuid(repo, "repository")?;

    let spinner = output::spinner("Creating signing key...");

    let body = artifact_keeper_sdk::types::CreateKeyPayload {
        name: name.to_string(),
        algorithm: Some(algorithm.to_string()),
        key_type: Some(key_type.to_string()),
        repository_id: Some(repo_id),
        uid_email: uid_email.map(|s| s.to_string()),
        uid_name: uid_name.map(|s| s.to_string()),
    };

    let key = client
        .create_key()
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("create signing key", e))?;

    let key = key.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", key.id);
        return Ok(());
    }

    eprintln!("Signing key '{}' created (ID: {}).", key.name, key.id);

    Ok(())
}

async fn delete_key(id: &str, skip_confirm: bool, global: &GlobalArgs) -> Result<()> {
    let key_id = parse_uuid(id, "signing key")?;

    if !confirm_action(
        &format!("Delete signing key {id}?"),
        skip_confirm,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Deleting signing key...");

    client
        .delete_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|e| sdk_err("delete signing key", e))?;

    spinner.finish_and_clear();
    eprintln!("Signing key {id} deleted.");

    Ok(())
}

async fn revoke_key(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let key_id = parse_uuid(id, "signing key")?;

    let spinner = output::spinner("Revoking signing key...");

    let resp = client
        .revoke_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|e| sdk_err("revoke signing key", e))?;

    let result = resp.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        return Ok(());
    }

    if matches!(global.format, OutputFormat::Json | OutputFormat::Yaml) {
        let val = serde_json::Value::Object(result);
        println!("{}", output::render(&val, &global.format, None));
    } else {
        eprintln!("Signing key {id} revoked.");
    }

    Ok(())
}

async fn rotate_key(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let key_id = parse_uuid(id, "signing key")?;

    let spinner = output::spinner("Rotating signing key...");

    let key = client
        .rotate_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|e| sdk_err("rotate signing key", e))?;

    let key = key.into_inner();
    spinner.finish_and_clear();

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", key.id);
        return Ok(());
    }

    eprintln!("Key rotated. New key '{}' (ID: {}).", key.name, key.id);

    Ok(())
}

async fn export_key(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let key_id = parse_uuid(id, "signing key")?;

    let spinner = output::spinner("Exporting public key...");

    let resp = client
        .get_public_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|e| sdk_err("export public key", e))?;

    spinner.finish_and_clear();

    let mut bytes = Vec::new();
    let mut stream = resp.into_inner();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.into_diagnostic()?;
        bytes.extend_from_slice(&chunk);
    }

    let pem =
        String::from_utf8(bytes).map_err(|e| sdk_err("decode public key (invalid UTF-8)", e))?;
    print!("{pem}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Config handlers
// ---------------------------------------------------------------------------

async fn show_config(repo_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let rid = parse_uuid(repo_id, "repository")?;

    let spinner = output::spinner("Fetching signing config...");

    let config = client
        .get_repo_signing_config()
        .repo_id(rid)
        .send()
        .await
        .map_err(|e| sdk_err("get signing config", e))?;

    let config = config.into_inner();
    spinner.finish_and_clear();

    let (info, table_str) = format_config_detail(&config);

    println!("{}", output::render(&info, &global.format, Some(table_str)));

    Ok(())
}

async fn update_config(
    repo_id: &str,
    require_signatures: bool,
    sign_metadata: bool,
    sign_packages: bool,
    signing_key_id: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let rid = parse_uuid(repo_id, "repository")?;
    let key_id = parse_optional_uuid(signing_key_id, "signing key")?;

    let spinner = output::spinner("Updating signing config...");

    // Only send flags that were explicitly set (booleans default to false from clap,
    // so we send Some(true) when the flag is present and None otherwise).
    let body = artifact_keeper_sdk::types::UpdateSigningConfigPayload {
        require_signatures: if require_signatures { Some(true) } else { None },
        sign_metadata: if sign_metadata { Some(true) } else { None },
        sign_packages: if sign_packages { Some(true) } else { None },
        signing_key_id: key_id,
    };

    client
        .update_repo_signing_config()
        .repo_id(rid)
        .body(body)
        .send()
        .await
        .map_err(|e| sdk_err("update signing config", e))?;

    spinner.finish_and_clear();
    eprintln!("Signing configuration updated for repository {repo_id}.");

    Ok(())
}

async fn export_repo_key(repo_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let rid = parse_uuid(repo_id, "repository")?;

    let spinner = output::spinner("Exporting repository public key...");

    let resp = client
        .get_repo_public_key()
        .repo_id(rid)
        .send()
        .await
        .map_err(|e| sdk_err("export repository public key", e))?;

    spinner.finish_and_clear();

    let mut bytes = Vec::new();
    let mut stream = resp.into_inner();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.into_diagnostic()?;
        bytes.extend_from_slice(&chunk);
    }

    let pem =
        String::from_utf8(bytes).map_err(|e| sdk_err("decode public key (invalid UTF-8)", e))?;
    print!("{pem}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers (pure functions, testable without HTTP)
// ---------------------------------------------------------------------------

fn format_keys_table(keys: &[SigningKeyPublic]) -> (Vec<Value>, String) {
    let entries: Vec<_> = keys
        .iter()
        .map(|k| {
            serde_json::json!({
                "id": k.id.to_string(),
                "name": k.name,
                "algorithm": k.algorithm,
                "key_type": k.key_type,
                "is_active": k.is_active,
                "repository_id": k.repository_id.map(|r| r.to_string()),
                "fingerprint": k.fingerprint,
            })
        })
        .collect();

    let table_str = {
        let mut table = new_table(vec![
            "ID",
            "NAME",
            "ALGORITHM",
            "TYPE",
            "ACTIVE",
            "REPO",
            "FINGERPRINT",
        ]);

        for key in keys {
            let id_short = short_id(&key.id);
            let active = if key.is_active { "yes" } else { "no" };
            let repo_short = key
                .repository_id
                .map(|r| short_id(&r))
                .unwrap_or_else(|| "-".to_string());
            let fp = key.fingerprint.as_deref().unwrap_or("-");

            table.add_row(vec![
                &id_short,
                &key.name,
                &key.algorithm,
                &key.key_type,
                active,
                &repo_short,
                fp,
            ]);
        }

        table.to_string()
    };

    (entries, table_str)
}

fn format_key_detail(key: &SigningKeyPublic) -> (Value, String) {
    let info = serde_json::json!({
        "id": key.id.to_string(),
        "name": key.name,
        "algorithm": key.algorithm,
        "key_type": key.key_type,
        "is_active": key.is_active,
        "fingerprint": key.fingerprint,
        "repository_id": key.repository_id.map(|r| r.to_string()),
        "created_at": key.created_at.to_rfc3339(),
        "expires_at": key.expires_at.map(|t| t.to_rfc3339()),
        "public_key_pem": key.public_key_pem,
    });

    let pem_preview = if key.public_key_pem.len() > 40 {
        format!("{}...", &key.public_key_pem[..40])
    } else {
        key.public_key_pem.clone()
    };

    let table_str = format!(
        "ID:            {}\n\
         Name:          {}\n\
         Algorithm:     {}\n\
         Type:          {}\n\
         Active:        {}\n\
         Fingerprint:   {}\n\
         Repository:    {}\n\
         Created:       {}\n\
         Expires:       {}\n\
         Public Key:    {}",
        key.id,
        key.name,
        key.algorithm,
        key.key_type,
        if key.is_active { "yes" } else { "no" },
        key.fingerprint.as_deref().unwrap_or("-"),
        key.repository_id
            .map(|r| r.to_string())
            .unwrap_or_else(|| "-".to_string()),
        key.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
        key.expires_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".to_string()),
        pem_preview,
    );

    (info, table_str)
}

fn format_config_detail(config: &SigningConfigResponse) -> (Value, String) {
    let info = serde_json::json!({
        "repository_id": config.repository_id.to_string(),
        "require_signatures": config.require_signatures,
        "sign_metadata": config.sign_metadata,
        "sign_packages": config.sign_packages,
        "signing_key_id": config.signing_key_id.map(|k| k.to_string()),
    });

    let table_str = format!(
        "Repository:          {}\n\
         Require Signatures:  {}\n\
         Sign Metadata:       {}\n\
         Sign Packages:       {}\n\
         Signing Key:         {}",
        config.repository_id,
        if config.require_signatures {
            "yes"
        } else {
            "no"
        },
        if config.sign_metadata { "yes" } else { "no" },
        if config.sign_packages { "yes" } else { "no" },
        config
            .signing_key_id
            .map(|k| k.to_string())
            .unwrap_or_else(|| "-".to_string()),
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
        command: SignCommand,
    }

    fn parse(args: &[&str]) -> TestCli {
        TestCli::try_parse_from(args).unwrap()
    }

    fn try_parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        TestCli::try_parse_from(args)
    }

    // ---- SignCommand top-level ----

    #[test]
    fn parse_key_subcommand() {
        let cli = parse(&["test", "key", "list"]);
        assert!(matches!(cli.command, SignCommand::Key(_)));
    }

    #[test]
    fn parse_config_subcommand() {
        let cli = parse(&[
            "test",
            "config",
            "show",
            "00000000-0000-0000-0000-000000000001",
        ]);
        assert!(matches!(cli.command, SignCommand::Config(_)));
    }

    // ---- SignKeyCommand ----

    #[test]
    fn parse_key_list() {
        let cli = parse(&["test", "key", "list"]);
        if let SignCommand::Key(SignKeyCommand::List { repo }) = cli.command {
            assert!(repo.is_none());
        } else {
            panic!("Expected Key List");
        }
    }

    #[test]
    fn parse_key_list_with_repo() {
        let cli = parse(&[
            "test",
            "key",
            "list",
            "--repo",
            "00000000-0000-0000-0000-000000000001",
        ]);
        if let SignCommand::Key(SignKeyCommand::List { repo }) = cli.command {
            assert_eq!(repo.unwrap(), "00000000-0000-0000-0000-000000000001");
        } else {
            panic!("Expected Key List with repo");
        }
    }

    #[test]
    fn parse_key_show() {
        let cli = parse(&["test", "key", "show", "some-key-id"]);
        if let SignCommand::Key(SignKeyCommand::Show { id }) = cli.command {
            assert_eq!(id, "some-key-id");
        } else {
            panic!("Expected Key Show");
        }
    }

    #[test]
    fn parse_key_create() {
        let cli = parse(&[
            "test",
            "key",
            "create",
            "my-key",
            "--algorithm",
            "ed25519",
            "--type",
            "signing",
            "--repo",
            "00000000-0000-0000-0000-000000000000",
        ]);
        if let SignCommand::Key(SignKeyCommand::Create {
            name,
            algorithm,
            key_type,
            repo,
            uid_email,
            uid_name,
        }) = cli.command
        {
            assert_eq!(name, "my-key");
            assert_eq!(algorithm, "ed25519");
            assert_eq!(key_type, "signing");
            assert_eq!(repo, "00000000-0000-0000-0000-000000000000");
            assert!(uid_email.is_none());
            assert!(uid_name.is_none());
        } else {
            panic!("Expected Key Create");
        }
    }

    #[test]
    fn parse_key_create_with_uid() {
        let cli = parse(&[
            "test",
            "key",
            "create",
            "my-key",
            "--algorithm",
            "rsa-4096",
            "--type",
            "encryption",
            "--repo",
            "00000000-0000-0000-0000-000000000000",
            "--uid-email",
            "user@example.com",
            "--uid-name",
            "Test User",
        ]);
        if let SignCommand::Key(SignKeyCommand::Create {
            uid_email,
            uid_name,
            ..
        }) = cli.command
        {
            assert_eq!(uid_email.unwrap(), "user@example.com");
            assert_eq!(uid_name.unwrap(), "Test User");
        } else {
            panic!("Expected Key Create with uid");
        }
    }

    #[test]
    fn parse_key_create_missing_required() {
        let result = try_parse(&["test", "key", "create", "my-key"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_key_delete() {
        let cli = parse(&["test", "key", "delete", "key-id"]);
        if let SignCommand::Key(SignKeyCommand::Delete { id, yes }) = cli.command {
            assert_eq!(id, "key-id");
            assert!(!yes);
        } else {
            panic!("Expected Key Delete");
        }
    }

    #[test]
    fn parse_key_delete_with_yes() {
        let cli = parse(&["test", "key", "delete", "key-id", "--yes"]);
        if let SignCommand::Key(SignKeyCommand::Delete { id, yes }) = cli.command {
            assert_eq!(id, "key-id");
            assert!(yes);
        } else {
            panic!("Expected Key Delete with --yes");
        }
    }

    #[test]
    fn parse_key_revoke() {
        let cli = parse(&["test", "key", "revoke", "key-id"]);
        if let SignCommand::Key(SignKeyCommand::Revoke { id }) = cli.command {
            assert_eq!(id, "key-id");
        } else {
            panic!("Expected Key Revoke");
        }
    }

    #[test]
    fn parse_key_rotate() {
        let cli = parse(&["test", "key", "rotate", "key-id"]);
        if let SignCommand::Key(SignKeyCommand::Rotate { id }) = cli.command {
            assert_eq!(id, "key-id");
        } else {
            panic!("Expected Key Rotate");
        }
    }

    #[test]
    fn parse_key_export() {
        let cli = parse(&["test", "key", "export", "key-id"]);
        if let SignCommand::Key(SignKeyCommand::Export { id }) = cli.command {
            assert_eq!(id, "key-id");
        } else {
            panic!("Expected Key Export");
        }
    }

    // ---- SignConfigCommand ----

    #[test]
    fn parse_config_show() {
        let cli = parse(&[
            "test",
            "config",
            "show",
            "00000000-0000-0000-0000-000000000001",
        ]);
        if let SignCommand::Config(SignConfigCommand::Show { repo_id }) = cli.command {
            assert_eq!(repo_id, "00000000-0000-0000-0000-000000000001");
        } else {
            panic!("Expected Config Show");
        }
    }

    #[test]
    fn parse_config_update_minimal() {
        let cli = parse(&[
            "test",
            "config",
            "update",
            "00000000-0000-0000-0000-000000000001",
        ]);
        if let SignCommand::Config(SignConfigCommand::Update {
            repo_id,
            require_signatures,
            sign_metadata,
            sign_packages,
            signing_key_id,
        }) = cli.command
        {
            assert_eq!(repo_id, "00000000-0000-0000-0000-000000000001");
            assert!(!require_signatures);
            assert!(!sign_metadata);
            assert!(!sign_packages);
            assert!(signing_key_id.is_none());
        } else {
            panic!("Expected Config Update");
        }
    }

    #[test]
    fn parse_config_update_with_flags() {
        let cli = parse(&[
            "test",
            "config",
            "update",
            "00000000-0000-0000-0000-000000000001",
            "--require-signatures",
            "--sign-metadata",
            "--sign-packages",
            "--signing-key-id",
            "00000000-0000-0000-0000-000000000002",
        ]);
        if let SignCommand::Config(SignConfigCommand::Update {
            require_signatures,
            sign_metadata,
            sign_packages,
            signing_key_id,
            ..
        }) = cli.command
        {
            assert!(require_signatures);
            assert!(sign_metadata);
            assert!(sign_packages);
            assert_eq!(
                signing_key_id.unwrap(),
                "00000000-0000-0000-0000-000000000002"
            );
        } else {
            panic!("Expected Config Update with flags");
        }
    }

    #[test]
    fn parse_config_export_key() {
        let cli = parse(&[
            "test",
            "config",
            "export-key",
            "00000000-0000-0000-0000-000000000001",
        ]);
        if let SignCommand::Config(SignConfigCommand::ExportKey { repo_id }) = cli.command {
            assert_eq!(repo_id, "00000000-0000-0000-0000-000000000001");
        } else {
            panic!("Expected Config ExportKey");
        }
    }

    // ---- Format function tests ----

    use artifact_keeper_sdk::types::{SigningConfigResponse, SigningKeyPublic};
    use chrono::Utc;
    use uuid::Uuid;

    fn make_test_key(name: &str, active: bool, fingerprint: Option<&str>) -> SigningKeyPublic {
        SigningKeyPublic {
            id: Uuid::nil(),
            name: name.to_string(),
            algorithm: "ed25519".to_string(),
            key_type: "signing".to_string(),
            is_active: active,
            fingerprint: fingerprint.map(|s| s.to_string()),
            repository_id: Some(Uuid::nil()),
            created_at: Utc::now(),
            expires_at: None,
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
            key_id: None,
            last_used_at: None,
            uid_email: None,
            uid_name: None,
        }
    }

    #[test]
    fn format_keys_table_single_key() {
        let keys = vec![make_test_key("test-key", true, Some("abc123"))];
        let (entries, table_str) = format_keys_table(&keys);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["name"], "test-key");
        assert_eq!(entries[0]["algorithm"], "ed25519");
        assert_eq!(entries[0]["is_active"], true);

        assert!(table_str.contains("ID"));
        assert!(table_str.contains("NAME"));
        assert!(table_str.contains("ALGORITHM"));
        assert!(table_str.contains("test-key"));
        assert!(table_str.contains("yes"));
        assert!(table_str.contains("abc123"));
    }

    #[test]
    fn format_keys_table_multiple_keys() {
        let keys = vec![
            make_test_key("key-1", true, Some("fp1")),
            make_test_key("key-2", false, None),
        ];
        let (entries, table_str) = format_keys_table(&keys);

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["name"], "key-1");
        assert_eq!(entries[1]["name"], "key-2");
        assert_eq!(entries[1]["is_active"], false);

        assert!(table_str.contains("key-1"));
        assert!(table_str.contains("key-2"));
        assert!(table_str.contains("no"));
    }

    #[test]
    fn format_keys_table_empty() {
        let keys: Vec<SigningKeyPublic> = vec![];
        let (entries, table_str) = format_keys_table(&keys);

        assert!(entries.is_empty());
        // Table still has headers
        assert!(table_str.contains("ID"));
    }

    #[test]
    fn format_keys_table_no_fingerprint() {
        let keys = vec![make_test_key("no-fp-key", true, None)];
        let (entries, table_str) = format_keys_table(&keys);

        assert!(entries[0]["fingerprint"].is_null());
        // The table should show "-" for missing fingerprint
        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_keys_table_no_repo() {
        let mut key = make_test_key("orphan-key", true, None);
        key.repository_id = None;
        let (entries, table_str) = format_keys_table(&[key]);

        assert!(entries[0]["repository_id"].is_null());
        assert!(table_str.contains("-"));
    }

    #[test]
    fn format_key_detail_active_key() {
        let key = make_test_key("my-signing-key", true, Some("deadbeef"));
        let (info, table_str) = format_key_detail(&key);

        assert_eq!(info["name"], "my-signing-key");
        assert_eq!(info["algorithm"], "ed25519");
        assert_eq!(info["key_type"], "signing");
        assert_eq!(info["is_active"], true);
        assert_eq!(info["fingerprint"], "deadbeef");
        assert!(info["created_at"].is_string());

        assert!(table_str.contains("my-signing-key"));
        assert!(table_str.contains("ed25519"));
        assert!(table_str.contains("Active:"));
        assert!(table_str.contains("yes"));
        assert!(table_str.contains("deadbeef"));
    }

    #[test]
    fn format_key_detail_inactive_key() {
        let key = make_test_key("revoked-key", false, None);
        let (info, table_str) = format_key_detail(&key);

        assert_eq!(info["is_active"], false);
        assert!(table_str.contains("no"));
        assert!(table_str.contains("Fingerprint:"));
    }

    #[test]
    fn format_key_detail_long_pem_truncated() {
        let mut key = make_test_key("long-pem-key", true, None);
        key.public_key_pem = "A".repeat(100);
        let (_info, table_str) = format_key_detail(&key);

        // The PEM should be truncated to 40 chars + "..."
        assert!(table_str.contains("..."));
    }

    #[test]
    fn format_key_detail_short_pem_not_truncated() {
        let mut key = make_test_key("short-pem-key", true, None);
        key.public_key_pem = "SHORT-PEM".to_string();
        let (_info, table_str) = format_key_detail(&key);

        assert!(table_str.contains("SHORT-PEM"));
        assert!(!table_str.contains("..."));
    }

    #[test]
    fn format_key_detail_with_expiry() {
        let mut key = make_test_key("expiring-key", true, None);
        key.expires_at = Some(Utc::now());
        let (info, table_str) = format_key_detail(&key);

        assert!(info["expires_at"].is_string());
        // Table should not show "-" for expiry since it's set
        assert!(table_str.contains("Expires:"));
    }

    #[test]
    fn format_key_detail_no_expiry() {
        let key = make_test_key("no-expiry-key", true, None);
        let (info, table_str) = format_key_detail(&key);

        assert!(info["expires_at"].is_null());
        assert!(table_str.contains("Expires:"));
    }

    #[test]
    fn format_config_detail_all_enabled() {
        let config = SigningConfigResponse {
            repository_id: Uuid::nil(),
            require_signatures: true,
            sign_metadata: true,
            sign_packages: true,
            signing_key_id: Some(Uuid::nil()),
            key: None,
        };
        let (info, table_str) = format_config_detail(&config);

        assert_eq!(info["require_signatures"], true);
        assert_eq!(info["sign_metadata"], true);
        assert_eq!(info["sign_packages"], true);
        assert!(info["signing_key_id"].is_string());

        assert!(table_str.contains("yes"));
        assert!(table_str.contains("Repository:"));
        assert!(table_str.contains("Require Signatures:"));
        assert!(table_str.contains("Sign Metadata:"));
        assert!(table_str.contains("Sign Packages:"));
    }

    #[test]
    fn format_config_detail_all_disabled() {
        let config = SigningConfigResponse {
            repository_id: Uuid::nil(),
            require_signatures: false,
            sign_metadata: false,
            sign_packages: false,
            signing_key_id: None,
            key: None,
        };
        let (info, table_str) = format_config_detail(&config);

        assert_eq!(info["require_signatures"], false);
        assert_eq!(info["sign_metadata"], false);
        assert_eq!(info["sign_packages"], false);
        assert!(info["signing_key_id"].is_null());

        assert!(table_str.contains("no"));
        assert!(table_str.contains("Signing Key:"));
    }

    // ========================================================================
    // Wiremock-based handler tests
    // ========================================================================

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    /// Set up env vars for handler tests; returns a guard that must be held.

    static NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";

    #[tokio::test]
    async fn handler_list_keys_empty() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/signing/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [],
                "total": 0
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_keys(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_keys_with_data() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/signing/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "id": NIL_UUID,
                        "name": "release-key",
                        "algorithm": "ed25519",
                        "key_type": "signing",
                        "is_active": true,
                        "fingerprint": "abc123def456",
                        "repository_id": NIL_UUID,
                        "created_at": "2024-02-21T00:00:00Z",
                        "expires_at": null,
                        "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
                        "key_id": null,
                        "last_used_at": null,
                        "uid_email": null,
                        "uid_name": null
                    }
                ],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_keys(None, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_list_keys_with_repo_filter() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path("/api/v1/signing/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "id": NIL_UUID,
                        "name": "repo-key",
                        "algorithm": "rsa-4096",
                        "key_type": "signing",
                        "is_active": true,
                        "fingerprint": "deadbeef",
                        "repository_id": NIL_UUID,
                        "created_at": "2024-02-21T00:00:00Z",
                        "expires_at": null,
                        "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
                        "key_id": null,
                        "last_used_at": null,
                        "uid_email": null,
                        "uid_name": null
                    }
                ],
                "total": 1
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = list_keys(Some(NIL_UUID), &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_key() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/signing/keys/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "name": "my-key",
                "algorithm": "ed25519",
                "key_type": "signing",
                "is_active": true,
                "fingerprint": "abc123",
                "repository_id": NIL_UUID,
                "created_at": "2024-02-21T00:00:00Z",
                "expires_at": null,
                "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----",
                "key_id": null,
                "last_used_at": null,
                "uid_email": null,
                "uid_name": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_key(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_key() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/signing/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "name": "new-key",
                "algorithm": "ed25519",
                "key_type": "signing",
                "is_active": true,
                "fingerprint": "newfingerprint",
                "repository_id": NIL_UUID,
                "created_at": "2024-02-21T00:00:00Z",
                "expires_at": null,
                "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
                "key_id": null,
                "last_used_at": null,
                "uid_email": null,
                "uid_name": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = create_key(
            "new-key",
            "ed25519",
            "signing",
            NIL_UUID,
            Some("user@example.com"),
            Some("Test User"),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_create_key_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path("/api/v1/signing/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "name": "quiet-key",
                "algorithm": "rsa-4096",
                "key_type": "encryption",
                "is_active": true,
                "fingerprint": null,
                "repository_id": NIL_UUID,
                "created_at": "2024-02-21T00:00:00Z",
                "expires_at": null,
                "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
                "key_id": null,
                "last_used_at": null,
                "uid_email": null,
                "uid_name": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = create_key(
            "quiet-key",
            "rsa-4096",
            "encryption",
            NIL_UUID,
            None,
            None,
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_delete_key() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("DELETE"))
            .and(path_regex("/api/v1/signing/keys/.+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "Key deleted"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        // skip_confirm=true because no_input=true in test_global
        let result = delete_key(NIL_UUID, true, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_revoke_key() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/signing/keys/.+/revoke"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "Key revoked successfully"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = revoke_key(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_revoke_key_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/signing/keys/.+/revoke"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "Key revoked"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = revoke_key(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_rotate_key() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/signing/keys/.+/rotate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "name": "rotated-key",
                "algorithm": "ed25519",
                "key_type": "signing",
                "is_active": true,
                "fingerprint": "new-fingerprint",
                "repository_id": NIL_UUID,
                "created_at": "2024-02-21T00:00:00Z",
                "expires_at": null,
                "public_key_pem": "-----BEGIN PUBLIC KEY-----\nnew-key\n-----END PUBLIC KEY-----",
                "key_id": null,
                "last_used_at": null,
                "uid_email": null,
                "uid_name": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = rotate_key(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_rotate_key_quiet() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/signing/keys/.+/rotate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "name": "rotated-quiet",
                "algorithm": "ed25519",
                "key_type": "signing",
                "is_active": true,
                "fingerprint": null,
                "repository_id": null,
                "created_at": "2024-02-21T00:00:00Z",
                "expires_at": null,
                "public_key_pem": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
                "key_id": null,
                "last_used_at": null,
                "uid_email": null,
                "uid_name": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = rotate_key(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_config() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("GET"))
            .and(path_regex("/api/v1/signing/repositories/.+/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "repository_id": NIL_UUID,
                "require_signatures": true,
                "sign_metadata": true,
                "sign_packages": false,
                "signing_key_id": NIL_UUID,
                "key": null
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_config(NIL_UUID, &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_update_config() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);

        Mock::given(method("POST"))
            .and(path_regex("/api/v1/signing/repositories/.+/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": NIL_UUID,
                "repository_id": NIL_UUID,
                "require_signatures": true,
                "sign_metadata": true,
                "sign_packages": true,
                "signing_key_id": NIL_UUID,
                "created_at": "2024-02-21T00:00:00Z",
                "updated_at": "2024-02-21T12:00:00Z"
            })))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = update_config(NIL_UUID, true, true, true, Some(NIL_UUID), &global).await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }
}
