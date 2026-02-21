use artifact_keeper_sdk::ClientSigningExt;
use clap::Subcommand;
use comfy_table::{ContentArrangement, Table, presets::UTF8_FULL_CONDENSED};
use futures::StreamExt;
use miette::{IntoDiagnostic, Result};

use super::client::client_for;
use super::helpers::{confirm_action, parse_optional_uuid, parse_uuid};
use crate::cli::GlobalArgs;
use crate::error::AkError;
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
        .map_err(|e| AkError::ServerError(format!("Failed to list signing keys: {e}")))?;

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

    let entries: Vec<_> = resp
        .keys
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
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "ID",
                "NAME",
                "ALGORITHM",
                "TYPE",
                "ACTIVE",
                "REPO",
                "FINGERPRINT",
            ]);

        for key in &resp.keys {
            let id_short = &key.id.to_string()[..8];
            let active = if key.is_active { "yes" } else { "no" };
            let repo_short = key
                .repository_id
                .map(|r| r.to_string()[..8].to_string())
                .unwrap_or_else(|| "-".to_string());
            let fp = key.fingerprint.as_deref().unwrap_or("-");

            table.add_row(vec![
                id_short,
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
        .map_err(|e| AkError::ServerError(format!("Failed to get signing key: {e}")))?;

    let key = key.into_inner();
    spinner.finish_and_clear();

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
        .map_err(|e| AkError::ServerError(format!("Failed to create signing key: {e}")))?;

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
        .map_err(|e| AkError::ServerError(format!("Failed to delete signing key: {e}")))?;

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
        .map_err(|e| AkError::ServerError(format!("Failed to revoke signing key: {e}")))?;

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
        .map_err(|e| AkError::ServerError(format!("Failed to rotate signing key: {e}")))?;

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
        .map_err(|e| AkError::ServerError(format!("Failed to export public key: {e}")))?;

    spinner.finish_and_clear();

    let mut bytes = Vec::new();
    let mut stream = resp.into_inner();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.into_diagnostic()?;
        bytes.extend_from_slice(&chunk);
    }

    let pem = String::from_utf8(bytes)
        .map_err(|e| AkError::ServerError(format!("Invalid UTF-8 in public key: {e}")))?;
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
        .map_err(|e| AkError::ServerError(format!("Failed to get signing config: {e}")))?;

    let config = config.into_inner();
    spinner.finish_and_clear();

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
        .map_err(|e| AkError::ServerError(format!("Failed to update signing config: {e}")))?;

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
        .map_err(|e| {
            AkError::ServerError(format!("Failed to export repository public key: {e}"))
        })?;

    spinner.finish_and_clear();

    let mut bytes = Vec::new();
    let mut stream = resp.into_inner();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.into_diagnostic()?;
        bytes.extend_from_slice(&chunk);
    }

    let pem = String::from_utf8(bytes)
        .map_err(|e| AkError::ServerError(format!("Invalid UTF-8 in public key: {e}")))?;
    print!("{pem}");

    Ok(())
}
