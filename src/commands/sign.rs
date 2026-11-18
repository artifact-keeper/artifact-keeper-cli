use artifact_keeper_sdk::ClientSigningExt;
use artifact_keeper_sdk::raw::capture;
use artifact_keeper_sdk::types::{SigningConfigResponse, SigningKeyPublic};
use clap::Subcommand;
use futures::StreamExt;
use miette::{IntoDiagnostic, Result};
use serde_json::Value;

use super::client::client_for;
use super::helpers::{
    confirm_action, emit_mutation_raw, new_table, parse_optional_uuid, parse_uuid,
    read_inline_or_file, resolve_artifact_id, resolve_optional_repo_id, resolve_repo_id, sdk_err,
    short_id, since,
};
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

    /// Sign an artifact with its repository's active key (admin only)
    ///
    /// This writes the attestation that a policy's --require-signature trusts, so signing
    /// vouches for the artifact and lets it through that check.
    ///
    /// The repository needs an active key set with `ak sign config update <repo>
    /// --signing-key-id <id> --sign-metadata`.
    Artifact {
        /// Artifact ID, or <repo-key>/<path>
        artifact: String,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum SignKeyCommand {
    /// List all signing keys
    List {
        /// Filter by repository key or ID
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

        /// Signing algorithm. Supported: rsa2048, rsa4096 (default: rsa4096)
        #[arg(long, default_value = "rsa4096")]
        algorithm: String,

        /// Key type: gpg, rsa or ed25519 (server default: gpg)
        #[arg(long = "type")]
        key_type: Option<String>,

        /// Repository key or ID to associate with this key. Leave it out for a key that
        /// isn't tied to one
        #[arg(long)]
        repo: Option<String>,

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
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Revoke (deactivate) a signing key
    Revoke {
        /// Signing key ID
        id: String,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Rotate a signing key (generates new key, deactivates old)
    Rotate {
        /// Signing key ID to rotate
        id: String,

        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Export the public key in PEM format
    Export {
        /// Signing key ID
        id: String,
    },

    /// Link a key to an external OpenPGP issuer key, such as a root key on a hardware
    /// token, with a signature over the key. Needs server 1.12
    #[command(subcommand)]
    TrustAttestation(TrustAttestationCommand),
}

#[derive(Subcommand)]
pub enum TrustAttestationCommand {
    /// Show the key's stored trust attestation, if it has one
    Show {
        /// Signing key ID
        id: String,
    },

    /// Print the payload to sign with the issuer key. In table output, stdout is the
    /// payload exactly, ready for `gpg --armor --detach-sign`
    #[command(
        after_help = "Example:\n  ak sign key trust-attestation challenge <id> > payload\n  gpg --armor --detach-sign --local-user <issuer> payload\n  gpg --armor --export <issuer> > issuer.asc\n  ak sign key trust-attestation verify <id> --issuer-public-key @issuer.asc --signature @payload.asc"
    )]
    Challenge {
        /// Signing key ID
        id: String,
    },

    /// Send the issuer's signature over the payload. The server checks it and stores
    /// the attestation. A valid signature isn't a trust decision: the server doesn't
    /// pin issuers to trust anchors
    Verify {
        /// Signing key ID
        id: String,

        /// The issuer's armored OpenPGP public key: the text, @file or @- for stdin
        #[arg(long, value_name = "KEY")]
        issuer_public_key: String,

        /// The armored detached signature over the challenge payload: the text,
        /// @file or @- for stdin
        #[arg(long, value_name = "SIGNATURE")]
        signature: String,

        /// A name for the issuer, to show with the attestation
        #[arg(long)]
        issuer_name: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum SignConfigCommand {
    /// Show signing configuration for a repository
    Show {
        /// Repository key or ID
        repo_id: String,
    },

    /// Update signing configuration for a repository. Only what you pass changes
    Update {
        /// Repository key or ID
        repo_id: String,

        /// Require signatures on all uploads. On its own, the flag means true
        #[arg(long, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
        require_signatures: Option<bool>,

        /// Sign package metadata. On its own, the flag means true
        #[arg(long, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
        sign_metadata: Option<bool>,

        /// Sign packages. On its own, the flag means true
        #[arg(long, num_args = 0..=1, default_missing_value = "true", value_name = "BOOL")]
        sign_packages: Option<bool>,

        /// Signing key ID to use
        #[arg(long)]
        signing_key_id: Option<String>,
    },

    /// Export the repository's public key in PEM format
    ExportKey {
        /// Repository key or ID
        repo_id: String,
    },
}

impl SignCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Key(cmd) => cmd.execute(global).await,
            Self::Config(cmd) => cmd.execute(global).await,
            Self::Artifact { artifact, yes } => sign_artifact(&artifact, yes, global).await,
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
                    key_type.as_deref(),
                    repo.as_deref(),
                    uid_email.as_deref(),
                    uid_name.as_deref(),
                    global,
                )
                .await
            }
            Self::Delete { id, yes } => delete_key(&id, yes, global).await,
            Self::Revoke { id, yes } => revoke_key(&id, yes, global).await,
            Self::Rotate { id, yes } => rotate_key(&id, yes, global).await,
            Self::Export { id } => export_key(&id, global).await,
            Self::TrustAttestation(cmd) => cmd.execute(global).await,
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

    let repo_id = resolve_optional_repo_id(&client, repo).await?;

    let mut req = client.list_keys();
    if let Some(rid) = repo_id {
        req = req.repository_id(rid);
    }

    let (resp, raw) = capture(req.send()).await;
    let resp = resp.map_err(|e| sdk_err("list signing keys", e))?;

    let resp = resp.into_inner();
    spinner.finish_and_clear();

    if resp.keys.is_empty() && !output::is_machine_format(&global.format) {
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
        output::render_raw(raw.as_deref(), &entries, &global.format, Some(table_str))
    );

    Ok(())
}

async fn show_key(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let key_id = parse_uuid(id, "signing key")?;

    let spinner = output::spinner("Fetching signing key...");
    let (key, raw) = capture(client.get_key().key_id(key_id).send()).await;
    let key = key.map_err(|e| sdk_err("get signing key", e))?;

    let key = key.into_inner();
    spinner.finish_and_clear();

    let (info, table_str) = format_key_detail(&key);

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn create_key(
    name: &str,
    algorithm: &str,
    key_type: Option<&str>,
    repo: Option<&str>,
    uid_email: Option<&str>,
    uid_name: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let repo_id = resolve_optional_repo_id(&client, repo).await?;

    let spinner = output::spinner("Creating signing key...");

    let body = artifact_keeper_sdk::types::CreateKeyPayload {
        name: name.to_string(),
        algorithm: Some(algorithm.to_string()),
        key_type: key_type.map(str::to_string),
        repository_id: repo_id,
        uid_email: uid_email.map(|s| s.to_string()),
        uid_name: uid_name.map(|s| s.to_string()),
    };

    let (key, raw) = capture(client.create_key().body(body).send()).await;
    let key = key.map_err(|e| sdk_err("create signing key", e))?;

    let key = key.into_inner();
    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &key,
        &key.id.to_string(),
        &format!("Signing key '{}' created (ID: {}).", key.name, key.id),
        global,
    );

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

    let (resp, raw) = capture(client.delete_key().key_id(key_id).send()).await;
    let result = resp.map_err(|e| sdk_err("delete signing key", e))?;

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &*result,
        id,
        &format!("Signing key {id} deleted."),
        global,
    );

    Ok(())
}

async fn revoke_key(id: &str, yes: bool, global: &GlobalArgs) -> Result<()> {
    let key_id = parse_uuid(id, "signing key")?;

    if !confirm_action(
        &format!("Revoke signing key {id}? Nothing can be signed with it afterwards."),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Revoking signing key...");

    let (resp, raw) = capture(client.revoke_key().key_id(key_id).send()).await;
    let result = resp.map_err(|e| sdk_err("revoke signing key", e))?;

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &*result,
        id,
        &format!("Signing key {id} revoked."),
        global,
    );

    Ok(())
}

async fn rotate_key(id: &str, yes: bool, global: &GlobalArgs) -> Result<()> {
    let key_id = parse_uuid(id, "signing key")?;

    if !confirm_action(
        &format!(
            "Rotate signing key {id}? It's replaced by a new key, and clients need the new \
             public key."
        ),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }

    let client = client_for(global)?;
    let spinner = output::spinner("Rotating signing key...");

    let (resp, raw) = capture(client.rotate_key().key_id(key_id).send()).await;
    let key = resp
        .map_err(|e| sdk_err("rotate signing key", e))?
        .into_inner();

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &key,
        &key.id.to_string(),
        &format!("Key rotated. New key '{}' (ID: {}).", key.name, key.id),
        global,
    );

    Ok(())
}

async fn sign_artifact(artifact: &str, yes: bool, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let artifact_id = resolve_artifact_id(&client, artifact).await?;

    if !confirm_action(
        &format!(
            "Sign {artifact}? The signature vouches for it and satisfies a policy that requires \
             one."
        ),
        yes,
        global.no_input,
    )? {
        return Ok(());
    }

    let spinner = output::spinner("Signing artifact...");

    let (resp, raw) = capture(client.sign_artifact().artifact_id(artifact_id).send()).await;
    let signed = resp.map_err(|e| sdk_err("sign artifact", e))?.into_inner();

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &signed,
        &signed.signature_sha256,
        &format!(
            "Signed {} with key {} ({}). Signature SHA-256: {}",
            signed.artifact_id, signed.key_id, signed.algorithm, signed.signature_sha256
        ),
        global,
    );

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

    let pem = String::from_utf8(bytes).map_err(|e| {
        crate::commands::helpers::bad_response("decode public key (invalid UTF-8)", e)
    })?;
    print!("{pem}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Trust attestation handlers
// ---------------------------------------------------------------------------

impl TrustAttestationCommand {
    pub async fn execute(self, global: &GlobalArgs) -> Result<()> {
        match self {
            Self::Show { id } => show_trust_attestation(&id, global).await,
            Self::Challenge { id } => trust_attestation_challenge(&id, global).await,
            Self::Verify {
                id,
                issuer_public_key,
                signature,
                issuer_name,
            } => {
                let issuer_public_key = text_arg(&issuer_public_key, "--issuer-public-key")?;
                let signature = text_arg(&signature, "--signature")?;
                verify_trust_attestation(&id, issuer_public_key, signature, issuer_name, global)
                    .await
            }
        }
    }
}

fn text_arg(value: &str, flag: &str) -> Result<String> {
    let bytes = read_inline_or_file(value, flag)?;
    String::from_utf8(bytes)
        .map_err(|_| AkError::Usage(format!("{flag}: the text isn't UTF-8")).into())
}

/// The error for a trust attestation route, which a 1.11 server doesn't have.
async fn attestation_err(
    error: artifact_keeper_sdk::Error,
    action: &str,
    command: &str,
    global: &GlobalArgs,
) -> miette::Report {
    since((1, 12), error, action, command, global).await.into()
}

async fn show_trust_attestation(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let key_id = parse_uuid(id, "signing key")?;

    let spinner = output::spinner("Fetching trust attestation...");
    let (attestation, raw) =
        capture(client.get_key_trust_attestation().key_id(key_id).send()).await;
    spinner.finish_and_clear();

    // The server answers `null` for a key with no attestation, which the SDK's type
    // can't hold.
    let no_attestation = raw
        .as_deref()
        .is_some_and(|body| body.trim_ascii() == b"null");
    let attestation = match attestation {
        Ok(attestation) => Some(attestation.into_inner()),
        Err(_) if no_attestation => None,
        Err(e) => {
            return Err(attestation_err(
                e,
                "get trust attestation",
                "sign key trust-attestation show",
                global,
            )
            .await);
        }
    };

    let Some(a) = attestation else {
        match global.format {
            OutputFormat::Json | OutputFormat::Yaml => {
                println!(
                    "{}",
                    output::render_raw(raw.as_deref(), &Value::Null, &global.format, None)
                );
            }
            OutputFormat::Quiet => {}
            OutputFormat::Table => eprintln!("Signing key {id} has no trust attestation."),
        }
        return Ok(());
    };

    if matches!(global.format, OutputFormat::Quiet) {
        println!("{}", a.id);
        return Ok(());
    }

    let table_str = format!(
        "ID:            {}\n\
         Signing Key:   {}\n\
         Issuer:        {}\n\
         Fingerprint:   {}\n\
         Signature:     {}\n\
         Status:        {}\n\
         Verified:      {}\n\
         Created:       {}",
        a.id,
        a.signing_key_id,
        a.issuer_name.as_deref().unwrap_or("-"),
        a.issuer_fingerprint,
        a.signature_type,
        a.verification_status,
        a.verified_at
            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "-".into()),
        a.created_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );
    println!(
        "{}",
        output::render_raw(raw.as_deref(), &a, &global.format, Some(table_str))
    );
    Ok(())
}

async fn trust_attestation_challenge(id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let key_id = parse_uuid(id, "signing key")?;

    let spinner = output::spinner("Fetching attestation challenge...");
    let (challenge, raw) = capture(
        client
            .get_key_trust_attestation_challenge()
            .key_id(key_id)
            .send(),
    )
    .await;
    spinner.finish_and_clear();
    let challenge = match challenge {
        Ok(challenge) => challenge.into_inner(),
        Err(e) => {
            return Err(attestation_err(
                e,
                "get trust attestation challenge",
                "sign key trust-attestation challenge",
                global,
            )
            .await);
        }
    };

    match global.format {
        OutputFormat::Json | OutputFormat::Yaml => {
            println!(
                "{}",
                output::render_raw(raw.as_deref(), &challenge, &global.format, None)
            );
        }
        // The payload exactly, with nothing added: a signature over anything else
        // doesn't verify.
        OutputFormat::Table | OutputFormat::Quiet => {
            if matches!(global.format, OutputFormat::Table) {
                eprintln!(
                    "Sign this payload for key {} ({} {}, fingerprint {}) with the issuer \
                     key, as an armored detached signature.",
                    challenge.signing_key_id,
                    challenge.key_type,
                    challenge.algorithm,
                    challenge.key_fingerprint.as_deref().unwrap_or("-"),
                );
            }
            print!("{}", challenge.payload);
        }
    }
    Ok(())
}

async fn verify_trust_attestation(
    id: &str,
    issuer_public_key_armored: String,
    signature_armored: String,
    issuer_name: Option<String>,
    global: &GlobalArgs,
) -> Result<()> {
    let client = client_for(global)?;
    let key_id = parse_uuid(id, "signing key")?;

    let body = artifact_keeper_sdk::types::VerifyTrustAttestationPayload {
        issuer_public_key_armored,
        signature_armored,
        issuer_name,
    };
    let spinner = output::spinner("Verifying trust attestation...");
    let (attestation, raw) = capture(
        client
            .verify_key_trust_attestation()
            .key_id(key_id)
            .body(body)
            .send(),
    )
    .await;
    spinner.finish_and_clear();
    let a = match attestation {
        Ok(a) => a.into_inner(),
        Err(e) => {
            return Err(attestation_err(
                e,
                "verify trust attestation",
                "sign key trust-attestation verify",
                global,
            )
            .await);
        }
    };

    emit_mutation_raw(
        raw.as_deref(),
        &a,
        &a.id.to_string(),
        &format!(
            "Trust attestation stored for key {}: {} by issuer {}.",
            a.signing_key_id, a.verification_status, a.issuer_fingerprint
        ),
        global,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Config handlers
// ---------------------------------------------------------------------------

async fn show_config(repo_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let rid = resolve_repo_id(&client, repo_id).await?;

    let spinner = output::spinner("Fetching signing config...");

    let (config, raw) = capture(client.get_repo_signing_config().repo_id(rid).send()).await;
    let config = config.map_err(|e| sdk_err("get signing config", e))?;

    let config = config.into_inner();
    spinner.finish_and_clear();

    let (info, table_str) = format_config_detail(&config);

    println!(
        "{}",
        output::render_raw(raw.as_deref(), &info, &global.format, Some(table_str))
    );

    Ok(())
}

async fn update_config(
    repo_id: &str,
    require_signatures: Option<bool>,
    sign_metadata: Option<bool>,
    sign_packages: Option<bool>,
    signing_key_id: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    if require_signatures.is_none()
        && sign_metadata.is_none()
        && sign_packages.is_none()
        && signing_key_id.is_none()
    {
        return Err(AkError::Usage(
            "Nothing to update. Pass at least one setting, such as --sign-packages true."
                .to_string(),
        )
        .into());
    }

    let client = client_for(global)?;
    let rid = resolve_repo_id(&client, repo_id).await?;
    let key_id = parse_optional_uuid(signing_key_id, "signing key")?;

    let spinner = output::spinner("Updating signing config...");

    let body = artifact_keeper_sdk::types::UpdateSigningConfigPayload {
        require_signatures,
        sign_metadata,
        sign_packages,
        signing_key_id: key_id,
    };

    let (resp, raw) = capture(
        client
            .update_repo_signing_config()
            .repo_id(rid)
            .body(body)
            .send(),
    )
    .await;
    let config = resp
        .map_err(|e| sdk_err("update signing config", e))?
        .into_inner();

    spinner.finish_and_clear();

    emit_mutation_raw(
        raw.as_deref(),
        &config,
        &config.id.to_string(),
        &format!("Signing configuration updated for repository {repo_id}."),
        global,
    );

    Ok(())
}

async fn export_repo_key(repo_id: &str, global: &GlobalArgs) -> Result<()> {
    let client = client_for(global)?;
    let rid = resolve_repo_id(&client, repo_id).await?;

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

    let pem = String::from_utf8(bytes).map_err(|e| {
        crate::commands::helpers::bad_response("decode public key (invalid UTF-8)", e)
    })?;
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
            assert_eq!(key_type.as_deref(), Some("signing"));
            assert_eq!(
                repo.as_deref(),
                Some("00000000-0000-0000-0000-000000000000")
            );
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
        let result = try_parse(&["test", "key", "create"]);
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
        if let SignCommand::Key(SignKeyCommand::Revoke { id, .. }) = cli.command {
            assert_eq!(id, "key-id");
        } else {
            panic!("Expected Key Revoke");
        }
    }

    #[test]
    fn parse_key_rotate() {
        let cli = parse(&["test", "key", "rotate", "key-id"]);
        if let SignCommand::Key(SignKeyCommand::Rotate { id, .. }) = cli.command {
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
            assert!(require_signatures.is_none());
            assert!(sign_metadata.is_none());
            assert!(sign_packages.is_none());
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
            assert_eq!(require_signatures, Some(true));
            assert_eq!(sign_metadata, Some(true));
            assert_eq!(sign_packages, Some(true));
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
            Some("signing"),
            Some(NIL_UUID),
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
            Some("encryption"),
            Some(NIL_UUID),
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
        let result = revoke_key(NIL_UUID, true, &global).await;
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
        let result = revoke_key(NIL_UUID, true, &global).await;
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
        let result = rotate_key(NIL_UUID, true, &global).await;
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
        let result = rotate_key(NIL_UUID, true, &global).await;
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
        let result = update_config(
            NIL_UUID,
            Some(true),
            Some(true),
            Some(true),
            Some(NIL_UUID),
            &global,
        )
        .await;
        assert!(result.is_ok());
        crate::test_utils::teardown_env();
    }

    // ---- insta snapshot tests ----

    #[test]
    fn snapshot_sign_key_list_json() {
        let data = serde_json::json!([{
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "release-key",
            "algorithm": "ed25519",
            "fingerprint": "SHA256:abc123def456",
            "created_at": "2026-01-10T08:00:00Z",
            "expires_at": "2027-01-10T08:00:00Z",
            "is_default": true
        }]);
        let output = crate::output::render(&data, &OutputFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        insta::assert_yaml_snapshot!("sign_key_list_json", parsed);
    }

    // ---- trust attestation (1.12) ----

    fn attestation_json() -> serde_json::Value {
        serde_json::json!({
            "id": NIL_UUID,
            "signing_key_id": NIL_UUID,
            "issuer_public_key_armored": "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            "issuer_fingerprint": "ABCD1234",
            "issuer_name": "root",
            "payload": "payload",
            "signature_armored": "-----BEGIN PGP SIGNATURE-----",
            "signature_type": "openpgp-detached",
            "verification_status": "signature_valid",
            "created_at": "2026-11-18T00:00:00Z",
            "verified_at": "2026-11-18T00:00:00Z"
        })
    }

    async fn health(server: &wiremock::MockServer, version: &str) {
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "version": version })),
            )
            .mount(server)
            .await;
    }

    #[test]
    fn parse_trust_attestation_verify() {
        match parse(&[
            "test",
            "key",
            "trust-attestation",
            "verify",
            NIL_UUID,
            "--issuer-public-key",
            "@issuer.asc",
            "--signature",
            "@payload.asc",
            "--issuer-name",
            "root",
        ])
        .command
        {
            SignCommand::Key(SignKeyCommand::TrustAttestation(
                TrustAttestationCommand::Verify {
                    id,
                    issuer_public_key,
                    signature,
                    issuer_name,
                },
            )) => {
                assert_eq!(id, NIL_UUID);
                assert_eq!(issuer_public_key, "@issuer.asc");
                assert_eq!(signature, "@payload.asc");
                assert_eq!(issuer_name.as_deref(), Some("root"));
            }
            _ => panic!("expected trust-attestation verify"),
        }
        assert!(try_parse(&["test", "key", "trust-attestation", "verify", NIL_UUID]).is_err());
    }

    #[tokio::test]
    async fn handler_show_trust_attestation() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/signing/keys/{NIL_UUID}/trust-attestation"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(attestation_json()))
            .expect(2)
            .mount(&server)
            .await;

        for format in [OutputFormat::Json, OutputFormat::Table] {
            let global = crate::test_utils::test_global(format);
            let result = show_trust_attestation(NIL_UUID, &global).await;
            assert!(result.is_ok(), "{result:?}");
        }
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_show_trust_attestation_none_is_not_an_error() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/signing/keys/{NIL_UUID}/trust-attestation"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_string("null"))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let result = show_trust_attestation(NIL_UUID, &global).await;
        assert!(result.is_ok(), "{result:?}");
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_trust_attestation_challenge() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/v1/signing/keys/{NIL_UUID}/trust-attestation/challenge"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "signing_key_id": NIL_UUID,
                "payload": "artifact-keeper-signing-key-attestation\n",
                "key_public_key_armored": "-----BEGIN PGP PUBLIC KEY BLOCK-----",
                "key_type": "gpg",
                "algorithm": "rsa4096",
                "key_fingerprint": "ABCD"
            })))
            .expect(2)
            .mount(&server)
            .await;

        for format in [OutputFormat::Json, OutputFormat::Quiet] {
            let global = crate::test_utils::test_global(format);
            let result = trust_attestation_challenge(NIL_UUID, &global).await;
            assert!(result.is_ok(), "{result:?}");
        }
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn handler_verify_trust_attestation_sends_the_signature() {
        use wiremock::matchers::body_json;
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        Mock::given(method("POST"))
            .and(path(format!(
                "/api/v1/signing/keys/{NIL_UUID}/trust-attestation/verify"
            )))
            .and(body_json(serde_json::json!({
                "issuer_public_key_armored": "KEY",
                "signature_armored": "SIG",
                "issuer_name": "root"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(attestation_json()))
            .expect(1)
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Quiet);
        let result = verify_trust_attestation(
            NIL_UUID,
            "KEY".into(),
            "SIG".into(),
            Some("root".into()),
            &global,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        crate::test_utils::teardown_env();
    }

    #[tokio::test]
    async fn trust_attestation_on_1_11_says_it_needs_1_12() {
        let (server, tmp) = crate::test_utils::mock_setup().await;
        let _guard = crate::test_utils::setup_env(&tmp);
        health(&server, "1.11.14").await;
        Mock::given(path_regex("/trust-attestation"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let global = crate::test_utils::test_global(OutputFormat::Json);
        let errors = [
            (
                "show",
                show_trust_attestation(NIL_UUID, &global).await.unwrap_err(),
            ),
            (
                "challenge",
                trust_attestation_challenge(NIL_UUID, &global)
                    .await
                    .unwrap_err(),
            ),
            (
                "verify",
                verify_trust_attestation(NIL_UUID, "K".into(), "S".into(), None, &global)
                    .await
                    .unwrap_err(),
            ),
        ];
        for (leaf, err) in errors {
            let err = err.to_string();
            assert!(
                err.contains(&format!(
                    "`ak sign key trust-attestation {leaf}` needs a server on 1.12"
                )),
                "{err}"
            );
        }
        crate::test_utils::teardown_env();
    }
}
