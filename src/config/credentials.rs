use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use miette::{IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};

use crate::error::AkError;

const KEYRING_SERVICE: &str = "artifact-keeper-cli";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

/// Store a credential for a given instance.
///
/// Tries OS keychain first; falls back to a credential file.
pub fn store_credential(instance: &str, cred: &StoredCredential) -> Result<()> {
    let json = serde_json::to_string(cred).into_diagnostic()?;

    let keychain_ok = keyring::Entry::new(KEYRING_SERVICE, instance)
        .and_then(|entry| entry.set_password(&json))
        .is_ok();

    if keychain_ok {
        return Ok(());
    }

    eprintln!("Keychain unavailable, using file fallback");
    store_to_file(instance, &json)
}

/// Retrieve a credential for a given instance.
///
/// Precedence: `AK_TOKEN` env var -> OS keychain -> credential file.
pub fn get_credential(instance: &str) -> Result<StoredCredential> {
    if let Ok(token) = std::env::var("AK_TOKEN") {
        return Ok(StoredCredential {
            access_token: token,
            refresh_token: None,
        });
    }

    if let Some(cred) = get_from_keychain(instance) {
        return Ok(cred);
    }

    if let Some(json) = load_from_file(instance)? {
        let cred: StoredCredential = serde_json::from_str(&json).into_diagnostic()?;
        return Ok(cred);
    }

    Err(AkError::NotAuthenticated(instance.to_string()).into())
}

/// Delete credential for a given instance from all stores.
pub fn delete_credential(instance: &str) -> Result<()> {
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, instance) {
        let _ = entry.delete_credential();
    }

    delete_from_file(instance)
}

fn get_from_keychain(instance: &str) -> Option<StoredCredential> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, instance).ok()?;
    let json = entry.get_password().ok()?;
    serde_json::from_str(&json).ok()
}

// --- File-based fallback ---

fn credentials_path() -> Result<PathBuf> {
    Ok(super::config_dir()?.join("credentials.json"))
}

fn load_all_file_creds() -> Result<HashMap<String, String>> {
    let path = credentials_path()?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let content = fs::read_to_string(&path).into_diagnostic()?;
    serde_json::from_str(&content).into_diagnostic()
}

fn save_all_file_creds(creds: &HashMap<String, String>) -> Result<()> {
    let path = credentials_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).into_diagnostic()?;
    }
    let content = serde_json::to_string_pretty(creds).into_diagnostic()?;
    fs::write(&path, content).into_diagnostic()
}

fn store_to_file(instance: &str, json: &str) -> Result<()> {
    let mut creds = load_all_file_creds()?;
    creds.insert(instance.to_string(), json.to_string());
    save_all_file_creds(&creds)
}

fn load_from_file(instance: &str) -> Result<Option<String>> {
    let creds = load_all_file_creds()?;
    Ok(creds.get(instance).cloned())
}

fn delete_from_file(instance: &str) -> Result<()> {
    let mut creds = load_all_file_creds()?;
    if creds.remove(instance).is_some() {
        save_all_file_creds(&creds)?;
    }
    Ok(())
}
