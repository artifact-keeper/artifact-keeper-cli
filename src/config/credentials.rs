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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::ENV_LOCK;

    fn with_temp_config<F: FnOnce()>(f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };
        f();
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn stored_credential_serialization() {
        let cred = StoredCredential {
            access_token: "abc123".into(),
            refresh_token: Some("refresh456".into()),
        };
        let json = serde_json::to_string(&cred).unwrap();
        let loaded: StoredCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.access_token, "abc123");
        assert_eq!(loaded.refresh_token.as_deref(), Some("refresh456"));
    }

    #[test]
    fn stored_credential_without_refresh() {
        let cred = StoredCredential {
            access_token: "token".into(),
            refresh_token: None,
        };
        let json = serde_json::to_string(&cred).unwrap();
        let loaded: StoredCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.access_token, "token");
        assert!(loaded.refresh_token.is_none());
    }

    #[test]
    fn file_store_and_load() {
        with_temp_config(|| {
            let json = r#"{"access_token":"test-token","refresh_token":null}"#;
            store_to_file("myinstance", json).unwrap();

            let loaded = load_from_file("myinstance").unwrap();
            assert_eq!(loaded.as_deref(), Some(json));
        });
    }

    #[test]
    fn file_load_nonexistent_instance() {
        with_temp_config(|| {
            let loaded = load_from_file("nonexistent").unwrap();
            assert!(loaded.is_none());
        });
    }

    #[test]
    fn file_delete() {
        with_temp_config(|| {
            let json = r#"{"access_token":"t","refresh_token":null}"#;
            store_to_file("to-delete", json).unwrap();

            delete_from_file("to-delete").unwrap();

            let loaded = load_from_file("to-delete").unwrap();
            assert!(loaded.is_none());
        });
    }

    #[test]
    fn file_delete_nonexistent_is_ok() {
        with_temp_config(|| {
            // Should not error
            delete_from_file("nonexistent").unwrap();
        });
    }

    #[test]
    fn file_store_multiple_instances() {
        with_temp_config(|| {
            store_to_file("instance-a", r#"{"access_token":"a","refresh_token":null}"#).unwrap();
            store_to_file("instance-b", r#"{"access_token":"b","refresh_token":null}"#).unwrap();

            let a = load_from_file("instance-a").unwrap().unwrap();
            let b = load_from_file("instance-b").unwrap().unwrap();
            assert!(a.contains("\"a\""));
            assert!(b.contains("\"b\""));
        });
    }

    #[test]
    fn file_overwrite_existing() {
        with_temp_config(|| {
            store_to_file("inst", r#"{"access_token":"old","refresh_token":null}"#).unwrap();
            store_to_file("inst", r#"{"access_token":"new","refresh_token":null}"#).unwrap();

            let loaded = load_from_file("inst").unwrap().unwrap();
            assert!(loaded.contains("\"new\""));
            assert!(!loaded.contains("\"old\""));
        });
    }

    #[test]
    fn get_credential_from_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("AK_TOKEN", "env-token-123") };

        let cred = get_credential("any-instance").unwrap();
        assert_eq!(cred.access_token, "env-token-123");
        assert!(cred.refresh_token.is_none());

        unsafe { std::env::remove_var("AK_TOKEN") };
    }

    #[test]
    fn get_credential_not_found() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("AK_TOKEN") };
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let result = get_credential("no-such-instance");
        assert!(result.is_err());

        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn get_credential_from_file_fallback() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("AK_TOKEN") };
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let cred = StoredCredential {
            access_token: "file-token".into(),
            refresh_token: None,
        };
        let json = serde_json::to_string(&cred).unwrap();
        store_to_file("file-inst", &json).unwrap();

        let loaded = get_credential("file-inst").unwrap();
        assert_eq!(loaded.access_token, "file-token");

        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn delete_credential_cleans_file() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };

        let json = r#"{"access_token":"t","refresh_token":null}"#;
        store_to_file("del-test", json).unwrap();

        delete_credential("del-test").unwrap();

        let loaded = load_from_file("del-test").unwrap();
        assert!(loaded.is_none());

        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }
}
