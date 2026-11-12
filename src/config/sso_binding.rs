//! The binding cookie of an OIDC or SAML login that hasn't been finished yet.
//!
//! Since 1.12 the server binds a browser login to the client that started it: the
//! login response sets an `ak_sso_bind_*` cookie, and `POST /auth/sso/exchange`
//! redeems the code only with that cookie. `ak auth login --sso oidc:<id>
//! --no-input` stops before the code is known and `ak auth sso-exchange` finishes
//! it in another process, so the cookie is kept here in between, per instance.
//! The file is owner-only, the cookie is useless after the server's 10 minutes,
//! and it's dropped after a successful exchange.

use std::collections::HashMap;
use std::path::PathBuf;

use miette::{IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};

/// The name every binding cookie starts with.
pub const COOKIE_PREFIX: &str = "ak_sso_bind_";

/// How long a pending binding is kept: the server's lifetime for the cookie and
/// the login's `state`.
pub const MAX_AGE_SECS: i64 = 600;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
struct Pending {
    /// `name=value`, as it goes in a `Cookie` header.
    cookie: String,
    /// When the login started, in seconds since the Unix epoch.
    started: i64,
}

fn path() -> Result<PathBuf> {
    Ok(super::config_dir()?.join("sso-pending.json"))
}

fn load_all() -> HashMap<String, Pending> {
    path()
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|content| serde_json::from_str(&content).ok())
        .unwrap_or_default()
}

fn save_all(all: &HashMap<String, Pending>) -> Result<()> {
    let path = path()?;
    if all.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).into_diagnostic(),
            _ => Ok(()),
        };
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).into_diagnostic()?;
    }
    let content = serde_json::to_string_pretty(all).into_diagnostic()?;
    super::write_private_atomic(&path, content)
}

/// The `name=value` of the binding cookie in a login response's `Set-Cookie`
/// headers, if the server set one. Servers before 1.12 don't.
pub fn from_set_cookie<'a>(headers: impl IntoIterator<Item = &'a str>) -> Option<String> {
    headers.into_iter().find_map(|header| {
        let pair = header.split(';').next()?.trim();
        let (name, value) = pair.split_once('=')?;
        let usable = name.starts_with(COOKIE_PREFIX)
            && !value.is_empty()
            && pair
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b',' && b != b'"');
        usable.then(|| pair.to_string())
    })
}

/// Keep the binding cookie of a login just started, replacing any earlier one for
/// this instance. With no cookie, forget the earlier one, so an exchange sends none.
pub fn store(instance: &str, cookie: Option<&str>) -> Result<()> {
    store_at(instance, cookie, chrono::Utc::now().timestamp())
}

fn store_at(instance: &str, cookie: Option<&str>, now: i64) -> Result<()> {
    let mut all = load_all();
    all.retain(|_, pending| fresh(pending, now));
    match cookie {
        Some(cookie) => {
            all.insert(
                instance.to_string(),
                Pending {
                    cookie: cookie.to_string(),
                    started: now,
                },
            );
        }
        None if !all.contains_key(instance) => return Ok(()),
        None => {
            all.remove(instance);
        }
    }
    save_all(&all)
}

/// The binding cookie of this instance's pending login, if it's recent enough.
pub fn load(instance: &str) -> Option<String> {
    load_at(instance, chrono::Utc::now().timestamp())
}

fn load_at(instance: &str, now: i64) -> Option<String> {
    load_all()
        .get(instance)
        .filter(|pending| fresh(pending, now))
        .map(|pending| pending.cookie.clone())
}

/// Forget this instance's pending login, after its exchange worked.
pub fn remove(instance: &str) -> Result<()> {
    let mut all = load_all();
    if all.remove(instance).is_none() {
        return Ok(());
    }
    save_all(&all)
}

fn fresh(pending: &Pending, now: i64) -> bool {
    (0..=MAX_AGE_SECS).contains(&(now - pending.started))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::ENV_LOCK;

    const COOKIE: &str = "ak_sso_bind_0123456789abcdef=\
                          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn with_temp_config<F: FnOnce(&std::path::Path)>(f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AK_CONFIG_DIR", dir.path()) };
        f(dir.path());
        unsafe { std::env::remove_var("AK_CONFIG_DIR") };
    }

    #[test]
    fn finds_the_binding_cookie_among_others() {
        let set = format!("{COOKIE}; HttpOnly; SameSite=Lax; Path=/api/v1/auth/sso; Max-Age=600");
        assert_eq!(
            from_set_cookie(["other=1; Path=/", set.as_str()]),
            Some(COOKIE.into())
        );
    }

    #[test]
    fn no_binding_cookie_is_none() {
        assert_eq!(from_set_cookie(["session=abc; Path=/"]), None);
        assert_eq!(from_set_cookie([]), None);
        assert_eq!(from_set_cookie(["ak_sso_bind_x=; Path=/"]), None);
        assert_eq!(from_set_cookie(["ak_sso_bind_x=a b"]), None);
    }

    #[test]
    fn round_trip_then_removed() {
        with_temp_config(|dir| {
            store("t", Some(COOKIE)).unwrap();
            assert_eq!(load("t").as_deref(), Some(COOKIE));
            assert_eq!(load("other"), None);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(dir.join("sso-pending.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600);
            }
            remove("t").unwrap();
            assert_eq!(load("t"), None);
            assert!(!dir.join("sso-pending.json").exists());
        });
    }

    #[test]
    fn expires_after_ten_minutes() {
        with_temp_config(|_| {
            store_at("t", Some(COOKIE), 1_000).unwrap();
            assert_eq!(load_at("t", 1_000 + MAX_AGE_SECS).as_deref(), Some(COOKIE));
            assert_eq!(load_at("t", 1_000 + MAX_AGE_SECS + 1), None);
        });
    }

    #[test]
    fn a_login_without_a_cookie_forgets_the_earlier_one() {
        with_temp_config(|_| {
            store("t", Some(COOKIE)).unwrap();
            store("u", Some(COOKIE)).unwrap();
            store("t", None).unwrap();
            assert_eq!(load("t"), None);
            assert_eq!(load("u").as_deref(), Some(COOKIE));
        });
    }

    #[test]
    fn stale_entries_are_dropped_on_the_next_login() {
        with_temp_config(|_| {
            store_at("old", Some(COOKIE), 1_000).unwrap();
            store_at("t", Some(COOKIE), 1_000 + MAX_AGE_SECS + 5).unwrap();
            assert!(!load_all().contains_key("old"));
        });
    }
}
