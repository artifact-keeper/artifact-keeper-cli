//! E2E tests for `ak sso` provider CRUD. Logging in through a provider needs an LDAP
//! server or an identity provider, which the E2E stack doesn't have: see the contract
//! tests in tests/auth_contract.rs.

mod common;

use serde_json::Value;

fn json_of(cmd: &mut assert_cmd::Command) -> Value {
    let output = cmd.output().expect("run ak");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON")
}

/// Deletes a provider when dropped, so a failed assertion doesn't leave it behind.
struct Provider<'a> {
    env: &'a common::TestEnv,
    kind: &'static str,
    id: String,
}

impl Drop for Provider<'_> {
    fn drop(&mut self) {
        let _ = self
            .env
            .api_delete(&format!("/api/v1/admin/sso/{}/{}", self.kind, self.id));
    }
}

fn name(kind: &str) -> String {
    format!("e2e-{kind}-{}", std::process::id())
}

#[test]
#[ignore = "requires E2E backend"]
fn ldap_create_sets_every_flag_and_update_changes_only_what_is_given() {
    let env = common::TestEnv::setup();
    let name = name("ldap");
    let output = env
        .ak_cmd()
        .args(["sso", "create", "ldap", &name])
        .args(["--server-url", "ldaps://ldap.example.com"])
        .args(["--user-base-dn", "dc=example,dc=com"])
        .args(["--bind-dn", "cn=reader"])
        .arg("--bind-password-stdin")
        .args(["--user-filter", "(uid={0})"])
        .args(["--username-attribute", "uid"])
        .args(["--email-attribute", "mail"])
        .args(["--display-name-attribute", "cn"])
        .args(["--groups-attribute", "memberOf"])
        .args(["--group-base-dn", "ou=groups"])
        .args(["--group-filter", "(member={0})"])
        .args(["--admin-group-dn", "cn=admins"])
        .args(["--insecure-skip-verify", "true"])
        .args(["--priority", "7"])
        .args(["--is-enabled", "false"])
        .write_stdin("the-bind-password")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("the-bind-password"));
    let created: Value = serde_json::from_slice(&output.stdout).unwrap();
    let provider = Provider {
        env: &env,
        kind: "ldap",
        id: created["id"].as_str().unwrap().to_string(),
    };
    let id = provider.id.as_str();
    assert_eq!(created["has_bind_password"], true);
    assert_eq!(created["user_filter"], "(uid={0})");
    assert_eq!(created["username_attribute"], "uid");
    assert_eq!(created["email_attribute"], "mail");
    assert_eq!(created["display_name_attribute"], "cn");
    assert_eq!(created["groups_attribute"], "memberOf");
    assert_eq!(created["group_base_dn"], "ou=groups");
    assert_eq!(created["group_filter"], "(member={0})");
    assert_eq!(created["admin_group_dn"], "cn=admins");
    assert_eq!(created["insecure_skip_verify"], true);
    assert_eq!(created["priority"], 7);
    assert_eq!(created["is_enabled"], false);

    let shown = json_of(env.ak_cmd().args(["sso", "show", id, "--type", "ldap"]));
    assert_eq!(shown, created);

    let listed = json_of(env.ak_cmd().args(["sso", "list"]));
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == id && p["name"] == name.as_str()),
        "{listed}"
    );

    let updated = json_of(env.ak_cmd().args([
        "sso",
        "update",
        "ldap",
        id,
        "--insecure-skip-verify",
        "false",
        "--priority",
        "8",
    ]));
    assert_eq!(updated["insecure_skip_verify"], false);
    assert_eq!(updated["priority"], 8);
    assert_eq!(updated["user_filter"], "(uid={0})", "the rest stays");

    env.ak_cmd()
        .args(["sso", "toggle", id, "--type", "ldap", "--enable"])
        .assert()
        .success();
    let shown = json_of(env.ak_cmd().args(["sso", "show", id, "--type", "ldap"]));
    assert_eq!(shown["is_enabled"], true);

    env.ak_cmd()
        .args(["sso", "toggle", id, "--type", "ldap"])
        .assert()
        .success();
    let shown = json_of(env.ak_cmd().args(["sso", "show", id, "--type", "ldap"]));
    assert_eq!(shown["is_enabled"], false);

    env.ak_cmd()
        .args(["sso", "delete", id, "--type", "ldap", "--yes"])
        .assert()
        .success();
    env.ak_cmd()
        .args(["sso", "show", id, "--type", "ldap"])
        .assert()
        .failure();
}

#[test]
#[ignore = "requires E2E backend"]
fn oidc_create_sets_every_flag_and_shows_on_the_login_screen() {
    let env = common::TestEnv::setup();
    let name = name("oidc");
    let output = env
        .ak_cmd()
        .args(["sso", "create", "oidc", &name])
        .args(["--issuer-url", "https://idp.example.com"])
        .args(["--client-id", "the-client"])
        .arg("--client-secret-stdin")
        .arg("--auto-create-users")
        .args(["--admin-group", "admins"])
        .args(["--allow-legacy-rsa-keys", "true"])
        .args(["--attribute-mapping", r#"{"email":"mail"}"#])
        .args(["--map-groups-to-groups", "true"])
        .args(["--pkce-enabled", "false"])
        .args(["--scope", "openid", "--scope", "profile"])
        .args(["--is-enabled", "true"])
        .write_stdin("the-client-secret")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("the-client-secret"));
    let created: Value = serde_json::from_slice(&output.stdout).unwrap();
    let provider = Provider {
        env: &env,
        kind: "oidc",
        id: created["id"].as_str().unwrap().to_string(),
    };
    let id = provider.id.as_str();
    assert_eq!(created["has_secret"], true);
    assert_eq!(created["auto_create_users"], true);
    assert_eq!(created["allow_legacy_rsa_keys"], true);
    assert_eq!(created["map_groups_to_groups"], true);
    assert_eq!(created["pkce_enabled"], false);
    assert_eq!(created["is_enabled"], true);
    assert_eq!(created["scopes"], serde_json::json!(["openid", "profile"]));
    assert_eq!(created["attribute_mapping"]["email"], "mail");
    assert_eq!(created["attribute_mapping"]["admin_group"], "admins");

    // What a browser would be sent to needs an identity provider to go any further,
    // but it's the server that says so, so the request got there.
    let public = json_of(env.ak_cmd().args(["sso", "providers", "--public"]));
    assert!(
        public.as_array().unwrap().iter().any(|p| p["id"] == id),
        "{public}"
    );
    let admin = json_of(env.ak_cmd().args(["sso", "providers"]));
    assert!(
        admin.as_array().unwrap().iter().any(|p| p["id"] == id),
        "{admin}"
    );

    let updated = json_of(env.ak_cmd().args([
        "sso",
        "update",
        "oidc",
        id,
        "--admin-group",
        "others",
        "--attribute-mapping",
        r#"{"name":"cn"}"#,
        "--attribute-mapping-replace",
        "true",
    ]));
    assert_eq!(updated["attribute_mapping"]["name"], "cn");
    assert_eq!(updated["attribute_mapping"]["admin_group"], "others");
    assert!(
        updated["attribute_mapping"].get("email").is_none(),
        "the mapping was merged rather than replaced: {updated}"
    );
}

#[test]
#[ignore = "requires E2E backend"]
fn saml_create_sets_every_flag_and_update_sets_the_slug() {
    let env = common::TestEnv::setup();
    let name = name("saml");
    let slug = format!("slug-{}", std::process::id());
    let cert = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(cert.path(), "from a file").unwrap();
    let created = json_of(
        env.ak_cmd()
            .args(["sso", "create", "saml", &name])
            .args(["--entity-id", "urn:idp"])
            .args(["--sso-url", "https://idp.example.com/sso"])
            .args(["--certificate", &format!("@{}", cert.path().display())])
            .arg("--sign-requests")
            .args(["--sp-entity-id", "urn:sp"])
            .args(["--slo-url", "https://idp.example.com/slo"])
            .args(["--name-id-format", "email"])
            .args(["--admin-group", "admins"])
            .args(["--attribute-mapping", r#"{"email":"mail"}"#])
            .args(["--map-groups-to-groups", "true"])
            .args(["--slug", &slug])
            .args(["--require-signed-assertions", "true"])
            .args(["--use-absolute-acs-url", "true"])
            .args(["--is-enabled", "false"]),
    );
    let provider = Provider {
        env: &env,
        kind: "saml",
        id: created["id"].as_str().unwrap().to_string(),
    };
    let id = provider.id.as_str();
    assert_eq!(created["slug"], slug.as_str());
    assert_eq!(created["sp_entity_id"], "urn:sp");
    assert_eq!(created["slo_url"], "https://idp.example.com/slo");
    assert_eq!(created["name_id_format"], "email");
    assert_eq!(created["admin_group"], "admins");
    assert_eq!(created["attribute_mapping"]["email"], "mail");
    assert_eq!(created["map_groups_to_groups"], true);
    assert_eq!(created["sign_requests"], true);
    assert_eq!(created["require_signed_assertions"], true);
    assert_eq!(created["use_absolute_acs_url"], true);
    assert_eq!(created["is_enabled"], false);

    let new_slug = format!("{slug}-2");
    let updated = json_of(env.ak_cmd().args([
        "sso",
        "update",
        "saml",
        id,
        "--slug",
        &new_slug,
        "--map-groups-to-groups",
        "false",
        "--attribute-mapping",
        r#"{"email":"email"}"#,
    ]));
    assert_eq!(updated["slug"], new_slug.as_str());
    assert_eq!(updated["map_groups_to_groups"], false);
    assert_eq!(updated["attribute_mapping"]["email"], "email");
}

#[test]
#[ignore = "requires E2E backend"]
fn a_bad_attribute_mapping_is_refused_before_any_request() {
    let env = common::TestEnv::setup();
    env.ak_cmd()
        .args(["sso", "create", "saml", "e2e-never-created"])
        .args(["--entity-id", "urn:idp"])
        .args(["--sso-url", "https://idp.example.com/sso"])
        .args(["--certificate", "text"])
        .args(["--attribute-mapping", "not json"])
        .assert()
        .failure();
    let listed = json_of(env.ak_cmd().args(["sso", "list"]));
    assert!(
        !listed
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "e2e-never-created")
    );
}
