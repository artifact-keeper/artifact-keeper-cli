//! Logins and password changes, against a mock server. Contract, not E2E: there's no
//! LDAP server or identity provider in the E2E stack, so the SSO flows here have never
//! met a real one. tests/e2e_auth.rs and tests/e2e_totp.rs run the rest for real.

#[path = "common/mock.rs"]
mod mock;

use mock::Mocked;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const ID: &str = "00000000-0000-0000-0000-000000000001";
const PASSWORD: &str = "hunter2-the-password";
const ACCESS: &str = "the-access-token";
const REFRESH: &str = "the-refresh-token";
const TICKET: &str = "the-one-time-ticket";

fn session() -> Value {
    json!({
        "access_token": ACCESS, "refresh_token": REFRESH, "expires_in": 1800,
        "token_type": "Bearer", "must_change_password": false
    })
}

fn wants(field: &str) -> Value {
    json!({
        "access_token": "", "refresh_token": "", "expires_in": 0, "token_type": "Bearer",
        "must_change_password": false, field: true, "totp_token": TICKET
    })
}

/// Everything the command printed, for checking what it must not have.
fn printed(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_no_secrets(output: &std::process::Output) {
    let all = printed(output);
    for secret in [PASSWORD, ACCESS, REFRESH] {
        assert!(!all.contains(secret), "printed a secret: {all}");
    }
}

#[tokio::test]
async fn password_login_stores_the_session_and_prints_no_secret() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/auth/login", 200, session())
        .await;
    let output = m.ak_anon(
        &["auth", "login", "--username", "alice", "--password-stdin"],
        PASSWORD,
        &[],
    );
    assert!(output.status.success(), "{}", printed(&output));
    assert_no_secrets(&output);
    let (_, body) = m.last("POST").await;
    assert_eq!(body, json!({"username": "alice", "password": PASSWORD}));
    assert!(m.stored_credentials().contains(ACCESS));
    assert!(m.stored_credentials().contains(REFRESH));
}

#[tokio::test]
async fn a_totp_challenge_is_answered_and_the_ticket_stays_private() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/auth/login", 200, wants("totp_required"))
        .await;
    m.respond("POST", "/api/v1/auth/totp/verify", 200, session())
        .await;
    let output = m.ak_anon(
        &["auth", "login", "--username", "alice", "--password-stdin"],
        PASSWORD,
        &[("AK_TOTP_CODE", "123456")],
    );
    assert!(output.status.success(), "{}", printed(&output));
    assert_no_secrets(&output);
    assert!(!printed(&output).contains(TICKET));
    assert!(!printed(&output).contains("123456"));
    let (_, body) = m.last("POST").await;
    assert_eq!(body, json!({"code": "123456", "totp_token": TICKET}));
    assert!(m.stored_credentials().contains(ACCESS));
}

#[tokio::test]
async fn a_totp_challenge_without_a_code_stores_nothing_and_says_how() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/auth/login", 200, wants("totp_required"))
        .await;
    let output = m.ak_anon(
        &["auth", "login", "--username", "alice", "--password-stdin"],
        PASSWORD,
        &[],
    );
    assert!(!output.status.success());
    let text = mock::unwrapped(&output.stderr);
    assert!(text.contains("--print-totp-ticket"), "{text}");
    assert!(!text.contains(TICKET), "{text}");
    assert_eq!(m.stored_credentials(), "");
}

#[tokio::test]
async fn the_ticket_is_printed_only_when_asked_for() {
    for field in ["totp_required", "totp_enrollment_required"] {
        let m = Mocked::start().await;
        m.respond("POST", "/api/v1/auth/login", 200, wants(field))
            .await;
        let output = m.ak_anon(
            &[
                "auth",
                "login",
                "--username",
                "alice",
                "--password-stdin",
                "--print-totp-ticket",
            ],
            PASSWORD,
            &[],
        );
        assert!(output.status.success(), "{}", printed(&output));
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), TICKET);
        assert_eq!(m.stored_credentials(), "");
    }
}

/// A server that wants enrollment sends empty tokens. Storing those as a session
/// would report a login that never happened.
#[tokio::test]
async fn enrollment_required_is_not_a_login() {
    let m = Mocked::start().await;
    m.respond(
        "POST",
        "/api/v1/auth/login",
        200,
        wants("totp_enrollment_required"),
    )
    .await;
    let output = m.ak_anon(
        &["auth", "login", "--username", "alice", "--password-stdin"],
        PASSWORD,
        &[],
    );
    assert!(!output.status.success());
    assert!(mock::unwrapped(&output.stderr).contains("ak totp enroll"));
    assert_eq!(m.stored_credentials(), "");
}

#[tokio::test]
async fn ldap_login_posts_to_the_provider_and_stores_the_session() {
    let m = Mocked::start().await;
    let route = format!("/api/v1/auth/sso/ldap/{ID}/login");
    m.respond("POST", &route, 200, session()).await;
    let sso = format!("ldap:{ID}");
    let output = m.ak_anon(
        &[
            "auth",
            "login",
            "--sso",
            &sso,
            "--username",
            "alice",
            "--password-stdin",
        ],
        PASSWORD,
        &[],
    );
    assert!(output.status.success(), "{}", printed(&output));
    assert_no_secrets(&output);
    let (_, body) = m.last("POST").await;
    assert_eq!(body, json!({"username": "alice", "password": PASSWORD}));
    assert!(m.stored_credentials().contains(ACCESS));
}

#[tokio::test]
async fn ldap_login_failure_shows_the_servers_message() {
    let m = Mocked::start().await;
    let route = format!("/api/v1/auth/sso/ldap/{ID}/login");
    m.respond("POST", &route, 401, json!({"message": "Bad bind"}))
        .await;
    let sso = format!("ldap:{ID}");
    let output = m.ak_anon(
        &[
            "auth",
            "login",
            "--sso",
            &sso,
            "--username",
            "alice",
            "--password-stdin",
        ],
        PASSWORD,
        &[],
    );
    assert!(!output.status.success());
    assert!(mock::unwrapped(&output.stderr).contains("Bad bind"));
    assert_no_secrets(&output);
    assert_eq!(m.stored_credentials(), "");
}

#[tokio::test]
async fn ldap_login_does_not_follow_a_redirect_with_the_password() {
    let m = Mocked::start().await;
    let route = format!("/api/v1/auth/sso/ldap/{ID}/login");
    let elsewhere = format!("{}/elsewhere", m.server.uri());
    Mock::given(method("POST"))
        .and(path(route.as_str()))
        .respond_with(ResponseTemplate::new(307).insert_header("location", elsewhere.as_str()))
        .mount(&m.server)
        .await;
    let sso = format!("ldap:{ID}");
    let output = m.ak_anon(
        &[
            "auth",
            "login",
            "--sso",
            &sso,
            "--username",
            "alice",
            "--password-stdin",
        ],
        PASSWORD,
        &[],
    );
    assert!(!output.status.success());
    let requests = m.server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "followed the redirect");
    assert_eq!(m.stored_credentials(), "");
}

async fn redirect(m: &Mocked, route: &str, to: &str) {
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(307).insert_header("location", to))
        .mount(&m.server)
        .await;
}

#[tokio::test]
async fn oidc_login_prints_the_providers_url_without_following_it() {
    let m = Mocked::start().await;
    let to = "https://idp.example.com/authorize?state=abc";
    redirect(&m, &format!("/api/v1/auth/sso/oidc/{ID}/login"), to).await;
    let sso = format!("oidc:{ID}");
    let output = m.ak_anon(
        &[
            "--format", "json", "auth", "login", "--sso", &sso, "--prompt", "login",
        ],
        "",
        &[],
    );
    assert!(output.status.success(), "{}", printed(&output));
    let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(shown["login_url"], to);
    assert_eq!(shown["provider_type"], "oidc");
    let (query, _) = m.last("GET").await;
    assert_eq!(query, vec![("prompt".to_string(), "login".to_string())]);
    assert!(mock::unwrapped(&output.stderr).contains("sso-exchange"));
    // It's only the start of a login.
    assert_eq!(m.stored_credentials(), "");
    let requests = m.server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "followed the redirect");
    assert!(
        !requests[0].headers.contains_key("authorization"),
        "sent a credential"
    );
}

#[tokio::test]
async fn saml_login_prints_the_url_alone_when_quiet() {
    let m = Mocked::start().await;
    let to = "https://idp.example.com/saml?SAMLRequest=x";
    redirect(&m, &format!("/api/v1/auth/sso/saml/{ID}/login"), to).await;
    let sso = format!("saml:{ID}");
    let output = m.ak_anon(
        &["--format", "quiet", "auth", "login", "--sso", &sso],
        "",
        &[],
    );
    assert!(output.status.success(), "{}", printed(&output));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), to);
}

#[tokio::test]
async fn sso_login_that_does_not_redirect_is_an_error() {
    let m = Mocked::start().await;
    let route = format!("/api/v1/auth/sso/oidc/{ID}/login");
    m.respond("GET", &route, 404, json!({"message": "No such provider"}))
        .await;
    let sso = format!("oidc:{ID}");
    let output = m.ak_anon(&["auth", "login", "--sso", &sso], "", &[]);
    assert!(!output.status.success());
    assert!(mock::unwrapped(&output.stderr).contains("No such provider"));
}

#[tokio::test]
async fn sso_exchange_takes_a_code_or_the_callback_url() {
    for given in [
        "the-code",
        "/callback?code=the-code",
        "https://ak.example.com/callback?state=s&code=the-code",
    ] {
        let m = Mocked::start().await;
        m.respond("POST", "/api/v1/auth/sso/exchange", 200, session())
            .await;
        let output = m.ak_anon(&["auth", "sso-exchange", "--code-stdin"], given, &[]);
        assert!(output.status.success(), "{}", printed(&output));
        assert_no_secrets(&output);
        let (_, body) = m.last("POST").await;
        assert_eq!(body, json!({"code": "the-code"}), "{given}");
        assert!(m.stored_credentials().contains(ACCESS));
    }
}

#[tokio::test]
async fn enroll_complete_stores_the_session_and_prints_only_the_backup_codes() {
    let m = Mocked::start().await;
    let mut done = session();
    done["backup_codes"] = json!(["one", "two"]);
    m.respond("POST", "/api/v1/auth/totp/enroll/complete", 200, done)
        .await;
    let output = m.ak_anon(
        &[
            "--format",
            "json",
            "totp",
            "enroll",
            "complete",
            "--totp-token-stdin",
            "--code",
            "123456",
        ],
        TICKET,
        &[],
    );
    assert!(output.status.success(), "{}", printed(&output));
    assert_no_secrets(&output);
    let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(shown["backup_codes"], json!(["one", "two"]));
    let (_, body) = m.last("POST").await;
    assert_eq!(body, json!({"code": "123456", "totp_token": TICKET}));
    assert!(m.stored_credentials().contains(ACCESS));
}

#[tokio::test]
async fn enroll_setup_sends_the_ticket_and_shows_the_secret() {
    let m = Mocked::start().await;
    let setup = json!({"secret": "JBSWY3DP", "qr_code_url": "otpauth://x"});
    m.respond("POST", "/api/v1/auth/totp/enroll/setup", 200, setup)
        .await;
    let output = m.ak_anon(
        &[
            "--format",
            "quiet",
            "totp",
            "enroll",
            "setup",
            "--totp-token-stdin",
        ],
        TICKET,
        &[],
    );
    assert!(output.status.success(), "{}", printed(&output));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "JBSWY3DP");
    let (_, body) = m.last("POST").await;
    assert_eq!(body, json!({"totp_token": TICKET}));
}

#[tokio::test]
async fn totp_commands_take_secrets_from_stdin_and_never_print_them() {
    let m = Mocked::start().await;
    m.respond("POST", "/api/v1/auth/totp/disable", 200, json!({}))
        .await;
    let output = m.ak_stdin(
        &["totp", "disable", "--password-stdin", "--code", "654321"],
        PASSWORD,
    );
    assert!(output.status.success(), "{}", printed(&output));
    assert_no_secrets(&output);
    let (_, body) = m.last("POST").await;
    assert_eq!(body, json!({"password": PASSWORD, "code": "654321"}));

    let m = Mocked::start().await;
    m.respond(
        "POST",
        "/api/v1/auth/totp/enable",
        200,
        json!({"backup_codes": ["a"], "from_a_newer_server": 1}),
    )
    .await;
    let output = m.ak_stdin(
        &["--format", "json", "totp", "enable", "--code-stdin"],
        "123456\n",
    );
    assert!(output.status.success(), "{}", printed(&output));
    assert!(!printed(&output).contains("123456"));
    let (_, body) = m.last("POST").await;
    assert_eq!(body, json!({"code": "123456"}));
    let shown: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(shown["from_a_newer_server"], 1, "not the server's body");
}

/// `resolve_secret` warns about a secret on the command line. Keep that from going
/// away, since nothing else tells a user that it's in their shell history.
#[tokio::test]
async fn a_password_on_the_command_line_gets_a_warning() {
    let m = Mocked::start().await;
    m.respond_empty("POST", "/api/v1/users/me/password", 200)
        .await;
    let output = m.ak(&[
        "profile",
        "change-password",
        "--current-password",
        PASSWORD,
        "--new-password",
        "another-long-password",
    ]);
    assert!(output.status.success(), "{}", printed(&output));
    let text = mock::unwrapped(&output.stderr);
    assert!(
        text.contains("--current-password on the command line"),
        "{text}"
    );
    assert!(
        text.contains("--new-password on the command line"),
        "{text}"
    );
    assert_no_secrets(&output);
}

#[tokio::test]
async fn change_password_takes_one_from_stdin_and_one_from_the_environment() {
    let m = Mocked::start().await;
    m.respond_empty("POST", "/api/v1/users/me/password", 200)
        .await;
    let output = m.ak_anon(
        &["profile", "change-password", "--new-password-stdin"],
        "the-new-password\n",
        &[("AK_TOKEN", "t"), ("AK_CURRENT_PASSWORD", PASSWORD)],
    );
    assert!(output.status.success(), "{}", printed(&output));
    assert_no_secrets(&output);
    assert!(!printed(&output).contains("the-new-password"));
    let (_, body) = m.last("POST").await;
    assert_eq!(
        body,
        json!({"current_password": PASSWORD, "new_password": "the-new-password"})
    );
}

#[tokio::test]
async fn set_password_sends_only_the_new_password_for_an_admin() {
    let m = Mocked::start().await;
    let route = format!("/api/v1/users/{ID}/password");
    m.respond_empty("POST", &route, 200).await;
    let output = m.ak_stdin(
        &["admin", "users", "set-password", ID, "--new-password-stdin"],
        "the-new-password",
    );
    assert!(output.status.success(), "{}", printed(&output));
    assert!(!printed(&output).contains("the-new-password"));
    let (_, body) = m.last("POST").await;
    assert_eq!(body, json!({"new_password": "the-new-password"}));
}

#[tokio::test]
async fn set_password_with_no_password_says_how() {
    let m = Mocked::start().await;
    let output = m.ak(&["admin", "users", "set-password", ID]);
    assert!(!output.status.success());
    assert!(mock::unwrapped(&output.stderr).contains("--new-password-stdin"));
    assert!(m.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn users_create_sends_a_given_password_and_list_sends_its_filters() {
    let m = Mocked::start().await;
    let user = json!({
        "id": ID, "username": "bob", "email": "b@example.com", "is_admin": false,
        "is_active": true, "is_service_account": false, "must_change_password": false,
        "auth_provider": "local", "created_at": "2026-01-01T00:00:00Z"
    });
    m.respond("POST", "/api/v1/users", 200, json!({"user": user}))
        .await;
    let output = m.ak_stdin(
        &[
            "admin",
            "users",
            "create",
            "bob",
            "--email",
            "b@example.com",
            "--password-stdin",
        ],
        PASSWORD,
    );
    assert!(output.status.success(), "{}", printed(&output));
    assert_no_secrets(&output);
    let (_, body) = m.last("POST").await;
    assert_eq!(body["password"], PASSWORD);

    let list = json!({
        "items": [], "pagination": {"page": 1, "per_page": 20, "total": 0, "total_pages": 0},
        "from_a_newer_server": 1
    });
    m.respond("GET", "/api/v1/users", 200, list.clone()).await;
    let shown = m.json(&[
        "admin",
        "users",
        "list",
        "--is-active",
        "true",
        "--is-admin",
        "false",
        "--is-service-account",
        "true",
    ]);
    assert_eq!(shown, list);
    let (query, _) = m.last("GET").await;
    for field in ["is_active", "is_admin", "is_service_account"] {
        assert!(query.iter().any(|(k, _)| k == field), "{query:?}");
    }
}

#[tokio::test]
async fn token_create_sends_scopes_and_a_repo_selector() {
    let m = Mocked::start().await;
    let created = json!({
        "id": ID, "name": "n", "token": "secret", "policy_applied": false,
        "from_a_newer_server": 1
    });
    m.respond("POST", "/api/v1/auth/tokens", 200, created.clone())
        .await;
    let shown = m.json(&[
        "auth",
        "token",
        "create",
        "--description",
        "n",
        "--scope",
        "read:artifacts,write:artifacts",
        "--repo-selector",
        r#"{"match_formats":["npm"]}"#,
    ]);
    assert_eq!(shown, created);
    let (_, body) = m.last("POST").await;
    assert_eq!(body["scopes"], json!(["read:artifacts", "write:artifacts"]));
    assert_eq!(body["repo_selector"], json!({"match_formats": ["npm"]}));
}

#[tokio::test]
async fn token_create_still_defaults_to_all_of_your_access() {
    let m = Mocked::start().await;
    let created = json!({"id": ID, "name": "n", "token": "secret", "policy_applied": false});
    m.respond("POST", "/api/v1/auth/tokens", 200, created).await;
    m.json(&["auth", "token", "create", "--description", "n"]);
    let (_, body) = m.last("POST").await;
    assert_eq!(body["scopes"], json!(["*"]));
    assert!(body.get("repo_selector").is_none());
}

#[tokio::test]
async fn access_tokens_use_their_own_route_and_print_the_body() {
    let m = Mocked::start().await;
    let route = "/api/v1/profile/access-tokens";
    let list = json!({"items": [], "from_a_newer_server": 1});
    m.respond("GET", route, 200, list.clone()).await;
    assert_eq!(m.json(&["profile", "access-tokens", "list"]), list);

    let created = json!({
        "id": ID, "name": "n", "token": "secret", "policy_applied": false,
        "from_a_newer_server": 1
    });
    m.respond("POST", route, 200, created.clone()).await;
    let shown = m.json(&[
        "profile",
        "access-tokens",
        "create",
        "n",
        "--scope",
        "read:artifacts",
        "--expires-in-days",
        "3",
    ]);
    assert_eq!(shown, created);
    let (_, body) = m.last("POST").await;
    assert_eq!(
        body,
        json!({"name": "n", "scopes": ["read:artifacts"], "expires_in_days": 3})
    );

    let one = format!("{route}/{ID}");
    m.respond_empty("DELETE", &one, 200).await;
    m.json(&["profile", "access-tokens", "revoke", ID]);
}

#[tokio::test]
async fn search_sends_its_parameters_and_prints_the_body() {
    let m = Mocked::start().await;
    let quick = json!({"results": [], "from_a_newer_server": 1});
    m.respond("GET", "/api/v1/search/quick", 200, quick.clone())
        .await;
    let shown = m.json(&[
        "search", "quick", "ngi", "--limit", "5", "--types", "artifact",
    ]);
    assert_eq!(shown, quick);
    let (query, _) = m.last("GET").await;
    assert!(query.contains(&("q".into(), "ngi".into())), "{query:?}");
    assert!(query.contains(&("limit".into(), "5".into())), "{query:?}");
    assert!(
        query.contains(&("types".into(), "artifact".into())),
        "{query:?}"
    );

    let checksum = json!({"artifacts": [], "from_a_newer_server": 1});
    m.respond("GET", "/api/v1/search/checksum", 200, checksum.clone())
        .await;
    let shown = m.json(&["search", "checksum", "abc", "--algorithm", "md5"]);
    assert_eq!(shown, checksum);
    let (query, _) = m.last("GET").await;
    assert!(
        query.contains(&("algorithm".into(), "md5".into())),
        "{query:?}"
    );

    let trending = json!([]);
    m.respond("GET", "/api/v1/search/trending", 200, trending.clone())
        .await;
    let shown = m.json(&["search", "trending", "--days", "9", "--limit", "2"]);
    assert_eq!(shown, trending);
    let (query, _) = m.last("GET").await;
    assert!(query.contains(&("days".into(), "9".into())), "{query:?}");
}

#[tokio::test]
async fn events_tail_stops_at_the_count_and_prints_each_event() {
    let m = Mocked::start().await;
    let stream = "event: connected\ndata: {\"status\":\"ok\"}\n\n: ping\n\n\
                  event: entity.changed\ndata: {\"type\":\"repository.created\"}\n\n\
                  event: entity.changed\ndata: {\"type\":\"never.reached\"}\n\n";
    Mock::given(method("GET"))
        .and(path("/api/v1/events/stream"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(stream, "text/event-stream"))
        .mount(&m.server)
        .await;
    let output = m.ak(&["--format", "json", "events", "tail", "--count", "1"]);
    assert!(output.status.success(), "{}", printed(&output));
    let lines: Vec<Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0]["event"], "connected");
    assert_eq!(lines[1]["data"]["type"], "repository.created");
}

/// 1.10.1 ignores a selector and makes a token with all of your access. 1.10.2
/// honours it. So the refusal goes by the patch version, and sends nothing.
#[tokio::test]
async fn repo_selector_is_refused_only_where_the_server_would_drop_it() {
    for (version, posts) in [("1.10.1", 0), ("1.10.2", 1), ("1.11.11", 1)] {
        let mock = Mocked::start().await;
        mock.respond("GET", "/health", 200, json!({ "version": version }))
            .await;
        mock.respond(
            "POST",
            "/api/v1/auth/tokens",
            200,
            json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "name": "n",
                "token": "t",
                "policy_applied": false
            }),
        )
        .await;

        let output = mock.ak(&[
            "auth",
            "token",
            "create",
            "--description",
            "n",
            "--repo-selector",
            r#"{"match_formats":["npm"]}"#,
        ]);

        let sent = mock
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method.as_str() == "POST")
            .count();
        assert_eq!(sent, posts, "{version}");
        assert_eq!(output.status.success(), posts == 1, "{version}: {output:?}");
    }
}

fn empty_session() -> Value {
    let mut session = session();
    session["access_token"] = json!("");
    session
}

/// A 200 with empty tokens used to be stored, with "Logged in" and exit 0.
#[tokio::test]
async fn an_empty_token_is_never_stored() {
    let ldap_route = format!("/api/v1/auth/sso/ldap/{ID}/login");
    let ldap = format!("ldap:{ID}");
    for (route, args, stdin) in [
        (
            "/api/v1/auth/totp/verify",
            vec!["auth", "verify-totp", "123456", "--totp-token", "t"],
            "",
        ),
        (
            "/api/v1/auth/sso/exchange",
            vec!["auth", "sso-exchange", "--code", "c"],
            "",
        ),
        (
            ldap_route.as_str(),
            vec![
                "auth",
                "login",
                "--sso",
                ldap.as_str(),
                "--username",
                "alice",
                "--password-stdin",
            ],
            "secret\n",
        ),
    ] {
        let mock = Mocked::start().await;
        mock.respond("POST", route, 200, empty_session()).await;
        let output = mock.ak_anon(&args, stdin, &[]);
        assert_eq!(output.status.code(), Some(4), "{args:?}: {output:?}");
        let stderr = mock::unwrapped(&output.stderr);
        assert!(!stderr.contains("ogged in to"), "{args:?}: {stderr}");
        assert!(stderr.contains("no session token"), "{args:?}: {stderr}");
        assert!(
            !mock.stored_credentials().contains("access_token"),
            "{args:?}"
        );
    }
}

/// With no version to go on, the flag goes ahead and the user is told.
#[tokio::test]
async fn a_flag_says_so_when_the_version_cant_be_read() {
    let mock = Mocked::start().await;
    mock.respond("GET", "/health", 503, json!({})).await;
    mock.respond(
        "POST",
        "/api/v1/auth/tokens",
        200,
        json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "n",
            "token": "t",
            "policy_applied": false
        }),
    )
    .await;
    let output = mock.ak(&[
        "auth",
        "token",
        "create",
        "--description",
        "n",
        "--repo-selector",
        r#"{"match_formats":["npm"]}"#,
        "--format",
        "json",
    ]);
    assert!(output.status.success(), "{output:?}");
    let stderr = mock::unwrapped(&output.stderr);
    assert!(
        stderr.contains("couldn't read this server's version"),
        "{stderr}"
    );
    assert!(stderr.contains("1.10.2"), "{stderr}");
    // Not on stdout, which a script parses.
    serde_json::from_slice::<Value>(&output.stdout).expect("JSON on stdout");
}
