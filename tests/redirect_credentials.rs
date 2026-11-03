//! Where the token goes when a server redirects. Each server here is real TLS and
//! real plain HTTP on one port, because that's the case that matters: reqwest
//! compares only host and port when it decides to drop `Authorization`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use assert_cmd::Command;
use serde_json::json;
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const TOKEN: &str = "sentinel-api-token";
const TLS_HANDSHAKE: u8 = 0x16;

#[derive(Clone, Debug)]
struct Seen {
    tls: bool,
    method: String,
    host: String,
    path: String,
    has_token: bool,
}

/// What to answer: a 307 to this URL, which keeps the method and body, a 302, or
/// the list `repo list` expects.
enum Reply {
    Redirect(String),
    Found(String),
    Ok,
}

type Route = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

struct Pki {
    dir: TempDir,
    acceptor: TlsAcceptor,
}

impl Pki {
    /// A CA, trusted through `AK_CA_CERT`, and a certificate for two names that
    /// reach the same listener, so a test can have a second host.
    fn new() -> Self {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();

        let private = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], private)
        .unwrap();

        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("ca.pem"), ca_cert.pem()).unwrap();
        Self {
            dir,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        }
    }

    fn ca_path(&self) -> std::path::PathBuf {
        self.dir.path().join("ca.pem")
    }
}

type Log = Arc<Mutex<Vec<Seen>>>;

async fn bind() -> (TcpListener, u16) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// Serve TLS and plain HTTP on the one port, telling them apart by the first byte.
fn serve(listener: TcpListener, pki: &Pki, log: &Log, route: Route) {
    let acceptor = pki.acceptor.clone();
    let log = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, log, route) = (acceptor.clone(), log.clone(), route.clone());
            tokio::spawn(async move {
                let tls = is_tls(&stream).await;
                if tls {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        answer(stream, true, &log, &route).await;
                    }
                } else {
                    answer(stream, false, &log, &route).await;
                }
            });
        }
    });
}

async fn is_tls(stream: &TcpStream) -> bool {
    let mut first = [0u8; 1];
    matches!(stream.peek(&mut first).await, Ok(1)) && first[0] == TLS_HANDSHAKE
}

async fn answer<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    tls: bool,
    log: &Log,
    route: &Route,
) {
    let mut request = Vec::new();
    let mut chunk = [0u8; 4096];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    }
    let request = String::from_utf8_lossy(&request);
    let seen = Seen {
        tls,
        method: request.split(' ').next().unwrap_or("").to_string(),
        host: request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("host")
                    .then(|| value.trim().to_string())
            })
            .unwrap_or_default(),
        path: request.split(' ').nth(1).unwrap_or("").to_string(),
        has_token: request.contains(TOKEN),
    };
    log.lock().unwrap().push(seen.clone());

    let response = match route(&seen) {
        // A 307, because that's the one that resends a body.
        Reply::Redirect(to) => format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        Reply::Found(to) => format!(
            "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        Reply::Ok => {
            let body = json!({
                "items": [],
                "pagination": {"page": 1, "per_page": 20, "total": 0, "total_pages": 0}
            })
            .to_string();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        }
    };
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Run `ak` with the instance at `https://127.0.0.1:<port>`.
async fn ak(pki: &Pki, port: u16, args: &[&str]) -> std::process::Output {
    ak_with_stdin(pki, port, args, "").await
}

async fn ak_with_stdin(pki: &Pki, port: u16, args: &[&str], stdin: &str) -> std::process::Output {
    let stdin = stdin.to_string();
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "default_instance = \"t\"\n[instances.t]\nurl = \"https://127.0.0.1:{port}\"\napi_version = \"v1\"\n"
        ),
    )
    .unwrap();
    let ca = pki.ca_path();
    let args: Vec<String> = args.iter().map(ToString::to_string).collect();
    tokio::task::spawn_blocking(move || {
        Command::cargo_bin("ak")
            .unwrap()
            .env_clear()
            .env("HOME", dir.path())
            .env("AK_CONFIG_DIR", dir.path())
            .env("AK_TOKEN", TOKEN)
            .env("AK_CREDENTIAL_STORE", "file")
            .env("AK_CA_CERT", ca)
            .env("AK_NO_INPUT", "true")
            .args(args)
            .write_stdin(stdin)
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

fn seen(log: &Log) -> Vec<Seen> {
    log.lock().unwrap().clone()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Commands that reach a server each of the ways `ak` builds an authenticated
/// client: the SDK client, the raw client, and `doctor`'s own.
const COMMANDS: [&[&str]; 3] = [
    &["repo", "list", "--format", "json"],
    &["import", "source", "list", "--format", "json"],
    &["doctor"],
];

/// The bug: to `http://` on the same host and port, reqwest keeps the header.
#[tokio::test(flavor = "multi_thread")]
async fn https_to_http_on_the_same_port_does_not_send_the_token() {
    for command in COMMANDS {
        let pki = Pki::new();
        let log = Log::default();
        let (listener, port) = bind().await;
        serve(
            listener,
            &pki,
            &log,
            Arc::new(move |s: &Seen| {
                if s.tls {
                    Reply::Redirect(format!("http://127.0.0.1:{port}{}", s.path))
                } else {
                    Reply::Ok
                }
            }),
        );

        let output = ak(&pki, port, command).await;

        let log = seen(&log);
        assert!(
            log.iter().any(|s| s.tls && s.has_token),
            "{command:?}: the first request should carry the token: {log:?}"
        );
        assert!(
            !log.iter().any(|s| !s.tls && s.has_token),
            "{command:?}: the token went over plain HTTP: {log:?}"
        );
        assert!(
            !stderr(&output).contains(TOKEN),
            "{command:?}: the token was printed"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_refusal_says_why() {
    let pki = Pki::new();
    let log = Log::default();
    let (listener, port) = bind().await;
    serve(
        listener,
        &pki,
        &log,
        Arc::new(move |s: &Seen| Reply::Redirect(format!("http://127.0.0.1:{port}{}", s.path))),
    );

    let output = ak(&pki, port, &["repo", "list"]).await;
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(err.contains("https"), "{err}");
    assert!(err.contains("plain http"), "{err}");
}

/// A normal redirect on the same origin keeps the token and works.
#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_within_the_origin_keeps_working() {
    let pki = Pki::new();
    let log = Log::default();
    let (listener, port) = bind().await;
    serve(
        listener,
        &pki,
        &log,
        Arc::new(move |s: &Seen| {
            if s.path.starts_with("/moved") {
                Reply::Ok
            } else {
                Reply::Redirect(format!("https://127.0.0.1:{port}/moved{}", s.path))
            }
        }),
    );

    let output = ak(&pki, port, &["repo", "list", "--format", "json"]).await;
    assert!(output.status.success(), "{}", stderr(&output));
    let log = seen(&log);
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(log.iter().all(|s| s.has_token), "{log:?}");
}

/// A presigned storage URL is on another host and can be plain HTTP, such as
/// MinIO inside a cluster. A download gets there with no token.
#[tokio::test(flavor = "multi_thread")]
async fn a_download_is_followed_to_plain_http_storage_without_the_token() {
    let pki = Pki::new();
    let log = Log::default();
    let (origin, origin_port) = bind().await;
    let (storage, storage_port) = bind().await;
    serve(
        origin,
        &pki,
        &log,
        Arc::new(move |s: &Seen| {
            Reply::Found(format!("http://127.0.0.1:{storage_port}{}", s.path))
        }),
    );
    serve(storage, &pki, &log, Arc::new(|_: &Seen| Reply::Ok));
    let out = TempDir::new().unwrap();
    let file = out.path().join("f.bin");

    let output = ak(
        &pki,
        origin_port,
        &[
            "artifact",
            "pull",
            "r",
            "f.bin",
            "-o",
            file.to_str().unwrap(),
        ],
    )
    .await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(file.exists());
    let log = seen(&log);
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(log[0].tls && log[0].has_token, "{log:?}");
    assert!(!log[1].tls && !log[1].has_token, "{log:?}");
}

/// tower-http only turns a POST into a GET on a 301 or 302. A PUT keeps its body, so
/// a secret would reach plain HTTP on a 302 from `https://host` to `http://host`.
#[tokio::test(flavor = "multi_thread")]
async fn a_secret_in_a_put_does_not_follow_a_302_to_plain_http() {
    for (command, stdin) in [
        (
            &[
                "repo",
                "upstream-auth",
                "r",
                "--type",
                "basic",
                "--username",
                "u",
                "--password-stdin",
            ][..],
            "secret-password\n",
        ),
        (
            &[
                "sso",
                "update",
                "oidc",
                "00000000-0000-0000-0000-000000000001",
                "--client-secret-stdin",
            ][..],
            "secret-client\n",
        ),
        (
            &[
                "sso",
                "update",
                "ldap",
                "00000000-0000-0000-0000-000000000001",
                "--bind-password-stdin",
            ][..],
            "secret-bind\n",
        ),
    ] {
        let pki = Pki::new();
        let log = Log::default();
        let (origin, origin_port) = bind().await;
        let (plain, plain_port) = bind().await;
        serve(
            origin,
            &pki,
            &log,
            Arc::new(move |s: &Seen| {
                if s.method == "PUT" || s.method == "PATCH" {
                    Reply::Found(format!("http://127.0.0.1:{plain_port}{}", s.path))
                } else {
                    Reply::Ok
                }
            }),
        );
        serve(plain, &pki, &log, Arc::new(|_: &Seen| Reply::Ok));

        ak_with_stdin(&pki, origin_port, command, stdin).await;

        let log = seen(&log);
        assert!(
            log.iter()
                .any(|s| s.tls && (s.method == "PUT" || s.method == "PATCH")),
            "{command:?} never sent its secret: {log:?}"
        );
        assert!(
            !log.iter().any(|s| !s.tls),
            "{command:?}: the secret went over plain HTTP: {log:?}"
        );
    }
}

/// A login's password would go to another HTTPS server on a 307: TLS doesn't help.
#[tokio::test(flavor = "multi_thread")]
async fn a_password_does_not_follow_a_307_to_another_server() {
    let pki = Pki::new();
    let log = Log::default();
    let (origin, origin_port) = bind().await;
    let (other, other_port) = bind().await;
    serve(
        origin,
        &pki,
        &log,
        Arc::new(move |s: &Seen| {
            Reply::Redirect(format!("https://127.0.0.1:{other_port}{}", s.path))
        }),
    );
    serve(other, &pki, &log, Arc::new(|_: &Seen| Reply::Ok));

    let output = ak_with_stdin(
        &pki,
        origin_port,
        &["auth", "login", "--username", "alice", "--password-stdin"],
        "secret-password\n",
    )
    .await;

    assert!(!output.status.success());
    let log = seen(&log);
    assert_eq!(log.len(), 1, "the password left the instance: {log:?}");
}

/// reqwest drops the header on the way to another host, then sends it there on
/// that host's own next redirect. So following this hop would hand it the token.
#[tokio::test(flavor = "multi_thread")]
async fn another_host_redirecting_to_itself_does_not_get_the_token() {
    let pki = Pki::new();
    let log = Log::default();
    let (listener, port) = bind().await;
    serve(
        listener,
        &pki,
        &log,
        Arc::new(move |s: &Seen| {
            if s.host.starts_with("localhost") {
                Reply::Redirect(format!("https://localhost:{port}/again{}", s.path))
            } else {
                Reply::Redirect(format!("https://localhost:{port}{}", s.path))
            }
        }),
    );

    // A download, because an API request doesn't go to another host at all.
    let out = TempDir::new().unwrap();
    let file = out.path().join("f.bin");
    let output = ak(
        &pki,
        port,
        &[
            "artifact",
            "pull",
            "r",
            "f.bin",
            "-o",
            file.to_str().unwrap(),
        ],
    )
    .await;
    assert!(!output.status.success());
    let log = seen(&log);
    assert!(
        log.iter().any(|s| s.host.starts_with("localhost")),
        "{log:?}"
    );
    assert!(
        !log.iter()
            .any(|s| s.host.starts_with("localhost") && s.has_token),
        "the token reached the other host: {log:?}"
    );
    assert!(
        stderr(&output).contains("another server"),
        "{}",
        stderr(&output)
    );
}

/// A 307 from https to http on another port drops the token but resends the body,
/// so what's in the body has to be protected differently. `auth verify-totp` runs
/// with no prompt, and it uses the same client as `auth login`.
#[tokio::test(flavor = "multi_thread")]
async fn a_login_body_does_not_follow_a_downgrade() {
    let pki = Pki::new();
    let log = Log::default();
    let (origin, origin_port) = bind().await;
    let (plain, plain_port) = bind().await;
    serve(
        origin,
        &pki,
        &log,
        Arc::new(move |s: &Seen| {
            Reply::Redirect(format!("http://127.0.0.1:{plain_port}{}", s.path))
        }),
    );
    serve(plain, &pki, &log, Arc::new(|_: &Seen| Reply::Ok));

    let output = ak(
        &pki,
        origin_port,
        &["auth", "verify-totp", "123456", "--totp-token", "tok"],
    )
    .await;

    assert!(!output.status.success());
    let log = seen(&log);
    assert!(log.iter().any(|s| s.tls), "{log:?}");
    assert!(
        !log.iter().any(|s| !s.tls),
        "the login went over plain HTTP: {log:?}"
    );
    assert!(
        stderr(&output).contains("plain http"),
        "{}",
        stderr(&output)
    );
}

/// Commands that send a secret in the body through each kind of client. A 307 to
/// plain http on another port drops the token, and would resend the body.
#[tokio::test(flavor = "multi_thread")]
async fn a_secret_in_a_body_does_not_follow_a_downgrade() {
    for command in [
        &[
            "totp",
            "disable",
            "--password",
            "secret-password",
            "--code",
            "123456",
        ][..],
        &[
            "webhook",
            "create",
            "w",
            "--url",
            "https://hook.test/",
            "--events",
            "artifact_uploaded",
            "--secret",
            "secret-hook",
        ][..],
        &["service-account", "create", "sa"][..],
    ] {
        let pki = Pki::new();
        let log = Log::default();
        let (origin, origin_port) = bind().await;
        let (plain, plain_port) = bind().await;
        serve(
            origin,
            &pki,
            &log,
            Arc::new(move |s: &Seen| {
                Reply::Redirect(format!("http://127.0.0.1:{plain_port}{}", s.path))
            }),
        );
        serve(plain, &pki, &log, Arc::new(|_: &Seen| Reply::Ok));

        let output = ak(&pki, origin_port, command).await;

        assert!(!output.status.success(), "{command:?}");
        let log = seen(&log);
        assert!(log.iter().any(|s| s.tls), "{command:?}: {log:?}");
        assert!(
            !log.iter().any(|s| !s.tls),
            "{command:?}: the body went over plain HTTP: {log:?}"
        );
        // Every client says why, including the raw one.
        let err = stderr(&output);
        assert!(
            err.contains("Not following the redirect"),
            "{command:?}: {err}"
        );
    }
}

/// The limit on redirects has to survive a custom policy.
#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_loop_still_ends() {
    let pki = Pki::new();
    let log = Log::default();
    let (listener, port) = bind().await;
    serve(
        listener,
        &pki,
        &log,
        Arc::new(move |s: &Seen| Reply::Redirect(format!("https://127.0.0.1:{port}{}", s.path))),
    );

    let output = ak(&pki, port, &["repo", "list"]).await;
    assert!(!output.status.success());
    assert!(seen(&log).len() <= 11, "{}", seen(&log).len());
}
