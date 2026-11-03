//! Contract tests for `ak api`, one per capability, with special attention to
//! where the instance's token and the user's headers may go. These run the real
//! binary against wiremock. `tests/e2e_api.rs` covers a real backend.

use std::process::Output;

use assert_cmd::Command;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{
    body_bytes, body_json, body_string, header, header_exists, method, path, query_param,
};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const TOKEN: &str = "sentinel-instance-token-5d3a";

struct Env {
    server: MockServer,
    dir: TempDir,
}

impl Env {
    async fn new() -> Self {
        let server = MockServer::start().await;
        let dir = TempDir::new().expect("temp dir");
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "default_instance = \"t\"\n[instances.t]\nurl = \"{}\"\napi_version = \"v1\"\n",
                server.uri()
            ),
        )
        .expect("write config");
        Self { server, dir }
    }

    fn file(&self, name: &str, content: &[u8]) -> String {
        let path = self.dir.path().join(name);
        std::fs::write(&path, content).expect("write file");
        path.display().to_string()
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("ak").expect("ak binary");
        cmd.env_remove("AK_INSTANCE")
            .env_remove("AK_FORMAT")
            .env_remove("AK_CA_CERT")
            .env("AK_CONFIG_DIR", self.dir.path())
            .env("AK_TOKEN", TOKEN)
            .env("AK_CREDENTIAL_STORE", "file")
            .env("NO_COLOR", "1")
            .current_dir(self.dir.path())
            .arg("api")
            .args(args);
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().expect("run ak")
    }

    /// Every request the server received.
    async fn received(&self) -> Vec<Request> {
        self.server.received_requests().await.expect("recording on")
    }
}

fn out(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn err(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn has_auth(request: &Request) -> bool {
    request.headers.contains_key("authorization")
}

fn assert_token_never_printed(output: &Output) {
    assert!(!out(output).contains(TOKEN), "token in stdout");
    assert!(!err(output).contains(TOKEN), "token in stderr");
}

async fn ok_any(server: &MockServer) {
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(server)
        .await;
}

// ---- methods ----

#[tokio::test]
async fn sends_the_instance_token_and_prints_the_body_as_received() {
    let env = Env::new().await;
    let body = "{\"id\":1,  \"unknown_field\": [true]}\n";
    Mock::given(method("GET"))
        .and(path("/api/v1/thing"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .expect(1)
        .mount(&env.server)
        .await;

    let output = env.run(&["GET", "/api/v1/thing"]);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    assert_eq!(out(&output), body, "the body must not be re-serialized");
    assert_token_never_printed(&output);
}

#[tokio::test]
async fn sends_any_method() {
    let env = Env::new().await;
    ok_any(&env.server).await;
    for verb in [
        "get", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "PROPFIND",
    ] {
        let output = env.run(&[verb, "/x"]);
        assert_eq!(output.status.code(), Some(0), "{verb}");
    }
    let methods: Vec<String> = env
        .received()
        .await
        .iter()
        .map(|r| r.method.to_string())
        .collect();
    assert_eq!(
        methods,
        [
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "PROPFIND"
        ]
    );
}

#[tokio::test]
async fn a_path_works_with_or_without_its_leading_slash() {
    let env = Env::new().await;
    Mock::given(path("/health"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&env.server)
        .await;
    assert_eq!(env.run(&["GET", "/health"]).status.code(), Some(0));
    assert_eq!(env.run(&["GET", "health"]).status.code(), Some(0));
}

// ---- headers and query ----

#[tokio::test]
async fn sends_repeated_headers() {
    let env = Env::new().await;
    ok_any(&env.server).await;
    env.run(&[
        "GET", "/x", "-H", "X-A: 1", "-H", "X-A: 2", "--header", "X-B: 3",
    ]);
    let received = env.received().await;
    let values: Vec<_> = received[0]
        .headers
        .get_all("x-a")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert_eq!(values, ["1", "2"]);
    assert_eq!(received[0].headers.get("x-b").unwrap(), "3");
}

#[tokio::test]
async fn a_users_authorization_header_replaces_the_token() {
    let env = Env::new().await;
    Mock::given(header("authorization", "Basic abc"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/x", "-H", "Authorization: Basic abc"]);
    assert_eq!(output.status.code(), Some(0));
}

#[tokio::test]
async fn sends_repeated_query_parameters_encoded() {
    let env = Env::new().await;
    Mock::given(path("/x"))
        .and(query_param("existing", "1"))
        .and(query_param("a", "x y&z"))
        .and(query_param("b", "2"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/x?existing=1", "-Q", "a=x y&z", "--query", "b=2"]);
    assert_eq!(output.status.code(), Some(0));
}

// ---- bodies ----

#[tokio::test]
async fn json_body_from_flag_file_and_stdin() {
    let env = Env::new().await;
    Mock::given(method("POST"))
        .and(header("content-type", "application/json"))
        .and(body_json(json!({"a": 1})))
        .respond_with(ResponseTemplate::new(200))
        .expect(3)
        .mount(&env.server)
        .await;

    let file = format!("@{}", env.file("b.json", br#"{"a":1}"#));
    assert_eq!(
        env.run(&["POST", "/x", "--body", r#"{"a":1}"#])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        env.run(&["POST", "/x", "--body", &file]).status.code(),
        Some(0)
    );
    let piped = env
        .cmd(&["POST", "/x", "--body", "@-"])
        .write_stdin(r#"{"a":1}"#)
        .output()
        .unwrap();
    assert_eq!(piped.status.code(), Some(0));
}

#[tokio::test]
async fn invalid_json_is_refused_without_quoting_it() {
    let env = Env::new().await;
    let output = env.run(&["POST", "/x", "--body", "password=hunter2"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(!err(&output).contains("hunter2"), "{}", err(&output));
    assert!(env.received().await.is_empty());
}

#[tokio::test]
async fn raw_body_from_a_file_is_streamed_with_its_length() {
    let env = Env::new().await;
    let content = vec![0xABu8; 300_000];
    Mock::given(method("PUT"))
        .and(header("content-type", "application/octet-stream"))
        .and(header("content-length", "300000"))
        .and(body_bytes(content.clone()))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&env.server)
        .await;
    let file = format!("@{}", env.file("b.bin", &content));
    let output = env.run(&["PUT", "/x", "--raw-body", &file]);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
}

#[tokio::test]
async fn raw_body_from_stdin_and_text_and_a_custom_type() {
    let env = Env::new().await;
    Mock::given(method("PUT"))
        .and(header("content-type", "text/x-custom"))
        .and(body_string("hello"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&env.server)
        .await;
    let piped = env
        .cmd(&[
            "PUT",
            "/x",
            "--raw-body",
            "@-",
            "-H",
            "Content-Type: text/x-custom",
        ])
        .write_stdin("hello")
        .output()
        .unwrap();
    assert_eq!(piped.status.code(), Some(0));
    let text = env.run(&[
        "PUT",
        "/x",
        "--raw-body",
        "hello",
        "-H",
        "Content-Type: text/x-custom",
    ]);
    assert_eq!(text.status.code(), Some(0));
}

#[tokio::test]
async fn multipart_form_with_text_and_files() {
    let env = Env::new().await;
    ok_any(&env.server).await;
    let file = env.file("plugin.zip", b"zip-bytes");
    let output = env.run(&[
        "POST",
        "/api/v1/plugins",
        "--form",
        "name=value",
        "--form",
        "literal=\\@at",
        "--form",
        &format!("file=@{file}"),
        "--form",
        &format!("other=@{file};type=text/x-a;filename=renamed.txt"),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));

    let received = env.received().await;
    let content_type = received[0].headers.get("content-type").unwrap();
    assert!(
        content_type
            .to_str()
            .unwrap()
            .starts_with("multipart/form-data; boundary="),
        "{content_type:?}"
    );
    let body = String::from_utf8_lossy(&received[0].body);
    assert!(body.contains("name=\"name\""), "{body}");
    assert!(body.contains("value"), "{body}");
    assert!(body.contains("@at"), "{body}");
    assert!(body.contains("filename=\"plugin.zip\""), "{body}");
    assert!(body.contains("zip-bytes"), "{body}");
    assert!(body.contains("filename=\"renamed.txt\""), "{body}");
    assert!(body.contains("text/x-a"), "{body}");
    assert!(!err(&output).contains("zip-bytes"));
}

#[tokio::test]
async fn urlencoded_form() {
    let env = Env::new().await;
    Mock::given(method("POST"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string("a=x+y&b=1%262"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&env.server)
        .await;
    let output = env.run(&["POST", "/x", "--urlencode", "a=x y", "--urlencode", "b=1&2"]);
    assert_eq!(output.status.code(), Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn a_body_from_a_pipe_has_no_false_length() {
    let env = Env::new().await;
    Mock::given(method("PUT"))
        .and(body_string("through a pipe"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&env.server)
        .await;
    let output = env
        .cmd(&["PUT", "/x", "--raw-body", "@/dev/stdin"])
        .write_stdin("through a pipe")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
}

#[cfg(unix)]
#[tokio::test]
async fn a_form_file_from_a_pipe_has_its_content() {
    let env = Env::new().await;
    ok_any(&env.server).await;
    let output = env
        .cmd(&["POST", "/x", "--form", "f=@/dev/stdin;filename=p.txt"])
        .write_stdin("through a pipe")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    let body = String::from_utf8_lossy(&env.received().await[0].body).into_owned();
    assert!(body.contains("through a pipe"), "{body}");
}

#[tokio::test]
async fn a_form_with_its_own_content_type_is_refused() {
    let env = Env::new().await;
    let output = env.run(&[
        "POST",
        "/x",
        "--form",
        "a=b",
        "-H",
        "Content-Type: multipart/form-data",
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert!(env.received().await.is_empty());
}

#[tokio::test]
async fn content_length_from_the_user_is_refused() {
    let env = Env::new().await;
    let output = env.run(&[
        "PUT",
        "/x",
        "--raw-body",
        "abcdef",
        "-H",
        "Content-Length: 3",
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert!(env.received().await.is_empty());
}

#[tokio::test]
async fn only_one_kind_of_body_is_allowed() {
    let env = Env::new().await;
    let output = env.run(&["POST", "/x", "--body", "{}", "--raw-body", "x"]);
    assert_eq!(output.status.code(), Some(2));
}

// ---- output ----

#[tokio::test]
async fn output_writes_a_file_and_range_goes_through() {
    let env = Env::new().await;
    let bytes = vec![7u8; 500_000];
    Mock::given(header("range", "bytes=0-9"))
        .respond_with(ResponseTemplate::new(206).set_body_bytes(bytes.clone()))
        .expect(1)
        .mount(&env.server)
        .await;
    let target = env.dir.path().join("out.bin");
    let output = env.run(&[
        "GET",
        "/x",
        "-H",
        "Range: bytes=0-9",
        "-o",
        target.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    assert_eq!(std::fs::read(&target).unwrap(), bytes);
    assert_eq!(out(&output), "", "the body went to the file");
}

#[tokio::test]
async fn output_dash_is_stdout_and_binary_is_untouched() {
    let env = Env::new().await;
    let bytes: Vec<u8> = (0..=255).collect();
    Mock::given(path("/x"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/x", "-o", "-"]);
    assert_eq!(output.stdout, bytes);
}

#[tokio::test]
async fn quiet_still_writes_the_output_file() {
    let env = Env::new().await;
    Mock::given(path("/x"))
        .respond_with(ResponseTemplate::new(200).set_body_string("content"))
        .mount(&env.server)
        .await;
    let target = env.dir.path().join("q.txt");
    let output = env.run(&["GET", "/x", "--quiet", "-o", target.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(std::fs::read(&target).unwrap(), b"content");
}

/// A server that promises more than it sends, then hangs up. On its own thread,
/// because the test blocks on the child process.
fn truncating_server() -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut buffer = [0u8; 4096];
        let _ = socket.read(&mut buffer);
        let _ = socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\nshort");
    });
    format!("http://{address}/x")
}

#[tokio::test]
async fn a_truncated_download_exits_3() {
    let env = Env::new().await;
    let url = truncating_server();
    let target = env.dir.path().join("partial.bin");
    let output = env.run(&["GET", &url, "-o", target.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(3), "{}", err(&output));
    assert!(err(&output).contains("incomplete"), "{}", err(&output));

    let url = truncating_server();
    let output = env.run(&["GET", &url]);
    assert_eq!(output.status.code(), Some(3), "{}", err(&output));
}

#[tokio::test]
async fn max_time_covers_the_whole_request() {
    let env = Env::new().await;
    Mock::given(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(30)))
        .mount(&env.server)
        .await;
    let started = std::time::Instant::now();
    let output = env.run(&["GET", "/slow", "--max-time", "1"]);
    assert_eq!(output.status.code(), Some(3), "{}", err(&output));
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

#[tokio::test]
async fn open_stdin_does_not_hold_up_exit() {
    // The server answers before the body ends, and stdin stays open.
    let env = Env::new().await;
    ok_any(&env.server).await;
    use std::io::Write;
    use std::process::Stdio;
    let binary = assert_cmd::cargo::cargo_bin("ak");
    let mut child = std::process::Command::new(binary)
        .env("AK_CONFIG_DIR", env.dir.path())
        .env("AK_TOKEN", TOKEN)
        .env("AK_CREDENTIAL_STORE", "file")
        .args(["api", "GET", "/x"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(b"");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "ak api didn't exit");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    drop(stdin);
}

#[tokio::test]
async fn head_only_on_a_failure_prints_no_body() {
    let env = Env::new().await;
    Mock::given(path("/x"))
        .respond_with(ResponseTemplate::new(404).set_body_string("the-body"))
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/x", "--head-only"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(out(&output).contains("404"));
    assert!(!err(&output).contains("the-body"));
}

#[tokio::test]
async fn a_failed_request_leaves_an_output_file_alone() {
    let env = Env::new().await;
    Mock::given(path("/x"))
        .respond_with(ResponseTemplate::new(404).set_body_string("nope"))
        .mount(&env.server)
        .await;
    let target = env.file("keep.txt", b"precious");
    let output = env.run(&["GET", "/x", "-o", &target]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(std::fs::read(&target).unwrap(), b"precious");
    assert!(err(&output).contains("nope"));
}

#[tokio::test]
async fn include_prints_status_and_headers_and_masks_credentials() {
    let env = Env::new().await;
    Mock::given(path("/x"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-plain", "shown")
                .insert_header("set-cookie", "ak_session=secret-cookie-value")
                .insert_header("www-authenticate", "Bearer secret-challenge")
                .insert_header("x-echo", format!("you sent {TOKEN}").as_str())
                .set_body_string("the-body"),
        )
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/x", "--include"]);
    let text = out(&output);
    assert!(text.contains("200 OK"), "{text}");
    assert!(text.contains("x-plain: shown"), "{text}");
    assert!(text.contains("set-cookie: [redacted]"), "{text}");
    assert!(!text.contains("secret-cookie-value"), "{text}");
    assert!(!text.contains("secret-challenge"), "{text}");
    assert!(text.ends_with("the-body"), "{text}");
    assert_token_never_printed(&output);
}

#[tokio::test]
async fn head_only_prints_no_body() {
    let env = Env::new().await;
    Mock::given(path("/x"))
        .respond_with(ResponseTemplate::new(200).set_body_string("the-body"))
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/x", "--head-only"]);
    assert!(out(&output).contains("200 OK"));
    assert!(!out(&output).contains("the-body"));
}

// ---- status and exit codes ----

#[tokio::test]
async fn a_failure_status_exits_1_with_the_body_on_stderr() {
    let env = Env::new().await;
    Mock::given(path("/x"))
        .respond_with(ResponseTemplate::new(403).set_body_string("no-access"))
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/x"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(out(&output), "");
    assert!(err(&output).contains("403"));
    assert!(err(&output).contains("no-access"));
}

#[tokio::test]
async fn fail_exits_22_and_hides_the_body() {
    let env = Env::new().await;
    Mock::given(path("/x"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal-detail"))
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/x", "--fail"]);
    assert_eq!(output.status.code(), Some(22));
    assert_eq!(out(&output), "");
    assert!(err(&output).contains("500"));
    assert!(!err(&output).contains("internal-detail"));
}

#[tokio::test]
async fn no_fail_exits_0_with_the_body_on_stdout() {
    let env = Env::new().await;
    Mock::given(path("/x"))
        .respond_with(ResponseTemplate::new(404).set_body_string("the-404-body"))
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/x", "--no-fail"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(out(&output), "the-404-body");
}

#[tokio::test]
async fn an_unreachable_server_exits_3_and_shows_no_credentials() {
    let env = Env::new().await;
    let output = env.run(&[
        "GET",
        "http://user:hunter2@127.0.0.1:1/x?token=hunter3",
        "--max-time",
        "5",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let text = err(&output);
    assert!(!text.contains("hunter2"), "{text}");
    assert!(!text.contains("hunter3"), "{text}");
    assert!(text.contains("127.0.0.1"), "{text}");
    assert_token_never_printed(&output);
}

#[tokio::test]
async fn a_missing_file_exits_3() {
    let env = Env::new().await;
    let output = env.run(&["PUT", "/x", "--raw-body", "@/nonexistent/file"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(env.received().await.is_empty());
}

// ---- --anon and no credentials ----

#[tokio::test]
async fn anon_sends_no_credentials() {
    let env = Env::new().await;
    ok_any(&env.server).await;
    let output = env.run(&["GET", "/x", "--anon"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(!has_auth(&env.received().await[0]));
}

#[tokio::test]
async fn no_credentials_says_how_to_go_on() {
    let env = Env::new().await;
    let output = env
        .cmd(&["GET", "/x"])
        .env_remove("AK_TOKEN")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(err(&output).contains("--anon"), "{}", err(&output));
    assert!(env.received().await.is_empty());
}

// ---- where the token may go: absolute URLs and --url ----

#[tokio::test]
async fn an_absolute_url_on_another_origin_gets_no_token() {
    let env = Env::new().await;
    let other = MockServer::start().await;
    ok_any(&other).await;
    let url = format!("{}/steal", other.uri());
    let output = env.run(&["GET", &url]);
    assert_eq!(output.status.code(), Some(0));
    let received = other.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert!(!has_auth(&received[0]), "the token went to another origin");
    assert!(
        err(&output).contains("isn't being sent"),
        "{}",
        err(&output)
    );
    assert_token_never_printed(&output);
}

#[tokio::test]
async fn an_absolute_url_on_the_instances_origin_gets_the_token() {
    let env = Env::new().await;
    ok_any(&env.server).await;
    let url = format!("{}/x", env.server.uri());
    assert_eq!(env.run(&["GET", &url]).status.code(), Some(0));
    assert!(has_auth(&env.received().await[0]));
}

#[tokio::test]
async fn a_lookalike_host_gets_no_token() {
    // Same port and scheme, different host: localhost isn't 127.0.0.1 here.
    let env = Env::new().await;
    ok_any(&env.server).await;
    let url = env.server.uri().replace("127.0.0.1", "localhost");
    let output = env.run(&["GET", &format!("{url}/x")]);
    assert_eq!(output.status.code(), Some(0));
    assert!(!has_auth(&env.received().await[0]));
}

#[tokio::test]
async fn url_flag_gets_the_token_only_on_the_instances_origin() {
    let env = Env::new().await;
    let other = MockServer::start().await;
    ok_any(&env.server).await;
    ok_any(&other).await;

    let output = env.run(&["GET", "/metrics", "--url", &other.uri()]);
    assert_eq!(output.status.code(), Some(0));
    let received = other.received_requests().await.unwrap();
    assert_eq!(received[0].url.path(), "/metrics");
    assert!(!has_auth(&received[0]));

    let output = env.run(&["GET", "/metrics", "--url", &env.server.uri()]);
    assert_eq!(output.status.code(), Some(0));
    assert!(has_auth(&env.received().await[0]));
}

#[tokio::test]
async fn a_path_cannot_redirect_the_request_to_another_host() {
    let env = Env::new().await;
    let other = MockServer::start().await;
    ok_any(&env.server).await;
    ok_any(&other).await;
    let other_authority = other.uri().replace("http://", "");
    for path in [
        format!("//{other_authority}/x"),
        format!("@{other_authority}/x"),
        format!("/@{other_authority}/x"),
    ] {
        env.run(&["GET", &path]);
    }
    assert!(
        other.received_requests().await.unwrap().is_empty(),
        "a path reached another server"
    );
}

#[tokio::test]
async fn userinfo_in_a_url_is_used_instead_of_the_token() {
    let env = Env::new().await;
    ok_any(&env.server).await;
    let url = env.server.uri().replace("http://", "http://u:p@");
    let output = env.run(&["GET", &format!("{url}/x")]);
    assert_eq!(output.status.code(), Some(0));
    let auth = env.received().await[0]
        .headers
        .get("authorization")
        .cloned();
    assert_eq!(auth.unwrap().to_str().unwrap(), "Basic dTpw");
}

// ---- where the token may go: redirects ----

fn redirect(status: u16, to: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).insert_header("location", to)
}

#[tokio::test]
async fn no_follow_prints_the_location_and_stops() {
    let env = Env::new().await;
    let other = MockServer::start().await;
    ok_any(&other).await;
    Mock::given(path("/x"))
        .respond_with(redirect(302, &format!("{}/target", other.uri())))
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/x", "--no-follow"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(err(&output).contains("Location:"), "{}", err(&output));
    assert!(err(&output).contains("/target"), "{}", err(&output));
    assert!(other.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_same_origin_redirect_keeps_credentials_and_headers() {
    let env = Env::new().await;
    Mock::given(path("/a"))
        .respond_with(redirect(302, "/b"))
        .mount(&env.server)
        .await;
    Mock::given(path("/b"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(header("x-custom", "kept"))
        .respond_with(ResponseTemplate::new(200).set_body_string("landed"))
        .expect(1)
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/a", "-H", "X-Custom: kept"]);
    assert_eq!(out(&output), "landed");
}

#[tokio::test]
async fn a_cross_origin_redirect_gets_no_token_and_no_user_headers() {
    let env = Env::new().await;
    let other = MockServer::start().await;
    Mock::given(path("/target"))
        .respond_with(ResponseTemplate::new(200).set_body_string("from-other"))
        .mount(&other)
        .await;
    Mock::given(path("/a"))
        .respond_with(redirect(302, &format!("{}/target", other.uri())))
        .mount(&env.server)
        .await;

    let output = env.run(&[
        "GET",
        "/a",
        "-H",
        "X-Api-Key: secret-key",
        "-H",
        "Cookie: session=secret-cookie",
        "-H",
        "X-Whatever: secret-custom",
        "-H",
        "Range: bytes=0-1",
    ]);
    assert_eq!(out(&output), "from-other");

    let received = other.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let sent = &received[0];
    assert!(!has_auth(sent), "the token crossed origins");
    assert!(!sent.headers.contains_key("x-api-key"));
    assert!(!sent.headers.contains_key("cookie"));
    assert!(!sent.headers.contains_key("x-whatever"));
    assert!(
        sent.headers.contains_key("range"),
        "Range is harmless and needed"
    );
}

#[tokio::test]
async fn a_users_own_authorization_header_does_not_cross_origins() {
    let env = Env::new().await;
    let other = MockServer::start().await;
    ok_any(&other).await;
    Mock::given(path("/a"))
        .respond_with(redirect(302, &format!("{}/t", other.uri())))
        .mount(&env.server)
        .await;
    env.run(&["GET", "/a", "-H", "Authorization: Basic abc"]);
    assert!(!has_auth(&other.received_requests().await.unwrap()[0]));
}

#[tokio::test]
async fn credentials_do_not_come_back_after_leaving_the_origin() {
    // Instance -> other -> instance: the other server picked this last request,
    // so it must not carry the user's token.
    let env = Env::new().await;
    let other = MockServer::start().await;
    Mock::given(path("/start"))
        .respond_with(redirect(302, &format!("{}/bounce", other.uri())))
        .mount(&env.server)
        .await;
    Mock::given(path("/bounce"))
        .respond_with(redirect(302, &format!("{}/admin/delete", env.server.uri())))
        .mount(&other)
        .await;
    Mock::given(path("/admin/delete"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&env.server)
        .await;

    let output = env.run(&["GET", "/start", "-H", "X-Api-Key: secret"]);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
    let received = env.received().await;
    let last = received.last().unwrap();
    assert_eq!(last.url.path(), "/admin/delete");
    assert!(
        !has_auth(last),
        "the token came back on another server's say-so"
    );
    assert!(!last.headers.contains_key("x-api-key"));
}

#[tokio::test]
async fn a_redirect_to_another_port_is_another_origin() {
    // An https-to-http downgrade is covered by the unit test on same_origin,
    // because wiremock here doesn't serve TLS.
    let env = Env::new().await;
    let other = MockServer::start().await;
    ok_any(&other).await;
    Mock::given(path("/a"))
        .respond_with(redirect(301, &format!("{}/t", other.uri())))
        .mount(&env.server)
        .await;
    env.run(&["GET", "/a"]);
    assert!(!has_auth(&other.received_requests().await.unwrap()[0]));
}

#[tokio::test]
async fn a_put_keeps_its_method_and_body_on_302() {
    let env = Env::new().await;
    Mock::given(path("/a"))
        .respond_with(redirect(302, "/b"))
        .mount(&env.server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/b"))
        .and(body_string("upload"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&env.server)
        .await;
    let output = env.run(&["PUT", "/a", "--raw-body", "upload"]);
    assert_eq!(output.status.code(), Some(0));
}

#[tokio::test]
async fn a_post_becomes_a_get_on_302_with_no_body() {
    let env = Env::new().await;
    Mock::given(method("POST"))
        .and(path("/a"))
        .respond_with(redirect(302, "/b"))
        .mount(&env.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/b"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&env.server)
        .await;
    env.run(&["POST", "/a", "--body", r#"{"password":"x"}"#]);
    let received = env.received().await;
    assert!(received.last().unwrap().body.is_empty());
}

#[tokio::test]
async fn a_307_on_the_same_origin_repeats_the_method_and_body() {
    let env = Env::new().await;
    Mock::given(path("/a"))
        .respond_with(redirect(307, "/b"))
        .mount(&env.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/b"))
        .and(body_json(json!({"a": 1})))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&env.server)
        .await;
    let output = env.run(&["POST", "/a", "--body", r#"{"a":1}"#]);
    assert_eq!(output.status.code(), Some(0));

    // A file is opened again, not lost.
    Mock::given(path("/f"))
        .respond_with(redirect(308, "/g"))
        .mount(&env.server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/g"))
        .and(body_string("file-bytes"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&env.server)
        .await;
    let file = format!("@{}", env.file("f.bin", b"file-bytes"));
    let output = env.run(&["PUT", "/f", "--raw-body", &file]);
    assert_eq!(output.status.code(), Some(0), "{}", err(&output));
}

#[tokio::test]
async fn a_307_to_another_origin_does_not_send_the_body() {
    let env = Env::new().await;
    let other = MockServer::start().await;
    ok_any(&other).await;
    Mock::given(path("/a"))
        .respond_with(redirect(307, &format!("{}/t", other.uri())))
        .mount(&env.server)
        .await;
    let output = env.run(&["POST", "/a", "--body", r#"{"password":"hunter2"}"#]);
    assert_eq!(output.status.code(), Some(1), "nothing reached the target");
    assert!(
        other.received_requests().await.unwrap().is_empty(),
        "the body reached another server"
    );
    assert!(err(&output).contains("another server"), "{}", err(&output));
}

#[tokio::test]
async fn a_307_with_stdin_is_not_followed() {
    let env = Env::new().await;
    Mock::given(path("/a"))
        .respond_with(redirect(307, "/b"))
        .mount(&env.server)
        .await;
    let output = env
        .cmd(&["PUT", "/a", "--raw-body", "@-"])
        .write_stdin("data")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "nothing reached the target");
    assert!(err(&output).contains("stdin"), "{}", err(&output));
    assert_eq!(env.received().await.len(), 1);
}

#[tokio::test]
async fn a_non_http_location_is_refused() {
    let env = Env::new().await;
    Mock::given(path("/a"))
        .respond_with(redirect(302, "file:///etc/passwd"))
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/a"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(err(&output).contains("Not following"), "{}", err(&output));
    assert!(!out(&output).contains("root:"));
}

#[tokio::test]
async fn a_redirect_loop_stops() {
    let env = Env::new().await;
    Mock::given(path("/a"))
        .respond_with(redirect(302, "/a"))
        .mount(&env.server)
        .await;
    let output = env.run(&["GET", "/a"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(err(&output).contains("redirects"), "{}", err(&output));
}

#[tokio::test]
async fn include_on_a_redirect_masks_each_hop() {
    let env = Env::new().await;
    Mock::given(path("/a"))
        .respond_with(redirect(302, "/b").insert_header("set-cookie", "s=secret-cookie-value"))
        .mount(&env.server)
        .await;
    Mock::given(path("/b"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&env.server)
        .await;
    let text = out(&env.run(&["GET", "/a", "--include"]));
    assert!(text.contains("302"), "{text}");
    assert!(text.contains("200"), "{text}");
    assert!(!text.contains("secret-cookie-value"), "{text}");
}
