//! `ak api`: send any HTTP request to the instance, with its auth and TLS settings.
//!
//! This is what makes "anything curl can do, ak can do" true for every route,
//! with or without a first-class command. It holds the user's token and sends
//! requests to URLs that can come from a command line or a server's redirect, so
//! the rule that matters most here is where that token may go:
//!
//! - The token goes only to the instance's own origin (scheme, host and port).
//!   A different origin gets no token, whether it came from an absolute URL,
//!   `--url` or a redirect.
//! - Once a redirect has left the origin, nothing is sent with credentials again,
//!   even if a later redirect points back. Otherwise another server could choose
//!   an authenticated request for us to make.
//! - Redirects are followed here rather than by reqwest, so these rules cover
//!   the user's own headers and the request body too.
//! - Nothing prints a request header. Response headers that carry credentials
//!   are masked, and URLs in errors lose their userinfo and query.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::Args;
use futures::StreamExt;
use miette::Result;
use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode};
use tokio_util::io::ReaderStream;
use url::Url;

use super::helpers::read_inline_or_file;
use crate::cli::GlobalArgs;
use crate::config::AppConfig;
use crate::config::credentials::get_credential;
use crate::error::AkError;
use crate::output::OutputFormat;
use crate::transport;

/// The server answered with a status this run treats as a failure.
const EXIT_HTTP_ERROR: i32 = 1;
/// The same, with `--fail`. curl uses 22 for this.
const EXIT_HTTP_FAIL: i32 = 22;
/// The request didn't complete: network, TLS, or a local file or setting.
const EXIT_NOT_COMPLETED: i32 = 3;

const MAX_REDIRECTS: usize = 10;
/// How much of a failed response goes to stderr. It's a message, not a download.
const MAX_ERROR_BODY: usize = 1024 * 1024;
const REDACTED: &str = "[redacted]";
/// Header values shorter than this aren't masked if they come back: "1" would
/// turn every digit in a response into a mask, and isn't a credential anyway.
const MIN_MASKED_LEN: usize = 6;

/// A response header whose name contains one of these carries a credential, and
/// is masked in `--include` output.
const SENSITIVE_HEADER_WORDS: &[&str] = &[
    "auth", "cookie", "token", "secret", "password", "api-key", "apikey",
];

/// User headers that may follow a redirect to another origin. Anything else
/// could be a credential under a name we can't predict, so it stays behind.
const HEADERS_SAFE_ACROSS_ORIGINS: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "range",
    "user-agent",
];

#[derive(Args, Debug)]
#[command(after_help = "\
Paths are relative to the instance, and may be an absolute URL. The instance's
token goes only to the instance's own scheme, host and port: another origin, from
an absolute URL, --url or a redirect, gets no token. A redirect to another origin
also drops your -H headers, except harmless ones like Range, and never carries a
body. A custom Host header also means no token, because it can reach another site
on a shared proxy.

Exit codes:
  0   success: a 2xx, or a 3xx that wasn't followed
  1   the server answered with another status, whose body goes to stderr, or a
      redirect couldn't be followed safely
  22  the same with --fail, which prints only the status
  2   bad arguments
  3   the request didn't complete: network, TLS, or a local file or setting

Examples:
  ak api GET /api/v1/auth/me
  ak api GET /api/v1/repositories -Q per_page=100 -Q format=npm
  ak api POST /api/v1/repositories --body '{\"key\":\"r\",\"name\":\"r\",\"format\":\"generic\",\"repo_type\":\"local\"}'
  ak api POST /api/v1/repositories --body @repo.json
  ak api PUT /api/v1/repositories/r/artifacts/a.bin --raw-body @a.bin
  ak api POST /api/v1/plugins --form file=@plugin.zip
  ak api GET /npm/r/left-pad/-/left-pad-1.3.0.tgz -o left-pad.tgz
  ak api GET /api/v1/repositories/r/download/a.bin -H 'Range: bytes=0-99' -o part.bin
  ak api HEAD /health --include
  ak api GET /api/v1/repositories/r/download/a.bin --no-follow --include
  ak api GET /metrics --url http://localhost:9090 --anon")]
pub struct ApiArgs {
    /// HTTP method: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, or any other
    #[arg(value_name = "METHOD")]
    method: String,

    /// Path on the instance, or an absolute URL
    #[arg(value_name = "PATH")]
    path: String,

    /// Request header as 'Name: value' (repeatable)
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    headers: Vec<String>,

    /// Query parameter as key=value, URL-encoded for you (repeatable)
    #[arg(short = 'Q', long = "query", value_name = "KEY=VALUE")]
    query: Vec<String>,

    /// JSON body: the text itself, @file, or @- for stdin
    #[arg(long, value_name = "JSON", group = "request_body")]
    body: Option<String>,

    /// Raw body, streamed: @file, @- for stdin, or the text itself.
    /// Content-Type defaults to application/octet-stream
    #[arg(long, value_name = "DATA", group = "request_body")]
    raw_body: Option<String>,

    /// Multipart field (repeatable): key=value, or key=@file with optional
    /// ;type=<mime> and ;filename=<name>. Start a value with \@ for a literal @
    #[arg(long, value_name = "FIELD", group = "request_body")]
    form: Vec<String>,

    /// URL-encoded form field as key=value (repeatable)
    #[arg(long, value_name = "KEY=VALUE", group = "request_body")]
    urlencode: Vec<String>,

    /// Write the response body to a file, or - for stdout, as it arrives
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Print the status and response headers before the body
    #[arg(short = 'i', long)]
    include: bool,

    /// Print the status and response headers, and no body
    #[arg(long, conflicts_with = "include")]
    head_only: bool,

    /// Don't follow redirects. Prints the Location to stderr
    #[arg(long)]
    no_follow: bool,

    /// On a failure status, print only the status and exit 22, like curl -f
    #[arg(long, conflicts_with = "no_fail")]
    fail: bool,

    /// Exit 0 whatever the status, with the body sent as usual, like plain curl
    #[arg(long)]
    no_fail: bool,

    /// Use this base URL instead of the instance's, such as the metrics port
    #[arg(long, value_name = "URL")]
    url: Option<String>,

    /// Send no credentials
    #[arg(long)]
    anon: bool,

    /// Give up after this many seconds. By default only connecting has a limit
    #[arg(long, value_name = "SECONDS")]
    max_time: Option<u64>,
}

pub async fn execute(args: ApiArgs, global: &GlobalArgs) -> Result<()> {
    let deadline = args.max_time.map(std::time::Duration::from_secs);
    let outcome = match deadline {
        Some(limit) => tokio::time::timeout(limit, run(args, global))
            .await
            .unwrap_or_else(|_| {
                Err(AkError::NetworkError(format!(
                    "Gave up after {} seconds (--max-time)",
                    limit.as_secs()
                ))
                .into())
            }),
        None => run(args, global).await,
    };
    let code = match outcome {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e:?}");
            EXIT_NOT_COMPLETED
        }
    };
    // Always exit here, 0 included. Returning would wait for tokio's blocking
    // stdin read, which holds up runtime shutdown for as long as stdin stays open.
    let _ = std::io::stdout().flush();
    std::process::exit(code)
}

/// Where the request goes and what it may carry.
struct Target {
    url: Url,
    /// The instance's token, present only when `url` is on the instance's origin.
    token: Option<String>,
}

async fn run(args: ApiArgs, global: &GlobalArgs) -> Result<i32> {
    let method = parse_method(&args.method)?;
    let headers = parse_headers(&args.headers)?;
    let target = resolve_target(&args, global, &headers)?;
    let body = RequestBody::from_args(&args)?;
    if matches!(body, RequestBody::Form(_)) && headers.contains_key(header::CONTENT_TYPE) {
        return Err(AkError::Usage(
            "--form sets its own Content-Type, with the boundary. Remove the -H for it."
                .to_string(),
        )
        .into());
    }
    let client = api_client()?;
    let quiet = matches!(global.format, OutputFormat::Quiet);
    let secrets = Secrets::new(target.token.as_deref(), &headers);

    let mut url = target.url;
    let mut method = method;
    let mut body = Some(body);
    let mut token = target.token;
    let mut user_headers = headers;
    let mut hops = 0;

    loop {
        let this_body = body.take().unwrap_or(RequestBody::None);
        let resent = this_body.reusable();
        let mut request = client.request(method.clone(), url.clone());
        request = this_body.apply(request, &user_headers).await?;
        request = request.headers(user_headers.clone());
        if let Some(token) = &token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await.map_err(|e| request_failed(&url, e))?;

        if args.include || args.head_only {
            print_head(&response, &secrets)?;
        }

        let redirect = (!args.no_follow)
            .then(|| next_hop(&response, &url, &method, resent.as_ref()))
            .flatten();

        match redirect {
            Some(Hop::Follow {
                to,
                method: next_method,
                keep_body,
            }) => {
                hops += 1;
                if hops > MAX_REDIRECTS {
                    return Err(AkError::NetworkError(format!(
                        "more than {MAX_REDIRECTS} redirects"
                    ))
                    .into());
                }
                if !same_origin(&url, &to) {
                    // Sticky: `token` stays gone, and so do these headers, even
                    // if a later hop returns to the instance.
                    token = None;
                    user_headers = headers_safe_across_origins(&user_headers);
                }
                body = keep_body.then_some(resent).flatten();
                method = next_method;
                url = to;
            }
            Some(Hop::Refused(reason)) => {
                eprintln!("Not following the redirect: {reason}");
                print_location(&response, &secrets);
                // The request hasn't done what was asked, so this can't look like
                // a success.
                return Ok(match (args.no_fail, args.fail) {
                    (true, _) => 0,
                    (_, true) => EXIT_HTTP_FAIL,
                    _ => EXIT_HTTP_ERROR,
                });
            }
            None => return finish(response, &args, quiet, &secrets).await,
        }
    }
}

fn parse_method(raw: &str) -> Result<Method> {
    Method::from_bytes(raw.to_ascii_uppercase().as_bytes())
        .map_err(|_| AkError::Usage(format!("Invalid HTTP method '{raw}'")).into())
}

/// Parse `Name: value` headers. Errors never quote what was typed unless it's a
/// valid header name: a mistyped value could be a credential.
fn parse_headers(raw: &[String]) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for entry in raw {
        let Some((name, value)) = entry.split_once(':') else {
            return Err(AkError::Usage(
                "A header must look like 'Name: value' (what you typed isn't shown here)"
                    .to_string(),
            )
            .into());
        };
        let parsed_name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|_| {
            AkError::Usage(
                "A header name isn't valid (what you typed isn't shown here)".to_string(),
            )
        })?;
        // These describe the body we send, and a wrong value silently truncates
        // it or leaves the server waiting.
        if parsed_name == header::CONTENT_LENGTH || parsed_name == header::TRANSFER_ENCODING {
            return Err(AkError::Usage(format!(
                "ak sets {parsed_name} itself from the body, so it can't be given with -H"
            ))
            .into());
        }
        let parsed_value = HeaderValue::from_str(value.trim()).map_err(|_| {
            AkError::Usage(format!(
                "The value of header '{parsed_name}' isn't valid (not shown)"
            ))
        })?;
        headers.append(parsed_name, parsed_value);
    }
    Ok(headers)
}

fn resolve_target(args: &ApiArgs, global: &GlobalArgs, headers: &HeaderMap) -> Result<Target> {
    let is_absolute = args.path.starts_with("http://") || args.path.starts_with("https://");
    let config = AppConfig::load()?;
    // An absolute URL or --url doesn't need an instance, but if there is one its
    // token may still apply, when the URL turns out to be on its origin.
    let instance = match config.resolve_instance(global.instance.as_deref()) {
        Ok(found) => Some(found),
        Err(e) if !is_absolute && args.url.is_none() => return Err(e),
        Err(_) => None,
    };

    let base = args
        .url
        .as_deref()
        .or(instance.as_ref().map(|(_, i)| i.url.as_str()))
        .unwrap_or_default();
    let mut url = build_url(base, &args.path)?;
    append_query(&mut url, &args.query)?;

    let instance_origin = instance.as_ref().and_then(|(_, i)| Url::parse(&i.url).ok());
    let on_instance = instance_origin
        .as_ref()
        .is_some_and(|origin| same_origin(origin, &url));

    let has_own_auth = headers.contains_key(header::AUTHORIZATION)
        || !url.username().is_empty()
        || url.password().is_some();
    let token = if args.anon || has_own_auth {
        None
    } else if headers.contains_key(header::HOST) {
        // A shared proxy routes on Host, so this could reach another site.
        eprintln!("Note: with a custom Host header, the instance's token isn't being sent.");
        None
    } else if on_instance {
        let (name, inst) = instance.as_ref().expect("on_instance implies an instance");
        match get_credential(name) {
            Ok(cred) => {
                transport::warn_if_insecure(name, inst);
                Some(cred.access_token)
            }
            Err(e) => {
                return Err(
                    miette::Report::new(AkError::NotAuthenticated(name.to_string())).wrap_err(
                        format!("{e}. Pass --anon to send the request with no credentials"),
                    ),
                );
            }
        }
    } else {
        if instance.is_some() {
            eprintln!(
                "Note: {} isn't the instance's address, so its token isn't being sent.",
                display_url(&url)
            );
        }
        None
    };

    Ok(Target { url, token })
}

/// Join a path to the base, or parse an absolute URL.
///
/// The path always goes after a `/` we add: `@evil.example` or `//evil.example`
/// typed as a path stays a path on the instance, and can't become its host.
fn build_url(base: &str, path: &str) -> Result<Url> {
    if path.starts_with("http://") || path.starts_with("https://") {
        return Url::parse(path).map_err(|e| AkError::Usage(format!("Invalid URL: {e}")).into());
    }
    if base.is_empty() {
        return Err(AkError::NoInstance.into());
    }
    let base_url =
        Url::parse(base).map_err(|e| AkError::ConfigError(format!("Invalid base URL: {e}")))?;
    let joined = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let url = Url::parse(&joined).map_err(|e| AkError::Usage(format!("Invalid path: {e}")))?;
    // Whatever the path held, the request must still go to the base's server.
    if !same_origin(&base_url, &url) {
        return Err(AkError::Usage(format!("Invalid path '{path}'")).into());
    }
    Ok(url)
}

fn append_query(url: &mut Url, query: &[String]) -> Result<()> {
    if query.is_empty() {
        return Ok(());
    }
    let mut pairs = Vec::with_capacity(query.len());
    for entry in query {
        pairs.push(split_key_value(entry, "-Q/--query")?);
    }
    url.query_pairs_mut().extend_pairs(pairs);
    Ok(())
}

fn split_key_value<'a>(entry: &'a str, flag: &str) -> Result<(&'a str, &'a str)> {
    entry.split_once('=').ok_or_else(|| {
        // What was typed isn't quoted: it could be a secret missing its key.
        AkError::Usage(format!(
            "{flag} takes key=value, and one of them has no '='"
        ))
        .into()
    })
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// A URL for a message: no userinfo and no query, which can hold credentials.
fn display_url(url: &Url) -> String {
    let mut shown = url.clone();
    let _ = shown.set_username("");
    let _ = shown.set_password(None);
    shown.set_query(None);
    shown.set_fragment(None);
    shown.to_string()
}

fn request_failed(url: &Url, e: reqwest::Error) -> miette::Report {
    // without_url: reqwest would print the URL in full, query and userinfo too.
    let e = e.without_url();
    let mut message = format!("Request to {} failed: {}", display_url(url), e);
    let mut source = std::error::Error::source(&e);
    while let Some(cause) = source {
        message.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    AkError::NetworkError(message).into()
}

fn api_client() -> Result<reqwest::Client> {
    let client = super::client::raw_http_client_builder(reqwest::redirect::Policy::none());
    transport::apply_custom_ca(client)?
        .build()
        .map_err(|e| AkError::Local(format!("Couldn't set up the HTTP client: {e}")).into())
}

fn headers_safe_across_origins(headers: &HeaderMap) -> HeaderMap {
    let mut kept = HeaderMap::new();
    for (name, value) in headers {
        if HEADERS_SAFE_ACROSS_ORIGINS.contains(&name.as_str()) {
            kept.append(name.clone(), value.clone());
        }
    }
    kept
}

enum Hop {
    Follow {
        to: Url,
        method: Method,
        keep_body: bool,
    },
    Refused(String),
}

/// Decide what to do about a redirect response, if this is one.
fn next_hop(
    response: &reqwest::Response,
    from: &Url,
    method: &Method,
    body: Option<&RequestBody>,
) -> Option<Hop> {
    let status = response.status();
    if !status.is_redirection() || status == StatusCode::NOT_MODIFIED {
        return None;
    }
    let location = response
        .headers()
        .get(header::LOCATION)?
        .to_str()
        .ok()?
        .to_string();
    let mut to = match from.join(&location) {
        Ok(to) => to,
        Err(_) => return Some(Hop::Refused("its Location isn't a valid URL".to_string())),
    };
    if !matches!(to.scheme(), "http" | "https") {
        return Some(Hop::Refused(format!(
            "its Location uses {}:, not http or https",
            to.scheme()
        )));
    }
    // A server doesn't get to choose the credentials we send. reqwest would turn
    // userinfo into a second Authorization header.
    let _ = to.set_username("");
    let _ = to.set_password(None);

    // Only a POST becomes a GET on 301 and 302, as in curl, and anything but HEAD
    // on 303. Every other redirect repeats the method and the body. A PUT turned
    // into a GET would lose the upload and report success.
    let becomes_get = status == StatusCode::SEE_OTHER && *method != Method::HEAD
        || matches!(status, StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND)
            && *method == Method::POST;
    if becomes_get {
        return Some(Hop::Follow {
            to,
            method: Method::GET,
            keep_body: false,
        });
    }
    if status == StatusCode::SEE_OTHER {
        return Some(Hop::Follow {
            to,
            method: Method::HEAD,
            keep_body: false,
        });
    }

    let Some(body) = body else {
        return Some(Hop::Refused(
            "the body came from a pipe or stdin, and can't be sent again".to_string(),
        ));
    };
    if !matches!(body, RequestBody::None) && !same_origin(from, &to) {
        return Some(Hop::Refused(
            "it would send the request body to another server".to_string(),
        ));
    }
    Some(Hop::Follow {
        to,
        method: method.clone(),
        keep_body: true,
    })
}

/// What to send. Everything but stdin can be built again for a redirect.
enum RequestBody {
    None,
    Bytes {
        bytes: Vec<u8>,
        content_type: &'static str,
    },
    File(PathBuf),
    Stdin,
    Form(Vec<FormField>),
}

#[derive(Clone)]
enum FormField {
    Text {
        name: String,
        value: String,
    },
    File {
        name: String,
        path: PathBuf,
        filename: String,
        mime: Option<String>,
    },
}

impl RequestBody {
    fn from_args(args: &ApiArgs) -> Result<Self> {
        if let Some(json) = &args.body {
            let bytes = read_inline_or_file(json, "--body")?;
            if serde_json::from_slice::<serde_json::Value>(&bytes).is_err() {
                // The body itself isn't quoted back: it could hold a password.
                return Err(AkError::Usage(
                    "--body isn't valid JSON. Use --raw-body to send other data.".to_string(),
                )
                .into());
            }
            return Ok(Self::Bytes {
                bytes,
                content_type: "application/json",
            });
        }
        if let Some(raw) = &args.raw_body {
            return Ok(match raw.strip_prefix('@') {
                Some("-") => Self::Stdin,
                Some(path) => {
                    let path = PathBuf::from(path);
                    check_readable(&path, "--raw-body")?;
                    Self::File(path)
                }
                None => Self::Bytes {
                    bytes: raw.clone().into_bytes(),
                    content_type: "application/octet-stream",
                },
            });
        }
        if !args.form.is_empty() {
            let fields = args
                .form
                .iter()
                .map(|f| parse_form_field(f))
                .collect::<Result<Vec<_>>>()?;
            return Ok(Self::Form(fields));
        }
        if !args.urlencode.is_empty() {
            let mut encoder = url::form_urlencoded::Serializer::new(String::new());
            for entry in &args.urlencode {
                let (key, value) = split_key_value(entry, "--urlencode")?;
                encoder.append_pair(key, value);
            }
            return Ok(Self::Bytes {
                bytes: encoder.finish().into_bytes(),
                content_type: "application/x-www-form-urlencoded",
            });
        }
        Ok(Self::None)
    }

    /// A copy for a possible redirect, or `None` if this body can only be read once.
    fn reusable(&self) -> Option<RequestBody> {
        match self {
            Self::None => Some(Self::None),
            Self::Bytes {
                bytes,
                content_type,
            } => Some(Self::Bytes {
                bytes: bytes.clone(),
                content_type,
            }),
            // A pipe can only be read once, so only a regular file can be sent again.
            Self::File(path) => path.is_file().then(|| Self::File(path.clone())),
            Self::Form(fields) => fields
                .iter()
                .all(|f| match f {
                    FormField::Text { .. } => true,
                    FormField::File { path, .. } => path.is_file(),
                })
                .then(|| Self::Form(fields.clone())),
            Self::Stdin => None,
        }
    }

    async fn apply(
        self,
        request: reqwest::RequestBuilder,
        user_headers: &HeaderMap,
    ) -> Result<reqwest::RequestBuilder> {
        let default_type = |request: reqwest::RequestBuilder, value: &'static str| {
            if user_headers.contains_key(header::CONTENT_TYPE) {
                request
            } else {
                request.header(header::CONTENT_TYPE, value)
            }
        };
        Ok(match self {
            Self::None => request,
            Self::Bytes {
                bytes,
                content_type,
            } => default_type(request, content_type).body(bytes),
            Self::File(path) => {
                let (file, length) = open_for_streaming(&path).await?;
                let request = default_type(request, "application/octet-stream");
                // A pipe or /dev/stdin has no length: it goes chunked.
                let request = match length {
                    Some(length) => request.header(header::CONTENT_LENGTH, length),
                    None => request,
                };
                request.body(reqwest::Body::wrap_stream(ReaderStream::new(file)))
            }
            Self::Stdin => {
                let stdin = ReaderStream::new(tokio::io::stdin());
                default_type(request, "application/octet-stream")
                    .body(reqwest::Body::wrap_stream(stdin))
            }
            Self::Form(fields) => {
                let mut form = reqwest::multipart::Form::new();
                for field in fields {
                    form = match field {
                        FormField::Text { name, value } => form.text(name, value),
                        FormField::File {
                            name,
                            path,
                            filename,
                            mime,
                        } => {
                            let (file, length) = open_for_streaming(&path).await?;
                            let mime = mime.unwrap_or_else(|| {
                                mime_guess::from_path(&path)
                                    .first_or_octet_stream()
                                    .to_string()
                            });
                            let stream = reqwest::Body::wrap_stream(ReaderStream::new(file));
                            let part = match length {
                                Some(length) => {
                                    reqwest::multipart::Part::stream_with_length(stream, length)
                                }
                                None => reqwest::multipart::Part::stream(stream),
                            };
                            let part = part.file_name(filename).mime_str(&mime).map_err(|_| {
                                AkError::Usage(format!("Invalid type '{mime}' for {name}"))
                            })?;
                            form.part(name, part)
                        }
                    };
                }
                request.multipart(form)
            }
        })
    }
}

/// The bytes for a flag that takes text, @file or @-.
fn check_readable(path: &Path, flag: &str) -> Result<()> {
    std::fs::File::open(path)
        .map(|_| ())
        .map_err(|e| AkError::Usage(format!("{flag}: can't read '{}': {e}", path.display())).into())
}

/// Open a file to stream, with its length if it's a regular file. Anything else,
/// such as a pipe, reports a length of 0 that isn't true.
async fn open_for_streaming(path: &Path) -> Result<(tokio::fs::File, Option<u64>)> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| AkError::Usage(format!("Can't read '{}': {e}", path.display())))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|e| AkError::Usage(format!("Can't read '{}': {e}", path.display())))?;
    Ok((file, metadata.is_file().then_some(metadata.len())))
}

/// Parse `key=value` or `key=@file[;type=<mime>][;filename=<name>]`.
fn parse_form_field(entry: &str) -> Result<FormField> {
    let (name, rest) = split_key_value(entry, "--form")?;
    if let Some(literal) = rest.strip_prefix("\\@") {
        return Ok(FormField::Text {
            name: name.to_string(),
            value: format!("@{literal}"),
        });
    }
    let Some(spec) = rest.strip_prefix('@') else {
        return Ok(FormField::Text {
            name: name.to_string(),
            value: rest.to_string(),
        });
    };

    let mut parts = spec.split(';');
    let path = PathBuf::from(parts.next().unwrap_or_default());
    check_readable(&path, "--form")?;
    let mut mime = None;
    let mut filename = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    for option in parts {
        match option.split_once('=') {
            Some(("type", value)) => mime = Some(value.to_string()),
            Some(("filename", value)) => filename = value.to_string(),
            _ => {
                return Err(AkError::Usage(format!(
                    "--form: unknown option '{option}'. Use ;type=<mime> or ;filename=<name>"
                ))
                .into());
            }
        }
    }
    Ok(FormField::File {
        name: name.to_string(),
        path,
        filename,
        mime,
    })
}

/// What must not be shown again if a server sends it back: the token, and values
/// of the user's own headers that could be credentials.
#[derive(Default)]
struct Secrets(Vec<String>);

impl Secrets {
    fn new(token: Option<&str>, headers: &HeaderMap) -> Self {
        let mut values: Vec<String> = token.map(str::to_string).into_iter().collect();
        for (name, value) in headers {
            if HEADERS_SAFE_ACROSS_ORIGINS.contains(&name.as_str())
                || *name == header::CONTENT_TYPE
                || *name == header::HOST
            {
                continue;
            }
            let Ok(value) = value.to_str() else { continue };
            // "Basic abc" or "Bearer abc" can come back as just "abc".
            values.extend(
                value
                    .rsplit(' ')
                    .next()
                    .into_iter()
                    .map(str::to_string)
                    .filter(|v| v.len() >= MIN_MASKED_LEN),
            );
            if value.len() >= MIN_MASKED_LEN {
                values.push(value.to_string());
            }
        }
        // Longest first, so a whole value goes before a part of it.
        values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        Self(values)
    }

    fn mask(&self, text: &str) -> String {
        let mut text = text.to_string();
        for secret in &self.0 {
            text = text.replace(secret.as_str(), REDACTED);
        }
        text
    }
}

fn is_sensitive_header(name: &str) -> bool {
    SENSITIVE_HEADER_WORDS.iter().any(|w| name.contains(w))
}

/// A Location for display: no userinfo, the server's words otherwise, with secrets
/// masked and the bytes safe for a terminal.
fn shown_location(raw: &str, secrets: &Secrets) -> String {
    let without_userinfo = match Url::parse(raw) {
        Ok(mut url) if !url.username().is_empty() || url.password().is_some() => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.to_string()
        }
        _ => raw.to_string(),
    };
    crate::output::sanitize_terminal(&secrets.mask(&without_userinfo))
}

/// Print the status line and headers, with credentials masked and the bytes made
/// safe for a terminal.
fn print_head(response: &reqwest::Response, secrets: &Secrets) -> Result<()> {
    let text = format_head(
        response.version(),
        response.status(),
        response.headers(),
        secrets,
    );
    let mut stdout = std::io::stdout().lock();
    let written = stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush());
    match written {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other.map_err(|e| AkError::Io(e).into()),
    }
}

fn format_head(
    version: reqwest::Version,
    status: StatusCode,
    headers: &HeaderMap,
    secrets: &Secrets,
) -> String {
    let mut text = format!("{version:?} {status}\r\n");
    for (name, value) in headers {
        let raw = String::from_utf8_lossy(value.as_bytes());
        let value = if is_sensitive_header(name.as_str()) {
            REDACTED.to_string()
        } else if *name == header::LOCATION {
            shown_location(&raw, secrets)
        } else {
            secrets.mask(&raw)
        };
        text.push_str(&crate::output::sanitize_terminal(&format!(
            "{name}: {value}"
        )));
        text.push_str("\r\n");
    }
    text.push_str("\r\n");
    text
}

fn print_location(response: &reqwest::Response, secrets: &Secrets) {
    if let Some(location) = response.headers().get(header::LOCATION) {
        let raw = String::from_utf8_lossy(location.as_bytes());
        eprintln!("Location: {}", shown_location(&raw, secrets));
    }
}

/// Handle the response that ended the request chain, and return the exit code.
async fn finish(
    response: reqwest::Response,
    args: &ApiArgs,
    quiet: bool,
    secrets: &Secrets,
) -> Result<i32> {
    let status = response.status();
    let ok = status.is_success() || status.is_redirection();

    if status.is_redirection() {
        print_location(&response, secrets);
    }

    if !ok && !args.no_fail {
        if args.fail {
            eprintln!("ak api: the server returned {status}");
            return Ok(EXIT_HTTP_FAIL);
        }
        if args.head_only {
            return Ok(EXIT_HTTP_ERROR);
        }
        print_error_body(response, status, secrets).await;
        return Ok(EXIT_HTTP_ERROR);
    }

    if args.head_only || (quiet && args.output.is_none()) {
        return Ok(0);
    }
    write_body(response, args.output.as_deref()).await?;
    Ok(0)
}

/// A failed response's body goes to stderr, so stdout and any `-o` file stay clean
/// for a pipeline.
async fn print_error_body(mut response: reqwest::Response, status: StatusCode, secrets: &Secrets) {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        body.extend_from_slice(&chunk);
        if body.len() >= MAX_ERROR_BODY {
            body.truncate(MAX_ERROR_BODY);
            break;
        }
    }
    let text = secrets.mask(&String::from_utf8_lossy(&body));
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "ak api: the server returned {status}");
    if !text.is_empty() {
        let shown = if std::io::stderr().is_terminal() {
            crate::output::sanitize_terminal(&text)
        } else {
            text
        };
        let _ = writeln!(stderr, "{shown}");
    }
}

/// Stream the body to a file or stdout without holding it in memory.
async fn write_body(response: reqwest::Response, output: Option<&Path>) -> Result<()> {
    let to_file = output.filter(|p| *p != Path::new("-"));
    match to_file {
        Some(path) => {
            let mut file = tokio::fs::File::create(path)
                .await
                .map_err(|e| AkError::Local(format!("Can't write '{}': {e}", path.display())))?;
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| {
                    AkError::NetworkError(format!(
                        "The download stopped, and '{}' is incomplete: {}",
                        path.display(),
                        e.without_url()
                    ))
                })?;
                tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
                    .await
                    .map_err(AkError::Io)?;
            }
            tokio::io::AsyncWriteExt::flush(&mut file)
                .await
                .map_err(AkError::Io)?;
            Ok(())
        }
        None => {
            let terminal = std::io::stdout().is_terminal();
            let mut filter = TerminalFilter::default();
            let mut stream = response.bytes_stream();
            let mut stdout = std::io::stdout().lock();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| {
                    AkError::NetworkError(format!("The response stopped: {}", e.without_url()))
                })?;
                // Flushed each time: stdout buffers by line, and a body without
                // newlines would otherwise sit there until the end.
                let result = if terminal {
                    stdout.write_all(filter.push(&chunk).as_bytes())
                } else {
                    stdout.write_all(&chunk)
                }
                .and_then(|()| stdout.flush());
                match result {
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
                    other => other.map_err(AkError::Io)?,
                }
            }
            if terminal {
                let _ = stdout.write_all(filter.finish().as_bytes());
            }
            match stdout.flush() {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                other => other.map_err(|e| AkError::Io(e).into()),
            }
        }
    }
}

/// Makes a body safe for a terminal, chunk by chunk: a chunk can end partway
/// through a UTF-8 character. Only used when stdout is a terminal. A pipe or a
/// file gets the bytes as received.
#[derive(Default)]
struct TerminalFilter {
    pending: Vec<u8>,
}

impl TerminalFilter {
    fn push(&mut self, chunk: &[u8]) -> String {
        self.pending.extend_from_slice(chunk);
        let keep_from = match std::str::from_utf8(&self.pending) {
            Ok(_) => self.pending.len(),
            // A short invalid tail may be a character split across chunks.
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => self.pending.len(),
        };
        let rest = self.pending.split_off(keep_from);
        let ready = std::mem::replace(&mut self.pending, rest);
        crate::output::sanitize_terminal(&String::from_utf8_lossy(&ready))
    }

    fn finish(&mut self) -> String {
        let rest = std::mem::take(&mut self.pending);
        crate::output::sanitize_terminal(&String::from_utf8_lossy(&rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn method_is_uppercased_and_custom_methods_work() {
        assert_eq!(parse_method("get").unwrap(), Method::GET);
        assert_eq!(parse_method("OPTIONS").unwrap(), Method::OPTIONS);
        assert_eq!(parse_method("propfind").unwrap().as_str(), "PROPFIND");
        assert!(parse_method("BAD METHOD").is_err());
    }

    #[test]
    fn a_path_cannot_change_the_host() {
        for path in [
            "@evil.example/x",
            "//evil.example/x",
            "/@evil.example/x",
            "\\\\evil.example/x",
            "/\\evil.example/x",
            ":pw@evil.example/x",
        ] {
            let built = build_url("https://ak.example.com", path);
            if let Ok(built) = built {
                assert_eq!(built.host_str(), Some("ak.example.com"), "{path}");
            }
        }
    }

    #[test]
    fn a_path_is_joined_to_a_base_with_a_prefix() {
        assert_eq!(
            build_url("https://ak.example.com/prefix/", "api/v1/x?a=b")
                .unwrap()
                .as_str(),
            "https://ak.example.com/prefix/api/v1/x?a=b"
        );
        assert_eq!(
            build_url("https://ak.example.com", "/api/v1/x")
                .unwrap()
                .as_str(),
            "https://ak.example.com/api/v1/x"
        );
    }

    #[test]
    fn same_origin_compares_scheme_host_and_port() {
        let base = url("https://ak.example.com/a");
        assert!(same_origin(&base, &url("https://ak.example.com:443/b")));
        assert!(!same_origin(&base, &url("http://ak.example.com/b")));
        assert!(!same_origin(&base, &url("https://ak.example.com:8443/b")));
        assert!(!same_origin(
            &base,
            &url("https://ak.example.com.evil.test/b")
        ));
    }

    #[test]
    fn display_url_drops_userinfo_and_query() {
        assert_eq!(
            display_url(&url("https://user:pw@ak.example.com/a?token=secret#f")),
            "https://ak.example.com/a"
        );
    }

    #[test]
    fn query_values_are_encoded_and_added_to_any_in_the_path() {
        let mut u = url("https://ak.example.com/a?x=1");
        append_query(&mut u, &["q=a b&c".to_string()]).unwrap();
        assert_eq!(u.query(), Some("x=1&q=a+b%26c"));
        assert!(append_query(&mut u, &["no-equals".to_string()]).is_err());
    }

    #[test]
    fn a_bad_header_error_never_shows_the_value() {
        let secret = "s3cret\nvalue";
        for raw in [
            secret.to_string(),
            format!("X-Token: {secret}"),
            "Bearer s3cret:value".to_string(),
        ] {
            let err = parse_headers(&[raw]).unwrap_err().to_string();
            assert!(!err.contains("s3cret"), "{err}");
        }
    }

    #[test]
    fn headers_keep_repeats_and_an_empty_value() {
        let headers = parse_headers(&[
            "X-A: 1".to_string(),
            "X-A: 2".to_string(),
            "X-Empty:".to_string(),
        ])
        .unwrap();
        assert_eq!(headers.get_all("x-a").iter().count(), 2);
        assert_eq!(headers.get("x-empty").unwrap(), "");
    }

    #[test]
    fn only_harmless_headers_cross_origins() {
        let headers = parse_headers(&[
            "Authorization: Basic abc".to_string(),
            "X-Api-Key: abc".to_string(),
            "X-Custom-Thing: abc".to_string(),
            "Cookie: a=b".to_string(),
            "Range: bytes=0-1".to_string(),
            "Accept: text/plain".to_string(),
        ])
        .unwrap();
        let kept = headers_safe_across_origins(&headers);
        assert_eq!(kept.len(), 2);
        assert!(kept.contains_key("range"));
        assert!(kept.contains_key("accept"));
    }

    #[test]
    fn head_output_masks_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("set-cookie", "session=secretvalue".parse().unwrap());
        headers.insert("www-authenticate", "Bearer secretvalue".parse().unwrap());
        headers.insert("x-vault-token", "secretvalue".parse().unwrap());
        headers.insert("x-echo", "got my-token-value here".parse().unwrap());
        headers.insert("x-echo-2", "got key-from-user".parse().unwrap());
        headers.insert(
            "location",
            "https://user:hunter2@cdn.example/x?sig=abc"
                .parse()
                .unwrap(),
        );
        headers.insert("content-type", "text/plain".parse().unwrap());
        let user = parse_headers(&["X-Api-Key: key-from-user".to_string()]).unwrap();
        let secrets = Secrets::new(Some("my-token-value"), &user);
        let text = format_head(
            reqwest::Version::HTTP_11,
            StatusCode::OK,
            &headers,
            &secrets,
        );
        for hidden in ["secretvalue", "my-token-value", "key-from-user", "hunter2"] {
            assert!(!text.contains(hidden), "{hidden} in {text}");
        }
        assert!(text.contains("HTTP/1.1 200 OK"), "{text}");
        assert!(text.contains("content-type: text/plain"), "{text}");
        assert!(text.contains("set-cookie: [redacted]"), "{text}");
        assert!(
            text.contains("location: https://cdn.example/x?sig=abc"),
            "{text}"
        );
    }

    #[test]
    fn secrets_mask_a_bare_credential_from_an_authorization_header() {
        let user = parse_headers(&["Authorization: Basic dXNlcjpwYXNz".to_string()]).unwrap();
        let shown = Secrets::new(None, &user).mask("you sent dXNlcjpwYXNz, or Basic dXNlcjpwYXNz");
        assert!(!shown.contains("dXNlcjpwYXNz"), "{shown}");
    }

    #[test]
    fn body_describing_headers_are_refused() {
        assert!(parse_headers(&["Content-Length: 3".to_string()]).is_err());
        assert!(parse_headers(&["Transfer-Encoding: chunked".to_string()]).is_err());
    }

    #[test]
    fn form_fields_parse() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("p.zip");
        std::fs::write(&file, "x").unwrap();

        assert!(matches!(
            parse_form_field("a=b").unwrap(),
            FormField::Text { value, .. } if value == "b"
        ));
        assert!(matches!(
            parse_form_field("a=\\@b").unwrap(),
            FormField::Text { value, .. } if value == "@b"
        ));
        let spec = format!("f=@{};type=application/zip;filename=n.zip", file.display());
        assert!(matches!(
            parse_form_field(&spec).unwrap(),
            FormField::File { filename, mime: Some(mime), .. }
                if filename == "n.zip" && mime == "application/zip"
        ));
        let plain = format!("f=@{}", file.display());
        assert!(matches!(
            parse_form_field(&plain).unwrap(),
            FormField::File { filename, mime: None, .. } if filename == "p.zip"
        ));
        assert!(parse_form_field("f=@/nonexistent/file").is_err());
        assert!(parse_form_field("no-equals").is_err());
        assert!(parse_form_field(&format!("{plain};bad=1")).is_err());
    }

    #[test]
    fn terminal_filter_neutralizes_escapes_and_keeps_split_characters() {
        let mut filter = TerminalFilter::default();
        assert_eq!(filter.push(b"ok\x1b[2J"), "ok\\u{1b}[2J");
        // "é" is 0xC3 0xA9: split across two chunks it must still come out whole.
        assert_eq!(filter.push(&[b'a', 0xC3]), "a");
        assert_eq!(filter.push(&[0xA9, b'b']), "éb");
        // A C1 CSI encoded in UTF-8 is a terminal escape too.
        assert!(!filter.push("x\u{9b}2J".as_bytes()).contains('\u{9b}'));
        assert_eq!(filter.push(&[0xC3]), "");
        assert_eq!(filter.finish(), "\u{fffd}");
    }
}
