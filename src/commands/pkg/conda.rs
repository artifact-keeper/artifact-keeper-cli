//! `ak pkg conda`. The server reads `index.json` from the package.
//!
//! conda and rattler can carry the token in the URL, in two shapes. Those routes are
//! here too: `--token-in-url` sends this instance's token that way and no header. The
//! server only takes an API token there, not a login session.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use miette::Result;
use reqwest::{Method, Url};
use serde_json::json;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::commands::helpers::{confirm_action, read_inline_or_file, refuse_flags_before_1_11};
use crate::error::AkError;

const CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Clone, Copy, ValueEnum)]
pub enum TokenUrl {
    /// /conda/t/<token>/<repo>/...
    CondaT,
    /// /t/<token>/conda/<repo>/..., which is what rattler uses
    TConda,
}

#[derive(Subcommand)]
pub enum CondaCommand {
    /// Upload a .conda or .tar.bz2 package
    #[command(after_help = "\
With --subdir it goes to PUT /conda/<repo>/<subdir>/<file>. Without, it goes to the
upload route, and the server takes the subdir from the package's index.json.

Examples:
  ak pkg conda publish my-conda demo-1.0-0.tar.bz2
  ak pkg conda publish my-conda demo-1.0-0.conda --subdir linux-64")]
    Publish {
        /// Repository key
        repo: String,
        /// The .conda or .tar.bz2 file
        file: PathBuf,
        /// Target subdir, such as linux-64 or noarch
        #[arg(long)]
        subdir: Option<String>,
        /// Send the token in the URL rather than a header
        #[arg(long, value_enum)]
        token_in_url: Option<TokenUrl>,
    },
    /// Attach a CEP-27 attestation to a package
    Attest {
        /// Repository key
        repo: String,
        /// Subdir of the package
        subdir: String,
        /// File name of the package
        filename: String,
        /// The attestation: JSON text, @file, or @- for stdin
        attestation: String,
        /// Send the token in the URL rather than a header
        #[arg(long, value_enum)]
        token_in_url: Option<TokenUrl>,
    },
    /// Withdraw a package from the channel (CEP-26). Needs an admin
    Withdraw {
        /// Repository key
        repo: String,
        /// Subdir of the package
        subdir: String,
        /// File name of the package
        filename: String,
        /// Why, recorded on the package
        #[arg(long)]
        reason: Option<String>,
        /// Don't ask for confirmation
        #[arg(long)]
        yes: bool,
    },
}

/// A login session is a JWT, which the server refuses in a URL. Say so, rather than
/// show its 401. So does a server older than the rattler form, which has no such route.
async fn check_url_token(wire: &Wire, token: Option<TokenUrl>, global: &GlobalArgs) -> Result<()> {
    if matches!(token, Some(TokenUrl::TConda)) {
        refuse_flags_before_1_11(&["--token-in-url t-conda"], global).await?;
    }
    if token.is_some() && wire.token().split('.').count() == 3 {
        return Err(AkError::Usage(
            "--token-in-url needs an API token, and this is a login session. Create one with \
             `ak auth token create`, and set it in AK_TOKEN"
                .to_string(),
        )
        .into());
    }
    Ok(())
}

/// A URL under the channel, which holds the token if it's asked to.
fn channel_url(wire: &Wire, repo: &str, tail: &[&str], token: Option<TokenUrl>) -> Url {
    let mut segments: Vec<&str> = match token {
        None => vec!["conda", repo],
        Some(TokenUrl::CondaT) => vec!["conda", "t", wire.token(), repo],
        Some(TokenUrl::TConda) => vec!["t", wire.token(), "conda", repo],
    };
    segments.extend(tail);
    wire.url(&segments)
}

fn conda_request(
    wire: &Wire,
    method: Method,
    url: Url,
    token: Option<TokenUrl>,
) -> reqwest::RequestBuilder {
    if token.is_some() {
        wire.request_no_header(method, url)
    } else {
        wire.request(method, url)
    }
}

pub async fn execute(command: CondaCommand, global: &GlobalArgs) -> Result<()> {
    let wire = Wire::new(global)?;
    match command {
        CondaCommand::Publish {
            repo,
            file,
            subdir,
            token_in_url,
        } => {
            check_url_token(&wire, token_in_url, global).await?;
            let upload = Upload::open(&file)?;
            let request = match &subdir {
                Some(subdir) => conda_request(
                    &wire,
                    Method::PUT,
                    channel_url(&wire, &repo, &[subdir, &upload.name], token_in_url),
                    token_in_url,
                ),
                None => conda_request(
                    &wire,
                    Method::POST,
                    channel_url(&wire, &repo, &["upload"], token_in_url),
                    token_in_url,
                )
                .header("X-Package-Filename", &upload.name),
            };
            let request = upload.attach(request, CONTENT_TYPE).await?;
            let reply = wire.send("upload the package", request).await?;
            emit(
                &reply,
                &upload.name,
                &format!("Published {} to {repo}.", upload.name),
                global,
            );
        }
        CondaCommand::Attest {
            repo,
            subdir,
            filename,
            attestation,
            token_in_url,
        } => {
            check_url_token(&wire, token_in_url, global).await?;
            let body = read_inline_or_file(&attestation, "the attestation")?;
            let reply = wire
                .send(
                    "attach the attestation",
                    conda_request(
                        &wire,
                        Method::PUT,
                        channel_url(
                            &wire,
                            &repo,
                            &[&subdir, &filename, "attestation"],
                            token_in_url,
                        ),
                        token_in_url,
                    )
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body),
                )
                .await?;
            emit(
                &reply,
                &filename,
                &format!("Attached the attestation to {filename}."),
                global,
            );
        }
        CondaCommand::Withdraw {
            repo,
            subdir,
            filename,
            reason,
            yes,
        } => {
            if !confirm_action(&format!("Withdraw {filename}?"), yes, global.no_input)? {
                return Ok(());
            }
            refuse_flags_before_1_11(&["`ak pkg conda withdraw`"], global).await?;
            let url = wire.url(&["conda", &repo, &subdir, &filename]);
            let mut request = wire.request(Method::DELETE, url);
            if let Some(reason) = reason {
                request = request.json(&json!({"reason": reason}));
            }
            let reply = wire.send("withdraw the package", request).await?;
            emit(&reply, &filename, &format!("Withdrew {filename}."), global);
        }
    }
    Ok(())
}
