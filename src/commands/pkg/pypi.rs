//! `ak pkg pypi`: what `twine upload` and the XML-RPC API send.

use std::path::PathBuf;

use clap::Subcommand;
use miette::Result;
use reqwest::Method;
use reqwest::multipart::Form;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;
use crate::error::AkError;

#[derive(Subcommand)]
pub enum PypiCommand {
    /// Upload a wheel or sdist, as `twine upload` does
    #[command(
        after_help = "\
The name and version come from the file name, and the server reads the rest of the
metadata from the package. Use --name and --version for a file named otherwise.

Examples:
  ak pkg pypi publish my-pypi dist/demo-1.0-py3-none-any.whl
  ak pkg pypi publish my-pypi dist/demo-1.0.tar.gz --summary 'A demo'",
        disable_version_flag = true
    )]
    Publish {
        /// Repository key
        repo: String,
        /// The .whl, .tar.gz or .zip to upload
        file: PathBuf,
        /// Project name, instead of the one in the file name
        #[arg(long)]
        name: Option<String>,
        /// Version, instead of the one in the file name
        #[arg(id = "package_version", long = "version")]
        version: Option<String>,
        /// One-line summary
        #[arg(long)]
        summary: Option<String>,
        /// Python versions it supports, such as '>=3.9'
        #[arg(long)]
        requires_python: Option<String>,
    },
    /// Call the XML-RPC API: list_packages, or browse with classifiers
    #[command(after_help = "\
Examples:
  ak pkg pypi xmlrpc my-pypi list_packages
  ak pkg pypi xmlrpc my-pypi browse 'Programming Language :: Python :: 3'")]
    Xmlrpc {
        /// Repository key
        repo: String,
        /// Method name
        method: String,
        /// Strings passed as the method's one list parameter
        values: Vec<String>,
    },
}

pub async fn execute(command: PypiCommand, global: &GlobalArgs) -> Result<()> {
    let wire = Wire::new(global)?;
    match command {
        PypiCommand::Publish {
            repo,
            file,
            name,
            version,
            summary,
            requires_python,
        } => {
            let upload = Upload::open(&file)?;
            let (name, version) = name_and_version(&upload.name, name, version)?;
            let filetype = if upload.name.ends_with(".whl") {
                "bdist_wheel"
            } else {
                "sdist"
            };
            let mut form = Form::new()
                .text(":action", "file_upload")
                .text("protocol_version", "1")
                .text("metadata_version", "2.1")
                .text("name", name.clone())
                .text("version", version.clone())
                .text("filetype", filetype)
                .text("sha256_digest", upload.sha256().await?);
            if let Some(summary) = summary {
                form = form.text("summary", summary);
            }
            if let Some(requires_python) = requires_python {
                form = form.text("requires_python", requires_python);
            }
            let form = form.part("content", upload.part("application/octet-stream").await?);
            // The route has a trailing slash, as the URL twine is given does.
            let mut url = wire.url(&["pypi", &repo]);
            url.set_path(&format!("{}/", url.path()));
            let reply = wire
                .send(
                    "upload the package",
                    wire.request(Method::POST, url).multipart(form),
                )
                .await?;
            emit(
                &reply,
                &format!("{name}=={version}"),
                &format!("Published {name} {version} to {repo}."),
                global,
            );
        }
        PypiCommand::Xmlrpc {
            repo,
            method,
            values,
        } => {
            let reply = wire
                .send(
                    "call the XML-RPC API",
                    wire.request(Method::POST, wire.url(&["pypi", &repo, "pypi"]))
                        .header("content-type", "text/xml")
                        .body(xmlrpc_call(&method, &values)),
                )
                .await?;
            // XML has nothing to print as JSON but its text, and a person wants that too.
            println!("{}", String::from_utf8_lossy(&reply.body).trim());
        }
    }
    Ok(())
}

/// `demo-1.0-py3-none-any.whl` or `demo-1.0.tar.gz`. A wheel's name has no `-` in it,
/// and neither has an sdist's version, so the split is the first or the last dash.
fn name_and_version(
    file: &str,
    name: Option<String>,
    version: Option<String>,
) -> Result<(String, String)> {
    let parsed = if let Some(stem) = file.strip_suffix(".whl") {
        let mut parts = stem.split('-');
        parts
            .next()
            .zip(parts.next())
            .map(|(n, v)| (n.to_string(), v.to_string()))
    } else {
        file.strip_suffix(".tar.gz")
            .or_else(|| file.strip_suffix(".zip"))
            .and_then(|stem| stem.rsplit_once('-'))
            .map(|(n, v)| (n.to_string(), v.to_string()))
    };
    match (name, version, parsed) {
        (Some(n), Some(v), _) => Ok((n, v)),
        (n, v, Some((parsed_n, parsed_v))) => Ok((n.unwrap_or(parsed_n), v.unwrap_or(parsed_v))),
        _ => Err(AkError::Usage(format!(
            "Can't tell the name and version from `{file}`. Give --name and --version"
        ))
        .into()),
    }
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xmlrpc_call(method: &str, values: &[String]) -> String {
    let params = if values.is_empty() {
        String::new()
    } else {
        let items: String = values
            .iter()
            .map(|v| format!("<value><string>{}</string></value>", xml_escape(v)))
            .collect();
        format!("<param><value><array><data>{items}</data></array></value></param>")
    };
    format!(
        "<?xml version=\"1.0\"?><methodCall><methodName>{}</methodName><params>{params}</params></methodCall>",
        xml_escape(method)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_version_from_each_kind_of_file() {
        let cases = [
            ("demo-1.0-py3-none-any.whl", "demo", "1.0"),
            ("my_pkg-2.0.1.tar.gz", "my_pkg", "2.0.1"),
            ("my-pkg-2.0.zip", "my-pkg", "2.0"),
        ];
        for (file, name, version) in cases {
            assert_eq!(
                name_and_version(file, None, None).unwrap(),
                (name.to_string(), version.to_string())
            );
        }
        assert!(name_and_version("odd.bin", None, None).is_err());
        assert_eq!(
            name_and_version("odd.bin", Some("a".into()), Some("1".into())).unwrap(),
            ("a".to_string(), "1".to_string())
        );
    }

    #[test]
    fn xmlrpc_escapes_and_lists() {
        let call = xmlrpc_call("browse", &["a<b".to_string()]);
        assert!(call.contains("<methodName>browse</methodName>"));
        assert!(call.contains("<string>a&lt;b</string>"));
        assert!(xmlrpc_call("list_packages", &[]).contains("<params></params>"));
    }
}
