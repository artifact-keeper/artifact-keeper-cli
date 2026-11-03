//! `ak pkg maven publish`: what `mvn deploy:deploy-file` does. Each file is a PUT, and
//! each has its checksum files next to it, which a client asks for and verifies. With no
//! POM given it writes the minimal one `deploy-file` would.

use std::path::{Path, PathBuf};

use clap::Subcommand;
use md5::Md5;
use miette::Result;
use reqwest::Method;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use super::wire::{Upload, Wire, emit, split_path};
use crate::cli::GlobalArgs;
use crate::error::AkError;

#[derive(Subcommand)]
pub enum MavenCommand {
    /// Upload an artifact with its POM and checksums, as `mvn deploy:deploy-file` does
    #[command(
        disable_version_flag = true,
        after_help = "\
Examples:
  ak pkg maven publish my-maven demo-1.0.jar --group com.acme --artifact demo --version 1.0
  ak pkg maven publish my-maven demo-1.0.jar --group com.acme --artifact demo --version 1.0 \\
    --pom pom.xml --classifier sources
  ak pkg maven publish my-maven pom.xml --path com/acme/demo/1.0/demo-1.0.pom

A snapshot's maven-metadata.xml, or any other single file, goes up with --path."
    )]
    Publish {
        /// Repository key
        repo: String,
        /// The file to upload
        file: PathBuf,
        /// Group ID
        #[arg(long, required_unless_present = "path")]
        group: Option<String>,
        /// Artifact ID
        #[arg(long, required_unless_present = "path")]
        artifact: Option<String>,
        /// Version
        #[arg(
            id = "artifact_version",
            long = "version",
            required_unless_present = "path"
        )]
        version: Option<String>,
        /// Classifier, such as sources or javadoc
        #[arg(long)]
        classifier: Option<String>,
        /// POM to send with it. Default: generate a minimal one, unless the file is a POM
        #[arg(long)]
        pom: Option<PathBuf>,
        /// Send no POM at all
        #[arg(long, conflicts_with = "pom")]
        no_pom: bool,
        /// Send to this exact path in the repository, instead of working it out
        #[arg(long, conflicts_with_all = ["group", "artifact", "artifact_version", "classifier", "pom", "no_pom"])]
        path: Option<String>,
    },
}

pub async fn execute(command: MavenCommand, global: &GlobalArgs) -> Result<()> {
    let MavenCommand::Publish {
        repo,
        file,
        group,
        artifact,
        version,
        classifier,
        pom,
        no_pom,
        path,
    } = command;
    let wire = Wire::new(global)?;
    let upload = Upload::open(&file)?;
    let content = upload.read().await?;

    if let Some(path) = path {
        put_with_checksums(&wire, &repo, &path, &content).await?;
        emit_done(&path, &repo, global);
        return Ok(());
    }
    // clap requires these when there's no --path.
    let (Some(group), Some(artifact), Some(version)) = (group, artifact, version) else {
        return Err(
            AkError::ConfigError("--group, --artifact and --version are required".into()).into(),
        );
    };
    let is_pom = upload.name.ends_with(".pom") || upload.name == "pom.xml";
    let stem = format!(
        "{}/{}/{}/{}-{}",
        group.replace('.', "/"),
        artifact,
        version,
        artifact,
        version
    );
    let ext = extension(&file)?;
    let main_path = match &classifier {
        Some(classifier) => format!("{stem}-{classifier}.{ext}"),
        None if is_pom => format!("{stem}.pom"),
        None => format!("{stem}.{ext}"),
    };
    put_with_checksums(&wire, &repo, &main_path, &content).await?;

    // A classifier's artifact belongs to a POM that's already there.
    if !is_pom && !no_pom && (classifier.is_none() || pom.is_some()) {
        let pom_body = match &pom {
            Some(path) => tokio::fs::read(path)
                .await
                .map_err(|e| AkError::ConfigError(format!("Can't read {}: {e}", path.display())))?,
            None => minimal_pom(&group, &artifact, &version, &ext).into_bytes(),
        };
        put_with_checksums(&wire, &repo, &format!("{stem}.pom"), &pom_body).await?;
    }
    emit_done(&main_path, &repo, global);
    Ok(())
}

/// Nothing a client needs comes back from these PUTs, so say what was stored.
fn emit_done(path: &str, repo: &str, global: &GlobalArgs) {
    let reply = super::wire::Reply::new(serde_json::json!({"path": path, "repository": repo}));
    emit(
        &reply,
        path,
        &format!("Published {path} to {repo}."),
        global,
    );
}

/// A file and its `.md5`, `.sha1`, `.sha256` and `.sha512`, each a separate PUT.
async fn put_with_checksums(wire: &Wire, repo: &str, path: &str, content: &[u8]) -> Result<()> {
    put(wire, repo, path, content.to_vec()).await?;
    for (suffix, digest) in checksums(content) {
        put(wire, repo, &format!("{path}.{suffix}"), digest.into_bytes()).await?;
    }
    Ok(())
}

async fn put(wire: &Wire, repo: &str, path: &str, body: Vec<u8>) -> Result<()> {
    let mut segments = vec!["maven", repo];
    segments.extend(split_path(path, "The path")?);
    wire.send(
        &format!("upload {path}"),
        wire.request(Method::PUT, wire.url(&segments)).body(body),
    )
    .await?;
    Ok(())
}

fn checksums(content: &[u8]) -> [(&'static str, String); 4] {
    [
        // The Maven layout's own file formats, which clients ask for. Not security.
        ("md5", hex::encode(Md5::digest(content))), // NOSONAR
        ("sha1", hex::encode(Sha1::digest(content))), // NOSONAR
        ("sha256", hex::encode(Sha256::digest(content))),
        ("sha512", hex::encode(Sha512::digest(content))),
    ]
}

fn extension(file: &Path) -> Result<String> {
    file.extension()
        .map(|e| e.to_string_lossy().to_string())
        .ok_or_else(|| AkError::ConfigError(format!("{} has no extension", file.display())).into())
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn minimal_pom(group: &str, artifact: &str, version: &str, packaging: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
         \x20 <modelVersion>4.0.0</modelVersion>\n\
         \x20 <groupId>{}</groupId>\n\
         \x20 <artifactId>{}</artifactId>\n\
         \x20 <version>{}</version>\n\
         \x20 <packaging>{}</packaging>\n\
         </project>\n",
        xml_escape(group),
        xml_escape(artifact),
        xml_escape(version),
        xml_escape(packaging)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_are_the_known_values() {
        let found: std::collections::BTreeMap<_, _> = checksums(b"abc").into_iter().collect();
        assert_eq!(found["md5"], "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(found["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            found["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(found["sha512"].starts_with("ddaf35a1"));
    }

    #[test]
    fn the_generated_pom_says_what_it_is() {
        let pom = minimal_pom("com.acme", "demo", "1.0", "jar");
        assert!(pom.contains("<groupId>com.acme</groupId>"));
        assert!(pom.contains("<packaging>jar</packaging>"));
    }
}
