//! `ak pkg helm`: what `helm cm-push` sends. The server reads the chart's name and
//! version from the `Chart.yaml` inside it.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};
use miette::Result;
use reqwest::Method;
use reqwest::multipart::Form;

use super::wire::{Upload, Wire, emit};
use crate::cli::GlobalArgs;

#[derive(Clone, Copy, ValueEnum)]
pub enum Endpoint {
    /// /helm/<repo>/api/charts
    Helm,
    /// /api/helm/<repo>/charts, the same handler, which is what cm-push uses
    ApiHelm,
}

impl Endpoint {
    /// The chart collection's segments.
    fn charts(self, repo: &str) -> Vec<&str> {
        match self {
            Endpoint::Helm => vec!["helm", repo, "api", "charts"],
            Endpoint::ApiHelm => vec!["api", "helm", repo, "charts"],
        }
    }
}

#[derive(Subcommand)]
pub enum HelmCommand {
    /// Upload a packaged chart, as `helm cm-push` does
    #[command(after_help = "\
Examples:
  ak pkg helm publish my-helm demo-1.0.0.tgz
  ak pkg helm publish my-helm demo-1.0.0.tgz --prov demo-1.0.0.tgz.prov")]
    Publish {
        /// Repository key
        repo: String,
        /// The chart .tgz, from `helm package`
        file: PathBuf,
        /// Provenance file to store with it
        #[arg(long)]
        prov: Option<PathBuf>,
        /// Which of the server's two equivalent URLs to send to
        #[arg(long, value_enum, default_value = "helm")]
        endpoint: Endpoint,
    },
    /// Delete a chart version
    Delete {
        /// Repository key
        repo: String,
        /// Chart name
        name: String,
        /// Chart version
        #[arg(id = "chart_version")]
        version: String,
        /// Which of the server's two equivalent URLs to send to
        #[arg(long, value_enum, default_value = "helm")]
        endpoint: Endpoint,
    },
}

pub async fn execute(command: HelmCommand, global: &GlobalArgs) -> Result<()> {
    let wire = Wire::new(global)?;
    match command {
        HelmCommand::Publish {
            repo,
            file,
            prov,
            endpoint,
        } => {
            let upload = Upload::open(&file)?;
            let mut form = Form::new().part("chart", upload.part("application/gzip").await?);
            if let Some(prov) = prov {
                let prov = Upload::open(&prov)?;
                form = form.part("prov", prov.part("application/octet-stream").await?);
            }
            let url = wire.url(&endpoint.charts(&repo));
            let reply = wire
                .send(
                    "upload the chart",
                    wire.request(Method::POST, url).multipart(form),
                )
                .await?;
            emit(
                &reply,
                &upload.name,
                &format!("Published {} to {repo}.", upload.name),
                global,
            );
        }
        HelmCommand::Delete {
            repo,
            name,
            version,
            endpoint,
        } => {
            let mut segments = endpoint.charts(&repo);
            segments.extend([name.as_str(), version.as_str()]);
            let reply = wire
                .send(
                    "delete the chart",
                    wire.request(Method::DELETE, wire.url(&segments)),
                )
                .await?;
            emit(
                &reply,
                &format!("{name}-{version}"),
                &format!("Deleted {name} {version} from {repo}."),
                global,
            );
        }
    }
    Ok(())
}
