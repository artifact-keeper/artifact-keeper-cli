//! `ak pkg`: what each package manager sends, for when the package manager isn't there.
//!
//! A format's wire protocol is a body someone has to build by hand with curl: a framed
//! `.crate`, an npm document with the tarball in base64, a multipart form with the right
//! field names. These helpers build that, one file per format. A plain GET of a format
//! route adds nothing over `ak api GET`, so those have no helper.

mod alpine;
mod archive;
mod bazel;
mod cargo;
mod composer;
mod conda;
mod cran;
mod debian;
mod gems;
mod go;
mod helm;
mod hex;
mod incus;
mod ivy;
mod maven;
mod npm;
mod nuget;
mod pacman;
mod pub_dart;
mod pypi;
mod rpm;
mod terraform;
mod wire;

use clap::{Args, Subcommand};
use miette::Result;

use crate::cli::GlobalArgs;

#[derive(Args)]
#[command(after_help = "\
Each publish reads the file and sends what the format's own client sends. Anything a
helper doesn't cover can be sent with `ak api`.

Examples:
  ak pkg npm publish my-npm demo-1.0.0.tgz
  ak pkg cargo publish my-cargo target/package/demo-1.0.0.crate
  ak pkg pypi publish my-pypi dist/demo-1.0-py3-none-any.whl")]
pub struct PkgArgs {
    #[command(subcommand)]
    format: PkgCommand,
}

#[derive(Subcommand)]
enum PkgCommand {
    /// Bazel modules
    #[command(subcommand)]
    Bazel(bazel::BazelCommand),
    /// Composer packages
    #[command(subcommand)]
    Composer(composer::ComposerCommand),
    /// R packages
    #[command(subcommand)]
    Cran(cran::CranCommand),
    /// RubyGems
    #[command(subcommand)]
    Gems(gems::GemsCommand),
    /// Go modules
    #[command(subcommand)]
    Go(go::GoCommand),
    /// Hex packages
    #[command(subcommand)]
    Hex(hex::HexCommand),
    /// Ivy and sbt artifacts
    #[command(subcommand)]
    Ivy(ivy::IvyCommand),
    /// Maven artifacts
    #[command(subcommand)]
    Maven(maven::MavenCommand),
    /// Dart and Flutter packages
    #[command(subcommand)]
    Pub(pub_dart::PubCommand),
    /// Terraform modules and providers
    #[command(subcommand)]
    Terraform(terraform::TerraformCommand),
    /// Alpine packages
    #[command(subcommand)]
    Alpine(alpine::AlpineCommand),
    /// Rust crates
    #[command(subcommand)]
    Cargo(cargo::CargoCommand),
    /// conda packages
    #[command(subcommand)]
    Conda(conda::CondaCommand),
    /// Debian packages
    #[command(subcommand)]
    Debian(debian::DebianCommand),
    /// Helm charts
    #[command(subcommand)]
    Helm(helm::HelmCommand),
    /// Incus images
    #[command(subcommand)]
    Incus(incus::IncusCommand),
    /// LXC images: the same as `incus`, under /lxc
    #[command(subcommand)]
    Lxc(incus::IncusCommand),
    /// npm packages
    #[command(subcommand)]
    Npm(npm::NpmCommand),
    /// NuGet packages
    #[command(subcommand)]
    Nuget(nuget::NugetCommand),
    /// Arch Linux packages
    #[command(subcommand)]
    Pacman(pacman::PacmanCommand),
    /// Python packages
    #[command(subcommand)]
    Pypi(pypi::PypiCommand),
    /// RPM packages
    #[command(subcommand)]
    Rpm(rpm::RpmCommand),
}

pub async fn execute(args: PkgArgs, global: &GlobalArgs) -> Result<()> {
    match args.format {
        PkgCommand::Bazel(c) => bazel::execute(c, global).await,
        PkgCommand::Composer(c) => composer::execute(c, global).await,
        PkgCommand::Cran(c) => cran::execute(c, global).await,
        PkgCommand::Gems(c) => gems::execute(c, global).await,
        PkgCommand::Go(c) => go::execute(c, global).await,
        PkgCommand::Hex(c) => hex::execute(c, global).await,
        PkgCommand::Ivy(c) => ivy::execute(c, global).await,
        PkgCommand::Maven(c) => maven::execute(c, global).await,
        PkgCommand::Pub(c) => pub_dart::execute(c, global).await,
        PkgCommand::Terraform(c) => terraform::execute(c, global).await,
        PkgCommand::Alpine(c) => alpine::execute(c, global).await,
        PkgCommand::Cargo(c) => cargo::execute(c, global).await,
        PkgCommand::Conda(c) => conda::execute(c, global).await,
        PkgCommand::Debian(c) => debian::execute(c, global).await,
        PkgCommand::Helm(c) => helm::execute(c, global).await,
        PkgCommand::Incus(c) => incus::execute("incus", c, global).await,
        PkgCommand::Lxc(c) => incus::execute("lxc", c, global).await,
        PkgCommand::Npm(c) => npm::execute(c, global).await,
        PkgCommand::Nuget(c) => nuget::execute(c, global).await,
        PkgCommand::Pacman(c) => pacman::execute(c, global).await,
        PkgCommand::Pypi(c) => pypi::execute(c, global).await,
        PkgCommand::Rpm(c) => rpm::execute(c, global).await,
    }
}
