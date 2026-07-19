//! Rust SDK for the Artifact Keeper REST API.
//!
//! The items re-exported below form the crate's intentional public API.
//! The `generated_sdk` module is produced by `cargo xtask generate` and is
//! deliberately private: only the names listed here are exposed, so an SDK
//! regeneration cannot silently change the public surface. When regeneration
//! adds a new operation tag (a new `Client*Ext` trait) or top-level item,
//! add it to the explicit re-export list below.

/// Re-export progenitor_client for consumers.
pub use progenitor_client;
pub use reqwest;

#[allow(clippy::all, unused, dead_code, unreachable_code)]
mod generated_sdk;

// Core client and progenitor runtime types used in operation signatures.
pub use generated_sdk::{ByteStream, Client, ClientInfo, Error, ResponseValue};

// Namespaced modules: request/response types, operation builders, and the
// convenience prelude (Client + all extension traits).
pub use generated_sdk::{builder, prelude, types};

// Per-tag operation extension traits.
pub use generated_sdk::{
    ClientAdminExt, ClientAgeGateExt, ClientAnalyticsExt, ClientApprovalExt,
    ClientArtifactLabelsExt, ClientArtifactsExt, ClientAuthExt, ClientBuildsExt, ClientCurationExt,
    ClientEmailSubscriptionsExt, ClientGroupsExt, ClientHealthExt, ClientLifecycleExt,
    ClientMigrationExt, ClientMonitoringExt, ClientPackagesExt, ClientPeerInstanceLabelsExt,
    ClientPeersExt, ClientPermissionsExt, ClientPluginsExt, ClientProjectsExt, ClientPromotionExt,
    ClientQualityExt, ClientQuarantineExt, ClientRepositoriesExt, ClientRepositoryLabelsExt,
    ClientRepositoryTokensExt, ClientSbomExt, ClientSearchExt, ClientSecurityExt,
    ClientServiceAccountsExt, ClientSigningExt, ClientSsoExt, ClientSystemExt, ClientTelemetryExt,
    ClientUploadsExt, ClientUsersExt, ClientWebhooksExt,
};
