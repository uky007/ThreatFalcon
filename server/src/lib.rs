//! ThreatFalcon management server.
//!
//! Receives batched telemetry from ThreatFalcon sensors (the sensor's
//! `[output] type = "http"` sink), authenticates each agent with its own
//! bearer token, and stores the events as per-agent JSONL files that use
//! the same layout and rotation scheme as the sensor's file sink. The
//! existing investigation CLI (`threatfalcon query`, `hunt`, `alert`, ...)
//! therefore works unchanged on the stored data.

pub mod app;
pub mod auth;
pub mod config;
pub mod export;
pub mod ingest;
pub mod status;
pub mod store;
pub mod tokens;

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Source revision the binary was built from. CI sets
/// `THREATFALCON_SERVER_REVISION` to the commit SHA; the deploy script uses
/// it to confirm that the new build is the one actually serving traffic.
pub const REVISION: &str = match option_env!("THREATFALCON_SERVER_REVISION") {
    Some(rev) => rev,
    None => "unknown",
};
