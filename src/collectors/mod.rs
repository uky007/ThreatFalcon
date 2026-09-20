pub mod etw;
pub mod etw_metadata;
pub mod etw_normalize;
#[cfg(target_os = "windows")]
mod tdh;
pub mod evasion;
pub mod health;
pub mod macos;
pub mod linux_audit;
pub mod sysmon;
pub mod sysmon_parser;
pub mod wfp_audit;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::events::{CollectorStatus, ThreatEvent};

/// All telemetry collectors implement this trait.
#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &str;
    fn enabled(&self) -> bool;
    fn supported(&self) -> bool {
        true
    }
    /// A live snapshot, including worker failures and collection quality.
    fn status(&self) -> Option<CollectorStatus> {
        None
    }
    async fn start(&mut self, tx: mpsc::Sender<ThreatEvent>) -> Result<()>;
    /// Signal background threads to stop and clean up OS resources.
    async fn stop(&mut self) -> Result<()>;
    /// Number of events dropped inside this collector (e.g. channel backpressure).
    fn dropped_events(&self) -> u64 {
        0
    }
}
