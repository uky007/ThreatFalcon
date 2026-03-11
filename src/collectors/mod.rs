pub mod etw;
pub mod evasion;
pub mod sysmon;
pub mod sysmon_parser;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::events::ThreatEvent;

/// All telemetry collectors implement this trait.
#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &str;
    fn enabled(&self) -> bool;
    async fn start(&mut self, tx: mpsc::Sender<ThreatEvent>) -> Result<()>;
    /// Signal background threads to stop and clean up OS resources.
    async fn stop(&mut self) -> Result<()>;
    /// Number of events dropped inside this collector (e.g. channel backpressure).
    fn dropped_events(&self) -> u64 {
        0
    }
}
