pub mod etw;
pub mod evasion;
// Used by the Windows ETW collector only (tested on every platform).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub mod kernel_io;
// Used by the Windows ETW collector only (tested on every platform).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub mod script_rules;
pub mod sysmon;
pub mod sysmon_parser;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::events::{EtwSessionStats, ThreatEvent};

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
    /// ETW session counters, for collectors that run an ETW session.
    fn etw_session(&self) -> Option<EtwSessionStats> {
        None
    }
}
