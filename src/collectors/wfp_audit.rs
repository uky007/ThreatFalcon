//! Opt-in Windows Security log reader for WFP authorization audit records.
use super::{health::RuntimeHealth, Collector};
use crate::{
    config::WfpAuditConfig,
    events::{AgentInfo, CollectorStatus, ThreatEvent},
};
use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

#[cfg(target_os = "windows")]
mod native;
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) mod parser;

pub struct WfpAuditCollector {
    config: WfpAuditConfig,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    agent: AgentInfo,
    health: RuntimeHealth,
    drops: std::sync::Arc<std::sync::atomic::AtomicU64>,
    #[cfg(target_os = "windows")]
    worker: Option<super::health::Worker>,
}

impl WfpAuditCollector {
    pub fn new(config: WfpAuditConfig, agent: AgentInfo) -> Self {
        Self {
            config,
            agent,
            health: RuntimeHealth::new("WfpAudit"),
            drops: Default::default(),
            #[cfg(target_os = "windows")]
            worker: None,
        }
    }
}

#[async_trait]
impl Collector for WfpAuditCollector {
    fn name(&self) -> &str {
        "WfpAudit"
    }
    fn enabled(&self) -> bool {
        self.config.enabled
    }
    fn supported(&self) -> bool {
        cfg!(target_os = "windows")
    }
    fn status(&self) -> Option<CollectorStatus> {
        #[cfg(target_os = "windows")]
        if let Some(worker) = &self.worker {
            worker.check();
        }
        Some(self.health.snapshot(self.dropped_events()))
    }
    fn dropped_events(&self) -> u64 {
        self.drops.load(std::sync::atomic::Ordering::Relaxed)
    }
    async fn start(&mut self, tx: mpsc::Sender<ThreatEvent>) -> Result<()> {
        #[cfg(not(target_os = "windows"))]
        {
            let _ = tx;
            anyhow::bail!("WFP audit requires Windows / WFP監査にはWindowsが必要です");
        }
        #[cfg(target_os = "windows")]
        {
            anyhow::ensure!(self.worker.is_none(), "WFP audit already started");
            self.health.starting();
            self.health.recovery_mode("future_only");
            self.health.wfp_audit(Default::default());
            self.drops.store(0, std::sync::atomic::Ordering::Relaxed);
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let (agent, drops) = (self.agent.clone(), self.drops.clone());
            self.worker = Some(super::health::Worker::spawn(
                self.health.clone(),
                move |stop, health| {
                    native::run(agent, tx, drops, stop, health, ready_tx);
                },
            ));
            match tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx).await {
                Ok(Ok(Ok(()))) => Ok(()),
                result => {
                    if !matches!(result, Ok(Ok(Err(())))) {
                        self.health.fail("wfp_start_timeout", None);
                    }
                    if let Some(mut worker) = self.worker.take() {
                        let _ = worker.stop().await;
                    }
                    anyhow::bail!("WFP audit startup failed; inspect health / WFP監査起動失敗：ヘルスを確認してください")
                }
            }
        }
    }
    async fn stop(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        if let Some(mut worker) = self.worker.take() {
            worker.stop().await?;
        }
        Ok(())
    }
}

/// Bound this noisy feed's admission into the shared queue; never block OS reads.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn enqueue(
    tx: &mpsc::Sender<ThreatEvent>,
    event: ThreatEvent,
    drops: &std::sync::atomic::AtomicU64,
) -> Result<(), ()> {
    let closed = tx.is_closed();
    let saturated = tx.max_capacity().saturating_sub(tx.capacity()) >= 512;
    if closed || saturated {
        increment_drop(drops);
        return if closed { Err(()) } else { Ok(()) };
    }
    match tx.try_send(event) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            increment_drop(drops);
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            increment_drop(drops);
            Err(())
        }
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn increment_drop(drops: &std::sync::atomic::AtomicU64) {
    use std::sync::atomic::Ordering;
    let _ = drops.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_add(1))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_opt_in() {
        let c = WfpAuditCollector::new(
            WfpAuditConfig::default(),
            AgentInfo {
                hostname: "test".into(),
                agent_id: uuid::Uuid::new_v4(),
            },
        );
        assert!(!c.enabled());
        assert_eq!(c.supported(), cfg!(target_os = "windows"));
    }
    #[test]
    fn bounded_admission_and_closed_queue_are_counted_without_overflow() {
        use crate::events::{EventCategory, EventData, EventSource, Severity};
        use std::sync::atomic::{AtomicU64, Ordering};
        let event = ThreatEvent::new(
            &AgentInfo {
                hostname: "test".into(),
                agent_id: uuid::Uuid::new_v4(),
            },
            EventSource::Sensor,
            EventCategory::Telemetry,
            Severity::Info,
            EventData::NativeTelemetry {
                pid: None,
                reason: "synthetic".into(),
                payload_hex: None,
            },
        );
        let drops = AtomicU64::new(0);
        let (tx, rx) = mpsc::channel(1024);
        for _ in 0..513 {
            enqueue(&tx, event.clone(), &drops).unwrap();
        }
        assert_eq!(tx.capacity(), 512);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        drop(rx);
        assert!(enqueue(&tx, event.clone(), &drops).is_err());
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        let (tx, _rx) = mpsc::channel(1);
        enqueue(&tx, event.clone(), &drops).unwrap();
        enqueue(&tx, event.clone(), &drops).unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), 3);
        drops.store(u64::MAX, Ordering::Relaxed);
        enqueue(&tx, event, &drops).unwrap();
        assert_eq!(drops.load(Ordering::Relaxed), u64::MAX);
    }
}
