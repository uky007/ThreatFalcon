//! Linux Audit read-only multicast, coexisting with the system audit daemon.
use super::{health::RuntimeHealth, Collector};
use crate::{
    config::LinuxAuditConfig,
    events::{AgentInfo, CollectorStatus, ThreatEvent},
};
use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod assembler;
#[cfg(target_os = "linux")]
mod native;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod parser;

pub struct LinuxAuditCollector {
    config: LinuxAuditConfig,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    agent: AgentInfo,
    health: RuntimeHealth,
    drops: std::sync::Arc<std::sync::atomic::AtomicU64>,
    #[cfg(target_os = "linux")]
    worker: Option<super::health::Worker>,
}
impl LinuxAuditCollector {
    pub fn new(config: LinuxAuditConfig, agent: AgentInfo) -> Self {
        Self {
            config,
            agent,
            health: RuntimeHealth::new("LinuxAudit"),
            drops: Default::default(),
            #[cfg(target_os = "linux")]
            worker: None,
        }
    }
}
#[async_trait]
impl Collector for LinuxAuditCollector {
    fn name(&self) -> &str {
        "LinuxAudit"
    }
    fn enabled(&self) -> bool {
        self.config.enabled
    }
    fn supported(&self) -> bool {
        cfg!(target_os = "linux")
    }
    fn status(&self) -> Option<CollectorStatus> {
        #[cfg(target_os = "linux")]
        if let Some(worker) = &self.worker {
            worker.check();
        }
        Some(self.health.snapshot(self.dropped_events()))
    }
    fn dropped_events(&self) -> u64 {
        self.drops.load(std::sync::atomic::Ordering::Relaxed)
    }
    async fn start(&mut self, tx: mpsc::Sender<ThreatEvent>) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = tx;
            anyhow::bail!("Linux Audit requires Linux");
        }
        #[cfg(target_os = "linux")]
        {
            anyhow::ensure!(self.worker.is_none(), "Linux Audit already started");
            self.health.starting();
            self.health.recovery_mode("future_only");
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
                    if !matches!(result, Ok(Ok(Err(_)))) {
                        self.health.fail("audit_start_timeout", None);
                    }
                    if let Some(mut worker) = self.worker.take() {
                        let _ = worker.stop().await;
                    }
                    anyhow::bail!("Linux Audit startup failed; inspect health / Linux Audit起動失敗：ヘルスを確認してください")
                }
            }
        }
    }
    async fn stop(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(mut worker) = self.worker.take() {
            worker.stop().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn collector_is_explicit_opt_in() {
        let c = LinuxAuditCollector::new(
            LinuxAuditConfig::default(),
            AgentInfo {
                hostname: "test".into(),
                agent_id: uuid::Uuid::new_v4(),
            },
        );
        assert!(!c.enabled());
        assert_eq!(c.supported(), cfg!(target_os = "linux"));
    }
}
