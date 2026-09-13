//! Native Endpoint Security NOTIFY collector. No eslogger dependency or fallback
//! to polling; permission failures are explicit, never reported as collection.
use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

use super::{health::RuntimeHealth, Collector};
use crate::{
    config::MacosConfig,
    events::{AgentInfo, CollectorStatus, ThreatEvent},
};

#[cfg(target_os = "macos")]
mod native;

pub struct MacosCollector {
    config: MacosConfig,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    agent: AgentInfo,
    health: RuntimeHealth,
    #[cfg(target_os = "macos")]
    worker: Option<super::health::Worker>,
    drops: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl MacosCollector {
    pub fn new(config: MacosConfig, agent: AgentInfo) -> Self {
        Self {
            config,
            agent,
            health: RuntimeHealth::new("EndpointSecurity"),
            #[cfg(target_os = "macos")]
            worker: None,
            drops: Default::default(),
        }
    }
}

#[async_trait]
impl Collector for MacosCollector {
    fn name(&self) -> &str {
        "EndpointSecurity"
    }
    fn enabled(&self) -> bool {
        self.config.enabled
    }
    fn supported(&self) -> bool {
        cfg!(target_os = "macos")
    }
    fn status(&self) -> Option<CollectorStatus> {
        #[cfg(target_os = "macos")]
        if let Some(worker) = &self.worker {
            worker.check();
        }
        Some(self.health.snapshot(self.dropped_events()))
    }
    fn dropped_events(&self) -> u64 {
        self.drops.load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn start(&mut self, tx: mpsc::Sender<ThreatEvent>) -> Result<()> {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = tx;
            anyhow::bail!("Endpoint Security requires macOS");
        }
        #[cfg(target_os = "macos")]
        {
            anyhow::ensure!(
                self.worker.is_none(),
                "Endpoint Security collector already started"
            );
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
            match tokio::time::timeout(std::time::Duration::from_secs(10), ready_rx).await {
                Ok(Ok(Ok(()))) => Ok(()),
                result => {
                    if !matches!(result, Ok(Ok(Err(_)))) {
                        self.health.fail("es_start_timeout", None);
                    }
                    // Failed startup is never left with a background subscription.
                    if let Some(mut worker) = self.worker.take() {
                        let _ = worker.stop().await;
                    }
                    anyhow::bail!("Endpoint Security startup failed; inspect health error code / Endpoint Security起動失敗：ヘルスのエラーコードを確認してください")
                }
            }
        }
    }

    async fn stop(&mut self) -> Result<()> {
        #[cfg(target_os = "macos")]
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
    fn collector_is_opt_in_and_reports_platform_support() {
        let collector = MacosCollector::new(
            MacosConfig::default(),
            AgentInfo {
                hostname: "test".into(),
                agent_id: uuid::Uuid::new_v4(),
            },
        );
        assert!(!collector.enabled());
        assert_eq!(collector.supported(), cfg!(target_os = "macos"));
    }
}
