use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::collectors::etw::EtwCollector;
use crate::collectors::evasion::EvasionCollector;
use crate::collectors::sysmon::SysmonCollector;
use crate::collectors::Collector;
use crate::config::SensorConfig;
use crate::output::EventWriter;

const EVENT_CHANNEL_SIZE: usize = 10_000;

pub struct Sensor {
    config: SensorConfig,
    collectors: Vec<Box<dyn Collector>>,
}

impl Sensor {
    pub fn new(config: SensorConfig) -> Result<Self> {
        let hostname = config.hostname.clone();

        let collectors: Vec<Box<dyn Collector>> = vec![
            Box::new(EtwCollector::new(
                config.collectors.etw.clone(),
                hostname.clone(),
            )),
            Box::new(SysmonCollector::new(
                config.collectors.sysmon.clone(),
                hostname.clone(),
            )),
            Box::new(EvasionCollector::new(
                config.collectors.evasion.clone(),
                hostname,
            )),
        ];

        Ok(Self {
            config,
            collectors,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(EVENT_CHANNEL_SIZE);

        // Start all enabled collectors
        let mut active = 0usize;
        for collector in &mut self.collectors {
            if !collector.enabled() {
                info!(collector = collector.name(), "Collector disabled, skipping");
                continue;
            }
            match collector.start(tx.clone()).await {
                Ok(()) => {
                    active += 1;
                }
                Err(e) => {
                    error!(
                        collector = collector.name(),
                        error = %e,
                        "Failed to start collector"
                    );
                }
            }
        }

        // Drop our copy so rx closes when all collectors finish
        drop(tx);

        info!(active_collectors = active, "Sensor running");

        let mut writer = EventWriter::new(&self.config.output)?;
        let mut event_count = 0u64;

        // Main event loop with graceful shutdown
        loop {
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Some(evt) => {
                            if let Err(e) = writer.write_event(&evt) {
                                error!(error = %e, "Failed to write event");
                            }
                            event_count += 1;
                            if event_count % 1000 == 0 {
                                info!(events = event_count, "Events processed");
                            }
                        }
                        None => {
                            info!("All collectors finished");
                            break;
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }

        // Stop all collectors
        for collector in &mut self.collectors {
            if let Err(e) = collector.stop().await {
                error!(collector = collector.name(), error = %e, "Error stopping collector");
            }
        }

        info!(total_events = event_count, "Sensor stopped");
        Ok(())
    }
}
