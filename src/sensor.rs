use std::time::Instant;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::collectors::etw::EtwCollector;
use crate::collectors::evasion::EvasionCollector;
use crate::collectors::sysmon::SysmonCollector;
use crate::collectors::Collector;
use crate::config::SensorConfig;
use crate::events::*;
use crate::output::EventWriter;

const EVENT_CHANNEL_SIZE: usize = 10_000;

pub struct Sensor {
    config: SensorConfig,
    collectors: Vec<Box<dyn Collector>>,
}

/// Tracks per-collector state for health reporting.
struct CollectorEntry {
    name: String,
    state: CollectorState,
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
        let start_time = Instant::now();

        // Start all enabled collectors, tracking their state
        let mut collector_states: Vec<CollectorEntry> = Vec::new();
        for collector in &mut self.collectors {
            let name = collector.name().to_string();
            if !collector.enabled() {
                info!(collector = %name, "Collector disabled, skipping");
                collector_states.push(CollectorEntry {
                    name,
                    state: CollectorState::Disabled,
                });
                continue;
            }
            match collector.start(tx.clone()).await {
                Ok(()) => {
                    collector_states.push(CollectorEntry {
                        name,
                        state: CollectorState::Running,
                    });
                }
                Err(e) => {
                    error!(collector = %name, error = %e, "Failed to start collector");
                    collector_states.push(CollectorEntry {
                        name,
                        state: CollectorState::Error,
                    });
                }
            }
        }

        // Drop our copy so rx closes when all collectors finish
        drop(tx);

        let active = collector_states
            .iter()
            .filter(|c| c.state == CollectorState::Running)
            .count();
        info!(active_collectors = active, "Sensor running");

        let mut writer = EventWriter::new(&self.config.output)?;
        let mut event_count = 0u64;
        let mut drop_count = 0u64;

        // Health tick — interval of 0 means disabled
        let health_interval = self.config.health_interval_secs;
        let mut health_tick = if health_interval > 0 {
            tokio::time::interval(std::time::Duration::from_secs(health_interval))
        } else {
            // Create a long interval that effectively never fires.
            // We skip the first tick below regardless.
            tokio::time::interval(std::time::Duration::from_secs(u64::MAX))
        };
        // Skip the immediate first tick
        health_tick.tick().await;

        // Main event loop with graceful shutdown
        loop {
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Some(evt) => {
                            if let Err(e) = writer.write_event(&evt) {
                                error!(error = %e, "Failed to write event");
                                drop_count += 1;
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
                _ = health_tick.tick() => {
                    let health = self.build_health_event(
                        &collector_states,
                        &start_time,
                        event_count,
                        drop_count,
                    );
                    if let Err(e) = writer.write_event(&health) {
                        error!(error = %e, "Failed to write health event");
                    }
                    info!(
                        uptime_secs = start_time.elapsed().as_secs(),
                        events_total = event_count,
                        events_dropped = drop_count,
                        "Health check"
                    );
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }

        // Stop all collectors
        for (i, collector) in self.collectors.iter_mut().enumerate() {
            if let Err(e) = collector.stop().await {
                error!(collector = collector.name(), error = %e, "Error stopping collector");
                if let Some(entry) = collector_states.get_mut(i) {
                    entry.state = CollectorState::Error;
                }
            } else if let Some(entry) = collector_states.get_mut(i) {
                if entry.state == CollectorState::Running {
                    entry.state = CollectorState::Stopped;
                }
            }
        }

        // Final health event
        let final_health = self.build_health_event(
            &collector_states,
            &start_time,
            event_count,
            drop_count,
        );
        if let Err(e) = writer.write_event(&final_health) {
            error!(error = %e, "Failed to write final health event");
        }

        info!(total_events = event_count, "Sensor stopped");
        Ok(())
    }

    fn build_health_event(
        &self,
        collector_states: &[CollectorEntry],
        start_time: &Instant,
        events_total: u64,
        events_dropped: u64,
    ) -> ThreatEvent {
        let collectors = collector_states
            .iter()
            .map(|c| CollectorStatus {
                name: c.name.clone(),
                state: c.state,
            })
            .collect();

        ThreatEvent::new(
            &self.config.hostname,
            EventSource::Sensor,
            EventCategory::Health,
            Severity::Info,
            EventData::SensorHealth {
                uptime_secs: start_time.elapsed().as_secs(),
                events_total,
                events_dropped,
                collectors,
            },
        )
    }
}
