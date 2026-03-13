use std::time::Instant;

use anyhow::Result;
use tokio::sync::{mpsc, watch};
use tracing::{error, info};

use crate::collectors::etw::EtwCollector;
use crate::collectors::evasion::EvasionCollector;
use crate::collectors::sysmon::SysmonCollector;
use crate::collectors::Collector;
use crate::config::SensorConfig;
use crate::events::*;
use crate::output;
use crate::process_cache::ProcessCache;
use crate::state;

const EVENT_CHANNEL_SIZE: usize = 10_000;
const PROCESS_CACHE_CAPACITY: usize = 10_000;

pub struct Sensor {
    config: SensorConfig,
    agent: AgentInfo,
    collectors: Vec<Box<dyn Collector>>,
}

/// Tracks per-collector state for health reporting.
struct CollectorEntry {
    name: String,
    state: CollectorState,
}

impl Sensor {
    pub fn new(config: SensorConfig) -> Result<Self> {
        let agent_id = state::load_or_create_agent_id(&config.state_path)?;
        let agent = AgentInfo {
            hostname: config.hostname.clone(),
            agent_id,
        };

        let collectors: Vec<Box<dyn Collector>> = vec![
            Box::new(EtwCollector::new(
                config.collectors.etw.clone(),
                agent.clone(),
            )),
            Box::new(SysmonCollector::new(
                config.collectors.sysmon.clone(),
                agent.clone(),
            )),
            Box::new(EvasionCollector::new(
                config.collectors.evasion.clone(),
                agent.clone(),
            )),
        ];

        info!(agent_id = %agent.agent_id, "Agent identity loaded");

        Ok(Self {
            config,
            agent,
            collectors,
        })
    }

    pub async fn run(&mut self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
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

        let mut writer = output::create_sink(&self.config.output)?;
        let mut process_cache = ProcessCache::new(PROCESS_CACHE_CAPACITY);
        let mut event_count = 0u64;

        // Health tick — interval of 0 disables periodic health events
        // (a final shutdown health event is always emitted regardless)
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
                        Some(mut evt) => {
                            process_cache.enrich(&mut evt);
                            if let Err(e) = writer.send(&evt).await {
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
                _ = health_tick.tick() => {
                    let total_dropped = writer.dropped_events() + self.collector_drops();
                    let sink_status = SinkStatus {
                        sink_type: writer.name().to_string(),
                        events_dropped: writer.dropped_events(),
                        spool_files: writer.spool_files(),
                        spool_bytes: writer.spool_bytes(),
                    };
                    let health = self.build_health_event(
                        &collector_states,
                        &start_time,
                        event_count,
                        total_dropped,
                        Some(sink_status),
                    );
                    if let Err(e) = writer.send(&health).await {
                        error!(error = %e, "Failed to write health event");
                    }
                    // Flush immediately so health events are delivered on
                    // schedule, even when the HTTP sink batch is not full.
                    if let Err(e) = writer.flush().await {
                        error!(error = %e, "Failed to flush health event");
                    }
                    info!(
                        uptime_secs = start_time.elapsed().as_secs(),
                        events_total = event_count,
                        events_dropped = total_dropped,
                        "Health check"
                    );
                }
                result = shutdown_rx.changed() => {
                    // Only shut down on an explicit true signal, not on
                    // channel close (sender dropped). This ensures a
                    // future service caller that accidentally drops the
                    // sender does not silently terminate the sensor.
                    if result.is_ok() && *shutdown_rx.borrow() {
                        info!("Shutdown signal received");
                        break;
                    }
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

        // Flush buffered events before final health so drop counts are accurate
        if let Err(e) = writer.flush().await {
            error!(error = %e, "Failed to flush sink on shutdown");
        }

        // Final health event (includes any drops from flush above)
        let total_dropped = writer.dropped_events() + self.collector_drops();
        let sink_status = SinkStatus {
            sink_type: writer.name().to_string(),
            events_dropped: writer.dropped_events(),
            spool_files: writer.spool_files(),
            spool_bytes: writer.spool_bytes(),
        };
        let final_health = self.build_health_event(
            &collector_states,
            &start_time,
            event_count,
            total_dropped,
            Some(sink_status),
        );
        if let Err(e) = writer.send(&final_health).await {
            error!(error = %e, "Failed to write final health event");
        }

        // Flush the final health event itself
        if let Err(e) = writer.flush().await {
            error!(error = %e, "Failed to flush final health event");
        }

        info!(total_events = event_count, "Sensor stopped");
        Ok(())
    }

    /// Sum of events dropped across all collectors (channel backpressure).
    fn collector_drops(&self) -> u64 {
        self.collectors.iter().map(|c| c.dropped_events()).sum()
    }

    fn build_health_event(
        &self,
        collector_states: &[CollectorEntry],
        start_time: &Instant,
        events_total: u64,
        events_dropped: u64,
        sink_info: Option<SinkStatus>,
    ) -> ThreatEvent {
        let collectors = collector_states
            .iter()
            .map(|c| CollectorStatus {
                name: c.name.clone(),
                state: c.state,
            })
            .collect();

        ThreatEvent::new(
            &self.agent,
            EventSource::Sensor,
            EventCategory::Health,
            Severity::Info,
            EventData::SensorHealth {
                uptime_secs: start_time.elapsed().as_secs(),
                events_total,
                events_dropped,
                collectors,
                sink: sink_info,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use tempfile::TempDir;

    /// Create a shutdown channel for tests. Returns both halves so the
    /// sender stays alive — the sensor shuts down via the collector
    /// channel closing (rx.recv() → None), not via a dropped sender.
    fn test_shutdown() -> (watch::Sender<bool>, watch::Receiver<bool>) {
        watch::channel(false)
    }

    fn test_config(dir: &TempDir) -> SensorConfig {
        SensorConfig {
            hostname: "TEST-HOST".into(),
            output: OutputConfig {
                path: dir.path().join("test_events.jsonl"),
                rotation_size_mb: 100,
                ..OutputConfig::default()
            },
            collectors: CollectorConfig::default(),
            health_interval_secs: 60,
            state_path: dir.path().join("test.state"),
        }
    }

    /// On non-Windows, all collectors are no-ops so the sensor starts,
    /// finds no event producers, and shuts down immediately — writing
    /// only the final health event.
    #[tokio::test]
    async fn sensor_writes_final_health_event() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let output_path = config.output.path.clone();

        let mut sensor = Sensor::new(config).unwrap();
        let (_shutdown_tx, shutdown_rx) = test_shutdown();
        sensor.run(shutdown_rx).await.unwrap();

        let content = std::fs::read_to_string(&output_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        // At least one event (the final health event)
        assert!(!lines.is_empty(), "expected at least one event in output");

        let last: ThreatEvent = serde_json::from_str(lines.last().unwrap()).unwrap();
        assert_eq!(last.hostname, "TEST-HOST");
        match &last.data {
            EventData::SensorHealth {
                events_total,
                events_dropped,
                collectors,
                ..
            } => {
                assert_eq!(*events_total, 0);
                assert_eq!(*events_dropped, 0);
                // All 3 collectors should be present
                assert_eq!(collectors.len(), 3);
            }
            _ => panic!("expected SensorHealth event"),
        }
    }

    #[tokio::test]
    async fn sensor_tracks_collector_states() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let output_path = config.output.path.clone();

        let mut sensor = Sensor::new(config).unwrap();
        let (_shutdown_tx, shutdown_rx) = test_shutdown();
        sensor.run(shutdown_rx).await.unwrap();

        let content = std::fs::read_to_string(&output_path).unwrap();
        let last_line = content.lines().last().unwrap();
        let event: ThreatEvent = serde_json::from_str(last_line).unwrap();

        match &event.data {
            EventData::SensorHealth { collectors, .. } => {
                let names: Vec<&str> = collectors.iter().map(|c| c.name.as_str()).collect();
                assert!(names.contains(&"ETW"));
                assert!(names.contains(&"Sysmon"));
                assert!(names.contains(&"EvasionDetector"));

                // On non-Windows, all collectors succeed start() but produce
                // no events. Sysmon is disabled by default.
                let sysmon = collectors.iter().find(|c| c.name == "Sysmon").unwrap();
                assert_eq!(sysmon.state, CollectorState::Disabled);
            }
            _ => panic!("expected SensorHealth"),
        }
    }

    #[tokio::test]
    async fn sensor_disabled_collectors() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        // Disable all collectors
        config.collectors.etw.enabled = false;
        config.collectors.sysmon.enabled = false;
        config.collectors.evasion.enabled = false;
        let output_path = config.output.path.clone();

        let mut sensor = Sensor::new(config).unwrap();
        let (_shutdown_tx, shutdown_rx) = test_shutdown();
        sensor.run(shutdown_rx).await.unwrap();

        let content = std::fs::read_to_string(&output_path).unwrap();
        let last_line = content.lines().last().unwrap();
        let event: ThreatEvent = serde_json::from_str(last_line).unwrap();

        match &event.data {
            EventData::SensorHealth { collectors, .. } => {
                // All should be Disabled
                for c in collectors {
                    assert_eq!(
                        c.state,
                        CollectorState::Disabled,
                        "collector {} should be Disabled",
                        c.name
                    );
                }
            }
            _ => panic!("expected SensorHealth"),
        }
    }

    #[tokio::test]
    async fn sensor_health_disabled_still_emits_final() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.health_interval_secs = 0; // disable periodic
        let output_path = config.output.path.clone();

        let mut sensor = Sensor::new(config).unwrap();
        let (_shutdown_tx, shutdown_rx) = test_shutdown();
        sensor.run(shutdown_rx).await.unwrap();

        let content = std::fs::read_to_string(&output_path).unwrap();
        // Final health event should still be emitted
        assert!(
            content.contains("\"SensorHealth\""),
            "final health event should be emitted even with periodic disabled"
        );
    }
}
