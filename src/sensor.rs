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
        config.validate()?;
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
            Box::new(crate::collectors::macos::MacosCollector::new(
                config.collectors.macos.clone(),
                agent.clone(),
            )),
            Box::new(crate::collectors::linux_audit::LinuxAuditCollector::new(
                config.collectors.linux_audit.clone(),
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

    pub async fn run(&mut self, shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        // Validate/open the destination before starting any privileged collector.
        let writer = output::create_sink(&self.config.output)?;
        self.run_with_sink(shutdown_rx, writer).await
    }

    async fn run_with_sink(
        &mut self,
        mut shutdown_rx: watch::Receiver<bool>,
        mut writer: Box<dyn output::Sink>,
    ) -> Result<()> {
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
            if !collector.supported() {
                collector_states.push(CollectorEntry {
                    name,
                    state: CollectorState::Unsupported,
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

        let mut process_cache = ProcessCache::new(PROCESS_CACHE_CAPACITY);
        let mut event_count = 0u64;
        let startup = self.build_health_event(
            &collector_states,
            &start_time,
            0,
            writer.dropped_events(),
            Some(SinkStatus {
                sink_type: writer.name().into(),
                events_dropped: writer.dropped_events(),
                spool_files: writer.spool_files(),
                spool_bytes: writer.spool_bytes(),
            }),
        );
        let mut sink_failed = false;
        if let Err(e) = writer.send(&startup).await {
            error!(error = %e, "Failed to write startup health event");
            sink_failed = true;
        }
        if let Err(e) = writer.flush().await {
            error!(error = %e, "Failed to flush startup health event");
            sink_failed = true;
        }

        // Health tick — interval of 0 disables periodic health events
        // (a final shutdown health event is always emitted regardless)
        let health_interval = self.config.health_interval_secs;
        let mut health_tick =
            tokio::time::interval(std::time::Duration::from_secs(health_interval.max(1)));
        health_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the immediate first tick
        health_tick.tick().await;

        // Main event loop with graceful shutdown
        let mut shutdown_open = true;
        let mut detector = crate::detection::Detector::default();
        loop {
            if sink_failed || *shutdown_rx.borrow() {
                break;
            }
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Some(evt) => {
                            if let Err(e) = deliver(evt, &mut process_cache, &mut detector, writer.as_mut()).await {
                                error!(error = %e, "Event delivery failed; stopping collectors without acknowledging source progress");
                                sink_failed = true;
                                break;
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
                _ = health_tick.tick(), if health_interval > 0 => {
                    let sink_status = SinkStatus {
                        sink_type: writer.name().to_string(),
                        events_dropped: writer.dropped_events(),
                        spool_files: writer.spool_files(),
                        spool_bytes: writer.spool_bytes(),
                    };
                    let mut health = self.build_health_event(
                        &collector_states,
                        &start_time,
                        event_count,
                        writer.dropped_events(),
                        Some(sink_status),
                    );
                    health.analysis_status = Some(detector.stats.clone());
                    if detector.stats.capacity_events_dropped > 0 || detector.stats.late_events > 0 {
                        health.severity = health.severity.max(Severity::Low);
                    }
                    if let Err(e) = writer.send(&health).await {
                        error!(error = %e, "Failed to write health event");
                        sink_failed = true;
                    }
                    // Flush immediately so health events are delivered on
                    // schedule, even when the HTTP sink batch is not full.
                    if let Err(e) = writer.flush().await {
                        error!(error = %e, "Failed to flush health event");
                        sink_failed = true;
                    }
                    info!(
                        uptime_secs = start_time.elapsed().as_secs(),
                        events_total = event_count,
                        "Health check"
                    );
                }
                result = shutdown_rx.changed(), if shutdown_open => {
                    // Only shut down on an explicit true signal, not on
                    // channel close (sender dropped). This ensures a
                    // future service caller that accidentally drops the
                    // sender does not silently terminate the sensor.
                    if result.is_ok() && *shutdown_rx.borrow() {
                        info!("Shutdown signal received");
                        break;
                    }
                    if result.is_err() { shutdown_open = false; }
                }
            }
        }

        // Establish a finite drain boundary. Later callbacks see a closed queue
        // and count their rejected events; already accepted events are preserved.
        rx.close();
        // Stop only collectors whose start succeeded. In particular, a disabled
        // or failed ETW instance must never stop somebody else's session.
        for (i, collector) in self.collectors.iter_mut().enumerate() {
            if collector_states[i].state != CollectorState::Running {
                continue;
            }
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

        while let Some(evt) = rx.recv().await {
            if let Err(e) = deliver(evt, &mut process_cache, &mut detector, writer.as_mut()).await {
                error!(error = %e, "Failed to write event during shutdown drain");
                sink_failed = true;
            } else {
                event_count += 1;
            }
        }

        // Flush buffered events before final health so drop counts are accurate
        if let Err(e) = writer.flush().await {
            error!(error = %e, "Failed to flush sink on shutdown");
            sink_failed = true;
        }

        // Final health event (includes any drops from flush above)
        let sink_status = SinkStatus {
            sink_type: writer.name().to_string(),
            events_dropped: writer.dropped_events(),
            spool_files: writer.spool_files(),
            spool_bytes: writer.spool_bytes(),
        };
        let mut final_health = self.build_health_event(
            &collector_states,
            &start_time,
            event_count,
            writer.dropped_events(),
            Some(sink_status),
        );
        final_health.analysis_status = Some(detector.stats.clone());
        if sink_failed {
            final_health.severity = final_health.severity.max(Severity::Medium);
        }
        if detector.stats.capacity_events_dropped > 0 || detector.stats.late_events > 0 {
            final_health.severity = final_health.severity.max(Severity::Low);
        }
        let collector_failed = matches!(&final_health.data, EventData::SensorHealth { collectors, .. }
            if collectors.iter().any(|c| c.state == CollectorState::Error));
        if let Err(e) = writer.send(&final_health).await {
            error!(error = %e, "Failed to write final health event");
            sink_failed = true;
        }

        // Flush the final health event itself
        if let Err(e) = writer.flush().await {
            error!(error = %e, "Failed to flush final health event");
            sink_failed = true;
        }

        info!(total_events = event_count, "Sensor stopped");
        if collector_failed || sink_failed {
            anyhow::bail!("One or more collectors or the output sink failed; inspect stderr logs and SensorHealth diagnostics");
        }
        Ok(())
    }

    fn build_health_event(
        &self,
        collector_states: &[CollectorEntry],
        start_time: &Instant,
        events_total: u64,
        sink_events_dropped: u64,
        sink_info: Option<SinkStatus>,
    ) -> ThreatEvent {
        let collectors: Vec<CollectorStatus> = collector_states
            .iter()
            .zip(&self.collectors)
            .map(|(entry, collector)| {
                let mut status = collector
                    .status()
                    .unwrap_or_else(|| CollectorStatus::new(&entry.name, entry.state));
                status.queue_events_dropped = collector.dropped_events();
                if entry.state != CollectorState::Running && status.state != CollectorState::Error {
                    status.state = entry.state;
                }
                if status.state == CollectorState::Error && status.error.is_none() {
                    status.error = Some(CollectorError {
                        code: "collector_start_failed".into(),
                        os_code: None,
                    });
                }
                status
            })
            .collect();
        let events_dropped = collectors.iter().fold(sink_events_dropped, |total, c| {
            total
                .saturating_add(c.queue_events_dropped)
                .saturating_add(c.events_lost_before_queue)
                .saturating_add(c.etw.as_ref().map_or(0, |s| s.events_lost))
                .saturating_add(c.endpoint_security.as_ref().map_or(0, |s| s.sequence_drops))
        });
        let severity = if collectors.iter().any(|c| c.state == CollectorState::Error) {
            Severity::Medium
        } else if events_dropped > 0
            || collectors.iter().any(|c| {
                matches!(
                    c.state,
                    CollectorState::Degraded | CollectorState::Unsupported
                ) || c.statistics_error.is_some()
                    || c.decode_failures > 0
                    || c.linux_audit
                        .as_ref()
                        .is_some_and(|s| s.quality_uncertain())
                    || c.endpoint_security.as_ref().is_some_and(|s| {
                        s.sequence_drops > 0
                            || s.sequence_discontinuities > 0
                            || s.sequence_unavailable > 0
                    })
                    || c.providers.iter().any(|p| !p.enabled)
                    || c.etw
                        .as_ref()
                        .is_some_and(|s| s.log_buffers_lost > 0 || s.realtime_buffers_lost > 0)
            })
        {
            Severity::Low
        } else {
            Severity::Info
        };

        ThreatEvent::new(
            &self.agent,
            EventSource::Sensor,
            EventCategory::Health,
            severity,
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

pub(crate) async fn deliver(
    mut event: ThreatEvent,
    cache: &mut ProcessCache,
    detector: &mut crate::detection::Detector,
    sink: &mut dyn output::Sink,
) -> Result<()> {
    let receipt = event.delivery.take();
    let result: Result<()> = async {
        if let Some(receipt) = &receipt {
            if let Some(snapshot) = receipt.take_restore() {
                detector.restore(snapshot, event.agent_id)?;
            }
            detector.enable_checkpointing(event.agent_id)?;
        }
        cache.enrich(&mut event);
        sink.send(&event).await?;
        for detection in detector.ingest(&event) {
            sink.send(&detection).await?;
        }
        if let Some(receipt) = &receipt {
            if receipt.written() {
                sink.durable_checkpoint().await?;
                receipt.committed(detector.take_delta(event.agent_id)?);
            }
        }
        Ok(())
    }
    .await;
    if result.is_err() {
        if let Some(receipt) = receipt {
            receipt.failed();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use tempfile::TempDir;

    #[derive(Default)]
    struct FaultSink {
        events: Vec<ThreatEvent>,
        send_attempts: usize,
        fail_send_at: Option<usize>,
        fail_sync: bool,
        fail_flush: bool,
        syncs: usize,
    }

    #[async_trait::async_trait]
    impl output::Sink for FaultSink {
        fn name(&self) -> &str {
            "fault-test"
        }
        fn dropped_events(&self) -> u64 {
            0
        }
        async fn send(&mut self, event: &ThreatEvent) -> Result<()> {
            self.send_attempts += 1;
            anyhow::ensure!(
                self.fail_send_at != Some(self.send_attempts),
                "injected write failure"
            );
            self.events.push(event.clone());
            Ok(())
        }
        async fn flush(&mut self) -> Result<()> {
            anyhow::ensure!(!self.fail_flush, "injected flush failure");
            Ok(())
        }
        async fn durable_checkpoint(&mut self) -> Result<()> {
            anyhow::ensure!(!self.fail_sync, "injected sync failure");
            self.syncs += 1;
            Ok(())
        }
    }

    fn acknowledged_pair() -> (
        Vec<ThreatEvent>,
        std::sync::mpsc::Receiver<crate::delivery::DeliveryResult>,
    ) {
        use crate::fixtures::{sysmon, ACTOR, TARGET};
        let (receipts, completion) = crate::delivery::Receipt::batch(2);
        let mut events = vec![sysmon(8, 0, ACTOR), sysmon(3, 1, TARGET)];
        for (event, receipt) in events.iter_mut().zip(receipts) {
            event.delivery = Some(receipt);
        }
        (events, completion)
    }

    #[tokio::test]
    async fn source_ack_requires_all_events_findings_and_sync() {
        let (events, completion) = acknowledged_pair();
        let mut cache = ProcessCache::new(100);
        let mut detector = crate::detection::Detector::default();
        let mut sink = FaultSink::default();
        let mut events = events.into_iter();
        deliver(events.next().unwrap(), &mut cache, &mut detector, &mut sink)
            .await
            .unwrap();
        assert!(completion.try_recv().is_err());
        assert_eq!(sink.syncs, 0);
        deliver(events.next().unwrap(), &mut cache, &mut detector, &mut sink)
            .await
            .unwrap();
        assert!(matches!(
            completion.try_recv().unwrap(),
            crate::delivery::DeliveryResult::Committed(_)
        ));
        assert_eq!(sink.syncs, 1);
        assert_eq!(sink.events.len(), 3);
        assert!(matches!(
            sink.events[2].data,
            EventData::CorrelationDetection { .. }
        ));
        assert!(sink.events.iter().all(|event| event.delivery.is_none()));
    }

    #[tokio::test]
    async fn write_finding_or_sync_failure_never_advances_checkpoint() {
        for (fail_send_at, fail_sync) in [(Some(1), false), (Some(3), false), (None, true)] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("checkpoint.db");
            let id = uuid::Uuid::new_v4();
            let mut checkpoint = crate::checkpoint::Checkpoint::open(&path, id).unwrap();
            checkpoint
                .save(&crate::checkpoint::test_position(
                    "previous-native-bookmark",
                ))
                .unwrap();
            let (events, completion) = acknowledged_pair();
            let mut cache = ProcessCache::new(100);
            let mut detector = crate::detection::Detector::default();
            let mut sink = FaultSink {
                fail_send_at,
                fail_sync,
                ..Default::default()
            };
            let mut failed = false;
            for event in events {
                if deliver(event, &mut cache, &mut detector, &mut sink)
                    .await
                    .is_err()
                {
                    failed = true;
                    break;
                }
            }
            assert!(failed);
            if let crate::delivery::DeliveryResult::Committed(_) = completion.try_recv().unwrap() {
                checkpoint
                    .save(&crate::checkpoint::test_position("new-native-bookmark"))
                    .unwrap();
            }
            drop(checkpoint);
            assert_eq!(
                crate::checkpoint::Checkpoint::open(&path, id)
                    .unwrap()
                    .load()
                    .unwrap(),
                Some(crate::checkpoint::test_position("previous-native-bookmark"))
            );
            assert_eq!(sink.syncs, 0);
        }
    }

    #[tokio::test]
    async fn interrupted_batch_keeps_checkpoint_before_partial_output() {
        let (mut events, completion) = acknowledged_pair();
        let first = events.remove(0);
        let mut cache = ProcessCache::new(100);
        let mut detector = crate::detection::Detector::default();
        let mut sink = FaultSink::default();
        deliver(first, &mut cache, &mut detector, &mut sink)
            .await
            .unwrap();
        drop(events); // interruption before the final record is delivered
        assert_eq!(
            completion.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        );
        assert_eq!(sink.syncs, 0);
    }

    #[tokio::test]
    async fn acknowledged_file_output_survives_reopen_with_evidence() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let (events, completion) = acknowledged_pair();
        let ids: Vec<_> = events.iter().map(|e| e.id).collect();
        let mut cache = ProcessCache::new(100);
        let mut detector = crate::detection::Detector::default();
        let mut sink = output::create_sink(&config.output).unwrap();
        for event in events {
            deliver(event, &mut cache, &mut detector, sink.as_mut())
                .await
                .unwrap();
        }
        assert!(matches!(
            completion.try_recv().unwrap(),
            crate::delivery::DeliveryResult::Committed(_)
        ));
        drop(sink);
        let saved = recorded(&config.output.path);
        assert_eq!(saved.len(), 3);
        assert_eq!(saved[0].id, ids[0]);
        assert_eq!(saved[1].id, ids[1]);
        assert!(
            matches!(&saved[2].data, EventData::CorrelationDetection { evidence_ids, .. } if evidence_ids.iter().all(|id| ids.contains(id)))
        );
    }

    #[tokio::test]
    async fn file_and_analysis_recovery_detect_sequence_across_sensor_restart() {
        use crate::delivery::{DeliveryResult, Receipt};
        use crate::fixtures::{sysmon, ACTOR, TARGET};
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let mut first = sysmon(8, 0, ACTOR);
        let first_id = first.id;
        let agent = first.agent_id;
        let path = dir.path().join("checkpoint.db");
        let mut store = crate::checkpoint::Checkpoint::open(&path, agent).unwrap();
        let (mut receipts, ack) = Receipt::batch(1);
        first.delivery = receipts.pop();
        let mut cache = ProcessCache::new(100);
        let mut detector = crate::detection::Detector::default();
        let mut sink = output::create_sink(&config.output).unwrap();
        deliver(first, &mut cache, &mut detector, sink.as_mut())
            .await
            .unwrap();
        let DeliveryResult::Committed(delta) = ack.try_recv().unwrap() else {
            panic!("not committed")
        };
        store
            .commit(&crate::checkpoint::test_position("before-restart"), &delta)
            .unwrap();
        drop(sink);
        drop(store);
        drop(detector);
        drop(cache);

        let mut store = crate::checkpoint::Checkpoint::open(&path, agent).unwrap();
        let (mut receipts, ack) = Receipt::with_restore(1, Some(store.load_analysis().unwrap()));
        let mut second = sysmon(3, 1, TARGET);
        let second_id = second.id;
        second.delivery = receipts.pop();
        let mut cache = ProcessCache::new(100);
        let mut detector = crate::detection::Detector::default();
        let mut sink = output::create_sink(&config.output).unwrap();
        deliver(second, &mut cache, &mut detector, sink.as_mut())
            .await
            .unwrap();
        let DeliveryResult::Committed(delta) = ack.try_recv().unwrap() else {
            panic!("not committed")
        };
        store
            .commit(&crate::checkpoint::test_position("after-restart"), &delta)
            .unwrap();
        drop(sink);
        let events = recorded(&config.output.path);
        assert_eq!(events.len(), 3);
        assert!(
            matches!(&events[2].data,EventData::CorrelationDetection {rule_id,evidence_ids,..}
            if rule_id=="TF-COR-001" && evidence_ids.contains(&first_id) && evidence_ids.contains(&second_id))
        );
        assert!(detector.stats.state_restored);
        assert_eq!(detector.stats.restored_timelines, 1);
    }

    #[tokio::test]
    async fn invalid_restore_fails_before_output_and_rejects_source_ack() {
        let mut event = crate::fixtures::sysmon(8, 0, crate::fixtures::ACTOR);
        let mut state = crate::detection::StateSnapshot::empty(event.agent_id);
        state.version += 1;
        let (mut receipts, ack) = crate::delivery::Receipt::with_restore(1, Some(state));
        event.delivery = receipts.pop();
        let mut cache = ProcessCache::new(100);
        let mut detector = crate::detection::Detector::default();
        let mut sink = FaultSink::default();
        assert!(deliver(event, &mut cache, &mut detector, &mut sink)
            .await
            .is_err());
        assert_eq!(
            ack.try_recv().unwrap(),
            crate::delivery::DeliveryResult::Failed
        );
        assert!(sink.events.is_empty());
        assert_eq!(sink.syncs, 0);
    }

    #[tokio::test]
    #[ignore = "synthetic local output/checkpoint workload; not Windows endpoint performance validation"]
    async fn checkpoint_workload_measurement() {
        use crate::delivery::{DeliveryResult, Receipt};
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let agent = uuid::Uuid::from_u128(1);
        let path = dir.path().join("checkpoint.db");
        let mut store = crate::checkpoint::Checkpoint::open(&path, agent).unwrap();
        let mut sink = output::create_sink(&config.output).unwrap();
        let mut cache = ProcessCache::new(1000);
        let mut detector = crate::detection::Detector::default();
        let began = Instant::now();
        for batch in 0..128 {
            let (receipts, ack) = Receipt::batch(32);
            for (offset, receipt) in receipts.into_iter().enumerate() {
                let n = batch * 32 + offset;
                let process = uuid::Uuid::from_u128(100 + (n % 128) as u128).to_string();
                let mut event = crate::fixtures::sysmon(3, (n / 256) as i64, &process);
                event.provenance.as_mut().unwrap().record_id = Some(n as u64 + 1);
                event.delivery = Some(receipt);
                deliver(event, &mut cache, &mut detector, sink.as_mut())
                    .await
                    .unwrap();
            }
            let DeliveryResult::Committed(delta) = ack.try_recv().unwrap() else {
                panic!("not committed")
            };
            assert_eq!(delta.changes.len(), 32);
            store
                .commit(
                    &crate::checkpoint::test_position(&format!("synthetic-{batch}")),
                    &delta,
                )
                .unwrap();
        }
        let elapsed = began.elapsed();
        assert_eq!(detector.stats.capacity_events_dropped, 0);
        assert_eq!(detector.stats.findings, 0);
        assert_eq!(store.load_analysis().unwrap().timelines.len(), 128);
        assert_eq!(recorded(&config.output.path).len(), 4096);
        eprintln!("synthetic_checkpoint_workload records=4096 batches=128 process_timelines=128 elapsed_ms={} output_bytes={} database_bytes={} platform={}",
            elapsed.as_millis(),std::fs::metadata(&config.output.path).unwrap().len(),std::fs::metadata(&path).unwrap().len(),std::env::consts::OS);
    }

    #[tokio::test]
    async fn health_write_or_flush_failure_stops_collectors_and_fails_run() {
        for sink in [
            FaultSink {
                fail_send_at: Some(1),
                ..Default::default()
            },
            FaultSink {
                fail_flush: true,
                ..Default::default()
            },
            FaultSink {
                fail_send_at: Some(2),
                ..Default::default()
            },
        ] {
            let dir = TempDir::new().unwrap();
            let mut sensor = Sensor::new(test_config(&dir)).unwrap();
            let collector = TestCollector::new();
            let stops = collector.stops.clone();
            sensor.collectors = vec![Box::new(collector)];
            let (_tx, rx) = test_shutdown();
            assert!(sensor.run_with_sink(rx, Box::new(sink)).await.is_err());
            assert_eq!(stops.load(std::sync::atomic::Ordering::Relaxed), 1);
        }
    }

    /// Create a shutdown channel for tests. Returns both halves so the
    /// sender stays alive — the sensor shuts down via the collector
    /// channel closing (rx.recv() → None), not via a dropped sender.
    fn test_shutdown() -> (watch::Sender<bool>, watch::Receiver<bool>) {
        watch::channel(false)
    }

    fn test_config(dir: &TempDir) -> SensorConfig {
        // Unit tests must never start real collectors on the developer/CI host.
        let mut collectors = CollectorConfig::default();
        collectors.etw.enabled = false;
        collectors.sysmon.enabled = false;
        collectors.evasion.enabled = false;
        SensorConfig {
            hostname: "TEST-HOST".into(),
            output: OutputConfig {
                path: dir.path().join("test_events.jsonl"),
                rotation_size_mb: 100,
                ..OutputConfig::default()
            },
            collectors,
            health_interval_secs: 60,
            state_path: dir.path().join("test.state"),
            rules: RulesConfig::default(),
        }
    }

    /// With collectors disabled, startup and final health are still persisted.
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
                // Include disabled / unsupported platform collectors.
                assert_eq!(collectors.len(), 5);
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

                // Disabled collectors remain explicitly disabled on every OS.
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

    struct TestCollector {
        enabled: bool,
        supported: bool,
        fail_start: bool,
        delayed: bool,
        status: CollectorStatus,
        events: Vec<ThreatEvent>,
        starts: std::sync::Arc<std::sync::atomic::AtomicU64>,
        stops: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl TestCollector {
        fn new() -> Self {
            Self {
                enabled: true,
                supported: true,
                fail_start: false,
                delayed: false,
                status: CollectorStatus::new("test", CollectorState::Running),
                events: vec![],
                starts: Default::default(),
                stops: Default::default(),
            }
        }
    }

    #[async_trait::async_trait]
    impl Collector for TestCollector {
        fn name(&self) -> &str {
            &self.status.name
        }
        fn enabled(&self) -> bool {
            self.enabled
        }
        fn supported(&self) -> bool {
            self.supported
        }
        fn status(&self) -> Option<CollectorStatus> {
            Some(self.status.clone())
        }
        fn dropped_events(&self) -> u64 {
            self.status.queue_events_dropped
        }
        async fn start(&mut self, tx: mpsc::Sender<ThreatEvent>) -> Result<()> {
            self.starts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.fail_start {
                anyhow::bail!("test startup failure");
            }
            let events = std::mem::take(&mut self.events);
            if self.delayed {
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    for event in events {
                        tx.send(event).await.unwrap();
                    }
                });
            } else {
                for event in events {
                    tx.try_send(event).unwrap();
                }
            }
            Ok(())
        }
        async fn stop(&mut self) -> Result<()> {
            self.stops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    fn recorded(path: &std::path::Path) -> Vec<ThreatEvent> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn process_event(agent: &AgentInfo) -> ThreatEvent {
        ThreatEvent::new(
            agent,
            EventSource::Sensor,
            EventCategory::Process,
            Severity::Info,
            EventData::ProcessCreate {
                pid: 42,
                ppid: 1,
                image_path: "test.exe".into(),
                command_line: "test.exe".into(),
                user: String::new(),
                integrity_level: String::new(),
                hashes: None,
                create_time: Some(123),
            },
        )
    }

    #[tokio::test]
    async fn shutdown_drains_accepted_events_in_order_with_process_context() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let path = config.output.path.clone();
        let mut sensor = Sensor::new(config).unwrap();
        let mut collector = TestCollector::new();
        let process = process_event(&sensor.agent);
        let file = ThreatEvent::new(
            &sensor.agent,
            EventSource::Sensor,
            EventCategory::File,
            Severity::Info,
            EventData::FileCreate {
                pid: 42,
                path: "test.txt".into(),
                operation: FileOperation::Create,
            },
        );
        let ids = [process.id, file.id];
        collector.events = vec![process, file];
        sensor.collectors = vec![Box::new(collector)];
        let (_shutdown_tx, shutdown_rx) = watch::channel(true);
        sensor.run(shutdown_rx).await.unwrap();
        let events = recorded(&path);
        assert_eq!(events.len(), 4); // startup, both queued events, final health
        assert_eq!([events[1].id, events[2].id], ids);
        assert_eq!(
            events[2].process_context.as_ref().unwrap().process_key,
            "42:123"
        );
        assert!(matches!(
            events[3].data,
            EventData::SensorHealth {
                events_total: 2,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn live_and_shutdown_paths_emit_evidence_and_analysis_health() {
        use crate::fixtures::*;
        for stop_immediately in [false, true] {
            let dir = TempDir::new().unwrap();
            let config = test_config(&dir);
            let path = config.output.path.clone();
            let mut sensor = Sensor::new(config).unwrap();
            let mut collector = TestCollector::new();
            let mut events = vec![
                sysmon(10, 0, ACTOR),
                sysmon(8, 10, ACTOR),
                sysmon(3, 20, TARGET),
            ];
            for event in &mut events {
                event.agent_id = sensor.agent.agent_id;
                event.hostname = sensor.agent.hostname.clone();
            }
            let ids: Vec<_> = events.iter().map(|e| e.id).collect();
            collector.events = events;
            sensor.collectors = vec![Box::new(collector)];
            let (_tx, rx) = watch::channel(stop_immediately);
            sensor.run(rx).await.unwrap();
            let output = recorded(&path);
            let detections: Vec<_> = output
                .iter()
                .filter(|e| matches!(e.data, EventData::CorrelationDetection { .. }))
                .collect();
            assert_eq!(detections.len(), 1);
            if let EventData::CorrelationDetection { evidence_ids, .. } = &detections[0].data {
                assert_eq!(evidence_ids.len(), 3);
                assert!(ids.iter().all(|id| evidence_ids.contains(id)));
            }
            let status = output.last().unwrap().analysis_status.as_ref().unwrap();
            assert_eq!(status.findings, 1);
            assert_eq!(status.eligible_events, 3);
        }
    }

    #[tokio::test]
    async fn failed_disabled_and_unsupported_collectors_are_never_stopped() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let path = config.output.path.clone();
        let mut sensor = Sensor::new(config).unwrap();
        let mut counters = Vec::new();
        sensor.collectors = (0..3)
            .map(|i| {
                let mut c = TestCollector::new();
                c.fail_start = i == 0;
                c.enabled = i != 1;
                c.supported = i != 2;
                counters.push((c.starts.clone(), c.stops.clone()));
                Box::new(c) as Box<dyn Collector>
            })
            .collect();
        let (_tx, rx) = watch::channel(false);
        assert!(sensor.run(rx).await.is_err());
        for (i, (starts, stops)) in counters.iter().enumerate() {
            assert_eq!(
                starts.load(std::sync::atomic::Ordering::Relaxed),
                if i == 0 { 1 } else { 0 }
            );
            assert_eq!(stops.load(std::sync::atomic::Ordering::Relaxed), 0);
        }
        if let EventData::SensorHealth { collectors, .. } = &recorded(&path).last().unwrap().data {
            assert_eq!(
                collectors.iter().map(|c| c.state).collect::<Vec<_>>(),
                vec![
                    CollectorState::Error,
                    CollectorState::Disabled,
                    CollectorState::Unsupported
                ]
            );
        } else {
            panic!("missing final health");
        }
    }

    #[tokio::test]
    async fn sink_failure_prevents_collector_start() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.output.path = dir.path().to_path_buf(); // a directory cannot be a log file
        let mut sensor = Sensor::new(config).unwrap();
        let c = TestCollector::new();
        let starts = c.starts.clone();
        sensor.collectors = vec![Box::new(c)];
        let (_tx, rx) = watch::channel(false);
        assert!(sensor.run(rx).await.is_err());
        assert_eq!(starts.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn closed_shutdown_sender_does_not_starve_event_producer() {
        let dir = TempDir::new().unwrap();
        let mut sensor = Sensor::new(test_config(&dir)).unwrap();
        let mut collector = TestCollector::new();
        collector.delayed = true;
        collector.events = vec![process_event(&sensor.agent)];
        sensor.collectors = vec![Box::new(collector)];
        let (tx, rx) = watch::channel(false);
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(1), sensor.run(rx))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn health_counts_lost_events_without_adding_lost_buffers() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let path = config.output.path.clone();
        let mut sensor = Sensor::new(config).unwrap();
        let mut c = TestCollector::new();
        c.status.queue_events_dropped = 2;
        c.status.etw = Some(EtwSessionStats {
            events_lost: 3,
            log_buffers_lost: 7,
            realtime_buffers_lost: 11,
            collected_at: chrono::Utc::now(),
        });
        sensor.collectors = vec![Box::new(c)];
        let (_tx, rx) = watch::channel(false);
        sensor.run(rx).await.unwrap();
        let events = recorded(&path);
        assert!(matches!(
            events.last().unwrap().data,
            EventData::SensorHealth {
                events_dropped: 5,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn final_health_keeps_decode_quality_visible_after_stop() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let path = config.output.path.clone();
        let mut sensor = Sensor::new(config).unwrap();
        let mut c = TestCollector::new();
        c.status.decode_failures = 1;
        sensor.collectors = vec![Box::new(c)];
        let (_tx, rx) = watch::channel(false);
        sensor.run(rx).await.unwrap();
        assert_eq!(recorded(&path).last().unwrap().severity, Severity::Low);
    }

    #[tokio::test]
    async fn runtime_failure_survives_successful_stop_and_returns_error() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let path = config.output.path.clone();
        let mut sensor = Sensor::new(config).unwrap();
        let mut c = TestCollector::new();
        c.status.state = CollectorState::Error;
        c.status.error = Some(CollectorError {
            code: "etw_consumer_ended".into(),
            os_code: Some(5),
        });
        sensor.collectors = vec![Box::new(c)];
        let (_tx, rx) = watch::channel(false);
        assert!(sensor.run(rx).await.is_err());
        if let EventData::SensorHealth { collectors, .. } = &recorded(&path).last().unwrap().data {
            assert_eq!(collectors[0].state, CollectorState::Error);
            assert_eq!(collectors[0].error.as_ref().unwrap().os_code, Some(5));
        } else {
            panic!("missing final health");
        }
    }
}
