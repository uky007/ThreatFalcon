//! Shared runtime status, independent of OS callbacks and display language.

use std::sync::{Arc, Mutex};

use crate::events::{
    CollectorError, CollectorState, CollectorStatus, EtwSessionStats, ProviderStatus,
};

#[derive(Clone)]
pub struct RuntimeHealth(Arc<Mutex<CollectorStatus>>);

// Some setters are only called by Windows collectors (or by portable tests).
#[allow(dead_code)]
impl RuntimeHealth {
    pub fn new(name: &str) -> Self {
        Self(Arc::new(Mutex::new(CollectorStatus::new(
            name,
            CollectorState::Stopped,
        ))))
    }

    fn update(&self, f: impl FnOnce(&mut CollectorStatus)) {
        f(&mut self.0.lock().unwrap_or_else(|e| e.into_inner()));
    }

    pub fn starting(&self) {
        self.update(|s| *s = CollectorStatus::new(&s.name, CollectorState::Starting));
    }

    pub fn running(&self) {
        self.update(|s| {
            if s.state == CollectorState::Starting {
                s.state = CollectorState::Running;
            }
        });
    }

    pub fn stopped(&self) {
        self.update(|s| {
            if s.state != CollectorState::Error {
                s.state = CollectorState::Stopped;
            }
        });
    }

    pub fn fail(&self, code: &str, os_code: Option<u32>) {
        self.update(|s| {
            s.state = CollectorState::Error;
            s.error = Some(CollectorError {
                code: code.into(),
                os_code,
            });
        });
    }

    pub fn providers(&self, providers: Vec<ProviderStatus>) {
        self.update(|s| s.providers = providers);
    }

    pub fn statistics(&self, stats: EtwSessionStats) {
        self.update(|s| {
            s.etw = Some(stats);
            s.statistics_error = None;
        });
    }

    pub fn statistics_failed(&self, os_code: u32) {
        self.update(|s| {
            s.statistics_error = Some(CollectorError {
                code: "etw_query_failed".into(),
                os_code: Some(os_code),
            })
        });
    }

    pub fn snapshot(&self, queue_drops: u64) -> CollectorStatus {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        s.queue_events_dropped = queue_drops;
        let lost = s.etw.as_ref().is_some_and(|v| {
            v.events_lost > 0 || v.log_buffers_lost > 0 || v.realtime_buffers_lost > 0
        });
        if s.state == CollectorState::Running
            && (queue_drops > 0
                || s.events_lost_before_queue > 0
                || s.decode_failures > 0
                || lost
                || s.statistics_error.is_some()
                || s.linux_audit
                    .as_ref()
                    .is_some_and(|s| s.quality_uncertain())
                || s.endpoint_security.as_ref().is_some_and(|v| {
                    v.sequence_drops > 0
                        || v.sequence_discontinuities > 0
                        || v.sequence_unavailable > 0
                })
                || s.providers.iter().any(|p| {
                    !p.enabled
                        || p.telemetry
                            .as_ref()
                            .is_some_and(|t| t.metadata_issue_events > 0)
                }))
        {
            s.state = CollectorState::Degraded;
        }
        s
    }

    pub fn decoded(&self, not_normalized: bool, failed: bool) {
        self.update(|s| {
            s.events_observed = s.events_observed.saturating_add(1);
            s.events_not_normalized = s
                .events_not_normalized
                .saturating_add(u64::from(not_normalized));
            s.decode_failures = s.decode_failures.saturating_add(u64::from(failed));
        });
    }

    pub fn etw_observed(&self, event: &crate::events::ThreatEvent) {
        use crate::collectors::etw_metadata::publisher_identity;
        let not_normalized = matches!(event.data, crate::events::EventData::NativeTelemetry { .. });
        let Some(p) = &event.provenance else {
            return;
        };
        let failed = p.issues.iter().any(|issue| issue.starts_with("tdh_"));
        self.update(|s| {
            s.events_observed = s.events_observed.saturating_add(1);
            s.events_not_normalized = s
                .events_not_normalized
                .saturating_add(u64::from(not_normalized));
            s.decode_failures = s.decode_failures.saturating_add(u64::from(failed));
            if let Some(t) = s
                .providers
                .iter_mut()
                .find(|provider| {
                    provider
                        .guid
                        .trim_matches(['{', '}'])
                        .eq_ignore_ascii_case(&p.provider_guid)
                })
                .and_then(|provider| provider.telemetry.as_mut())
            {
                t.observed = t.observed.saturating_add(1);
                t.normalized = t.normalized.saturating_add(u64::from(!not_normalized));
                t.last_observed_at = Some(chrono::Utc::now());
                if let Some(metadata) = &p.etw_extended {
                    t.extended_events = t.extended_events.saturating_add(1);
                    t.publisher_identity_events = t
                        .publisher_identity_events
                        .saturating_add(u64::from(publisher_identity(event).is_some()));
                    t.stack_events = t
                        .stack_events
                        .saturating_add(u64::from(!metadata.stacks.is_empty()));
                    t.metadata_issue_events = t
                        .metadata_issue_events
                        .saturating_add(u64::from(!metadata.issues.is_empty()));
                }
            }
        });
    }

    pub fn etw_queue_result(&self, guid: &str, admitted: bool) {
        self.update(|s| {
            if let Some(t) = s
                .providers
                .iter_mut()
                .find(|p| p.guid.trim_matches(['{', '}']).eq_ignore_ascii_case(guid))
                .and_then(|p| p.telemetry.as_mut())
            {
                if admitted {
                    t.queue_admitted = t.queue_admitted.saturating_add(1);
                } else {
                    t.queue_dropped = t.queue_dropped.saturating_add(1);
                }
            }
        });
    }

    pub fn endpoint_security(&self, stats: crate::macos_events::EndpointSecurityStats) {
        self.update(|s| s.endpoint_security = Some(stats));
    }
    pub fn linux_audit(&self, stats: crate::linux_events::LinuxAuditStats) {
        self.update(|s| s.linux_audit = Some(stats));
    }
    pub fn wfp_audit(&self, stats: crate::wfp_events::WfpAuditStats) {
        self.update(|s| s.wfp_audit = Some(stats));
    }

    pub fn lost_before_queue(&self) {
        self.decoded(true, true);
        self.update(|s| s.events_lost_before_queue = s.events_lost_before_queue.saturating_add(1));
    }

    pub fn recovery_mode(&self, mode: &str) {
        self.update(|s| s.recovery_mode = Some(mode.into()));
    }
    pub fn checkpoint_committed(&self, count: u64) {
        self.update(|s| {
            s.checkpoint_committed_events = s.checkpoint_committed_events.saturating_add(count);
            s.checkpoint_last_commit_at = Some(chrono::Utc::now());
        });
    }
}

/// Owns the lifetime of a blocking collector task. Dropping signals shutdown;
/// explicit stop also waits for its callbacks to release their resources.
#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
pub struct Worker {
    stop: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<()>,
    health: RuntimeHealth,
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
impl Worker {
    pub fn spawn(
        health: RuntimeHealth,
        run: impl FnOnce(Arc<std::sync::atomic::AtomicBool>, RuntimeHealth) + Send + 'static,
    ) -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker_health = health.clone();
        let task = tokio::task::spawn_blocking(move || run(worker_stop, worker_health));
        Self { stop, task, health }
    }

    pub fn check(&self) {
        if self.task.is_finished()
            && !self.stop.load(std::sync::atomic::Ordering::Acquire)
            && self.health.snapshot(0).state != CollectorState::Error
        {
            self.health.fail("collector_worker_ended", None);
        }
    }

    pub async fn stop(&mut self) -> anyhow::Result<()> {
        self.check();
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        match tokio::time::timeout(std::time::Duration::from_secs(5), &mut self.task).await {
            Ok(Ok(())) => {
                self.health.stopped();
                Ok(())
            }
            Ok(Err(e)) => {
                self.health.fail("collector_worker_failed", None);
                Err(e.into())
            }
            Err(e) => {
                self.health.fail("collector_stop_timeout", None);
                Err(e.into())
            }
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_overruns_are_not_invented_event_drop_counts_and_survive_stop() {
        let health = RuntimeHealth::new("LinuxAudit");
        health.starting();
        health.running();
        health.linux_audit(crate::linux_events::LinuxAuditStats {
            socket_overruns: 2,
            ..Default::default()
        });
        let status = health.snapshot(0);
        assert_eq!(status.state, CollectorState::Degraded);
        assert_eq!(status.events_lost_before_queue, 0);
        assert_eq!(status.queue_events_dropped, 0);
        health.stopped();
        assert_eq!(health.snapshot(0).linux_audit.unwrap().socket_overruns, 2);
    }

    #[test]
    fn decoder_loss_is_not_reported_as_queue_backpressure() {
        let health = RuntimeHealth::new("test");
        health.starting();
        health.running();
        health.lost_before_queue();
        let status = health.snapshot(0);
        assert_eq!(status.state, CollectorState::Degraded);
        assert_eq!(status.events_observed, 1);
        assert_eq!(status.events_lost_before_queue, 1);
        assert_eq!(status.decode_failures, 1);
        assert_eq!(status.queue_events_dropped, 0);
    }

    #[test]
    fn failed_provider_degrades_running_collector_and_retains_native_error() {
        let health = RuntimeHealth::new("ETW");
        health.starting();
        health.providers(vec![ProviderStatus {
            telemetry: None,
            name: "restricted".into(),
            guid: "test".into(),
            enabled: false,
            error_code: Some(5),
        }]);
        health.running();
        let s = health.snapshot(0);
        assert_eq!(s.state, CollectorState::Degraded);
        assert_eq!(s.providers[0].error_code, Some(5));
    }

    #[test]
    fn failed_query_preserves_last_sample_and_recovers_on_success() {
        let health = RuntimeHealth::new("ETW");
        health.starting();
        health.running();
        let stats = EtwSessionStats {
            events_lost: 0,
            log_buffers_lost: 0,
            realtime_buffers_lost: 0,
            collected_at: chrono::Utc::now(),
        };
        health.statistics(stats.clone());
        health.statistics_failed(5);
        let s = health.snapshot(0);
        assert_eq!(s.state, CollectorState::Degraded);
        assert_eq!(s.etw.unwrap().collected_at, stats.collected_at);
        health.statistics(stats);
        assert_eq!(health.snapshot(0).state, CollectorState::Running);
    }

    #[test]
    fn runtime_error_is_not_hidden_by_start_or_stop() {
        let health = RuntimeHealth::new("ETW");
        health.starting();
        health.fail("etw_consumer_ended", Some(0));
        health.running();
        health.stopped();
        assert_eq!(health.snapshot(0).state, CollectorState::Error);
    }
}
