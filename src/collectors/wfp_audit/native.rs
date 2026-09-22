//! All Win32 handles remain owned by a single bounded polling worker.
use super::parser;
use crate::{
    collectors::health::RuntimeHealth,
    events::{AgentInfo, EventData, ThreatEvent},
    wfp_events::WfpAuditStats,
};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use tokio::sync::{mpsc, oneshot};
use windows::{
    core::{HRESULT, PCWSTR},
    Win32::{
        Foundation::*,
        System::{EventLog::*, Threading::*},
    },
};

const QUERY: &str = "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=5156 or EventID=5157)]]";
const BATCH: usize = 16;

struct EventHandle(EVT_HANDLE);
impl Drop for EventHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = EvtClose(self.0);
        }
    }
}
struct SignalHandle(HANDLE);
impl Drop for SignalHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
struct Failure(&'static str, Option<u32>);
fn failure(code: &'static str, error: windows::core::Error) -> Failure {
    Failure(
        if error.code() == HRESULT::from_win32(ERROR_ACCESS_DENIED.0) {
            "wfp_access_denied"
        } else {
            code
        },
        Some(error.code().0 as u32),
    )
}

pub(super) fn run(
    agent: AgentInfo,
    tx: mpsc::Sender<ThreatEvent>,
    drops: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    health: RuntimeHealth,
    ready: oneshot::Sender<Result<(), ()>>,
) {
    let mut ready = Some(ready);
    let result = collect(&agent, &tx, &drops, &stop, &health, &mut ready);
    if let Err(Failure(code, os_code)) = result {
        health.fail(code, os_code);
    }
    if let Some(ready) = ready {
        let _ = ready.send(Err(()));
    }
}

fn collect(
    agent: &AgentInfo,
    tx: &mpsc::Sender<ThreatEvent>,
    drops: &AtomicU64,
    stop: &AtomicBool,
    health: &RuntimeHealth,
    ready: &mut Option<oneshot::Sender<Result<(), ()>>>,
) -> Result<(), Failure> {
    let signal = SignalHandle(
        unsafe { CreateEventW(None, true, false, None) }
            .map_err(|e| failure("wfp_signal_failed", e))?,
    );
    let channel: Vec<u16> = "Security".encode_utf16().chain(Some(0)).collect();
    let query: Vec<u16> = QUERY.encode_utf16().chain(Some(0)).collect();
    // No remote session, callback, bookmark, privilege adjustment, policy or filter writes.
    let subscription = EventHandle(
        unsafe {
            EvtSubscribe(
                EVT_HANDLE::default(),
                signal.0,
                PCWSTR(channel.as_ptr()),
                PCWSTR(query.as_ptr()),
                EVT_HANDLE::default(),
                None,
                None,
                EvtSubscribeToFutureEvents.0 | EvtSubscribeStrict.0,
            )
        }
        .map_err(|e| failure("wfp_subscription_failed", e))?,
    );
    let mut stats = WfpAuditStats::default();
    health.wfp_audit(stats.clone());
    health.running();
    if ready.take().is_some_and(|r| r.send(Ok(())).is_err()) {
        return Ok(());
    }
    while !stop.load(Ordering::Acquire) {
        let mut handles = [0isize; BATCH];
        let mut count = 0;
        let next = unsafe { EvtNext(subscription.0, &mut handles, 0, 0, &mut count) };
        // Own even unexpected handles on an API failure; always close the whole batch.
        let events: Vec<EventHandle> = handles
            .into_iter()
            .filter(|h| *h != 0)
            .map(|h| EventHandle(EVT_HANDLE(h)))
            .collect();
        if let Err(e) = next {
            for _ in &events {
                health.lost_before_queue();
            }
            if events.is_empty()
                && (e.code() == HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0)
                    || e.code() == HRESULT::from_win32(ERROR_TIMEOUT.0))
            {
                if !crate::collectors::eventlog::wait_for_events(signal.0, stop)
                    .map_err(|e| failure("wfp_signal_failed", e))?
                {
                    return Ok(());
                }
                continue;
            }
            // Includes stale query/log errors. Never reinterpret record-ID gaps as counts.
            return Err(failure("wfp_read_failed", e));
        }
        if count == 0 || count as usize != events.len() {
            for _ in &events {
                health.lost_before_queue();
            }
            return Err(Failure("wfp_invalid_batch", None));
        }
        for handle in events {
            stats.records_read = stats.records_read.saturating_add(1);
            let event = render(handle.0).and_then(|xml| parser::parse(&xml, agent).ok());
            let Some(event) = event else {
                health.lost_before_queue();
                continue;
            };
            let partial = event
                .provenance
                .as_ref()
                .is_some_and(|p| !p.issues.is_empty());
            health.decoded(partial, partial);
            if let EventData::WfpConnectionAudit { record } = &event.data {
                stats.fields_omitted = stats
                    .fields_omitted
                    .saturating_add(record.omitted_fields.len() as u64);
            }
            if super::enqueue(tx, event, drops).is_err() {
                health.wfp_audit(stats);
                return Err(Failure("wfp_queue_closed", None));
            }
        }
        health.wfp_audit(stats.clone());
    }
    Ok(())
}

fn render(handle: EVT_HANDLE) -> Option<String> {
    let (mut bytes, mut properties) = (0, 0);
    let probe = unsafe {
        EvtRender(
            EVT_HANDLE::default(),
            handle,
            EvtRenderEventXml.0,
            0,
            None,
            &mut bytes,
            &mut properties,
        )
    };
    if !matches!(probe, Err(ref e) if e.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0))
        || bytes < 2
        || bytes as usize > 2 * (parser::MAX_XML_BYTES + 1)
        || bytes % 2 != 0
    {
        return None;
    }
    let allocated_bytes = bytes;
    let mut buffer = vec![0u16; bytes as usize / 2];
    unsafe {
        EvtRender(
            EVT_HANDLE::default(),
            handle,
            EvtRenderEventXml.0,
            allocated_bytes,
            Some(buffer.as_mut_ptr().cast()),
            &mut bytes,
            &mut properties,
        )
    }
    .ok()?;
    if bytes < 2 || bytes > allocated_bytes || bytes % 2 != 0 {
        return None;
    }
    let used = &buffer[..bytes as usize / 2];
    if used.last() != Some(&0) || used[..used.len() - 1].contains(&0) {
        return None;
    }
    String::from_utf16(&used[..used.len() - 1])
        .ok()
        .filter(|s| s.len() <= parser::MAX_XML_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{collectors::Collector, config::WfpAuditConfig};
    #[tokio::test]
    #[ignore = "Windows native Security log permission/lifecycle probe; does not verify audit coverage"]
    async fn native_subscription_probe() {
        let mut collector = super::super::WfpAuditCollector::new(
            WfpAuditConfig { enabled: true },
            AgentInfo {
                hostname: "WFP-TEST".into(),
                agent_id: uuid::Uuid::new_v4(),
            },
        );
        let (tx, _rx) = mpsc::channel(16);
        collector
            .start(tx)
            .await
            .expect("Security log subscription must succeed");
        // The former loop failed after its first 100 ms idle timeout. A
        // start/immediate-stop probe never exercised that path.
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let live = collector.status().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), collector.stop())
            .await
            .expect("idle collector must stop promptly")
            .unwrap();
        assert_eq!(live.state, crate::events::CollectorState::Running);
        let status = collector.status().unwrap();
        assert_eq!(status.state, crate::events::CollectorState::Stopped);
        assert!(!status.wfp_audit.unwrap().audit_policy_verified);
    }
}
