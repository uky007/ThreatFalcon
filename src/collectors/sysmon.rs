use anyhow::Result;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

use crate::config::SysmonConfig;
use crate::events::{AgentInfo, CollectorStatus, ThreatEvent};

use super::health::RuntimeHealth;
use super::Collector;

/// Reads Sysmon events from the Windows Event Log channel
/// `Microsoft-Windows-Sysmon/Operational` using EvtSubscribe. Defaults to live
/// push delivery; checkpoint_path opts into acknowledged, bounded pull delivery.
///
/// Supported Sysmon Event IDs:
///   1  - Process Create
///   3  - Network Connection
///   5  - Process Terminated
///   6  - Driver Loaded
///   7  - Image Loaded
///   8  - CreateRemoteThread
///  10  - ProcessAccess
///  11  - FileCreate
///  12  - Registry Object Create/Delete
///  13  - Registry Value Set
///  14  - Registry Key Rename
///  15  - FileCreateStreamHash (ADS)
///  17  - Pipe Created
///  18  - Pipe Connected
///  22  - DNS Query
///  23  - FileDelete (archived)
///  25  - Process Tampering
///  26  - FileDeleteDetected
pub struct SysmonCollector {
    config: SysmonConfig,
    #[allow(dead_code)] // used on Windows only
    agent: AgentInfo,
    dropped: Arc<AtomicU64>,
    health: RuntimeHealth,
    #[cfg(target_os = "windows")]
    worker: Option<super::health::Worker>,
}

impl SysmonCollector {
    pub fn new(config: SysmonConfig, agent: AgentInfo) -> Self {
        Self {
            config,
            agent,
            dropped: Arc::new(AtomicU64::new(0)),
            health: RuntimeHealth::new("Sysmon"),
            #[cfg(target_os = "windows")]
            worker: None,
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::EventLog::*;

    const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

    /// Start an owned EventLog subscription with an explicit readiness barrier.
    pub fn start_subscription(
        agent: crate::events::AgentInfo,
        tx: mpsc::Sender<ThreatEvent>,
        dropped: Arc<AtomicU64>,
        health: RuntimeHealth,
        ready: tokio::sync::oneshot::Sender<()>,
        checkpoint_path: Option<std::path::PathBuf>,
    ) -> super::super::health::Worker {
        super::super::health::Worker::spawn(health, move |stop, health| {
            if let Some(path) = checkpoint_path {
                if let Err(e) = subscribe_acknowledged(&agent, tx, &stop, &health, ready, &path) {
                    tracing::error!(error=%e,"Acknowledged Sysmon subscription failed");
                    health.fail("sysmon_recovery_failed", None);
                }
            } else {
                subscribe_events(&agent, tx, stop, dropped, health, ready);
            }
        })
    }

    fn subscribe_events(
        agent: &crate::events::AgentInfo,
        tx: mpsc::Sender<ThreatEvent>,
        stop: Arc<AtomicBool>,
        dropped: Arc<AtomicU64>,
        health: RuntimeHealth,
        ready: tokio::sync::oneshot::Sender<()>,
    ) {
        let channel_wide: Vec<u16> = SYSMON_CHANNEL
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let query_wide: Vec<u16> = "*".encode_utf16().chain(std::iter::once(0)).collect();

        let ctx = Box::new(SubscribeContext {
            agent: agent.clone(),
            tx,
            dropped,
            health: health.clone(),
        });
        let ctx_ptr = Box::into_raw(ctx);

        let sub = unsafe {
            EvtSubscribe(
                EVT_HANDLE::default(), // local session
                HANDLE::default(),     // Push mode: SignalEvent MUST be null when Callback is set.
                PCWSTR(channel_wide.as_ptr()),
                PCWSTR(query_wide.as_ptr()),
                EVT_HANDLE::default(), // no bookmark — start from now
                Some(ctx_ptr as *const std::ffi::c_void),
                Some(subscription_callback),
                EvtSubscribeToFutureEvents.0 | EvtSubscribeStrict.0,
            )
        };

        let sub_handle = match sub {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(error = %e, "EvtSubscribe failed (is Sysmon installed?)");
                health.fail("sysmon_subscribe_failed", Some(e.code().0 as u32));
                unsafe {
                    drop(Box::from_raw(ctx_ptr));
                }
                return;
            }
        };

        health.running();
        health.recovery_mode("future_only");
        if ready.send(()).is_err() {
            stop.store(true, Ordering::Release);
        }
        // Wait until told to stop
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        unsafe {
            let _ = EvtClose(sub_handle);
            drop(Box::from_raw(ctx_ptr));
        }
    }

    struct SubscribeContext {
        agent: crate::events::AgentInfo,
        tx: mpsc::Sender<ThreatEvent>,
        dropped: Arc<AtomicU64>,
        health: RuntimeHealth,
    }

    unsafe extern "system" fn subscription_callback(
        action: EVT_SUBSCRIBE_NOTIFY_ACTION,
        usercontext: *const std::ffi::c_void,
        event: EVT_HANDLE,
    ) -> u32 {
        let ctx = unsafe { &*(usercontext as *const SubscribeContext) };
        if action == EvtSubscribeActionError {
            ctx.health
                .fail("sysmon_subscription_error", Some(event.0 as usize as u32));
            return 0;
        }
        if action != EvtSubscribeActionDeliver {
            return 0;
        }

        // No Rust panic may unwind across the Windows callback ABI.
        let mapped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            render_and_map(event, &ctx.agent)
        }));
        if let Ok(Some(te)) = mapped {
            ctx.health.decoded(
                matches!(te.data, crate::events::EventData::NativeTelemetry { .. }),
                te.provenance.as_ref().is_some_and(|p| !p.issues.is_empty()),
            );
            if let Err(_) = ctx.tx.try_send(te) {
                let n = ctx.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_power_of_two() || n % 1000 == 0 {
                    tracing::warn!(
                        total_dropped = n,
                        "Sysmon events dropped due to channel backpressure"
                    );
                }
            }
        } else {
            ctx.health.lost_before_queue();
            if mapped.is_err() {
                ctx.health.fail("sysmon_callback_panic", None);
            }
        }
        0
    }

    /// Render a Sysmon event to XML and map it to a ThreatEvent.
    fn render_and_map(evt: EVT_HANDLE, agent: &crate::events::AgentInfo) -> Option<ThreatEvent> {
        let xml = render_event_xml(evt)?;
        let parsed = super::super::sysmon_parser::parse_sysmon_xml(&xml)?;
        super::super::sysmon_parser::map_to_threat_event(&parsed, agent)
    }

    /// Render the event as XML via EvtRender.
    fn render_event_xml(evt: EVT_HANDLE) -> Option<String> {
        render_xml(evt, EvtRenderEventXml)
    }

    fn render_xml(evt: EVT_HANDLE, flags: EVT_RENDER_FLAGS) -> Option<String> {
        let mut buf_size = 0u32;
        let mut prop_count = 0u32;

        // First call to get required buffer size
        let _ = unsafe {
            EvtRender(
                EVT_HANDLE::default(),
                evt,
                flags.0,
                0,
                None,
                &mut buf_size,
                &mut prop_count,
            )
        };

        if buf_size == 0 || buf_size > 2 * 1024 * 1024 {
            return None;
        }

        let mut buf = vec![0u16; (buf_size as usize) / 2 + 1];
        let result = unsafe {
            EvtRender(
                EVT_HANDLE::default(),
                evt,
                flags.0,
                buf_size,
                Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
                &mut buf_size,
                &mut prop_count,
            )
        };

        if result.is_err() {
            return None;
        }

        // Find null terminator
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16(&buf[..len]).ok()
    }

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
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }

    /// Pull mode owns every native handle on one worker, applies backpressure,
    /// and advances a strict bookmark only after the sink's group-commit ACK.
    fn subscribe_acknowledged(
        agent: &AgentInfo,
        tx: mpsc::Sender<ThreatEvent>,
        stop: &AtomicBool,
        health: &RuntimeHealth,
        ready: tokio::sync::oneshot::Sender<()>,
        path: &std::path::Path,
    ) -> Result<()> {
        use anyhow::Context;
        use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT};
        use windows::Win32::System::Threading::CreateEventW;
        let mut store = crate::checkpoint::Checkpoint::open(path, agent.agent_id)?;
        let saved = store.load()?;
        let analysis = store.load_analysis()?;
        let mut restore = saved.as_ref().map(|_| analysis);
        let saved_wide: Option<Vec<u16>> = saved
            .as_ref()
            .map(|s| s.bookmark.encode_utf16().chain(Some(0)).collect());
        let bookmark = EventHandle(unsafe {
            EvtCreateBookmark(
                saved_wide
                    .as_ref()
                    .map_or(PCWSTR::null(), |s| PCWSTR(s.as_ptr())),
            )
        }?);
        let signal = SignalHandle(unsafe { CreateEventW(None, true, false, None) }?);
        let channel: Vec<u16> = SYSMON_CHANNEL.encode_utf16().chain(Some(0)).collect();
        if let Some(position) = &saved {
            verify_bookmark_record(&channel, bookmark.0, &position.anchor, agent)?;
        }
        let flags = if saved.is_some() {
            EvtSubscribeStartAfterBookmark.0
        } else {
            EvtSubscribeStartAtOldestRecord.0
        };
        let subscription=EventHandle(unsafe {EvtSubscribe(EVT_HANDLE::default(),signal.0,PCWSTR(channel.as_ptr()),PCWSTR::null(),
            if saved.is_some() {bookmark.0} else {EVT_HANDLE::default()},None,None,flags|EvtSubscribeStrict.0)}
            .context("strict Sysmon subscription failed; a missing/stale bookmark is NOT reset automatically")?);
        health.running();
        health.recovery_mode("acknowledged_file_checkpoint");
        if ready.send(()).is_err() {
            return Ok(());
        }
        while !stop.load(Ordering::Acquire) {
            let mut handles = [0isize; 32];
            let mut count = 0;
            let next = unsafe { EvtNext(subscription.0, &mut handles, 0, 0, &mut count) };
            // Own all returned handles even when Windows reports an error.
            let events: Vec<EventHandle> = handles
                .into_iter()
                .filter(|h| *h != 0)
                .map(|h| EventHandle(EVT_HANDLE(h)))
                .collect();
            if let Err(e) = next {
                if events.is_empty()
                    && (e.code() == windows::core::HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0)
                        || e.code() == windows::core::HRESULT::from_win32(ERROR_TIMEOUT.0))
                {
                    if !crate::collectors::eventlog::wait_for_events(signal.0, stop)
                        .context("waiting for Sysmon signal failed")?
                    {
                        return Ok(());
                    }
                    continue;
                }
                return Err(e).context("EvtNext failed; refusing to advance source checkpoint");
            }
            anyhow::ensure!(
                count > 0 && count as usize == events.len(),
                "invalid EventLog batch size"
            );
            let mut normalized = Vec::with_capacity(events.len());
            for handle in &events {
                let Some(event) = render_and_map(handle.0, agent) else {
                    health.lost_before_queue();
                    anyhow::bail!("Sysmon render/parse failed; checkpoint held before this batch");
                };
                health.decoded(
                    matches!(event.data, crate::events::EventData::NativeTelemetry { .. }),
                    event
                        .provenance
                        .as_ref()
                        .is_some_and(|p| !p.issues.is_empty()),
                );
                normalized.push(event);
            }
            unsafe { EvtUpdateBookmark(bookmark.0, events.last().unwrap().0) }?;
            let bookmark_xml = render_xml(bookmark.0, EvtRenderBookmark)
                .context("cannot render Sysmon bookmark")?;
            let position = crate::checkpoint::Position {
                bookmark: bookmark_xml,
                anchor: crate::checkpoint::SourceAnchor::from_event(normalized.last().unwrap())?,
            };
            drop(events);
            let (receipts, completion) =
                crate::delivery::Receipt::with_restore(normalized.len(), restore.take());
            for (mut event, receipt) in normalized.into_iter().zip(receipts) {
                event.delivery = Some(receipt);
                if tx.blocking_send(event).is_err() {
                    // Source remains before the uncommitted batch. Shutdown
                    // rejects new sends but does not lose the retained OS records.
                    if stop.load(Ordering::Acquire) || tx.is_closed() {
                        stop.store(true, Ordering::Release);
                        return Ok(());
                    }
                    anyhow::bail!("Sysmon delivery queue closed");
                }
            }
            loop {
                match completion.recv_timeout(std::time::Duration::from_millis(100)) {
                    Ok(crate::delivery::DeliveryResult::Committed(delta)) => {
                        store.commit(&position, &delta)?;
                        health.checkpoint_committed(count as u64);
                        break;
                    }
                    Ok(crate::delivery::DeliveryResult::Failed) => anyhow::bail!(
                        "sink did not durably commit Sysmon batch; bookmark unchanged"
                    ),
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        if stop.load(Ordering::Acquire) {
                            return Ok(());
                        }
                        anyhow::bail!("Sysmon acknowledgement channel closed without commit");
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if stop.load(Ordering::Acquire) {
                            return Ok(());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn verify_bookmark_record(
        channel: &[u16],
        bookmark: EVT_HANDLE,
        expected: &crate::checkpoint::SourceAnchor,
        agent: &AgentInfo,
    ) -> Result<()> {
        use anyhow::Context;
        // EvtQuery/EvtSeek/EvtNext handles stay on this worker thread.
        let query = EventHandle(unsafe {
            EvtQuery(
                EVT_HANDLE::default(),
                PCWSTR(channel.as_ptr()),
                PCWSTR::null(),
                EvtQueryChannelPath.0,
            )
        }?);
        unsafe {
            EvtSeek(
                query.0,
                0,
                bookmark,
                0,
                EvtSeekRelativeToBookmark.0 | EvtSeekStrict.0,
            )
        }
        .context("bookmarked source record no longer exists; refusing silent recovery reset")?;
        let mut handles = [0isize; 1];
        let mut count = 0;
        let result = unsafe { EvtNext(query.0, &mut handles, 1000, 0, &mut count) };
        let events: Vec<_> = handles
            .into_iter()
            .filter(|h| *h != 0)
            .map(|h| EventHandle(EVT_HANDLE(h)))
            .collect();
        result?;
        anyhow::ensure!(
            count == 1 && events.len() == 1,
            "bookmarked source record unavailable"
        );
        let event =
            render_and_map(events[0].0, agent).context("cannot verify bookmarked source record")?;
        anyhow::ensure!(crate::checkpoint::SourceAnchor::from_event(&event)?==*expected,
            "bookmarked record identity changed (channel cleared/replaced?); refusing to skip source evidence");
        Ok(())
    }

    #[cfg(test)]
    mod windows_tests {
        use super::*;
        use crate::checkpoint::{Checkpoint, Position, SourceAnchor};
        use crate::events::{CollectorState, EventData, EventSource};
        use crate::output::FileSink;
        use anyhow::Context;
        use std::time::Duration;

        fn agent() -> AgentInfo {
            AgentInfo {
                hostname: "Sysmon-Smoke-Test".into(),
                agent_id: uuid::Uuid::new_v4(),
            }
        }

        fn benign_child() -> Result<u32> {
            let mut child = std::process::Command::new("cmd.exe")
                .args(["/d", "/c", "exit", "0"])
                .spawn()?;
            let pid = child.id();
            anyhow::ensure!(child.wait()?.success(), "benign child failed");
            Ok(pid)
        }

        fn is_child(event: &ThreatEvent, pid: u32) -> bool {
            matches!(&event.data,EventData::ProcessCreate {pid:found,image_path,..}
                if *found==pid && image_path.to_ascii_lowercase().ends_with("cmd.exe"))
        }

        #[tokio::test]
        #[ignore = "requires an elevated Windows lab with preinstalled Sysmon and ProcessCreate enabled"]
        async fn windows_sysmon_push_process_smoke() -> Result<()> {
            let mut collector = SysmonCollector::new(
                SysmonConfig {
                    enabled: true,
                    checkpoint_path: None,
                },
                agent(),
            );
            let (tx, mut rx) = mpsc::channel(10_000);
            collector.start(tx).await?;
            let result = tokio::time::timeout(Duration::from_secs(15), async {
                let pid = benign_child()?;
                while let Some(event) = rx.recv().await {
                    if is_child(&event, pid) {
                        anyhow::ensure!(
                            matches!(event.source, EventSource::Sysmon { event_id: 1 }),
                            "wrong source"
                        );
                        let p = event.provenance.as_ref().context("missing provenance")?;
                        anyhow::ensure!(
                            p.original_time && p.issues.is_empty(),
                            "missing source evidence: {:?}",
                            p.issues
                        );
                        anyhow::ensure!(
                            p.process_guid.is_some_and(|g| !g.is_nil()),
                            "missing ProcessGuid"
                        );
                        SourceAnchor::from_event(&event)?;
                        anyhow::ensure!(
                            (event.observed_at.context("missing observation time")?
                                - event.timestamp)
                                .num_seconds()
                                .abs()
                                < 30,
                            "unexpected timestamp"
                        );
                        return Ok(());
                    }
                }
                anyhow::bail!("Sysmon stream ended without the benign child");
            })
            .await;
            let live = collector.status().unwrap();
            collector.stop().await?;
            result.context("Sysmon child observation timed out")??;
            anyhow::ensure!(
                live.state == CollectorState::Running && live.queue_events_dropped == 0,
                "unhealthy Sysmon collector: {live:?}"
            );
            anyhow::ensure!(
                collector.status().unwrap().state == CollectorState::Stopped,
                "collector did not stop"
            );
            Ok(())
        }

        // Read one existing record to seed this test's private cursor. Does not
        // clear the channel, replace Sysmon policy, or drain an entire host log.
        fn latest_position(agent: &AgentInfo) -> Result<Position> {
            let channel: Vec<u16> = SYSMON_CHANNEL.encode_utf16().chain(Some(0)).collect();
            let query = EventHandle(unsafe {
                EvtQuery(
                    EVT_HANDLE::default(),
                    PCWSTR(channel.as_ptr()),
                    PCWSTR::null(),
                    EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
                )
            }?);
            let mut handles = [0isize; 1];
            let mut count = 0;
            let result = unsafe { EvtNext(query.0, &mut handles, 1000, 0, &mut count) };
            let events: Vec<_> = handles
                .into_iter()
                .filter(|h| *h != 0)
                .map(|h| EventHandle(EVT_HANDLE(h)))
                .collect();
            result.context("test requires at least one existing Sysmon event")?;
            anyhow::ensure!(count == 1 && events.len() == 1, "missing Sysmon event");
            let event = render_and_map(events[0].0, agent).context("cannot parse seed event")?;
            let bookmark = EventHandle(unsafe { EvtCreateBookmark(PCWSTR::null()) }?);
            unsafe { EvtUpdateBookmark(bookmark.0, events[0].0) }?;
            Ok(Position {
                bookmark: render_xml(bookmark.0, EvtRenderBookmark)
                    .context("cannot render bookmark")?,
                anchor: SourceAnchor::from_event(&event)?,
            })
        }

        async fn write_and_ack(
            event: ThreatEvent,
            sink: &mut FileSink,
            cache: &mut crate::process_cache::ProcessCache,
            detector: &mut crate::detection::Detector,
        ) -> Result<bool> {
            let receipt = event
                .delivery
                .as_ref()
                .context("missing delivery receipt")?
                .clone();
            crate::sensor::deliver(event, cache, detector, sink).await?;
            Ok(receipt.was_committed())
        }

        #[tokio::test]
        #[ignore = "requires an elevated Windows lab with preinstalled Sysmon; uses private temporary checkpoint/output"]
        async fn windows_sysmon_unacknowledged_restart_smoke() -> Result<()> {
            let agent = agent();
            let dir = tempfile::tempdir()?;
            let checkpoint_path = dir.path().join("sysmon.db");
            let seed = latest_position(&agent)?;
            {
                let mut store = Checkpoint::open(&checkpoint_path, agent.agent_id)?;
                store.save(&seed)?;
            }
            let config = SysmonConfig {
                enabled: true,
                checkpoint_path: Some(checkpoint_path.clone()),
            };
            let mut sink = FileSink::new(&crate::config::OutputConfig {
                path: dir.path().join("events.jsonl"),
                rotation_size_mb: 0,
                ..Default::default()
            })?;
            let mut first = SysmonCollector::new(config.clone(), agent.clone());
            let (tx, mut rx) = mpsc::channel(128);
            first.start(tx).await?;
            let mut cache = crate::process_cache::ProcessCache::new(100);
            let mut detector = crate::detection::Detector::default();
            let interrupted = tokio::time::timeout(Duration::from_secs(20), async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                anyhow::ensure!(
                    first.status().unwrap().state == CollectorState::Running,
                    "Sysmon pull subscription failed while idle"
                );
                let pid = benign_child()?;
                while let Some(event) = rx.recv().await {
                    if is_child(&event, pid) {
                        // Deliberately withhold this receipt. The native cursor
                        // must stay before its batch, even if prior writes worked.
                        let anchor = SourceAnchor::from_event(&event)?;
                        return Ok::<_, anyhow::Error>((anchor, event));
                    }
                    write_and_ack(event, &mut sink, &mut cache, &mut detector).await?;
                }
                anyhow::bail!("stream ended before interruption point");
            })
            .await;
            first.stop().await?;
            drop(rx);
            let (expected, held_event) = interrupted.context("interruption point timed out")??;
            drop(held_event);
            let before = Checkpoint::open(&checkpoint_path, agent.agent_id)?
                .load()?
                .context("checkpoint missing")?;
            anyhow::ensure!(
                before.anchor.record_id < expected.record_id,
                "unacknowledged record was checkpointed"
            );

            let mut second = SysmonCollector::new(config, agent.clone());
            let (tx, mut rx) = mpsc::channel(128);
            second.start(tx).await?;
            let mut cache = crate::process_cache::ProcessCache::new(100);
            let mut detector = crate::detection::Detector::default();
            let replay = tokio::time::timeout(Duration::from_secs(20), async {
                let mut found = false;
                let mut processed = 0;
                while let Some(event) = rx.recv().await {
                    processed += 1;
                    if SourceAnchor::from_event(&event)? == expected {
                        found = true;
                    }
                    if write_and_ack(event, &mut sink, &mut cache, &mut detector).await? && found {
                        while second.status().unwrap().checkpoint_committed_events < processed {
                            anyhow::ensure!(
                                second.status().unwrap().state != CollectorState::Error,
                                "checkpoint worker failed"
                            );
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        return Ok::<_, anyhow::Error>(());
                    }
                }
                anyhow::bail!("unacknowledged source record was not replayed");
            })
            .await;
            tokio::time::sleep(Duration::from_millis(500)).await;
            let live = second.status().unwrap();
            second.stop().await?;
            drop(rx);
            replay.context("resume/replay timed out")??;
            anyhow::ensure!(
                live.state == CollectorState::Running,
                "Sysmon pull subscription failed after draining replay: {live:?}"
            );
            anyhow::ensure!(
                detector.stats.state_restored,
                "persisted analysis was not restored"
            );
            let after = Checkpoint::open(&checkpoint_path, agent.agent_id)?
                .load()?
                .context("checkpoint missing")?;
            anyhow::ensure!(
                after.anchor.record_id >= expected.record_id,
                "replayed record not committed"
            );
            Ok(())
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {}

#[async_trait]
impl Collector for SysmonCollector {
    fn name(&self) -> &str {
        "Sysmon"
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

    async fn start(&mut self, _tx: mpsc::Sender<ThreatEvent>) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            if self.worker.is_some() {
                anyhow::bail!("Sysmon collector already started");
            }
            self.dropped.store(0, Ordering::Relaxed);
            self.health.starting();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            self.worker = Some(platform::start_subscription(
                self.agent.clone(),
                _tx,
                self.dropped.clone(),
                self.health.clone(),
                ready_tx,
                self.config.checkpoint_path.clone(),
            ));
            // Report successful start only after the native subscription exists.
            // Loading bounded persisted analysis can take longer than creating
            // a live-only subscription, especially on cold disks.
            let ready_timeout = if self.config.checkpoint_path.is_some() {
                30
            } else {
                5
            };
            if !matches!(
                tokio::time::timeout(std::time::Duration::from_secs(ready_timeout), ready_rx).await,
                Ok(Ok(()))
            ) {
                if self.health.snapshot(0).state != crate::events::CollectorState::Error {
                    self.health.fail("sysmon_start_timeout", None);
                }
                if let Some(mut worker) = self.worker.take() {
                    let _ = worker.stop().await;
                }
                anyhow::bail!("Sysmon subscription did not become ready; see collector health");
            }
            info!(
                checkpoint = self.config.checkpoint_path.is_some(),
                "Sysmon subscription ready"
            );
        }

        #[cfg(not(target_os = "windows"))]
        tracing::warn!("Sysmon collector is only available on Windows");

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        if let Some(mut worker) = self.worker.take() {
            worker.stop().await?;
        }

        info!("Sysmon collector stopped");
        Ok(())
    }

    fn dropped_events(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}
