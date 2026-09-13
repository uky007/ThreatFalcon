//! Only the small private bridge ABI crosses FFI; Apple SDK structs stay in C.
use std::{
    ffi::{c_char, c_void, CStr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use super::RuntimeHealth;
use crate::{events::*, macos_events::*};

#[derive(Clone, Copy)]
#[repr(C)]
struct NativeString {
    data: *const u8,
    length: usize,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct NativeFile {
    path: NativeString,
    inode: u64,
    device: i32,
    mode: u32,
    path_truncated: u32,
    present: u32,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct NativeProcess {
    identity: MacosIdentity,
    parent: MacosIdentity,
    responsible: MacosIdentity,
    executable: NativeFile,
    signing_id: NativeString,
    team_id: NativeString,
    cdhash: [u8; 20],
    ppid: u32,
    original_ppid: u32,
    codesigning_flags: u32,
    is_platform_binary: u32,
    is_es_client: u32,
    has_parent: u32,
    has_start_time: u32,
    present: u32,
    start_seconds: i64,
    start_microseconds: i64,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct NativeRecord {
    abi_version: u32,
    message_version: u32,
    native_event_type: u32,
    kind: u32,
    seconds: i64,
    nanoseconds: i64,
    mach_time: u64,
    seq_num: u64,
    global_seq_num: u64,
    has_seq_num: u32,
    has_global_seq_num: u32,
    actor: NativeProcess,
    target: NativeProcess,
    file: NativeFile,
    destination: NativeFile,
    destination_name: NativeString,
    destination_is_new_path: u32,
    modified: u32,
    has_mapped_writable: u32,
    mapped_writable: u32,
    exit_status: i32,
    result_type: u32,
    result_value: u32,
}
type Callback = unsafe extern "C" fn(*mut c_void, *const NativeRecord);
extern "C" {
    fn tf_es_boot_uuid(out: *mut c_char, capacity: usize) -> i32;
    fn tf_es_open(handle: *mut *mut c_void, callback: Callback, context: *mut c_void) -> i32;
    fn tf_es_close(handle: *mut c_void) -> i32;
    #[cfg(test)]
    fn tf_es_test_fixture(callback: Callback, context: *mut c_void, kind: u32, version: u32);
    #[cfg(test)]
    fn tf_es_record_size() -> usize;
    #[cfg(test)]
    fn tf_es_record_alignment() -> usize;
}

fn boot_uuid() -> Result<Uuid> {
    let mut buffer = [0 as c_char; 64];
    // SAFETY: writable bounded buffer; bridge verifies null termination.
    ensure!(
        unsafe { tf_es_boot_uuid(buffer.as_mut_ptr(), buffer.len()) } == 0,
        "boot UUID unavailable"
    );
    let boot = Uuid::parse_str(unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_str()?)?;
    ensure!(!boot.is_nil(), "boot UUID is nil");
    Ok(boot)
}

fn error_code(result: i32) -> &'static str {
    match result {
        0 => "es_ready",
        1 => "es_invalid_argument",
        2 => "es_internal_error",
        3 => "es_not_entitled",
        4 => "es_not_permitted",
        5 => "es_not_privileged",
        6 => "es_too_many_clients",
        1001 => "es_self_mute_failed",
        1002 => "es_subscribe_failed",
        _ => "es_open_failed",
    }
}

pub(super) fn run(
    agent: AgentInfo,
    tx: mpsc::Sender<ThreatEvent>,
    drops: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    health: RuntimeHealth,
    ready: oneshot::Sender<Result<(), ()>>,
) {
    let boot = match boot_uuid() {
        Ok(boot) => boot,
        Err(_) => {
            health.fail("es_boot_identity_failed", None);
            let _ = ready.send(Err(()));
            return;
        }
    };
    let session = Uuid::new_v4();
    let stats = EndpointSecurityStats {
        collection_session_uuid: session,
        ..Default::default()
    };
    health.endpoint_security(stats.clone());
    let mut context = Box::new(Context {
        agent,
        boot,
        session,
        tx: Mutex::new(Some(tx)),
        drops,
        health: health.clone(),
        sequences: Mutex::new(Sequences {
            stats,
            ..Default::default()
        }),
    });
    let mut handle = std::ptr::null_mut();
    // SAFETY: Box address stays stable and live through deletion of the client.
    // The serial ES callback borrows SDK data only for the callback duration.
    let result = unsafe {
        tf_es_open(
            &mut handle,
            callback,
            (&mut *context as *mut Context).cast(),
        )
    };
    if result == 0 {
        health.running();
        if ready.send(Ok(())).is_ok() {
            while !stop.load(Ordering::Acquire) && health.snapshot(0).state != CollectorState::Error
            {
                std::thread::park_timeout(std::time::Duration::from_millis(50));
            }
        }
    } else {
        health.fail(error_code(result), Some(result as u32));
        let _ = ready.send(Err(()));
    }
    // Creation and deletion occur on this same OS thread, as Apple requires.
    if !handle.is_null() && unsafe { tf_es_close(handle) } != 0 {
        health.fail("es_delete_failed", None);
        // A leaked callback must not hold the sensor queue open forever.
        context.tx.lock().unwrap_or_else(|e| e.into_inner()).take();
        // Apple documents resources may leak on delete failure. Avoid releasing
        // a callback context that a leaked native handler might still reference.
        std::mem::forget(context);
    }
}

struct Context {
    agent: AgentInfo,
    boot: Uuid,
    session: Uuid,
    tx: Mutex<Option<mpsc::Sender<ThreatEvent>>>,
    drops: Arc<AtomicU64>,
    health: RuntimeHealth,
    sequences: Mutex<Sequences>,
}

#[derive(Default)]
struct Sequences {
    global: Option<u64>,
    per_kind: [Option<u64>; 8],
    stats: EndpointSecurityStats,
}
impl Sequences {
    fn observe(&mut self, record: &NativeRecord) {
        // Do not add per-type gaps to global gaps: they describe the same loss.
        let stream = if record.has_global_seq_num != 0 {
            Some((&mut self.global, record.global_seq_num))
        } else if record.has_seq_num != 0 && (1..=8).contains(&record.kind) {
            Some((&mut self.per_kind[record.kind as usize - 1], record.seq_num))
        } else {
            None
        };
        if let Some((previous, next)) = stream {
            if let Some(last) = *previous {
                if next <= last {
                    self.stats.sequence_discontinuities =
                        self.stats.sequence_discontinuities.saturating_add(1);
                } else {
                    self.stats.sequence_drops =
                        self.stats.sequence_drops.saturating_add(next - last - 1);
                }
            }
            // First event establishes a baseline; don't guess the initial value.
            *previous = Some(next);
        } else {
            self.stats.sequence_unavailable = self.stats.sequence_unavailable.saturating_add(1);
        }
    }
}

unsafe extern "C" fn callback(raw: *mut c_void, record: *const NativeRecord) {
    if raw.is_null() || record.is_null() {
        return;
    }
    // SAFETY: pointers owned by run() / C emit(); no native pointer escapes.
    let context = &*raw.cast::<Context>();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let record = &*record;
        {
            let mut seq = context.sequences.lock().unwrap_or_else(|e| e.into_inner());
            seq.observe(record);
            context.health.endpoint_security(seq.stats.clone());
        }
        match convert(record, context) {
            Ok(event) => {
                let failed = matches!(&event.data, EventData::MacosEndpointSecurity { record } if !record.issues.is_empty());
                context.health.decoded(false, failed);
                let sent = context
                    .tx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .is_some_and(|tx| tx.try_send(event).is_ok());
                if !sent {
                    let _ = context
                        .drops
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                            Some(n.saturating_add(1))
                        });
                }
            }
            Err(_) => context.health.lost_before_queue(),
        }
    }));
    if result.is_err() {
        context.health.lost_before_queue();
        context.health.fail("es_callback_panic", None);
    }
}

// Hard caps bound callback allocation even with maliciously long path/name data.
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_RECORD_TEXT_BYTES: usize = 32 * 1024;
struct Decoder {
    remaining: usize,
    issues: Vec<String>,
}
impl Decoder {
    unsafe fn text(&mut self, raw: NativeString) -> MacosText {
        let length = raw.length.min(MAX_TEXT_BYTES).min(self.remaining);
        let missing = length != 0 && raw.data.is_null();
        let bytes = if length == 0 || missing {
            &[][..]
        } else {
            std::slice::from_raw_parts(raw.data, length)
        };
        self.remaining -= bytes.len();
        let truncated = length != raw.length || missing;
        if truncated {
            self.issues.push("native_text_truncated_or_missing".into());
        }
        let (value, invalid_utf8_hex) = match std::str::from_utf8(bytes) {
            Ok(value) => (value.to_owned(), None),
            Err(_) => {
                self.issues.push("native_text_invalid_utf8".into());
                (
                    String::from_utf8_lossy(bytes).into_owned(),
                    Some(hex(bytes)),
                )
            }
        };
        MacosText {
            value,
            invalid_utf8_hex,
            truncated,
        }
    }
    unsafe fn file(&mut self, raw: &NativeFile) -> Option<MacosFile> {
        if raw.present == 0 {
            return None;
        }
        if raw.path_truncated != 0 {
            self.issues.push("native_path_truncated_by_os".into());
        }
        Some(MacosFile {
            path: self.text(raw.path),
            path_truncated_by_os: raw.path_truncated != 0,
            inode: raw.inode,
            device: raw.device,
            mode: raw.mode,
        })
    }
    unsafe fn process(&mut self, raw: &NativeProcess) -> Result<MacosProcess> {
        ensure!(raw.present != 0, "missing native process");
        let start_time = if raw.has_start_time != 0 {
            let valid = (0..1_000_000).contains(&raw.start_microseconds);
            let value = valid
                .then(|| {
                    DateTime::from_timestamp(
                        raw.start_seconds,
                        raw.start_microseconds as u32 * 1000,
                    )
                })
                .flatten();
            if value.is_none() {
                self.issues.push("invalid_process_start_time".into());
            }
            value
        } else {
            None
        };
        Ok(MacosProcess {
            identity: raw.identity,
            parent: (raw.has_parent != 0).then_some(raw.parent),
            responsible: (raw.has_parent != 0).then_some(raw.responsible),
            ppid: raw.ppid,
            original_ppid: raw.original_ppid,
            start_time,
            executable: self
                .file(&raw.executable)
                .ok_or_else(|| anyhow::anyhow!("missing executable"))?,
            codesigning_flags: raw.codesigning_flags,
            is_platform_binary: raw.is_platform_binary != 0,
            is_es_client: raw.is_es_client != 0,
            cdhash: hex(&raw.cdhash),
            signing_id: self.text(raw.signing_id),
            team_id: self.text(raw.team_id),
        })
    }
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}

unsafe fn convert(raw: &NativeRecord, context: &Context) -> Result<ThreatEvent> {
    ensure!(raw.abi_version == 1, "unknown bridge ABI");
    let kind = match raw.kind {
        1 => MacosEventKind::Exec,
        2 => MacosEventKind::Fork,
        3 => MacosEventKind::Exit,
        4 => MacosEventKind::Create,
        5 => MacosEventKind::Rename,
        6 => MacosEventKind::Unlink,
        7 => MacosEventKind::Close,
        8 => MacosEventKind::Write,
        _ => anyhow::bail!("unsupported event type"),
    };
    let mut decoder = Decoder {
        remaining: MAX_RECORD_TEXT_BYTES,
        issues: vec![],
    };
    let actor = decoder.process(&raw.actor)?;
    let target = if matches!(kind, MacosEventKind::Exec | MacosEventKind::Fork) {
        Some(decoder.process(&raw.target)?)
    } else {
        None
    };
    let file = decoder.file(&raw.file);
    let destination = decoder.file(&raw.destination);
    if matches!(
        kind,
        MacosEventKind::Rename
            | MacosEventKind::Unlink
            | MacosEventKind::Close
            | MacosEventKind::Write
    ) && file.is_none()
        || kind == MacosEventKind::Create && file.is_none() && destination.is_none()
        || kind == MacosEventKind::Rename && destination.is_none()
    {
        decoder.issues.push("missing_native_file".into());
    }
    let destination_name =
        (raw.destination_is_new_path != 0).then(|| decoder.text(raw.destination_name));
    let timestamp = (0..1_000_000_000)
        .contains(&raw.nanoseconds)
        .then(|| DateTime::<Utc>::from_timestamp(raw.seconds, raw.nanoseconds as u32))
        .flatten();
    if timestamp.is_none() {
        decoder.issues.push("invalid_native_timestamp".into());
    }
    let record = MacosRecord {
        boot_session_uuid: context.boot,
        collection_session_uuid: context.session,
        message_version: raw.message_version,
        native_event_type: raw.native_event_type,
        kind,
        original_time: timestamp.is_some(),
        time_seconds: raw.seconds,
        time_nanoseconds: raw.nanoseconds,
        mach_time: raw.mach_time,
        seq_num: (raw.has_seq_num != 0).then_some(raw.seq_num),
        global_seq_num: (raw.has_global_seq_num != 0).then_some(raw.global_seq_num),
        actor,
        target,
        file,
        destination,
        destination_name,
        destination_is_new_path: raw.destination_is_new_path != 0,
        modified: (kind == MacosEventKind::Close).then_some(raw.modified != 0),
        was_mapped_writable: (kind == MacosEventKind::Close && raw.has_mapped_writable != 0)
            .then_some(raw.mapped_writable != 0),
        exit_status: (kind == MacosEventKind::Exit).then_some(raw.exit_status),
        result_type: raw.result_type,
        result_value: raw.result_value,
        issues: decoder.issues,
    };
    let subject = record.subject();
    let process_context = ProcessContext {
        process_key: subject
            .identity
            .process_key(context.agent.agent_id, context.boot),
        image_path: Some(subject.executable.path.value.clone()),
        command_line: None,
        user: Some(format!("uid:{}", subject.identity.euid)),
        integrity_level: None,
        ppid: Some(subject.ppid),
    };
    let category = if matches!(
        kind,
        MacosEventKind::Exec | MacosEventKind::Fork | MacosEventKind::Exit
    ) {
        EventCategory::Process
    } else {
        EventCategory::File
    };
    let mut event = ThreatEvent::new(
        &context.agent,
        EventSource::EndpointSecurity,
        category,
        Severity::Info,
        EventData::MacosEndpointSecurity {
            record: Box::new(record),
        },
    );
    if let Some(timestamp) = timestamp {
        event.timestamp = timestamp;
    }
    event.process_context = Some(process_context);
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(capacity: usize) -> (Context, mpsc::Receiver<ThreatEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        let health = RuntimeHealth::new("EndpointSecurity");
        health.starting();
        health.running();
        (
            Context {
                agent: AgentInfo {
                    hostname: "synthetic-mac".into(),
                    agent_id: Uuid::new_v4(),
                },
                boot: Uuid::new_v4(),
                session: Uuid::new_v4(),
                tx: Mutex::new(Some(tx)),
                drops: Default::default(),
                health,
                sequences: Default::default(),
            },
            rx,
        )
    }
    fn fixture(context: &mut Context, kind: u32, version: u32) {
        unsafe {
            tf_es_test_fixture(callback, (context as *mut Context).cast(), kind, version);
        }
    }
    #[test]
    fn sdk_bridge_all_events_and_message_versions_roundtrip() {
        assert_eq!(
            unsafe { tf_es_record_size() },
            std::mem::size_of::<NativeRecord>()
        );
        assert_eq!(
            unsafe { tf_es_record_alignment() },
            std::mem::align_of::<NativeRecord>()
        );
        for version in [1, 2, 3, 4, 5, 6, 10] {
            for kind in 1..=8 {
                let (mut ctx, mut rx) = context(1);
                fixture(&mut ctx, kind, version);
                let event = rx.try_recv().unwrap();
                assert_eq!(event.timestamp.timestamp(), 1700000001);
                assert_eq!(event.timestamp.timestamp_subsec_nanos(), 123456789);
                let serialized = serde_json::to_string(&event).unwrap();
                let decoded: ThreatEvent = serde_json::from_str(&serialized).unwrap();
                let EventData::MacosEndpointSecurity { record } = &decoded.data else {
                    panic!()
                };
                assert_eq!(record.actor.identity.pid, 123);
                assert_eq!(record.actor.identity.pidversion, 9);
                assert_eq!(record.actor.executable.inode, 42);
                assert_eq!(
                    record.actor.executable.path.value,
                    "/tmp/ThreatFalcon-日本語"
                );
                assert_eq!(record.seq_num, (version >= 2).then_some(5));
                assert_eq!(record.global_seq_num, (version >= 4).then_some(12));
                assert_eq!(record.actor.start_time.is_some(), version >= 3);
                assert_eq!(record.actor.parent.is_some(), version >= 4);
                assert!(record.issues.is_empty());
                if kind <= 2 {
                    assert_eq!(record.target.as_ref().unwrap().identity.pidversion, 10);
                    assert_eq!(
                        record.subject().identity.pid,
                        if kind == 2 { 124 } else { 123 }
                    );
                }
                if kind == 3 {
                    assert_eq!(record.exit_status, Some(256));
                }
                if kind == 5 {
                    assert_eq!(record.destination_name.as_ref().unwrap().value, "moved");
                }
                if kind == 7 {
                    assert_eq!(record.modified, Some(true));
                    assert_eq!(record.was_mapped_writable, (version >= 6).then_some(true));
                }
                assert!(decoded
                    .process_context
                    .as_ref()
                    .unwrap()
                    .command_line
                    .is_none());
                // Existing Windows enrichment must not rewrite native identity.
                let mut enriched = decoded.clone();
                crate::process_cache::ProcessCache::new(8).enrich(&mut enriched);
                assert_eq!(
                    serde_json::to_string(&decoded).unwrap(),
                    serde_json::to_string(&enriched).unwrap()
                );
            }
        }
    }
    #[test]
    fn bounded_text_preserves_invalid_utf8_and_marks_loss() {
        let bytes = [b'a', 0xff];
        let mut decoder = Decoder {
            remaining: 2,
            issues: vec![],
        };
        let text = unsafe {
            decoder.text(NativeString {
                data: bytes.as_ptr(),
                length: 2,
            })
        };
        assert_eq!(text.invalid_utf8_hex.as_deref(), Some("61ff"));
        assert!(!text.truncated);
        let text = unsafe {
            decoder.text(NativeString {
                data: bytes.as_ptr(),
                length: 2,
            })
        };
        assert!(text.truncated);
        assert!(text.value.is_empty());
    }

    #[test]
    fn denied_create_and_overwrite_rename_keep_distinct_native_destinations() {
        let (mut ctx, mut rx) = context(2);
        fixture(&mut ctx, 9, 6);
        fixture(&mut ctx, 10, 6);
        let EventData::MacosEndpointSecurity { record } = rx.try_recv().unwrap().data else {
            panic!()
        };
        assert_eq!(record.kind, MacosEventKind::Create);
        assert!(record.file.is_none());
        assert!(record.destination_is_new_path);
        assert_eq!(record.destination_name.unwrap().value, "denied");
        assert_eq!(record.result_value, 1); // ES_AUTH_RESULT_DENY, not a success claim.
        let EventData::MacosEndpointSecurity { record } = rx.try_recv().unwrap().data else {
            panic!()
        };
        assert_eq!(record.kind, MacosEventKind::Rename);
        assert!(!record.destination_is_new_path);
        assert!(record.destination_name.is_none());
        assert!(record.file.is_some() && record.destination.is_some());
    }

    #[test]
    fn native_text_limits_and_bad_source_time_remain_explicit() {
        let bytes = vec![b'x'; MAX_TEXT_BYTES + 1];
        let mut decoder = Decoder {
            remaining: MAX_RECORD_TEXT_BYTES,
            issues: vec![],
        };
        let raw = NativeString {
            data: bytes.as_ptr(),
            length: bytes.len(),
        };
        for _ in 0..2 {
            let text = unsafe { decoder.text(raw) };
            assert_eq!(text.value.len(), MAX_TEXT_BYTES);
            assert!(text.truncated);
        }
        assert!(unsafe { decoder.text(raw) }.value.is_empty());
        unsafe extern "C" fn corrupt_time(context: *mut c_void, raw: *const NativeRecord) {
            let mut record = *raw;
            record.nanoseconds = -1;
            record.actor.executable.path_truncated = 1;
            callback(context, &record);
        }
        let (mut ctx, mut rx) = context(1);
        unsafe {
            tf_es_test_fixture(corrupt_time, (&mut ctx as *mut Context).cast(), 1, 6);
        }
        let EventData::MacosEndpointSecurity { record } = rx.try_recv().unwrap().data else {
            panic!()
        };
        assert!(!record.original_time);
        assert_eq!(record.time_nanoseconds, -1);
        assert!(record
            .issues
            .iter()
            .any(|s| s == "invalid_native_timestamp"));
        assert!(record.actor.executable.path_truncated_by_os);
        assert_eq!(ctx.health.snapshot(0).decode_failures, 1);
    }
    #[test]
    fn callback_does_not_block_when_queue_is_full_or_closed() {
        let (mut ctx, rx) = context(1);
        fixture(&mut ctx, 1, 6);
        fixture(&mut ctx, 1, 6);
        assert_eq!(ctx.drops.load(Ordering::Relaxed), 1);
        drop(rx);
        fixture(&mut ctx, 1, 6);
        assert_eq!(ctx.drops.load(Ordering::Relaxed), 2);
        assert_eq!(ctx.health.snapshot(2).state, CollectorState::Degraded);
    }
    #[test]
    fn sequence_gaps_are_not_double_counted() {
        // Zeroed private POD fixture, with no dereferenced pointers.
        let mut record: NativeRecord = unsafe { std::mem::zeroed() };
        record.kind = 1;
        record.has_global_seq_num = 1;
        record.has_seq_num = 1;
        record.global_seq_num = 10;
        record.seq_num = 5;
        let mut seq = Sequences::default();
        seq.observe(&record);
        record.global_seq_num = 14;
        record.seq_num = 9;
        seq.observe(&record);
        assert_eq!(seq.stats.sequence_drops, 3);
        seq.observe(&record);
        assert_eq!(seq.stats.sequence_discontinuities, 1);
        record.has_global_seq_num = 0;
        seq.observe(&record);
        record.seq_num = 12;
        seq.observe(&record);
        assert_eq!(seq.stats.sequence_drops, 5);
        record.has_seq_num = 0;
        seq.observe(&record);
        assert_eq!(seq.stats.sequence_unavailable, 1);
    }
    #[test]
    fn boot_identity_is_stable_for_this_mac() {
        assert_eq!(boot_uuid().unwrap(), boot_uuid().unwrap());
    }

    #[tokio::test]
    async fn sdk_fixture_survives_sensor_file_output_analysis_and_index() {
        let (mut ctx, mut rx) = context(8);
        for kind in 1..=8 {
            fixture(&mut ctx, kind, 6);
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic-macos.jsonl");
        let config = crate::config::OutputConfig {
            path: path.clone(),
            ..Default::default()
        };
        let mut sink = crate::output::create_sink(&config).unwrap();
        let mut cache = crate::process_cache::ProcessCache::new(8);
        let mut detector = crate::detection::Detector::default();
        for _ in 1..=8 {
            crate::sensor::deliver(
                rx.try_recv().unwrap(),
                &mut cache,
                &mut detector,
                sink.as_mut(),
            )
            .await
            .unwrap();
        }
        sink.flush().await.unwrap();
        drop(sink);
        let content = std::fs::read_to_string(&path).unwrap();
        let report = crate::analysis::analyze(content.as_bytes()).unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.malformed_lines, 0);
        assert!(report
            .limitations
            .contains(&"macos_detection_rules_not_implemented"));
        let coverage = report.agents.get(&ctx.agent.agent_id).unwrap();
        assert_eq!(coverage.source_time_events, 8);
        assert_eq!(coverage.macos_native_identity_events, 8);
        assert_eq!(coverage.macos_event_kinds.len(), 8);
        let index = crate::index::EventIndex::open(&path).unwrap();
        assert_eq!(index.build(&path).unwrap().total_events, 8);
        assert_eq!(index.status(&path).unwrap().event_count, 8);
        let locations = index
            .query_locations(&crate::index::IndexFilter {
                pid: Some(123),
                source_type: Some("endpointsecurity".into()),
                process_key: None,
                category: None,
                rule_id: None,
                min_severity_ord: None,
                from: None,
                to: None,
                limit: None,
            })
            .unwrap();
        assert_eq!(locations.len(), 7); // Fork is indexed by child identity, not parent.
    }

    #[test]
    fn native_sequence_loss_is_visible_even_after_stop() {
        let health = RuntimeHealth::new("EndpointSecurity");
        health.starting();
        health.running();
        health.endpoint_security(EndpointSecurityStats {
            sequence_drops: 3,
            ..Default::default()
        });
        assert_eq!(health.snapshot(0).state, CollectorState::Degraded);
        health.stopped();
        assert_eq!(
            health.snapshot(0).endpoint_security.unwrap().sequence_drops,
            3
        );
    }

    #[tokio::test]
    #[ignore = "native startup failure validation; requires NON-root test process"]
    async fn macos_es_unprivileged_startup() {
        extern "C" {
            fn geteuid() -> u32;
        }
        assert_ne!(unsafe { geteuid() }, 0, "this test must run without root");
        use crate::collectors::Collector;
        let (mut ctx, _rx) = context(1);
        let mut collector = super::super::MacosCollector::new(
            crate::config::MacosConfig { enabled: true },
            ctx.agent.clone(),
        );
        let tx = ctx.tx.get_mut().unwrap().take().unwrap();
        assert!(collector.start(tx).await.is_err());
        let status = collector.status().unwrap();
        assert_eq!(status.state, CollectorState::Error);
        assert_eq!(status.error.unwrap().code, "es_not_privileged");
        assert_eq!(status.events_observed, 0);
        assert!(collector.worker.is_none());
        collector.stop().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires approved ES signing, root and Full Disk Access; observes live host metadata briefly"]
    async fn macos_es_live_smoke() {
        use crate::collectors::Collector;
        let dir = tempfile::tempdir().unwrap();
        let marker = dir
            .path()
            .canonicalize()
            .unwrap()
            .join("threatfalcon-es-smoke-日本語");
        let marker = marker.to_str().unwrap();
        let (tx, mut rx) = mpsc::channel(4096);
        let mut collector = super::super::MacosCollector::new(
            crate::config::MacosConfig { enabled: true },
            AgentInfo {
                hostname: "native-smoke".into(),
                agent_id: Uuid::new_v4(),
            },
        );
        collector
            .start(tx)
            .await
            .expect("ES startup failed: inspect signing, root and FDA");
        let observation = async {
            let mut child = tokio::process::Command::new("/usr/bin/touch")
                .arg(marker)
                .kill_on_drop(true)
                .spawn()?;
            let pid = child.id().unwrap();
            let mut exec_key = None;
            let mut file_key = None;
            let mut exit_key = None;
            while let Some(event) = rx.recv().await {
                let EventData::MacosEndpointSecurity { record } = &event.data else {
                    continue;
                };
                // Full-host events are discarded in memory; nothing is persisted
                // or printed, and assertions only concern our benign child.
                let key = event.process_context.as_ref().unwrap().process_key.clone();
                if record.kind == MacosEventKind::Exec && record.subject().identity.pid == pid {
                    ensure!(record.issues.is_empty(), "native exec quality issues");
                    exec_key = Some(key);
                } else if record.kind == MacosEventKind::Create
                    && record.actor.identity.pid == pid
                    && record.file.as_ref().is_some_and(|f| f.path.value == marker)
                {
                    file_key = Some(key);
                } else if record.kind == MacosEventKind::Exit && record.actor.identity.pid == pid {
                    exit_key = Some(key);
                }
                if exec_key.is_some() && file_key.is_some() && exit_key.is_some() {
                    ensure!(
                        exec_key == file_key && file_key == exit_key,
                        "native identity mismatch"
                    );
                    ensure!(child.wait().await?.success(), "benign touch failed");
                    return Ok::<_, anyhow::Error>(());
                }
            }
            anyhow::bail!("native event stream closed before evidence arrived")
        };
        let result = tokio::time::timeout(std::time::Duration::from_secs(15), observation).await;
        // Always request native teardown before assertions, including on timeout.
        collector.stop().await.unwrap();
        result
            .expect("native exec/create/exit evidence timed out")
            .unwrap();
        let status = collector.status().unwrap();
        assert_eq!(status.state, CollectorState::Stopped);
        assert_eq!(status.queue_events_dropped, 0);
        assert_eq!(status.decode_failures, 0);
        let stats = status.endpoint_security.unwrap();
        assert_eq!(stats.sequence_drops, 0);
        assert_eq!(stats.sequence_discontinuities, 0);
        assert_eq!(stats.sequence_unavailable, 0);
    }
    #[tokio::test]
    #[ignore = "explicit native ES permission probe; may trigger macOS permission UI; collects no subscribed events"]
    async fn macos_es_permission_probe() {
        // Deliberately don't subscribe: checks native es_new_client only via a
        // separate C probe, without enabling full-host collection.
        extern "C" {
            fn tf_es_permission_probe() -> i32;
        }
        let result = tokio::task::spawn_blocking(|| unsafe { tf_es_permission_probe() })
            .await
            .unwrap();
        eprintln!(
            "Endpoint Security native permission result: {result} ({})",
            error_code(result)
        );
        assert!((0..=6).contains(&result), "native ES cleanup failed");
    }
}
