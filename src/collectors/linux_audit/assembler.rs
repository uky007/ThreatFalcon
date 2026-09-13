use super::parser;
use crate::{events::*, linux_events::*};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAX_PENDING: usize = 256;
const MAX_RECORDS: usize = 64;
const MAX_EVENT_BYTES: usize = 32 * 1024;
const MAX_PENDING_BYTES: usize = 4 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(2);
struct Pending {
    records: Vec<AuditRecord>,
    bytes: usize,
    first: Instant,
}

pub struct Assembler {
    agent: AgentInfo,
    boot_id: Uuid,
    pending: BTreeMap<AuditStamp, Pending>,
    pending_bytes: usize,
    recent: BTreeSet<AuditStamp>,
    recent_order: VecDeque<AuditStamp>,
    pub stats: LinuxAuditStats,
}
impl Assembler {
    pub fn new(agent: AgentInfo, boot_id: Uuid) -> Self {
        Self {
            agent,
            boot_id,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            recent: BTreeSet::new(),
            recent_order: VecDeque::new(),
            stats: LinuxAuditStats {
                collection_session_uuid: Uuid::new_v4(),
                ..Default::default()
            },
        }
    }
    pub fn push(&mut self, kind: u16, payload: &[u8], now: Instant) -> Vec<ThreatEvent> {
        let mut output = self.expire(now);
        self.stats.records_received = self.stats.records_received.saturating_add(1);
        if !parser::supported(kind) {
            self.stats.records_filtered = self.stats.records_filtered.saturating_add(1);
            return output;
        }
        let (stamp, record) = match parser::parse(kind, payload) {
            Ok(record) => record,
            Err(_) => {
                self.stats.malformed_records = self.stats.malformed_records.saturating_add(1);
                return output; // Never log raw payloads or parser input on error.
            }
        };
        self.stats.fields_omitted = self
            .stats
            .fields_omitted
            .saturating_add(record.omitted_fields.len() as u64);
        if self.recent.contains(&stamp) {
            self.stats.late_records = self.stats.late_records.saturating_add(1);
            return output;
        }
        let bytes = serde_json::to_vec(&record)
            .map(|v| v.len())
            .unwrap_or(MAX_EVENT_BYTES + 1);
        while !self.pending.is_empty()
            && ((!self.pending.contains_key(&stamp) && self.pending.len() >= MAX_PENDING)
                || self.pending_bytes + bytes > MAX_PENDING_BYTES)
        {
            let oldest = self
                .pending
                .iter()
                .min_by_key(|(_, v)| v.first)
                .unwrap()
                .0
                .clone();
            output.push(self.finish(&oldest, AuditCompletion::Capacity));
        }
        // If global pressure just evicted this event, keep subsequent fragments
        // out of a new apparently complete event with the same identity.
        if self.recent.contains(&stamp) {
            self.stats.late_records = self.stats.late_records.saturating_add(1);
            return output;
        }
        if bytes > MAX_EVENT_BYTES {
            self.stats.malformed_records = self.stats.malformed_records.saturating_add(1);
            return output;
        }
        if self
            .pending
            .get(&stamp)
            .is_some_and(|v| v.records.len() >= MAX_RECORDS || v.bytes + bytes > MAX_EVENT_BYTES)
        {
            output.push(self.finish(&stamp, AuditCompletion::Capacity));
            self.stats.late_records = self.stats.late_records.saturating_add(1);
            return output;
        }
        let pending = self
            .pending
            .entry(stamp.clone())
            .or_insert_with(|| Pending {
                records: vec![],
                bytes: 0,
                first: now,
            });
        pending.bytes += bytes;
        self.pending_bytes += bytes;
        pending.records.push(record);
        if kind == 1320 || parser::standalone(kind) {
            output.push(self.finish(
                &stamp,
                if kind == 1320 {
                    AuditCompletion::EndOfEvent
                } else {
                    AuditCompletion::Standalone
                },
            ));
        }
        output
    }
    pub fn expire(&mut self, now: Instant) -> Vec<ThreatEvent> {
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, v)| now.saturating_duration_since(v.first) >= TIMEOUT)
            .map(|(k, _)| k.clone())
            .collect();
        expired
            .iter()
            .map(|k| self.finish(k, AuditCompletion::Timeout))
            .collect()
    }
    pub fn shutdown(&mut self) -> Vec<ThreatEvent> {
        let keys: Vec<_> = self.pending.keys().cloned().collect();
        keys.iter()
            .map(|k| self.finish(k, AuditCompletion::Shutdown))
            .collect()
    }
    fn finish(&mut self, stamp: &AuditStamp, completion: AuditCompletion) -> ThreatEvent {
        let pending = self.pending.remove(stamp).unwrap();
        self.pending_bytes -= pending.bytes;
        self.recent.insert(stamp.clone());
        self.recent_order.push_back(stamp.clone());
        if self.recent_order.len() > 1024 {
            self.recent.remove(&self.recent_order.pop_front().unwrap());
        }
        let mut issues = Vec::new();
        if !matches!(
            completion,
            AuditCompletion::EndOfEvent | AuditCompletion::Standalone
        ) {
            self.stats.events_without_eoe = self.stats.events_without_eoe.saturating_add(1);
            issues.push("audit_completion_without_eoe".into());
        }
        if completion == AuditCompletion::Capacity {
            self.stats.capacity_flushes = self.stats.capacity_flushes.saturating_add(1);
        }
        let syscalls: Vec<_> = pending
            .records
            .iter()
            .filter(|r| r.native_type == 1300)
            .collect();
        if syscalls.len() > 1 {
            issues.push("audit_duplicate_syscall_record".into());
        }
        if completion != AuditCompletion::Standalone && syscalls.is_empty() {
            issues.push("audit_missing_syscall_record".into());
        }
        let paths: Vec<_> = pending
            .records
            .iter()
            .filter(|r| r.native_type == 1302)
            .collect();
        if let Some(syscall) = syscalls.first() {
            match syscall
                .fields
                .get("items")
                .and_then(|v| v.value.parse::<usize>().ok())
            {
                Some(items) if items == paths.len() => {}
                Some(_) => issues.push("audit_path_count_mismatch".into()),
                None => issues.push("audit_path_count_unavailable".into()),
            }
        }
        let mut path_items = BTreeSet::new();
        for path in paths {
            match path
                .fields
                .get("item")
                .and_then(|v| v.value.parse::<usize>().ok())
            {
                Some(item) if path_items.insert(item) => {}
                _ => issues.push("audit_invalid_or_duplicate_path_item".into()),
            }
        }
        // An EOE marker is not proof that all prior records reached this reader.
        let data = LinuxAuditEvent {
            boot_id: Some(self.boot_id),
            collection_session_uuid: self.stats.collection_session_uuid,
            transport: "netlink_multicast".into(),
            stamp: stamp.clone(),
            completion,
            records: pending.records,
            issues,
        };
        let category = if data.records.iter().any(|r| r.native_type == 1309) {
            EventCategory::Process
        } else if data.records.iter().any(|r| r.native_type == 1302) {
            EventCategory::File
        } else {
            EventCategory::Telemetry
        };
        let mut event = ThreatEvent::new(
            &self.agent,
            EventSource::LinuxAudit,
            category,
            Severity::Info,
            EventData::LinuxAudit {
                record: Box::new(data),
            },
        );
        event.timestamp =
            chrono::DateTime::from_timestamp(stamp.seconds, stamp.nanoseconds).unwrap();
        // No stable process identity in these audit records: context stays None.
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn assembler() -> Assembler {
        Assembler::new(
            AgentInfo {
                hostname: "synthetic-linux".into(),
                agent_id: Uuid::new_v4(),
            },
            Uuid::new_v4(),
        )
    }
    fn add(
        a: &mut Assembler,
        kind: u16,
        serial: u64,
        body: &str,
        now: Instant,
    ) -> Vec<ThreatEvent> {
        a.push(
            kind,
            format!("audit(1700000000.123:{serial}): {body}").as_bytes(),
            now,
        )
    }
    #[test]
    fn interleaved_records_join_only_by_audit_stamp_not_pid() {
        let mut a = assembler();
        let now = Instant::now();
        assert!(add(&mut a, 1300, 1, "pid=42 items=1 success=yes", now).is_empty());
        assert!(add(&mut a, 1300, 2, "pid=42 items=0 success=no", now).is_empty());
        add(
            &mut a,
            1302,
            1,
            "item=0 name=\"/tmp/file\" nametype=CREATE",
            now,
        );
        let event = add(&mut a, 1320, 2, "", now).pop().unwrap();
        let EventData::LinuxAudit { record } = event.data else {
            panic!()
        };
        assert_eq!(record.records.len(), 2);
        assert_eq!(record.stamp.serial, 2);
        assert!(event.process_context.is_none());
        assert!(record.issues.is_empty());
        let event = add(&mut a, 1320, 1, "", now).pop().unwrap();
        let EventData::LinuxAudit { record } = event.data else {
            panic!()
        };
        assert_eq!(record.records.len(), 3);
        assert!(record.issues.is_empty());
    }
    #[test]
    fn timeout_and_late_records_never_look_complete() {
        let mut a = assembler();
        let now = Instant::now();
        add(&mut a, 1300, 1, "pid=42 items=1", now);
        let event = a.expire(now + TIMEOUT).pop().unwrap();
        let EventData::LinuxAudit { record } = event.data else {
            panic!()
        };
        assert_eq!(record.completion, AuditCompletion::Timeout);
        assert!(record
            .issues
            .iter()
            .any(|s| s == "audit_path_count_mismatch"));
        assert!(add(&mut a, 1320, 1, "", now + TIMEOUT).is_empty());
        assert_eq!(a.stats.late_records, 1);
        assert!(a.stats.quality_uncertain());
    }
    #[test]
    fn pending_and_record_count_limits_preserve_marked_partial_evidence() {
        let mut a = assembler();
        let now = Instant::now();
        for serial in 0..MAX_PENDING as u64 {
            add(&mut a, 1300, serial, "pid=42 items=0", now);
        }
        let event = add(&mut a, 1300, MAX_PENDING as u64, "pid=42 items=0", now)
            .pop()
            .unwrap();
        let EventData::LinuxAudit { record } = event.data else {
            panic!()
        };
        assert_eq!(record.completion, AuditCompletion::Capacity);
        assert_eq!(a.pending.len(), MAX_PENDING);
        assert!(a.pending_bytes <= MAX_PENDING_BYTES);
        assert_eq!(a.shutdown().len(), MAX_PENDING);
        assert_eq!(a.pending_bytes, 0);
        let mut a = assembler();
        for _ in 0..MAX_RECORDS {
            add(&mut a, 1309, 1, "argc=1", now);
        }
        assert_eq!(add(&mut a, 1320, 1, "", now).len(), 1);
        assert_eq!(a.stats.capacity_flushes, 1);
    }
    #[test]
    fn malformed_record_and_unknown_type_are_observable_without_data_leak() {
        let mut a = assembler();
        assert!(a.push(1300, b"SECRET", Instant::now()).is_empty());
        assert!(a.push(9999, b"SECRET", Instant::now()).is_empty());
        assert_eq!(a.stats.malformed_records, 1);
        assert_eq!(a.stats.records_filtered, 1);
        assert!(!serde_json::to_string(&a.stats).unwrap().contains("SECRET"));
    }
    #[test]
    fn byte_budgets_eoe_checks_and_standalone_records() {
        let mut a = assembler();
        let now = Instant::now();
        for serial in 0..200 {
            for item in 0..6 {
                add(
                    &mut a,
                    1302,
                    serial,
                    &format!("item={item} name=\"{}\"", "x".repeat(4000)),
                    now,
                );
                assert!(a.pending_bytes <= MAX_PENDING_BYTES);
                assert!(a.pending.values().all(|p| p.bytes <= MAX_EVENT_BYTES));
            }
        }
        assert!(a.stats.capacity_flushes > 0);
        let mut a = assembler();
        let event = add(&mut a, 1006, 1, "pid=42 uid=0 auid=1000 res=1", now)
            .pop()
            .unwrap();
        let EventData::LinuxAudit { record } = event.data else {
            panic!()
        };
        assert_eq!(record.completion, AuditCompletion::Standalone);
        assert!(record.issues.is_empty());
        assert_eq!(a.stats.events_without_eoe, 0);
        add(&mut a, 1300, 2, "pid=42 items=2", now);
        add(&mut a, 1302, 2, "item=0 name=\"one\"", now);
        add(&mut a, 1302, 2, "item=0 name=\"two\"", now);
        let event = add(&mut a, 1320, 2, "", now).pop().unwrap();
        let EventData::LinuxAudit { record } = event.data else {
            panic!()
        };
        assert!(record
            .issues
            .iter()
            .any(|s| s == "audit_invalid_or_duplicate_path_item"));
    }
    #[tokio::test]
    async fn native_records_roundtrip_delivery_analysis_and_index_without_pid_join_or_secrets() {
        use crate::{
            config::OutputConfig,
            detection::Detector,
            index::{EventIndex, IndexFilter},
            output::{FileSink, Sink},
            process_cache::ProcessCache,
        };
        let mut a = assembler();
        let now = Instant::now();
        add(
            &mut a,
            1300,
            1,
            "arch=c000003e syscall=59 pid=42 items=0 success=yes exe=\"/usr/bin/true\" a0=SECRET",
            now,
        );
        add(&mut a, 1309, 1, "argc=2 a0=74727565 a1=534543524554", now);
        add(&mut a, 1327, 1, "proctitle=534543524554", now);
        let event = add(&mut a, 1320, 1, "", now).pop().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let config = OutputConfig {
            path: path.clone(),
            ..Default::default()
        };
        let mut sink = FileSink::new(&config).unwrap();
        let mut cache = ProcessCache::new(100);
        let mut detector = Detector::default();
        // Seed the legacy cache with the same numeric PID. It is a different
        // source, not evidence of Linux process identity.
        let mut legacy = ThreatEvent::new(
            &a.agent,
            EventSource::Etw {
                provider: "synthetic".into(),
            },
            EventCategory::Process,
            Severity::Info,
            EventData::ProcessCreate {
                pid: 42,
                ppid: 1,
                image_path: "wrong-process".into(),
                command_line: "wrong-command".into(),
                user: String::new(),
                integrity_level: String::new(),
                hashes: None,
                create_time: Some(1),
            },
        );
        cache.enrich(&mut legacy);
        crate::sensor::deliver(event, &mut cache, &mut detector, &mut sink)
            .await
            .unwrap();
        sink.flush().await.unwrap();
        let jsonl = std::fs::read_to_string(&path).unwrap();
        for secret in ["SECRET", "534543524554", "wrong-process", "wrong-command"] {
            assert!(!jsonl.contains(secret));
        }
        let event: ThreatEvent = serde_json::from_str(jsonl.trim()).unwrap();
        assert!(event.process_context.is_none());
        assert_eq!(event.data.acting_pid(), Some(42));
        let report = crate::analysis::analyze(std::io::Cursor::new(jsonl)).unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.analysis.eligible_events, 0);
        assert_eq!(report.agents[&a.agent.agent_id].linux_audit_events, 1);
        assert_eq!(report.agents[&a.agent.agent_id].source_time_events, 1);
        assert!(report
            .limitations
            .contains(&"linux_detection_rules_not_implemented"));
        let index = EventIndex::open(&path).unwrap();
        assert_eq!(index.build(&path).unwrap().new_events, 1);
        assert_eq!(
            index
                .query_locations(&IndexFilter {
                    pid: Some(42),
                    source_type: Some("linuxaudit".into()),
                    ..Default::default()
                })
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            index
                .query_locations(&IndexFilter {
                    pid: Some(99),
                    ..Default::default()
                })
                .unwrap()
                .len(),
            0
        );
    }
}
