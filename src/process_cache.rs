use std::collections::HashMap;

use crate::events::{EventData, ProcessContext, ThreatEvent};

/// Cached process metadata, populated from ProcessCreate events.
#[derive(Debug, Clone)]
struct CacheEntry {
    process_key: String,
    image_path: String,
    command_line: String,
    user: String,
    integrity_level: String,
    ppid: u32,
}

/// Short-lived in-memory cache mapping PID to process metadata.
///
/// Populated from `ProcessCreate` events, consulted on activity events
/// (file, network, registry, DNS, etc.), and evicted on `ProcessTerminate`.
///
/// The cache is keyed by PID. When a new ProcessCreate arrives for an
/// existing PID, the old entry is replaced — this naturally handles PID
/// reuse within the sensor's lifetime.
pub struct ProcessCache {
    entries: HashMap<u32, CacheEntry>,
    /// Maximum number of entries. When exceeded, the oldest entries are
    /// not proactively evicted — the HashMap grows until ProcessTerminate
    /// events drain it. The cap serves as a circuit-breaker: inserts are
    /// skipped once the limit is reached.
    capacity: usize,
}

impl ProcessCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
        }
    }

    /// Enrich a ThreatEvent with process context:
    ///
    /// - **ProcessCreate**: insert into cache, set `process_context` with
    ///   `process_key` only (the event payload already carries the data).
    /// - **ProcessTerminate**: look up cached context, set it on the event,
    ///   then evict the entry.
    /// - **Activity events**: look up by PID and attach full context.
    pub fn enrich(&mut self, event: &mut ThreatEvent) {
        match &event.data {
            EventData::ProcessCreate {
                pid,
                ppid,
                image_path,
                command_line,
                user,
                integrity_level,
                create_time,
                ..
            } => {
                let process_key = make_process_key(*pid, *create_time);

                let entry = CacheEntry {
                    process_key: process_key.clone(),
                    image_path: image_path.clone(),
                    command_line: command_line.clone(),
                    user: user.clone(),
                    integrity_level: integrity_level.clone(),
                    ppid: *ppid,
                };

                // Set process_context with just the key — the event payload
                // already contains image_path, command_line, etc.
                event.process_context = Some(ProcessContext {
                    process_key,
                    image_path: None,
                    command_line: None,
                    user: None,
                    integrity_level: None,
                    ppid: None,
                });

                if self.entries.len() < self.capacity {
                    self.entries.insert(*pid, entry);
                } else {
                    // Replace existing entry for the same PID even at capacity
                    if self.entries.contains_key(pid) {
                        self.entries.insert(*pid, entry);
                    }
                    // Otherwise skip — don't grow beyond capacity
                }
            }

            EventData::ProcessTerminate {
                pid, create_time, ..
            } => {
                if let Some(entry) = self.entries.get(pid) {
                    // If create_time is available, verify it matches to avoid
                    // evicting a newer process that reused the same PID.
                    let matches = match create_time {
                        Some(ct) => {
                            let expected = make_process_key(*pid, Some(*ct));
                            entry.process_key == expected
                        }
                        None => true,
                    };

                    if matches {
                        event.process_context = Some(build_context(entry));
                        self.entries.remove(pid);
                    }
                }
            }

            _ => {
                if let Some(pid) = event.data.acting_pid() {
                    if let Some(entry) = self.entries.get(&pid) {
                        event.process_context = Some(build_context(entry));
                    }
                }
            }
        }
    }

    /// Number of cached process entries.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Build a `process_key` string from PID and optional creation timestamp.
fn make_process_key(pid: u32, create_time: Option<u64>) -> String {
    match create_time {
        Some(ct) => format!("{pid}:{ct}"),
        None => format!("{pid}:0"),
    }
}

/// Build a full `ProcessContext` from a cache entry. Empty strings are
/// converted to `None` so they are omitted from serialized JSON.
fn build_context(entry: &CacheEntry) -> ProcessContext {
    ProcessContext {
        process_key: entry.process_key.clone(),
        image_path: non_empty(&entry.image_path),
        command_line: non_empty(&entry.command_line),
        user: non_empty(&entry.user),
        integrity_level: non_empty(&entry.integrity_level),
        ppid: Some(entry.ppid),
    }
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::*;
    use uuid::Uuid;

    fn test_agent() -> AgentInfo {
        AgentInfo {
            hostname: "TEST".into(),
            agent_id: Uuid::nil(),
        }
    }

    fn process_create_event(pid: u32, create_time: Option<u64>) -> ThreatEvent {
        ThreatEvent::new(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Windows-Kernel-Process".into(),
            },
            EventCategory::Process,
            Severity::Info,
            EventData::ProcessCreate {
                pid,
                ppid: 1,
                image_path: "C:\\Windows\\System32\\cmd.exe".into(),
                command_line: "cmd.exe /c whoami".into(),
                user: "DESKTOP\\admin".into(),
                integrity_level: "High".into(),
                hashes: None,
                create_time,
            },
        )
    }

    fn process_terminate_event(pid: u32, create_time: Option<u64>) -> ThreatEvent {
        ThreatEvent::new(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Windows-Kernel-Process".into(),
            },
            EventCategory::Process,
            Severity::Info,
            EventData::ProcessTerminate {
                pid,
                image_path: "cmd.exe".into(),
                create_time,
            },
        )
    }

    fn network_event(pid: u32) -> ThreatEvent {
        ThreatEvent::new(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Windows-Kernel-Network".into(),
            },
            EventCategory::Network,
            Severity::Info,
            EventData::NetworkConnect {
                pid,
                image_path: String::new(),
                protocol: "TCP".into(),
                src_addr: "10.0.0.1".into(),
                src_port: 12345,
                dst_addr: "93.184.216.34".into(),
                dst_port: 443,
                direction: NetworkDirection::Outbound,
            },
        )
    }

    fn dns_event(pid: u32) -> ThreatEvent {
        ThreatEvent::new(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Windows-DNS-Client".into(),
            },
            EventCategory::Dns,
            Severity::Info,
            EventData::DnsQuery {
                pid,
                query_name: "example.com".into(),
                query_type: "A".into(),
                response: None,
            },
        )
    }

    fn registry_event(pid: u32) -> ThreatEvent {
        ThreatEvent::new(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Windows-Kernel-Registry".into(),
            },
            EventCategory::Registry,
            Severity::Info,
            EventData::RegistryEvent {
                pid,
                operation: RegistryOperation::SetValue,
                key: "HKLM\\Software\\Test".into(),
                value_name: Some("Foo".into()),
                value_data: Some("Bar".into()),
            },
        )
    }

    fn file_event(pid: u32) -> ThreatEvent {
        ThreatEvent::new(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Windows-Kernel-File".into(),
            },
            EventCategory::File,
            Severity::Info,
            EventData::FileCreate {
                pid,
                path: "C:\\temp\\test.txt".into(),
                operation: FileOperation::Create,
            },
        )
    }

    // ---- Core enrichment tests -----------------------------------------------

    #[test]
    fn process_create_inserts_and_sets_key() {
        let mut cache = ProcessCache::new(1000);
        let mut evt = process_create_event(100, Some(0xAABBCCDD));
        cache.enrich(&mut evt);

        // process_context should have process_key only
        let ctx = evt.process_context.unwrap();
        assert_eq!(ctx.process_key, "100:2864434397");
        assert!(ctx.image_path.is_none());
        assert!(ctx.ppid.is_none());

        // Cache should have the entry
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn activity_event_enriched_with_full_context() {
        let mut cache = ProcessCache::new(1000);
        let mut create = process_create_event(200, Some(12345));
        cache.enrich(&mut create);

        let mut net = network_event(200);
        cache.enrich(&mut net);

        let ctx = net.process_context.unwrap();
        assert_eq!(ctx.process_key, "200:12345");
        assert_eq!(ctx.image_path.as_deref(), Some("C:\\Windows\\System32\\cmd.exe"));
        assert_eq!(ctx.command_line.as_deref(), Some("cmd.exe /c whoami"));
        assert_eq!(ctx.user.as_deref(), Some("DESKTOP\\admin"));
        assert_eq!(ctx.integrity_level.as_deref(), Some("High"));
        assert_eq!(ctx.ppid, Some(1));
    }

    #[test]
    fn process_terminate_evicts_and_enriches() {
        let mut cache = ProcessCache::new(1000);
        let mut create = process_create_event(300, Some(999));
        cache.enrich(&mut create);
        assert_eq!(cache.len(), 1);

        let mut term = process_terminate_event(300, Some(999));
        cache.enrich(&mut term);

        // Terminate event should get full context
        let ctx = term.process_context.unwrap();
        assert_eq!(ctx.process_key, "300:999");
        assert_eq!(ctx.image_path.as_deref(), Some("C:\\Windows\\System32\\cmd.exe"));

        // Cache should be empty
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn unknown_pid_returns_no_context() {
        let mut cache = ProcessCache::new(1000);
        let mut net = network_event(999);
        cache.enrich(&mut net);

        assert!(net.process_context.is_none());
    }

    #[test]
    fn pid_reuse_replaces_old_entry() {
        let mut cache = ProcessCache::new(1000);

        // First process with PID 400
        let mut create1 = process_create_event(400, Some(100));
        cache.enrich(&mut create1);

        // Same PID, new create_time (PID reuse)
        let mut create2 = ThreatEvent::new(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Windows-Kernel-Process".into(),
            },
            EventCategory::Process,
            Severity::Info,
            EventData::ProcessCreate {
                pid: 400,
                ppid: 2,
                image_path: "C:\\evil.exe".into(),
                command_line: "evil.exe".into(),
                user: String::new(),
                integrity_level: String::new(),
                hashes: None,
                create_time: Some(200),
            },
        );
        cache.enrich(&mut create2);

        // Activity should see the new process
        let mut net = network_event(400);
        cache.enrich(&mut net);

        let ctx = net.process_context.unwrap();
        assert_eq!(ctx.process_key, "400:200");
        assert_eq!(ctx.image_path.as_deref(), Some("C:\\evil.exe"));
    }

    #[test]
    fn terminate_with_mismatched_create_time_does_not_evict() {
        let mut cache = ProcessCache::new(1000);

        let mut create = process_create_event(500, Some(1000));
        cache.enrich(&mut create);

        // Terminate with different create_time (belongs to an older instance)
        let mut term = process_terminate_event(500, Some(999));
        cache.enrich(&mut term);

        // Should NOT evict — create_time mismatch
        assert!(term.process_context.is_none());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn terminate_without_create_time_evicts() {
        let mut cache = ProcessCache::new(1000);

        let mut create = process_create_event(600, Some(5000));
        cache.enrich(&mut create);

        // Terminate without create_time (e.g., from Sysmon)
        let mut term = process_terminate_event(600, None);
        cache.enrich(&mut term);

        // Should evict — no create_time to mismatch
        let ctx = term.process_context.unwrap();
        assert_eq!(ctx.process_key, "600:5000");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn empty_user_and_integrity_become_none() {
        let mut cache = ProcessCache::new(1000);

        let mut create = ThreatEvent::new(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Windows-Kernel-Process".into(),
            },
            EventCategory::Process,
            Severity::Info,
            EventData::ProcessCreate {
                pid: 700,
                ppid: 1,
                image_path: "test.exe".into(),
                command_line: "test.exe".into(),
                user: String::new(),
                integrity_level: String::new(),
                hashes: None,
                create_time: Some(42),
            },
        );
        cache.enrich(&mut create);

        let mut net = network_event(700);
        cache.enrich(&mut net);

        let ctx = net.process_context.unwrap();
        assert!(ctx.user.is_none(), "empty user should be None");
        assert!(
            ctx.integrity_level.is_none(),
            "empty integrity_level should be None"
        );
    }

    #[test]
    fn capacity_limit_prevents_unbounded_growth() {
        let mut cache = ProcessCache::new(2);

        let mut c1 = process_create_event(1, Some(10));
        let mut c2 = process_create_event(2, Some(20));
        let mut c3 = process_create_event(3, Some(30));
        cache.enrich(&mut c1);
        cache.enrich(&mut c2);
        cache.enrich(&mut c3);

        // Third insert should be skipped (new PID, at capacity)
        assert_eq!(cache.len(), 2);

        // PID 3 should not be enrichable
        let mut net = network_event(3);
        cache.enrich(&mut net);
        assert!(net.process_context.is_none());
    }

    #[test]
    fn capacity_allows_replace_existing_pid() {
        let mut cache = ProcessCache::new(2);

        let mut c1 = process_create_event(1, Some(10));
        let mut c2 = process_create_event(2, Some(20));
        cache.enrich(&mut c1);
        cache.enrich(&mut c2);

        // Replace PID 1 (PID reuse) — should succeed even at capacity
        let mut c1_new = process_create_event(1, Some(30));
        cache.enrich(&mut c1_new);

        assert_eq!(cache.len(), 2);

        let mut net = network_event(1);
        cache.enrich(&mut net);
        assert_eq!(
            net.process_context.unwrap().process_key,
            "1:30"
        );
    }

    #[test]
    fn dns_event_enriched() {
        let mut cache = ProcessCache::new(1000);
        let mut create = process_create_event(800, Some(55));
        cache.enrich(&mut create);

        let mut dns = dns_event(800);
        cache.enrich(&mut dns);

        let ctx = dns.process_context.unwrap();
        assert_eq!(ctx.process_key, "800:55");
        assert!(ctx.image_path.is_some());
    }

    #[test]
    fn registry_event_enriched() {
        let mut cache = ProcessCache::new(1000);
        let mut create = process_create_event(900, Some(66));
        cache.enrich(&mut create);

        let mut reg = registry_event(900);
        cache.enrich(&mut reg);

        let ctx = reg.process_context.unwrap();
        assert_eq!(ctx.process_key, "900:66");
    }

    #[test]
    fn file_event_enriched() {
        let mut cache = ProcessCache::new(1000);
        let mut create = process_create_event(1000, Some(77));
        cache.enrich(&mut create);

        let mut file = file_event(1000);
        cache.enrich(&mut file);

        let ctx = file.process_context.unwrap();
        assert_eq!(ctx.process_key, "1000:77");
    }

    #[test]
    fn health_event_not_enriched() {
        let mut cache = ProcessCache::new(1000);

        let mut health = ThreatEvent::new(
            &test_agent(),
            EventSource::Sensor,
            EventCategory::Health,
            Severity::Info,
            EventData::SensorHealth {
                uptime_secs: 60,
                events_total: 100,
                events_dropped: 0,
                collectors: vec![],
                sink: None,
            },
        );
        cache.enrich(&mut health);

        assert!(health.process_context.is_none());
    }

    #[test]
    fn process_key_format() {
        assert_eq!(make_process_key(1234, Some(567890)), "1234:567890");
        assert_eq!(make_process_key(1234, None), "1234:0");
        assert_eq!(make_process_key(0, Some(0)), "0:0");
    }

    #[test]
    fn create_without_create_time_uses_zero() {
        let mut cache = ProcessCache::new(1000);
        let mut create = process_create_event(50, None);
        cache.enrich(&mut create);

        let ctx = create.process_context.unwrap();
        assert_eq!(ctx.process_key, "50:0");
    }

    #[test]
    fn process_context_serialization_omits_none_fields() {
        let ctx = ProcessContext {
            process_key: "100:42".into(),
            image_path: None,
            command_line: None,
            user: None,
            integrity_level: None,
            ppid: None,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("\"process_key\""));
        assert!(!json.contains("image_path"));
        assert!(!json.contains("command_line"));
        assert!(!json.contains("user"));
        assert!(!json.contains("ppid"));
    }

    #[test]
    fn process_context_backward_compatible_deserialization() {
        // Simulates deserializing an older event without process_context
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000000",
            "timestamp": "2026-01-01T00:00:00Z",
            "hostname": "HOST",
            "agent_id": "00000000-0000-0000-0000-000000000000",
            "sensor_version": "0.2.0",
            "source": {"Etw": {"provider": "test"}},
            "category": "Network",
            "severity": "Info",
            "data": {
                "type": "NetworkConnect",
                "pid": 1, "image_path": "", "protocol": "TCP",
                "src_addr": "0.0.0.0", "src_port": 0,
                "dst_addr": "0.0.0.0", "dst_port": 0,
                "direction": "Outbound"
            }
        }"#;
        let event: ThreatEvent = serde_json::from_str(json).unwrap();
        assert!(
            event.process_context.is_none(),
            "missing process_context should deserialize as None"
        );
    }
}
