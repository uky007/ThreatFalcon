//! Evidence-based, bounded streaming correlation shared by the live sensor and
//! offline replay. Findings indicate suspicious behavior, not confirmed malware.
use crate::events::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use uuid::Uuid;
use crate::detection_catalog::{sysmon_provenance, RuleSpec, RULES};

#[path = "detection_recovery.rs"]
mod recovery;
pub(crate) use recovery::{StateDelta, StateSnapshot, MAX_TIMELINE_BYTES, STATE_VERSION};

pub(crate) const WINDOW_SECS: i64 = 600;
pub(crate) const MAX_KEYS: usize = 10_000;
pub(crate) const MAX_PER_KEY: usize = 64;
pub(crate) const MAX_DEDUP: usize = 50_000;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DetectionStats {
    pub state_restored: bool,
    pub restored_timelines: u64,
    pub input_events: u64,
    pub eligible_events: u64,
    pub missing_evidence_events: u64,
    pub duplicate_events: u64,
    pub late_events: u64,
    pub capacity_events_dropped: u64,
    pub findings: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Observation {
    id: Uuid,
    time: DateTime<Utc>,
    fact: Fact,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Fact {
    Access {
        actor: Uuid,
        mask: u32,
    },
    Thread {
        actor: Uuid,
    },
    ScriptChild {
        parent: String,
        image: String,
    },
    Connect {
        addr: String,
        port: u16,
        protocol: String,
    },
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Timeline {
    observations: Vec<Observation>,
    latest: Option<DateTime<Utc>>,
    emitted: HashSet<String>,
}

#[derive(Default)]
pub struct Detector {
    timelines: HashMap<(Uuid, Uuid), Timeline>,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
    pending: Option<recovery::Pending>,
    pub stats: DetectionStats,
}

impl Detector {
    pub fn ingest(&mut self, event: &ThreatEvent) -> Vec<ThreatEvent> {
        self.stats.input_events += 1;
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.agent_id != event.agent_id)
        {
            self.stats.missing_evidence_events += 1;
            return vec![];
        }
        if !matches!(
            event.data,
            EventData::ProcessAccess { .. }
                | EventData::CreateRemoteThread { .. }
                | EventData::ProcessCreate { .. }
                | EventData::NetworkConnect { .. }
        ) {
            return vec![];
        }
        // V1 timestamps represented observation time and PID-only identities are
        // ambiguous. Do not silently upgrade either into source evidence.
        let Some(p) = sysmon_provenance(event) else {
            self.stats.missing_evidence_events += 1;
            return vec![];
        };
        let Some(actor) = p.process_guid.filter(|g| !g.is_nil()) else {
            self.stats.missing_evidence_events += 1;
            return vec![];
        };
        let Some((process, fact)) = fact(event, p, actor) else {
            return vec![];
        };
        self.stats.eligible_events += 1;
        // A replayed native record can have a newly generated envelope UUID.
        let dedup = p
            .record_id
            .map(|id| {
                format!(
                    "{}:{}:{id}:{}",
                    event.agent_id, p.provider_guid, event.timestamp
                )
            })
            .unwrap_or_else(|| format!("{}:{}", event.agent_id, event.id));
        if !self.seen.insert(dedup.clone()) {
            self.stats.duplicate_events += 1;
            return vec![];
        }
        if let Some(p) = &mut self.pending {
            p.seen_added(&dedup);
        }
        self.seen_order.push_back(dedup);
        if self.seen_order.len() > MAX_DEDUP {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
                if let Some(p) = &mut self.pending {
                    p.seen_removed(&old);
                }
            }
        }
        let key = (event.agent_id, process);
        // Expire only this host's old timelines. Another host's clock cannot
        // evict evidence belonging to this host.
        if !self.timelines.contains_key(&key) {
            self.timelines.retain(|(agent, process), t| {
                let keep = *agent != event.agent_id
                    || t.latest
                        .is_some_and(|time| (event.timestamp - time).num_seconds() <= WINDOW_SECS);
                if !keep {
                    if let Some(p) = &mut self.pending {
                        p.changed(*process);
                    }
                }
                keep
            });
            if self.timelines.len() >= MAX_KEYS {
                self.stats.capacity_events_dropped += 1;
                return vec![];
            }
        }
        let timeline = self.timelines.entry(key).or_default();
        if let Some(p) = &mut self.pending {
            p.changed(process);
        }
        let latest = timeline
            .latest
            .map_or(event.timestamp, |t| t.max(event.timestamp));
        if (latest - event.timestamp).num_seconds() > WINDOW_SECS {
            self.stats.late_events += 1;
            return vec![];
        }
        timeline.latest = Some(latest);
        timeline
            .observations
            .retain(|o| (latest - o.time).num_seconds() <= WINDOW_SECS);
        if timeline.observations.len() >= MAX_PER_KEY {
            // Bounded retention is observable; it must not masquerade as full coverage.
            timeline.observations.sort_by_key(|o| o.time);
            timeline.observations.remove(0);
            self.stats.capacity_events_dropped += 1;
        }
        timeline.observations.push(Observation {
            id: event.id,
            time: event.timestamp,
            fact,
        });
        timeline.observations.sort_by_key(|o| o.time);
        // Emission keys reference retained evidence only, bounding dedup state.
        let retained: HashSet<String> = timeline
            .observations
            .iter()
            .map(|o| o.id.to_string())
            .collect();
        timeline
            .emitted
            .retain(|s| s.split('|').nth(1).is_some_and(|id| retained.contains(id)));
        let findings = evaluate(event, process, timeline);
        self.stats.findings += findings.len() as u64;
        findings
    }
}

fn fact(e: &ThreatEvent, p: &EventProvenance, actor: Uuid) -> Option<(Uuid, Fact)> {
    match &e.data {
        EventData::ProcessAccess { granted_access, .. } if p.event_id == 10 => {
            let target = p
                .target_process_guid
                .filter(|g| !g.is_nil() && *g != actor)?;
            // PROCESS_VM_WRITE + PROCESS_VM_OPERATION. Access alone is not a finding.
            (*granted_access & 0x28 == 0x28).then_some((
                target,
                Fact::Access {
                    actor,
                    mask: *granted_access,
                },
            ))
        }
        EventData::CreateRemoteThread { .. } if p.event_id == 8 => Some((
            p.target_process_guid
                .filter(|g| !g.is_nil() && *g != actor)?,
            Fact::Thread { actor },
        )),
        EventData::ProcessCreate { image_path, .. } if p.event_id == 1 => {
            let parent = p.fields.get("ParentImage")?;
            p.parent_process_guid
                .filter(|g| !g.is_nil() && *g != actor)?;
            let base = |s: &str| {
                s.rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(s)
                    .to_ascii_lowercase()
            };
            if ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
                .contains(&base(parent).as_str())
                && [
                    "powershell.exe",
                    "pwsh.exe",
                    "wscript.exe",
                    "cscript.exe",
                    "mshta.exe",
                ]
                .contains(&base(image_path).as_str())
            {
                Some((
                    actor,
                    Fact::ScriptChild {
                        parent: base(parent),
                        image: base(image_path),
                    },
                ))
            } else {
                None
            }
        }
        EventData::NetworkConnect {
            dst_addr,
            dst_port,
            protocol,
            direction: NetworkDirection::Outbound,
            ..
        } if p.event_id == 3 => {
            let ip: std::net::IpAddr = dst_addr.parse().ok()?;
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || *dst_port == 0 {
                return None;
            }
            if !protocol.eq_ignore_ascii_case("tcp") && !protocol.eq_ignore_ascii_case("udp") {
                return None;
            }
            Some((
                actor,
                Fact::Connect {
                    addr: ip.to_string(),
                    port: *dst_port,
                    protocol: protocol.to_ascii_uppercase(),
                },
            ))
        }
        _ => None,
    }
}

fn evaluate(event: &ThreatEvent, process: Uuid, t: &mut Timeline) -> Vec<ThreatEvent> {
    let mut results = Vec::new();
    for connection in &t.observations {
        let Fact::Connect { addr, port, .. } = &connection.fact else {
            continue;
        };
        for preceding in &t.observations {
            let elapsed = (connection.time - preceding.time).num_milliseconds();
            if !(1..=120_000).contains(&elapsed) {
                continue;
            }
            let (rule,detail,mut evidence)=match &preceding.fact {
                Fact::Thread {actor} => (&RULES[0],
                    format!("actor=sysmon:{actor}; target=sysmon:{process}; destination={addr}:{port}; elapsed_ms={elapsed}; behavior is suspicious, not proof of injection"),
                    vec![preceding.clone(),connection.clone()]),
                Fact::ScriptChild {parent,image} => (&RULES[1],
                    format!("parent={parent}; child={image}; destination={addr}:{port}; elapsed_ms={elapsed}; administrative automation may also match"),
                    vec![preceding.clone(),connection.clone()]),
                _ => continue,
            };
            if let Fact::Thread { actor } = &preceding.fact {
                if let Some(access)=t.observations.iter().rev().find(|a| matches!(a.fact,Fact::Access {actor:other,mask} if other==*actor && mask & 0x28==0x28)
                    && a.time<=preceding.time && (preceding.time-a.time).num_seconds()<=120) {
                    evidence.push(access.clone());
                }
            }
            let dedup = format!("{}|{}", rule.id, preceding.id);
            if t.emitted.insert(dedup) {
                results.push(finding(
                    event, process, rule, detail, &evidence,
                ));
            }
        }
    }
    // Periodicity requires real TCP connection events and an interval pattern,
    // not merely a count of packets or connections to a popular destination.
    let mut destinations: HashMap<(&str, u16), Vec<&Observation>> = HashMap::new();
    for o in &t.observations {
        if let Fact::Connect {
            addr,
            port,
            protocol,
        } = &o.fact
        {
            if protocol == "TCP" {
                destinations.entry((addr, *port)).or_default().push(o);
            }
        }
    }
    for ((addr, port), samples) in destinations {
        if samples.len() < 10 {
            continue;
        }
        let samples = &samples[samples.len() - 10..];
        let times: Vec<_> = samples.iter().map(|s| s.time).collect();
        let Some((mean, cv)) = periodicity(&times, 10) else {
            continue;
        };
        // One finding per destination while evidence stays in the 10-minute window.
        let prefix = format!("{}:", RULES[2].id);
        let suffix = format!("|{addr}:{port}");
        if t.emitted
            .iter()
            .any(|s| s.starts_with(&prefix) && s.ends_with(&suffix))
        {
            continue;
        }
        t.emitted
            .insert(format!("{prefix}|{}{suffix}", samples[0].id));
        results.push(finding(event,process,&RULES[2],format!("destination={addr}:{port}; samples=10; mean_interval_secs={mean:.3}; interval_cv={cv:.4}; scheduled benign traffic may also match"),
            &samples.iter().map(|o|(*o).clone()).collect::<Vec<_>>()));
    }
    results
}

/// Shared with the legacy hunt command so connection count alone is never
/// described as periodic beaconing. Callers must validate identity and source time.
pub fn periodicity(times: &[DateTime<Utc>], minimum: usize) -> Option<(f64, f64)> {
    if times.len() < minimum.max(10) {
        return None;
    }
    let mut times = times.to_vec();
    times.sort();
    let span = (*times.last()? - *times.first()?).num_milliseconds();
    if !(90_000..=WINDOW_SECS * 1000).contains(&span) {
        return None;
    }
    let intervals: Vec<f64> = times
        .windows(2)
        .map(|p| (p[1] - p[0]).num_milliseconds() as f64 / 1000.0)
        .collect();
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean < 10.0 || intervals.iter().any(|x| *x <= 0.0) {
        return None;
    }
    let cv = (intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64)
        .sqrt()
        / mean;
    (cv <= 0.15).then_some((mean, cv))
}

fn finding(
    event: &ThreatEvent,
    process: Uuid,
    rule: &RuleSpec,
    detail: String,
    evidence: &[Observation],
) -> ThreatEvent {
    let (id, en, ja, technique) = (rule.id, rule.title_en, rule.title_ja, rule.technique_id);
    let start = evidence.iter().map(|o| o.time).min().unwrap();
    let end = evidence.iter().map(|o| o.time).max().unwrap();
    let mut ids: Vec<_> = evidence.iter().map(|o| o.id).collect();
    ids.sort();
    ids.dedup();
    let agent = AgentInfo {
        hostname: event.hostname.clone(),
        agent_id: event.agent_id,
    };
    let mut result = ThreatEvent::with_rule(
        &agent,
        EventSource::Sensor,
        EventCategory::Detection,
        if id == "TF-COR-003" {
            Severity::Medium
        } else {
            Severity::High
        },
        EventData::CorrelationDetection {
            rule_id: id.into(),
            title_en: en.into(),
            title_ja: ja.into(),
            evidence_ids: ids.clone(),
            process_key: format!("sysmon:{process}"),
            window_start: start,
            window_end: end,
            details: detail.clone(),
        },
        RuleMetadata {
            id: id.into(),
            name: en.into(),
            description: format!("{en} / {ja}"),
            mitre: MitreRef {
                tactic: if id == "TF-COR-001" {
                    "Defense Evasion"
                } else if id == "TF-COR-002" {
                    "Execution"
                } else {
                    "Command and Control"
                }
                .into(),
                technique_id: technique.into(),
                technique_name: if id == "TF-COR-001" {
                    "Process Injection"
                } else if id == "TF-COR-002" {
                    "Command and Scripting Interpreter"
                } else {
                    "Application Layer Protocol"
                }
                .into(),
            },
            confidence: if id == "TF-COR-003" {
                Confidence::Low
            } else {
                Confidence::Medium
            },
            evidence: ids
                .iter()
                .map(|id| format!("event:{id}"))
                .chain(Some(detail))
                .collect(),
        },
    );
    result.timestamp = end;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::*;
    fn evidence(e: &ThreatEvent) -> &[Uuid] {
        match &e.data {
            EventData::CorrelationDetection { evidence_ids, .. } => evidence_ids,
            _ => panic!("not a detection"),
        }
    }
    #[test]
    fn remote_thread_then_target_connection_has_exact_evidence() {
        let mut d = Detector::default();
        let thread = sysmon(8, 10, ACTOR);
        let net = sysmon(3, 20, TARGET);
        assert!(d.ingest(&thread).is_empty());
        let findings = d.ingest(&net);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule.as_ref().unwrap().id, "TF-COR-001");
        assert!(evidence(&findings[0]).contains(&thread.id));
        assert!(evidence(&findings[0]).contains(&net.id));
        assert_eq!(findings[0].timestamp, net.timestamp);
    }
    #[test]
    fn matching_access_adds_third_evidence_but_unrelated_actor_does_not() {
        for actor in [ACTOR, OTHER] {
            let mut d = Detector::default();
            d.ingest(&sysmon(10, 0, actor));
            d.ingest(&sysmon(8, 10, ACTOR));
            let f = d.ingest(&sysmon(3, 20, TARGET));
            assert_eq!(evidence(&f[0]).len(), if actor == ACTOR { 3 } else { 2 });
        }
    }
    #[test]
    fn access_and_connection_alone_are_not_injection_detection() {
        let mut d = Detector::default();
        d.ingest(&sysmon(10, 0, ACTOR));
        assert!(d.ingest(&sysmon(3, 20, TARGET)).is_empty());
    }
    #[test]
    fn same_pid_different_guid_or_host_never_joins() {
        let mut d = Detector::default();
        d.ingest(&sysmon(8, 0, ACTOR));
        assert!(d.ingest(&sysmon(3, 20, OTHER)).is_empty());
        let mut other_host = sysmon(3, 20, TARGET);
        other_host.agent_id = Uuid::from_u128(2);
        assert!(d.ingest(&other_host).is_empty());
    }
    #[test]
    fn out_of_order_arrival_uses_source_chronology() {
        let mut d = Detector::default();
        d.ingest(&sysmon(3, 20, TARGET));
        assert_eq!(d.ingest(&sysmon(8, 10, ACTOR)).len(), 1);
        let mut d = Detector::default();
        d.ingest(&sysmon(3, 0, TARGET));
        assert!(d.ingest(&sysmon(8, 10, ACTOR)).is_empty());
    }
    #[test]
    fn outside_sequence_window_and_loopback_do_not_match() {
        let mut d = Detector::default();
        d.ingest(&sysmon(8, 0, ACTOR));
        assert!(d.ingest(&sysmon(3, 121, TARGET)).is_empty());
        let mut net = sysmon(3, 20, TARGET);
        if let EventData::NetworkConnect { dst_addr, .. } = &mut net.data {
            *dst_addr = "127.0.0.1".into();
        }
        assert!(d.ingest(&net).is_empty());
    }
    #[test]
    fn incomplete_or_legacy_evidence_is_reported_not_guessed() {
        for change in 0..5 {
            let mut d = Detector::default();
            let mut thread = sysmon(8, 0, ACTOR);
            let p = thread.provenance.as_mut().unwrap();
            match change {
                0 => p.original_time = false,
                1 => p.process_guid = None,
                2 => p.issues.push("decode_failed".into()),
                3 => thread.schema_version = 1,
                _ => p.provider_guid = "unknown".into(),
            }
            d.ingest(&thread);
            assert!(d.ingest(&sysmon(3, 20, TARGET)).is_empty());
            assert_eq!(d.stats.missing_evidence_events, 1);
        }
    }
    #[test]
    fn duplicate_native_records_with_new_envelope_ids_are_ignored() {
        let mut d = Detector::default();
        let mut thread = sysmon(8, 0, ACTOR);
        thread.provenance.as_mut().unwrap().record_id = Some(99);
        d.ingest(&thread);
        thread.id = Uuid::new_v4();
        d.ingest(&thread);
        assert_eq!(d.stats.duplicate_events, 1);
        let net = sysmon(3, 20, TARGET);
        assert_eq!(d.ingest(&net).len(), 1);
        assert!(d.ingest(&net).is_empty());
    }
    #[test]
    fn office_script_child_with_network_has_two_observations() {
        let mut d = Detector::default();
        d.ingest(&sysmon(1, 0, TARGET));
        let findings = d.ingest(&sysmon(3, 15, TARGET));
        assert_eq!(findings[0].rule.as_ref().unwrap().id, "TF-COR-002");
        assert_eq!(evidence(&findings[0]).len(), 2);
    }
    #[test]
    fn benign_parent_does_not_match_office_rule() {
        let mut d = Detector::default();
        let mut create = sysmon(1, 0, TARGET);
        create
            .provenance
            .as_mut()
            .unwrap()
            .fields
            .insert("ParentImage".into(), "explorer.exe".into());
        d.ingest(&create);
        assert!(d.ingest(&sysmon(3, 15, TARGET)).is_empty());
    }
    #[test]
    fn periodic_tcp_requires_intervals_and_distinct_events() {
        let mut d = Detector::default();
        for i in 0..9 {
            assert!(d.ingest(&sysmon(3, i * 30, TARGET)).is_empty());
        }
        let findings = d.ingest(&sysmon(3, 270, TARGET));
        assert_eq!(findings[0].rule.as_ref().unwrap().id, "TF-COR-003");
        assert_eq!(evidence(&findings[0]).len(), 10);
        assert!(d.ingest(&sysmon(3, 300, TARGET)).is_empty());
        let mut d = Detector::default();
        let net = sysmon(3, 0, TARGET);
        for _ in 0..12 {
            assert!(d.ingest(&net).is_empty());
        }
    }
    #[test]
    fn bursts_irregular_intervals_and_different_ports_are_not_periodic() {
        for kind in 0..3 {
            let mut d = Detector::default();
            for i in 0..10 {
                let mut e = sysmon(
                    3,
                    if kind == 0 {
                        i
                    } else if kind == 1 {
                        i * i * 5
                    } else {
                        i * 30
                    },
                    TARGET,
                );
                if kind == 2 {
                    if let EventData::NetworkConnect { dst_port, .. } = &mut e.data {
                        *dst_port += i as u16;
                    }
                }
                assert!(d.ingest(&e).is_empty());
            }
        }
    }
    #[test]
    fn packets_are_not_connections() {
        let mut d = Detector::default();
        for i in 0..12 {
            let mut e = sysmon(3, i * 30, TARGET);
            e.data = EventData::NetworkTraffic {
                pid: 100,
                protocol: "TCP".into(),
                src_addr: "10.0.0.1".into(),
                src_port: 1000,
                dst_addr: "192.0.2.10".into(),
                dst_port: 443,
                direction: NetworkDirection::Outbound,
                bytes: 100,
            };
            assert!(d.ingest(&e).is_empty());
        }
        assert_eq!(d.stats.eligible_events, 0);
    }
    #[test]
    fn state_and_lateness_limits_are_visible() {
        let mut d = Detector::default();
        for i in 0..70 {
            d.ingest(&sysmon(3, i, TARGET));
        }
        assert_eq!(d.stats.capacity_events_dropped, 6);
        assert!(d
            .timelines
            .values()
            .all(|t| t.observations.len() <= MAX_PER_KEY));
        d.ingest(&sysmon(3, 1000, TARGET));
        d.ingest(&sysmon(3, 0, TARGET));
        assert_eq!(d.stats.late_events, 1);
    }
}
