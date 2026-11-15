//! In-memory agent status: last contact, last successful ingest, counters
//! and the most recent sensor health report, exposed through the admin API.
//!
//! Liveness is based on successful ingests (`last_seen`), not on contact:
//! an agent that keeps retrying while every request fails (for example with
//! 507 while the disk is full) is reported as `failing`, never as `ok`.
//!
//! Counters cover the current server process only. After a restart an
//! agent's `last_seen` is seeded from the modification time of its events
//! file until it reports again.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::ingest::BatchSummary;

/// Agent-supplied strings kept in the status are capped at this length.
const MAX_FIELD_CHARS: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    pub received_at: DateTime<Utc>,
    /// `data` of the agent's latest `SensorHealth` event, as sent.
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AgentStatus {
    pub name: String,
    /// Last time a batch from the agent was stored (or was already stored).
    pub last_seen: Option<DateTime<Utc>>,
    /// Last authenticated request from the agent, successful or not.
    pub last_contact: Option<DateTime<Utc>>,
    /// False when `last_seen` comes from the events file on disk rather
    /// than from a request received by this server process.
    pub seen_since_start: bool,
    pub remote_addr: Option<String>,
    pub hostname: Option<String>,
    pub agent_id: Option<String>,
    /// How often the reported `agent_id` changed (shared token, or the
    /// sensor's state file was reset).
    pub agent_id_changes: u64,
    pub sensor_version: Option<String>,
    pub last_event_timestamp: Option<String>,
    /// Successfully processed requests.
    pub batches: u64,
    /// Authenticated requests that failed (4xx/5xx).
    pub failed_requests: u64,
    /// Events stored.
    pub events: u64,
    /// Re-sent events that were already stored.
    pub duplicate_events: u64,
    /// Invalid elements written to the agent's quarantine file.
    pub quarantined_events: u64,
    /// Request body bytes of successful requests.
    pub bytes: u64,
    pub last_error: Option<String>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub health: Option<HealthReport>,
}

/// A status entry with derived fields, as returned by the admin API.
#[derive(Debug, Clone, Serialize)]
pub struct AgentView {
    #[serde(flatten)]
    pub status: AgentStatus,
    /// `ok`, `failing`, `stale` or `never_seen`; see [`agent_state`].
    pub state: &'static str,
    pub last_seen_age_secs: Option<i64>,
    pub last_contact_age_secs: Option<i64>,
    pub warnings: Vec<String>,
}

/// Everything recorded about one successfully processed request.
pub struct BatchRecord<'a> {
    pub remote_addr: &'a str,
    pub summary: BatchSummary,
    pub stored: u64,
    pub duplicates: u64,
    pub quarantined: u64,
    pub wire_bytes: u64,
}

pub struct StatusRegistry {
    agents: Mutex<BTreeMap<String, AgentStatus>>,
    stale_after: chrono::Duration,
}

impl StatusRegistry {
    /// `agents` yields every configured agent with its on-disk last write
    /// time, if any.
    pub fn new<'a>(
        agents: impl IntoIterator<Item = (&'a str, Option<SystemTime>)>,
        stale_after_secs: u64,
    ) -> Self {
        let agents = agents
            .into_iter()
            .map(|(name, last_write)| {
                let status = AgentStatus {
                    name: name.to_owned(),
                    last_seen: last_write.map(DateTime::<Utc>::from),
                    ..AgentStatus::default()
                };
                (name.to_owned(), status)
            })
            .collect();
        Self {
            agents: Mutex::new(agents),
            stale_after: chrono::Duration::seconds(
                i64::try_from(stale_after_secs).unwrap_or(i64::MAX),
            ),
        }
    }

    pub fn stale_after_secs(&self) -> i64 {
        self.stale_after.num_seconds()
    }

    /// Record a processed batch. Returns true if this is the agent's first
    /// request since the server started.
    pub fn record_batch(&self, agent: &str, now: DateTime<Utc>, rec: BatchRecord<'_>) -> bool {
        let mut agents = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        let st = entry(&mut agents, agent);
        let first = !st.seen_since_start;
        st.seen_since_start = true;
        st.last_seen = Some(now);
        st.last_contact = Some(now);
        st.remote_addr = Some(clip(rec.remote_addr.to_owned()));
        st.batches += 1;
        st.bytes += rec.wire_bytes;
        st.events += rec.stored;
        st.duplicate_events += rec.duplicates;
        st.quarantined_events += rec.quarantined;

        let s = rec.summary;
        if let Some(agent_id) = s.agent_id.map(clip) {
            if st.agent_id.as_deref().is_some_and(|prev| prev != agent_id) {
                st.agent_id_changes += 1;
            }
            st.agent_id = Some(agent_id);
        }
        if let Some(hostname) = s.hostname {
            st.hostname = Some(clip(hostname));
        }
        if let Some(version) = s.sensor_version {
            st.sensor_version = Some(clip(version));
        }
        if let Some(ts) = s.last_event_timestamp {
            st.last_event_timestamp = Some(clip(ts));
        }
        if let Some(data) = s.health {
            st.health = Some(HealthReport {
                received_at: now,
                data,
            });
        }
        first
    }

    /// Record a failed request from an authenticated agent. This is contact,
    /// not a successful ingest: `last_seen` is left alone.
    pub fn record_error(&self, agent: &str, now: DateTime<Utc>, remote_addr: &str, error: String) {
        let mut agents = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        let st = entry(&mut agents, agent);
        st.last_contact = Some(now);
        st.remote_addr = Some(clip(remote_addr.to_owned()));
        st.failed_requests += 1;
        st.last_error = Some(clip(error));
        st.last_error_at = Some(now);
    }

    pub fn snapshot(&self, now: DateTime<Utc>) -> Vec<AgentView> {
        let agents = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        let age = |t: Option<DateTime<Utc>>| t.map(|t| (now - t).num_seconds().max(0));
        agents
            .values()
            .map(|st| AgentView {
                state: agent_state(st, now, self.stale_after),
                last_seen_age_secs: age(st.last_seen),
                last_contact_age_secs: age(st.last_contact),
                warnings: warnings(st, now, self.stale_after),
                status: st.clone(),
            })
            .collect()
    }
}

fn entry<'m>(agents: &'m mut BTreeMap<String, AgentStatus>, agent: &str) -> &'m mut AgentStatus {
    agents
        .entry(agent.to_owned())
        .or_insert_with(|| AgentStatus {
            name: agent.to_owned(),
            ..AgentStatus::default()
        })
}

/// - `ok`: data was stored within `stale_after` and the latest request
///   did not fail.
/// - `failing`: the agent is in contact (within `stale_after`) but its
///   latest request failed, or nothing was stored for `stale_after`.
/// - `stale`: no contact and no data for `stale_after`.
/// - `never_seen`: nothing received since the agent was configured.
pub fn agent_state(
    st: &AgentStatus,
    now: DateTime<Utc>,
    stale_after: chrono::Duration,
) -> &'static str {
    let fresh = |t: Option<DateTime<Utc>>| t.is_some_and(|t| now - t <= stale_after);
    let latest_failed = match (st.last_error_at, st.last_seen) {
        (Some(err), Some(ok)) => err > ok,
        (Some(_), None) => true,
        (None, _) => false,
    };
    if st.last_seen.is_none() && st.last_contact.is_none() {
        "never_seen"
    } else if fresh(st.last_contact) && (latest_failed || !fresh(st.last_seen)) {
        "failing"
    } else if fresh(st.last_seen) {
        "ok"
    } else {
        "stale"
    }
}

fn warnings(st: &AgentStatus, now: DateTime<Utc>, recent: chrono::Duration) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(h) = &st.health {
        let d = &h.data;
        if let Some(n) = d
            .get("events_dropped")
            .and_then(|v| v.as_u64())
            .filter(|n| *n > 0)
        {
            out.push(format!("sensor dropped {n} events"));
        }
        if let Some(collectors) = d.get("collectors").and_then(|v| v.as_array()) {
            let state = |c: &serde_json::Value| {
                c.get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_owned()
            };
            // The sensor marks its collectors Stopped only in the final
            // health event it sends when it shuts down.
            let shut_down = collectors.iter().any(|c| state(c) == "Stopped")
                && collectors
                    .iter()
                    .all(|c| matches!(state(c).as_str(), "Stopped" | "Disabled"));
            if shut_down {
                out.push("sensor was shut down (final health event)".to_owned());
            } else {
                for c in collectors {
                    let state = state(c);
                    if state != "Running" && state != "Disabled" {
                        let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                        out.push(clip(format!("collector {name} is {state}")));
                    }
                }
            }
        }
        if let Some(sink) = d.get("sink") {
            if let Some(n) = sink
                .get("events_dropped")
                .and_then(|v| v.as_u64())
                .filter(|n| *n > 0)
            {
                out.push(format!("sink dropped {n} events"));
            }
            if let Some(n) = sink
                .get("spool_files")
                .and_then(|v| v.as_u64())
                .filter(|n| *n > 0)
            {
                out.push(format!("{n} batches spooled on the agent"));
            }
        }
    }
    if st.quarantined_events > 0 {
        out.push(format!(
            "{} invalid events quarantined since server start (agents/{}/rejected.jsonl)",
            st.quarantined_events, st.name
        ));
    }
    if st.agent_id_changes > 0 {
        out.push(format!("agent_id changed {} times", st.agent_id_changes));
    }
    if let (Some(err), Some(at)) = (&st.last_error, st.last_error_at) {
        if now - at <= recent {
            out.push(format!("last failed request: {err}"));
        }
    }
    out
}

fn clip(s: String) -> String {
    if s.chars().count() <= MAX_FIELD_CHARS {
        s
    } else {
        let mut out: String = s.chars().take(MAX_FIELD_CHARS).collect();
        out.push('…');
        out
    }
}

/// Make agent-supplied text safe to print on a terminal: no control
/// characters (escape sequences, line breaks) and no bidi overrides.
fn terminal_safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            let bidi = matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
            if c.is_control() || bidi {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Fixed-width table for `GET /api/v1/agents?format=text`.
pub fn render_text(views: &[AgentView], now: DateTime<Utc>) -> String {
    let mut rows = vec![[
        "NAME".to_string(),
        "STATE".into(),
        "LAST SEEN (UTC)".into(),
        "AGE".into(),
        "HOSTNAME".into(),
        "VERSION".into(),
        "EVENTS".into(),
        "QUARANTINED".into(),
        "FAILED".into(),
    ]];
    for v in views {
        let s = &v.status;
        let dash = || "-".to_string();
        let text = |o: &Option<String>| o.as_deref().map(terminal_safe).unwrap_or_else(dash);
        rows.push([
            s.name.clone(),
            v.state.to_string(),
            s.last_seen
                .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(dash),
            v.last_seen_age_secs.map(format_age).unwrap_or_else(dash),
            text(&s.hostname),
            text(&s.sensor_version),
            s.events.to_string(),
            s.quarantined_events.to_string(),
            s.failed_requests.to_string(),
        ]);
    }
    let mut widths = [0usize; 9];
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut out = format!(
        "generated {} (LAST SEEN = last stored batch; counters since server start)\n",
        now.format("%Y-%m-%d %H:%M:%S UTC")
    );
    for row in &rows {
        let mut line = String::new();
        for (i, (cell, w)) in row.iter().zip(widths).enumerate() {
            if i > 0 {
                line.push_str("  ");
            }
            let _ = write!(line, "{cell:<w$}");
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    for v in views.iter().filter(|v| !v.warnings.is_empty()) {
        for w in &v.warnings {
            let _ = writeln!(out, "! {}: {}", v.status.name, terminal_safe(w));
        }
    }
    out
}

fn format_age(secs: i64) -> String {
    match secs {
        s if s < 120 => format!("{s}s"),
        s if s < 7200 => format!("{}m", s / 60),
        s if s < 172_800 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    fn record<'a>(summary: BatchSummary, stored: u64) -> BatchRecord<'a> {
        BatchRecord {
            remote_addr: "198.51.100.7",
            summary,
            stored,
            duplicates: 0,
            quarantined: 0,
            wire_bytes: 100,
        }
    }

    fn state_at(reg: &StatusRegistry, secs: i64) -> &'static str {
        reg.snapshot(t(secs))[0].state
    }

    #[test]
    fn configured_agents_start_as_never_seen() {
        let reg = StatusRegistry::new([("a", None), ("b", Some(SystemTime::UNIX_EPOCH))], 300);
        let views = reg.snapshot(t(0));
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].state, "never_seen");
        assert_eq!(views[1].state, "stale");
        assert!(!views[1].status.seen_since_start);
        assert!(views[1].status.last_contact.is_none());
    }

    #[test]
    fn records_batches_and_staleness() {
        let reg = StatusRegistry::new([("a", None)], 300);
        let summary = BatchSummary {
            hostname: Some("HOST".into()),
            agent_id: Some("id-1".into()),
            sensor_version: Some("0.5.0".into()),
            last_event_timestamp: Some("2026-11-15T00:00:00Z".into()),
            health: Some(json!({"uptime_secs": 5, "events_dropped": 0, "collectors": []})),
        };
        assert!(reg.record_batch("a", t(0), record(summary, 10)));
        let mut dup = record(BatchSummary::default(), 0);
        dup.duplicates = 10;
        assert!(!reg.record_batch("a", t(1), dup));

        let v = &reg.snapshot(t(10))[0];
        assert_eq!(v.state, "ok");
        assert_eq!(v.last_seen_age_secs, Some(9));
        assert_eq!(v.status.events, 10);
        assert_eq!(v.status.duplicate_events, 10);
        assert_eq!(v.status.batches, 2);
        assert_eq!(v.status.hostname.as_deref(), Some("HOST"));
        assert!(v.warnings.is_empty(), "{:?}", v.warnings);
        assert_eq!(state_at(&reg, 1000), "stale");
    }

    #[test]
    fn failing_requests_never_count_as_alive() {
        let reg = StatusRegistry::new([("a", None)], 300);
        // Contact without any stored data is failing, not ok.
        reg.record_error("a", t(0), "198.51.100.7", "disk full".into());
        assert_eq!(state_at(&reg, 1), "failing");

        reg.record_batch("a", t(10), record(BatchSummary::default(), 1));
        assert_eq!(state_at(&reg, 11), "ok");

        // The latest request failed: failing right away.
        reg.record_error("a", t(20), "198.51.100.7", "disk full".into());
        assert_eq!(state_at(&reg, 21), "failing");

        // Sustained failures (e.g. 507 for an hour) stay failing, while
        // last_seen keeps the time of the last stored batch.
        for s in (60..3600).step_by(60) {
            reg.record_error("a", t(s), "198.51.100.7", "disk full".into());
        }
        let v = &reg.snapshot(t(3600))[0];
        assert_eq!(v.state, "failing");
        assert_eq!(v.status.last_seen, Some(t(10)));
        assert_eq!(v.last_contact_age_secs, Some(60));
        assert_eq!(v.status.failed_requests, 61);
        assert!(v.warnings.iter().any(|w| w.contains("disk full")));

        // Once the retries stop as well, the agent is stale.
        assert_eq!(state_at(&reg, 3600 + 1000), "stale");

        // A successful batch recovers immediately.
        reg.record_batch("a", t(5000), record(BatchSummary::default(), 1));
        assert_eq!(state_at(&reg, 5001), "ok");
    }

    #[test]
    fn derives_warnings_from_health_and_errors() {
        let reg = StatusRegistry::new([("a", None)], 300);
        let mk = |id: &str, health| BatchSummary {
            agent_id: Some(id.into()),
            health,
            ..BatchSummary::default()
        };
        let mut first = record(
            mk(
                "id-1",
                Some(json!({
                    "events_dropped": 3,
                    "collectors": [
                        {"name": "ETW", "state": "Error"},
                        {"name": "Sysmon", "state": "Disabled"}
                    ],
                    "sink": {"sink_type": "http", "events_dropped": 2, "spool_files": 4}
                })),
            ),
            1,
        );
        first.quarantined = 2;
        reg.record_batch("a", t(0), first);
        reg.record_batch("a", t(1), record(mk("id-2", None), 1));
        reg.record_error("a", t(2), "198.51.100.7", "disk full".into());

        let v = &reg.snapshot(t(3))[0];
        let w = v.warnings.join("|");
        assert!(w.contains("sensor dropped 3 events"), "{w}");
        assert!(w.contains("collector ETW is Error"), "{w}");
        assert!(!w.contains("Sysmon"), "{w}");
        assert!(w.contains("sink dropped 2 events"), "{w}");
        assert!(w.contains("4 batches spooled"), "{w}");
        assert!(w.contains("2 invalid events quarantined"), "{w}");
        assert!(w.contains("agents/a/rejected.jsonl"), "{w}");
        assert!(w.contains("agent_id changed 1 times"), "{w}");
        assert!(w.contains("last failed request: disk full"), "{w}");
        // The health report from the first batch is kept.
        assert!(v.status.health.is_some());
        // Old errors stop being reported.
        let later = reg.snapshot(t(1000));
        assert!(!later[0].warnings.iter().any(|w| w.contains("disk full")));
    }

    #[test]
    fn final_health_event_reads_as_shutdown() {
        let reg = StatusRegistry::new([("a", None)], 300);
        let health = |states: [&str; 3]| BatchSummary {
            agent_id: Some("id-1".into()),
            health: Some(json!({
                "collectors": [
                    {"name": "ETW", "state": states[0]},
                    {"name": "Sysmon", "state": states[1]},
                    {"name": "EvasionDetector", "state": states[2]}
                ]
            })),
            ..BatchSummary::default()
        };
        reg.record_batch(
            "a",
            t(0),
            record(health(["Stopped", "Disabled", "Stopped"]), 1),
        );
        let w = reg.snapshot(t(1))[0].warnings.join("|");
        assert_eq!(w, "sensor was shut down (final health event)");

        // A collector that stopped while others still run is still reported
        reg.record_batch(
            "a",
            t(2),
            record(health(["Running", "Disabled", "Stopped"]), 1),
        );
        let w = reg.snapshot(t(3))[0].warnings.join("|");
        assert_eq!(w, "collector EvasionDetector is Stopped");
    }

    #[test]
    fn renders_text_table() {
        let reg = StatusRegistry::new([("lab-ws01", None), ("lab-ws02", None)], 300);
        reg.record_batch(
            "lab-ws01",
            t(0),
            record(
                BatchSummary {
                    hostname: Some("MALANA-WS".into()),
                    sensor_version: Some("0.5.0".into()),
                    ..BatchSummary::default()
                },
                42,
            ),
        );
        let text = render_text(&reg.snapshot(t(5)), t(5));
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[1].starts_with("NAME"));
        assert!(lines[2].starts_with("lab-ws01"));
        assert!(
            lines[2].contains("ok") && lines[2].contains("MALANA-WS") && lines[2].contains("42")
        );
        assert!(lines[3].starts_with("lab-ws02") && lines[3].contains("never_seen"));
    }

    #[test]
    fn agent_supplied_text_is_clipped_and_terminal_safe() {
        let reg = StatusRegistry::new([("a", None)], 300);
        let evil = format!(
            "\u{1b}]0;pwned\u{7}HOST\nFAKE LINE\u{202e}{}",
            "x".repeat(1000)
        );
        reg.record_batch(
            "a",
            t(0),
            record(
                BatchSummary {
                    hostname: Some(evil.clone()),
                    health: Some(json!({"collectors": [{"name": "\u{1b}[2J", "state": "Error"}]})),
                    ..BatchSummary::default()
                },
                1,
            ),
        );
        let views = reg.snapshot(t(1));
        let stored = views[0].status.hostname.as_deref().unwrap();
        assert_eq!(stored.chars().count(), MAX_FIELD_CHARS + 1);
        let text = render_text(&views, t(1));
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "{text:?}"
        );
        assert!(!text.contains('\u{202e}'));
        assert!(!text.contains("\nFAKE LINE"));
        // JSON output keeps the (clipped) value; serde escapes it.
        let json = serde_json::to_string(&views).unwrap();
        assert!(json.contains("\\u001b"));
    }

    #[test]
    fn formats_ages() {
        assert_eq!(format_age(5), "5s");
        assert_eq!(format_age(600), "10m");
        assert_eq!(format_age(36_000), "10h");
        assert_eq!(format_age(864_000), "10d");
    }
}
