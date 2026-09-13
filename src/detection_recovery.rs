//! Incremental persistence protocol for the bounded correlator. Kept separate
//! from its rules; offline analysis does not accumulate persistence mutations.
use super::*;
use anyhow::{Context, Result};

// Bump whenever rule semantics, dedup keys, or serialized state change.
pub(crate) const STATE_VERSION: u32 = 1;
pub(crate) const MAX_TIMELINE_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateSnapshot {
    pub agent_id: Uuid,
    pub version: u32,
    pub timelines: Vec<(Uuid, Timeline)>,
    pub seen_order: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateDelta {
    pub agent_id: Uuid,
    pub version: u32,
    pub changes: Vec<(Uuid, Option<Timeline>)>,
    pub seen_added: Vec<String>,
    pub seen_removed: Vec<String>,
}

pub(super) struct Pending {
    pub agent_id: Uuid,
    changed: HashSet<Uuid>,
    added: Vec<String>,
    removed: Vec<String>,
    overflow: bool,
}

impl Pending {
    fn new(agent_id: Uuid) -> Self {
        Self {
            agent_id,
            changed: HashSet::new(),
            added: vec![],
            removed: vec![],
            overflow: false,
        }
    }
    pub(super) fn changed(&mut self, key: Uuid) {
        if self.changed.contains(&key) || self.changed.len() < MAX_KEYS + 32 {
            self.changed.insert(key);
        } else {
            self.overflow = true;
        }
    }
    pub(super) fn seen_added(&mut self, key: &str) {
        if self.added.len() < MAX_DEDUP {
            self.added.push(key.into());
        } else {
            self.overflow = true;
        }
    }
    pub(super) fn seen_removed(&mut self, key: &str) {
        if self.removed.len() < MAX_DEDUP {
            self.removed.push(key.into());
        } else {
            self.overflow = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{test_position, Checkpoint};
    use crate::fixtures::{sysmon, ACTOR, OTHER, TARGET};

    fn native(id: u16, time: i64, process: &str, record: u64) -> ThreatEvent {
        let mut event = sysmon(id, time, process);
        event.provenance.as_mut().unwrap().record_id = Some(record);
        event
    }

    fn signatures(events: &[ThreatEvent]) -> Vec<(String, Vec<Uuid>)> {
        events
            .iter()
            .map(|e| match &e.data {
                EventData::CorrelationDetection {
                    rule_id,
                    evidence_ids,
                    ..
                } => (rule_id.clone(), evidence_ids.clone()),
                _ => panic!("not a correlation"),
            })
            .collect()
    }

    #[test]
    fn every_restart_boundary_preserves_all_three_rules_and_evidence_ids() {
        let mut events = vec![
            native(10, 0, ACTOR, 1),
            native(8, 1, ACTOR, 2),
            native(3, 2, TARGET, 3),
            native(1, 10, OTHER, 4),
            native(3, 11, OTHER, 5),
        ];
        // Parent GUID must differ from child GUID in this Office fixture.
        events[3].provenance.as_mut().unwrap().parent_process_guid = Some(ACTOR.parse().unwrap());
        for n in 0..10 {
            events.push(native(3, 30 + n * 30, ACTOR, 6 + n as u64));
        }
        let agent = events[0].agent_id;
        let mut baseline = Detector::default();
        let expected: Vec<_> = events.iter().flat_map(|e| baseline.ingest(e)).collect();
        assert_eq!(expected.len(), 3);
        for split in 1..events.len() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.db");
            let mut store = Checkpoint::open(&path, agent).unwrap();
            let mut before = Detector::default();
            before.enable_checkpointing(agent).unwrap();
            let mut actual: Vec<_> = events[..split]
                .iter()
                .flat_map(|e| before.ingest(e))
                .collect();
            store
                .commit(
                    &test_position("native-position"),
                    &before.take_delta(agent).unwrap(),
                )
                .unwrap();
            drop(store);
            drop(before);
            let store = Checkpoint::open(&path, agent).unwrap();
            let mut after = Detector::default();
            after
                .restore(store.load_analysis().unwrap(), agent)
                .unwrap();
            actual.extend(events[split..].iter().flat_map(|e| after.ingest(e)));
            assert_eq!(
                signatures(&actual),
                signatures(&expected),
                "split at {split}"
            );
            assert!(after.stats.state_restored);
        }
    }

    #[test]
    fn committed_dedup_and_finding_suppression_survive_restart() {
        let first = native(8, 0, ACTOR, 1);
        let connection = native(3, 1, TARGET, 2);
        let agent = first.agent_id;
        let dir = tempfile::tempdir().unwrap();
        let mut store = Checkpoint::open(&dir.path().join("state.db"), agent).unwrap();
        let mut before = Detector::default();
        before.enable_checkpointing(agent).unwrap();
        before.ingest(&first);
        assert_eq!(before.ingest(&connection).len(), 1);
        store
            .commit(
                &test_position("native-position"),
                &before.take_delta(agent).unwrap(),
            )
            .unwrap();
        let mut after = Detector::default();
        after
            .restore(store.load_analysis().unwrap(), agent)
            .unwrap();
        let mut replay = connection.clone();
        replay.id = Uuid::new_v4();
        assert!(after.ingest(&replay).is_empty());
        assert_eq!(after.stats.duplicate_events, 1);
        assert!(after.ingest(&native(3, 2, TARGET, 3)).is_empty());
    }

    #[test]
    fn checkpoint_delta_contains_only_changed_timelines() {
        let agent = Uuid::from_u128(1);
        let mut detector = Detector::default();
        detector.enable_checkpointing(agent).unwrap();
        for n in 100..1100 {
            detector.ingest(&native(3, 0, &Uuid::from_u128(n).to_string(), n as u64));
        }
        assert_eq!(detector.take_delta(agent).unwrap().changes.len(), 1000);
        detector.ingest(&native(3, 1, &Uuid::from_u128(100).to_string(), 1100));
        let delta = detector.take_delta(agent).unwrap();
        assert_eq!(delta.changes.len(), 1);
        assert_eq!(delta.seen_added.len(), 1);
        assert!(delta.seen_removed.is_empty());
        assert_eq!(detector.timelines.len(), 1000);
    }

    #[test]
    fn timeline_expiration_and_late_arrivals_match_after_restore() {
        let event = native(8, 0, ACTOR, 1);
        let agent = event.agent_id;
        let dir = tempfile::tempdir().unwrap();
        let mut store = Checkpoint::open(&dir.path().join("state.db"), agent).unwrap();
        let mut detector = Detector::default();
        detector.enable_checkpointing(agent).unwrap();
        detector.ingest(&event);
        store
            .commit(
                &test_position("first"),
                &detector.take_delta(agent).unwrap(),
            )
            .unwrap();
        detector.ingest(&native(3, 700, OTHER, 2));
        let delta = detector.take_delta(agent).unwrap();
        assert!(delta
            .changes
            .iter()
            .any(|(id, t)| id.to_string() == TARGET && t.is_none()));
        store.commit(&test_position("second"), &delta).unwrap();
        let mut restored = Detector::default();
        restored
            .restore(store.load_analysis().unwrap(), agent)
            .unwrap();
        assert!(!restored
            .timelines
            .contains_key(&(agent, TARGET.parse().unwrap())));
        assert!(restored.ingest(&native(3, 0, OTHER, 3)).is_empty());
        assert_eq!(restored.stats.late_events, 1);
    }

    #[test]
    fn invalid_or_wrong_agent_snapshot_never_overwrites_live_state() {
        let agent = Uuid::from_u128(1);
        let mut detector = Detector::default();
        let mut snapshot = StateSnapshot::empty(agent);
        snapshot.version += 1;
        assert!(detector.restore(snapshot, agent).is_err());
        assert!(detector
            .restore(StateSnapshot::empty(Uuid::new_v4()), agent)
            .is_err());
        detector.ingest(&native(8, 0, ACTOR, 1));
        assert!(detector
            .restore(StateSnapshot::empty(agent), agent)
            .is_err());
        assert_eq!(detector.ingest(&native(3, 1, TARGET, 2)).len(), 1);
    }

    #[test]
    fn offline_analysis_never_accumulates_persistence_mutations() {
        let mut detector = Detector::default();
        for n in 0..100 {
            detector.ingest(&native(3, n, TARGET, n as u64 + 1));
        }
        assert!(detector.pending.is_none());
    }

    #[test]
    fn invalid_timeline_and_oversized_dedup_state_are_rejected() {
        let event = native(8, 0, ACTOR, 1);
        let agent = event.agent_id;
        let mut detector = Detector::default();
        detector.enable_checkpointing(agent).unwrap();
        detector.ingest(&event);
        let delta = detector.take_delta(agent).unwrap();
        let timeline = delta.changes[0].1.clone().unwrap();
        let mut snapshot = StateSnapshot::empty(agent);
        snapshot.timelines.push((TARGET.parse().unwrap(), timeline));
        assert!(snapshot.validate(agent).is_ok());
        snapshot.timelines[0].1.latest = None;
        assert!(snapshot.validate(agent).is_err());
        snapshot.timelines.clear();
        snapshot.seen_order = vec![format!("{agent}:test"); MAX_DEDUP + 1];
        assert!(snapshot.validate(agent).is_err());
    }
}

impl StateSnapshot {
    #[allow(dead_code)] // Constructed by Windows checkpoint loading; also tested portably.
    pub fn empty(agent_id: Uuid) -> Self {
        Self {
            agent_id,
            version: STATE_VERSION,
            timelines: vec![],
            seen_order: vec![],
        }
    }

    pub fn validate(&self, agent_id: Uuid) -> Result<()> {
        anyhow::ensure!(
            self.version == STATE_VERSION && self.agent_id == agent_id,
            "analysis state version/agent mismatch"
        );
        anyhow::ensure!(
            self.timelines.len() <= MAX_KEYS && self.seen_order.len() <= MAX_DEDUP,
            "analysis state exceeds capacity"
        );
        let mut keys = HashSet::new();
        for (process, timeline) in &self.timelines {
            anyhow::ensure!(
                !process.is_nil() && keys.insert(*process),
                "duplicate/invalid analysis process identity"
            );
            validate_timeline(timeline)?;
        }
        let mut seen = HashSet::new();
        for key in &self.seen_order {
            validate_seen_key(key, agent_id)?;
            anyhow::ensure!(seen.insert(key), "duplicate analysis dedup key");
        }
        Ok(())
    }
}

impl StateDelta {
    #[allow(dead_code)]
    pub fn empty(agent_id: Uuid) -> Self {
        Self {
            agent_id,
            version: STATE_VERSION,
            changes: vec![],
            seen_added: vec![],
            seen_removed: vec![],
        }
    }

    pub fn validate(&self, agent_id: Uuid) -> Result<()> {
        anyhow::ensure!(
            self.version == STATE_VERSION && self.agent_id == agent_id,
            "analysis delta version/agent mismatch"
        );
        anyhow::ensure!(
            self.changes.len() <= MAX_KEYS + 32
                && self.seen_added.len() <= MAX_DEDUP
                && self.seen_removed.len() <= MAX_DEDUP,
            "analysis delta exceeds capacity"
        );
        let mut keys = HashSet::new();
        for (key, timeline) in &self.changes {
            anyhow::ensure!(
                !key.is_nil() && keys.insert(*key),
                "duplicate/invalid analysis delta process identity"
            );
            if let Some(t) = timeline {
                validate_timeline(t)?;
            }
        }
        for key in self.seen_added.iter().chain(&self.seen_removed) {
            validate_seen_key(key, agent_id)?;
        }
        Ok(())
    }
}

fn validate_seen_key(key: &str, agent_id: Uuid) -> Result<()> {
    anyhow::ensure!(
        key.len() <= 256 && key.starts_with(&format!("{agent_id}:")),
        "invalid analysis dedup key"
    );
    Ok(())
}

fn validate_timeline(t: &Timeline) -> Result<()> {
    anyhow::ensure!(
        !t.observations.is_empty()
            && t.observations.len() <= MAX_PER_KEY
            && t.emitted.len() <= MAX_PER_KEY * 3,
        "invalid analysis timeline size"
    );
    let latest = t.latest.context("analysis timeline lacks source time")?;
    anyhow::ensure!(
        t.observations.iter().map(|o| o.time).max() == Some(latest),
        "analysis timeline source time mismatch"
    );
    for o in &t.observations {
        anyhow::ensure!(
            !o.id.is_nil() && (latest - o.time).num_seconds() <= WINDOW_SECS,
            "invalid analysis observation identity/time"
        );
        match &o.fact {
            Fact::Access { actor, mask } => anyhow::ensure!(
                !actor.is_nil() && mask & 0x28 == 0x28,
                "invalid process access state"
            ),
            Fact::Thread { actor } => {
                anyhow::ensure!(!actor.is_nil(), "invalid remote thread state")
            }
            Fact::ScriptChild { parent, image } => anyhow::ensure!(
                parent.len() <= 64 && image.len() <= 64,
                "invalid script child state"
            ),
            Fact::Connect {
                addr,
                port,
                protocol,
            } => {
                let ip: std::net::IpAddr = addr.parse()?;
                anyhow::ensure!(
                    !ip.is_loopback()
                        && !ip.is_unspecified()
                        && !ip.is_multicast()
                        && *port > 0
                        && matches!(protocol.as_str(), "TCP" | "UDP"),
                    "invalid network state"
                );
            }
        }
    }
    for key in &t.emitted {
        let mut parts = key.split('|');
        anyhow::ensure!(
            matches!(
                parts.next(),
                Some("TF-COR-001" | "TF-COR-002" | "TF-COR-003:")
            ) && key.len() <= 256,
            "invalid finding suppression key"
        );
        let id: Uuid = parts
            .next()
            .context("suppression key lacks evidence")?
            .parse()?;
        anyhow::ensure!(
            t.observations.iter().any(|o| o.id == id),
            "suppression key refers to expired evidence"
        );
    }
    anyhow::ensure!(
        serde_json::to_vec(t)?.len() <= MAX_TIMELINE_BYTES,
        "serialized analysis timeline exceeds limit"
    );
    Ok(())
}

impl Detector {
    pub fn enable_checkpointing(&mut self, agent_id: Uuid) -> Result<()> {
        if let Some(p) = &self.pending {
            anyhow::ensure!(p.agent_id == agent_id, "analysis checkpoint agent changed");
        } else {
            anyhow::ensure!(
                self.timelines.is_empty() && self.seen.is_empty(),
                "cannot enable checkpointing after untracked analysis"
            );
            self.pending = Some(Pending::new(agent_id));
        }
        Ok(())
    }

    pub fn restore(&mut self, snapshot: StateSnapshot, agent_id: Uuid) -> Result<()> {
        snapshot.validate(agent_id)?;
        anyhow::ensure!(
            self.timelines.is_empty() && self.seen.is_empty() && self.pending.is_none(),
            "cannot overwrite active analysis state"
        );
        self.stats.state_restored = true;
        self.stats.restored_timelines = snapshot.timelines.len() as u64;
        self.timelines = snapshot
            .timelines
            .into_iter()
            .map(|(process, t)| ((agent_id, process), t))
            .collect();
        self.seen = snapshot.seen_order.iter().cloned().collect();
        self.seen_order = snapshot.seen_order.into();
        self.pending = Some(Pending::new(agent_id));
        Ok(())
    }

    /// Called only after output durability succeeds for an acknowledged batch.
    pub fn take_delta(&mut self, agent_id: Uuid) -> Result<StateDelta> {
        self.enable_checkpointing(agent_id)?;
        let p = self.pending.as_mut().unwrap();
        anyhow::ensure!(
            !p.overflow,
            "analysis changes exceeded persistence capacity; checkpoint held"
        );
        let mut changes: Vec<_> = p
            .changed
            .drain()
            .map(|key| (key, self.timelines.get(&(agent_id, key)).cloned()))
            .collect();
        changes.sort_by_key(|(key, _)| *key);
        // Keep only surviving additions; the source batch is bounded, but this
        // also supports test/replay callers that checkpoint less frequently.
        let mut retained = HashSet::new();
        let mut seen_added: Vec<_> = std::mem::take(&mut p.added)
            .into_iter()
            .rev()
            .filter(|key| self.seen.contains(key) && retained.insert(key.clone()))
            .collect();
        seen_added.reverse();
        let delta = StateDelta {
            agent_id,
            version: STATE_VERSION,
            changes,
            seen_added,
            seen_removed: std::mem::take(&mut p.removed),
        };
        delta.validate(agent_id)?;
        Ok(delta)
    }
}
