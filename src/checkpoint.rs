//! Small, agent-bound SQLite checkpoint. Never records queue acceptance as delivery.
#![allow(dead_code)] // Production caller is Windows-only; tests are portable.
use crate::detection::{
    StateDelta, StateSnapshot, MAX_DEDUP, MAX_KEYS, MAX_TIMELINE_BYTES, STATE_VERSION,
};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

const CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";
pub struct Checkpoint {
    conn: Connection,
    agent_id: Uuid,
}

/// Record numbers may be reused after a channel is cleared. Bind the bookmark
/// to native creation time and event identity as well, without copying payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceAnchor {
    pub record_id: u64,
    pub event_id: u16,
    pub system_time: String,
    pub computer: String,
}

impl SourceAnchor {
    pub fn from_event(event: &crate::events::ThreatEvent) -> Result<Self> {
        let p = event
            .provenance
            .as_ref()
            .context("checkpoint event lacks native provenance")?;
        let anchor = Self {
            record_id: p.record_id.context("checkpoint event lacks record ID")?,
            event_id: p.event_id,
            system_time: p
                .fields
                .get("System.TimeCreated")
                .context("checkpoint event lacks native SystemTime")?
                .clone(),
            computer: p
                .fields
                .get("System.Computer")
                .context("checkpoint event lacks Computer")?
                .clone(),
        };
        anchor.validate()?;
        Ok(anchor)
    }
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.record_id > 0 && !self.computer.is_empty() && self.computer.len() <= 1024,
            "invalid checkpoint record identity"
        );
        chrono::DateTime::parse_from_rfc3339(&self.system_time)
            .context("invalid checkpoint source time")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    pub bookmark: String,
    pub anchor: SourceAnchor,
}

impl Checkpoint {
    pub fn open(path: &Path, agent: Uuid) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut conn = Connection::open(path).context("cannot open Sysmon checkpoint")?;
        conn.busy_timeout(std::time::Duration::from_millis(250))?;
        // Hold an exclusive SQLite lock for the lifetime of this collector.
        // Two sensors must not independently advance the same source cursor.
        // Reuse the rollback journal instead of creating/deleting it per batch;
        // this also limits self-generated filesystem telemetry.
        conn.execute_batch(
            "PRAGMA journal_mode=PERSIST; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE;
            BEGIN EXCLUSIVE; COMMIT;",
        )?;
        let tx = conn.transaction()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='checkpoint' AND type='table')",
            [],
            |r| r.get(0),
        )?;
        if !exists {
            let tables: i64 = tx.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                [],
                |r| r.get(0),
            )?;
            anyhow::ensure!(
                tables == 0,
                "refusing to initialize checkpoint in a nonempty unrelated database"
            );
            tx.execute_batch(
                "CREATE TABLE checkpoint (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), format_version INTEGER NOT NULL,
                agent_id TEXT NOT NULL, channel TEXT NOT NULL, bookmark TEXT, analysis_version INTEGER NOT NULL);
                CREATE TABLE analysis_timelines (process_guid TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE analysis_seen (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT NOT NULL UNIQUE);",
            )?;
            tx.execute(
                "INSERT INTO checkpoint VALUES(1,3,?1,?2,NULL,?3)",
                params![agent.to_string(), CHANNEL, STATE_VERSION],
            )?;
        }
        let format: i64 = tx.query_row(
            "SELECT format_version FROM checkpoint WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        anyhow::ensure!(format==3,"checkpoint version mismatch; older source-only checkpoints cannot safely reconstruct analysis and are not automatically migrated or reset");
        let identity: (i64, String, String, i64) = tx.query_row(
            "SELECT format_version,agent_id,channel,analysis_version FROM checkpoint WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?,r.get(3)?)),
        )?;
        anyhow::ensure!(
            identity
                == (
                    3,
                    agent.to_string(),
                    CHANNEL.to_owned(),
                    STATE_VERSION as i64
                ),
            "checkpoint identity/version mismatch; refusing to reuse or reset it"
        );
        tx.commit()?;
        Ok(Self {
            conn,
            agent_id: agent,
        })
    }

    pub fn load(&self) -> Result<Option<Position>> {
        let bookmark: Option<String> = self.conn.query_row(
            "SELECT bookmark FROM checkpoint WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        bookmark
            .map(|data| {
                anyhow::ensure!(data.len() <= 131072, "checkpoint exceeds size limit");
                let position: Position =
                    serde_json::from_str(&data).context("invalid checkpoint record")?;
                validate(&position.bookmark)?;
                position.anchor.validate()?;
                Ok(position)
            })
            .transpose()
    }

    #[cfg(test)]
    pub fn save(&mut self, position: &Position) -> Result<()> {
        self.commit(position, &StateDelta::empty(self.agent_id))
    }

    /// Source position and correlator mutations form ONE database commit. File
    /// output has already been synchronized before this method is called.
    pub fn commit(&mut self, position: &Position, delta: &StateDelta) -> Result<()> {
        validate(&position.bookmark)?;
        position.anchor.validate()?;
        delta.validate(self.agent_id)?;
        let data = serde_json::to_string(position)?;
        let tx = self.conn.transaction()?;
        for (key, timeline) in &delta.changes {
            if let Some(timeline) = timeline {
                tx.execute("INSERT INTO analysis_timelines VALUES(?1,?2) ON CONFLICT(process_guid) DO UPDATE SET payload=excluded.payload",
                    params![key.to_string(),serde_json::to_string(timeline)?])?;
            } else {
                tx.execute(
                    "DELETE FROM analysis_timelines WHERE process_guid=?1",
                    [key.to_string()],
                )?;
            }
        }
        for key in &delta.seen_removed {
            tx.execute("DELETE FROM analysis_seen WHERE event_key=?1", [key])?;
        }
        for key in &delta.seen_added {
            tx.execute(
                "INSERT OR REPLACE INTO analysis_seen(event_key) VALUES(?1)",
                [key],
            )?;
        }
        let timelines: i64 =
            tx.query_row("SELECT COUNT(*) FROM analysis_timelines", [], |r| r.get(0))?;
        let seen: i64 = tx.query_row("SELECT COUNT(*) FROM analysis_seen", [], |r| r.get(0))?;
        anyhow::ensure!(
            timelines <= MAX_KEYS as i64 && seen <= MAX_DEDUP as i64,
            "persisted analysis capacity exceeded"
        );
        anyhow::ensure!(
            tx.execute(
                "UPDATE checkpoint SET bookmark=?1 WHERE singleton=1",
                [data]
            )? == 1,
            "checkpoint row missing"
        );
        tx.commit()?;
        Ok(())
    }

    pub fn load_analysis(&self) -> Result<StateSnapshot> {
        let (count,max_bytes,max_key):(i64,i64,i64)=self.conn.query_row(
            "SELECT COUNT(*),COALESCE(MAX(length(CAST(payload AS BLOB))),0),COALESCE(MAX(length(CAST(process_guid AS BLOB))),0) FROM analysis_timelines",[],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        let (seen_count, max_seen): (i64, i64) = self.conn.query_row(
            "SELECT COUNT(*),COALESCE(MAX(length(CAST(event_key AS BLOB))),0) FROM analysis_seen",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        anyhow::ensure!(
            count <= MAX_KEYS as i64
                && max_bytes <= MAX_TIMELINE_BYTES as i64
                && max_key <= 36
                && seen_count <= MAX_DEDUP as i64
                && max_seen <= 256,
            "stored analysis state exceeds limits"
        );
        anyhow::ensure!(
            self.load()?.is_some() || (count == 0 && seen_count == 0),
            "analysis state has no matching source checkpoint"
        );
        let mut state = StateSnapshot::empty(self.agent_id);
        let mut statement = self
            .conn
            .prepare("SELECT process_guid,payload FROM analysis_timelines ORDER BY process_guid")?;
        let rows =
            statement.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (key, payload) = row?;
            state
                .timelines
                .push((key.parse()?, serde_json::from_str(&payload)?));
        }
        let mut statement = self
            .conn
            .prepare("SELECT event_key FROM analysis_seen ORDER BY seq")?;
        state.seen_order = statement
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?;
        state.validate(self.agent_id)?;
        Ok(state)
    }
}

fn validate(xml: &str) -> Result<()> {
    anyhow::ensure!(
        !xml.is_empty() && xml.len() <= 65536 && !xml.contains('\0'),
        "invalid checkpoint XML size/encoding"
    );
    Ok(())
}

#[cfg(test)]
pub fn test_position(bookmark: &str) -> Position {
    Position {
        bookmark: bookmark.into(),
        anchor: SourceAnchor {
            record_id: 1,
            event_id: 1,
            system_time: "2026-09-12T00:00:00.0000000Z".into(),
            computer: "TEST".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_source_only_checkpoint_requires_explicit_operator_migration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let agent = Uuid::new_v4();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE checkpoint(singleton INTEGER PRIMARY KEY,format_version INTEGER,agent_id TEXT,channel TEXT,bookmark TEXT);").unwrap();
        conn.execute(
            "INSERT INTO checkpoint VALUES(1,2,?1,?2,'retained-native-bookmark')",
            params![agent.to_string(), CHANNEL],
        )
        .unwrap();
        drop(conn);
        let error = Checkpoint::open(&path, agent).err().unwrap().to_string();
        assert!(error.contains("not automatically migrated"));
        let conn = Connection::open(&path).unwrap();
        let bookmark: String = conn
            .query_row("SELECT bookmark FROM checkpoint", [], |r| r.get(0))
            .unwrap();
        assert_eq!(bookmark, "retained-native-bookmark");
    }

    #[test]
    fn transaction_failure_rolls_back_source_cursor_and_analysis_together() {
        use crate::detection::Detector;
        use crate::fixtures::{sysmon, ACTOR, TARGET};
        let first = sysmon(8, 0, ACTOR);
        let later = sysmon(3, 1, TARGET);
        let agent = first.agent_id;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.db");
        let mut store = Checkpoint::open(&path, agent).unwrap();
        let mut detector = Detector::default();
        detector.enable_checkpointing(agent).unwrap();
        detector.ingest(&first);
        store
            .commit(
                &test_position("before"),
                &detector.take_delta(agent).unwrap(),
            )
            .unwrap();
        let old = store.load_analysis().unwrap();
        assert_eq!(detector.ingest(&later).len(), 1);
        let delta = detector.take_delta(agent).unwrap();
        store.conn.execute_batch("CREATE TEMP TRIGGER inject_failure BEFORE UPDATE ON checkpoint BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
        assert!(store.commit(&test_position("after"), &delta).is_err());
        drop(store);
        let store = Checkpoint::open(&path, agent).unwrap();
        assert_eq!(store.load().unwrap(), Some(test_position("before")));
        assert_eq!(store.load_analysis().unwrap(), old);
        let mut restored = Detector::default();
        restored.restore(old, agent).unwrap();
        // The failed commit must not suppress the finding on source replay.
        assert_eq!(restored.ingest(&later).len(), 1);
    }

    #[test]
    fn corrupt_or_version_mismatched_analysis_is_not_silently_discarded() {
        for mutation in [
            "UPDATE checkpoint SET analysis_version=999",
            "INSERT INTO analysis_timelines VALUES('22222222-2222-2222-2222-222222222222','broken')",
            "INSERT INTO analysis_seen(event_key) VALUES('wrong-agent:key')",
        ] {
            let dir=tempfile::tempdir().unwrap();let path=dir.path().join("state.db");let agent=Uuid::new_v4();
            let mut store=Checkpoint::open(&path,agent).unwrap();store.save(&test_position("before")).unwrap();drop(store);
            Connection::open(&path).unwrap().execute_batch(mutation).unwrap();
            assert!(Checkpoint::open(&path,agent).and_then(|s|s.load_analysis()).is_err());
        }
    }
    #[test]
    fn survives_restart_and_rejects_a_different_agent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.db");
        let id = Uuid::new_v4();
        {
            let mut c = Checkpoint::open(&path, id).unwrap();
            assert!(c.load().unwrap().is_none());
            c.save(&test_position("<BookmarkList/>")).unwrap();
        }
        assert!(Checkpoint::open(&path, Uuid::new_v4()).is_err());
        let c = Checkpoint::open(&path, id).unwrap();
        assert_eq!(c.load().unwrap(), Some(test_position("<BookmarkList/>")));
    }
    #[test]
    fn failure_keeps_previous_checkpoint_and_duplicate_owner_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.db");
        let id = Uuid::new_v4();
        let mut c = Checkpoint::open(&path, id).unwrap();
        c.save(&test_position("first")).unwrap();
        assert!(c.save(&test_position("")).is_err());
        assert_eq!(c.load().unwrap().unwrap(), test_position("first"));
        assert!(Checkpoint::open(&path, id).is_err());
    }

    #[test]
    fn damaged_row_or_payload_is_not_silently_reset() {
        for mutation in [
            "DELETE FROM checkpoint",
            "UPDATE checkpoint SET bookmark='broken'",
            "UPDATE checkpoint SET format_version=999",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("checkpoint.db");
            let id = Uuid::new_v4();
            drop(Checkpoint::open(&path, id).unwrap());
            Connection::open(&path)
                .unwrap()
                .execute_batch(mutation)
                .unwrap();
            assert!(Checkpoint::open(&path, id).and_then(|c| c.load()).is_err());
        }
    }

    #[test]
    fn source_anchor_requires_native_identity_and_detects_reused_record_number() {
        let mut event = crate::fixtures::sysmon(1, 0, crate::fixtures::ACTOR);
        assert!(SourceAnchor::from_event(&event).is_err());
        let p = event.provenance.as_mut().unwrap();
        p.record_id = Some(1);
        p.fields
            .insert("System.TimeCreated".into(), "2026-09-12T00:00:00Z".into());
        p.fields.insert("System.Computer".into(), "TEST".into());
        let previous = SourceAnchor::from_event(&event).unwrap();
        event
            .provenance
            .as_mut()
            .unwrap()
            .fields
            .insert("System.TimeCreated".into(), "2026-09-12T00:00:01Z".into());
        assert_ne!(SourceAnchor::from_event(&event).unwrap(), previous);
    }

    #[test]
    fn checkpoint_uses_full_sync_and_reuses_rollback_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.db");
        let mut store = Checkpoint::open(&path, Uuid::new_v4()).unwrap();
        let mode: String = store
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        let sync: i64 = store
            .conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "persist");
        assert_eq!(sync, 2);
        store.save(&test_position("first")).unwrap();
        let journal = dir.path().join("checkpoint.db-journal");
        assert!(journal.exists());
        store.save(&test_position("second")).unwrap();
        assert!(journal.exists());
    }
}
