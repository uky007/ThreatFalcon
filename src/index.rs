//! SQLite-based sidecar index for fast event lookups from JSONL files.
//!
//! The JSONL file remains the source of truth. The index stores extracted
//! fields plus byte offsets so that queries can skip full file scans and
//! seek directly to matching events.

use std::io::{BufRead, Read as _, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OpenFlags};

use crate::events::{EventCategory, EventData, EventSource, Severity, ThreatEvent};

/// Current schema version — bump when the table structure changes.
const SCHEMA_VERSION: u32 = 1;

/// A location within the JSONL file for direct seeking.
#[derive(Debug, Clone)]
pub struct EventLocation {
    pub byte_offset: u64,
    pub line_length: u64,
}

/// SQLite-backed event index.
pub struct EventIndex {
    conn: Connection,
}

/// Index health status returned by `status()`.
#[derive(Debug)]
pub struct IndexStatus {
    pub event_count: u64,
    pub indexed_up_to: u64,
    pub jsonl_size: u64,
    pub is_current: bool,
}

impl EventIndex {
    /// Open or create an index for the given JSONL file.
    pub fn open(jsonl_path: &Path) -> Result<Self> {
        let idx_path = index_path_for(jsonl_path);
        let conn = Connection::open_with_flags(
            &idx_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("failed to open index at {}", idx_path.display()))?;

        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        init_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Open an existing index read-only. Returns `None` if the file doesn't exist.
    #[allow(dead_code)]
    pub fn open_readonly(jsonl_path: &Path) -> Result<Option<Self>> {
        let idx_path = index_path_for(jsonl_path);
        if !idx_path.exists() {
            return Ok(None);
        }
        let conn = Connection::open_with_flags(
            &idx_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("failed to open index at {}", idx_path.display()))?;
        Ok(Some(Self { conn }))
    }

    /// Build or incrementally update the index from the JSONL file.
    pub fn build(&self, jsonl_path: &Path) -> Result<IndexStats> {
        let file_size = std::fs::metadata(jsonl_path)
            .with_context(|| format!("cannot stat {}", jsonl_path.display()))?
            .len();

        let indexed_up_to = self.get_meta_u64("indexed_up_to").unwrap_or(0);
        let stored_version = self.get_meta_u64("schema_version").unwrap_or(0);

        // Rebuild from scratch if file was truncated or schema changed
        if file_size < indexed_up_to || stored_version != SCHEMA_VERSION as u64 {
            self.conn.execute("DELETE FROM events", [])?;
            self.index_range(jsonl_path, 0, file_size)
        } else if indexed_up_to < file_size {
            self.index_range(jsonl_path, indexed_up_to, file_size)
        } else {
            Ok(IndexStats {
                new_events: 0,
                total_events: self.event_count()?,
            })
        }
    }

    /// Force a full rebuild (drop all rows and re-index).
    pub fn rebuild(&self, jsonl_path: &Path) -> Result<IndexStats> {
        self.conn.execute("DELETE FROM events", [])?;
        self.set_meta_u64("indexed_up_to", 0)?;
        let file_size = std::fs::metadata(jsonl_path)
            .with_context(|| format!("cannot stat {}", jsonl_path.display()))?
            .len();
        self.index_range(jsonl_path, 0, file_size)
    }

    /// Check if the index needs updating (stale or missing data).
    pub fn needs_update(&self, jsonl_path: &Path) -> Result<bool> {
        let file_size = std::fs::metadata(jsonl_path)
            .with_context(|| format!("cannot stat {}", jsonl_path.display()))?
            .len();
        let indexed_up_to = self.get_meta_u64("indexed_up_to").unwrap_or(0);
        let stored_version = self.get_meta_u64("schema_version").unwrap_or(0);
        Ok(stored_version != SCHEMA_VERSION as u64 || indexed_up_to != file_size)
    }

    /// Return index health status.
    pub fn status(&self, jsonl_path: &Path) -> Result<IndexStatus> {
        let file_size = std::fs::metadata(jsonl_path)
            .with_context(|| format!("cannot stat {}", jsonl_path.display()))?
            .len();
        let indexed_up_to = self.get_meta_u64("indexed_up_to").unwrap_or(0);
        let count = self.event_count()?;
        Ok(IndexStatus {
            event_count: count,
            indexed_up_to,
            jsonl_size: file_size,
            is_current: indexed_up_to == file_size,
        })
    }

    /// Query the index and return byte-offset locations matching the filter.
    pub fn query_locations(&self, filter: &IndexFilter) -> Result<Vec<EventLocation>> {
        let mut conditions = Vec::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(pid) = filter.pid {
            conditions.push("pid = ?".to_string());
            param_values.push(Box::new(pid as i64));
        }
        if let Some(ref key) = filter.process_key {
            conditions.push("process_key = ?".to_string());
            param_values.push(Box::new(key.clone()));
        }
        if let Some(ref cat) = filter.category {
            conditions.push("category = ? COLLATE NOCASE".to_string());
            param_values.push(Box::new(cat.clone()));
        }
        if let Some(ref rule_id) = filter.rule_id {
            conditions.push("rule_id = ?".to_string());
            param_values.push(Box::new(rule_id.clone()));
        }
        if let Some(ref src) = filter.source_type {
            conditions.push("(source_type = ? COLLATE NOCASE OR source_detail LIKE ? COLLATE NOCASE)".to_string());
            param_values.push(Box::new(src.clone()));
            param_values.push(Box::new(format!("%{src}%")));
        }
        if let Some(sev_ord) = filter.min_severity_ord {
            conditions.push("severity_ord >= ?".to_string());
            param_values.push(Box::new(sev_ord as i64));
        }
        if let Some(ref from) = filter.from {
            conditions.push("timestamp >= ?".to_string());
            param_values.push(Box::new(from.clone()));
        }
        if let Some(ref to) = filter.to {
            conditions.push("timestamp <= ?".to_string());
            param_values.push(Box::new(to.clone()));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let limit_clause = if let Some(limit) = filter.limit {
            format!("LIMIT {limit}")
        } else {
            String::new()
        };

        let sql = format!(
            "SELECT byte_offset, line_length FROM events {where_clause} ORDER BY timestamp {limit_clause}"
        );

        let params: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok(EventLocation {
                byte_offset: row.get::<_, i64>(0)? as u64,
                line_length: row.get::<_, i64>(1)? as u64,
            })
        })?;

        let mut locations = Vec::new();
        for row in rows {
            locations.push(row?);
        }
        Ok(locations)
    }

    /// Find event locations by event ID (exact or prefix match).
    pub fn find_by_id(&self, id: &str) -> Result<Vec<EventLocation>> {
        let mut stmt = self.conn.prepare(
            "SELECT byte_offset, line_length FROM events WHERE event_id LIKE ?1"
        )?;
        let pattern = format!("{id}%");
        let rows = stmt.query_map([&pattern], |row| {
            Ok(EventLocation {
                byte_offset: row.get::<_, i64>(0)? as u64,
                line_length: row.get::<_, i64>(1)? as u64,
            })
        })?;

        let mut locations = Vec::new();
        for row in rows {
            locations.push(row?);
        }
        Ok(locations)
    }

    /// Find events by PID within a time window (fallback when process_key is
    /// unavailable, e.g. unenriched events).
    pub fn find_by_pid(
        &self,
        pid: u32,
        from: &str,
        to: &str,
    ) -> Result<Vec<EventLocation>> {
        let mut stmt = self.conn.prepare(
            "SELECT byte_offset, line_length FROM events \
             WHERE pid = ?1 AND timestamp >= ?2 AND timestamp <= ?3 \
             ORDER BY timestamp",
        )?;
        let rows = stmt.query_map(params![pid as i64, from, to], |row| {
            Ok(EventLocation {
                byte_offset: row.get::<_, i64>(0)? as u64,
                line_length: row.get::<_, i64>(1)? as u64,
            })
        })?;

        let mut locations = Vec::new();
        for row in rows {
            locations.push(row?);
        }
        Ok(locations)
    }

    /// Find events by process_key within a time window.
    pub fn find_by_process_key(
        &self,
        process_key: &str,
        from: &str,
        to: &str,
    ) -> Result<Vec<EventLocation>> {
        let mut stmt = self.conn.prepare(
            "SELECT byte_offset, line_length FROM events \
             WHERE process_key = ?1 AND timestamp >= ?2 AND timestamp <= ?3 \
             ORDER BY timestamp",
        )?;
        let rows = stmt.query_map(params![process_key, from, to], |row| {
            Ok(EventLocation {
                byte_offset: row.get::<_, i64>(0)? as u64,
                line_length: row.get::<_, i64>(1)? as u64,
            })
        })?;

        let mut locations = Vec::new();
        for row in rows {
            locations.push(row?);
        }
        Ok(locations)
    }

    // -- Internal helpers --

    fn event_count(&self) -> Result<u64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    fn get_meta_u64(&self, key: &str) -> Option<u64> {
        self.conn
            .query_row(
                "SELECT value FROM _meta WHERE key = ?1",
                [key],
                |row| {
                    let v: String = row.get(0)?;
                    Ok(v.parse::<u64>().unwrap_or(0))
                },
            )
            .ok()
    }

    fn set_meta_u64(&self, key: &str, value: u64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO _meta (key, value) VALUES (?1, ?2)",
            params![key, value.to_string()],
        )?;
        Ok(())
    }

    /// Index a byte range of the JSONL file.
    fn index_range(
        &self,
        jsonl_path: &Path,
        start_offset: u64,
        _file_size: u64,
    ) -> Result<IndexStats> {
        let file = std::fs::File::open(jsonl_path)
            .with_context(|| format!("cannot open {}", jsonl_path.display()))?;
        let mut reader = std::io::BufReader::new(file);

        if start_offset > 0 {
            reader.seek(SeekFrom::Start(start_offset))?;
        }

        let tx = self.conn.unchecked_transaction()?;

        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO events \
             (event_id, timestamp, pid, process_key, category, source_type, \
              source_detail, rule_id, severity, severity_ord, byte_offset, line_length) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )?;

        let mut offset = start_offset;
        let mut line_buf = String::new();
        let mut new_events = 0u64;

        loop {
            line_buf.clear();
            let bytes_read = reader.read_line(&mut line_buf)?;
            if bytes_read == 0 {
                break;
            }

            let line = line_buf.trim();
            if !line.is_empty() {
                if let Ok(event) = serde_json::from_str::<ThreatEvent>(line) {
                    let pid = event_pid(&event.data);
                    let process_key = event
                        .process_context
                        .as_ref()
                        .map(|c| c.process_key.as_str());
                    let category = category_short(&event.category);
                    let (source_type, source_detail) = source_index_fields(&event.source);
                    let rule_id = event.rule.as_ref().map(|r| r.id.as_str());
                    let severity = severity_str(&event.severity);
                    let severity_ord = severity_ord(&event.severity);
                    let timestamp = event.timestamp.to_rfc3339();

                    stmt.execute(params![
                        event.id.to_string(),
                        timestamp,
                        pid.map(|p| p as i64),
                        process_key,
                        category,
                        source_type,
                        source_detail,
                        rule_id,
                        severity,
                        severity_ord,
                        offset as i64,
                        bytes_read as i64,
                    ])?;
                    new_events += 1;
                }
            }

            offset += bytes_read as u64;
        }

        drop(stmt);
        self.set_meta_u64("indexed_up_to", offset)?;
        self.set_meta_u64("schema_version", SCHEMA_VERSION as u64)?;
        tx.commit()?;

        let total_events = self.event_count()?;
        Ok(IndexStats {
            new_events,
            total_events,
        })
    }
}

/// Statistics returned from build/rebuild operations.
pub struct IndexStats {
    pub new_events: u64,
    pub total_events: u64,
}

/// Filter for index queries — mirrors the CLI query filters but uses
/// pre-parsed values suitable for SQL.
pub struct IndexFilter {
    pub pid: Option<u32>,
    pub process_key: Option<String>,
    pub category: Option<String>,
    pub rule_id: Option<String>,
    pub source_type: Option<String>,
    pub min_severity_ord: Option<i32>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<usize>,
}

/// Fetch events from the JSONL file at the given byte offsets.
pub fn fetch_events(jsonl_path: &Path, locations: &[EventLocation]) -> Result<Vec<ThreatEvent>> {
    if locations.is_empty() {
        return Ok(Vec::new());
    }
    let mut file = std::fs::File::open(jsonl_path)
        .with_context(|| format!("cannot open {}", jsonl_path.display()))?;

    let mut events = Vec::with_capacity(locations.len());
    let mut buf = Vec::new();

    for loc in locations {
        file.seek(SeekFrom::Start(loc.byte_offset))?;
        buf.resize(loc.line_length as usize, 0u8);
        file.read_exact(&mut buf)?;

        let line = String::from_utf8_lossy(&buf);
        let line = line.trim();
        if let Ok(event) = serde_json::from_str::<ThreatEvent>(line) {
            events.push(event);
        }
    }

    Ok(events)
}

/// Derive the index file path from the JSONL file path.
pub fn index_path_for(jsonl_path: &Path) -> PathBuf {
    let mut p = jsonl_path.as_os_str().to_owned();
    p.push(".idx.sqlite");
    PathBuf::from(p)
}

/// Try to open an existing index, auto-update it if behind, and return it.
/// Returns `None` if no index exists (does not create one automatically).
pub fn try_open_and_update(jsonl_path: &Path) -> Result<Option<EventIndex>> {
    let idx_path = index_path_for(jsonl_path);
    if !idx_path.exists() {
        return Ok(None);
    }

    match EventIndex::open(jsonl_path) {
        Ok(idx) => {
            if idx.needs_update(jsonl_path)? {
                idx.build(jsonl_path)?;
            }
            Ok(Some(idx))
        }
        Err(_) => {
            // Corrupt index — delete and fall back to full scan
            let _ = std::fs::remove_file(&idx_path);
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Schema + mapping helpers
// ---------------------------------------------------------------------------

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
            event_id      TEXT    PRIMARY KEY,
            timestamp     TEXT    NOT NULL,
            pid           INTEGER,
            process_key   TEXT,
            category      TEXT    NOT NULL,
            source_type   TEXT    NOT NULL,
            source_detail TEXT,
            rule_id       TEXT,
            severity      TEXT    NOT NULL,
            severity_ord  INTEGER NOT NULL,
            byte_offset   INTEGER NOT NULL,
            line_length   INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_timestamp   ON events (timestamp);
        CREATE INDEX IF NOT EXISTS idx_pid         ON events (pid)         WHERE pid IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_process_key ON events (process_key) WHERE process_key IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_category    ON events (category);
        CREATE INDEX IF NOT EXISTS idx_rule_id     ON events (rule_id)     WHERE rule_id IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_source_type ON events (source_type);
        CREATE INDEX IF NOT EXISTS idx_severity    ON events (severity_ord);",
    )?;
    Ok(())
}

fn severity_ord(sev: &Severity) -> i32 {
    match sev {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn severity_str(sev: &Severity) -> &'static str {
    match sev {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

fn source_index_fields(source: &EventSource) -> (&'static str, Option<String>) {
    match source {
        EventSource::Etw { provider } => ("etw", Some(provider.clone())),
        EventSource::Sysmon { event_id } => ("sysmon", Some(event_id.to_string())),
        EventSource::EvasionDetector => ("evasion", None),
        EventSource::Sensor => ("sensor", None),
    }
}

fn category_short(cat: &EventCategory) -> &'static str {
    match cat {
        EventCategory::Process => "Process",
        EventCategory::File => "File",
        EventCategory::Network => "Network",
        EventCategory::Registry => "Registry",
        EventCategory::ImageLoad => "ImageLoad",
        EventCategory::Dns => "Dns",
        EventCategory::Evasion => "Evasion",
        EventCategory::Script => "Script",
        EventCategory::Health => "Health",
    }
}

/// Extract PID from any EventData variant (duplicated from investigate to
/// keep this module self-contained).
fn event_pid(data: &EventData) -> Option<u32> {
    match data {
        EventData::ProcessCreate { pid, .. }
        | EventData::ProcessTerminate { pid, .. }
        | EventData::FileCreate { pid, .. }
        | EventData::FileDelete { pid, .. }
        | EventData::NetworkConnect { pid, .. }
        | EventData::RegistryEvent { pid, .. }
        | EventData::ImageLoad { pid, .. }
        | EventData::DnsQuery { pid, .. }
        | EventData::ScriptBlock { pid, .. }
        | EventData::AmsiScan { pid, .. }
        | EventData::PipeEvent { pid, .. } => Some(*pid),
        EventData::EvasionDetected { pid, .. } => *pid,
        EventData::CreateRemoteThread { source_pid, .. } => Some(*source_pid),
        EventData::ProcessAccess { source_pid, .. } => Some(*source_pid),
        EventData::SensorHealth { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::*;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn test_agent() -> AgentInfo {
        AgentInfo {
            hostname: "TEST".into(),
            agent_id: Uuid::nil(),
        }
    }

    fn make_network_event(pid: u32, key: &str) -> ThreatEvent {
        let mut evt = ThreatEvent::new(
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
        );
        evt.process_context = Some(ProcessContext {
            process_key: key.into(),
            image_path: None,
            command_line: None,
            user: None,
            integrity_level: None,
            ppid: None,
        });
        evt
    }

    fn make_detection_event(pid: u32, rule_id: &str) -> ThreatEvent {
        ThreatEvent::with_rule(
            &test_agent(),
            EventSource::EvasionDetector,
            EventCategory::Evasion,
            Severity::High,
            EventData::EvasionDetected {
                technique: EvasionTechnique::EtwPatching,
                pid: Some(pid),
                process_name: Some("malware.exe".into()),
                details: "patched".into(),
            },
            RuleMetadata {
                id: rule_id.into(),
                name: "Test Rule".into(),
                description: "test".into(),
                mitre: MitreRef {
                    tactic: "Defense Evasion".into(),
                    technique_id: "T1562.006".into(),
                    technique_name: "Indicator Blocking".into(),
                },
                confidence: Confidence::High,
                evidence: vec!["byte 0xC3".into()],
            },
        )
    }

    fn write_events(dir: &TempDir, events: &[ThreatEvent]) -> PathBuf {
        let path = dir.path().join("events.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        for event in events {
            let json = serde_json::to_string(event).unwrap();
            std::io::Write::write_all(&mut f, json.as_bytes()).unwrap();
            std::io::Write::write_all(&mut f, b"\n").unwrap();
        }
        path
    }

    #[test]
    fn index_path_derivation() {
        let p = index_path_for(Path::new("/var/log/events.jsonl"));
        assert_eq!(p, PathBuf::from("/var/log/events.jsonl.idx.sqlite"));
    }

    #[test]
    fn build_creates_index_with_correct_count() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_network_event(200, "200:43"),
            make_detection_event(100, "TF-EVA-001"),
        ];
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        let stats = idx.build(&path).unwrap();

        assert_eq!(stats.new_events, 3);
        assert_eq!(stats.total_events, 3);
    }

    #[test]
    fn incremental_update_indexes_only_new_events() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.jsonl");

        // Write 2 events and build
        let events = vec![
            make_network_event(100, "100:42"),
            make_network_event(200, "200:43"),
        ];
        {
            let mut f = std::fs::File::create(&path).unwrap();
            for event in &events {
                let json = serde_json::to_string(event).unwrap();
                std::io::Write::write_all(&mut f, json.as_bytes()).unwrap();
                std::io::Write::write_all(&mut f, b"\n").unwrap();
            }
        }

        let idx = EventIndex::open(&path).unwrap();
        let stats = idx.build(&path).unwrap();
        assert_eq!(stats.new_events, 2);
        assert_eq!(stats.total_events, 2);

        // Append 1 more event
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            let json = serde_json::to_string(&make_detection_event(100, "TF-EVA-001")).unwrap();
            writeln!(f, "{json}").unwrap();
        }

        // Incremental build should pick up only the new one
        let stats = idx.build(&path).unwrap();
        assert_eq!(stats.new_events, 1);
        assert_eq!(stats.total_events, 3);
    }

    #[test]
    fn rebuild_reindexes_everything() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_network_event(200, "200:43"),
        ];
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();

        let stats = idx.rebuild(&path).unwrap();
        assert_eq!(stats.new_events, 2);
        assert_eq!(stats.total_events, 2);
    }

    #[test]
    fn truncated_file_triggers_rebuild() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_network_event(200, "200:43"),
            make_network_event(300, "300:44"),
        ];
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();
        assert_eq!(idx.event_count().unwrap(), 3);

        // Truncate the file to just 1 event (simulate rotation)
        let short_events = vec![make_network_event(400, "400:45")];
        let mut f = std::fs::File::create(&path).unwrap();
        let json = serde_json::to_string(&short_events[0]).unwrap();
        std::io::Write::write_all(&mut f, json.as_bytes()).unwrap();
        std::io::Write::write_all(&mut f, b"\n").unwrap();
        drop(f);

        // Build should detect truncation and rebuild
        let stats = idx.build(&path).unwrap();
        assert_eq!(stats.total_events, 1);
    }

    #[test]
    fn find_by_id_exact_and_prefix() {
        let dir = TempDir::new().unwrap();
        let evt = make_network_event(100, "100:42");
        let known_id = evt.id;
        let events = vec![evt];
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();

        // Exact match
        let locs = idx.find_by_id(&known_id.to_string()).unwrap();
        assert_eq!(locs.len(), 1);

        // Prefix match
        let prefix = &known_id.to_string()[..8];
        let locs = idx.find_by_id(prefix).unwrap();
        assert_eq!(locs.len(), 1);

        // No match
        let locs = idx.find_by_id("00000000-dead-beef").unwrap();
        assert_eq!(locs.len(), 0);
    }

    #[test]
    fn find_by_process_key_within_window() {
        let dir = TempDir::new().unwrap();
        let mut e1 = make_network_event(100, "100:42");
        e1.timestamp = "2026-03-13T10:00:00Z".parse().unwrap();
        let mut e2 = make_network_event(100, "100:42");
        e2.timestamp = "2026-03-13T10:03:00Z".parse().unwrap();
        let mut e3 = make_network_event(100, "100:42");
        e3.timestamp = "2026-03-13T12:00:00Z".parse().unwrap(); // outside window
        let events = vec![e1, e2, e3];
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();

        let locs = idx
            .find_by_process_key("100:42", "2026-03-13T09:55:00+00:00", "2026-03-13T10:05:00+00:00")
            .unwrap();
        assert_eq!(locs.len(), 2);
    }

    #[test]
    fn query_filter_by_pid() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_network_event(200, "200:43"),
        ];
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();

        let filter = IndexFilter {
            pid: Some(100),
            process_key: None,
            category: None,
            rule_id: None,
            source_type: None,
            min_severity_ord: None,
            from: None,
            to: None,
            limit: None,
        };
        let locs = idx.query_locations(&filter).unwrap();
        assert_eq!(locs.len(), 1);
    }

    #[test]
    fn query_filter_by_severity() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),         // Info
            make_detection_event(200, "TF-EVA-001"),    // High
        ];
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();

        let filter = IndexFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source_type: None,
            min_severity_ord: Some(3), // High
            from: None,
            to: None,
            limit: None,
        };
        let locs = idx.query_locations(&filter).unwrap();
        assert_eq!(locs.len(), 1);
    }

    #[test]
    fn query_filter_by_source_type() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),         // etw
            make_detection_event(200, "TF-EVA-001"),    // evasion
        ];
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();

        let filter = IndexFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source_type: Some("evasion".into()),
            min_severity_ord: None,
            from: None,
            to: None,
            limit: None,
        };
        let locs = idx.query_locations(&filter).unwrap();
        assert_eq!(locs.len(), 1);
    }

    #[test]
    fn query_filter_by_rule_id() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_detection_event(200, "TF-EVA-001"),
        ];
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();

        let filter = IndexFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: Some("TF-EVA-001".into()),
            source_type: None,
            min_severity_ord: None,
            from: None,
            to: None,
            limit: None,
        };
        let locs = idx.query_locations(&filter).unwrap();
        assert_eq!(locs.len(), 1);
    }

    #[test]
    fn fetch_events_by_offset() {
        let dir = TempDir::new().unwrap();
        let e1 = make_network_event(100, "100:42");
        let e2 = make_network_event(200, "200:43");
        let id1 = e1.id;
        let id2 = e2.id;
        let events = vec![e1, e2];
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();

        // Fetch all
        let filter = IndexFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source_type: None,
            min_severity_ord: None,
            from: None,
            to: None,
            limit: None,
        };
        let locs = idx.query_locations(&filter).unwrap();
        let fetched = fetch_events(&path, &locs).unwrap();
        assert_eq!(fetched.len(), 2);

        let ids: Vec<_> = fetched.iter().map(|e| e.id).collect();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn status_reports_correctly() {
        let dir = TempDir::new().unwrap();
        let events = vec![make_network_event(100, "100:42")];
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();

        let status = idx.status(&path).unwrap();
        assert_eq!(status.event_count, 1);
        assert!(status.is_current);
        assert_eq!(status.indexed_up_to, status.jsonl_size);
    }

    #[test]
    fn needs_update_detects_new_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.jsonl");
        let events = vec![make_network_event(100, "100:42")];
        {
            let mut f = std::fs::File::create(&path).unwrap();
            for event in &events {
                let json = serde_json::to_string(event).unwrap();
                std::io::Write::write_all(&mut f, json.as_bytes()).unwrap();
                std::io::Write::write_all(&mut f, b"\n").unwrap();
            }
        }

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();
        assert!(!idx.needs_update(&path).unwrap());

        // Append
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            let json = serde_json::to_string(&make_network_event(200, "200:43")).unwrap();
            writeln!(f, "{json}").unwrap();
        }
        assert!(idx.needs_update(&path).unwrap());
    }

    #[test]
    fn query_with_limit() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_network_event(200, "200:43"),
            make_network_event(300, "300:44"),
        ];
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();

        let filter = IndexFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source_type: None,
            min_severity_ord: None,
            from: None,
            to: None,
            limit: Some(2),
        };
        let locs = idx.query_locations(&filter).unwrap();
        assert_eq!(locs.len(), 2);
    }

    #[test]
    fn corrupt_index_recovery() {
        let dir = TempDir::new().unwrap();
        let events = vec![make_network_event(100, "100:42")];
        let path = write_events(&dir, &events);
        let idx_path = index_path_for(&path);

        // Write garbage to the index file
        std::fs::write(&idx_path, b"this is not sqlite").unwrap();

        // try_open_and_update should delete corrupt file and return None
        let result = try_open_and_update(&path).unwrap();
        assert!(result.is_none());
        assert!(!idx_path.exists());
    }

    #[test]
    fn try_open_returns_none_when_no_index() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.jsonl");
        std::fs::write(&path, "").unwrap();

        let result = try_open_and_update(&path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn source_detail_enables_provider_name_search() {
        let dir = TempDir::new().unwrap();
        let events = vec![make_network_event(100, "100:42")]; // provider = Kernel-Network
        let path = write_events(&dir, &events);

        let idx = EventIndex::open(&path).unwrap();
        idx.build(&path).unwrap();

        // Search by provider name substring
        let filter = IndexFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source_type: Some("Kernel-Network".into()),
            min_severity_ord: None,
            from: None,
            to: None,
            limit: None,
        };
        let locs = idx.query_locations(&filter).unwrap();
        assert_eq!(locs.len(), 1);
    }
}
