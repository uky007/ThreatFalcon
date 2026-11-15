//! Event export for the read API: the matching lines of an agent's stored
//! event files, oldest file first, delivered in chunks of whole lines.
//!
//! Reading the files is what an export costs (the data volume is typically
//! larger than the page cache), so files that cannot hold a match are not
//! read. Rotated files (`events.jsonl.N`) never change, so the first export
//! that reads one in full records a summary of it in `.export-index.json`
//! in the agent directory: event time range, counts by category and
//! severity, detections. Later exports skip files by their summary.
//! Without a summary (or for the active file), only a time range can rule
//! a file out, by its write times with generous clock slack.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use chrono::{DateTime, Utc};
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};

use crate::store::{rotated_generations, EVENTS_FILE};

/// Events per export when the request does not say.
pub const DEFAULT_LIMIT: usize = 100_000;
/// Most events one export may return.
pub const MAX_LIMIT: usize = 1_000_000;
/// Longest `contains` filter.
const MAX_CONTAINS_BYTES: usize = 256;
/// Size at which a chunk is handed to the response.
const CHUNK_BYTES: usize = 256 * 1024;
/// Event timestamps come from the agents' clocks. Without a summary, a file
/// is skipped by its write times only when it lies at least this far
/// outside the range.
const CLOCK_SLACK: Duration = Duration::from_secs(24 * 3600);
/// Summaries of rotated files, per agent directory.
pub const INDEX_FILE: &str = ".export-index.json";
const INDEX_VERSION: u32 = 1;
/// Serializes read-modify-write of index files between concurrent exports.
static INDEX_LOCK: Mutex<()> = Mutex::new(());

const SEVERITIES: [&str; 5] = ["Info", "Low", "Medium", "High", "Critical"];

fn severity_rank(name: &str) -> Option<usize> {
    SEVERITIES.iter().position(|s| s.eq_ignore_ascii_case(name))
}

/// Query string of `GET /api/v1/agents/{agent}/events`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub category: Option<String>,
    pub min_severity: Option<String>,
    pub detections: Option<bool>,
    pub contains: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ExportFilter {
    /// Inclusive bounds on the event `timestamp`.
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// Event category, compared case-insensitively.
    pub category: Option<String>,
    /// Lowest severity rank (index into Info, Low, Medium, High, Critical).
    pub min_severity: Option<usize>,
    /// Only events with detection rule metadata (`rule`).
    pub detections: bool,
    /// Substring of the stored JSON line (byte-wise, case-sensitive).
    pub contains: Option<String>,
    pub limit: usize,
}

impl ExportFilter {
    pub fn from_query(query: ExportQuery) -> Result<Self, String> {
        let time = |name: &str, value: Option<String>| {
            value
                .map(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .map(|t| t.with_timezone(&Utc))
                        .map_err(|_| {
                            format!("{name} must be an RFC 3339 time such as 2026-11-15T05:00:00Z")
                        })
                })
                .transpose()
        };
        let from = time("from", query.from)?;
        let to = time("to", query.to)?;
        if let (Some(from), Some(to)) = (from, to) {
            if from > to {
                return Err("from must not be later than to".into());
            }
        }
        if let Some(category) = &query.category {
            let ok = !category.is_empty()
                && category.len() <= 32
                && category.bytes().all(|b| b.is_ascii_alphanumeric());
            if !ok {
                return Err("category must be an event category such as File or Registry".into());
            }
        }
        let min_severity = match &query.min_severity {
            Some(name) => Some(severity_rank(name).ok_or_else(|| {
                "min_severity must be one of Info, Low, Medium, High, Critical".to_string()
            })?),
            None => None,
        };
        if let Some(contains) = &query.contains {
            if contains.is_empty() || contains.len() > MAX_CONTAINS_BYTES {
                return Err(format!("contains must be 1-{MAX_CONTAINS_BYTES} bytes"));
            }
        }
        let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(format!("limit must be between 1 and {MAX_LIMIT}"));
        }
        Ok(Self {
            from,
            to,
            category: query.category,
            min_severity,
            detections: query.detections.unwrap_or(false),
            contains: query.contains,
            limit,
        })
    }

    /// Whether the filter looks at envelope fields (not just raw bytes).
    fn uses_envelope(&self) -> bool {
        self.from.is_some()
            || self.to.is_some()
            || self.category.is_some()
            || self.min_severity.is_some()
            || self.detections
    }

    fn matches(&self, line: &[u8], head: Option<&Head<'_>>) -> bool {
        if let Some(needle) = &self.contains {
            if !contains(line, needle.as_bytes()) {
                return false;
            }
        }
        if !self.uses_envelope() {
            return true;
        }
        let Some(head) = head else {
            return false;
        };
        if let Some(category) = &self.category {
            if !head.category.eq_ignore_ascii_case(category) {
                return false;
            }
        }
        if let Some(min) = self.min_severity {
            if severity_rank(&head.severity).is_none_or(|rank| rank < min) {
                return false;
            }
        }
        if self.detections && head.rule.is_none() {
            return false;
        }
        if self.from.is_some() || self.to.is_some() {
            let Some(t) = head.time() else {
                return false;
            };
            if self.from.is_some_and(|from| t < from) || self.to.is_some_and(|to| t > to) {
                return false;
            }
        }
        true
    }

    /// Whether a file with this summary can hold a matching event.
    fn may_match(&self, summary: &FileSummary) -> bool {
        if !self.uses_envelope() {
            return true;
        }
        if self.from.is_some() || self.to.is_some() {
            let (Some(min), Some(max)) = (summary.min_ts, summary.max_ts) else {
                return false;
            };
            if self.from.is_some_and(|from| max < from) || self.to.is_some_and(|to| min > to) {
                return false;
            }
        }
        if let Some(category) = &self.category {
            let present = summary
                .categories
                .iter()
                .any(|(name, n)| *n > 0 && name.eq_ignore_ascii_case(category));
            if !present {
                return false;
            }
        }
        if let Some(min) = self.min_severity {
            let present = summary
                .severities
                .iter()
                .any(|(name, n)| *n > 0 && severity_rank(name).is_some_and(|rank| rank >= min));
            if !present {
                return false;
            }
        }
        if self.detections && summary.detections == 0 {
            return false;
        }
        true
    }
}

/// The envelope fields the filters and summaries need.
#[derive(Deserialize)]
struct Head<'a> {
    #[serde(borrow)]
    timestamp: Cow<'a, str>,
    #[serde(borrow)]
    category: Cow<'a, str>,
    #[serde(borrow, default)]
    severity: Cow<'a, str>,
    #[serde(default)]
    rule: Option<IgnoredAny>,
}

impl Head<'_> {
    fn parse(line: &[u8]) -> Option<Head<'_>> {
        serde_json::from_slice(line).ok()
    }

    fn time(&self) -> Option<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(&self.timestamp)
            .ok()
            .map(|t| t.with_timezone(&Utc))
    }
}

/// What a rotated file holds, recorded the first time it is read in full.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct FileSummary {
    /// Identify the file content the summary describes.
    size: u64,
    mtime_ns: u128,
    min_ts: Option<DateTime<Utc>>,
    max_ts: Option<DateTime<Utc>>,
    events: u64,
    categories: BTreeMap<String, u64>,
    severities: BTreeMap<String, u64>,
    detections: u64,
}

impl FileSummary {
    fn add(&mut self, head: &Head<'_>) {
        self.events += 1;
        if let Some(t) = head.time() {
            self.min_ts = Some(self.min_ts.map_or(t, |m| m.min(t)));
            self.max_ts = Some(self.max_ts.map_or(t, |m| m.max(t)));
        }
        *self
            .categories
            .entry(head.category.to_string())
            .or_default() += 1;
        *self
            .severities
            .entry(head.severity.to_string())
            .or_default() += 1;
        if head.rule.is_some() {
            self.detections += 1;
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Index {
    version: u32,
    /// By file name (`events.jsonl.N`).
    files: HashMap<String, FileSummary>,
}

fn file_identity(meta: &fs::Metadata) -> Option<(u64, u128)> {
    let mtime = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    Some((meta.len(), mtime.as_nanos()))
}

fn load_index(dir: &Path) -> Index {
    let Ok(text) = fs::read(dir.join(INDEX_FILE)) else {
        return Index::default();
    };
    match serde_json::from_slice::<Index>(&text) {
        Ok(index) if index.version == INDEX_VERSION => index,
        _ => Index::default(),
    }
}

/// Merge new summaries into the index on disk, dropping entries of files
/// that no longer exist. The index is a cache: errors only cost speed.
fn save_summaries(dir: &Path, new: Vec<(String, FileSummary)>) {
    if new.is_empty() {
        return;
    }
    let _guard = INDEX_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut index = load_index(dir);
    index.version = INDEX_VERSION;
    index.files.extend(new);
    index.files.retain(|name, _| dir.join(name).exists());
    let result = (|| -> io::Result<()> {
        let tmp = dir.join(format!("{INDEX_FILE}.tmp-{}", std::process::id()));
        let mut file = File::create(&tmp)?;
        file.write_all(&serde_json::to_vec(&index)?)?;
        drop(file);
        fs::rename(&tmp, dir.join(INDEX_FILE))
    })();
    if let Err(e) = result {
        tracing::warn!(dir = %dir.display(), error = %e, "failed to write export index");
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExportStats {
    /// Files read.
    pub files: usize,
    /// Files left unread because their summary rules out a match.
    pub files_skipped: usize,
    /// Summaries recorded by this export.
    pub summaries_built: usize,
    pub lines_scanned: u64,
    pub events: u64,
    /// `limit` events were returned; there may be more.
    pub limit_reached: bool,
    /// The receiver went away before the export finished.
    pub aborted: bool,
}

struct Candidate {
    path: PathBuf,
    name: String,
    /// Rotated files can be summarized; the active file cannot.
    rotated: bool,
    identity: Option<(u64, u128)>,
}

/// Write the events of agent directory `dir` that match `filter` to `emit`,
/// oldest file first, in chunks of whole lines. `emit` returns false when
/// the client has gone away, which ends the export.
pub fn export(
    dir: &Path,
    filter: &ExportFilter,
    mut emit: impl FnMut(Bytes) -> bool,
) -> io::Result<ExportStats> {
    let mut stats = ExportStats::default();
    let index = load_index(dir);
    let mut built: Vec<(String, FileSummary)> = Vec::new();
    let mut chunk: Vec<u8> = Vec::with_capacity(CHUNK_BYTES + 4096);
    let mut line = Vec::new();

    'files: for candidate in candidate_files(dir, filter, &index)? {
        // A summary that still describes the file decides on its own.
        let summary = index
            .files
            .get(&candidate.name)
            .filter(|s| candidate.rotated && candidate.identity == Some((s.size, s.mtime_ns)));
        if let Some(summary) = summary {
            if !filter.may_match(summary) {
                stats.files_skipped += 1;
                continue;
            }
        }
        let file = match File::open(&candidate.path) {
            Ok(file) => file,
            // Pruned by retention since it was listed
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        stats.files += 1;
        let mut building = (candidate.rotated && summary.is_none()).then(FileSummary::default);
        let mut reader = BufReader::with_capacity(64 * 1024, file);
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if line.last() != Some(&b'\n') {
                // The active file's last line is still being written.
                building = None;
                break;
            }
            stats.lines_scanned += 1;
            let body = &line[..line.len() - 1];
            let head = if building.is_some() || filter.uses_envelope() {
                Head::parse(body)
            } else {
                None
            };
            if let (Some(summary), Some(head)) = (building.as_mut(), head.as_ref()) {
                summary.add(head);
            }
            if !filter.matches(body, head.as_ref()) {
                continue;
            }
            chunk.extend_from_slice(&line);
            stats.events += 1;
            if stats.events >= filter.limit as u64 {
                stats.limit_reached = true;
                break 'files;
            }
            if chunk.len() >= CHUNK_BYTES && !emit(Bytes::from(std::mem::take(&mut chunk))) {
                stats.aborted = true;
                break 'files;
            }
        }
        // Only a complete read of an unchanged rotated file is summarized.
        if let (Some(mut summary), Some((size, mtime_ns))) = (building, candidate.identity) {
            let unchanged = fs::metadata(&candidate.path)
                .ok()
                .and_then(|m| file_identity(&m))
                == Some((size, mtime_ns));
            if unchanged {
                summary.size = size;
                summary.mtime_ns = mtime_ns;
                built.push((candidate.name.clone(), summary));
            }
        }
    }
    if !stats.aborted && !chunk.is_empty() && !emit(Bytes::from(chunk)) {
        stats.aborted = true;
    }
    stats.summaries_built = built.len();
    save_summaries(dir, built);
    Ok(stats)
}

/// The event files to consider, oldest first: `events.jsonl.N` in ascending
/// `N`, then `events.jsonl`. With a time range, files without a summary
/// whose write times show they cannot hold matching events are left out.
fn candidate_files(dir: &Path, filter: &ExportFilter, index: &Index) -> io::Result<Vec<Candidate>> {
    let generations = match rotated_generations(dir, EVENTS_FILE) {
        Ok(generations) => generations,
        // Nothing stored for this agent yet
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut names: Vec<(String, bool)> = generations
        .into_iter()
        .map(|n| (format!("{EVENTS_FILE}.{n}"), true))
        .collect();
    names.push((EVENTS_FILE.to_string(), false));

    let from = filter
        .from
        .and_then(|t| SystemTime::from(t).checked_sub(CLOCK_SLACK));
    let to = filter
        .to
        .and_then(|t| SystemTime::from(t).checked_add(CLOCK_SLACK));
    let mut selected = Vec::new();
    // A file holds what arrived between the previous file's last write and
    // its own last write.
    let mut previous_end: Option<SystemTime> = None;
    for (name, rotated) in names {
        let path = dir.join(&name);
        let meta = match fs::metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let identity = file_identity(&meta);
        let end = meta.modified()?;
        let start = previous_end.replace(end);
        let summarized = rotated
            && index
                .files
                .get(&name)
                .is_some_and(|s| identity == Some((s.size, s.mtime_ns)));
        if !summarized {
            let ends_before = from.is_some_and(|from| end < from);
            let starts_after = matches!((start, to), (Some(start), Some(to)) if start > to);
            if ends_before || starts_after {
                continue;
            }
        }
        selected.push(Candidate {
            path,
            name,
            rotated,
            identity,
        });
    }
    Ok(selected)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;
    use tempfile::TempDir;

    fn event(ts: &str, category: &str, path: &str) -> String {
        event_with(ts, category, "Info", path, false)
    }

    fn event_with(ts: &str, category: &str, severity: &str, path: &str, rule: bool) -> String {
        let rule = if rule {
            r#","rule":{"id":"TF-TEST-001"}"#
        } else {
            ""
        };
        format!(
            r#"{{"id":"x","timestamp":"{ts}","category":"{category}","severity":"{severity}","data":{{"type":"T","path":"{path}"}}{rule}}}"#
        )
    }

    fn write(dir: &Path, name: &str, lines: &[String]) -> PathBuf {
        let path = dir.join(name);
        let mut f = File::create(&path).unwrap();
        for line in lines {
            writeln!(f, "{line}").unwrap();
        }
        path
    }

    fn filter(query: ExportQuery) -> ExportFilter {
        ExportFilter::from_query(query).unwrap()
    }

    fn run(dir: &Path, f: &ExportFilter) -> (Vec<String>, ExportStats) {
        let mut out = Vec::new();
        let stats = export(dir, f, |chunk| {
            out.extend_from_slice(&chunk);
            true
        })
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        (text.lines().map(str::to_owned).collect(), stats)
    }

    fn set_mtime(path: &Path, rfc3339: &str) {
        let t = DateTime::parse_from_rfc3339(rfc3339).unwrap();
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::from(t))
            .unwrap();
    }

    /// Three generations: .1 (oldest), .2, then the active file, with write
    /// times matching their content (the last event of the active file came
    /// from an agent whose clock is behind).
    fn sample() -> TempDir {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "events.jsonl.1",
            &[
                event("2026-11-15T01:00:00Z", "File", "a"),
                event("2026-11-15T01:30:00Z", "Registry", "b"),
            ],
        );
        write(
            dir.path(),
            "events.jsonl.2",
            &[event("2026-11-15T02:00:00.5Z", "File", "c")],
        );
        write(
            dir.path(),
            "events.jsonl",
            &[
                event("2026-11-15T03:00:00Z", "Process", "d"),
                event("2026-11-15T03:30:00+09:00", "File", "e"),
            ],
        );
        // Not event files
        write(
            dir.path(),
            "events.jsonl.01",
            &[event("2026-11-15T09:00:00Z", "File", "junk")],
        );
        write(
            dir.path(),
            "rejected.jsonl",
            &[event("2026-11-15T09:00:00Z", "File", "junk")],
        );
        set_mtime(&dir.path().join("events.jsonl.1"), "2026-11-15T01:30:00Z");
        set_mtime(&dir.path().join("events.jsonl.2"), "2026-11-15T02:00:01Z");
        set_mtime(&dir.path().join("events.jsonl"), "2026-11-15T03:30:00Z");
        dir
    }

    fn paths(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["data"]["path"].as_str().unwrap().to_owned()
            })
            .collect()
    }

    #[test]
    fn exports_all_generations_oldest_first() {
        let dir = sample();
        let (lines, stats) = run(dir.path(), &filter(ExportQuery::default()));
        assert_eq!(paths(&lines), ["a", "b", "c", "d", "e"]);
        assert_eq!(stats.files, 3);
        assert_eq!(stats.events, 5);
        assert!(!stats.limit_reached);
    }

    #[test]
    fn filters_by_time_category_and_substring() {
        let dir = sample();
        let q = |from: Option<&str>,
                 to: Option<&str>,
                 category: Option<&str>,
                 contains: Option<&str>| {
            filter(ExportQuery {
                from: from.map(Into::into),
                to: to.map(Into::into),
                category: category.map(Into::into),
                contains: contains.map(Into::into),
                ..ExportQuery::default()
            })
        };
        let (lines, _) = run(
            dir.path(),
            &q(
                Some("2026-11-15T01:30:00Z"),
                Some("2026-11-15T03:00:00Z"),
                None,
                None,
            ),
        );
        assert_eq!(paths(&lines), ["b", "c", "d"]);
        // 03:30+09:00 is 18:30Z the day before
        let (lines, _) = run(
            dir.path(),
            &q(None, Some("2026-11-15T00:00:00Z"), None, None),
        );
        assert_eq!(paths(&lines), ["e"]);
        let (lines, _) = run(dir.path(), &q(None, None, Some("file"), None));
        assert_eq!(paths(&lines), ["a", "c", "e"]);
        let (lines, _) = run(
            dir.path(),
            &q(None, None, Some("File"), Some(r#""path":"c""#)),
        );
        assert_eq!(paths(&lines), ["c"]);
    }

    #[test]
    fn stops_at_the_limit() {
        let dir = sample();
        let f = filter(ExportQuery {
            limit: Some(2),
            ..ExportQuery::default()
        });
        let (lines, stats) = run(dir.path(), &f);
        assert_eq!(paths(&lines), ["a", "b"]);
        assert!(stats.limit_reached);
    }

    #[test]
    fn skips_incomplete_and_unreadable_lines() {
        let dir = TempDir::new().unwrap();
        let path = write(
            dir.path(),
            "events.jsonl",
            &[
                event("2026-11-15T01:00:00Z", "File", "a"),
                "not json".into(),
            ],
        );
        let mut f = OpenOptions::new().append(true).open(path).unwrap();
        write!(f, "{}", event("2026-11-15T02:00:00Z", "File", "partial")).unwrap(); // no newline yet
        let all = filter(ExportQuery::default());
        // Without filters lines are passed through as stored (they were
        // validated on ingest); the incomplete last line never is.
        let (lines, _) = run(dir.path(), &all);
        assert_eq!(lines.len(), 2);
        let by_category = filter(ExportQuery {
            category: Some("File".into()),
            ..ExportQuery::default()
        });
        let (lines, stats) = run(dir.path(), &by_category);
        assert_eq!(paths(&lines), ["a"]);
        assert_eq!(stats.lines_scanned, 2);
    }

    #[test]
    fn skips_files_outside_the_range_by_write_time() {
        let dir = sample();
        let day = Duration::from_secs(24 * 3600);
        // A fixed "now" after all sample events: .1 was last written 10
        // days before it, .2 four days before, the active file at it.
        let now = SystemTime::from(DateTime::parse_from_rfc3339("2026-11-20T00:00:00Z").unwrap());
        let set = |name: &str, t: SystemTime| {
            File::options()
                .write(true)
                .open(dir.path().join(name))
                .unwrap()
                .set_modified(t)
                .unwrap();
        };
        set("events.jsonl.1", now - 10 * day);
        set("events.jsonl.2", now - 4 * day);
        set("events.jsonl", now);
        let recent = filter(ExportQuery {
            from: Some(DateTime::<Utc>::from(now - 2 * day).to_rfc3339()),
            ..ExportQuery::default()
        });
        // Only the active file can hold events of the last two days (plus
        // slack); its events are older by timestamp, so none match.
        let (lines, stats) = run(dir.path(), &recent);
        assert!(lines.is_empty());
        assert_eq!(stats.files, 1);

        let old = filter(ExportQuery {
            to: Some(DateTime::<Utc>::from(now - 9 * day).to_rfc3339()),
            ..ExportQuery::default()
        });
        let (_, stats) = run(dir.path(), &old);
        // .1 (everything up to 10 days before) and .2 (started 10 days
        // before, within the slack of 9 days before) are read; the active
        // file started 4 days before and is skipped.
        assert_eq!(stats.files, 2);
    }

    #[test]
    fn stops_when_the_client_goes_away() {
        let dir = TempDir::new().unwrap();
        let big = "x".repeat(1000);
        let lines: Vec<String> = (0..1000)
            .map(|i| event("2026-11-15T01:00:00Z", "File", &format!("{i}{big}")))
            .collect();
        write(dir.path(), "events.jsonl", &lines);
        let mut chunks = 0;
        let stats = export(dir.path(), &filter(ExportQuery::default()), |_| {
            chunks += 1;
            false
        })
        .unwrap();
        assert_eq!(chunks, 1);
        assert!(stats.aborted);
        assert!(stats.events < 1000);
    }

    #[test]
    fn missing_agent_directory_exports_nothing() {
        let dir = TempDir::new().unwrap();
        let (lines, stats) = run(&dir.path().join("none"), &filter(ExportQuery::default()));
        assert!(lines.is_empty());
        assert_eq!(stats, ExportStats::default());
    }

    #[test]
    fn rejects_bad_queries() {
        let bad = [
            ExportQuery {
                from: Some("yesterday".into()),
                ..ExportQuery::default()
            },
            ExportQuery {
                from: Some("2026-11-15T02:00:00Z".into()),
                to: Some("2026-11-15T01:00:00Z".into()),
                ..ExportQuery::default()
            },
            ExportQuery {
                category: Some("File; DROP".into()),
                ..ExportQuery::default()
            },
            ExportQuery {
                contains: Some(String::new()),
                ..ExportQuery::default()
            },
            ExportQuery {
                contains: Some("x".repeat(257)),
                ..ExportQuery::default()
            },
            ExportQuery {
                min_severity: Some("Severe".into()),
                ..ExportQuery::default()
            },
            ExportQuery {
                limit: Some(0),
                ..ExportQuery::default()
            },
            ExportQuery {
                limit: Some(MAX_LIMIT + 1),
                ..ExportQuery::default()
            },
        ];
        for q in bad {
            assert!(ExportFilter::from_query(q).is_err());
        }
        assert_eq!(filter(ExportQuery::default()).limit, DEFAULT_LIMIT);
    }

    fn index(dir: &Path) -> Index {
        load_index(dir)
    }

    #[test]
    fn filters_by_severity_and_detections() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "events.jsonl",
            &[
                event_with("2026-11-15T01:00:00Z", "Script", "Medium", "ps1", false),
                event_with("2026-11-15T01:00:01Z", "Evasion", "High", "amsi", true),
                event_with("2026-11-15T01:00:02Z", "File", "Info", "f", false),
            ],
        );
        let q = |min_severity: Option<&str>, detections: Option<bool>| {
            filter(ExportQuery {
                min_severity: min_severity.map(Into::into),
                detections,
                ..ExportQuery::default()
            })
        };
        assert_eq!(
            paths(&run(dir.path(), &q(Some("medium"), None)).0),
            ["ps1", "amsi"]
        );
        assert_eq!(paths(&run(dir.path(), &q(Some("High"), None)).0), ["amsi"]);
        assert_eq!(paths(&run(dir.path(), &q(None, Some(true))).0), ["amsi"]);
        assert_eq!(paths(&run(dir.path(), &q(None, Some(false))).0).len(), 3);
    }

    #[test]
    fn summaries_of_rotated_files_skip_them_later() {
        let dir = sample();
        // A full read summarizes the rotated files, not the active one
        let (_, stats) = run(dir.path(), &filter(ExportQuery::default()));
        assert_eq!(stats.summaries_built, 2);
        let idx = index(dir.path());
        let mut names: Vec<_> = idx.files.keys().cloned().collect();
        names.sort();
        assert_eq!(names, ["events.jsonl.1", "events.jsonl.2"]);
        let one = &idx.files["events.jsonl.1"];
        assert_eq!(one.events, 2);
        assert_eq!(one.categories["Registry"], 1);
        assert_eq!(
            one.min_ts.unwrap().to_rfc3339(),
            "2026-11-15T01:00:00+00:00"
        );

        // Registry only occurs in .1: .2 is skipped, the active file read
        let registry = filter(ExportQuery {
            category: Some("Registry".into()),
            ..ExportQuery::default()
        });
        let (lines, stats) = run(dir.path(), &registry);
        assert_eq!(paths(&lines), ["b"]);
        assert_eq!((stats.files, stats.files_skipped), (2, 1));

        // Exact time ranges: 02:00-02:30 is only in .2
        let window = filter(ExportQuery {
            from: Some("2026-11-15T02:00:00Z".into()),
            to: Some("2026-11-15T02:30:00Z".into()),
            ..ExportQuery::default()
        });
        let (lines, stats) = run(dir.path(), &window);
        assert_eq!(paths(&lines), ["c"]);
        assert_eq!(stats.files_skipped, 1);

        // No detections anywhere in the rotated files
        let detections = filter(ExportQuery {
            detections: Some(true),
            ..ExportQuery::default()
        });
        let (lines, stats) = run(dir.path(), &detections);
        assert!(lines.is_empty());
        assert_eq!((stats.files, stats.files_skipped), (1, 2));
    }

    #[test]
    fn a_changed_file_is_read_again() {
        let dir = sample();
        run(dir.path(), &filter(ExportQuery::default()));
        // .1 is replaced (the server never does this, but its summary must
        // not be trusted then)
        write(
            dir.path(),
            "events.jsonl.1",
            &[event_with(
                "2026-11-15T01:00:00Z",
                "Registry",
                "High",
                "new",
                true,
            )],
        );
        let detections = filter(ExportQuery {
            detections: Some(true),
            ..ExportQuery::default()
        });
        let (lines, stats) = run(dir.path(), &detections);
        assert_eq!(paths(&lines), ["new"]);
        assert_eq!(stats.summaries_built, 1);
        assert_eq!(index(dir.path()).files["events.jsonl.1"].detections, 1);
    }

    #[test]
    fn partial_reads_are_not_summarized() {
        let dir = sample();
        let first = filter(ExportQuery {
            limit: Some(1),
            ..ExportQuery::default()
        });
        let (_, stats) = run(dir.path(), &first);
        assert_eq!(stats.summaries_built, 0);
        assert!(!dir.path().join(INDEX_FILE).exists());
    }

    #[test]
    fn index_forgets_deleted_files_and_survives_corruption() {
        let dir = sample();
        run(dir.path(), &filter(ExportQuery::default()));
        fs::remove_file(dir.path().join("events.jsonl.1")).unwrap();
        // The next summary write prunes the entry of the deleted file
        write(
            dir.path(),
            "events.jsonl.3",
            &[event("2026-11-15T04:00:00Z", "File", "g")],
        );
        set_mtime(&dir.path().join("events.jsonl.3"), "2026-11-15T04:00:01Z");
        run(dir.path(), &filter(ExportQuery::default()));
        let mut names: Vec<_> = index(dir.path()).files.keys().cloned().collect();
        names.sort();
        assert_eq!(names, ["events.jsonl.2", "events.jsonl.3"]);

        fs::write(dir.path().join(INDEX_FILE), b"{not json").unwrap();
        let (lines, _) = run(dir.path(), &filter(ExportQuery::default()));
        assert_eq!(paths(&lines), ["c", "g", "d", "e"]);
    }
}
