//! Event export for the read API: the matching lines of an agent's stored
//! event files, oldest file first, delivered in chunks of whole lines.

use std::borrow::Cow;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::store::{rotated_generations, EVENTS_FILE};

/// Events per export when the request does not say.
pub const DEFAULT_LIMIT: usize = 100_000;
/// Most events one export may return.
pub const MAX_LIMIT: usize = 1_000_000;
/// Longest `contains` filter.
const MAX_CONTAINS_BYTES: usize = 256;
/// Size at which a chunk is handed to the response.
const CHUNK_BYTES: usize = 256 * 1024;
/// Event timestamps come from the agents' clocks. A file is skipped by its
/// write times only when it lies at least this far outside the range.
const CLOCK_SLACK: Duration = Duration::from_secs(24 * 3600);

/// Query string of `GET /api/v1/agents/{agent}/events`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub category: Option<String>,
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
            contains: query.contains,
            limit,
        })
    }

    fn matches(&self, line: &[u8]) -> bool {
        if let Some(needle) = &self.contains {
            if !contains(line, needle.as_bytes()) {
                return false;
            }
        }
        if self.from.is_none() && self.to.is_none() && self.category.is_none() {
            return true;
        }
        let Ok(head) = serde_json::from_slice::<Head<'_>>(line) else {
            return false;
        };
        if let Some(category) = &self.category {
            if !head.category.eq_ignore_ascii_case(category) {
                return false;
            }
        }
        if self.from.is_some() || self.to.is_some() {
            let Ok(t) = DateTime::parse_from_rfc3339(&head.timestamp) else {
                return false;
            };
            let t = t.with_timezone(&Utc);
            if self.from.is_some_and(|from| t < from) || self.to.is_some_and(|to| t > to) {
                return false;
            }
        }
        true
    }
}

/// The envelope fields the filters need.
#[derive(Deserialize)]
struct Head<'a> {
    #[serde(borrow)]
    timestamp: Cow<'a, str>,
    #[serde(borrow)]
    category: Cow<'a, str>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExportStats {
    pub files: usize,
    pub lines_scanned: u64,
    pub events: u64,
    /// `limit` events were returned; there may be more.
    pub limit_reached: bool,
    /// The receiver went away before the export finished.
    pub aborted: bool,
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
    let mut chunk: Vec<u8> = Vec::with_capacity(CHUNK_BYTES + 4096);
    let mut line = Vec::new();

    'files: for path in candidate_files(dir, filter)? {
        let file = match File::open(&path) {
            Ok(file) => file,
            // Pruned by retention since it was listed
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        stats.files += 1;
        let mut reader = BufReader::with_capacity(64 * 1024, file);
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if line.last() != Some(&b'\n') {
                // The active file's last line is still being written.
                break;
            }
            stats.lines_scanned += 1;
            if !filter.matches(&line[..line.len() - 1]) {
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
                return Ok(stats);
            }
        }
    }
    if !chunk.is_empty() && !emit(Bytes::from(chunk)) {
        stats.aborted = true;
    }
    Ok(stats)
}

/// The event files to read, oldest first: `events.jsonl.N` in ascending `N`,
/// then `events.jsonl`. With a time range, files whose write times show they
/// cannot hold matching events are left out.
fn candidate_files(dir: &Path, filter: &ExportFilter) -> io::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = match rotated_generations(dir, EVENTS_FILE) {
        Ok(generations) => generations
            .into_iter()
            .map(|n| dir.join(format!("{EVENTS_FILE}.{n}")))
            .collect(),
        // Nothing stored for this agent yet
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    files.push(dir.join(EVENTS_FILE));
    if filter.from.is_none() && filter.to.is_none() {
        return Ok(files);
    }

    // A file holds what arrived between the previous file's last write and
    // its own last write.
    let from = filter
        .from
        .and_then(|t| SystemTime::from(t).checked_sub(CLOCK_SLACK));
    let to = filter
        .to
        .and_then(|t| SystemTime::from(t).checked_add(CLOCK_SLACK));
    let mut selected = Vec::new();
    let mut previous_end: Option<SystemTime> = None;
    for path in files {
        let end = match fs::metadata(&path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let start = previous_end.replace(end);
        let ends_before = from.is_some_and(|from| end < from);
        let starts_after = matches!((start, to), (Some(start), Some(to)) if start > to);
        if !ends_before && !starts_after {
            selected.push(path);
        }
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
        format!(
            r#"{{"id":"x","timestamp":"{ts}","category":"{category}","data":{{"type":"T","path":"{path}"}}}}"#
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
                limit: None,
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
}
