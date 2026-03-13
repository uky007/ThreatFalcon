//! Local investigation CLI: query, explain, and bundle events from JSONL files.
//!
//! These commands read existing JSONL telemetry output and provide quick
//! investigation workflows without requiring an external SIEM or database.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use serde::{Deserialize, Serialize};

use crate::events::{EventCategory, EventData, Severity, ThreatEvent};
use crate::index;

/// Investigation subcommands for local JSONL analysis.
#[derive(Subcommand)]
pub enum Command {
    /// Query events from a JSONL telemetry file
    Query {
        /// Path to JSONL event file
        #[arg(long, value_name = "PATH")]
        input: PathBuf,

        /// Filter by process ID
        #[arg(long)]
        pid: Option<u32>,

        /// Filter by process_key (e.g., "1234:133579284000000000")
        #[arg(long)]
        process_key: Option<String>,

        /// Filter by event category (Process, Network, File, Registry, Dns, etc.)
        #[arg(long)]
        category: Option<String>,

        /// Filter by detection rule ID (e.g., "TF-EVA-001")
        #[arg(long)]
        rule_id: Option<String>,

        /// Filter by event source type (etw, sysmon, evasion, sensor)
        #[arg(long)]
        source: Option<String>,

        /// Filter by minimum severity (Info, Low, Medium, High, Critical)
        #[arg(long)]
        severity: Option<String>,

        /// Case-insensitive text search across serialized event data
        #[arg(long, value_name = "TEXT")]
        contains: Option<String>,

        /// Only events after this timestamp (RFC 3339). Alias: --since
        #[arg(long, alias = "since")]
        from: Option<String>,

        /// Only events before this timestamp (RFC 3339)
        #[arg(long)]
        to: Option<String>,

        /// Maximum number of results (default: 100)
        #[arg(long, default_value = "100")]
        limit: usize,

        /// Skip the SQLite index and force a full JSONL scan
        #[arg(long)]
        no_index: bool,
    },

    /// Explain an event with its process context timeline
    Explain {
        /// Event ID (UUID) to investigate
        #[arg(long, value_name = "ID")]
        event: String,

        /// Path to JSONL event file
        #[arg(long, value_name = "PATH")]
        input: PathBuf,

        /// Time window in minutes around the target event (default: 5)
        #[arg(long, default_value = "5")]
        window: u64,

        /// Output as structured JSON instead of human-readable text
        #[arg(long)]
        json: bool,

        /// Skip the SQLite index and force a full JSONL scan
        #[arg(long)]
        no_index: bool,
    },

    /// Bundle an event and related context into a single JSON document
    Bundle {
        /// Event ID (UUID) to investigate
        #[arg(long, value_name = "ID")]
        event: String,

        /// Path to JSONL event file
        #[arg(long, value_name = "PATH")]
        input: PathBuf,

        /// Time window in minutes around the target event (default: 5)
        #[arg(long, default_value = "5")]
        window: u64,

        /// Output file path (default: stdout)
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,

        /// Skip the SQLite index and force a full JSONL scan
        #[arg(long)]
        no_index: bool,
    },

    /// Build or manage the SQLite index for fast event lookups
    Index {
        /// Path to JSONL event file
        #[arg(long, value_name = "PATH")]
        input: PathBuf,

        /// Force a full rebuild (drop and recreate)
        #[arg(long)]
        rebuild: bool,

        /// Show index health and coverage status
        #[arg(long)]
        status: bool,
    },

    /// Show summary statistics for a JSONL telemetry file
    Stats {
        /// Path to JSONL event file
        #[arg(long, value_name = "PATH")]
        input: PathBuf,

        /// Output as structured JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// Follow new events appended to a JSONL file (like tail -f)
    Tail {
        /// Path to JSONL event file
        #[arg(long, value_name = "PATH")]
        input: PathBuf,

        /// Filter by process ID
        #[arg(long)]
        pid: Option<u32>,

        /// Filter by process_key (e.g., "1234:133579284000000000")
        #[arg(long)]
        process_key: Option<String>,

        /// Filter by event category (Process, Network, File, Registry, Dns, etc.)
        #[arg(long)]
        category: Option<String>,

        /// Filter by detection rule ID (e.g., "TF-EVA-001")
        #[arg(long)]
        rule_id: Option<String>,

        /// Filter by event source type (etw, sysmon, evasion, sensor)
        #[arg(long)]
        source: Option<String>,

        /// Filter by minimum severity (Info, Low, Medium, High, Critical)
        #[arg(long)]
        severity: Option<String>,

        /// Case-insensitive text search across serialized event data
        #[arg(long, value_name = "TEXT")]
        contains: Option<String>,

        /// Output as JSONL instead of human-readable format
        #[arg(long)]
        json: bool,
    },
}

/// Run an investigation subcommand.
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Query {
            input,
            pid,
            process_key,
            category,
            rule_id,
            source,
            severity,
            contains,
            from,
            to,
            limit,
            no_index,
        } => {
            let from = from
                .map(|s| parse_datetime(&s))
                .transpose()
                .context("invalid --from value")?;
            let to = to
                .map(|s| parse_datetime(&s))
                .transpose()
                .context("invalid --to value")?;
            let severity = severity
                .map(|s| parse_severity(&s))
                .transpose()
                .context("invalid --severity value")?;

            let filter = QueryFilter {
                pid,
                process_key,
                category,
                rule_id,
                source,
                severity,
                contains,
                from,
                to,
            };

            run_query(&input, &filter, limit, no_index)
        }

        Command::Explain {
            event,
            input,
            window,
            json,
            no_index,
        } => run_explain(&input, &event, window, json, no_index),

        Command::Bundle {
            event,
            input,
            window,
            output,
            no_index,
        } => run_bundle(&input, &event, window, output.as_deref(), no_index),

        Command::Index {
            input,
            rebuild,
            status,
        } => run_index(&input, rebuild, status),

        Command::Stats { input, json } => run_stats(&input, json),

        Command::Tail {
            input,
            pid,
            process_key,
            category,
            rule_id,
            source,
            severity,
            contains,
            json,
        } => {
            let severity = severity
                .map(|s| parse_severity(&s))
                .transpose()
                .context("invalid --severity value")?;
            let filter = QueryFilter {
                pid,
                process_key,
                category,
                rule_id,
                source,
                severity,
                contains,
                from: None,
                to: None,
            };
            run_tail(&input, &filter, json)
        }
    }
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

struct QueryFilter {
    pid: Option<u32>,
    process_key: Option<String>,
    category: Option<String>,
    rule_id: Option<String>,
    source: Option<String>,
    severity: Option<crate::events::Severity>,
    contains: Option<String>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
}

impl QueryFilter {
    /// Convert CLI filter to an index-compatible filter for SQL queries.
    fn to_index_filter(&self, limit: Option<usize>) -> index::IndexFilter {
        index::IndexFilter {
            pid: self.pid,
            process_key: self.process_key.clone(),
            category: self.category.clone(),
            rule_id: self.rule_id.clone(),
            source_type: self.source.clone(),
            min_severity_ord: self.severity.map(severity_ord),
            from: self.from.map(|dt| dt.to_rfc3339()),
            to: self.to.map(|dt| dt.to_rfc3339()),
            limit,
        }
    }

    fn matches(&self, event: &ThreatEvent) -> bool {
        if let Some(ref from) = self.from {
            if event.timestamp < *from {
                return false;
            }
        }

        if let Some(ref to) = self.to {
            if event.timestamp > *to {
                return false;
            }
        }

        if let Some(pid) = self.pid {
            if event_pid(&event.data) != Some(pid) {
                return false;
            }
        }

        if let Some(ref key) = self.process_key {
            let event_key = event
                .process_context
                .as_ref()
                .map(|c| c.process_key.as_str());
            if event_key != Some(key.as_str()) {
                return false;
            }
        }

        if let Some(ref cat) = self.category {
            if !category_matches(&event.category, cat) {
                return false;
            }
        }

        if let Some(ref rule_id) = self.rule_id {
            let has_rule = event.rule.as_ref().map(|r| r.id.as_str()) == Some(rule_id.as_str());
            if !has_rule {
                return false;
            }
        }

        if let Some(ref src) = self.source {
            if !source_matches(&event.source, src) {
                return false;
            }
        }

        if let Some(min_sev) = self.severity {
            if event.severity < min_sev {
                return false;
            }
        }

        if let Some(ref text) = self.contains {
            if !event_contains(event, text) {
                return false;
            }
        }

        true
    }
}

fn run_query(input: &Path, filter: &QueryFilter, limit: usize, no_index: bool) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    let mut count = 0;

    // Try index-accelerated query if applicable
    if !no_index && filter.contains.is_none() {
        if let Some(idx) = index::try_open_and_update(input)? {
            let idx_filter = filter.to_index_filter(Some(limit));
            let locations = idx.query_locations(&idx_filter)?;
            let events = index::fetch_events(input, &locations)?;
            for event in &events {
                if filter.matches(event) {
                    if let Ok(json) = serde_json::to_string(event) {
                        let _ = writeln!(stdout, "{json}");
                    }
                    count += 1;
                }
            }
            eprintln!("{count} event(s) matched (indexed)");
            return Ok(());
        }
    }

    // Fallback: full JSONL scan
    for_each_event(input, |event| {
        if count >= limit {
            return false; // stop iteration
        }
        if filter.matches(&event) {
            // Output as JSONL for pipeability
            if let Ok(json) = serde_json::to_string(&event) {
                let _ = writeln!(stdout, "{json}");
            }
            count += 1;
        }
        true // continue
    })?;

    eprintln!("{count} event(s) matched");
    Ok(())
}

// ---------------------------------------------------------------------------
// Explain
// ---------------------------------------------------------------------------

/// Structured explain output for `--json` mode.
#[derive(Serialize)]
struct ExplainOutput {
    target_event: ThreatEvent,
    window_minutes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_key: Option<String>,
    timeline: Vec<ThreatEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    script_amsi_activity: Vec<ThreatEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<crate::events::RuleMetadata>,
}

fn run_explain(input: &Path, event_id: &str, window_mins: u64, json: bool, no_index: bool) -> Result<()> {
    // Try index-accelerated lookup
    if !no_index {
        if let Some(idx) = index::try_open_and_update(input)? {
            return run_explain_indexed(input, &idx, event_id, window_mins, json);
        }
    }

    // Fallback: full JSONL scan
    let events = read_all_events(input)?;
    let target = find_event(&events, event_id)?;

    // --- Build timeline ---
    let process_key = target.process_context.as_ref().map(|c| c.process_key.as_str());
    let target_pid = target.data.acting_pid();
    let window = chrono::Duration::minutes(window_mins as i64);
    let t_start = target.timestamp - window;
    let t_end = target.timestamp + window;

    let mut timeline: Vec<&ThreatEvent> = if let Some(key) = process_key {
        events
            .iter()
            .filter(|e| {
                e.process_context
                    .as_ref()
                    .map(|c| c.process_key.as_str())
                    == Some(key)
                    && e.timestamp >= t_start
                    && e.timestamp <= t_end
            })
            .collect()
    } else if let Some(pid) = target_pid {
        // PID-based fallback when process_context is unavailable
        events
            .iter()
            .filter(|e| {
                e.data.acting_pid() == Some(pid)
                    && e.timestamp >= t_start
                    && e.timestamp <= t_end
            })
            .collect()
    } else {
        vec![]
    };
    timeline.sort_by_key(|e| e.timestamp);

    // --- JSON output ---
    if json {
        let script_activity = build_script_activity(target, &events, window_mins);
        let output = ExplainOutput {
            target_event: target.clone(),
            window_minutes: window_mins,
            process_key: process_key.map(|s| s.to_string()),
            timeline: timeline.into_iter().cloned().collect(),
            script_amsi_activity: script_activity,
            rule: target.rule.clone(),
        };
        let json_str = serde_json::to_string_pretty(&output)?;
        println!("{json_str}");
        return Ok(());
    }

    // --- Human-readable output ---
    let mut stdout = std::io::stdout().lock();

    writeln!(stdout, "=== Target Event ===")?;
    print_event_detail(&mut stdout, target)?;

    if process_key.is_some() || target_pid.is_some() {
        let key_display = process_key
            .map(|k| k.to_string())
            .unwrap_or_else(|| format!("pid:{}", target_pid.unwrap()));
        writeln!(
            stdout,
            "\n=== Process Timeline ({key_display}, ±{window_mins} min, {} events) ===",
            timeline.len()
        )?;
        for evt in &timeline {
            let marker = if evt.id == target.id { ">" } else { " " };
            writeln!(
                stdout,
                "{marker} {}  {:9} {}",
                evt.timestamp.format("%H:%M:%S%.3fZ"),
                category_short(&evt.category),
                event_summary(&evt.data),
            )?;
        }
    } else {
        writeln!(stdout, "\nNo process_context — cannot build timeline.")?;
    }

    // --- Script / AMSI correlation ---
    if is_script_related(&target.data) {
        let activity = build_script_activity(target, &events, window_mins);
        if !activity.is_empty() {
            let amsi_count = activity
                .iter()
                .filter(|e| matches!(e.data, EventData::AmsiScan { .. }))
                .count();
            let script_count = activity
                .iter()
                .filter(|e| matches!(e.data, EventData::ScriptBlock { .. }))
                .count();
            let detected_count = activity
                .iter()
                .filter(|e| matches!(&e.data, EventData::AmsiScan { scan_result, .. } if *scan_result >= 32768))
                .count();

            writeln!(
                stdout,
                "\n=== Script / AMSI Activity ({script_count} script block(s), \
                 {amsi_count} scan(s), {detected_count} detected) ==="
            )?;

            for evt in &activity {
                let marker = if evt.id == target.id { ">" } else { " " };
                writeln!(
                    stdout,
                    "{marker} {}  {}",
                    evt.timestamp.format("%H:%M:%S%.3fZ"),
                    event_summary(&evt.data),
                )?;
            }
        }
    }

    // --- Rule ---
    if let Some(ref rule) = target.rule {
        writeln!(stdout, "\n=== Detection Rule ===")?;
        writeln!(stdout, "  ID:          {}", rule.id)?;
        writeln!(stdout, "  Name:        {}", rule.name)?;
        writeln!(stdout, "  Description: {}", rule.description)?;
        writeln!(
            stdout,
            "  MITRE:       {} / {} ({})",
            rule.mitre.tactic, rule.mitre.technique_id, rule.mitre.technique_name
        )?;
        writeln!(stdout, "  Confidence:  {:?}", rule.confidence)?;
        for e in &rule.evidence {
            writeln!(stdout, "  Evidence:    {e}")?;
        }
    }

    Ok(())
}

fn print_event_detail(w: &mut impl Write, event: &ThreatEvent) -> Result<()> {
    writeln!(w, "  ID:       {}", event.id)?;
    writeln!(w, "  Time:     {}", event.timestamp.to_rfc3339())?;
    writeln!(w, "  Category: {}", category_short(&event.category))?;
    writeln!(w, "  Severity: {:?}", event.severity)?;
    writeln!(w, "  Source:   {}", source_display(&event.source))?;
    writeln!(w, "  Host:     {}", event.hostname)?;

    if let Some(ref ctx) = event.process_context {
        writeln!(w, "  Process:")?;
        writeln!(w, "    key:        {}", ctx.process_key)?;
        if let Some(ref p) = ctx.image_path {
            writeln!(w, "    image:      {p}")?;
        }
        if let Some(ref c) = ctx.command_line {
            writeln!(w, "    cmdline:    {c}")?;
        }
        if let Some(ref u) = ctx.user {
            writeln!(w, "    user:       {u}")?;
        }
        if let Some(ref il) = ctx.integrity_level {
            writeln!(w, "    integrity:  {il}")?;
        }
        if let Some(ppid) = ctx.ppid {
            writeln!(w, "    ppid:       {ppid}")?;
        }
    }

    writeln!(w, "  Data:     {}", event_summary(&event.data))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct EvidenceBundle {
    bundle_version: u32,
    created_at: DateTime<Utc>,
    target_event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_key: Option<String>,
    window_minutes: u64,
    event_count: usize,
    target_event: ThreatEvent,
    related_events: Vec<ThreatEvent>,
}

fn run_bundle(
    input: &Path,
    event_id: &str,
    window_mins: u64,
    output: Option<&Path>,
    no_index: bool,
) -> Result<()> {
    // Try index-accelerated lookup
    if !no_index {
        if let Some(idx) = index::try_open_and_update(input)? {
            return run_bundle_indexed(input, &idx, event_id, window_mins, output);
        }
    }

    // Fallback: full JSONL scan
    let events = read_all_events(input)?;
    let target = find_event(&events, event_id)?.clone();

    let process_key = target
        .process_context
        .as_ref()
        .map(|c| c.process_key.clone());

    let mut related: Vec<ThreatEvent> = if let Some(ref key) = process_key {
        let window = chrono::Duration::minutes(window_mins as i64);
        let t_start = target.timestamp - window;
        let t_end = target.timestamp + window;

        events
            .into_iter()
            .filter(|e| {
                e.id != target.id
                    && e.process_context
                        .as_ref()
                        .map(|c| c.process_key.as_str())
                        == Some(key.as_str())
                    && e.timestamp >= t_start
                    && e.timestamp <= t_end
            })
            .collect()
    } else {
        vec![]
    };
    related.sort_by_key(|e| e.timestamp);

    let bundle = EvidenceBundle {
        bundle_version: 1,
        created_at: Utc::now(),
        target_event_id: target.id.to_string(),
        event_count: 1 + related.len(),
        process_key,
        window_minutes: window_mins,
        target_event: target,
        related_events: related,
    };

    match output {
        Some(path) if is_zip_extension(path) => {
            write_bundle_zip(path, &bundle)?;
            eprintln!(
                "Bundle written to {} ({} events, zip)",
                path.display(),
                bundle.event_count
            );
        }
        Some(path) => {
            let json = serde_json::to_string_pretty(&bundle)?;
            std::fs::write(path, &json)
                .with_context(|| format!("failed to write bundle to {}", path.display()))?;
            eprintln!(
                "Bundle written to {} ({} events)",
                path.display(),
                bundle.event_count
            );
        }
        None => {
            let json = serde_json::to_string_pretty(&bundle)?;
            println!("{json}");
        }
    }

    Ok(())
}

/// True if the path has a `.zip` extension (case-insensitive).
fn is_zip_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
}

/// Manifest included in zip bundles for metadata and tool interop.
#[derive(Serialize)]
struct BundleManifest {
    format: &'static str,
    format_version: u32,
    created_at: DateTime<Utc>,
    sensor_version: String,
    target_event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_key: Option<String>,
    window_minutes: u64,
    event_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    time_range: Option<TimeRange>,
    files: Vec<&'static str>,
}

/// Time range of events included in a bundle.
#[derive(Serialize, Deserialize, Debug)]
struct TimeRange {
    earliest: DateTime<Utc>,
    latest: DateTime<Utc>,
}

/// Write an evidence bundle as a zip archive containing:
///   - `manifest.json`    — machine-readable metadata
///   - `target_event.json` — the target event (pretty-printed)
///   - `related_events.jsonl` — related events (one per line)
///   - `bundle.json`      — the full combined bundle (same as JSON output)
fn write_bundle_zip(path: &Path, bundle: &EvidenceBundle) -> Result<()> {
    let file = std::fs::File::create(path)
        .with_context(|| format!("failed to create zip at {}", path.display()))?;
    let mut zip = zip::ZipWriter::new(file);

    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // manifest.json
    let time_range = {
        let mut all_ts: Vec<DateTime<Utc>> =
            vec![bundle.target_event.timestamp];
        all_ts.extend(bundle.related_events.iter().map(|e| e.timestamp));
        let earliest = *all_ts.iter().min().unwrap();
        let latest = *all_ts.iter().max().unwrap();
        Some(TimeRange { earliest, latest })
    };
    let manifest = BundleManifest {
        format: "threatfalcon-evidence-bundle",
        format_version: 1,
        created_at: bundle.created_at,
        sensor_version: bundle.target_event.sensor_version.clone(),
        target_event_id: bundle.target_event_id.clone(),
        process_key: bundle.process_key.clone(),
        window_minutes: bundle.window_minutes,
        event_count: bundle.event_count,
        time_range,
        files: vec![
            "manifest.json",
            "target_event.json",
            "related_events.jsonl",
            "bundle.json",
        ],
    };
    zip.start_file("manifest.json", options)?;
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    zip.write_all(manifest_json.as_bytes())?;

    // target_event.json
    zip.start_file("target_event.json", options)?;
    let target_json = serde_json::to_string_pretty(&bundle.target_event)?;
    zip.write_all(target_json.as_bytes())?;

    // related_events.jsonl
    zip.start_file("related_events.jsonl", options)?;
    for event in &bundle.related_events {
        let line = serde_json::to_string(event)?;
        zip.write_all(line.as_bytes())?;
        zip.write_all(b"\n")?;
    }

    // bundle.json (full combined — same as non-zip output)
    zip.start_file("bundle.json", options)?;
    let bundle_json = serde_json::to_string_pretty(bundle)?;
    zip.write_all(bundle_json.as_bytes())?;

    zip.finish()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Index subcommand
// ---------------------------------------------------------------------------

fn run_index(input: &Path, rebuild: bool, status: bool) -> Result<()> {
    let idx = index::EventIndex::open(input)?;

    if status {
        let st = idx.status(input)?;
        eprintln!("Index:      {}", index::index_path_for(input).display());
        eprintln!("Events:     {}", st.event_count);
        eprintln!("Indexed to: {} / {} bytes", st.indexed_up_to, st.jsonl_size);
        eprintln!(
            "Status:     {}",
            if st.is_current { "current" } else { "stale" }
        );
        return Ok(());
    }

    let stats = if rebuild {
        idx.rebuild(input)?
    } else {
        idx.build(input)?
    };

    eprintln!(
        "Indexed {} new event(s), {} total in {}",
        stats.new_events,
        stats.total_events,
        index::index_path_for(input).display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Summary statistics for a JSONL telemetry file.
#[derive(Serialize)]
struct EventStats {
    total_events: u64,
    time_range: Option<TimeRange>,
    by_category: Vec<CountEntry>,
    by_severity: Vec<CountEntry>,
    by_source: Vec<CountEntry>,
    top_processes: Vec<ProcessEntry>,
    top_rules: Vec<CountEntry>,
}

#[derive(Serialize)]
struct CountEntry {
    label: String,
    count: u64,
}

#[derive(Serialize)]
struct ProcessEntry {
    pid: u32,
    process_key: Option<String>,
    image: Option<String>,
    count: u64,
}

fn run_stats(input: &Path, json: bool) -> Result<()> {
    use std::collections::HashMap;

    let mut total: u64 = 0;
    let mut earliest: Option<DateTime<Utc>> = None;
    let mut latest: Option<DateTime<Utc>> = None;
    let mut by_category: HashMap<String, u64> = HashMap::new();
    let mut by_severity: HashMap<String, u64> = HashMap::new();
    let mut by_source: HashMap<String, u64> = HashMap::new();
    let mut by_rule: HashMap<String, u64> = HashMap::new();

    // Track per-process stats keyed by process_key (PID-reuse safe),
    // with PID-only fallback for unenriched events.
    struct ProcessInfo {
        pid: u32,
        process_key: Option<String>,
        image: Option<String>,
        count: u64,
    }
    let mut by_process: HashMap<String, ProcessInfo> = HashMap::new();

    for_each_event(input, |event| {
        total += 1;

        // Time range
        match (&earliest, &latest) {
            (None, _) => {
                earliest = Some(event.timestamp);
                latest = Some(event.timestamp);
            }
            (Some(e), Some(l)) => {
                if event.timestamp < *e {
                    earliest = Some(event.timestamp);
                }
                if event.timestamp > *l {
                    latest = Some(event.timestamp);
                }
            }
            _ => unreachable!(),
        }

        // Category
        *by_category
            .entry(category_short(&event.category).to_string())
            .or_default() += 1;

        // Severity
        *by_severity
            .entry(format!("{:?}", event.severity))
            .or_default() += 1;

        // Source
        let src_label = match &event.source {
            crate::events::EventSource::Etw { provider } => format!("ETW/{provider}"),
            crate::events::EventSource::Sysmon { event_id } => {
                format!("Sysmon/{event_id}")
            }
            crate::events::EventSource::EvasionDetector => "EvasionDetector".into(),
            crate::events::EventSource::Sensor => "Sensor".into(),
        };
        *by_source.entry(src_label).or_default() += 1;

        // Rules
        if let Some(ref rule) = event.rule {
            *by_rule.entry(rule.id.clone()).or_default() += 1;
        }

        // Per-process — prefer process_key, fall back to PID
        if let Some(pid) = event_pid(&event.data) {
            let key = event
                .process_context
                .as_ref()
                .map(|c| c.process_key.clone())
                .unwrap_or_else(|| format!("pid:{pid}"));
            let info = by_process.entry(key.clone()).or_insert_with(|| ProcessInfo {
                pid,
                process_key: event.process_context.as_ref().map(|c| c.process_key.clone()),
                image: None,
                count: 0,
            });
            info.count += 1;
            if info.image.is_none() {
                if let Some(ref ctx) = event.process_context {
                    info.image = ctx.image_path.clone();
                }
            }
        }

        true
    })?;

    // Sort aggregates by count descending
    let mut cat_vec: Vec<CountEntry> = by_category
        .into_iter()
        .map(|(label, count)| CountEntry { label, count })
        .collect();
    cat_vec.sort_by(|a, b| b.count.cmp(&a.count));

    // Sort severity in logical order
    let sev_order = ["Critical", "High", "Medium", "Low", "Info"];
    let mut sev_vec: Vec<CountEntry> = sev_order
        .iter()
        .filter_map(|s| {
            by_severity
                .get(*s)
                .map(|c| CountEntry {
                    label: s.to_string(),
                    count: *c,
                })
        })
        .collect();
    // Include any unexpected severity values
    for (label, count) in &by_severity {
        if !sev_order.contains(&label.as_str()) {
            sev_vec.push(CountEntry {
                label: label.clone(),
                count: *count,
            });
        }
    }

    let mut src_vec: Vec<CountEntry> = by_source
        .into_iter()
        .map(|(label, count)| CountEntry { label, count })
        .collect();
    src_vec.sort_by(|a, b| b.count.cmp(&a.count));

    let mut rule_vec: Vec<CountEntry> = by_rule
        .into_iter()
        .map(|(label, count)| CountEntry { label, count })
        .collect();
    rule_vec.sort_by(|a, b| b.count.cmp(&a.count));

    // Top 10 processes by event count
    let mut proc_vec: Vec<ProcessInfo> = by_process.into_values().collect();
    proc_vec.sort_by(|a, b| b.count.cmp(&a.count));
    let top_processes: Vec<ProcessEntry> = proc_vec
        .into_iter()
        .take(10)
        .map(|info| ProcessEntry {
            pid: info.pid,
            process_key: info.process_key,
            image: info.image,
            count: info.count,
        })
        .collect();

    let time_range = earliest.and_then(|e| latest.map(|l| TimeRange { earliest: e, latest: l }));

    let stats = EventStats {
        total_events: total,
        time_range,
        by_category: cat_vec,
        by_severity: sev_vec,
        by_source: src_vec,
        top_processes,
        top_rules: rule_vec,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&stats)?);
        return Ok(());
    }

    // Human-readable output
    let mut out = std::io::stdout().lock();

    writeln!(out, "=== Event Statistics ===")?;
    writeln!(out, "Total events: {}", stats.total_events)?;

    if let Some(ref tr) = stats.time_range {
        writeln!(out, "Time range:   {} → {}", tr.earliest, tr.latest)?;
        let duration = tr.latest - tr.earliest;
        let hours = duration.num_hours();
        let mins = duration.num_minutes() % 60;
        if hours > 0 {
            writeln!(out, "Duration:     {hours}h {mins}m")?;
        } else {
            writeln!(out, "Duration:     {mins}m")?;
        }
    }

    if !stats.by_category.is_empty() {
        writeln!(out, "\n--- By Category ---")?;
        for entry in &stats.by_category {
            writeln!(out, "  {:12} {:>6}", entry.label, entry.count)?;
        }
    }

    if !stats.by_severity.is_empty() {
        writeln!(out, "\n--- By Severity ---")?;
        for entry in &stats.by_severity {
            writeln!(out, "  {:12} {:>6}", entry.label, entry.count)?;
        }
    }

    if !stats.by_source.is_empty() {
        writeln!(out, "\n--- By Source ---")?;
        for entry in &stats.by_source {
            writeln!(out, "  {:40} {:>6}", entry.label, entry.count)?;
        }
    }

    if !stats.top_processes.is_empty() {
        writeln!(out, "\n--- Top Processes (by event count) ---")?;
        for p in &stats.top_processes {
            let label = p
                .image
                .as_deref()
                .unwrap_or_else(|| p.process_key.as_deref().unwrap_or("?"));
            writeln!(out, "  PID {:>6}  {:>6} events  {}", p.pid, p.count, label)?;
        }
    }

    if !stats.top_rules.is_empty() {
        writeln!(out, "\n--- Detection Rules ---")?;
        for entry in &stats.top_rules {
            writeln!(out, "  {:20} {:>6}", entry.label, entry.count)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tail
// ---------------------------------------------------------------------------

fn run_tail(input: &Path, filter: &QueryFilter, json: bool) -> Result<()> {
    use std::io::{Seek, SeekFrom};

    let file = std::fs::File::open(input)
        .with_context(|| format!("cannot open {}", input.display()))?;
    let file_size = file.metadata()?.len();
    let mut reader = std::io::BufReader::new(file);

    // Seek to end — only show newly appended events
    reader.seek(SeekFrom::End(0))?;
    eprintln!(
        "Tailing {} (skipped {} bytes, Ctrl+C to stop)",
        input.display(),
        file_size,
    );

    let mut stdout = std::io::stdout().lock();
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        match reader.read_line(&mut line_buf) {
            Ok(0) => {
                // No new data — check for file rotation before sleeping.
                // The file at the path may have been replaced (rename + new
                // create) by the output sink's rotation logic.
                if tail_file_rotated(input, &reader) {
                    eprintln!("File rotated, reopening {}", input.display());
                    drop(stdout);
                    let new_file = std::fs::File::open(input)
                        .with_context(|| format!("cannot reopen {}", input.display()))?;
                    reader = std::io::BufReader::new(new_file);
                    stdout = std::io::stdout().lock();
                    continue;
                }

                drop(stdout);
                std::thread::sleep(std::time::Duration::from_secs(1));
                stdout = std::io::stdout().lock();
            }
            Ok(_) => {
                let line = line_buf.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(event) = serde_json::from_str::<ThreatEvent>(line) {
                    if !filter.matches(&event) {
                        continue;
                    }
                    if json {
                        let _ = writeln!(stdout, "{line}");
                    } else {
                        let sev = format!("{:?}", event.severity);
                        let pid_str = event_pid(&event.data)
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".into());
                        writeln!(
                            stdout,
                            "{} {:>8} {:>9} PID {:>6}  {}",
                            event.timestamp.format("%H:%M:%S%.3fZ"),
                            sev,
                            category_short(&event.category),
                            pid_str,
                            event_summary(&event.data),
                        )?;
                    }
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Check if the file at `path` is a different file than the one backing
/// `reader` (i.e., the file was rotated/replaced).
fn tail_file_rotated(
    path: &Path,
    reader: &std::io::BufReader<std::fs::File>,
) -> bool {
    let path_meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false, // path gone temporarily during rotation
    };
    let handle_meta = match reader.get_ref().metadata() {
        Ok(m) => m,
        Err(_) => return false,
    };

    // On Unix, compare device + inode to detect file replacement.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if handle_meta.dev() != path_meta.dev() || handle_meta.ino() != path_meta.ino() {
            return true;
        }
    }

    // Fallback (non-Unix): if the path's file is smaller than our handle's
    // current size, assume rotation. Not perfect but covers truncation.
    #[cfg(not(unix))]
    {
        if path_meta.len() < handle_meta.len() {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Index-accelerated explain
// ---------------------------------------------------------------------------

fn run_explain_indexed(
    input: &Path,
    idx: &index::EventIndex,
    event_id: &str,
    window_mins: u64,
    json: bool,
) -> Result<()> {
    // Find target event by ID
    let target_locs = idx.find_by_id(event_id)?;
    let target = match target_locs.len() {
        0 => return Err(anyhow::anyhow!("event not found: {event_id}")),
        1 => {
            let events = index::fetch_events(input, &target_locs)?;
            events.into_iter().next().unwrap()
        }
        n => {
            return Err(anyhow::anyhow!(
                "ambiguous event ID prefix '{event_id}' matches {n} events"
            ))
        }
    };

    // Find related events by process_key (or PID fallback) within window
    let process_key = target
        .process_context
        .as_ref()
        .map(|c| c.process_key.as_str());
    let target_pid = target.data.acting_pid();
    let window = chrono::Duration::minutes(window_mins as i64);
    let t_start = target.timestamp - window;
    let t_end = target.timestamp + window;
    let from_str = t_start.to_rfc3339();
    let to_str = t_end.to_rfc3339();

    let mut timeline = if let Some(key) = process_key {
        let locs = idx.find_by_process_key(key, &from_str, &to_str)?;
        index::fetch_events(input, &locs)?
    } else if let Some(pid) = target_pid {
        // PID-based fallback — same semantics as the full-scan path
        let locs = idx.find_by_pid(pid, &from_str, &to_str)?;
        index::fetch_events(input, &locs)?
    } else {
        vec![]
    };
    timeline.sort_by_key(|e| e.timestamp);

    // Script / AMSI correlation — use the same build_script_activity()
    // function as the full-scan path so PID-based fallback is preserved.
    let script_activity = build_script_activity(&target, &timeline, window_mins);

    if json {
        let output = ExplainOutput {
            target_event: target.clone(),
            window_minutes: window_mins,
            process_key: process_key.map(|s| s.to_string()),
            timeline,
            script_amsi_activity: script_activity,
            rule: target.rule.clone(),
        };
        let json_str = serde_json::to_string_pretty(&output)?;
        println!("{json_str}");
        return Ok(());
    }

    // Human-readable output (reuse existing formatting)
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "=== Target Event ===")?;
    print_event_detail(&mut stdout, &target)?;

    if process_key.is_some() || target_pid.is_some() {
        let key_display = process_key
            .map(|k| k.to_string())
            .unwrap_or_else(|| format!("pid:{}", target_pid.unwrap()));
        writeln!(
            stdout,
            "\n=== Process Timeline ({key_display}, ±{window_mins} min, {} events) ===",
            timeline.len()
        )?;
        for evt in &timeline {
            let marker = if evt.id == target.id { ">" } else { " " };
            writeln!(
                stdout,
                "{marker} {}  {:9} {}",
                evt.timestamp.format("%H:%M:%S%.3fZ"),
                category_short(&evt.category),
                event_summary(&evt.data),
            )?;
        }
    } else {
        writeln!(stdout, "\nNo process_context — cannot build timeline.")?;
    }

    // Script / AMSI correlation
    if !script_activity.is_empty() {
        let amsi_count = script_activity
            .iter()
            .filter(|e| matches!(e.data, EventData::AmsiScan { .. }))
            .count();
        let script_count = script_activity
            .iter()
            .filter(|e| matches!(e.data, EventData::ScriptBlock { .. }))
            .count();
        let detected_count = script_activity
            .iter()
            .filter(|e| matches!(&e.data, EventData::AmsiScan { scan_result, .. } if *scan_result >= 32768))
            .count();

        writeln!(
            stdout,
            "\n=== Script / AMSI Activity ({script_count} script block(s), \
             {amsi_count} scan(s), {detected_count} detected) ==="
        )?;

        for evt in &script_activity {
            let marker = if evt.id == target.id { ">" } else { " " };
            writeln!(
                stdout,
                "{marker} {}  {}",
                evt.timestamp.format("%H:%M:%S%.3fZ"),
                event_summary(&evt.data),
            )?;
        }
    }

    // Rule
    if let Some(ref rule) = target.rule {
        writeln!(stdout, "\n=== Detection Rule ===")?;
        writeln!(stdout, "  ID:          {}", rule.id)?;
        writeln!(stdout, "  Name:        {}", rule.name)?;
        writeln!(stdout, "  Description: {}", rule.description)?;
        writeln!(
            stdout,
            "  MITRE:       {} / {} ({})",
            rule.mitre.tactic, rule.mitre.technique_id, rule.mitre.technique_name
        )?;
        writeln!(stdout, "  Confidence:  {:?}", rule.confidence)?;
        for e in &rule.evidence {
            writeln!(stdout, "  Evidence:    {e}")?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Index-accelerated bundle
// ---------------------------------------------------------------------------

fn run_bundle_indexed(
    input: &Path,
    idx: &index::EventIndex,
    event_id: &str,
    window_mins: u64,
    output: Option<&Path>,
) -> Result<()> {
    // Find target event by ID
    let target_locs = idx.find_by_id(event_id)?;
    let target = match target_locs.len() {
        0 => return Err(anyhow::anyhow!("event not found: {event_id}")),
        1 => {
            let events = index::fetch_events(input, &target_locs)?;
            events.into_iter().next().unwrap()
        }
        n => {
            return Err(anyhow::anyhow!(
                "ambiguous event ID prefix '{event_id}' matches {n} events"
            ))
        }
    };

    let process_key = target
        .process_context
        .as_ref()
        .map(|c| c.process_key.clone());

    let mut related = if let Some(ref key) = process_key {
        let window = chrono::Duration::minutes(window_mins as i64);
        let t_start = target.timestamp - window;
        let t_end = target.timestamp + window;
        let locs = idx.find_by_process_key(
            key,
            &t_start.to_rfc3339(),
            &t_end.to_rfc3339(),
        )?;
        let mut events = index::fetch_events(input, &locs)?;
        events.retain(|e| e.id != target.id);
        events
    } else {
        vec![]
    };
    related.sort_by_key(|e| e.timestamp);

    let bundle = EvidenceBundle {
        bundle_version: 1,
        created_at: Utc::now(),
        target_event_id: target.id.to_string(),
        event_count: 1 + related.len(),
        process_key,
        window_minutes: window_mins,
        target_event: target,
        related_events: related,
    };

    match output {
        Some(path) if is_zip_extension(path) => {
            write_bundle_zip(path, &bundle)?;
            eprintln!(
                "Bundle written to {} ({} events, zip)",
                path.display(),
                bundle.event_count
            );
        }
        Some(path) => {
            let json = serde_json::to_string_pretty(&bundle)?;
            std::fs::write(path, &json)
                .with_context(|| format!("failed to write bundle to {}", path.display()))?;
            eprintln!(
                "Bundle written to {} ({} events)",
                path.display(),
                bundle.event_count
            );
        }
        None => {
            let json = serde_json::to_string_pretty(&bundle)?;
            println!("{json}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map severity to a numeric ordering for index queries.
fn severity_ord(sev: Severity) -> i32 {
    match sev {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Parse a severity level string (case-insensitive).
fn parse_severity(s: &str) -> Result<crate::events::Severity> {
    match s.to_ascii_lowercase().as_str() {
        "info" => Ok(crate::events::Severity::Info),
        "low" => Ok(crate::events::Severity::Low),
        "medium" | "med" => Ok(crate::events::Severity::Medium),
        "high" => Ok(crate::events::Severity::High),
        "critical" | "crit" => Ok(crate::events::Severity::Critical),
        _ => anyhow::bail!(
            "unknown severity: {s} (expected: info, low, medium, high, critical)"
        ),
    }
}

/// Check if an event's source matches a source type string (case-insensitive).
fn source_matches(source: &crate::events::EventSource, filter: &str) -> bool {
    let filter_lower = filter.to_ascii_lowercase();
    match source {
        crate::events::EventSource::Etw { provider } => {
            filter_lower == "etw"
                || provider.to_ascii_lowercase().contains(&filter_lower)
        }
        crate::events::EventSource::Sysmon { .. } => filter_lower == "sysmon",
        crate::events::EventSource::EvasionDetector => {
            filter_lower == "evasion" || filter_lower == "evasiondetector"
        }
        crate::events::EventSource::Sensor => filter_lower == "sensor",
    }
}

/// Case-insensitive text search across the serialized event JSON.
///
/// Searches both the raw JSON (which has escaped backslashes like `C:\\Temp`)
/// and an unescaped version (where `\\` is collapsed to `\`), so that a user
/// query for `C:\Temp\evil.exe` matches the JSON-escaped form.
fn event_contains(event: &ThreatEvent, text: &str) -> bool {
    if let Ok(json) = serde_json::to_string(event) {
        let lower_json = json.to_ascii_lowercase();
        let lower_text = text.to_ascii_lowercase();
        if lower_json.contains(&lower_text) {
            return true;
        }
        // Also search an unescaped copy so that Windows paths typed naturally
        // (C:\Temp\evil.exe) match their JSON-escaped form (C:\\Temp\\evil.exe).
        let unescaped = lower_json.replace("\\\\", "\\");
        unescaped.contains(&lower_text)
    } else {
        false
    }
}

/// Parse an RFC 3339 datetime string.
fn parse_datetime(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| anyhow::anyhow!("expected RFC 3339 datetime (e.g., 2026-03-13T00:00:00Z): {e}"))
}

/// Iterate over events in a JSONL file. The callback returns `true` to
/// continue or `false` to stop early.
fn for_each_event(path: &Path, mut f: impl FnMut(ThreatEvent) -> bool) -> Result<()> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        // Skip lines that don't parse — JSONL files may have partial writes
        if let Ok(event) = serde_json::from_str::<ThreatEvent>(&line) {
            if !f(event) {
                break;
            }
        }
    }

    Ok(())
}

/// Read all events from a JSONL file into memory.
fn read_all_events(path: &Path) -> Result<Vec<ThreatEvent>> {
    let mut events = Vec::new();
    for_each_event(path, |event| {
        events.push(event);
        true
    })?;
    Ok(events)
}

/// Find an event by ID (prefix match supported).
fn find_event<'a>(events: &'a [ThreatEvent], id: &str) -> Result<&'a ThreatEvent> {
    // Try exact match first
    if let Some(event) = events.iter().find(|e| e.id.to_string() == id) {
        return Ok(event);
    }

    // Try prefix match (e.g., "a1b2c3d4" matches "a1b2c3d4-e5f6-...")
    let matches: Vec<&ThreatEvent> = events
        .iter()
        .filter(|e| e.id.to_string().starts_with(id))
        .collect();

    match matches.len() {
        0 => Err(anyhow::anyhow!("event not found: {id}")),
        1 => Ok(matches[0]),
        n => Err(anyhow::anyhow!(
            "ambiguous event ID prefix '{id}' matches {n} events"
        )),
    }
}

/// Extract PID from any EventData variant.
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

/// Case-insensitive category match.
fn category_matches(category: &EventCategory, filter: &str) -> bool {
    category_short(category).eq_ignore_ascii_case(filter)
}

/// Short display string for EventCategory.
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

/// Display string for EventSource.
fn source_display(source: &crate::events::EventSource) -> String {
    match source {
        crate::events::EventSource::Etw { provider } => format!("ETW / {provider}"),
        crate::events::EventSource::Sysmon { event_id } => format!("Sysmon / event {event_id}"),
        crate::events::EventSource::EvasionDetector => "EvasionDetector".into(),
        crate::events::EventSource::Sensor => "Sensor".into(),
    }
}

/// One-line summary of an EventData variant for timeline display.
fn event_summary(data: &EventData) -> String {
    match data {
        EventData::ProcessCreate {
            pid,
            image_path,
            command_line,
            ..
        } => {
            let cmd = truncate(command_line, 80);
            format!("ProcessCreate     pid:{pid} {image_path} {cmd}")
        }
        EventData::ProcessTerminate {
            pid, image_path, ..
        } => {
            format!("ProcessTerminate  pid:{pid} {image_path}")
        }
        EventData::FileCreate {
            pid,
            path,
            operation,
            ..
        } => {
            format!("FileCreate        pid:{pid} {operation:?} {path}")
        }
        EventData::FileDelete { pid, path, .. } => {
            format!("FileDelete        pid:{pid} {path}")
        }
        EventData::NetworkConnect {
            pid,
            protocol,
            dst_addr,
            dst_port,
            ..
        } => {
            format!("NetworkConnect    pid:{pid} {protocol} -> {dst_addr}:{dst_port}")
        }
        EventData::RegistryEvent {
            pid,
            operation,
            key,
            ..
        } => {
            let k = truncate(key, 60);
            format!("RegistryEvent     pid:{pid} {operation:?} {k}")
        }
        EventData::ImageLoad {
            pid,
            image_name,
            signed,
            ..
        } => {
            let sig = if *signed { "signed" } else { "unsigned" };
            format!("ImageLoad         pid:{pid} {image_name} ({sig})")
        }
        EventData::DnsQuery {
            pid,
            query_name,
            query_type,
            ..
        } => {
            format!("DnsQuery          pid:{pid} {query_name} ({query_type})")
        }
        EventData::ScriptBlock {
            pid,
            script_engine,
            script_path,
            ..
        } => {
            let path_suffix = script_path
                .as_deref()
                .map(|p| format!(" {p}"))
                .unwrap_or_default();
            format!("ScriptBlock       pid:{pid} {script_engine}{path_suffix}")
        }
        EventData::AmsiScan {
            pid,
            app_name,
            content_name,
            scan_result_name,
            ..
        } => {
            let result = if scan_result_name.is_empty() {
                "unknown"
            } else {
                scan_result_name.as_str()
            };
            format!("AmsiScan          pid:{pid} {app_name} [{result}] {content_name}")
        }
        EventData::EvasionDetected {
            technique,
            pid,
            details,
            ..
        } => {
            let p = pid.map(|p| format!("pid:{p} ")).unwrap_or_default();
            let d = truncate(details, 60);
            format!("EvasionDetected   {p}{technique:?} {d}")
        }
        EventData::CreateRemoteThread {
            source_pid,
            target_pid,
            ..
        } => {
            format!("CreateRemoteThread {source_pid} -> {target_pid}")
        }
        EventData::ProcessAccess {
            source_pid,
            target_pid,
            granted_access,
            ..
        } => {
            format!("ProcessAccess     {source_pid} -> {target_pid} (0x{granted_access:X})")
        }
        EventData::PipeEvent {
            pid,
            pipe_name,
            operation,
            ..
        } => {
            format!("PipeEvent         pid:{pid} {operation:?} {pipe_name}")
        }
        EventData::SensorHealth {
            uptime_secs,
            events_total,
            ..
        } => {
            format!("SensorHealth      uptime:{uptime_secs}s events:{events_total}")
        }
    }
}

/// Collect ScriptBlock + AmsiScan events correlated with the target,
/// within the time window. Used by both human-readable and JSON explain.
fn build_script_activity(
    target: &ThreatEvent,
    events: &[ThreatEvent],
    window_mins: u64,
) -> Vec<ThreatEvent> {
    if !is_script_related(&target.data) {
        return vec![];
    }
    let process_key =
        target.process_context.as_ref().map(|c| c.process_key.as_str());
    let target_pid = target.data.acting_pid();
    let window = chrono::Duration::minutes(window_mins as i64);
    let t_start = target.timestamp - window;
    let t_end = target.timestamp + window;

    let mut result: Vec<ThreatEvent> = events
        .iter()
        .filter(|e| {
            if !is_script_or_amsi(&e.data) {
                return false;
            }
            if e.timestamp < t_start || e.timestamp > t_end {
                return false;
            }
            if let Some(key) = process_key {
                e.process_context
                    .as_ref()
                    .map(|c| c.process_key.as_str())
                    == Some(key)
            } else if let Some(pid) = target_pid {
                e.data.acting_pid() == Some(pid)
            } else {
                false
            }
        })
        .cloned()
        .collect();
    result.sort_by_key(|e| e.timestamp);
    result
}

/// True if the event is a script-related type that benefits from
/// Script / AMSI correlation display in explain output.
fn is_script_related(data: &EventData) -> bool {
    matches!(
        data,
        EventData::ScriptBlock { .. }
            | EventData::AmsiScan { .. }
            | EventData::EvasionDetected {
                technique: crate::events::EvasionTechnique::AmsiBypass,
                ..
            }
    )
}

/// True if the event is a ScriptBlock or AmsiScan.
fn is_script_or_amsi(data: &EventData) -> bool {
    matches!(
        data,
        EventData::ScriptBlock { .. } | EventData::AmsiScan { .. }
    )
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    // Find the last char boundary at or before `max` to avoid panicking
    // on multibyte UTF-8 sequences (CJK paths, script content, etc.).
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
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

    /// Write events as JSONL to a temp file, return the path.
    fn write_events(dir: &TempDir, events: &[ThreatEvent]) -> PathBuf {
        let path = dir.path().join("events.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        for event in events {
            let json = serde_json::to_string(event).unwrap();
            writeln!(f, "{json}").unwrap();
        }
        path
    }

    fn make_process_create(pid: u32, key: &str) -> ThreatEvent {
        let mut evt = ThreatEvent::new(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Windows-Kernel-Process".into(),
            },
            EventCategory::Process,
            Severity::Info,
            EventData::ProcessCreate {
                pid,
                ppid: 1,
                image_path: "cmd.exe".into(),
                command_line: "cmd.exe /c test".into(),
                user: String::new(),
                integrity_level: String::new(),
                hashes: None,
                create_time: Some(42),
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
            image_path: Some("cmd.exe".into()),
            command_line: Some("cmd.exe /c test".into()),
            user: None,
            integrity_level: None,
            ppid: Some(1),
        });
        evt
    }

    fn make_dns_event(pid: u32, key: &str) -> ThreatEvent {
        let mut evt = ThreatEvent::new(
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
        );
        evt.process_context = Some(ProcessContext {
            process_key: key.into(),
            image_path: Some("cmd.exe".into()),
            command_line: None,
            user: None,
            integrity_level: None,
            ppid: None,
        });
        evt
    }

    fn make_health_event() -> ThreatEvent {
        ThreatEvent::new(
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
        )
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
                evidence: vec!["test evidence".into()],
            },
        )
    }

    // ---- Query tests ---------------------------------------------------------

    #[test]
    fn query_filter_by_pid() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_network_event(200, "200:43"),
            make_network_event(100, "100:42"),
        ];
        let path = write_events(&dir, &events);

        let filter = QueryFilter {
            pid: Some(100),
            process_key: None,
            category: None,
            rule_id: None,
            source: None,
            severity: None,
            contains: None,
            from: None,
            to: None,
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 2);
    }

    #[test]
    fn query_filter_by_process_key() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_network_event(200, "200:43"),
        ];
        let path = write_events(&dir, &events);

        let filter = QueryFilter {
            pid: None,
            process_key: Some("200:43".into()),
            category: None,
            rule_id: None,
            source: None,
            severity: None,
            contains: None,
            from: None,
            to: None,
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn query_filter_by_category() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_dns_event(100, "100:42"),
            make_health_event(),
        ];
        let path = write_events(&dir, &events);

        let filter = QueryFilter {
            pid: None,
            process_key: None,
            category: Some("dns".into()), // case-insensitive
            rule_id: None,
            source: None,
            severity: None,
            contains: None,
            from: None,
            to: None,
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 1);
        assert!(matches!(matched[0].category, EventCategory::Dns));
    }

    #[test]
    fn query_filter_by_rule_id() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_detection_event(200, "TF-EVA-001"),
            make_detection_event(300, "TF-EVA-002"),
        ];
        let path = write_events(&dir, &events);

        let filter = QueryFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: Some("TF-EVA-001".into()),
            source: None,
            severity: None,
            contains: None,
            from: None,
            to: None,
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].rule.as_ref().unwrap().id, "TF-EVA-001");
    }

    #[test]
    fn query_filter_by_since() {
        let dir = TempDir::new().unwrap();

        let mut old_event = make_network_event(100, "100:42");
        old_event.timestamp = "2026-01-01T00:00:00Z".parse().unwrap();

        let mut new_event = make_network_event(200, "200:43");
        new_event.timestamp = "2026-06-01T00:00:00Z".parse().unwrap();

        let path = write_events(&dir, &[old_event, new_event]);

        let filter = QueryFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source: None,
            severity: None,
            contains: None,
            from: Some("2026-03-01T00:00:00Z".parse().unwrap()),
            to: None,
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn query_combined_filters() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_dns_event(100, "100:42"),
            make_network_event(200, "200:43"),
        ];
        let path = write_events(&dir, &events);

        // pid=100 AND category=Network
        let filter = QueryFilter {
            pid: Some(100),
            process_key: None,
            category: Some("Network".into()),
            rule_id: None,
            source: None,
            severity: None,
            contains: None,
            from: None,
            to: None,
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn query_limit_applied() {
        let dir = TempDir::new().unwrap();
        let events: Vec<_> = (0..10)
            .map(|i| make_network_event(100 + i, &format!("{}:42", 100 + i)))
            .collect();
        let path = write_events(&dir, &events);

        let filter = QueryFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source: None,
            severity: None,
            contains: None,
            from: None,
            to: None,
        };

        let mut count = 0;
        for_each_event(&path, |event| {
            if count >= 3 {
                return false;
            }
            if filter.matches(&event) {
                count += 1;
            }
            true
        })
        .unwrap();

        assert_eq!(count, 3);
    }

    // ---- Explain tests -------------------------------------------------------

    #[test]
    fn find_event_exact_match() {
        let events = vec![make_network_event(100, "100:42")];
        let id = events[0].id.to_string();
        let found = find_event(&events, &id).unwrap();
        assert_eq!(found.id, events[0].id);
    }

    #[test]
    fn find_event_prefix_match() {
        let events = vec![make_network_event(100, "100:42")];
        let id = events[0].id.to_string();
        let prefix = &id[..8]; // first 8 chars of UUID
        let found = find_event(&events, prefix).unwrap();
        assert_eq!(found.id, events[0].id);
    }

    #[test]
    fn find_event_not_found() {
        let events = vec![make_network_event(100, "100:42")];
        let result = find_event(&events, "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn explain_builds_timeline() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";
        let mut events = vec![
            make_process_create(100, key),
            make_network_event(100, key),
            make_dns_event(100, key),
            make_network_event(200, "200:99"), // different process
        ];

        // Stagger timestamps slightly
        events[0].timestamp = "2026-03-13T10:00:00Z".parse().unwrap();
        events[1].timestamp = "2026-03-13T10:00:01Z".parse().unwrap();
        events[2].timestamp = "2026-03-13T10:00:02Z".parse().unwrap();
        events[3].timestamp = "2026-03-13T10:00:03Z".parse().unwrap();

        let path = write_events(&dir, &events);

        // Load and find
        let all = read_all_events(&path).unwrap();
        let target = find_event(&all, &events[1].id.to_string()).unwrap();

        assert_eq!(target.process_context.as_ref().unwrap().process_key, key);

        // Check that the timeline includes only events with the same key
        let window = chrono::Duration::minutes(5);
        let t_start = target.timestamp - window;
        let t_end = target.timestamp + window;

        let related: Vec<_> = all
            .iter()
            .filter(|e| {
                e.process_context.as_ref().map(|c| c.process_key.as_str()) == Some(key)
                    && e.timestamp >= t_start
                    && e.timestamp <= t_end
            })
            .collect();

        assert_eq!(related.len(), 3); // ProcessCreate + 2 activity events (same key)
    }

    // ---- Bundle tests --------------------------------------------------------

    #[test]
    fn bundle_creates_valid_json() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";
        let events = vec![
            make_process_create(100, key),
            make_network_event(100, key),
            make_dns_event(100, key),
        ];
        let path = write_events(&dir, &events);
        let output_path = dir.path().join("bundle.json");

        let event_id = events[1].id.to_string();
        run_bundle(&path, &event_id, 5, Some(&output_path), false).unwrap();

        let content = std::fs::read_to_string(&output_path).unwrap();
        let bundle: EvidenceBundle = serde_json::from_str(&content).unwrap();

        assert_eq!(bundle.bundle_version, 1);
        assert_eq!(bundle.target_event_id, event_id);
        assert_eq!(bundle.process_key.as_deref(), Some(key));
        assert_eq!(bundle.event_count, 3); // target + 2 related
        assert_eq!(bundle.related_events.len(), 2);
    }

    #[test]
    fn bundle_excludes_different_process_key() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_network_event(200, "200:99"), // different key
        ];
        let path = write_events(&dir, &events);
        let output_path = dir.path().join("bundle.json");

        let event_id = events[0].id.to_string();
        run_bundle(&path, &event_id, 5, Some(&output_path), false).unwrap();

        let content = std::fs::read_to_string(&output_path).unwrap();
        let bundle: EvidenceBundle = serde_json::from_str(&content).unwrap();

        assert_eq!(bundle.event_count, 1); // only the target
        assert!(bundle.related_events.is_empty());
    }

    // ---- Helper tests --------------------------------------------------------

    #[test]
    fn parse_datetime_valid() {
        let dt = parse_datetime("2026-03-13T10:00:00Z").unwrap();
        assert_eq!(chrono::Datelike::year(&dt), 2026);
    }

    #[test]
    fn parse_datetime_invalid() {
        assert!(parse_datetime("not-a-date").is_err());
    }

    #[test]
    fn category_match_case_insensitive() {
        assert!(category_matches(&EventCategory::Network, "network"));
        assert!(category_matches(&EventCategory::Network, "Network"));
        assert!(category_matches(&EventCategory::Network, "NETWORK"));
        assert!(!category_matches(&EventCategory::Network, "Process"));
    }

    #[test]
    fn event_summary_covers_all_variants() {
        // Smoke test — just ensure event_summary doesn't panic
        let summaries = vec![
            event_summary(&EventData::ProcessCreate {
                pid: 1,
                ppid: 0,
                image_path: "test.exe".into(),
                command_line: "test".into(),
                user: String::new(),
                integrity_level: String::new(),
                hashes: None,
                create_time: None,
            }),
            event_summary(&EventData::ProcessTerminate {
                pid: 1,
                image_path: "test.exe".into(),
                create_time: None,
            }),
            event_summary(&EventData::NetworkConnect {
                pid: 1,
                image_path: String::new(),
                protocol: "TCP".into(),
                src_addr: "0.0.0.0".into(),
                src_port: 0,
                dst_addr: "0.0.0.0".into(),
                dst_port: 80,
                direction: NetworkDirection::Outbound,
            }),
            event_summary(&EventData::DnsQuery {
                pid: 1,
                query_name: "example.com".into(),
                query_type: "A".into(),
                response: None,
            }),
            event_summary(&EventData::SensorHealth {
                uptime_secs: 60,
                events_total: 100,
                events_dropped: 0,
                collectors: vec![],
                sink: None,
            }),
        ];

        for s in &summaries {
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn empty_jsonl_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.jsonl");
        std::fs::write(&path, "").unwrap();

        let events = read_all_events(&path).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn malformed_lines_skipped() {
        let dir = TempDir::new().unwrap();
        let event = make_network_event(100, "100:42");
        let json = serde_json::to_string(&event).unwrap();

        let path = dir.path().join("mixed.jsonl");
        std::fs::write(&path, format!("not json\n{json}\nalso bad\n")).unwrap();

        let events = read_all_events(&path).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn missing_file_errors() {
        let result = read_all_events(Path::new("/nonexistent/file.jsonl"));
        assert!(result.is_err());
    }

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello world", 5), "hello");
    }

    #[test]
    fn truncate_multibyte_cjk() {
        // Each CJK character is 3 bytes in UTF-8.
        // "日本語パス" = 15 bytes. Truncating at 7 bytes must not
        // split a 3-byte char — should back up to byte 6.
        let s = "日本語パス";
        assert_eq!(s.len(), 15);
        let result = truncate(s, 7);
        assert_eq!(result, "日本"); // 6 bytes, not 7
    }

    #[test]
    fn truncate_multibyte_boundary_exact() {
        // Truncate exactly at a char boundary (6 bytes = 2 CJK chars)
        let s = "日本語パス";
        let result = truncate(s, 6);
        assert_eq!(result, "日本");
    }

    #[test]
    fn truncate_emoji() {
        // 🔥 is 4 bytes. Truncating "🔥abc" at 2 must not split the emoji.
        let s = "🔥abc";
        let result = truncate(s, 2);
        assert_eq!(result, ""); // no complete char fits in 2 bytes from a 4-byte start
    }

    #[test]
    fn explain_timeline_is_chronological() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";

        // Create events out of timestamp order in the file
        let mut evt_c = make_dns_event(100, key);
        evt_c.timestamp = "2026-03-13T10:00:03Z".parse().unwrap();

        let mut evt_a = make_process_create(100, key);
        evt_a.timestamp = "2026-03-13T10:00:01Z".parse().unwrap();

        let mut evt_b = make_network_event(100, key);
        evt_b.timestamp = "2026-03-13T10:00:02Z".parse().unwrap();

        // Write in non-chronological order: C, A, B
        let path = write_events(&dir, &[evt_c.clone(), evt_a.clone(), evt_b.clone()]);

        let all = read_all_events(&path).unwrap();
        let target = find_event(&all, &evt_b.id.to_string()).unwrap();

        let window = chrono::Duration::minutes(5);
        let t_start = target.timestamp - window;
        let t_end = target.timestamp + window;

        let mut related: Vec<&ThreatEvent> = all
            .iter()
            .filter(|e| {
                e.process_context.as_ref().map(|c| c.process_key.as_str()) == Some(key)
                    && e.timestamp >= t_start
                    && e.timestamp <= t_end
            })
            .collect();
        related.sort_by_key(|e| e.timestamp);

        // Must be in chronological order: A, B, C
        assert_eq!(related.len(), 3);
        assert_eq!(related[0].id, evt_a.id);
        assert_eq!(related[1].id, evt_b.id);
        assert_eq!(related[2].id, evt_c.id);
    }

    #[test]
    fn bundle_related_events_are_chronological() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";

        let mut evt_b = make_network_event(100, key);
        evt_b.timestamp = "2026-03-13T10:00:02Z".parse().unwrap();

        let mut evt_a = make_process_create(100, key);
        evt_a.timestamp = "2026-03-13T10:00:01Z".parse().unwrap();

        let mut evt_c = make_dns_event(100, key);
        evt_c.timestamp = "2026-03-13T10:00:03Z".parse().unwrap();

        // Write out of order: B, A, C — target is B
        let path = write_events(&dir, &[evt_b.clone(), evt_a.clone(), evt_c.clone()]);
        let output_path = dir.path().join("bundle.json");

        run_bundle(&path, &evt_b.id.to_string(), 5, Some(&output_path), false).unwrap();

        let content = std::fs::read_to_string(&output_path).unwrap();
        let bundle: EvidenceBundle = serde_json::from_str(&content).unwrap();

        // related_events (excluding target) must be sorted: A then C
        assert_eq!(bundle.related_events.len(), 2);
        assert_eq!(bundle.related_events[0].id, evt_a.id);
        assert_eq!(bundle.related_events[1].id, evt_c.id);
    }

    // ---- Script / AMSI correlation tests ------------------------------------

    fn make_script_block(pid: u32, key: &str, content: &str) -> ThreatEvent {
        let mut evt = ThreatEvent::new(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Windows-PowerShell".into(),
            },
            EventCategory::Script,
            Severity::Medium,
            EventData::ScriptBlock {
                pid,
                script_engine: "PowerShell".into(),
                content: content.into(),
                script_path: Some(r"C:\Users\test\malware.ps1".into()),
                script_block_id: Some("abc-123".into()),
            },
        );
        evt.process_context = Some(ProcessContext {
            process_key: key.into(),
            image_path: Some("powershell.exe".into()),
            command_line: Some("powershell.exe -File malware.ps1".into()),
            user: None,
            integrity_level: None,
            ppid: Some(1),
        });
        evt
    }

    fn make_amsi_scan(
        pid: u32,
        key: &str,
        content_name: &str,
        scan_result: u32,
    ) -> ThreatEvent {
        let mut evt = ThreatEvent::new(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Antimalware-Scan-Interface".into(),
            },
            EventCategory::Script,
            if scan_result >= 32768 {
                Severity::High
            } else {
                Severity::Info
            },
            EventData::AmsiScan {
                pid,
                app_name: "PowerShell".into(),
                content_name: content_name.into(),
                content_size: 256,
                scan_result,
                scan_result_name: crate::events::amsi_result_name(scan_result).to_string(),
            },
        );
        evt.process_context = Some(ProcessContext {
            process_key: key.into(),
            image_path: Some("powershell.exe".into()),
            command_line: None,
            user: None,
            integrity_level: None,
            ppid: None,
        });
        evt
    }

    #[test]
    fn is_script_related_matches_script_events() {
        assert!(is_script_related(&EventData::ScriptBlock {
            pid: 1,
            script_engine: "PowerShell".into(),
            content: String::new(),
            script_path: None,
            script_block_id: None,
        }));
        assert!(is_script_related(&EventData::AmsiScan {
            pid: 1,
            app_name: "PowerShell".into(),
            content_name: String::new(),
            content_size: 0,
            scan_result: 0,
            scan_result_name: String::new(),
        }));
        assert!(is_script_related(&EventData::EvasionDetected {
            technique: EvasionTechnique::AmsiBypass,
            pid: Some(1),
            process_name: None,
            details: String::new(),
        }));
        // Non-script events should not match
        assert!(!is_script_related(&EventData::DnsQuery {
            pid: 1,
            query_name: String::new(),
            query_type: String::new(),
            response: None,
        }));
        // Non-AMSI evasion should not match
        assert!(!is_script_related(&EventData::EvasionDetected {
            technique: EvasionTechnique::EtwPatching,
            pid: Some(1),
            process_name: None,
            details: String::new(),
        }));
    }

    #[test]
    fn explain_script_amsi_correlation() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";

        let mut evt_script = make_script_block(100, key, "Invoke-Mimikatz");
        evt_script.timestamp = "2026-03-13T10:00:01Z".parse().unwrap();

        let mut evt_amsi_clean = make_amsi_scan(100, key, "prompt", 0);
        evt_amsi_clean.timestamp = "2026-03-13T10:00:00Z".parse().unwrap();

        let mut evt_amsi_detected =
            make_amsi_scan(100, key, "malware.ps1", 32768);
        evt_amsi_detected.timestamp = "2026-03-13T10:00:02Z".parse().unwrap();

        // Unrelated event from a different process
        let mut evt_other = make_network_event(200, "200:99");
        evt_other.timestamp = "2026-03-13T10:00:01Z".parse().unwrap();

        let path = write_events(
            &dir,
            &[
                evt_amsi_clean.clone(),
                evt_script.clone(),
                evt_amsi_detected.clone(),
                evt_other,
            ],
        );

        // When we explain a ScriptBlock event, the script/AMSI section
        // should include the 2 AMSI scans + 1 ScriptBlock from the same
        // process within the time window.
        let all = read_all_events(&path).unwrap();
        let target = find_event(&all, &evt_script.id.to_string()).unwrap();

        assert!(is_script_related(&target.data));

        let pk = target
            .process_context
            .as_ref()
            .map(|c| c.process_key.as_str());
        let window = chrono::Duration::minutes(5);
        let t_start = target.timestamp - window;
        let t_end = target.timestamp + window;

        let script_events: Vec<&ThreatEvent> = all
            .iter()
            .filter(|e| {
                is_script_or_amsi(&e.data)
                    && e.timestamp >= t_start
                    && e.timestamp <= t_end
                    && e.process_context
                        .as_ref()
                        .map(|c| c.process_key.as_str())
                        == pk
            })
            .collect();

        assert_eq!(script_events.len(), 3);

        // Count breakdowns
        let amsi_count = script_events
            .iter()
            .filter(|e| matches!(e.data, EventData::AmsiScan { .. }))
            .count();
        let detected_count = script_events
            .iter()
            .filter(|e| matches!(&e.data, EventData::AmsiScan { scan_result, .. } if *scan_result >= 32768))
            .count();

        assert_eq!(amsi_count, 2);
        assert_eq!(detected_count, 1);
    }

    #[test]
    fn explain_script_correlation_respects_window() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";

        // Target event at 10:00:00
        let mut evt_script = make_script_block(100, key, "Get-Process");
        evt_script.timestamp = "2026-03-13T10:00:00Z".parse().unwrap();

        // AMSI scan within 5-min window (10:04:00)
        let mut evt_amsi_near = make_amsi_scan(100, key, "near.ps1", 0);
        evt_amsi_near.timestamp = "2026-03-13T10:04:00Z".parse().unwrap();

        // AMSI scan outside 5-min window (11:00:00 — 1 hour later)
        let mut evt_amsi_stale = make_amsi_scan(100, key, "stale.ps1", 32768);
        evt_amsi_stale.timestamp = "2026-03-13T11:00:00Z".parse().unwrap();

        let path = write_events(
            &dir,
            &[evt_script.clone(), evt_amsi_near.clone(), evt_amsi_stale.clone()],
        );

        let all = read_all_events(&path).unwrap();
        let target = find_event(&all, &evt_script.id.to_string()).unwrap();
        let pk = target
            .process_context
            .as_ref()
            .map(|c| c.process_key.as_str());

        // With a 5-min window, the stale event should be excluded
        let window = chrono::Duration::minutes(5);
        let t_start = target.timestamp - window;
        let t_end = target.timestamp + window;

        let script_events: Vec<&ThreatEvent> = all
            .iter()
            .filter(|e| {
                is_script_or_amsi(&e.data)
                    && e.timestamp >= t_start
                    && e.timestamp <= t_end
                    && e.process_context
                        .as_ref()
                        .map(|c| c.process_key.as_str())
                        == pk
            })
            .collect();

        // Only the target ScriptBlock + the near AMSI scan; stale excluded
        assert_eq!(script_events.len(), 2);
    }

    #[test]
    fn amsi_scan_result_name_in_summary() {
        let summary = event_summary(&EventData::AmsiScan {
            pid: 100,
            app_name: "PowerShell".into(),
            content_name: "malware.ps1".into(),
            content_size: 256,
            scan_result: 32768,
            scan_result_name: "AMSI_RESULT_DETECTED".into(),
        });
        assert!(summary.contains("AMSI_RESULT_DETECTED"));
        assert!(summary.contains("malware.ps1"));
    }

    #[test]
    fn script_block_summary_includes_path() {
        let summary = event_summary(&EventData::ScriptBlock {
            pid: 100,
            script_engine: "PowerShell".into(),
            content: "Get-Process".into(),
            script_path: Some(r"C:\test.ps1".into()),
            script_block_id: Some("abc".into()),
        });
        assert!(summary.contains(r"C:\test.ps1"));
    }

    #[test]
    fn script_block_summary_without_path() {
        let summary = event_summary(&EventData::ScriptBlock {
            pid: 100,
            script_engine: "PowerShell".into(),
            content: "Get-Process".into(),
            script_path: None,
            script_block_id: None,
        });
        assert!(summary.contains("PowerShell"));
        assert!(!summary.contains("null"));
    }

    #[test]
    fn amsi_scan_roundtrip_with_new_fields() {
        let evt = make_amsi_scan(100, "100:42", "test.ps1", 32768);
        let json = serde_json::to_string(&evt).unwrap();
        let rt: ThreatEvent = serde_json::from_str(&json).unwrap();
        match rt.data {
            EventData::AmsiScan {
                scan_result_name,
                scan_result,
                ..
            } => {
                assert_eq!(scan_result, 32768);
                assert_eq!(scan_result_name, "AMSI_RESULT_DETECTED");
            }
            _ => panic!("expected AmsiScan"),
        }
    }

    #[test]
    fn script_block_roundtrip_with_new_fields() {
        let evt = make_script_block(100, "100:42", "test content");
        let json = serde_json::to_string(&evt).unwrap();
        let rt: ThreatEvent = serde_json::from_str(&json).unwrap();
        match rt.data {
            EventData::ScriptBlock {
                script_path,
                script_block_id,
                ..
            } => {
                assert_eq!(script_path.as_deref(), Some(r"C:\Users\test\malware.ps1"));
                assert_eq!(script_block_id.as_deref(), Some("abc-123"));
            }
            _ => panic!("expected ScriptBlock"),
        }
    }

    #[test]
    fn old_amsi_json_without_result_name_deserializes() {
        // Simulate JSONL from before scan_result_name was added
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000000",
            "timestamp": "2026-03-13T10:00:00Z",
            "hostname": "TEST",
            "agent_id": "00000000-0000-0000-0000-000000000000",
            "sensor_version": "0.2.0",
            "source": {"Etw":{"provider":"AMSI"}},
            "category": "Script",
            "severity": "High",
            "data": {
                "type": "AmsiScan",
                "pid": 100,
                "app_name": "PowerShell",
                "content_name": "test.ps1",
                "content_size": 256,
                "scan_result": 32768
            }
        }"#;
        let evt: ThreatEvent = serde_json::from_str(json).unwrap();
        match evt.data {
            EventData::AmsiScan {
                scan_result_name, ..
            } => {
                // Default empty string when field is missing
                assert_eq!(scan_result_name, "");
            }
            _ => panic!("expected AmsiScan"),
        }
    }

    #[test]
    fn old_scriptblock_json_without_new_fields_deserializes() {
        // Simulate JSONL from before script_path/script_block_id were added
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000000",
            "timestamp": "2026-03-13T10:00:00Z",
            "hostname": "TEST",
            "agent_id": "00000000-0000-0000-0000-000000000000",
            "sensor_version": "0.2.0",
            "source": {"Etw":{"provider":"PowerShell"}},
            "category": "Script",
            "severity": "Medium",
            "data": {
                "type": "ScriptBlock",
                "pid": 100,
                "script_engine": "PowerShell",
                "content": "Get-Process"
            }
        }"#;
        let evt: ThreatEvent = serde_json::from_str(json).unwrap();
        match evt.data {
            EventData::ScriptBlock {
                script_path,
                script_block_id,
                ..
            } => {
                assert!(script_path.is_none());
                assert!(script_block_id.is_none());
            }
            _ => panic!("expected ScriptBlock"),
        }
    }

    // ---- Zip bundle tests ---------------------------------------------------

    #[test]
    fn bundle_zip_creates_valid_archive() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";
        let events = vec![
            make_process_create(100, key),
            make_network_event(100, key),
            make_dns_event(100, key),
        ];
        let path = write_events(&dir, &events);
        let zip_path = dir.path().join("bundle.zip");

        let event_id = events[1].id.to_string();
        run_bundle(&path, &event_id, 5, Some(&zip_path), false).unwrap();

        // Open and verify the zip
        let file = std::fs::File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let expected_files = [
            "manifest.json",
            "target_event.json",
            "related_events.jsonl",
            "bundle.json",
        ];
        assert_eq!(archive.len(), expected_files.len());
        for name in &expected_files {
            assert!(
                archive.by_name(name).is_ok(),
                "missing zip entry: {name}"
            );
        }
    }

    #[test]
    fn bundle_zip_manifest_is_valid() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";
        let events = vec![
            make_process_create(100, key),
            make_network_event(100, key),
        ];
        let path = write_events(&dir, &events);
        let zip_path = dir.path().join("out.zip");

        let event_id = events[1].id.to_string();
        run_bundle(&path, &event_id, 5, Some(&zip_path), false).unwrap();

        let file = std::fs::File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let manifest_entry = archive.by_name("manifest.json").unwrap();
        let manifest: serde_json::Value =
            serde_json::from_reader(manifest_entry).unwrap();

        assert_eq!(manifest["format"], "threatfalcon-evidence-bundle");
        assert_eq!(manifest["format_version"], 1);
        assert_eq!(manifest["target_event_id"], event_id);
        assert_eq!(manifest["process_key"], key);
        assert_eq!(manifest["event_count"], 2); // target + 1 related
        assert_eq!(manifest["files"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn bundle_zip_target_event_matches() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";
        let events = vec![make_network_event(100, key)];
        let path = write_events(&dir, &events);
        let zip_path = dir.path().join("target.zip");

        let event_id = events[0].id.to_string();
        run_bundle(&path, &event_id, 5, Some(&zip_path), false).unwrap();

        let file = std::fs::File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let target_entry = archive.by_name("target_event.json").unwrap();
        let target: ThreatEvent =
            serde_json::from_reader(target_entry).unwrap();

        assert_eq!(target.id.to_string(), event_id);
    }

    #[test]
    fn bundle_zip_related_events_as_jsonl() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";
        let events = vec![
            make_process_create(100, key),
            make_network_event(100, key),
            make_dns_event(100, key),
        ];
        let path = write_events(&dir, &events);
        let zip_path = dir.path().join("related.zip");

        // Target is events[1]; related should be events[0] and events[2]
        let event_id = events[1].id.to_string();
        run_bundle(&path, &event_id, 5, Some(&zip_path), false).unwrap();

        let file = std::fs::File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let related_entry = archive.by_name("related_events.jsonl").unwrap();
        let reader = std::io::BufReader::new(related_entry);
        let lines: Vec<String> = reader
            .lines()
            .map(|l| l.unwrap())
            .filter(|l| !l.is_empty())
            .collect();

        assert_eq!(lines.len(), 2);
        // Each line should be valid JSON
        for line in &lines {
            let _: ThreatEvent = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn bundle_zip_bundle_json_matches_standalone() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";
        let events = vec![
            make_process_create(100, key),
            make_network_event(100, key),
        ];
        let path = write_events(&dir, &events);
        let zip_path = dir.path().join("full.zip");
        let json_path = dir.path().join("full.json");

        let event_id = events[1].id.to_string();
        run_bundle(&path, &event_id, 5, Some(&json_path), false).unwrap();
        run_bundle(&path, &event_id, 5, Some(&zip_path), false).unwrap();

        // Read bundle.json from the zip
        let file = std::fs::File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let zip_entry = archive.by_name("bundle.json").unwrap();
        let zip_bundle: EvidenceBundle =
            serde_json::from_reader(zip_entry).unwrap();

        // Read the standalone JSON
        let json_content = std::fs::read_to_string(&json_path).unwrap();
        let json_bundle: EvidenceBundle =
            serde_json::from_str(&json_content).unwrap();

        // Core fields should match
        assert_eq!(
            zip_bundle.target_event_id,
            json_bundle.target_event_id
        );
        assert_eq!(zip_bundle.event_count, json_bundle.event_count);
        assert_eq!(zip_bundle.process_key, json_bundle.process_key);
        assert_eq!(
            zip_bundle.related_events.len(),
            json_bundle.related_events.len()
        );
    }

    #[test]
    fn bundle_non_zip_extension_stays_json() {
        let dir = TempDir::new().unwrap();
        let events = vec![make_network_event(100, "100:42")];
        let path = write_events(&dir, &events);
        let out_path = dir.path().join("bundle.json");

        let event_id = events[0].id.to_string();
        run_bundle(&path, &event_id, 5, Some(&out_path), false).unwrap();

        // Should be plain JSON, not a zip
        let content = std::fs::read_to_string(&out_path).unwrap();
        let _: EvidenceBundle = serde_json::from_str(&content).unwrap();
    }

    #[test]
    fn is_zip_extension_variants() {
        assert!(is_zip_extension(Path::new("bundle.zip")));
        assert!(is_zip_extension(Path::new("bundle.ZIP")));
        assert!(is_zip_extension(Path::new("/tmp/out.Zip")));
        assert!(!is_zip_extension(Path::new("bundle.json")));
        assert!(!is_zip_extension(Path::new("bundle")));
        assert!(!is_zip_extension(Path::new("zipfile.tar")));
    }

    // ---- New filter tests ---------------------------------------------------

    #[test]
    fn query_filter_by_source_etw() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),      // ETW
            make_detection_event(200, "TF-EVA-001"), // EvasionDetector
        ];
        let path = write_events(&dir, &events);

        let filter = QueryFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source: Some("etw".into()),
            severity: None,
            contains: None,
            from: None,
            to: None,
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 1);
        assert!(matches!(
            matched[0].source,
            crate::events::EventSource::Etw { .. }
        ));
    }

    #[test]
    fn query_filter_by_source_evasion() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_detection_event(200, "TF-EVA-001"),
        ];
        let path = write_events(&dir, &events);

        let filter = QueryFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source: Some("evasion".into()),
            severity: None,
            contains: None,
            from: None,
            to: None,
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 1);
        assert!(matches!(
            matched[0].source,
            crate::events::EventSource::EvasionDetector
        ));
    }

    #[test]
    fn query_filter_by_source_provider_name() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"), // Kernel-Network
            make_dns_event(100, "100:42"),      // DNS-Client
        ];
        let path = write_events(&dir, &events);

        let filter = QueryFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source: Some("DNS-Client".into()),
            severity: None,
            contains: None,
            from: None,
            to: None,
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 1);
        assert!(matches!(matched[0].category, EventCategory::Dns));
    }

    #[test]
    fn query_filter_by_severity() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"), // Info
            make_detection_event(200, "TF-EVA-001"), // High
        ];
        let path = write_events(&dir, &events);

        let filter = QueryFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source: None,
            severity: Some(crate::events::Severity::High),
            contains: None,
            from: None,
            to: None,
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 1);
        assert!(matched[0].severity >= crate::events::Severity::High);
    }

    #[test]
    fn query_filter_by_contains() {
        let dir = TempDir::new().unwrap();
        let events = vec![
            make_network_event(100, "100:42"),
            make_dns_event(100, "100:42"), // contains "example.com"
        ];
        let path = write_events(&dir, &events);

        let filter = QueryFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source: None,
            severity: None,
            contains: Some("example.com".into()),
            from: None,
            to: None,
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn query_filter_contains_case_insensitive() {
        let dir = TempDir::new().unwrap();
        let events = vec![make_dns_event(100, "100:42")]; // "example.com"
        let path = write_events(&dir, &events);

        let filter = QueryFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source: None,
            severity: None,
            contains: Some("EXAMPLE.COM".into()),
            from: None,
            to: None,
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn contains_matches_windows_path_with_backslashes() {
        // The JSON serializer escapes backslashes (C:\Temp → C:\\Temp).
        // A user searching for "C:\Temp\evil.exe" should still match.
        let mut evt = make_process_create(100, "100:42");
        evt.data = EventData::ProcessCreate {
            pid: 100,
            ppid: 1,
            image_path: r"C:\Temp\evil.exe".into(),
            command_line: r"C:\Temp\evil.exe --payload".into(),
            user: String::new(),
            integrity_level: String::new(),
            hashes: None,
            create_time: Some(42),
        };
        assert!(
            event_contains(&evt, r"C:\Temp\evil.exe"),
            "natural Windows path should match JSON-escaped backslashes"
        );
        // Also verify the escaped form still matches
        assert!(
            event_contains(&evt, r"C:\\Temp\\evil.exe"),
            "escaped path should also match directly"
        );
    }

    #[test]
    fn query_filter_by_from_and_to() {
        let dir = TempDir::new().unwrap();

        let mut old = make_network_event(100, "100:42");
        old.timestamp = "2026-01-01T00:00:00Z".parse().unwrap();

        let mut mid = make_network_event(100, "100:42");
        mid.timestamp = "2026-06-01T00:00:00Z".parse().unwrap();

        let mut new = make_network_event(100, "100:42");
        new.timestamp = "2026-12-01T00:00:00Z".parse().unwrap();

        let path = write_events(&dir, &[old, mid, new]);

        let filter = QueryFilter {
            pid: None,
            process_key: None,
            category: None,
            rule_id: None,
            source: None,
            severity: None,
            contains: None,
            from: Some("2026-03-01T00:00:00Z".parse().unwrap()),
            to: Some("2026-09-01T00:00:00Z".parse().unwrap()),
        };

        let mut matched = Vec::new();
        for_each_event(&path, |event| {
            if filter.matches(&event) {
                matched.push(event);
            }
            true
        })
        .unwrap();

        assert_eq!(matched.len(), 1); // only mid
    }

    #[test]
    fn parse_severity_variants() {
        assert_eq!(
            parse_severity("info").unwrap(),
            crate::events::Severity::Info
        );
        assert_eq!(
            parse_severity("HIGH").unwrap(),
            crate::events::Severity::High
        );
        assert_eq!(
            parse_severity("crit").unwrap(),
            crate::events::Severity::Critical
        );
        assert_eq!(
            parse_severity("med").unwrap(),
            crate::events::Severity::Medium
        );
        assert!(parse_severity("bogus").is_err());
    }

    #[test]
    fn source_matches_variants() {
        use crate::events::EventSource;

        assert!(source_matches(
            &EventSource::Etw {
                provider: "Microsoft-Windows-Kernel-Network".into()
            },
            "etw"
        ));
        assert!(source_matches(
            &EventSource::Etw {
                provider: "Microsoft-Windows-DNS-Client".into()
            },
            "dns-client"
        ));
        assert!(!source_matches(
            &EventSource::Etw {
                provider: "Microsoft-Windows-Kernel-Network".into()
            },
            "sysmon"
        ));
        assert!(source_matches(&EventSource::EvasionDetector, "evasion"));
        assert!(source_matches(
            &EventSource::Sysmon { event_id: 1 },
            "sysmon"
        ));
        assert!(source_matches(&EventSource::Sensor, "sensor"));
    }

    #[test]
    fn explain_json_output() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";
        let events = vec![
            make_process_create(100, key),
            make_network_event(100, key),
        ];
        let path = write_events(&dir, &events);

        // Capture JSON output by calling run_explain with json=true
        // through run_bundle (we can't easily capture stdout, so we
        // verify the ExplainOutput struct serializes correctly)
        let all = read_all_events(&path).unwrap();
        let target = find_event(&all, &events[1].id.to_string()).unwrap();

        let output = ExplainOutput {
            target_event: target.clone(),
            window_minutes: 5,
            process_key: target
                .process_context
                .as_ref()
                .map(|c| c.process_key.clone()),
            timeline: all.clone(),
            script_amsi_activity: vec![],
            rule: target.rule.clone(),
        };

        let json = serde_json::to_string_pretty(&output).unwrap();
        assert!(json.contains("\"target_event\""));
        assert!(json.contains("\"timeline\""));
        assert!(json.contains("\"window_minutes\""));
        // script_amsi_activity should be omitted when empty
        assert!(!json.contains("\"script_amsi_activity\""));
    }

    #[test]
    fn bundle_manifest_has_time_range() {
        let dir = TempDir::new().unwrap();
        let key = "100:42";

        let mut evt_a = make_process_create(100, key);
        evt_a.timestamp = "2026-03-13T10:00:00Z".parse().unwrap();
        let mut evt_b = make_network_event(100, key);
        evt_b.timestamp = "2026-03-13T10:05:00Z".parse().unwrap();

        let path = write_events(&dir, &[evt_a, evt_b.clone()]);
        let zip_path = dir.path().join("range.zip");

        run_bundle(&path, &evt_b.id.to_string(), 10, Some(&zip_path), false).unwrap();

        let file = std::fs::File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let manifest_entry = archive.by_name("manifest.json").unwrap();
        let manifest: serde_json::Value =
            serde_json::from_reader(manifest_entry).unwrap();

        let time_range = &manifest["time_range"];
        assert!(time_range.is_object());
        assert!(time_range["earliest"].is_string());
        assert!(time_range["latest"].is_string());
    }
}
