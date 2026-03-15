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

    /// Show process tree (parent-child relationships) from ProcessCreate events
    Tree {
        /// Path to JSONL event file
        #[arg(long, value_name = "PATH")]
        input: PathBuf,

        /// Root process ID to display the tree for
        #[arg(long)]
        pid: u32,

        /// Select a specific process instance by process_key (disambiguates PID reuse)
        #[arg(long)]
        process_key: Option<String>,

        /// Show ancestors (parent chain) instead of descendants
        #[arg(long)]
        ancestors: bool,

        /// Output as structured JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// Inspect a PE file: headers, sections, imports, and exports
    Inspect {
        /// Path to PE file to inspect
        #[arg(long, value_name = "PATH")]
        file: PathBuf,

        /// Output as structured JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// Score processes by threat signals (detections, network, LOLBins, etc.)
    Score {
        /// Path to JSONL event file
        #[arg(long, value_name = "PATH")]
        input: PathBuf,

        /// Maximum number of processes to display (default: 20)
        #[arg(long, default_value = "20")]
        limit: usize,

        /// Output as structured JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// Run threat hunting rules against events
    Hunt {
        /// Path to JSONL event file
        #[arg(long, value_name = "PATH")]
        input: PathBuf,

        /// Run only a specific rule (e.g., "suspicious-parent", "lolbin", "unsigned-dll", "beaconing")
        #[arg(long)]
        rule: Option<String>,

        /// Maximum results per rule (default: 50)
        #[arg(long, default_value = "50")]
        limit: usize,

        /// Output as structured JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// Extract indicators of compromise (IPs, domains, hashes) from events
    Ioc {
        /// Path to JSONL event file
        #[arg(long, value_name = "PATH")]
        input: PathBuf,

        /// Show only IOCs of a specific type (ip, domain, hash)
        #[arg(long)]
        r#type: Option<String>,

        /// Maximum number of results per type (default: 50)
        #[arg(long, default_value = "50")]
        limit: usize,

        /// Output as structured JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// Monitor events in real time and alert on threat detections
    Alert {
        /// Path to JSONL event file
        #[arg(long, value_name = "PATH")]
        input: PathBuf,

        /// Score threshold to trigger a score-based alert (default: 40)
        #[arg(long, default_value = "40")]
        threshold: u32,

        /// Seconds to suppress duplicate alerts for the same process + rule (default: 300)
        #[arg(long, default_value = "300")]
        cooldown: u64,

        /// Output as structured JSONL instead of human-readable text
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

        Command::Tree {
            input,
            pid,
            process_key,
            ancestors,
            json,
        } => run_tree(&input, pid, process_key.as_deref(), ancestors, json),

        Command::Inspect { file, json } => run_inspect(&file, json),

        Command::Score { input, limit, json } => run_score(&input, limit, json),

        Command::Hunt {
            input,
            rule,
            limit,
            json,
        } => run_hunt(&input, rule.as_deref(), limit, json),

        Command::Ioc {
            input,
            r#type,
            limit,
            json,
        } => run_ioc(&input, r#type.as_deref(), limit, json),

        Command::Alert {
            input,
            threshold,
            cooldown,
            json,
        } => run_alert(&input, threshold, cooldown, json),

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
// Score
// ---------------------------------------------------------------------------

/// Point values for each signal type.
const SCORE_DETECTION: u32 = 40;
const SCORE_SUSPICIOUS_PARENT: u32 = 20;
const SCORE_LOLBIN: u32 = 20;
const SCORE_UNSIGNED_DLL: u32 = 5;
const SCORE_EXTERNAL_IP: u32 = 2;
const SCORE_DNS_QUERY: u32 = 1;

#[derive(Serialize)]
struct ScoreReport {
    total_events: u64,
    scored_processes: Vec<ScoredProcess>,
}

#[derive(Serialize)]
struct ScoredProcess {
    process_key: String,
    pid: u32,
    image: String,
    score: u32,
    breakdown: ScoreBreakdown,
}

#[derive(Serialize, Default)]
struct ScoreBreakdown {
    detections: u32,
    suspicious_parent: bool,
    lolbin: bool,
    unsigned_dlls: u32,
    external_ips: u32,
    dns_queries: u32,
}

impl ScoreBreakdown {
    fn total(&self) -> u32 {
        self.detections * SCORE_DETECTION
            + if self.suspicious_parent { SCORE_SUSPICIOUS_PARENT } else { 0 }
            + if self.lolbin { SCORE_LOLBIN } else { 0 }
            + self.unsigned_dlls * SCORE_UNSIGNED_DLL
            + self.external_ips * SCORE_EXTERNAL_IP
            + self.dns_queries * SCORE_DNS_QUERY
    }
}

fn run_score(input: &Path, limit: usize, json: bool) -> Result<()> {
    use std::collections::{HashMap, HashSet};

    struct ProcAcc {
        pid: u32,
        image: String,
        breakdown: ScoreBreakdown,
        unique_ips: HashSet<String>,
        unique_domains: HashSet<String>,
    }

    let mut total: u64 = 0;
    let mut acc_map: HashMap<String, ProcAcc> = HashMap::new();

    // Collect ProcessCreate events for parent lookup (sorted by timestamp).
    struct ProcCreate {
        pid: u32,
        ppid: u32,
        image_path: String,
        process_key: Option<String>,
        timestamp: DateTime<Utc>,
    }
    let mut proc_creates: Vec<ProcCreate> = Vec::new();

    for_each_event(input, |event| {
        total += 1;

        let event_key = event
            .process_context
            .as_ref()
            .map(|c| c.process_key.clone());

        match &event.data {
            EventData::ProcessCreate {
                pid,
                ppid,
                image_path,
                ..
            } => {
                let key = event_key.clone().unwrap_or_else(|| format!("pid:{pid}"));
                proc_creates.push(ProcCreate {
                    pid: *pid,
                    ppid: *ppid,
                    image_path: image_path.clone(),
                    process_key: event_key,
                    timestamp: event.timestamp,
                });
                let acc = acc_map.entry(key).or_insert_with(|| ProcAcc {
                    pid: *pid,
                    image: image_path.clone(),
                    breakdown: ScoreBreakdown::default(),
                    unique_ips: HashSet::new(),
                    unique_domains: HashSet::new(),
                });
                // LOLBin check
                let child_lower = basename(image_path).to_ascii_lowercase();
                if LOLBINS.iter().any(|l| child_lower == *l) {
                    acc.breakdown.lolbin = true;
                }
            }

            EventData::EvasionDetected { pid, process_name, .. } => {
                if event.rule.is_some() {
                    let pid_val = pid.unwrap_or(0);
                    let key = event_key
                        .clone()
                        .unwrap_or_else(|| format!("pid:{pid_val}"));
                    let acc = acc_map.entry(key).or_insert_with(|| ProcAcc {
                        pid: pid_val,
                        image: event
                            .process_context
                            .as_ref()
                            .and_then(|c| c.image_path.clone())
                            .or_else(|| process_name.clone())
                            .unwrap_or_default(),
                        breakdown: ScoreBreakdown::default(),
                        unique_ips: HashSet::new(),
                        unique_domains: HashSet::new(),
                    });
                    acc.breakdown.detections += 1;
                }
            }

            EventData::ImageLoad {
                pid,
                signed,
                ..
            } => {
                if !signed {
                    let key = event_key.unwrap_or_else(|| format!("pid:{pid}"));
                    let acc = acc_map.entry(key).or_insert_with(|| ProcAcc {
                        pid: *pid,
                        image: event
                            .process_context
                            .as_ref()
                            .and_then(|c| c.image_path.clone())
                            .unwrap_or_else(|| format!("PID {pid}")),
                        breakdown: ScoreBreakdown::default(),
                        unique_ips: HashSet::new(),
                        unique_domains: HashSet::new(),
                    });
                    acc.breakdown.unsigned_dlls += 1;
                }
            }

            EventData::NetworkConnect {
                pid,
                dst_addr,
                ..
            } => {
                if is_public_ip(dst_addr) {
                    let key = event_key.unwrap_or_else(|| format!("pid:{pid}"));
                    let acc = acc_map.entry(key).or_insert_with(|| ProcAcc {
                        pid: *pid,
                        image: event
                            .process_context
                            .as_ref()
                            .and_then(|c| c.image_path.clone())
                            .unwrap_or_else(|| format!("PID {pid}")),
                        breakdown: ScoreBreakdown::default(),
                        unique_ips: HashSet::new(),
                        unique_domains: HashSet::new(),
                    });
                    acc.unique_ips.insert(dst_addr.clone());
                }
            }

            EventData::DnsQuery {
                pid,
                query_name,
                ..
            } => {
                if !query_name.is_empty() {
                    let key = event_key.unwrap_or_else(|| format!("pid:{pid}"));
                    let acc = acc_map.entry(key).or_insert_with(|| ProcAcc {
                        pid: *pid,
                        image: event
                            .process_context
                            .as_ref()
                            .and_then(|c| c.image_path.clone())
                            .unwrap_or_else(|| format!("PID {pid}")),
                        breakdown: ScoreBreakdown::default(),
                        unique_ips: HashSet::new(),
                        unique_domains: HashSet::new(),
                    });
                    acc.unique_domains.insert(query_name.clone());
                }
            }

            _ => {}
        }

        true
    })?;

    // Suspicious-parent: sort ProcessCreate by timestamp, build parent map.
    proc_creates.sort_by_key(|p| p.timestamp);
    let mut parent_procs: HashMap<String, String> = HashMap::new(); // key → image
    let mut pid_to_key: HashMap<u32, String> = HashMap::new();

    for pc in &proc_creates {
        let child_key = pc
            .process_key
            .clone()
            .unwrap_or_else(|| format!("pid:{}", pc.pid));

        let parent_name = pid_to_key
            .get(&pc.ppid)
            .and_then(|k| parent_procs.get(k))
            .map(|img| basename(img))
            .unwrap_or_default();

        pid_to_key.insert(pc.pid, child_key.clone());
        parent_procs.insert(child_key.clone(), pc.image_path.clone());

        let child_lower = basename(&pc.image_path).to_ascii_lowercase();
        let parent_lower = parent_name.to_ascii_lowercase();
        if SUSPICIOUS_PARENTS.iter().any(|p| parent_lower == *p)
            && SUSPICIOUS_CHILDREN.iter().any(|c| child_lower == *c)
        {
            if let Some(acc) = acc_map.get_mut(&child_key) {
                acc.breakdown.suspicious_parent = true;
            }
        }
    }

    // Finalize counts and scores.
    let mut scored: Vec<ScoredProcess> = acc_map
        .into_iter()
        .map(|(key, mut acc)| {
            acc.breakdown.external_ips = acc.unique_ips.len() as u32;
            acc.breakdown.dns_queries = acc.unique_domains.len() as u32;
            let score = acc.breakdown.total();
            ScoredProcess {
                process_key: key,
                pid: acc.pid,
                image: acc.image,
                score,
                breakdown: acc.breakdown,
            }
        })
        .filter(|p| p.score > 0)
        .collect();

    scored.sort_by(|a, b| b.score.cmp(&a.score));
    scored.truncate(limit);

    let report = ScoreReport {
        total_events: total,
        scored_processes: scored,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Human-readable output.
    let mut out = std::io::stdout().lock();

    writeln!(
        out,
        "=== Process Threat Scores ({} events scanned) ===",
        report.total_events
    )?;

    if report.scored_processes.is_empty() {
        writeln!(out, "\nNo scored processes.")?;
        return Ok(());
    }

    writeln!(out)?;
    for p in &report.scored_processes {
        writeln!(
            out,
            "[Score: {:>4}]  PID {:>6}  {}",
            p.score, p.pid, p.image
        )?;
        writeln!(out, "              key: {}", p.process_key)?;

        let mut signals = Vec::new();
        if p.breakdown.detections > 0 {
            signals.push(format!(
                "{}x detection (+{})",
                p.breakdown.detections,
                p.breakdown.detections * SCORE_DETECTION
            ));
        }
        if p.breakdown.suspicious_parent {
            signals.push(format!("suspicious parent (+{SCORE_SUSPICIOUS_PARENT})"));
        }
        if p.breakdown.lolbin {
            signals.push(format!("LOLBin (+{SCORE_LOLBIN})"));
        }
        if p.breakdown.unsigned_dlls > 0 {
            signals.push(format!(
                "{}x unsigned DLL (+{})",
                p.breakdown.unsigned_dlls,
                p.breakdown.unsigned_dlls * SCORE_UNSIGNED_DLL
            ));
        }
        if p.breakdown.external_ips > 0 {
            signals.push(format!(
                "{} external IP(s) (+{})",
                p.breakdown.external_ips,
                p.breakdown.external_ips * SCORE_EXTERNAL_IP
            ));
        }
        if p.breakdown.dns_queries > 0 {
            signals.push(format!(
                "{} DNS query(s) (+{})",
                p.breakdown.dns_queries,
                p.breakdown.dns_queries * SCORE_DNS_QUERY
            ));
        }
        writeln!(out, "              {}", signals.join(", "))?;
        writeln!(out)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// IOC extraction
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct IocReport {
    total_events: u64,
    ips: Vec<IocEntry>,
    domains: Vec<IocEntry>,
    hashes: Vec<IocEntry>,
}

#[derive(Serialize)]
struct IocEntry {
    value: String,
    count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_seen: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sources: Vec<String>,
}

/// Returns true if the address is a public (non-private, non-loopback,
/// non-link-local) IPv4 or IPv6 address.
fn is_public_ip(addr: &str) -> bool {
    use std::net::IpAddr;
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                && !v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            let is_unique_local = (seg[0] & 0xfe00) == 0xfc00; // fc00::/7
            let is_link_local = (seg[0] & 0xffc0) == 0xfe80; // fe80::/10
            let is_multicast = (seg[0] & 0xff00) == 0xff00; // ff00::/8
            let is_documentation = seg[0] == 0x2001 && seg[1] == 0x0db8; // 2001:db8::/32
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !is_unique_local
                && !is_link_local
                && !is_multicast
                && !is_documentation
        }
    }
}

fn run_ioc(input: &Path, type_filter: Option<&str>, limit: usize, json: bool) -> Result<()> {
    use std::collections::HashMap;

    // Validate --type early
    if let Some(t) = type_filter {
        if !["ip", "domain", "hash"].contains(&t) {
            anyhow::bail!("invalid --type value: {t} (expected: ip, domain, hash)");
        }
    }

    struct IocAcc {
        count: u64,
        first_seen: DateTime<Utc>,
        sources: std::collections::HashSet<String>,
    }

    let mut total: u64 = 0;
    let mut ips: HashMap<String, IocAcc> = HashMap::new();
    let mut domains: HashMap<String, IocAcc> = HashMap::new();
    let mut hashes: HashMap<String, IocAcc> = HashMap::new();

    let record = |map: &mut HashMap<String, IocAcc>,
                  key: String,
                  ts: DateTime<Utc>,
                  source: String| {
        let acc = map.entry(key).or_insert_with(|| IocAcc {
            count: 0,
            first_seen: ts,
            sources: std::collections::HashSet::new(),
        });
        acc.count += 1;
        if ts < acc.first_seen {
            acc.first_seen = ts;
        }
        acc.sources.insert(source);
    };

    for_each_event(input, |event| {
        total += 1;
        let ts = event.timestamp;

        match &event.data {
            EventData::NetworkConnect {
                dst_addr,
                image_path,
                ..
            } => {
                if is_public_ip(dst_addr) {
                    let src = image_path
                        .rsplit(['/', '\\'])
                        .next()
                        .unwrap_or(image_path)
                        .to_string();
                    record(&mut ips, dst_addr.clone(), ts, src);
                }
            }
            EventData::DnsQuery {
                query_name,
                response,
                ..
            } => {
                if !query_name.is_empty() {
                    let src = format!("DNS/{}", query_name);
                    record(&mut domains, query_name.clone(), ts, "DnsQuery".into());
                    // Also extract IPs from DNS responses
                    if let Some(resp) = response {
                        for part in resp.split(';') {
                            let part = part.trim();
                            if is_public_ip(part) {
                                record(&mut ips, part.to_string(), ts, src.clone());
                            }
                        }
                    }
                }
            }
            EventData::ProcessCreate {
                hashes: Some(h),
                image_path,
                ..
            } => {
                for hash_str in parse_hash_field(h) {
                    let src = image_path
                        .rsplit(['/', '\\'])
                        .next()
                        .unwrap_or(image_path)
                        .to_string();
                    record(&mut hashes, hash_str, ts, src);
                }
            }
            EventData::ImageLoad {
                hashes: Some(h),
                image_name,
                ..
            } => {
                for hash_str in parse_hash_field(h) {
                    record(&mut hashes, hash_str, ts, image_name.clone());
                }
            }
            _ => {}
        }

        true
    })?;

    // Convert to sorted vecs (descending by count)
    let to_entries = |map: HashMap<String, IocAcc>, limit: usize| -> Vec<IocEntry> {
        let mut vec: Vec<_> = map.into_iter().collect();
        vec.sort_by(|a, b| b.1.count.cmp(&a.1.count));
        vec.into_iter()
            .take(limit)
            .map(|(value, acc)| {
                let mut sources: Vec<String> = acc.sources.into_iter().collect();
                sources.sort();
                IocEntry {
                    value,
                    count: acc.count,
                    first_seen: Some(acc.first_seen.to_rfc3339()),
                    sources,
                }
            })
            .collect()
    };

    let show_ip = type_filter.is_none() || type_filter == Some("ip");
    let show_domain = type_filter.is_none() || type_filter == Some("domain");
    let show_hash = type_filter.is_none() || type_filter == Some("hash");

    let report = IocReport {
        total_events: total,
        ips: if show_ip { to_entries(ips, limit) } else { Vec::new() },
        domains: if show_domain { to_entries(domains, limit) } else { Vec::new() },
        hashes: if show_hash { to_entries(hashes, limit) } else { Vec::new() },
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Human-readable output
    let mut out = std::io::stdout().lock();

    writeln!(out, "=== IOC Extraction ({} events scanned) ===", report.total_events)?;

    if show_ip {
        writeln!(out)?;
        if report.ips.is_empty() {
            writeln!(out, "[External IPs] (none)")?;
        } else {
            writeln!(out, "[External IPs] ({})", report.ips.len())?;
            for entry in &report.ips {
                let sources = entry.sources.join(", ");
                writeln!(out, "  {:>6}x  {:<40} ({})", entry.count, entry.value, sources)?;
            }
        }
    }

    if show_domain {
        writeln!(out)?;
        if report.domains.is_empty() {
            writeln!(out, "[Domains] (none)")?;
        } else {
            writeln!(out, "[Domains] ({})", report.domains.len())?;
            for entry in &report.domains {
                writeln!(out, "  {:>6}x  {}", entry.count, entry.value)?;
            }
        }
    }

    if show_hash {
        writeln!(out)?;
        if report.hashes.is_empty() {
            writeln!(out, "[File Hashes] (none)")?;
        } else {
            writeln!(out, "[File Hashes] ({})", report.hashes.len())?;
            for entry in &report.hashes {
                let sources = entry.sources.join(", ");
                writeln!(out, "  {:>6}x  {} ({})", entry.count, entry.value, sources)?;
            }
        }
    }

    Ok(())
}

/// Parse a hash field like "SHA256=abc123,MD5=def456" into individual values
/// preserving the algorithm prefix.
fn parse_hash_field(field: &str) -> Vec<String> {
    field
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// Hunt
// ---------------------------------------------------------------------------

const HUNT_RULES: &[&str] = &["suspicious-parent", "lolbin", "unsigned-dll", "beaconing"];

/// LOLBins — legitimate Windows binaries commonly abused by adversaries.
const LOLBINS: &[&str] = &[
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wscript.exe",
    "cscript.exe",
    "msiexec.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "cmstp.exe",
    "esentutl.exe",
    "expand.exe",
    "extrac32.exe",
    "hh.exe",
    "ieexec.exe",
    "makecab.exe",
    "replace.exe",
];

/// Parent images that should not normally spawn shells/scripting engines.
const SUSPICIOUS_PARENTS: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "mspub.exe",
    "visio.exe",
    "onenote.exe",
    "acrobat.exe",
    "acrord32.exe",
];

/// Children that are suspicious when spawned from office/document apps.
const SUSPICIOUS_CHILDREN: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe",
];

#[derive(Serialize)]
struct HuntReport {
    total_events: u64,
    findings: Vec<HuntFinding>,
}

#[derive(Serialize, Clone)]
struct HuntFinding {
    rule: String,
    severity: String,
    mitre: String,
    process: String,
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_key: Option<String>,
    detail: String,
    timestamp: String,
}

fn run_hunt(input: &Path, rule_filter: Option<&str>, limit: usize, json: bool) -> Result<()> {
    use std::collections::HashMap;

    if let Some(r) = rule_filter {
        if !HUNT_RULES.contains(&r) {
            anyhow::bail!(
                "unknown rule: {r} (available: {})",
                HUNT_RULES.join(", ")
            );
        }
    }

    let run_rule = |name: &str| rule_filter.is_none() || rule_filter == Some(name);

    let mut total: u64 = 0;
    let mut findings: Vec<HuntFinding> = Vec::new();

    // For beaconing detection: track (dst, process_key) → timestamps
    struct BeaconAcc {
        image: String,
        pid: u32,
        process_key: Option<String>,
        timestamps: Vec<DateTime<Utc>>,
    }
    let mut beacon_map: HashMap<String, BeaconAcc> = HashMap::new();

    // Collected ProcessCreate events — sorted by timestamp after the scan
    // so that parent lookup is temporal, not file-order dependent.
    struct ProcCreate {
        pid: u32,
        ppid: u32,
        image_path: String,
        command_line: String,
        process_key: Option<String>,
        timestamp: DateTime<Utc>,
    }
    let mut proc_creates: Vec<ProcCreate> = Vec::new();

    // Single pass: collect ProcessCreate events and handle streaming rules
    // (unsigned-dll, beaconing, lolbin) that don't depend on parent lookup.
    for_each_event(input, |event| {
        total += 1;
        let ts = event.timestamp;

        // Extract process_key from event's process_context if available.
        let event_key = event
            .process_context
            .as_ref()
            .map(|c| c.process_key.clone());

        match &event.data {
            EventData::ProcessCreate {
                pid,
                ppid,
                image_path,
                command_line,
                ..
            } => {
                proc_creates.push(ProcCreate {
                    pid: *pid,
                    ppid: *ppid,
                    image_path: image_path.clone(),
                    command_line: command_line.clone(),
                    process_key: event_key.clone(),
                    timestamp: ts,
                });

                // Rule: lolbin (no parent dependency)
                if run_rule("lolbin") {
                    let child_name = basename(image_path);
                    let child_lower = child_name.to_ascii_lowercase();
                    if LOLBINS.iter().any(|l| child_lower == *l) {
                        findings.push(HuntFinding {
                            rule: "lolbin".into(),
                            severity: "Medium".into(),
                            mitre: "T1218".into(),
                            process: image_path.clone(),
                            pid: *pid,
                            process_key: event_key.clone(),
                            detail: format!(
                                "LOLBin execution: {} ({})",
                                child_name, command_line
                            ),
                            timestamp: ts.to_rfc3339(),
                        });
                    }
                }
            }

            EventData::ImageLoad {
                pid,
                image_path,
                image_name,
                signed,
                ..
            } => {
                // Rule: unsigned-dll
                // Uses the event's own process_context — no parent dependency.
                if run_rule("unsigned-dll") && !signed {
                    let proc_image = event
                        .process_context
                        .as_ref()
                        .and_then(|c| c.image_path.clone())
                        .unwrap_or_else(|| format!("PID {pid}"));
                    findings.push(HuntFinding {
                        rule: "unsigned-dll".into(),
                        severity: "Low".into(),
                        mitre: "T1574.001".into(),
                        process: proc_image,
                        pid: *pid,
                        process_key: event_key.clone(),
                        detail: format!("Unsigned DLL loaded: {} ({})", image_name, image_path),
                        timestamp: ts.to_rfc3339(),
                    });
                }
            }

            EventData::NetworkConnect {
                pid,
                dst_addr,
                image_path,
                ..
            } => {
                // Rule: beaconing — accumulate for post-processing.
                // Key by process_key to avoid merging traffic across PID reuse.
                if run_rule("beaconing") && is_public_ip(dst_addr) {
                    let pkey = event_key
                        .clone()
                        .unwrap_or_else(|| format!("pid:{pid}"));
                    let key = format!("{dst_addr}|{pkey}");
                    let acc = beacon_map.entry(key).or_insert_with(|| BeaconAcc {
                        image: image_path.clone(),
                        pid: *pid,
                        process_key: event_key.clone(),
                        timestamps: Vec::new(),
                    });
                    acc.timestamps.push(ts);
                }
            }

            _ => {}
        }

        true
    })?;

    // Post-processing: suspicious-parent rule.
    // Sort ProcessCreate events by timestamp so parent lookup is temporal,
    // regardless of file order.
    if run_rule("suspicious-parent") {
        proc_creates.sort_by_key(|p| p.timestamp);

        struct ProcInfo {
            image_path: String,
        }
        let mut procs: HashMap<String, ProcInfo> = HashMap::new();
        let mut pid_to_key: HashMap<u32, String> = HashMap::new();

        for pc in &proc_creates {
            let child_key = pc
                .process_key
                .clone()
                .unwrap_or_else(|| format!("pid:{}", pc.pid));

            let parent_name = pid_to_key
                .get(&pc.ppid)
                .and_then(|k| procs.get(k))
                .map(|p| basename(&p.image_path))
                .unwrap_or_default();

            pid_to_key.insert(pc.pid, child_key.clone());
            procs.insert(child_key, ProcInfo {
                image_path: pc.image_path.clone(),
            });

            let child_name = basename(&pc.image_path);
            let parent_lower = parent_name.to_ascii_lowercase();
            let child_lower = child_name.to_ascii_lowercase();
            if SUSPICIOUS_PARENTS.iter().any(|p| parent_lower == *p)
                && SUSPICIOUS_CHILDREN.iter().any(|c| child_lower == *c)
            {
                findings.push(HuntFinding {
                    rule: "suspicious-parent".into(),
                    severity: "High".into(),
                    mitre: "T1204.002".into(),
                    process: pc.image_path.clone(),
                    pid: pc.pid,
                    process_key: pc.process_key.clone(),
                    detail: format!(
                        "{} spawned {} ({})",
                        parent_name, child_name, pc.command_line
                    ),
                    timestamp: pc.timestamp.to_rfc3339(),
                });
            }
        }
    }

    // Post-processing: beaconing detection
    // Flag connections to the same IP from the same process ≥ threshold
    if run_rule("beaconing") {
        let beacon_threshold: usize = 10;
        for (key, acc) in &beacon_map {
            if acc.timestamps.len() >= beacon_threshold {
                let dst = key.split('|').next().unwrap_or("?");
                let earliest = acc
                    .timestamps
                    .iter()
                    .min()
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default();
                findings.push(HuntFinding {
                    rule: "beaconing".into(),
                    severity: "Medium".into(),
                    mitre: "T1071.001".into(),
                    process: acc.image.clone(),
                    pid: acc.pid,
                    process_key: acc.process_key.clone(),
                    detail: format!(
                        "{} connections to {} from {}",
                        acc.timestamps.len(),
                        dst,
                        basename(&acc.image)
                    ),
                    timestamp: earliest,
                });
            }
        }
    }

    // Sort by severity descending, then by timestamp
    let sev_rank = |s: &str| -> u8 {
        match s {
            "Critical" => 4,
            "High" => 3,
            "Medium" => 2,
            "Low" => 1,
            _ => 0,
        }
    };
    findings.sort_by(|a, b| {
        sev_rank(&b.severity)
            .cmp(&sev_rank(&a.severity))
            .then_with(|| a.timestamp.cmp(&b.timestamp))
    });
    findings.truncate(limit);

    let report = HuntReport {
        total_events: total,
        findings,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Human-readable output
    let mut out = std::io::stdout().lock();

    writeln!(
        out,
        "=== Threat Hunt ({} events scanned, {} findings) ===",
        report.total_events,
        report.findings.len()
    )?;

    if report.findings.is_empty() {
        writeln!(out, "\nNo findings.")?;
        return Ok(());
    }

    writeln!(out)?;
    for f in &report.findings {
        writeln!(
            out,
            "[{}] {} ({})",
            f.severity, f.rule, f.mitre
        )?;
        writeln!(out, "  PID:     {}", f.pid)?;
        writeln!(out, "  Process: {}", f.process)?;
        writeln!(out, "  Detail:  {}", f.detail)?;
        writeln!(out, "  Time:    {}", f.timestamp)?;
        writeln!(out)?;
    }

    Ok(())
}

fn basename(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_string()
}

// ---------------------------------------------------------------------------
// Tree
// ---------------------------------------------------------------------------

/// A node in the process tree (for JSON output and tree construction).
#[derive(Serialize, Clone)]
struct TreeNode {
    pid: u32,
    ppid: u32,
    image_path: String,
    command_line: String,
    user: String,
    timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_key: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<TreeNode>,
}

/// Intermediate storage for ProcessCreate data.
struct ProcInfo {
    pid: u32,
    ppid: u32,
    image_path: String,
    command_line: String,
    user: String,
    timestamp: DateTime<Utc>,
    process_key: Option<String>,
}

fn run_tree(
    input: &Path,
    target_pid: u32,
    target_key: Option<&str>,
    ancestors: bool,
    json: bool,
) -> Result<()> {
    use std::collections::HashMap;

    let mut procs: Vec<ProcInfo> = Vec::new();

    for_each_event(input, |event| {
        if let EventData::ProcessCreate {
            pid,
            ppid,
            ref image_path,
            ref command_line,
            ref user,
            ..
        } = event.data
        {
            procs.push(ProcInfo {
                pid,
                ppid,
                image_path: image_path.clone(),
                command_line: command_line.clone(),
                user: user.clone(),
                timestamp: event.timestamp,
                process_key: event.process_context.as_ref().map(|c| c.process_key.clone()),
            });
        }
        true
    })?;

    if procs.is_empty() {
        eprintln!("No ProcessCreate events found.");
        return Ok(());
    }

    // Group by PID for efficient lookup (indices are in chronological order).
    let mut by_pid: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, p) in procs.iter().enumerate() {
        by_pid.entry(p.pid).or_default().push(i);
    }

    // Resolve target process — by process_key if given, else latest instance.
    let target_idx = resolve_target(&procs, &by_pid, target_pid, target_key)?;

    if ancestors {
        // Build ancestor chain: target → parent → grandparent → root
        let mut chain: Vec<usize> = vec![target_idx];
        let mut visited = std::collections::HashSet::new();
        visited.insert(target_idx);
        let mut current_idx = target_idx;
        loop {
            let current = &procs[current_idx];
            if current.ppid == 0 || current.ppid == current.pid {
                break;
            }
            // Find parent: the instance of ppid created most recently before this child.
            let parent_idx = by_pid.get(&current.ppid).and_then(|candidates| {
                candidates
                    .iter()
                    .rev()
                    .find(|&&ci| procs[ci].timestamp <= current.timestamp)
                    .copied()
            });
            match parent_idx {
                Some(pi) if visited.insert(pi) => {
                    chain.push(pi);
                    current_idx = pi;
                }
                _ => break,
            }
        }
        chain.reverse(); // root first

        let chain_refs: Vec<&ProcInfo> = chain.iter().map(|&i| &procs[i]).collect();

        if json {
            let tree = build_chain_tree(&chain_refs);
            println!("{}", serde_json::to_string_pretty(&tree)?);
            return Ok(());
        }

        let tree = build_chain_tree(&chain_refs);
        let mut stdout = std::io::stdout().lock();
        writeln!(
            stdout,
            "=== Ancestor Chain for PID {} ({} levels) ===",
            target_pid,
            chain.len()
        )?;
        print_tree_node(&mut stdout, &tree, "", true, true)?;
    } else {
        // Descendant tree rooted at target.
        // Assign each child to the correct parent instance using temporal ordering.
        let mut children_of: HashMap<usize, Vec<usize>> = HashMap::new();
        for (i, p) in procs.iter().enumerate() {
            if let Some(candidates) = by_pid.get(&p.ppid) {
                // Parent = latest instance of ppid created before this child.
                if let Some(&parent_idx) = candidates
                    .iter()
                    .rev()
                    .find(|&&ci| procs[ci].timestamp <= p.timestamp && ci != i)
                {
                    children_of.entry(parent_idx).or_default().push(i);
                }
            }
        }

        let tree = build_descendant_tree(&procs, &children_of, target_idx);

        if json {
            println!("{}", serde_json::to_string_pretty(&tree)?);
            return Ok(());
        }

        let mut stdout = std::io::stdout().lock();
        let desc_count = count_descendants(&tree);
        writeln!(
            stdout,
            "=== Process Tree for PID {} ({} descendants) ===",
            target_pid, desc_count
        )?;
        print_tree_node(&mut stdout, &tree, "", true, true)?;
    }

    Ok(())
}

/// Resolve the target process index by PID and optional process_key.
/// When multiple instances share the same PID, `target_key` disambiguates.
/// Without it, the latest (most recent) instance is chosen.
fn resolve_target(
    procs: &[ProcInfo],
    by_pid: &std::collections::HashMap<u32, Vec<usize>>,
    target_pid: u32,
    target_key: Option<&str>,
) -> Result<usize> {
    let candidates = by_pid.get(&target_pid).ok_or_else(|| {
        anyhow::anyhow!("PID {target_pid} not found in ProcessCreate events")
    })?;
    if let Some(key) = target_key {
        candidates
            .iter()
            .find(|&&i| procs[i].process_key.as_deref() == Some(key))
            .copied()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "process_key \"{key}\" not found for PID {target_pid}"
                )
            })
    } else {
        // Latest instance (last in chronological order).
        Ok(*candidates.last().unwrap())
    }
}

fn proc_to_node(p: &ProcInfo) -> TreeNode {
    TreeNode {
        pid: p.pid,
        ppid: p.ppid,
        image_path: p.image_path.clone(),
        command_line: p.command_line.clone(),
        user: p.user.clone(),
        timestamp: p.timestamp,
        process_key: p.process_key.clone(),
        children: Vec::new(),
    }
}

fn build_descendant_tree(
    procs: &[ProcInfo],
    children_of: &std::collections::HashMap<usize, Vec<usize>>,
    idx: usize,
) -> TreeNode {
    let mut node = proc_to_node(&procs[idx]);
    if let Some(child_indices) = children_of.get(&idx) {
        for &ci in child_indices {
            node.children
                .push(build_descendant_tree(procs, children_of, ci));
        }
        node.children.sort_by_key(|c| c.timestamp);
    }
    node
}

fn build_chain_tree(chain: &[&ProcInfo]) -> TreeNode {
    if chain.is_empty() {
        // Should not happen — caller checks. Return a placeholder.
        return TreeNode {
            pid: 0,
            ppid: 0,
            image_path: String::new(),
            command_line: String::new(),
            user: String::new(),
            timestamp: Utc::now(),
            process_key: None,
            children: Vec::new(),
        };
    }
    let mut node = proc_to_node(chain[0]);
    let mut current = &mut node;
    for p in &chain[1..] {
        let child = proc_to_node(p);
        current.children.push(child);
        current = current.children.last_mut().unwrap();
    }
    node
}

fn count_descendants(node: &TreeNode) -> usize {
    let mut count = 0;
    for child in &node.children {
        count += 1 + count_descendants(child);
    }
    count
}

fn print_tree_node(
    out: &mut impl Write,
    node: &TreeNode,
    prefix: &str,
    is_last: bool,
    is_root: bool,
) -> Result<()> {
    let connector = if is_root {
        ""
    } else if is_last {
        "└─ "
    } else {
        "├─ "
    };
    let key_str = node
        .process_key
        .as_deref()
        .map(|k| format!("  [{k}]"))
        .unwrap_or_default();
    writeln!(
        out,
        "{prefix}{connector}{} [PID {}, PPID {}] {}{key_str}",
        short_image(&node.image_path),
        node.pid,
        node.ppid,
        node.user,
    )?;

    let child_prefix = if is_root {
        String::new()
    } else if is_last {
        format!("{prefix}   ")
    } else {
        format!("{prefix}│  ")
    };
    for (i, child) in node.children.iter().enumerate() {
        let last = i == node.children.len() - 1;
        print_tree_node(out, child, &child_prefix, last, false)?;
    }
    Ok(())
}

fn short_image(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

// ---------------------------------------------------------------------------
// Inspect
// ---------------------------------------------------------------------------

use crate::pe::{self, PeHeaders};

/// Suspicious API categories for import classification.
struct SuspiciousCategory {
    name: &'static str,
    apis: &'static [&'static str],
}

const SUSPICIOUS_APIS: &[SuspiciousCategory] = &[
    SuspiciousCategory {
        name: "Process Injection",
        apis: &[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "NtCreateThreadEx",
            "NtWriteVirtualMemory",
            "NtMapViewOfSection",
            "QueueUserAPC",
            "RtlCreateUserThread",
        ],
    },
    SuspiciousCategory {
        name: "Code Execution",
        apis: &[
            "CreateProcessA",
            "CreateProcessW",
            "CreateProcessAsUserA",
            "CreateProcessAsUserW",
            "ShellExecuteA",
            "ShellExecuteW",
            "ShellExecuteExA",
            "ShellExecuteExW",
            "WinExec",
        ],
    },
    SuspiciousCategory {
        name: "Memory Manipulation",
        apis: &[
            "VirtualProtect",
            "VirtualProtectEx",
            "VirtualAlloc",
            "VirtualAllocEx",
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
        ],
    },
    SuspiciousCategory {
        name: "Hooking / Dynamic Resolution",
        apis: &[
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "GetProcAddress",
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "LoadLibraryExW",
            "LdrLoadDll",
        ],
    },
    SuspiciousCategory {
        name: "Credential Access",
        apis: &[
            "CredReadA",
            "CredReadW",
            "LsaRetrievePrivateData",
            "CryptUnprotectData",
        ],
    },
    SuspiciousCategory {
        name: "Defense Evasion",
        apis: &[
            "NtUnmapViewOfSection",
            "NtCreateSection",
            "NtSetContextThread",
            "NtResumeThread",
            "NtSuspendThread",
            "EtwEventWrite",
        ],
    },
];

fn classify_api(name: &str) -> Vec<&'static str> {
    let mut cats = Vec::new();
    for cat in SUSPICIOUS_APIS {
        if cat.apis.contains(&name) {
            cats.push(cat.name);
        }
    }
    cats
}

fn section_rwx(chars: u32) -> String {
    let r = if chars & pe::SCN_MEM_READ != 0 { 'R' } else { '-' };
    let w = if chars & pe::SCN_MEM_WRITE != 0 { 'W' } else { '-' };
    let x = if chars & pe::SCN_MEM_EXECUTE != 0 { 'X' } else { '-' };
    format!("{r}{w}{x}")
}

#[derive(Serialize)]
struct InspectReport {
    file: String,
    architecture: String,
    entry_point_rva: String,
    image_base: String,
    image_size: String,
    subsystem: String,
    sections: Vec<InspectSection>,
    imports: Vec<InspectImportDll>,
    exports: Vec<pe::ExportEntry>,
    suspicious_summary: Vec<SuspiciousSummary>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct InspectSection {
    name: String,
    virtual_size: u32,
    raw_size: u32,
    characteristics: String,
    suspicious: bool,
}

#[derive(Serialize)]
struct InspectImportDll {
    dll_name: String,
    functions: Vec<InspectImportFunc>,
}

#[derive(Serialize)]
struct InspectImportFunc {
    name: Option<String>,
    ordinal: Option<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    suspicious_categories: Vec<String>,
}

#[derive(Serialize)]
struct SuspiciousSummary {
    category: String,
    count: usize,
    apis: Vec<String>,
}

fn run_inspect(path: &Path, json: bool) -> Result<()> {
    let data =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let pe = PeHeaders::parse(&data)
        .ok_or_else(|| anyhow::anyhow!("not a valid PE file: {}", path.display()))?;

    let mut warnings: Vec<String> = Vec::new();

    let has_import_dir = pe.import_directory().is_some();
    let imports = match pe.parse_imports(&data) {
        Some(v) => v,
        None if has_import_dir => {
            warnings.push("Import table is present but could not be parsed (malformed data)".to_string());
            Vec::new()
        }
        None => Vec::new(),
    };

    let has_export_dir = pe.export_directory().is_some();
    let exports = match pe.parse_exports(&data) {
        Some(v) => v,
        None if has_export_dir => {
            warnings.push("Export table is present but could not be parsed (malformed data)".to_string());
            Vec::new()
        }
        None => Vec::new(),
    };

    // Build sections info.
    let sections: Vec<InspectSection> = pe
        .sections
        .iter()
        .map(|s| {
            let rwx = section_rwx(s.characteristics);
            let suspicious = s.is_writable() && s.is_executable();
            if suspicious {
                warnings.push(format!(
                    "Section {} is writable + executable ({})",
                    s.name, rwx
                ));
            }
            InspectSection {
                name: s.name.clone(),
                virtual_size: s.virtual_size,
                raw_size: s.raw_data_size,
                characteristics: rwx,
                suspicious,
            }
        })
        .collect();

    // Build imports with suspicious classification.
    let mut suspicious_map: std::collections::HashMap<&str, Vec<String>> =
        std::collections::HashMap::new();
    let inspect_imports: Vec<InspectImportDll> = imports
        .iter()
        .map(|dll| InspectImportDll {
            dll_name: dll.dll_name.clone(),
            functions: dll
                .functions
                .iter()
                .map(|f| {
                    let cats = f
                        .name
                        .as_deref()
                        .map(|n| {
                            let c = classify_api(n);
                            for &cat in &c {
                                suspicious_map
                                    .entry(cat)
                                    .or_default()
                                    .push(n.to_string());
                            }
                            c
                        })
                        .unwrap_or_default();
                    InspectImportFunc {
                        name: f.name.clone(),
                        ordinal: f.ordinal,
                        suspicious_categories: cats.iter().map(|s| s.to_string()).collect(),
                    }
                })
                .collect(),
        })
        .collect();

    // Build suspicious summary, sorted by count descending.
    let mut suspicious_summary: Vec<SuspiciousSummary> = suspicious_map
        .into_iter()
        .map(|(cat, apis)| SuspiciousSummary {
            category: cat.to_string(),
            count: apis.len(),
            apis,
        })
        .collect();
    suspicious_summary.sort_by(|a, b| b.count.cmp(&a.count));

    let report = InspectReport {
        file: path.display().to_string(),
        architecture: pe.machine_name().to_string(),
        entry_point_rva: format!("0x{:08X}", pe.entry_point_rva),
        image_base: format!("0x{:016X}", pe.image_base),
        image_size: format!("0x{:08X}", pe.size_of_image),
        subsystem: pe.subsystem_name().to_string(),
        sections,
        imports: inspect_imports,
        exports,
        suspicious_summary,
        warnings,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Human-readable output.
    let mut out = std::io::stdout().lock();

    writeln!(out, "=== PE Inspection: {} ===", path.display())?;
    writeln!(out)?;

    // Basic info.
    writeln!(out, "[Basic Info]")?;
    writeln!(out, "  Architecture:    {}", report.architecture)?;
    writeln!(out, "  Entry Point:     {}", report.entry_point_rva)?;
    writeln!(out, "  Image Base:      {}", report.image_base)?;
    writeln!(out, "  Image Size:      {}", report.image_size)?;
    writeln!(out, "  Subsystem:       {}", report.subsystem)?;
    writeln!(out)?;

    // Sections.
    writeln!(out, "[Sections] ({})", report.sections.len())?;
    writeln!(out, "  {:<10} {:>10} {:>10}  Flags", "Name", "VirtSize", "RawSize")?;
    for s in &report.sections {
        let flag = if s.suspicious { " [!] W+X" } else { "" };
        writeln!(
            out,
            "  {:<10} 0x{:08X} 0x{:08X}  {}{}",
            s.name, s.virtual_size, s.raw_size, s.characteristics, flag
        )?;
    }
    writeln!(out)?;

    // Imports.
    let total_funcs: usize = report.imports.iter().map(|d| d.functions.len()).sum();
    writeln!(
        out,
        "[Imports] ({} DLLs, {} functions)",
        report.imports.len(),
        total_funcs
    )?;
    for dll in &report.imports {
        writeln!(out, "  {} ({} functions)", dll.dll_name, dll.functions.len())?;
        for f in &dll.functions {
            let ord_fallback = format!("ordinal #{}", f.ordinal.unwrap_or(0));
            let name_str = f.name.as_deref().unwrap_or(&ord_fallback);
            if f.suspicious_categories.is_empty() {
                writeln!(out, "    {name_str}")?;
            } else {
                writeln!(
                    out,
                    "    {name_str:<40} [!] {}",
                    f.suspicious_categories.join(", ")
                )?;
            }
        }
    }
    writeln!(out)?;

    // Suspicious summary.
    if !report.suspicious_summary.is_empty() {
        writeln!(out, "[Suspicious API Summary]")?;
        for s in &report.suspicious_summary {
            writeln!(out, "  {:<35} {} API(s)", s.category, s.count)?;
        }
        writeln!(out)?;
    }

    // Exports.
    writeln!(out, "[Exports] ({})", report.exports.len())?;
    if report.exports.is_empty() {
        writeln!(out, "  (none)")?;
    } else {
        for e in &report.exports {
            let name_str = e.name.as_deref().unwrap_or("(ordinal)");
            let fwd = if e.is_forward { " [forwarder]" } else { "" };
            writeln!(
                out,
                "  #{:<5} 0x{:08X}  {}{fwd}",
                e.ordinal, e.rva, name_str
            )?;
        }
    }

    // Warnings.
    if !report.warnings.is_empty() {
        writeln!(out)?;
        writeln!(out, "[Warnings]")?;
        for w in &report.warnings {
            writeln!(out, "  [!] {w}")?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Alert — real-time detection monitor
// ---------------------------------------------------------------------------

/// A single alert emitted by the monitor.
#[derive(Serialize)]
struct AlertEvent {
    /// "hunt" for hunt-rule matches, "score" for threshold breaches.
    alert_type: String,
    rule: String,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mitre: Option<String>,
    process_key: String,
    pid: u32,
    image: String,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<u32>,
    timestamp: String,
}

fn run_alert(input: &Path, threshold: u32, cooldown_secs: u64, json: bool) -> Result<()> {
    use std::collections::{HashMap, HashSet};
    use std::io::{Seek, SeekFrom};
    use std::time::Instant;

    let cooldown = std::time::Duration::from_secs(cooldown_secs);

    let file = std::fs::File::open(input)
        .with_context(|| format!("cannot open {}", input.display()))?;
    let file_size = file.metadata()?.len();
    let mut reader = std::io::BufReader::new(file);

    // Seek to end — only process newly appended events.
    reader.seek(SeekFrom::End(0))?;
    eprintln!(
        "Monitoring {} for threats (skipped {} bytes, Ctrl+C to stop)",
        input.display(),
        file_size,
    );
    eprintln!(
        "  score threshold: {}, cooldown: {}s",
        threshold, cooldown_secs,
    );

    let mut stdout = std::io::stdout().lock();
    let mut line_buf = String::new();

    // Per-process scoring accumulators (same as run_score).
    struct ProcAcc {
        pid: u32,
        image: String,
        breakdown: ScoreBreakdown,
        unique_ips: HashSet<String>,
        unique_domains: HashSet<String>,
        threshold_alerted: bool,
    }
    let mut acc_map: HashMap<String, ProcAcc> = HashMap::new();

    // Deduplication: (process_key, rule) → last alert time.
    let mut seen: HashMap<String, Instant> = HashMap::new();

    // Parent tracking for suspicious-parent rule (streaming).
    // Maps pid → (process_key, image_path) for the most recent ProcessCreate.
    let mut pid_to_proc: HashMap<u32, (String, String)> = HashMap::new();

    let should_emit = |dedup_key: &str, seen: &mut HashMap<String, Instant>, cooldown: std::time::Duration| -> bool {
        let now = Instant::now();
        if let Some(last) = seen.get(dedup_key) {
            if now.duration_since(*last) < cooldown {
                return false;
            }
        }
        seen.insert(dedup_key.to_string(), now);
        true
    };

    loop {
        line_buf.clear();
        match reader.read_line(&mut line_buf) {
            Ok(0) => {
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
                let event = match serde_json::from_str::<ThreatEvent>(line) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                let event_key = event
                    .process_context
                    .as_ref()
                    .map(|c| c.process_key.clone());

                let mut alerts: Vec<AlertEvent> = Vec::new();

                match &event.data {
                    EventData::ProcessCreate {
                        pid,
                        ppid,
                        image_path,
                        command_line,
                        ..
                    } => {
                        let key = event_key.clone().unwrap_or_else(|| format!("pid:{pid}"));
                        let acc = acc_map.entry(key.clone()).or_insert_with(|| ProcAcc {
                            pid: *pid,
                            image: image_path.clone(),
                            breakdown: ScoreBreakdown::default(),
                            unique_ips: HashSet::new(),
                            unique_domains: HashSet::new(),
                            threshold_alerted: false,
                        });

                        // LOLBin check
                        let child_name = basename(image_path);
                        let child_lower = child_name.to_ascii_lowercase();
                        if LOLBINS.iter().any(|l| child_lower == *l) {
                            acc.breakdown.lolbin = true;
                            let dedup = format!("{key}|lolbin");
                            if should_emit(&dedup, &mut seen, cooldown) {
                                alerts.push(AlertEvent {
                                    alert_type: "hunt".into(),
                                    rule: "lolbin".into(),
                                    severity: "Medium".into(),
                                    mitre: Some("T1218".into()),
                                    process_key: key.clone(),
                                    pid: *pid,
                                    image: image_path.clone(),
                                    detail: format!(
                                        "LOLBin execution: {} ({})",
                                        child_name, command_line,
                                    ),
                                    score: None,
                                    timestamp: event.timestamp.to_rfc3339(),
                                });
                            }
                        }

                        // Suspicious-parent check (streaming: look up parent pid)
                        if let Some((_, parent_image)) = pid_to_proc.get(ppid) {
                            let parent_lower = basename(parent_image).to_ascii_lowercase();
                            if SUSPICIOUS_PARENTS.iter().any(|p| parent_lower == *p)
                                && SUSPICIOUS_CHILDREN.iter().any(|c| child_lower == *c)
                            {
                                acc.breakdown.suspicious_parent = true;
                                let dedup = format!("{key}|suspicious-parent");
                                if should_emit(&dedup, &mut seen, cooldown) {
                                    alerts.push(AlertEvent {
                                        alert_type: "hunt".into(),
                                        rule: "suspicious-parent".into(),
                                        severity: "High".into(),
                                        mitre: Some("T1204.002".into()),
                                        process_key: key.clone(),
                                        pid: *pid,
                                        image: image_path.clone(),
                                        detail: format!(
                                            "{} spawned {} ({})",
                                            basename(parent_image),
                                            child_name,
                                            command_line,
                                        ),
                                        score: None,
                                        timestamp: event.timestamp.to_rfc3339(),
                                    });
                                }
                            }
                        }

                        // Update parent tracking
                        pid_to_proc.insert(*pid, (key, image_path.clone()));
                    }

                    EventData::EvasionDetected { pid, process_name, .. } => {
                        if event.rule.is_some() {
                            let pid_val = pid.unwrap_or(0);
                            let key = event_key
                                .clone()
                                .unwrap_or_else(|| format!("pid:{pid_val}"));
                            let rule_id = event
                                .rule
                                .as_ref()
                                .map(|r| r.id.clone())
                                .unwrap_or_else(|| "detection".into());
                            let img = event
                                .process_context
                                .as_ref()
                                .and_then(|c| c.image_path.clone())
                                .or_else(|| process_name.clone())
                                .unwrap_or_default();
                            let acc = acc_map.entry(key.clone()).or_insert_with(|| ProcAcc {
                                pid: pid_val,
                                image: img.clone(),
                                breakdown: ScoreBreakdown::default(),
                                unique_ips: HashSet::new(),
                                unique_domains: HashSet::new(),
                                threshold_alerted: false,
                            });
                            acc.breakdown.detections += 1;

                            let dedup = format!("{key}|{rule_id}");
                            if should_emit(&dedup, &mut seen, cooldown) {
                                alerts.push(AlertEvent {
                                    alert_type: "detection".into(),
                                    rule: rule_id,
                                    severity: format!("{:?}", event.severity),
                                    mitre: event.rule.as_ref().map(|r| {
                                        r.mitre.technique_id.clone()
                                    }),
                                    process_key: key.clone(),
                                    pid: pid_val,
                                    image: img,
                                    detail: event_summary(&event.data),
                                    score: None,
                                    timestamp: event.timestamp.to_rfc3339(),
                                });
                            }
                        }
                    }

                    EventData::ImageLoad {
                        pid,
                        image_name,
                        image_path,
                        signed,
                        ..
                    } => {
                        if !signed {
                            let key = event_key.unwrap_or_else(|| format!("pid:{pid}"));
                            let proc_image = event
                                .process_context
                                .as_ref()
                                .and_then(|c| c.image_path.clone())
                                .unwrap_or_else(|| format!("PID {pid}"));
                            let acc = acc_map.entry(key.clone()).or_insert_with(|| ProcAcc {
                                pid: *pid,
                                image: proc_image.clone(),
                                breakdown: ScoreBreakdown::default(),
                                unique_ips: HashSet::new(),
                                unique_domains: HashSet::new(),
                                threshold_alerted: false,
                            });
                            acc.breakdown.unsigned_dlls += 1;

                            let dedup = format!("{key}|unsigned-dll|{image_name}");
                            if should_emit(&dedup, &mut seen, cooldown) {
                                alerts.push(AlertEvent {
                                    alert_type: "hunt".into(),
                                    rule: "unsigned-dll".into(),
                                    severity: "Low".into(),
                                    mitre: Some("T1574.001".into()),
                                    process_key: key.clone(),
                                    pid: *pid,
                                    image: proc_image,
                                    detail: format!(
                                        "Unsigned DLL loaded: {} ({})",
                                        image_name, image_path,
                                    ),
                                    score: None,
                                    timestamp: event.timestamp.to_rfc3339(),
                                });
                            }
                        }
                    }

                    EventData::NetworkConnect {
                        pid,
                        dst_addr,
                        ..
                    } => {
                        if is_public_ip(dst_addr) {
                            let key = event_key.unwrap_or_else(|| format!("pid:{pid}"));
                            let proc_image = event
                                .process_context
                                .as_ref()
                                .and_then(|c| c.image_path.clone())
                                .unwrap_or_else(|| format!("PID {pid}"));
                            let acc = acc_map.entry(key.clone()).or_insert_with(|| ProcAcc {
                                pid: *pid,
                                image: proc_image,
                                breakdown: ScoreBreakdown::default(),
                                unique_ips: HashSet::new(),
                                unique_domains: HashSet::new(),
                                threshold_alerted: false,
                            });
                            acc.unique_ips.insert(dst_addr.clone());
                        }
                    }

                    EventData::DnsQuery {
                        pid,
                        query_name,
                        ..
                    } => {
                        if !query_name.is_empty() {
                            let key = event_key.unwrap_or_else(|| format!("pid:{pid}"));
                            let proc_image = event
                                .process_context
                                .as_ref()
                                .and_then(|c| c.image_path.clone())
                                .unwrap_or_else(|| format!("PID {pid}"));
                            let acc = acc_map.entry(key.clone()).or_insert_with(|| ProcAcc {
                                pid: *pid,
                                image: proc_image,
                                breakdown: ScoreBreakdown::default(),
                                unique_ips: HashSet::new(),
                                unique_domains: HashSet::new(),
                                threshold_alerted: false,
                            });
                            acc.unique_domains.insert(query_name.clone());
                        }
                    }

                    _ => {}
                }

                // Check score threshold for all affected accumulators.
                // We only need to check keys that were touched this iteration.
                // Collect keys from alerts to check.
                let keys_to_check: Vec<String> = alerts
                    .iter()
                    .map(|a| a.process_key.clone())
                    .collect();

                // Also check the event's own key if it had scoring updates
                // but no hunt alert (e.g. network/dns events).
                let event_own_key = match &event.data {
                    EventData::NetworkConnect { pid, .. } => {
                        let k = event
                            .process_context
                            .as_ref()
                            .map(|c| c.process_key.clone())
                            .unwrap_or_else(|| format!("pid:{pid}"));
                        Some(k)
                    }
                    EventData::DnsQuery { pid, .. } => {
                        let k = event
                            .process_context
                            .as_ref()
                            .map(|c| c.process_key.clone())
                            .unwrap_or_else(|| format!("pid:{pid}"));
                        Some(k)
                    }
                    _ => None,
                };

                let all_keys: HashSet<String> = keys_to_check
                    .into_iter()
                    .chain(event_own_key)
                    .collect();

                for key in &all_keys {
                    if let Some(acc) = acc_map.get_mut(key.as_str()) {
                        acc.breakdown.external_ips = acc.unique_ips.len() as u32;
                        acc.breakdown.dns_queries = acc.unique_domains.len() as u32;
                        let current_score = acc.breakdown.total();
                        if current_score >= threshold && !acc.threshold_alerted {
                            acc.threshold_alerted = true;
                            let dedup = format!("{key}|score-threshold");
                            if should_emit(&dedup, &mut seen, cooldown) {
                                alerts.push(AlertEvent {
                                    alert_type: "score".into(),
                                    rule: "score-threshold".into(),
                                    severity: "High".into(),
                                    mitre: None,
                                    process_key: key.clone(),
                                    pid: acc.pid,
                                    image: acc.image.clone(),
                                    detail: format!(
                                        "Process score {} reached threshold {}",
                                        current_score, threshold,
                                    ),
                                    score: Some(current_score),
                                    timestamp: event.timestamp.to_rfc3339(),
                                });
                            }
                        }
                    }
                }

                // Emit alerts
                for alert in &alerts {
                    if json {
                        writeln!(stdout, "{}", serde_json::to_string(alert)?)?;
                    } else {
                        let mitre = alert
                            .mitre
                            .as_deref()
                            .map(|m| format!(" ({m})"))
                            .unwrap_or_default();
                        let score_str = alert
                            .score
                            .map(|s| format!(" [score: {s}]"))
                            .unwrap_or_default();
                        writeln!(
                            stdout,
                            "{} [{}] {} {}{}{} PID {} {}",
                            alert.timestamp,
                            alert.severity,
                            alert.alert_type.to_ascii_uppercase(),
                            alert.rule,
                            mitre,
                            score_str,
                            alert.pid,
                            alert.image,
                        )?;
                        writeln!(stdout, "  {}", alert.detail)?;
                    }
                    stdout.flush()?;
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
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
                        writeln!(stdout, "{line}")?;
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
                    stdout.flush()?;
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
