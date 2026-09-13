//! Read-only JSONL replay. Does not start collectors, execute samples, or contact a server.
use crate::detection::{DetectionStats, Detector};
use crate::diagnostics::Language;
use crate::events::*;
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

#[derive(Default, Serialize)]
pub struct Coverage {
    pub events: u64,
    pub source_time_events: u64,
    pub stable_process_guid_events: u64,
    pub macos_native_identity_events: u64,
    pub macos_event_kinds: BTreeMap<String, u64>,
    pub native_only_events: u64,
    pub quality_issues: BTreeMap<String, u64>,
    pub sysmon_event_ids: BTreeMap<u16, u64>,
    pub health_records: u64,
    pub recorded_loss_or_degradation: bool,
}

#[derive(Serialize)]
pub struct Report {
    pub report_version: u16,
    pub analysis: DetectionStats,
    pub agents: BTreeMap<uuid::Uuid, Coverage>,
    pub findings: Vec<ThreatEvent>,
    pub malformed_lines: u64,
    pub findings_truncated: u64,
    pub limitations: Vec<&'static str>,
}

pub fn analyze(reader: impl BufRead) -> Result<Report> {
    let mut detector = Detector::default();
    let mut agents: BTreeMap<uuid::Uuid, Coverage> = BTreeMap::new();
    let mut findings = Vec::new();
    let mut malformed_lines = 0;
    let mut findings_truncated = 0;
    // Bound each line before parsing; don't allocate an attacker-sized line.
    let mut reader = reader;
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        let n = reader
            .by_ref()
            .take(4 * 1024 * 1024 + 1)
            .read_until(b'\n', &mut buffer)?;
        if n == 0 {
            break;
        }
        anyhow::ensure!(
            n <= 4 * 1024 * 1024,
            "JSONL line exceeds 4 MiB safety limit"
        );
        if buffer.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let event: ThreatEvent = match serde_json::from_slice(&buffer) {
            Ok(e) => e,
            Err(_) => {
                malformed_lines += 1;
                continue;
            }
        };
        anyhow::ensure!(
            agents.len() < 1024 || agents.contains_key(&event.agent_id),
            "combined log exceeds 1024-agent limit"
        );
        let coverage = agents.entry(event.agent_id).or_default();
        coverage.events += 1;
        if let Some(p) = &event.provenance {
            coverage.source_time_events += u64::from(p.original_time);
            coverage.stable_process_guid_events += u64::from(p.process_guid.is_some());
            for issue in &p.issues {
                // Field names/status suffixes need not create unbounded map cardinality.
                let code = issue
                    .split(':')
                    .next()
                    .unwrap_or("unknown")
                    .chars()
                    .take(80)
                    .collect::<String>();
                if coverage.quality_issues.len() < 128
                    || coverage.quality_issues.contains_key(&code)
                {
                    *coverage.quality_issues.entry(code).or_default() += 1;
                }
            }
        }
        if let EventSource::Sysmon { event_id } = event.source {
            *coverage.sysmon_event_ids.entry(event_id).or_default() += 1;
        }
        if let EventData::MacosEndpointSecurity { record } = &event.data {
            coverage.source_time_events += u64::from(record.original_time);
            coverage.macos_native_identity_events +=
                u64::from(!record.boot_session_uuid.is_nil() && !event.agent_id.is_nil());
            *coverage
                .macos_event_kinds
                .entry(format!("{:?}", record.kind))
                .or_default() += 1;
            for issue in &record.issues {
                let code: String = issue.chars().take(80).collect();
                if coverage.quality_issues.len() < 128
                    || coverage.quality_issues.contains_key(&code)
                {
                    *coverage.quality_issues.entry(code).or_default() += 1;
                }
            }
        }
        if matches!(event.data, EventData::NativeTelemetry { .. }) {
            coverage.native_only_events += 1;
        }
        if let EventData::SensorHealth {
            events_dropped,
            collectors,
            ..
        } = &event.data
        {
            coverage.health_records += 1;
            coverage.recorded_loss_or_degradation |= *events_dropped > 0
                || collectors.iter().any(|c| {
                    c.decode_failures > 0
                        || c.events_lost_before_queue > 0
                        || c.queue_events_dropped > 0
                        || c.endpoint_security.as_ref().is_some_and(|s| {
                            s.sequence_drops > 0
                                || s.sequence_discontinuities > 0
                                || s.sequence_unavailable > 0
                        })
                        || matches!(c.state, CollectorState::Error | CollectorState::Degraded)
                        || c.etw.as_ref().is_some_and(|s| {
                            s.events_lost > 0
                                || s.log_buffers_lost > 0
                                || s.realtime_buffers_lost > 0
                        })
                });
        }
        for finding in detector.ingest(&event) {
            if findings.len() < 10_000 {
                findings.push(finding);
            } else {
                findings_truncated += 1;
            }
        }
    }
    let mut limitations = vec![
        "no_findings_does_not_mean_clean",
        "behavioral_findings_require_investigation",
        "correlation_requires_v2_sysmon_source_time_and_process_guids",
        "ten_minute_window_two_minute_sequence",
        "replay_uses_input_order_with_bounded_out_of_order_support",
        "no_cross_feed_pid_only_join",
        "offline_analysis_starts_with_empty_state",
        "real_windows_detection_quality_not_validated",
    ];
    if agents.values().any(|c| c.health_records == 0) {
        limitations.push("collection_loss_unknown_without_health");
    }
    if agents.values().any(|c| !c.macos_event_kinds.is_empty()) {
        limitations.push("macos_detection_rules_not_implemented");
        limitations.push("macos_live_only_no_outage_replay");
    }
    if malformed_lines > 0 {
        limitations.push("malformed_input_skipped");
    }
    Ok(Report {
        report_version: 1,
        analysis: detector.stats,
        agents,
        findings,
        malformed_lines,
        findings_truncated,
        limitations,
    })
}

pub fn run(path: &Path, lang: Language, json: bool) -> Result<()> {
    let report = analyze(BufReader::new(
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?,
    ))?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if json {
        serde_json::to_writer_pretty(&mut out, &report)?;
        writeln!(out)?;
        return Ok(());
    }
    let ja = matches!(lang, Language::Ja);
    writeln!(
        out,
        "{}: {}",
        if ja {
            "相関検知"
        } else {
            "Correlated findings"
        },
        report.findings.len()
    )?;
    writeln!(
        out,
        "{}: {} / {}",
        if ja {
            "解析可能な証拠 / 入力イベント"
        } else {
            "Eligible evidence / input events"
        },
        report.analysis.eligible_events,
        report.analysis.input_events
    )?;
    writeln!(
        out,
        "{}: {}",
        if ja {
            "時刻・識別情報が不足するイベント"
        } else {
            "Events missing required evidence"
        },
        report.analysis.missing_evidence_events
    )?;
    for (agent, c) in &report.agents {
        writeln!(out,"agent={agent} events={} source_time={} process_guid={} native_only={} recorded_loss={}",
            c.events,c.source_time_events,c.stable_process_guid_events,c.native_only_events,c.recorded_loss_or_degradation)?;
        if !c.macos_event_kinds.is_empty() {
            writeln!(
                out,
                "{}: {} / {:?}",
                if ja {
                    "macOSネイティブ識別情報（検知ルールは未実装）"
                } else {
                    "macOS native identities (detection rules not implemented)"
                },
                c.macos_native_identity_events,
                c.macos_event_kinds
            )?;
        }
    }
    for e in &report.findings {
        if let EventData::CorrelationDetection {
            rule_id,
            title_en,
            title_ja,
            evidence_ids,
            details,
            ..
        } = &e.data
        {
            writeln!(out, "{rule_id}: {}", if ja { title_ja } else { title_en })?;
            writeln!(out, "  {details}")?;
            writeln!(
                out,
                "  evidence={}",
                evidence_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )?;
        }
    }
    writeln!(
        out,
        "{}",
        if ja {
            "検知ゼロは安全を意味しません。実Windowsでの検知品質は未検証です。"
        } else {
            "No findings does not mean clean. Real Windows detection quality is not yet validated."
        }
    )?;
    writeln!(out, "limitations={}", report.limitations.join(", "))?;
    writeln!(
        out,
        "malformed_lines={} late_events={} capacity_drops={} findings_truncated={}",
        report.malformed_lines,
        report.analysis.late_events,
        report.analysis.capacity_events_dropped,
        report.findings_truncated
    )?;
    Ok(())
}

/// Import is intentionally read-only; caller chooses whether to redirect stdout.
/// A file must represent a single host; assigning a mixed-host export one agent
/// ID could manufacture cross-host process correlations.
pub fn import_sysmon(path: &Path, agent_id: uuid::Uuid, hostname: String) -> Result<()> {
    use crate::collectors::sysmon_parser::{map_to_threat_event, parse_sysmon_xml};
    use quick_xml::events::Event;
    anyhow::ensure!(
        !agent_id.is_nil() && !hostname.trim().is_empty(),
        "source agent ID and hostname must be nonempty / 元端末のIDと名前が必要です"
    );
    let mut xml = String::new();
    std::fs::File::open(path)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_string(&mut xml)
        .context("expected UTF-8 Sysmon XML / UTF-8形式のSysmon XMLが必要です")?;
    anyhow::ensure!(
        xml.len() <= 64 * 1024 * 1024,
        "XML import limit is 64 MiB; export smaller time ranges"
    );
    let mut reader = quick_xml::Reader::from_str(&xml);
    let agent = AgentInfo { hostname, agent_id };
    let mut start = None;
    let mut depth = 0usize;
    let mut count = 0;
    let mut parsed_events = Vec::new();
    // Validate the entire bounded export before emitting any partial results.
    loop {
        let offset = reader.buffer_position() as usize;
        match reader.read_event().context("malformed XML")? {
            Event::Start(tag) => {
                if tag.local_name().as_ref() == b"Event" {
                    anyhow::ensure!(start.is_none(), "nested Event elements are invalid");
                    start = Some(offset);
                }
                depth += 1;
                anyhow::ensure!(depth <= 18, "XML nesting limit exceeded");
            }
            Event::End(tag) => {
                anyhow::ensure!(depth > 0, "unbalanced XML");
                depth -= 1;
                if tag.local_name().as_ref() == b"Event" {
                    let start = start.take().context("unmatched Event end")?;
                    let event_xml = &xml[start..reader.buffer_position() as usize];
                    let parsed = parse_sysmon_xml(event_xml)
                        .context("invalid Sysmon event; no output emitted")?;
                    if let Some(computer) = parsed.get("System.Computer") {
                        anyhow::ensure!(computer.eq_ignore_ascii_case(&agent.hostname),"System/Computer does not match --hostname; split exports by source host");
                    }
                    parsed_events.push(
                        map_to_threat_event(&parsed, &agent)
                            .context("cannot normalize Sysmon event")?,
                    );
                    count += 1;
                    anyhow::ensure!(
                        count <= 50_000,
                        "XML event limit exceeded; export smaller time ranges"
                    );
                }
            }
            Event::DocType(_) => anyhow::bail!("DTD is not accepted"),
            Event::Eof => break,
            _ => {}
        }
    }
    anyhow::ensure!(
        depth == 0 && start.is_none() && count > 0,
        "no complete Sysmon events found"
    );
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for mut event in parsed_events {
        // GUID-backed enrichment is independent of PID and of file arrival order.
        if let Some(guid) = event.provenance.as_ref().and_then(|p| p.process_guid) {
            event.process_context = Some(ProcessContext {
                process_key: format!("sysmon:{guid}"),
                image_path: None,
                command_line: None,
                user: None,
                integrity_level: None,
                ppid: None,
            });
        }
        serde_json::to_writer(&mut out, &event)?;
        writeln!(out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::*;
    #[test]
    fn replay_runs_same_detector_and_reports_bad_input() {
        let a = sysmon(8, 0, ACTOR);
        let b = sysmon(3, 10, TARGET);
        let input = format!(
            "{}\ninvalid\n{}\n",
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
        let report = analyze(input.as_bytes()).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.malformed_lines, 1);
        assert_eq!(report.agents[&a.agent_id].source_time_events, 2);
        assert!(report
            .limitations
            .contains(&"collection_loss_unknown_without_health"));
    }
    #[test]
    fn old_logs_are_readable_but_not_upgraded_to_source_evidence() {
        let mut e = serde_json::to_value(sysmon(8, 0, ACTOR)).unwrap();
        e.as_object_mut().unwrap().remove("schema_version");
        e.as_object_mut().unwrap().remove("provenance");
        let r = analyze(serde_json::to_vec(&e).unwrap().as_slice()).unwrap();
        assert_eq!(r.analysis.missing_evidence_events, 1);
        assert!(r.findings.is_empty());
    }
    #[test]
    fn oversized_line_fails_explicitly() {
        assert!(analyze(vec![b'x'; 4 * 1024 * 1024 + 1].as_slice()).is_err());
    }
}
