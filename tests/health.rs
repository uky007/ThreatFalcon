use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{json, Value};
use std::fs;
use tempfile::TempDir;

fn cmd() -> Command {
    Command::cargo_bin("threatfalcon").unwrap()
}

fn event(agent: &str, timestamp: &str) -> Value {
    json!({
        "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "timestamp": timestamp, "hostname": "TEST", "agent_id": agent,
        "sensor_version": "0.3.0", "source": "Sensor", "category": "Health", "severity": "Info",
        "data": { "type": "SensorHealth", "uptime_secs": 60, "events_total": 42,
            "events_dropped": 0, "collectors": [{ "name": "ETW", "state": "Running" }] }
    })
}

const AGENT: &str = "00000000-0000-0000-0000-000000000001";

#[test]
fn invalid_utf8_tail_does_not_hide_later_health() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    let mut bytes = b"{\"partial\":\"".to_vec();
    bytes.extend_from_slice(&[0xe3, 0x81, b'\n']);
    bytes.extend_from_slice(event(AGENT, "2026-09-12T00:00:00Z").to_string().as_bytes());
    fs::write(&path, bytes).unwrap();
    let output = cmd()
        .args(["health", "--input", path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["skipped_lines"], 1);
    assert_eq!(report["event"]["data"]["events_total"], 42);
}

#[test]
fn health_rejects_oversized_lines_before_unbounded_allocation() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    fs::write(&path, vec![b'x'; 4 * 1024 * 1024 + 1]).unwrap();
    cmd()
        .args(["health", "--input", path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("4 MiB"));
}

#[test]
fn health_explains_recovery_mode_and_failure_in_both_languages() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    let mut sample = event(AGENT, "2026-09-12T00:00:00Z");
    sample["analysis_status"] = json!({"state_restored":true,"restored_timelines":12});
    sample["data"]["collectors"] = json!([{"name":"Sysmon","state":"Error",
        "recovery_mode":"acknowledged_file_checkpoint","checkpoint_committed_events":32,
        "checkpoint_last_commit_at":"2026-09-12T00:00:00Z","error":{"code":"sysmon_recovery_failed"}}]);
    fs::write(&path, sample.to_string()).unwrap();
    for (lang, mode, error) in [
        ("ja", "ファイル保存確認後", "自動リセットしません"),
        (
            "en",
            "Acknowledged file checkpoint",
            "No automatic cursor reset",
        ),
    ] {
        cmd()
            .args(["health", "--input", path.to_str().unwrap(), "--lang", lang])
            .assert()
            .success()
            .stdout(
                predicate::str::contains(mode)
                    .and(predicate::str::contains(error))
                    .and(predicate::str::contains(": 32"))
                    .and(predicate::str::contains(": 12")),
            );
    }
}

#[test]
fn health_reads_legacy_schema_reports_staleness_and_partial_lines() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    fs::write(
        &path,
        format!("{}\n{{\"partial\":", event(AGENT, "2020-01-01T00:00:00Z")),
    )
    .unwrap();
    let output = cmd()
        .args(["health", "--input", path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["stale"], true);
    assert_eq!(report["skipped_lines"], 1);
    assert_eq!(report["event"]["data"]["events_total"], 42);
    assert_eq!(report["event"]["data"]["collectors"][0]["state"], "Running");
}

#[test]
fn health_explains_degraded_collection_in_japanese_and_english() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    let mut sample = event(AGENT, "2020-01-01T00:00:00Z");
    sample["data"]["collectors"] = json!([{
        "name": "ETW", "state": "Degraded", "queue_events_dropped": 2,
        "providers": [{ "name": "restricted-provider", "guid": "test-guid", "enabled": false, "error_code": 5 }],
        "etw": { "events_lost": 3, "log_buffers_lost": 7, "realtime_buffers_lost": 11, "collected_at": "2020-01-01T00:00:00Z" },
        "statistics_error": { "code": "etw_query_failed", "os_code": 5 }
    }]);
    fs::write(&path, sample.to_string()).unwrap();
    cmd()
        .args(["health", "--input", path.to_str().unwrap(), "--lang", "ja"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("収集品質低下")
                .and(predicate::str::contains("有効化失敗"))
                .and(predicate::str::contains("前回の値を保持"))
                .and(predicate::str::contains("リアルタイムバッファ欠落数: 11")),
        );
    cmd()
        .args(["health", "--input", path.to_str().unwrap(), "--lang", "en"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Degraded")
                .and(predicate::str::contains("previous sample retained")),
        );
    let report = |lang| {
        let output = cmd()
            .args([
                "health",
                "--input",
                path.to_str().unwrap(),
                "--lang",
                lang,
                "--json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice::<Value>(&output).unwrap()["event"].clone()
    };
    assert_eq!(report("ja"), report("en"));
}

#[test]
fn combined_logs_require_agent_selection() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    let other = "00000000-0000-0000-0000-000000000002";
    fs::write(
        &path,
        format!(
            "{}\n{}\n",
            event(AGENT, "2020-01-01T00:00:00Z"),
            event(other, "2020-01-01T00:00:01Z")
        ),
    )
    .unwrap();
    cmd()
        .args(["health", "--input", path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--agent-id"));
    let output = cmd()
        .args([
            "health",
            "--input",
            path.to_str().unwrap(),
            "--agent-id",
            AGENT,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["event"]["agent_id"], AGENT);
}

#[test]
fn latest_append_wins_after_clock_adjustment_and_future_clock_is_flagged() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    fs::write(&path, event(AGENT, &future).to_string()).unwrap();
    let output = cmd()
        .args(["health", "--input", path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        serde_json::from_slice::<Value>(&output).unwrap()["clock_skew"],
        true
    );
    fs::write(
        &path,
        format!(
            "{}\n{}\n",
            event(AGENT, &future),
            event(AGENT, "2020-01-01T00:00:00Z")
        ),
    )
    .unwrap();
    let output = cmd()
        .args(["health", "--input", path.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["event"]["timestamp"], "2020-01-01T00:00:00Z");
    assert_eq!(report["clock_skew"], false);
}

#[test]
fn health_does_not_report_success_for_missing_data() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("empty.jsonl");
    fs::write(&path, "").unwrap();
    cmd()
        .args(["health", "--input", path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("No matching SensorHealth"));
}
