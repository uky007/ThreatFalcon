//! Independently authored synthetic evidence; no sensor or malware is executed.
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{json, Value};
use tempfile::TempDir;

const AGENT: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const PROVIDER: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
const TARGET: &str = "11111111-1111-1111-1111-111111111111";

fn cmd() -> Command {
    Command::cargo_bin("threatfalcon").unwrap()
}

fn event() -> Value {
    json!({
        "schema_version":2, "id":TARGET, "agent_id":AGENT, "hostname":"SYNTHETIC-WINDOWS",
        "sensor_version":"0.3.0", "timestamp":"2026-09-13T00:00:00Z",
        "source":{"Etw":{"provider":"Microsoft-Windows-DNS-Client"}}, "category":"Telemetry", "severity":"Info",
        "provenance":{"provider_guid":PROVIDER,"event_id":3010,"original_time":true,
            "etw_extended":{
                "capture_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "header_pid":4242,"header_tid":333,
                "requested":{"process_start_key":true,"event_key":true,"stack_trace":true},
                "process_start_key":100,"event_key":200,"stacks":[{
                    "pointer_width":8,"match_id":0,"addresses":[8192,12288],"original_frame_count":2,
                    "locally_truncated":false,"capture_limit_reached":false
                }],"omitted_types":[],"issues":[]
            }
        },
        "process_context":{"process_key":"unverified-legacy-cache"},
        "data":{"type":"NativeTelemetry","pid":4242,"reason":"synthetic","payload_hex":null}
    })
}

fn write(dir: &TempDir, events: &[Value]) -> std::path::PathBuf {
    let path = dir.path().join("events.jsonl");
    let data = events.iter().map(|e| format!("{e}\n")).collect::<String>();
    std::fs::write(&path, data).unwrap();
    path
}

fn run_json(command: &mut Command) -> Value {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn analysis_reports_saved_metadata_and_missing_context_in_both_languages() {
    let dir = TempDir::new().unwrap();
    let first = event();
    let mut second = first.clone();
    second["id"] = "22222222-2222-2222-2222-222222222222".into();
    second["provenance"]["etw_extended"]["process_start_key"] = Value::Null;
    second["provenance"]["etw_extended"]["stacks"] = json!([]);
    second["provenance"]["etw_extended"]["issues"] =
        json!(["stack_unavailable", "process_start_key_unavailable"]);
    let path = write(&dir, &[first, second]);
    let report = run_json(cmd().args(["analyze", "--input", path.to_str().unwrap(), "--json"]));
    let c = &report["agents"][AGENT];
    assert_eq!(c["etw_saved_provider_events"][PROVIDER], 2);
    assert_eq!(c["etw_extended_events"], 2);
    assert_eq!(c["etw_publisher_identity_events"], 1);
    assert_eq!(c["etw_stack_events"], 1);
    assert_eq!(c["etw_saved_stack_frames"], 2);
    assert_eq!(c["etw_metadata_issue_events"], 1);
    assert_eq!(c["recorded_loss_or_degradation"], true);
    assert_eq!(report["malformed_lines"], 0);
    assert!(report["findings"].as_array().unwrap().is_empty());
    for (lang, label) in [
        ("ja", "ETW拡張情報 / 発行元識別"),
        ("en", "ETW extended / publisher identities"),
    ] {
        cmd()
            .args(["analyze", "--input", path.to_str().unwrap(), "--lang", lang])
            .assert()
            .success()
            .stdout(
                predicate::str::contains(label).and(predicate::str::contains("2 / 1 / 1 / 2 / 1")),
            );
    }
}

#[test]
fn query_preserves_extensions_with_and_without_index() {
    let dir = TempDir::new().unwrap();
    let original = event();
    let path = write(&dir, &[original.clone()]);
    for no_index in [true, false] {
        let mut command = cmd();
        command.args([
            "query",
            "--input",
            path.to_str().unwrap(),
            "--source",
            "etw",
        ]);
        if no_index {
            command.arg("--no-index");
        }
        let queried = run_json(&mut command);
        assert_eq!(
            queried["provenance"]["etw_extended"],
            original["provenance"]["etw_extended"]
        );
    }
}

#[test]
fn publisher_activity_does_not_cross_lifetimes_agents_or_actor_semantics() {
    let dir = TempDir::new().unwrap();
    let target = event();
    let mut same = target.clone();
    same["id"] = "22222222-2222-2222-2222-222222222222".into();
    // Same publisher, DIFFERENT payload process. The actor PID index must not
    // hide this event or turn it into the publisher's process creation.
    same["data"] = json!({"type":"ProcessCreate","pid":555,"ppid":444,"image_path":"owned.exe",
        "command_line":"", "user":"", "integrity_level":"", "hashes":null,"create_time":null});
    same["category"] = "Process".into();
    let mut records = vec![target.clone(), same];
    for n in 3..=7 {
        let mut other = target.clone();
        other["id"] = format!("{n:08x}-0000-0000-0000-000000000000").into();
        match n {
            3 => other["provenance"]["etw_extended"]["process_start_key"] = 101.into(),
            4 => {
                other["provenance"]["etw_extended"]["capture_id"] =
                    "cccccccc-cccc-cccc-cccc-cccccccccccc".into()
            }
            5 => other["agent_id"] = "dddddddd-dddd-dddd-dddd-dddddddddddd".into(),
            6 => {
                other["provenance"]
                    .as_object_mut()
                    .unwrap()
                    .remove("etw_extended");
            }
            _ => other["timestamp"] = "2026-09-12T00:00:00Z".into(),
        }
        records.push(other);
    }
    let path = write(&dir, &records);
    for no_index in [true, false] {
        let mut command = cmd();
        command.args([
            "explain",
            "--input",
            path.to_str().unwrap(),
            "--event",
            TARGET,
            "--json",
        ]);
        if no_index {
            command.arg("--no-index");
        }
        let output = run_json(&mut command);
        assert!(output["timeline"].as_array().unwrap().is_empty());
        assert!(output.get("process_key").is_none());
        assert_eq!(output["publisher_activity"]["matched_events"], 2);
        assert_eq!(
            output["publisher_activity"]["events"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(output["publisher_activity"]["truncated"], false);
        assert_eq!(output["publisher_activity"]["identity"]["pid"], 4242);
        let mut command = cmd();
        command.args([
            "bundle",
            "--input",
            path.to_str().unwrap(),
            "--event",
            TARGET,
        ]);
        if no_index {
            command.arg("--no-index");
        }
        let bundled = run_json(&mut command);
        assert_eq!(bundled["event_count"], 1);
        assert_eq!(
            bundled["target_event"]["provenance"]["etw_extended"],
            target["provenance"]["etw_extended"]
        );
    }
}

#[test]
fn missing_publisher_key_does_not_fall_back_to_cached_key_or_pid() {
    let dir = TempDir::new().unwrap();
    let mut target = event();
    target["provenance"]["etw_extended"]["process_start_key"] = Value::Null;
    let path = write(&dir, &[target]);
    let output = run_json(cmd().args([
        "explain",
        "--input",
        path.to_str().unwrap(),
        "--event",
        TARGET,
        "--json",
    ]));
    assert!(output.get("publisher_activity").is_none());
    assert!(output.get("process_key").is_none());
    assert!(output["timeline"].as_array().unwrap().is_empty());
}

#[test]
fn publisher_activity_has_an_explicit_output_limit() {
    let dir = TempDir::new().unwrap();
    let mut records = vec![event()];
    for n in 0..260 {
        let mut e = event();
        e["id"] = format!("{n:08x}-0000-0000-0000-000000000000").into();
        records.push(e);
    }
    let path = write(&dir, &records);
    let output = run_json(cmd().args([
        "explain",
        "--input",
        path.to_str().unwrap(),
        "--event",
        TARGET,
        "--json",
    ]));
    assert_eq!(output["publisher_activity"]["matched_events"], 261);
    assert_eq!(
        output["publisher_activity"]["events"]
            .as_array()
            .unwrap()
            .len(),
        256
    );
    assert_eq!(output["publisher_activity"]["truncated"], true);
}

#[test]
fn health_observation_counts_are_not_treated_as_saved_events_or_coverage() {
    let dir = TempDir::new().unwrap();
    let mut health = event();
    health.as_object_mut().unwrap().remove("provenance");
    health["source"] = "Sensor".into();
    health["category"] = "Health".into();
    health["data"] = json!({"type":"SensorHealth","uptime_secs":30,"events_total":0,"events_dropped":0,
    "collectors":[{"name":"ETW","state":"Running","providers":[{
        "name":"owned-provider","guid":PROVIDER,"enabled":true,
        "telemetry":{"requested":{"stack_trace":true},"observed":1000,"normalized":600,
            "queue_admitted":900,"queue_dropped":100,"metadata_issue_events":1}
    }]}]});
    let path = write(&dir, &[health]);
    for (lang, label) in [
        ("ja", "永続保存数ではありません"),
        ("en", "not durable-save counts"),
    ] {
        cmd()
            .args(["health", "--input", path.to_str().unwrap(), "--lang", lang])
            .assert()
            .success()
            .stdout(
                predicate::str::contains(label)
                    .and(predicate::str::contains("1000 / 600 / 900 / 100")),
            );
    }
    let report = run_json(cmd().args(["analyze", "--input", path.to_str().unwrap(), "--json"]));
    assert_eq!(report["agents"][AGENT]["etw_extended_events"], 0);
    assert_eq!(report["agents"][AGENT]["etw_coverage_unverified"], true);
    assert!(report["agents"][AGENT]["etw_saved_provider_events"]
        .as_object()
        .unwrap()
        .is_empty());
    assert_eq!(
        report["agents"][AGENT]["recorded_loss_or_degradation"],
        true
    );
}
