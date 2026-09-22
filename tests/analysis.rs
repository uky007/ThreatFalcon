use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn cmd() -> Command {
    Command::cargo_bin("threatfalcon").unwrap()
}
fn import() -> std::process::Output {
    cmd()
        .args([
            "import-sysmon",
            "--input",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/sysmon-correlation.xml"
            ),
            "--agent-id",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "--hostname",
            "synthetic-fixture",
        ])
        .output()
        .unwrap()
}

#[test]
fn imported_xml_roundtrips_through_correlation_in_both_languages() {
    let output = import();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events: Vec<serde_json::Value> = String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["provenance"]["record_id"], 100);
    assert_eq!(events[0]["schema_version"], 2);
    assert_ne!(events[0]["timestamp"], events[0]["observed_at"]);
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    std::fs::write(&path, output.stdout).unwrap();
    let result = cmd()
        .args(["analyze", "--input", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["findings"][0]["data"]["evidence_ids"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    for (lang, text) in [
        ("ja", "リモートスレッド生成後"),
        ("en", "Remote thread followed"),
    ] {
        cmd()
            .args(["analyze", "--input", path.to_str().unwrap(), "--lang", lang])
            .assert()
            .success()
            .stdout(predicate::str::contains(text));
    }
}

#[test]
fn import_rejects_wrong_host_without_partial_output() {
    cmd()
        .args([
            "import-sysmon",
            "--input",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/sysmon-correlation.xml"
            ),
            "--agent-id",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "--hostname",
            "different-host",
        ])
        .assert()
        .failure()
        .stdout("")
        .stderr(predicate::str::contains("does not match"));
}

#[test]
fn empty_analysis_is_not_a_clean_bill_of_health() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("empty.jsonl");
    std::fs::write(&path, "").unwrap();
    cmd()
        .args(["analyze", "--input", path.to_str().unwrap(), "--lang", "ja"])
        .assert()
        .success()
        .stdout(predicate::str::contains("検知ゼロは安全を意味しません"));
}

#[test]
fn rule_input_reports_do_not_merge_agents_or_claim_detection_readiness() {
    let imported = import();
    assert!(imported.status.success());
    let mut events: Vec<serde_json::Value> = String::from_utf8(imported.stdout).unwrap()
        .lines().map(|s| serde_json::from_str(s).unwrap()).collect();
    let agent_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let agent_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    events[2]["agent_id"] = agent_b.into();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agents.jsonl");
    std::fs::write(&path, events.iter().map(|e| format!("{e}\n")).collect::<String>()).unwrap();
    let output = cmd().args(["analyze", "--input", path.to_str().unwrap(), "--json"]).output().unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let a = &report["agents"][agent_a]["rule_inputs"];
    let b = &report["agents"][agent_b]["rule_inputs"];
    assert_eq!(a[0]["unobserved_required_event_ids"], serde_json::json!([3]));
    assert_eq!(b[0]["unobserved_required_event_ids"], serde_json::json!([8]));
    assert_eq!(b[2]["state"], "required_types_observed");
    assert_eq!(b[2]["coverage_verified"], false);
    assert_eq!(b[2]["observed_input_counts"]["3"], 1);
    assert!(report["findings"].as_array().unwrap().is_empty()); // one connection is not periodicity
    for (lang, text) in [("ja", "証拠不足"), ("en", "Insufficient evidence")] {
        cmd().args(["analyze", "--input", path.to_str().unwrap(), "--lang", lang])
            .assert().success().stdout(predicate::str::contains(text));
    }
}

#[test]
fn raw_sysmon_event_ids_do_not_substitute_for_usable_input() {
    let imported = import();
    assert!(imported.status.success());
    let mut events: Vec<serde_json::Value> = String::from_utf8(imported.stdout).unwrap()
        .lines().map(|s| serde_json::from_str(s).unwrap()).collect();
    events[1]["provenance"]["target_process_guid"] = serde_json::Value::Null;
    events[2]["provenance"]["original_time"] = false.into();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("incomplete.jsonl");
    std::fs::write(&path, events.iter().map(|e| format!("{e}\n")).collect::<String>()).unwrap();
    let output = cmd().args(["analyze", "--input", path.to_str().unwrap(), "--json"]).output().unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let agent = &report["agents"]["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"];
    assert_eq!(agent["sysmon_event_ids"]["8"], 1);
    assert_eq!(agent["rule_inputs"][0]["unobserved_required_event_ids"], serde_json::json!([8, 3]));
    assert_eq!(agent["rule_inputs"][0]["state"], "insufficient_evidence");
}

#[test]
fn powershell_fragment_analysis_is_bilingual_and_legacy_position_is_unknown() {
    use serde_json::json;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("scripts.jsonl");
    let mut event = json!({
        "id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "agent_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "hostname":"synthetic-windows", "sensor_version":"0.3.0", "timestamp":"2026-09-13T00:00:00Z",
        "source":{"Etw":{"provider":"PowerShellCore"}}, "category":"Script", "severity":"Info",
        "data":{"type":"ScriptBlock","pid":4242,"script_engine":"PowerShellCore","content":"Write-Output 'test'",
            "script_block_id":"cccccccc-cccc-cccc-cccc-cccccccccccc", "message_number":1,"message_total":2}
    });
    let first = event.to_string();
    event["id"] = "dddddddd-dddd-dddd-dddd-dddddddddddd".into();
    event["data"]
        .as_object_mut()
        .unwrap()
        .remove("message_number");
    event["data"]
        .as_object_mut()
        .unwrap()
        .remove("message_total");
    std::fs::write(&path, format!("{first}\n{event}\n")).unwrap();
    for (lang, label) in [
        ("ja", "再構成・実行成功の保証なし"),
        ("en", "no reassembly or execution guarantee"),
    ] {
        cmd()
            .args(["analyze", "--input", path.to_str().unwrap(), "--lang", lang])
            .assert()
            .success()
            .stdout(predicate::str::contains(label).and(predicate::str::contains("0 / 1 / 1 / 0")));
    }
    for no_index in [true, false] {
        let mut command = cmd();
        command.args([
            "query",
            "--input",
            path.to_str().unwrap(),
            "--source",
            "PowerShellCore",
            "--pid",
            "4242",
        ]);
        if no_index {
            command.arg("--no-index");
        }
        command
            .assert()
            .success()
            .stdout(predicate::str::contains("message_number"));
    }
    let result = cmd()
        .args(["analyze", "--input", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["malformed_lines"], 0);
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert_eq!(
        report["agents"]["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"]
            ["script_fragment_position_unknown"],
        1
    );
}

#[test]
fn powershell_native_explain_never_makes_a_pid_only_process_timeline() {
    use serde_json::json;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("native-scripts.jsonl");
    let target_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let target = json!({
        "id":target_id,"agent_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "hostname":"synthetic-windows","sensor_version":"0.3.0","timestamp":"2026-09-13T00:00:00Z",
        "source":{"Etw":{"provider":"PowerShellCore"}},"category":"Script","severity":"Info",
        "provenance":{"provider_guid":"f90714a8-5509-434a-bf6d-b1624c8a19a2","event_id":4104,"original_time":true},
        "process_context":{"process_key":"unverified-legacy-cache"},
        "data":{"type":"ScriptBlock","pid":4242,"script_engine":"PowerShellCore","content":"Write-Output 'test'",
            "script_block_id":"cccccccc-cccc-cccc-cccc-cccccccccccc","message_number":1,"message_total":2}
    });
    let mut second = target.clone();
    second["id"] = "dddddddd-dddd-dddd-dddd-dddddddddddd".into();
    second["data"]["message_number"] = 2.into();
    let mut other = target.clone();
    other["id"] = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee".into();
    other["agent_id"] = "ffffffff-ffff-ffff-ffff-ffffffffffff".into();
    let mut amsi = target.clone();
    amsi["id"] = "11111111-1111-1111-1111-111111111111".into();
    amsi.as_object_mut().unwrap().remove("provenance");
    amsi["data"] = json!({"type":"AmsiScan","pid":4242,"app_name":"PowerShell","content_name":"test","content_size":4,"scan_result":0});
    std::fs::write(&path, format!("{target}\n{second}\n{other}\n{amsi}\n")).unwrap();
    for no_index in [true, false] {
        let mut command = cmd();
        command.args([
            "explain",
            "--input",
            path.to_str().unwrap(),
            "--event",
            target_id,
            "--json",
        ]);
        if no_index {
            command.arg("--no-index");
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let output: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(output["timeline"].as_array().unwrap().is_empty());
        assert!(output.get("process_key").is_none());
        assert_eq!(output["script_amsi_activity"].as_array().unwrap().len(), 2);
        assert!(output["script_amsi_activity"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["agent_id"] == target["agent_id"] && e["data"]["type"] == "ScriptBlock"));
    }
}

#[test]
fn wfp_audit_is_queryable_but_never_a_flow_or_threat_verdict() {
    use serde_json::json;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("wfp.jsonl");
    let event = json!({
        "id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "agent_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "hostname":"synthetic-windows", "sensor_version":"0.3.0", "timestamp":"2026-09-13T00:00:00Z",
        "source":{"WindowsSecurity":{"event_id":5157}}, "category":"Network", "severity":"Info",
        "data":{"type":"WfpConnectionAudit", "record":{
            "decision":"Blocked", "pid":4242, "application":"synthetic.exe", "source_address":"192.0.2.1",
            "source_port":51000, "destination_address":"198.51.100.2", "destination_port":443,
            "protocol":6, "direction_token":"%%14592", "filter_runtime_id":1,"layer_runtime_id":48,"omitted_fields":[]
        }}
    });
    std::fs::write(&path, format!("{event}\n")).unwrap();
    for (lang, explanation) in [
        ("ja", "接続認可のみ・監査設定と網羅性は未確認"),
        ("en", "authorization only; policy/coverage unverified"),
    ] {
        cmd()
            .args(["analyze", "--input", path.to_str().unwrap(), "--lang", lang])
            .assert()
            .success()
            .stdout(
                predicate::str::contains(explanation).and(predicate::str::contains(
                    "wfp_audit_detection_rules_not_implemented",
                )),
            );
    }
    for indexed in [false, true] {
        let mut command = cmd();
        command.args([
            "query",
            "--input",
            path.to_str().unwrap(),
            "--source",
            "windowssecurity",
            "--pid",
            "4242",
        ]);
        if !indexed {
            command.arg("--no-index");
        }
        command
            .assert()
            .success()
            .stdout(predicate::str::contains("WfpConnectionAudit"));
    }
    let result = cmd()
        .args(["analyze", "--input", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert_eq!(report["analysis"]["eligible_events"], 0);
    assert_eq!(report["malformed_lines"], 0);
}

#[test]
fn linux_audit_is_queryable_and_analysis_limits_are_bilingual() {
    use serde_json::json;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("linux.jsonl");
    let event = json!({
        "id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "agent_id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "hostname":"synthetic-linux", "sensor_version":"0.3.0", "timestamp":"2026-09-13T00:00:00Z",
        "source":"LinuxAudit", "category":"Process", "severity":"Info",
        "data":{"type":"LinuxAudit", "record":{
            "boot_id":"cccccccc-cccc-cccc-cccc-cccccccccccc", "collection_session_uuid":"dddddddd-dddd-dddd-dddd-dddddddddddd",
            "transport":"netlink_multicast", "stamp":{"seconds":1789257600,"nanoseconds":0,"serial":42},
            "completion":"end_of_event", "issues":[], "records":[{
                "native_type":1300,"fields":{"pid":{"value":"42","audit_hex_encoded":false}},"omitted_fields":[],"issues":[]
            }]
        }}
    });
    std::fs::write(&path, format!("{event}\n")).unwrap();
    for (lang, explanation) in [
        ("ja", "検知ルールは未実装・PID相関なし"),
        ("en", "no detection rules or PID-only correlation"),
    ] {
        cmd()
            .args(["analyze", "--input", path.to_str().unwrap(), "--lang", lang])
            .assert()
            .success()
            .stdout(
                predicate::str::contains(explanation).and(predicate::str::contains(
                    "linux_audit_policy_and_total_kernel_loss_not_verified",
                )),
            );
    }
    cmd()
        .args([
            "query",
            "--input",
            path.to_str().unwrap(),
            "--source",
            "linuxaudit",
            "--pid",
            "42",
            "--no-index",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("LinuxAudit"));
}
