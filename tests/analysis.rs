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
