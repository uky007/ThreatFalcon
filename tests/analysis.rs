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
