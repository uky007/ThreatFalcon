use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn cmd() -> Command {
    Command::cargo_bin("threatfalcon").unwrap()
}

/// Minimal valid JSONL event for investigation CLI tests.
/// Fields are hand-crafted to avoid pulling in the library crate.
fn sample_event(id: &str, pid: u32, process_key: &str, category: &str) -> String {
    format!(
        r#"{{"id":"{id}","timestamp":"2026-03-13T10:00:00Z","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":{{"Etw":{{"provider":"Microsoft-Windows-Kernel-Network"}}}},"category":"{category}","severity":"Info","data":{{"type":"NetworkConnect","pid":{pid},"image_path":"","protocol":"TCP","src_addr":"10.0.0.1","src_port":12345,"dst_addr":"93.184.216.34","dst_port":443,"direction":"Outbound"}},"process_context":{{"process_key":"{process_key}"}}}}"#
    )
}

fn sample_detection_event(id: &str, rule_id: &str) -> String {
    format!(
        r#"{{"id":"{id}","timestamp":"2026-03-13T10:00:00Z","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":"EvasionDetector","category":"Evasion","severity":"High","data":{{"type":"EvasionDetected","technique":"EtwPatching","pid":100,"process_name":"malware.exe","details":"patched"}},"rule":{{"id":"{rule_id}","name":"Test","description":"test","mitre":{{"tactic":"Defense Evasion","technique_id":"T1562.006","technique_name":"Indicator Blocking"}},"confidence":"High","evidence":["byte 0xC3"]}}}}"#
    )
}

#[test]
fn help_flag() {
    cmd().arg("--help").assert().success().stdout(
        predicate::str::contains("--config")
            .and(predicate::str::contains("--stdout"))
            .and(predicate::str::contains("--output"))
            .and(predicate::str::contains("--validate-config"))
            .and(predicate::str::contains("--dump-default-config")),
    );
}

#[test]
fn version_flag() {
    cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn dump_default_config() {
    cmd()
        .arg("--dump-default-config")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("hostname")
                .and(predicate::str::contains("[output]"))
                .and(predicate::str::contains("[collectors.etw]"))
                .and(predicate::str::contains("[collectors.sysmon]"))
                .and(predicate::str::contains("[collectors.evasion]")),
        );
}

#[test]
fn dump_default_config_is_valid_toml() {
    let output = cmd()
        .arg("--dump-default-config")
        .output()
        .unwrap();
    assert!(output.status.success());
    let toml_str = String::from_utf8(output.stdout).unwrap();
    // Must parse back as valid TOML
    let _: toml::Value = toml::from_str(&toml_str).expect("dump output should be valid TOML");
}

#[test]
fn validate_config_with_valid_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("valid.toml");
    fs::write(&path, "hostname = \"TEST\"\n").unwrap();

    cmd()
        .args(["--config", path.to_str().unwrap(), "--validate-config"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Config is valid"));
}

#[test]
fn validate_config_with_invalid_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("bad.toml");
    fs::write(&path, "invalid = [[[broken").unwrap();

    cmd()
        .args(["--config", path.to_str().unwrap(), "--validate-config"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("validation failed"));
}

#[test]
fn validate_config_missing_file_errors() {
    cmd()
        .args(["--config", "/nonexistent/path.toml", "--validate-config"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn stdout_and_output_conflict() {
    cmd()
        .args(["--stdout", "--output", "out.jsonl"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn service_flags_shown_in_help() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--service")
                .and(predicate::str::contains("--install-service"))
                .and(predicate::str::contains("--uninstall-service")),
        );
}

#[test]
fn service_and_stdout_conflict() {
    cmd()
        .args(["--service", "--stdout"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn service_and_output_conflict() {
    cmd()
        .args(["--service", "--output", "out.jsonl"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
#[cfg(not(target_os = "windows"))]
fn service_flag_rejected_on_non_windows() {
    cmd()
        .arg("--service")
        .assert()
        .failure()
        .stderr(predicate::str::contains("only supported on Windows"));
}

#[test]
#[cfg(not(target_os = "windows"))]
fn install_service_rejected_on_non_windows() {
    cmd()
        .arg("--install-service")
        .assert()
        .failure()
        .stderr(predicate::str::contains("only supported on Windows"));
}

#[test]
#[cfg(not(target_os = "windows"))]
fn uninstall_service_rejected_on_non_windows() {
    cmd()
        .arg("--uninstall-service")
        .assert()
        .failure()
        .stderr(predicate::str::contains("only supported on Windows"));
}

#[test]
fn install_service_conflicts_with_stdout() {
    cmd()
        .args(["--install-service", "--stdout"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn uninstall_service_conflicts_with_service() {
    cmd()
        .args(["--uninstall-service", "--service"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

// ---- Investigation CLI tests ------------------------------------------------

#[test]
fn help_shows_subcommands() {
    cmd().arg("--help").assert().success().stdout(
        predicate::str::contains("query")
            .and(predicate::str::contains("explain"))
            .and(predicate::str::contains("bundle")),
    );
}

#[test]
fn query_help() {
    cmd().args(["query", "--help"]).assert().success().stdout(
        predicate::str::contains("--input")
            .and(predicate::str::contains("--pid"))
            .and(predicate::str::contains("--process-key"))
            .and(predicate::str::contains("--category"))
            .and(predicate::str::contains("--rule-id"))
            .and(predicate::str::contains("--since"))
            .and(predicate::str::contains("--limit")),
    );
}

#[test]
fn explain_help() {
    cmd().args(["explain", "--help"]).assert().success().stdout(
        predicate::str::contains("--event")
            .and(predicate::str::contains("--input"))
            .and(predicate::str::contains("--window")),
    );
}

#[test]
fn bundle_help() {
    cmd().args(["bundle", "--help"]).assert().success().stdout(
        predicate::str::contains("--event")
            .and(predicate::str::contains("--input"))
            .and(predicate::str::contains("--window"))
            .and(predicate::str::contains("--output")),
    );
}

#[test]
fn query_returns_matching_events() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network"),
        sample_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 200, "200:43", "Network"),
        sample_event("cccccccc-cccc-cccc-cccc-cccccccccccc", 100, "100:42", "Network"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args(["query", "--input", path.to_str().unwrap(), "--pid", "100"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("aaaaaaaa")
                .and(predicate::str::contains("cccccccc"))
                .and(predicate::str::contains("bbbbbbbb").not()),
        )
        .stderr(predicate::str::contains("2 event(s) matched"));
}

#[test]
fn query_filter_by_category() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network"),
        sample_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 200, "200:43", "File"),
    ];
    // Fix File category event to have FileCreate data
    let file_event = r#"{"id":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","timestamp":"2026-03-13T10:00:00Z","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":{"Etw":{"provider":"Microsoft-Windows-Kernel-File"}},"category":"File","severity":"Info","data":{"type":"FileCreate","pid":200,"path":"C:\\test.txt","operation":"Create"},"process_context":{"process_key":"200:43"}}"#;
    fs::write(&path, format!("{}\n{file_event}\n", lines[0])).unwrap();

    cmd()
        .args([
            "query",
            "--input",
            path.to_str().unwrap(),
            "--category",
            "network",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("aaaaaaaa"))
        .stderr(predicate::str::contains("1 event(s) matched"));
}

#[test]
fn query_filter_by_rule_id() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network"),
        sample_detection_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "TF-EVA-001"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args([
            "query",
            "--input",
            path.to_str().unwrap(),
            "--rule-id",
            "TF-EVA-001",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("bbbbbbbb"))
        .stderr(predicate::str::contains("1 event(s) matched"));
}

#[test]
fn query_empty_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("empty.jsonl");
    fs::write(&path, "").unwrap();

    cmd()
        .args(["query", "--input", path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("0 event(s) matched"));
}

#[test]
fn query_missing_file() {
    cmd()
        .args(["query", "--input", "/nonexistent/file.jsonl"])
        .assert()
        .failure();
}

#[test]
fn explain_shows_event_detail() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let event_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let lines = [
        sample_event(event_id, 100, "100:42", "Network"),
        sample_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 100, "100:42", "Network"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args([
            "explain",
            "--event",
            event_id,
            "--input",
            path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("=== Target Event ===")
                .and(predicate::str::contains(event_id))
                .and(predicate::str::contains("=== Process Timeline")),
        );
}

#[test]
fn explain_prefix_match() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let event = sample_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network");
    fs::write(&path, &event).unwrap();

    cmd()
        .args([
            "explain",
            "--event",
            "aaaaaaaa", // prefix
            "--input",
            path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
}

#[test]
fn explain_event_not_found() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let event = sample_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network");
    fs::write(&path, &event).unwrap();

    cmd()
        .args([
            "explain",
            "--event",
            "nonexistent",
            "--input",
            path.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn bundle_to_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    let output = dir.path().join("bundle.json");

    let event_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let lines = [
        sample_event(event_id, 100, "100:42", "Network"),
        sample_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 100, "100:42", "Network"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args([
            "bundle",
            "--event",
            event_id,
            "--input",
            path.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Bundle written to"));

    let content = fs::read_to_string(&output).unwrap();
    assert!(content.contains("\"bundle_version\""));
    assert!(content.contains(event_id));
    assert!(content.contains("\"related_events\""));
}

#[test]
fn bundle_to_stdout() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let event_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let event = sample_event(event_id, 100, "100:42", "Network");
    fs::write(&path, &event).unwrap();

    cmd()
        .args([
            "bundle",
            "--event",
            event_id,
            "--input",
            path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("\"bundle_version\"")
                .and(predicate::str::contains(event_id)),
        );
}

#[test]
fn bundle_to_zip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    let zip_output = dir.path().join("bundle.zip");

    let event_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let lines = [
        sample_event(event_id, 100, "100:42", "Network"),
        sample_event(
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            100,
            "100:42",
            "Network",
        ),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args([
            "bundle",
            "--event",
            event_id,
            "--input",
            path.to_str().unwrap(),
            "--output",
            zip_output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("Bundle written to")
                .and(predicate::str::contains("zip")),
        );

    // Verify it's a valid zip with the expected entries
    let file = fs::File::open(&zip_output).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    assert_eq!(archive.len(), 4);

    for name in ["manifest.json", "target_event.json", "related_events.jsonl", "bundle.json"] {
        assert!(archive.by_name(name).is_ok(), "missing zip entry: {name}");
    }
}

// ---- PR #27: Investigation CLI filter extension tests -----------------------

fn sample_etw_event(id: &str, pid: u32, process_key: &str, category: &str, severity: &str, timestamp: &str) -> String {
    format!(
        r#"{{"id":"{id}","timestamp":"{timestamp}","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":{{"Etw":{{"provider":"Microsoft-Windows-Kernel-Network"}}}},"category":"{category}","severity":"{severity}","data":{{"type":"NetworkConnect","pid":{pid},"image_path":"","protocol":"TCP","src_addr":"10.0.0.1","src_port":12345,"dst_addr":"93.184.216.34","dst_port":443,"direction":"Outbound"}},"process_context":{{"process_key":"{process_key}"}}}}"#
    )
}

fn sample_evasion_event(id: &str, severity: &str, timestamp: &str) -> String {
    format!(
        r#"{{"id":"{id}","timestamp":"{timestamp}","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":"EvasionDetector","category":"Evasion","severity":"{severity}","data":{{"type":"EvasionDetected","technique":"EtwPatching","pid":100,"process_name":"malware.exe","details":"patched"}},"rule":{{"id":"TF-EVA-001","name":"Test","description":"test","mitre":{{"tactic":"Defense Evasion","technique_id":"T1562.006","technique_name":"Indicator Blocking"}},"confidence":"High","evidence":["byte 0xC3"]}}}}"#
    )
}

#[test]
fn query_filter_by_source_etw() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z"),
        sample_evasion_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "High", "2026-03-13T10:01:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args(["query", "--input", path.to_str().unwrap(), "--source", "etw"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("aaaaaaaa")
                .and(predicate::str::contains("bbbbbbbb").not()),
        )
        .stderr(predicate::str::contains("1 event(s) matched"));
}

#[test]
fn query_filter_by_source_evasion() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z"),
        sample_evasion_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "High", "2026-03-13T10:01:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args(["query", "--input", path.to_str().unwrap(), "--source", "evasion"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("bbbbbbbb")
                .and(predicate::str::contains("aaaaaaaa").not()),
        )
        .stderr(predicate::str::contains("1 event(s) matched"));
}

#[test]
fn query_filter_by_severity() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z"),
        sample_evasion_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "High", "2026-03-13T10:01:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args(["query", "--input", path.to_str().unwrap(), "--severity", "high"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("bbbbbbbb")
                .and(predicate::str::contains("aaaaaaaa").not()),
        )
        .stderr(predicate::str::contains("1 event(s) matched"));
}

#[test]
fn query_filter_by_contains() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z"),
        sample_evasion_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "High", "2026-03-13T10:01:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args(["query", "--input", path.to_str().unwrap(), "--contains", "malware.exe"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("bbbbbbbb")
                .and(predicate::str::contains("aaaaaaaa").not()),
        )
        .stderr(predicate::str::contains("1 event(s) matched"));
}

#[test]
fn query_filter_by_from_to() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network", "Info", "2026-03-13T09:00:00Z"),
        sample_etw_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 200, "200:43", "Network", "Info", "2026-03-13T11:00:00Z"),
        sample_etw_event("cccccccc-cccc-cccc-cccc-cccccccccccc", 300, "300:44", "Network", "Info", "2026-03-13T13:00:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    // Only events between 10:00 and 12:00
    cmd()
        .args([
            "query",
            "--input", path.to_str().unwrap(),
            "--from", "2026-03-13T10:00:00Z",
            "--to", "2026-03-13T12:00:00Z",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("bbbbbbbb")
                .and(predicate::str::contains("aaaaaaaa").not())
                .and(predicate::str::contains("cccccccc").not()),
        )
        .stderr(predicate::str::contains("1 event(s) matched"));
}

#[test]
fn query_since_alias_works() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network", "Info", "2026-03-13T09:00:00Z"),
        sample_etw_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 200, "200:43", "Network", "Info", "2026-03-13T11:00:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    // --since is an alias for --from
    cmd()
        .args([
            "query",
            "--input", path.to_str().unwrap(),
            "--since", "2026-03-13T10:00:00Z",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("bbbbbbbb"))
        .stderr(predicate::str::contains("1 event(s) matched"));
}

#[test]
fn query_help_shows_new_flags() {
    cmd().args(["query", "--help"]).assert().success().stdout(
        predicate::str::contains("--source")
            .and(predicate::str::contains("--severity"))
            .and(predicate::str::contains("--contains"))
            .and(predicate::str::contains("--from"))
            .and(predicate::str::contains("--to")),
    );
}

#[test]
fn explain_json_output() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let event_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let lines = [
        sample_etw_event(event_id, 100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z"),
        sample_etw_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 100, "100:42", "Network", "Info", "2026-03-13T10:01:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args([
            "explain",
            "--event", event_id,
            "--input", path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    // Must be valid JSON with expected fields
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("explain --json should output valid JSON");
    assert!(json.get("target_event").is_some());
    assert!(json.get("timeline").is_some());
    assert!(json.get("window_minutes").is_some());
}

#[test]
fn explain_help_shows_json_flag() {
    cmd().args(["explain", "--help"]).assert().success().stdout(
        predicate::str::contains("--json"),
    );
}

// ---- Index subcommand tests -------------------------------------------------

#[test]
fn index_help() {
    cmd().args(["index", "--help"]).assert().success().stdout(
        predicate::str::contains("--input")
            .and(predicate::str::contains("--rebuild"))
            .and(predicate::str::contains("--status")),
    );
}

#[test]
fn help_shows_index_subcommand() {
    cmd().arg("--help").assert().success().stdout(
        predicate::str::contains("index"),
    );
}

#[test]
fn index_build_creates_index_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    let event = sample_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network");
    fs::write(&path, &event).unwrap();

    cmd()
        .args(["index", "--input", path.to_str().unwrap()])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("Indexed")
                .and(predicate::str::contains("1 new event(s)"))
                .and(predicate::str::contains("1 total")),
        );

    // Verify index file was created
    let idx_path = format!("{}.idx.sqlite", path.display());
    assert!(std::path::Path::new(&idx_path).exists(), "index file should be created");
}

#[test]
fn index_status_shows_health() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network"),
        sample_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 200, "200:43", "Network"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    // Build first
    cmd()
        .args(["index", "--input", path.to_str().unwrap()])
        .assert()
        .success();

    // Check status
    cmd()
        .args(["index", "--input", path.to_str().unwrap(), "--status"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("Events:")
                .and(predicate::str::contains("2"))
                .and(predicate::str::contains("current")),
        );
}

#[test]
fn index_rebuild_reindexes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    let event = sample_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network");
    fs::write(&path, &event).unwrap();

    // Build
    cmd()
        .args(["index", "--input", path.to_str().unwrap()])
        .assert()
        .success();

    // Rebuild
    cmd()
        .args(["index", "--input", path.to_str().unwrap(), "--rebuild"])
        .assert()
        .success()
        .stderr(predicate::str::contains("1 new event(s)"));
}

#[test]
fn query_with_index_returns_same_results() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z"),
        sample_evasion_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "High", "2026-03-13T10:01:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    // Build index
    cmd()
        .args(["index", "--input", path.to_str().unwrap()])
        .assert()
        .success();

    // Query with index (--severity high should return only the evasion event)
    cmd()
        .args(["query", "--input", path.to_str().unwrap(), "--severity", "high"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("bbbbbbbb")
                .and(predicate::str::contains("aaaaaaaa").not()),
        )
        .stderr(predicate::str::contains("1 event(s) matched (indexed)"));
}

#[test]
fn query_no_index_forces_scan() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z"),
        sample_evasion_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "High", "2026-03-13T10:01:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    // Build index
    cmd()
        .args(["index", "--input", path.to_str().unwrap()])
        .assert()
        .success();

    // Query with --no-index should use full scan (no "(indexed)" in output)
    cmd()
        .args(["query", "--input", path.to_str().unwrap(), "--severity", "high", "--no-index"])
        .assert()
        .success()
        .stdout(predicate::str::contains("bbbbbbbb"))
        .stderr(
            predicate::str::contains("1 event(s) matched")
                .and(predicate::str::contains("indexed").not()),
        );
}

#[test]
fn query_no_index_flag_shown_in_help() {
    cmd().args(["query", "--help"]).assert().success().stdout(
        predicate::str::contains("--no-index"),
    );
    cmd().args(["explain", "--help"]).assert().success().stdout(
        predicate::str::contains("--no-index"),
    );
    cmd().args(["bundle", "--help"]).assert().success().stdout(
        predicate::str::contains("--no-index"),
    );
}
