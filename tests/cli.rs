use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn cmd() -> Command {
    Command::cargo_bin("threatfalcon").unwrap()
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
