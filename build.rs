//! Build metadata for the sensor.
//!
//! `THREATFALCON_VERSION` is the crate version plus the commit it was built
//! from, as semver build metadata (`0.5.0+443155e`), so a deployed sensor
//! reports exactly which build it runs (`sensor_version` in every event,
//! `--version`, the startup log). The commit comes from
//! `THREATFALCON_BUILD_COMMIT` if set, else from the git checkout the crate
//! is built in. Without either (e.g. a crates.io build) it is just the
//! crate version. Uncommitted changes are not reflected.

use std::path::Path;
use std::process::Command;

fn main() {
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    println!("cargo:rerun-if-env-changed=THREATFALCON_BUILD_COMMIT");

    let commit = match std::env::var("THREATFALCON_BUILD_COMMIT") {
        Ok(c) if !c.trim().is_empty() => short_commit(c.trim()),
        // Only this crate's own checkout: never a repository that happens
        // to contain the build directory.
        _ if Path::new(&manifest_dir).join(".git").exists() => {
            watch_git_head(&manifest_dir);
            git(&manifest_dir, &["rev-parse", "HEAD"]).and_then(|c| short_commit(&c))
        }
        _ => None,
    };
    let full = match commit {
        Some(commit) => format!("{version}+{commit}"),
        None => version,
    };
    println!("cargo:rustc-env=THREATFALCON_VERSION={full}");
}

/// First 7 characters of a hex commit id.
fn short_commit(commit: &str) -> Option<String> {
    let valid = commit.len() >= 7 && commit.bytes().all(|b| b.is_ascii_hexdigit());
    valid.then(|| commit[..7].to_ascii_lowercase())
}

fn git(dir: &str, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}

/// Rebuild when HEAD moves: a checkout (HEAD) or a new commit on the current
/// branch (its ref, loose or packed).
fn watch_git_head(dir: &str) {
    let mut files = vec!["HEAD".to_string(), "packed-refs".to_string()];
    if let Some(reference) = git(dir, &["symbolic-ref", "-q", "HEAD"]) {
        files.push(reference);
    }
    for file in files {
        // Relative to `dir` unless git prints an absolute path
        if let Some(path) = git(dir, &["rev-parse", "--git-path", &file]) {
            let path = Path::new(dir).join(path);
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}
