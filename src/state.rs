//! Persistent agent state.
//!
//! On first run a random `agent_id` (UUID v4) is generated and written to a
//! state file.  Subsequent runs re-use the same id so the agent is stable
//! across restarts.
//!
//! Atomicity: the new state is written to a temp file in the same directory,
//! then placed at the final path via `persist_noclobber()`.  This uses
//! `link()`+`unlink()` on Unix and `CREATE_NEW` on Windows — both refuse
//! to overwrite an existing file.  Only one process can win; the loser
//! reads the winner's fully-written file.

use std::io::Write;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct StateFile {
    agent_id: Uuid,
}

/// Load `agent_id` from `path`, or generate and persist a new one.
///
/// Creation is atomic and exclusive: content is written to a temp file,
/// then `persist_noclobber()` attempts to place it at the final path.
/// If the target already exists the call fails, and we read the existing
/// file instead.  This guarantees that exactly one agent_id wins, even
/// under concurrent first-run startup.
pub fn load_or_create_agent_id(path: &Path) -> Result<Uuid> {
    // Ensure parent directories exist.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Fast path: file already exists — just read it.
    if path.exists() {
        return read_state(path);
    }

    // Slow path: generate a new ID and try to claim the file.
    let id = Uuid::new_v4();
    let state = StateFile { agent_id: id };
    let content = toml::to_string_pretty(&state)?;

    // Write to a temp file in the same directory (same filesystem) so
    // the subsequent rename never crosses mount points.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(content.as_bytes())?;
    tmp.as_file().sync_all()?;

    // persist_noclobber() uses link()+unlink() on Unix and CREATE_NEW on
    // Windows — it fails if the target already exists.  This is the
    // single serialization point: exactly one process succeeds.
    match tmp.persist_noclobber(path) {
        Ok(_) => {
            tracing::info!(agent_id = %id, path = %path.display(), "Created new agent state");
            Ok(id)
        }
        Err(e) => {
            // Another process placed the file between our exists() check
            // and persist_noclobber().  Read their (complete) file.
            if path.exists() {
                read_state(path)
            } else {
                Err(e.error.into())
            }
        }
    }
}

/// Read and parse an existing state file.
fn read_state(path: &Path) -> Result<Uuid> {
    let content = std::fs::read_to_string(path)?;
    let state: StateFile = toml::from_str(&content)?;
    tracing::info!(agent_id = %state.agent_id, path = %path.display(), "Loaded agent state");
    Ok(state.agent_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn creates_new_state_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.toml");

        let id = load_or_create_agent_id(&path).unwrap();
        assert!(path.exists());

        // File should contain the generated UUID
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains(&id.to_string()));
    }

    #[test]
    fn reuses_existing_state() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.toml");

        let first = load_or_create_agent_id(&path).unwrap();
        let second = load_or_create_agent_id(&path).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn creates_parent_directories() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sub").join("dir").join("state.toml");

        let id = load_or_create_agent_id(&path).unwrap();
        assert!(path.exists());

        let reloaded = load_or_create_agent_id(&path).unwrap();
        assert_eq!(id, reloaded);
    }

    #[test]
    fn invalid_state_file_errors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.toml");
        std::fs::write(&path, "garbage content").unwrap();

        assert!(load_or_create_agent_id(&path).is_err());
    }

    /// Fast-path: file already present before load_or_create is called.
    #[test]
    fn concurrent_create_returns_existing_id() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.toml");

        // A "first process" writes a known ID
        let known_id = Uuid::new_v4();
        let content = toml::to_string_pretty(&StateFile { agent_id: known_id }).unwrap();
        std::fs::write(&path, &content).unwrap();

        // A "second process" calls load_or_create — the exists() fast
        // path returns the existing ID.
        let got = load_or_create_agent_id(&path).unwrap();
        assert_eq!(got, known_id);
    }

    /// Simulate the persist_noclobber race: two threads both pass the
    /// exists() check, but only one wins the rename.  Both must end up
    /// with the same agent_id — the winner's.
    #[test]
    fn concurrent_persist_noclobber_race() {
        use std::sync::{Arc, Barrier};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.toml");
        let path = Arc::new(path);
        // Barrier so both threads call load_or_create at ~the same time.
        let barrier = Arc::new(Barrier::new(2));

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let p = Arc::clone(&path);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    load_or_create_agent_id(&p).unwrap()
                })
            })
            .collect();

        let ids: Vec<Uuid> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // Both threads must agree on the same agent_id.
        assert_eq!(ids[0], ids[1], "concurrent first-run produced divergent agent_ids");

        // The on-disk file must match.
        let on_disk = load_or_create_agent_id(&path).unwrap();
        assert_eq!(on_disk, ids[0]);
    }
}
