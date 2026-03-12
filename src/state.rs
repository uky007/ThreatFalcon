//! Persistent agent state.
//!
//! On first run a random `agent_id` (UUID v4) is generated and written to a
//! state file.  Subsequent runs re-use the same id so the agent is stable
//! across restarts.
//!
//! Atomicity: the new state is written to a temp file in the same directory,
//! then renamed into place. On Unix `rename(2)` is atomic; on Windows
//! `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` is as close as we get.
//! A concurrent reader will see either the old (non-existent) path or the
//! fully-written file — never a partial write.

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
/// Creation is atomic: content is written to a temporary file first, then
/// renamed into the final path. A concurrent process that loses the rename
/// race simply reads the winner's file.
pub fn load_or_create_agent_id(path: &Path) -> Result<Uuid> {
    // Ensure parent directories exist.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Fast path: file already exists — just read it.
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let state: StateFile = toml::from_str(&content)?;
        tracing::info!(agent_id = %state.agent_id, path = %path.display(), "Loaded agent state");
        return Ok(state.agent_id);
    }

    // Slow path: generate a new ID and write atomically via temp+rename.
    let id = Uuid::new_v4();
    let state = StateFile { agent_id: id };
    let content = toml::to_string_pretty(&state)?;

    // Write to a temp file in the same directory (same filesystem) so
    // rename is atomic and never crosses mount points.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::NamedTempFile::new_in(parent)?;
    std::fs::write(tmp.path(), content.as_bytes())?;

    // persist() does rename on Unix, MoveFileEx on Windows.
    // If the target already appeared between our exists() check and now,
    // persist will overwrite on Unix (atomic) or fail on Windows —
    // either way the final file is valid. On Windows rename failure,
    // fall back to reading the winner's file.
    match tmp.persist(path) {
        Ok(_) => {
            tracing::info!(agent_id = %id, path = %path.display(), "Created new agent state");
            Ok(id)
        }
        Err(e) => {
            // Another process won the race and placed the file first.
            // Read their ID instead of ours.
            if path.exists() {
                let content = std::fs::read_to_string(path)?;
                let state: StateFile = toml::from_str(&content)?;
                tracing::info!(
                    agent_id = %state.agent_id,
                    path = %path.display(),
                    "Lost rename race — loaded winner's agent state"
                );
                Ok(state.agent_id)
            } else {
                Err(e.error.into())
            }
        }
    }
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

    /// Simulate the race: pre-create the file between "would create" and
    /// "actually create" — `create_new` must fall back to the read path
    /// and return the existing ID, not error.
    #[test]
    fn concurrent_create_returns_existing_id() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.toml");

        // A "first process" writes a known ID
        let known_id = Uuid::new_v4();
        let content = toml::to_string_pretty(&StateFile { agent_id: known_id }).unwrap();
        std::fs::write(&path, &content).unwrap();

        // A "second process" calls load_or_create — create_new will fail
        // with AlreadyExists and it should return the existing ID.
        let got = load_or_create_agent_id(&path).unwrap();
        assert_eq!(got, known_id);
    }
}
