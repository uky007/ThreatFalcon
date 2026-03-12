//! Persistent agent state.
//!
//! On first run a random `agent_id` (UUID v4) is generated and written to a
//! state file.  Subsequent runs re-use the same id so the agent is stable
//! across restarts.
//!
//! File creation uses `create_new` (O_CREAT|O_EXCL) for atomic exclusive
//! creation, preventing two concurrent first-run processes from generating
//! divergent agent IDs.

use std::fs::OpenOptions;
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
/// Uses exclusive file creation (`create_new`) so that concurrent first-run
/// processes cannot both observe "file missing" and write different IDs.
pub fn load_or_create_agent_id(path: &Path) -> Result<Uuid> {
    // Ensure parent directories exist.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Try exclusive create — only one process can win this race.
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            let id = Uuid::new_v4();
            let state = StateFile { agent_id: id };
            let content = toml::to_string_pretty(&state)?;
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
            tracing::info!(agent_id = %id, path = %path.display(), "Created new agent state");
            Ok(id)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // File exists — another process may have just created it, or it
            // was there from a previous run. Read and return its agent_id.
            let content = std::fs::read_to_string(path)?;
            let state: StateFile = toml::from_str(&content)?;
            tracing::info!(agent_id = %state.agent_id, path = %path.display(), "Loaded agent state");
            Ok(state.agent_id)
        }
        Err(e) => Err(e.into()),
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
