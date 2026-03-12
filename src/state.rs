//! Persistent agent state.
//!
//! On first run a random `agent_id` (UUID v4) is generated and written to a
//! state file.  Subsequent runs re-use the same id so the agent is stable
//! across restarts.

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct StateFile {
    agent_id: Uuid,
}

/// Load `agent_id` from `path`, or generate and persist a new one.
pub fn load_or_create_agent_id(path: &Path) -> Result<Uuid> {
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let state: StateFile = toml::from_str(&content)?;
        tracing::info!(agent_id = %state.agent_id, path = %path.display(), "Loaded agent state");
        return Ok(state.agent_id);
    }

    let id = Uuid::new_v4();
    let state = StateFile { agent_id: id };
    let content = toml::to_string_pretty(&state)?;

    // Best-effort: create parent directories if missing.
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    std::fs::write(path, &content)?;
    tracing::info!(agent_id = %id, path = %path.display(), "Created new agent state");
    Ok(id)
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
}
