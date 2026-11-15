//! `token add | remove | list`: edit the `[[agents]]` list in the config
//! file in place, preserving its comments and formatting.

use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use toml_edit::{value, ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value};

use crate::auth::{generate_token, token_sha256_hex};
use crate::config::{is_valid_agent_name, ServerConfig};

/// Add an agent with a freshly generated token. Returns the token, which is
/// not stored anywhere (only its hash is).
pub fn add_agent(config_path: &Path, name: &str) -> Result<String> {
    if !is_valid_agent_name(name) {
        bail!(
            "invalid agent name {name:?}: use 1-64 characters from [a-z0-9._-], starting with a letter or digit"
        );
    }
    let path = resolve(config_path)?;
    let text = read(&path)?;
    let config = ServerConfig::parse(&text, &path)?;
    if config.agents.iter().any(|a| a.name == name) {
        bail!("agent {name:?} already exists in {}", path.display());
    }

    let token = generate_token()?;
    let hash = token_sha256_hex(&token);
    let mut doc = parse_document(&text, &path)?;
    match doc
        .entry("agents")
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()))
    {
        Item::ArrayOfTables(tables) => {
            let mut table = Table::new();
            table.insert("name", value(name));
            table.insert("token_sha256", value(&hash));
            tables.push(table);
        }
        Item::Value(Value::Array(array)) => {
            let mut table = InlineTable::new();
            table.insert("name", name.into());
            table.insert("token_sha256", hash.as_str().into());
            array.push(table);
        }
        _ => bail!(
            "`agents` in {} must be an array of tables ([[agents]])",
            path.display()
        ),
    }
    write_validated(&path, &doc)?;
    Ok(token)
}

/// Remove an agent. Its stored telemetry is left in place.
pub fn remove_agent(config_path: &Path, name: &str) -> Result<()> {
    let path = resolve(config_path)?;
    let text = read(&path)?;
    ServerConfig::parse(&text, &path)?;
    let mut doc = parse_document(&text, &path)?;
    let removed = match doc.get_mut("agents") {
        Some(Item::ArrayOfTables(tables)) => {
            let before = tables.len();
            tables.retain(|t| t.get("name").and_then(Item::as_str) != Some(name));
            before - tables.len()
        }
        Some(Item::Value(Value::Array(array))) => {
            let before = array.len();
            array.retain(|v| {
                v.as_inline_table()
                    .and_then(|t| t.get("name"))
                    .and_then(Value::as_str)
                    != Some(name)
            });
            before - array.len()
        }
        _ => 0,
    };
    if removed == 0 {
        bail!("agent {name:?} not found in {}", path.display());
    }
    write_validated(&path, &doc)
}

/// Configured agents as (name, first 12 hex characters of the token hash).
pub fn list_agents(config_path: &Path) -> Result<Vec<(String, String)>> {
    let config = ServerConfig::load(config_path)?;
    Ok(config
        .agents
        .into_iter()
        .map(|a| (a.name, a.token_sha256[..12].to_string()))
        .collect())
}

/// Operate on the real file if the config path is a symlink.
fn resolve(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path).with_context(|| format!("config file {} not found", path.display()))
}

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

fn parse_document(text: &str, path: &Path) -> Result<DocumentMut> {
    text.parse::<DocumentMut>()
        .with_context(|| format!("failed to parse {}", path.display()))
}

fn write_validated(path: &Path, doc: &DocumentMut) -> Result<()> {
    let text = doc.to_string();
    ServerConfig::parse(&text, path).context("refusing to write an invalid config")?;
    write_atomic(path, text.as_bytes())
}

/// Replace `path` atomically, keeping its owner, group and mode (the config
/// is typically `root:threatfalcon 0640`).
fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let meta = fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    let dir = path
        .parent()
        .context("config path has no parent directory")?;
    let file_name = path
        .file_name()
        .context("config path has no file name")?
        .to_string_lossy();
    let tmp = dir.join(format!(".{file_name}.tmp-{}", std::process::id()));

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("failed to create {}", tmp.display()))?;
        file.write_all(contents)?;
        let current = file.metadata()?;
        if (current.uid(), current.gid()) != (meta.uid(), meta.gid()) {
            std::os::unix::fs::fchown(&file, Some(meta.uid()), Some(meta.gid())).with_context(
                || {
                    format!(
                        "failed to preserve ownership of {} (run this command with sudo)",
                        path.display()
                    )
                },
            )?;
        }
        file.set_permissions(Permissions::from_mode(meta.mode() & 0o7777))?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        fs::File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TokenTable;
    use tempfile::TempDir;

    const BASE: &str =
        "# ThreatFalcon server\nlisten = \"127.0.0.1:8080\" # ingest\n\n[storage]\nfsync = true\n";

    fn write_config(dir: &TempDir, text: &str) -> PathBuf {
        let path = dir.path().join("server.toml");
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o640)).unwrap();
        path
    }

    #[test]
    fn add_list_remove_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, BASE);

        let t1 = add_agent(&path, "lab-ws01").unwrap();
        let t2 = add_agent(&path, "lab-ws02").unwrap();
        assert_ne!(t1, t2);

        let text = fs::read_to_string(&path).unwrap();
        // Comments and existing settings survive.
        assert!(text.starts_with("# ThreatFalcon server\nlisten = \"127.0.0.1:8080\" # ingest\n"));
        assert!(text.contains("[[agents]]"));
        assert!(!text.contains(&t1), "plaintext token must not be written");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o640);

        let config = ServerConfig::load(&path).unwrap();
        let table = TokenTable::new(&config.agents).unwrap();
        assert_eq!(table.verify(&t1).as_deref(), Some("lab-ws01"));
        assert_eq!(table.verify(&t2).as_deref(), Some("lab-ws02"));

        let names: Vec<String> = list_agents(&path)
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, vec!["lab-ws01", "lab-ws02"]);

        remove_agent(&path, "lab-ws01").unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert_eq!(config.agents.len(), 1);
        assert_eq!(config.agents[0].name, "lab-ws02");
        assert!(fs::read_to_string(&path).unwrap().contains("[storage]"));

        remove_agent(&path, "lab-ws02").unwrap();
        assert!(ServerConfig::load(&path).unwrap().agents.is_empty());
        // No temp files are left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn rejects_duplicates_bad_names_and_unknown_agents() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, BASE);
        add_agent(&path, "a").unwrap();
        assert!(add_agent(&path, "a").is_err());
        assert!(add_agent(&path, "../evil").is_err());
        assert!(add_agent(&path, "Upper").is_err());
        assert!(remove_agent(&path, "missing").is_err());
        assert_eq!(ServerConfig::load(&path).unwrap().agents.len(), 1);
    }

    #[test]
    fn refuses_to_edit_an_invalid_config() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "admin_listen = \"0.0.0.0:1\"\n");
        assert!(add_agent(&path, "a").is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "admin_listen = \"0.0.0.0:1\"\n"
        );
    }

    #[test]
    fn supports_inline_agent_arrays() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "agents = []\n");
        let token = add_agent(&path, "a").unwrap();
        add_agent(&path, "b").unwrap();
        let config = ServerConfig::load(&path).unwrap();
        assert_eq!(config.agents.len(), 2);
        assert_eq!(
            TokenTable::new(&config.agents)
                .unwrap()
                .verify(&token)
                .as_deref(),
            Some("a")
        );
        remove_agent(&path, "a").unwrap();
        assert_eq!(ServerConfig::load(&path).unwrap().agents.len(), 1);
    }

    #[test]
    fn follows_symlinked_config() {
        let dir = TempDir::new().unwrap();
        let real = write_config(&dir, BASE);
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        add_agent(&link, "a").unwrap();
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(ServerConfig::load(&real).unwrap().agents.len(), 1);
    }
}
