//! Server configuration (`server.toml`).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Default location of the configuration file on a deployed server.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/threatfalcon-server/server.toml";

const MIB: u64 = 1024 * 1024;
const MAX_AGENT_NAME_LEN: usize = 64;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Ingest listener. Plain HTTP: terminate TLS in front of it.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Admin listener (status API, metrics). Unauthenticated, so it must be
    /// bound to a loopback address.
    #[serde(default = "default_admin_listen")]
    pub admin_listen: SocketAddr,
    /// Root directory for stored telemetry. Relative paths are resolved
    /// against the directory that contains the config file.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Public ingest URL. Only used when printing agent config snippets.
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub status: StatusConfig,
    /// One entry per agent. Managed with `threatfalcon-server token add`.
    #[serde(default)]
    pub agents: Vec<AgentEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum request body size as received on the wire.
    pub max_body_mb: u64,
    /// Maximum size of the decoded (decompressed) payload.
    pub max_decompressed_mb: u64,
    /// Maximum number of events in one batch.
    pub max_events_per_batch: usize,
    /// Requests processed concurrently (bounds peak memory use).
    pub max_concurrent_requests: usize,
    /// Time allowed for receiving a request body.
    pub request_timeout_secs: u64,
    /// Refuse writes (HTTP 507) when free space on the data volume drops
    /// below this. Agents keep the batch and retry later. 0 disables.
    pub min_free_disk_mb: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_mb: 16,
            max_decompressed_mb: 32,
            max_events_per_batch: 10_000,
            max_concurrent_requests: 8,
            request_timeout_secs: 30,
            min_free_disk_mb: 1024,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// Rotate an agent's `events.jsonl` at this size. 0 disables rotation.
    pub rotation_size_mb: u64,
    /// Rotated files kept per agent; the oldest are deleted beyond this.
    /// 0 keeps everything.
    pub max_rotated_files: u32,
    /// fsync every batch before acknowledging it. Turning this off trades
    /// durability on power loss for throughput.
    pub fsync: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            rotation_size_mb: 100,
            max_rotated_files: 50,
            fsync: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StatusConfig {
    /// An agent is reported as `stale` when nothing was received from it
    /// for this long. Sensors flush at least once per health interval
    /// (60 s by default).
    pub stale_after_secs: u64,
}

impl Default for StatusConfig {
    fn default() -> Self {
        Self {
            stale_after_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEntry {
    /// Agent name. Also the name of its storage directory.
    pub name: String,
    /// Lowercase hex SHA-256 of the agent's bearer token.
    pub token_sha256: String,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}

fn default_admin_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8081))
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/threatfalcon-server")
}

impl ServerConfig {
    /// Read, parse and validate a config file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        Self::parse(&text, path)
    }

    /// Parse and validate config text. `path` is used to resolve a relative
    /// `data_dir` and in error messages.
    pub fn parse(text: &str, path: &Path) -> Result<Self> {
        let mut config: ServerConfig = toml::from_str(text)
            .with_context(|| format!("invalid config file {}", path.display()))?;
        if config.data_dir.is_relative() {
            let base = path.parent().unwrap_or_else(|| Path::new("."));
            config.data_dir = base.join(&config.data_dir);
        }
        config
            .validate()
            .with_context(|| format!("invalid config file {}", path.display()))?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if !self.admin_listen.ip().is_loopback() {
            bail!(
                "admin_listen ({}) must be a loopback address: the admin API is unauthenticated",
                self.admin_listen
            );
        }
        if self.listen == self.admin_listen && self.listen.port() != 0 {
            bail!("listen and admin_listen must differ");
        }
        if let Some(url) = &self.public_url {
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                bail!("public_url must start with https:// or http://");
            }
        }

        let l = &self.limits;
        if !(1..=1024).contains(&l.max_body_mb) {
            bail!("limits.max_body_mb must be between 1 and 1024");
        }
        if !(1..=4096).contains(&l.max_decompressed_mb) {
            bail!("limits.max_decompressed_mb must be between 1 and 4096");
        }
        if l.max_decompressed_mb < l.max_body_mb {
            bail!("limits.max_decompressed_mb must be >= limits.max_body_mb");
        }
        if l.max_events_per_batch == 0 {
            bail!("limits.max_events_per_batch must be at least 1");
        }
        if !(1..=1024).contains(&l.max_concurrent_requests) {
            bail!("limits.max_concurrent_requests must be between 1 and 1024");
        }
        if l.request_timeout_secs == 0 {
            bail!("limits.request_timeout_secs must be at least 1");
        }
        if self.storage.rotation_size_mb > 1024 * 1024 {
            bail!("storage.rotation_size_mb is unreasonably large");
        }
        if self.status.stale_after_secs == 0 {
            bail!("status.stale_after_secs must be at least 1");
        }

        let mut names = HashSet::new();
        let mut hashes = HashSet::new();
        for agent in &self.agents {
            if !is_valid_agent_name(&agent.name) {
                bail!(
                    "invalid agent name {:?}: use 1-{MAX_AGENT_NAME_LEN} characters from [a-z0-9._-], starting with a letter or digit",
                    agent.name
                );
            }
            if !is_valid_token_hash(&agent.token_sha256) {
                bail!(
                    "agent {:?}: token_sha256 must be 64 lowercase hex characters",
                    agent.name
                );
            }
            if !names.insert(agent.name.as_str()) {
                bail!("duplicate agent name {:?}", agent.name);
            }
            if !hashes.insert(agent.token_sha256.as_str()) {
                bail!("agent {:?} reuses another agent's token", agent.name);
            }
        }
        Ok(())
    }

    pub fn max_body_bytes(&self) -> usize {
        mib_to_bytes(self.limits.max_body_mb)
    }

    pub fn max_decompressed_bytes(&self) -> usize {
        mib_to_bytes(self.limits.max_decompressed_mb)
    }

    pub fn min_free_disk_bytes(&self) -> u64 {
        self.limits.min_free_disk_mb.saturating_mul(MIB)
    }

    pub fn rotation_bytes(&self) -> u64 {
        self.storage.rotation_size_mb.saturating_mul(MIB)
    }
}

fn mib_to_bytes(mb: u64) -> usize {
    usize::try_from(mb.saturating_mul(MIB)).unwrap_or(usize::MAX)
}

/// Agent names double as directory names, so they are restricted to a
/// conservative character set that cannot express path traversal.
pub fn is_valid_agent_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_AGENT_NAME_LEN
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

pub fn is_valid_token_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn parse(text: &str) -> Result<ServerConfig> {
        ServerConfig::parse(text, Path::new("/etc/threatfalcon-server/server.toml"))
    }

    #[test]
    fn empty_config_uses_defaults() {
        let cfg = parse("").unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(cfg.admin_listen, "127.0.0.1:8081".parse().unwrap());
        assert_eq!(cfg.data_dir, PathBuf::from("/var/lib/threatfalcon-server"));
        assert!(cfg.agents.is_empty());
        assert!(cfg.storage.fsync);
        assert_eq!(cfg.max_body_bytes(), 16 * 1024 * 1024);
    }

    #[test]
    fn parses_agents_and_sections() {
        let cfg = parse(&format!(
            r#"
            public_url = "https://tf.example.com/api/v1/events"
            [limits]
            max_body_mb = 4
            max_decompressed_mb = 8
            [storage]
            rotation_size_mb = 10
            max_rotated_files = 3
            fsync = false
            [[agents]]
            name = "lab-ws01"
            token_sha256 = "{HASH_A}"
            [[agents]]
            name = "lab.ws_02"
            token_sha256 = "{HASH_B}"
            "#
        ))
        .unwrap();
        assert_eq!(cfg.agents.len(), 2);
        assert_eq!(cfg.limits.max_body_mb, 4);
        assert_eq!(cfg.storage.max_rotated_files, 3);
        assert!(!cfg.storage.fsync);
    }

    #[test]
    fn relative_data_dir_resolves_against_config_dir() {
        let cfg =
            ServerConfig::parse("data_dir = \"data\"", Path::new("/srv/tfs/server.toml")).unwrap();
        assert_eq!(cfg.data_dir, PathBuf::from("/srv/tfs/data"));
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(parse("lisen = \"127.0.0.1:1\"").is_err());
        assert!(parse("[limits]\nmax_body = 1").is_err());
        assert!(parse(&format!(
            "[[agents]]\nname = \"a\"\ntoken_sha256 = \"{HASH_A}\"\nextra = 1"
        ))
        .is_err());
    }

    #[test]
    fn rejects_public_admin_listener() {
        let err = parse("admin_listen = \"0.0.0.0:8081\"").unwrap_err();
        assert!(format!("{err:#}").contains("loopback"));
    }

    #[test]
    fn rejects_same_listen_addresses() {
        assert!(parse("listen = \"127.0.0.1:9000\"\nadmin_listen = \"127.0.0.1:9000\"").is_err());
        // Port 0 (ephemeral, used by tests) is allowed for both.
        assert!(parse("listen = \"127.0.0.1:0\"\nadmin_listen = \"127.0.0.1:0\"").is_ok());
    }

    #[test]
    fn rejects_invalid_agent_names() {
        for name in [
            "",
            "../etc",
            "..",
            ".hidden",
            "UPPER",
            "a/b",
            "a b",
            "-x",
            &"a".repeat(65),
        ] {
            let text = format!("[[agents]]\nname = {name:?}\ntoken_sha256 = \"{HASH_A}\"");
            assert!(parse(&text).is_err(), "name {name:?} should be rejected");
        }
        for name in ["a", "0", "lab-ws01", "a.b_c-d", &"a".repeat(64)] {
            let text = format!("[[agents]]\nname = {name:?}\ntoken_sha256 = \"{HASH_A}\"");
            assert!(parse(&text).is_ok(), "name {name:?} should be accepted");
        }
    }

    #[test]
    fn rejects_bad_token_hashes() {
        for hash in [
            "",
            "abc",
            &HASH_A.to_uppercase(),
            &format!("{HASH_A}0"),
            &"g".repeat(64),
        ] {
            let text = format!("[[agents]]\nname = \"a\"\ntoken_sha256 = {hash:?}");
            assert!(parse(&text).is_err(), "hash {hash:?} should be rejected");
        }
    }

    #[test]
    fn rejects_duplicates() {
        let dup_name = format!(
            "[[agents]]\nname = \"a\"\ntoken_sha256 = \"{HASH_A}\"\n[[agents]]\nname = \"a\"\ntoken_sha256 = \"{HASH_B}\""
        );
        assert!(parse(&dup_name).is_err());
        let dup_hash = format!(
            "[[agents]]\nname = \"a\"\ntoken_sha256 = \"{HASH_A}\"\n[[agents]]\nname = \"b\"\ntoken_sha256 = \"{HASH_A}\""
        );
        assert!(parse(&dup_hash).is_err());
    }

    #[test]
    fn rejects_out_of_range_limits() {
        assert!(parse("[limits]\nmax_body_mb = 0").is_err());
        assert!(parse("[limits]\nmax_body_mb = 8\nmax_decompressed_mb = 4").is_err());
        assert!(parse("[limits]\nmax_events_per_batch = 0").is_err());
        assert!(parse("[limits]\nmax_concurrent_requests = 0").is_err());
        assert!(parse("[status]\nstale_after_secs = 0").is_err());
        assert!(parse("public_url = \"ftp://x\"").is_err());
    }
}
