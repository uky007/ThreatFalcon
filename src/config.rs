use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

const CONFIG_FILE: &str = "threatfalcon.toml";

/// Platform-appropriate base directory for ThreatFalcon data files.
///
/// Windows: `%ProgramData%\ThreatFalcon` (typically `C:\ProgramData\ThreatFalcon`).
/// Other platforms: `None` — relative paths are used for development.
fn default_base_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("ProgramData")
            .ok()
            .map(|pd| PathBuf::from(pd).join("ThreatFalcon"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SensorConfig {
    pub hostname: String,
    pub output: OutputConfig,
    pub collectors: CollectorConfig,
    /// Interval in seconds between periodic health events (0 = periodic
    /// disabled; a final shutdown health event is always emitted).
    pub health_interval_secs: u64,
    /// Path to the persistent agent state file (stores agent_id).
    pub state_path: PathBuf,
    /// Hunt / score / alert rule configuration.
    pub rules: RulesConfig,
}

/// Configuration for hunt, score, and alert rules.
/// All fields have sensible defaults matching the built-in behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    pub hunt: HuntRulesConfig,
    pub score: ScoreWeights,
    pub alert: AlertDefaults,
}

/// Configurable process lists and thresholds for hunt rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HuntRulesConfig {
    /// Parent images that should not normally spawn shells/scripting engines.
    pub suspicious_parents: Vec<String>,
    /// Children that are suspicious when spawned from a suspicious parent.
    pub suspicious_children: Vec<String>,
    /// LOLBins — legitimate Windows binaries commonly abused by adversaries.
    pub lolbins: Vec<String>,
    /// Minimum connection count to the same IP before flagging as beaconing.
    pub beaconing_threshold: usize,
}

/// Point values for each scoring signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScoreWeights {
    pub detection: u32,
    pub suspicious_parent: u32,
    pub lolbin: u32,
    pub unsigned_dll: u32,
    pub external_ip: u32,
    pub dns_query: u32,
}

/// Default values for the alert subcommand.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertDefaults {
    /// Score threshold to trigger a score-based alert.
    pub threshold: u32,
    /// Seconds to suppress duplicate alerts for the same process + rule.
    pub cooldown: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    /// Sink type: "file" (default), "stdout", or "http".
    #[serde(rename = "type")]
    pub sink_type: SinkType,
    /// Path for file sink output.
    pub path: PathBuf,
    /// Max file size in MB before rotation (0 = no rotation). File sink only.
    pub rotation_size_mb: u64,
    /// Pretty-print JSON output. Stdout sink only.
    pub pretty: bool,
    /// Endpoint URL for HTTP sink.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Number of events to batch before POSTing. HTTP sink only.
    pub batch_size: usize,
    /// HTTP request timeout in seconds. HTTP sink only.
    pub timeout_secs: u64,
    /// Bearer token for HTTP sink Authorization header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<String>,
    /// Custom HTTP headers (key-value pairs). HTTP sink only.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    /// Number of retry attempts on HTTP failure (default: 3).
    pub retry_count: u32,
    /// Base backoff in milliseconds between retries (default: 100).
    /// Actual delay = retry_backoff_ms * attempt_number.
    pub retry_backoff_ms: u64,
    /// Compress HTTP request body with gzip. HTTP sink only.
    pub gzip: bool,
    /// Directory for disk-backed spool when HTTP delivery fails.
    /// When set, failed batches are written to disk instead of dropped,
    /// and re-sent when the endpoint recovers. HTTP sink only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spool_dir: Option<PathBuf>,
    /// Maximum total spool size in MB (default: 256). HTTP sink only.
    /// When exceeded, new spool writes fall back to dropping events.
    pub spool_max_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SinkType {
    #[serde(rename = "file")]
    File,
    #[serde(rename = "stdout")]
    Stdout,
    #[serde(rename = "http")]
    Http,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectorConfig {
    pub etw: EtwConfig,
    pub sysmon: SysmonConfig,
    pub evasion: EvasionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EtwConfig {
    pub enabled: bool,
    pub providers: Vec<EtwProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwProviderConfig {
    pub name: String,
    pub guid: String,
    #[serde(default = "default_level")]
    pub level: u8,
    #[serde(
        default = "default_keywords",
        deserialize_with = "deserialize_keywords",
        serialize_with = "serialize_keywords"
    )]
    pub keywords: u64,
}

fn default_level() -> u8 {
    5
}
fn default_keywords() -> u64 {
    0xFFFFFFFFFFFFFFFF
}

/// Deserialize keywords from either a hex string ("0xFF..") or an integer.
fn deserialize_keywords<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct KeywordsVisitor;

    impl<'de> de::Visitor<'de> for KeywordsVisitor {
        type Value = u64;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a hex string (\"0xFF..\") or an integer")
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<u64, E> {
            Ok(v)
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<u64, E> {
            if v < 0 {
                return Err(de::Error::custom(format!(
                    "keywords must be non-negative, got {v}"
                )));
            }
            Ok(v as u64)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<u64, E> {
            let s = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")).unwrap_or(v);
            u64::from_str_radix(s, 16).map_err(de::Error::custom)
        }
    }

    deserializer.deserialize_any(KeywordsVisitor)
}

fn serialize_keywords<S>(value: &u64, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("0x{value:016X}"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SysmonConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EvasionConfig {
    pub enabled: bool,
    pub scan_interval_ms: u64,
    pub detect_etw_patching: bool,
    pub detect_amsi_bypass: bool,
    pub detect_unhooking: bool,
    pub detect_direct_syscall: bool,
}

/// Search for `CONFIG_FILE` in a list of candidate directories.
///
/// When `cwd_override` is `Some`, that directory is checked first (used in
/// tests to avoid mutating the process-global cwd). When `None`, the real
/// current directory is checked. The platform base dir (ProgramData on
/// Windows) is always checked second.
pub fn find_config_file(cwd_override: Option<&std::path::Path>) -> Option<PathBuf> {
    let cwd_path = match cwd_override {
        Some(dir) => dir.join(CONFIG_FILE),
        None => PathBuf::from(CONFIG_FILE),
    };
    let platform_path = default_base_dir().map(|d| d.join(CONFIG_FILE));

    if cwd_path.exists() {
        Some(cwd_path)
    } else if let Some(ref pp) = platform_path {
        if pp.exists() { Some(pp.clone()) } else { None }
    } else {
        None
    }
}

impl SensorConfig {
    /// Load config from the given path, or from the default `CONFIG_FILE` if
    /// `path` is `None`. Returns defaults when no file is found.
    ///
    /// Relative `state_path` values are resolved to an absolute path anchored
    /// to the config file's directory (when a config file is loaded) or the
    /// executable's directory (when using built-in defaults). This ensures the
    /// same state file is found regardless of the process working directory
    /// (important for Windows service mode where cwd is typically System32).
    pub fn load_from(path: Option<&std::path::Path>) -> Result<Self> {
        let (config, anchor) = match path {
            Some(p) => {
                if !p.exists() {
                    anyhow::bail!("Config file not found: {}", p.display());
                }
                let content = std::fs::read_to_string(p)?;
                let cfg: SensorConfig = toml::from_str(&content)?;
                tracing::info!("Loaded config from {}", p.display());
                // Anchor relative paths to the config file's directory.
                let anchor = p
                    .canonicalize()
                    .unwrap_or_else(|_| p.to_path_buf())
                    .parent()
                    .map(|p| p.to_path_buf());
                (cfg, anchor)
            }
            None => {
                let found = find_config_file(None);

                if let Some(path) = found {
                    let content = std::fs::read_to_string(&path)?;
                    let cfg: SensorConfig = toml::from_str(&content)?;
                    tracing::info!("Loaded config from {}", path.display());
                    let anchor = path
                        .canonicalize()
                        .unwrap_or_else(|_| path.clone())
                        .parent()
                        .map(|p| p.to_path_buf());
                    (cfg, anchor)
                } else {
                    tracing::info!(
                        "No config file found — using defaults"
                    );
                    // Anchor to the executable's directory.
                    let anchor = std::env::current_exe()
                        .ok()
                        .and_then(|p| p.parent().map(|p| p.to_path_buf()));
                    (Self::default(), anchor)
                }
            }
        };

        Ok(config.resolve_paths(anchor))
    }

    /// Resolve relative paths against `anchor` so they are stable
    /// regardless of process working directory.
    fn resolve_paths(mut self, anchor: Option<PathBuf>) -> Self {
        if let Some(ref base) = anchor {
            if self.state_path.is_relative() {
                self.state_path = base.join(&self.state_path);
            }
            if self.output.path.is_relative() {
                self.output.path = base.join(&self.output.path);
            }
            if let Some(ref dir) = self.output.spool_dir {
                if dir.is_relative() {
                    self.output.spool_dir = Some(base.join(dir));
                }
            }
        }
        self
    }
}

impl SensorConfig {
    /// Build defaults rooted at `base`. When `Some`, paths are absolute
    /// under that directory (used on Windows with ProgramData). When
    /// `None`, paths are relative (development / non-Windows).
    pub fn with_base_dir(base: Option<&std::path::Path>) -> Self {
        Self {
            hostname: hostname(),
            output: OutputConfig::with_base_dir(base),
            collectors: CollectorConfig::default(),
            health_interval_secs: 60,
            state_path: match base {
                Some(d) => d.join("threatfalcon.state"),
                None => PathBuf::from("threatfalcon.state"),
            },
            rules: RulesConfig::default(),
        }
    }
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self::with_base_dir(default_base_dir().as_deref())
    }
}

impl Default for SinkType {
    fn default() -> Self {
        Self::File
    }
}

impl OutputConfig {
    fn with_base_dir(base: Option<&std::path::Path>) -> Self {
        Self {
            sink_type: SinkType::File,
            path: match base {
                Some(d) => d.join("threatfalcon_events.jsonl"),
                None => PathBuf::from("threatfalcon_events.jsonl"),
            },
            rotation_size_mb: 100,
            pretty: false,
            url: None,
            batch_size: 100,
            timeout_secs: 10,
            bearer_token: None,
            headers: HashMap::new(),
            retry_count: 3,
            retry_backoff_ms: 100,
            gzip: false,
            spool_dir: None,
            spool_max_mb: 256,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self::with_base_dir(default_base_dir().as_deref())
    }
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            etw: EtwConfig::default(),
            sysmon: SysmonConfig::default(),
            evasion: EvasionConfig::default(),
        }
    }
}

impl Default for EtwConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            providers: default_etw_providers(),
        }
    }
}

impl Default for SysmonConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_ms: 5000,
            detect_etw_patching: true,
            detect_amsi_bypass: true,
            detect_unhooking: true,
            detect_direct_syscall: true,
        }
    }
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            hunt: HuntRulesConfig::default(),
            score: ScoreWeights::default(),
            alert: AlertDefaults::default(),
        }
    }
}

impl Default for HuntRulesConfig {
    fn default() -> Self {
        Self {
            suspicious_parents: vec![
                "winword.exe".into(),
                "excel.exe".into(),
                "powerpnt.exe".into(),
                "outlook.exe".into(),
                "msaccess.exe".into(),
                "mspub.exe".into(),
                "visio.exe".into(),
                "onenote.exe".into(),
                "acrobat.exe".into(),
                "acrord32.exe".into(),
            ],
            suspicious_children: vec![
                "cmd.exe".into(),
                "powershell.exe".into(),
                "pwsh.exe".into(),
                "wscript.exe".into(),
                "cscript.exe".into(),
                "mshta.exe".into(),
                "regsvr32.exe".into(),
                "rundll32.exe".into(),
                "certutil.exe".into(),
                "bitsadmin.exe".into(),
            ],
            lolbins: vec![
                "certutil.exe".into(),
                "mshta.exe".into(),
                "regsvr32.exe".into(),
                "rundll32.exe".into(),
                "wscript.exe".into(),
                "cscript.exe".into(),
                "msiexec.exe".into(),
                "bitsadmin.exe".into(),
                "wmic.exe".into(),
                "msbuild.exe".into(),
                "installutil.exe".into(),
                "regasm.exe".into(),
                "regsvcs.exe".into(),
                "cmstp.exe".into(),
                "esentutl.exe".into(),
                "expand.exe".into(),
                "extrac32.exe".into(),
                "hh.exe".into(),
                "ieexec.exe".into(),
                "makecab.exe".into(),
                "replace.exe".into(),
            ],
            beaconing_threshold: 10,
        }
    }
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            detection: 40,
            suspicious_parent: 20,
            lolbin: 20,
            unsigned_dll: 5,
            external_ip: 2,
            dns_query: 1,
        }
    }
}

impl Default for AlertDefaults {
    fn default() -> Self {
        Self {
            threshold: 40,
            cooldown: 300,
        }
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn default_etw_providers() -> Vec<EtwProviderConfig> {
    vec![
        EtwProviderConfig {
            name: "Microsoft-Windows-Kernel-Process".into(),
            guid: "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716".into(),
            level: 5,
            keywords: 0xFFFFFFFFFFFFFFFF,
        },
        EtwProviderConfig {
            name: "Microsoft-Windows-Kernel-File".into(),
            guid: "EDD08927-9CC4-4E65-B970-C2560FB5C289".into(),
            level: 5,
            keywords: 0xFFFFFFFFFFFFFFFF,
        },
        EtwProviderConfig {
            name: "Microsoft-Windows-Kernel-Network".into(),
            guid: "7DD42A49-5329-4832-8DFD-43D979153A88".into(),
            level: 5,
            keywords: 0xFFFFFFFFFFFFFFFF,
        },
        EtwProviderConfig {
            name: "Microsoft-Windows-Kernel-Registry".into(),
            guid: "70EB4F03-C1DE-4F73-A051-33D13D5413BD".into(),
            level: 4,
            keywords: 0xFFFFFFFFFFFFFFFF,
        },
        EtwProviderConfig {
            name: "Microsoft-Windows-DNS-Client".into(),
            guid: "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D".into(),
            level: 5,
            keywords: 0xFFFFFFFFFFFFFFFF,
        },
        EtwProviderConfig {
            name: "Microsoft-Windows-PowerShell".into(),
            guid: "A0C1853B-5C40-4B15-8766-3CF1C58F985A".into(),
            level: 5,
            keywords: 0xFFFFFFFFFFFFFFFF,
        },
        EtwProviderConfig {
            name: "Microsoft-Antimalware-Scan-Interface".into(),
            guid: "2A576B87-09A7-520E-C21A-4942F0271D67".into(),
            level: 5,
            keywords: 0xFFFFFFFFFFFFFFFF,
        },
        EtwProviderConfig {
            name: "Microsoft-Windows-Threat-Intelligence".into(),
            guid: "F4E1897C-BB5D-5668-F1D8-040F4D8DD344".into(),
            level: 5,
            keywords: 0xFFFFFFFFFFFFFFFF,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = SensorConfig::default();
        assert!(cfg.collectors.etw.enabled);
        assert!(!cfg.collectors.sysmon.enabled);
        assert!(cfg.collectors.evasion.enabled);
        assert_eq!(cfg.output.sink_type, SinkType::File);
        assert_eq!(cfg.output.rotation_size_mb, 100);
        assert_eq!(cfg.collectors.etw.providers.len(), 8);
    }

    #[test]
    fn empty_toml_uses_defaults() {
        let cfg: SensorConfig = toml::from_str("").unwrap();
        assert!(cfg.collectors.etw.enabled);
        assert_eq!(cfg.collectors.etw.providers.len(), 8);
        assert_eq!(cfg.output.sink_type, SinkType::File);
        assert_eq!(cfg.output.rotation_size_mb, 100);
    }

    #[test]
    fn partial_toml_merges_with_defaults() {
        let toml = r#"
            hostname = "WORKSTATION-01"

            [output]
            path = "custom.jsonl"
            rotation_size_mb = 50

            [collectors.sysmon]
            enabled = true
        "#;
        let cfg: SensorConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.hostname, "WORKSTATION-01");
        assert_eq!(cfg.output.sink_type, SinkType::File); // default
        assert_eq!(cfg.output.path, PathBuf::from("custom.jsonl"));
        assert_eq!(cfg.output.rotation_size_mb, 50);
        assert!(cfg.collectors.sysmon.enabled);
        // Untouched fields keep defaults
        assert!(cfg.collectors.etw.enabled);
        assert!(cfg.collectors.evasion.enabled);
    }

    #[test]
    fn stdout_sink_config() {
        let toml = r#"
            [output]
            type = "stdout"
            pretty = true
        "#;
        let cfg: SensorConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.output.sink_type, SinkType::Stdout);
        assert!(cfg.output.pretty);
    }

    #[test]
    fn http_sink_config() {
        let toml = r#"
            [output]
            type = "http"
            url = "https://example.com/api/events"
            batch_size = 50
            timeout_secs = 30
        "#;
        let cfg: SensorConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.output.sink_type, SinkType::Http);
        assert_eq!(cfg.output.url.as_deref(), Some("https://example.com/api/events"));
        assert_eq!(cfg.output.batch_size, 50);
        assert_eq!(cfg.output.timeout_secs, 30);
    }

    #[test]
    fn keywords_hex_string() {
        let toml = r#"
            [[collectors.etw.providers]]
            name = "Test"
            guid = "00000000-0000-0000-0000-000000000000"
            keywords = "0x0000000000000010"
        "#;
        let cfg: SensorConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.collectors.etw.providers[0].keywords, 0x10);
    }

    #[test]
    fn keywords_integer() {
        let toml = r#"
            [[collectors.etw.providers]]
            name = "Test"
            guid = "00000000-0000-0000-0000-000000000000"
            keywords = 255
        "#;
        let cfg: SensorConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.collectors.etw.providers[0].keywords, 255);
    }

    #[test]
    fn evasion_partial_overrides() {
        let toml = r#"
            [collectors.evasion]
            detect_unhooking = false
            scan_interval_ms = 10000
        "#;
        let cfg: SensorConfig = toml::from_str(toml).unwrap();
        assert!(!cfg.collectors.evasion.detect_unhooking);
        assert_eq!(cfg.collectors.evasion.scan_interval_ms, 10000);
        // Other evasion defaults preserved
        assert!(cfg.collectors.evasion.detect_etw_patching);
        assert!(cfg.collectors.evasion.detect_amsi_bypass);
    }

    #[test]
    fn custom_providers_replace_defaults() {
        let toml = r#"
            [collectors.etw]
            providers = [
                { name = "Only-This", guid = "11111111-1111-1111-1111-111111111111" },
            ]
        "#;
        let cfg: SensorConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.collectors.etw.providers.len(), 1);
        assert_eq!(cfg.collectors.etw.providers[0].name, "Only-This");
    }

    #[test]
    fn keywords_negative_rejected() {
        let toml = r#"
            [[collectors.etw.providers]]
            name = "Test"
            guid = "00000000-0000-0000-0000-000000000000"
            keywords = -1
        "#;
        let result: std::result::Result<SensorConfig, _> = toml::from_str(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("non-negative"), "error was: {err}");
    }

    #[test]
    fn roundtrip_serialization() {
        let cfg = SensorConfig::default();
        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let cfg2: SensorConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg.collectors.etw.providers.len(), cfg2.collectors.etw.providers.len());
        assert_eq!(cfg.output.rotation_size_mb, cfg2.output.rotation_size_mb);
    }

    #[test]
    fn load_from_custom_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("custom.toml");
        std::fs::write(
            &path,
            "hostname = \"CUSTOM\"\n[output]\npath = \"custom.jsonl\"\n",
        )
        .unwrap();
        let cfg = SensorConfig::load_from(Some(&path)).unwrap();
        assert_eq!(cfg.hostname, "CUSTOM");
        // Relative output.path is resolved against config directory
        let expected_dir = dir.path().canonicalize().unwrap();
        assert_eq!(cfg.output.path, expected_dir.join("custom.jsonl"));
    }

    #[test]
    fn load_from_missing_custom_path_errors() {
        let result = SensorConfig::load_from(Some(std::path::Path::new("/nonexistent.toml")));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"), "error was: {err}");
    }

    #[test]
    fn load_from_none_uses_defaults_when_no_file() {
        // Run in a temp dir where no threatfalcon.toml exists
        let dir = tempfile::TempDir::new().unwrap();
        let _guard = std::env::set_current_dir(dir.path());
        // This may or may not find a file depending on the test runner's cwd,
        // but load_from(None) should never panic.
        let _ = SensorConfig::load_from(None);
    }

    #[test]
    fn with_base_dir_none_uses_relative_paths() {
        let cfg = SensorConfig::with_base_dir(None);
        assert_eq!(cfg.state_path, PathBuf::from("threatfalcon.state"));
        assert_eq!(cfg.output.path, PathBuf::from("threatfalcon_events.jsonl"));
    }

    #[test]
    fn with_base_dir_some_uses_absolute_paths() {
        let base = std::path::Path::new("C:\\ProgramData\\ThreatFalcon");
        let cfg = SensorConfig::with_base_dir(Some(base));

        assert_eq!(cfg.state_path, base.join("threatfalcon.state"));
        assert_eq!(cfg.output.path, base.join("threatfalcon_events.jsonl"));
        // health_interval and collectors unchanged
        assert_eq!(cfg.health_interval_secs, 60);
        assert!(cfg.collectors.etw.enabled);
    }

    #[test]
    fn with_base_dir_output_paths_match_sensor() {
        let base = std::path::Path::new("/opt/threatfalcon");
        let cfg = SensorConfig::with_base_dir(Some(base));

        assert!(cfg.state_path.starts_with(base));
        assert!(cfg.output.path.starts_with(base));
    }

    #[test]
    fn resolve_paths_skips_absolute() {
        let cfg = SensorConfig {
            state_path: PathBuf::from("/absolute/state.file"),
            output: OutputConfig {
                path: PathBuf::from("/absolute/events.jsonl"),
                spool_dir: Some(PathBuf::from("/absolute/spool")),
                ..OutputConfig::with_base_dir(None)
            },
            ..SensorConfig::with_base_dir(None)
        };
        let resolved = cfg.resolve_paths(Some(PathBuf::from("/other/dir")));
        // Absolute paths should not be rewritten
        assert_eq!(resolved.state_path, PathBuf::from("/absolute/state.file"));
        assert_eq!(resolved.output.path, PathBuf::from("/absolute/events.jsonl"));
        assert_eq!(resolved.output.spool_dir, Some(PathBuf::from("/absolute/spool")));
    }

    #[test]
    fn resolve_paths_resolves_relative() {
        let cfg = SensorConfig {
            state_path: PathBuf::from("my.state"),
            output: OutputConfig {
                path: PathBuf::from("events.jsonl"),
                spool_dir: Some(PathBuf::from("spool")),
                ..OutputConfig::with_base_dir(None)
            },
            ..SensorConfig::with_base_dir(None)
        };
        let anchor = PathBuf::from("/config/dir");
        let resolved = cfg.resolve_paths(Some(anchor.clone()));
        assert_eq!(resolved.state_path, anchor.join("my.state"));
        assert_eq!(resolved.output.path, anchor.join("events.jsonl"));
        assert_eq!(resolved.output.spool_dir, Some(anchor.join("spool")));
    }

    #[test]
    fn resolve_paths_none_anchor_leaves_unchanged() {
        let cfg = SensorConfig {
            state_path: PathBuf::from("my.state"),
            output: OutputConfig {
                path: PathBuf::from("events.jsonl"),
                ..OutputConfig::with_base_dir(None)
            },
            ..SensorConfig::with_base_dir(None)
        };
        let resolved = cfg.resolve_paths(None);
        assert_eq!(resolved.state_path, PathBuf::from("my.state"));
        assert_eq!(resolved.output.path, PathBuf::from("events.jsonl"));
    }

    #[test]
    fn spool_dir_resolved_relative_to_config_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("sensor.toml");
        std::fs::write(
            &config_path,
            "[output]\ntype = \"http\"\nurl = \"https://example.com\"\nspool_dir = \"spool\"\n",
        )
        .unwrap();

        let cfg = SensorConfig::load_from(Some(&config_path)).unwrap();
        let expected_dir = dir.path().canonicalize().unwrap();
        assert_eq!(
            cfg.output.spool_dir,
            Some(expected_dir.join("spool")),
        );
    }

    #[test]
    fn config_file_lookup_finds_in_cwd() {
        // find_config_file should discover a config in the given directory.
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join(CONFIG_FILE);
        std::fs::write(&config_path, "hostname = \"FROM-CWD\"\n").unwrap();

        let found = find_config_file(Some(dir.path()));
        assert_eq!(found, Some(config_path));
    }

    #[test]
    fn config_file_lookup_returns_none_when_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        // No config file written — should return None.
        let found = find_config_file(Some(dir.path()));
        assert_eq!(found, None);
    }

    #[test]
    fn state_path_resolved_relative_to_config_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let conf_dir = dir.path().join("conf");
        let config_path = conf_dir.join("sensor.toml");
        std::fs::create_dir_all(&conf_dir).unwrap();
        std::fs::write(
            &config_path,
            "state_path = \"my.state\"\n",
        )
        .unwrap();

        let cfg = SensorConfig::load_from(Some(&config_path)).unwrap();
        // state_path should be anchored to the config file's directory,
        // not the process cwd.
        assert!(cfg.state_path.is_absolute(), "state_path should be absolute: {:?}", cfg.state_path);
        // Canonicalize the expected dir to handle platform symlinks (e.g.
        // /var → /private/var on macOS).
        let expected_dir = conf_dir.canonicalize().unwrap();
        assert!(
            cfg.state_path.starts_with(&expected_dir),
            "state_path {:?} should be under config dir {:?}",
            cfg.state_path,
            expected_dir,
        );
    }

    #[test]
    fn rules_defaults_match_original_values() {
        let rules = RulesConfig::default();
        // Hunt defaults
        assert_eq!(rules.hunt.beaconing_threshold, 10);
        assert!(rules.hunt.lolbins.contains(&"certutil.exe".to_string()));
        assert!(rules.hunt.suspicious_parents.contains(&"winword.exe".to_string()));
        assert!(rules.hunt.suspicious_children.contains(&"cmd.exe".to_string()));
        // Score weights
        assert_eq!(rules.score.detection, 40);
        assert_eq!(rules.score.suspicious_parent, 20);
        assert_eq!(rules.score.lolbin, 20);
        assert_eq!(rules.score.unsigned_dll, 5);
        assert_eq!(rules.score.external_ip, 2);
        assert_eq!(rules.score.dns_query, 1);
        // Alert defaults
        assert_eq!(rules.alert.threshold, 40);
        assert_eq!(rules.alert.cooldown, 300);
    }

    #[test]
    fn rules_partial_override() {
        let toml = r#"
            [rules.score]
            detection = 100

            [rules.hunt]
            beaconing_threshold = 5

            [rules.alert]
            cooldown = 60
        "#;
        let cfg: SensorConfig = toml::from_str(toml).unwrap();
        // Overridden
        assert_eq!(cfg.rules.score.detection, 100);
        assert_eq!(cfg.rules.hunt.beaconing_threshold, 5);
        assert_eq!(cfg.rules.alert.cooldown, 60);
        // Defaults preserved
        assert_eq!(cfg.rules.score.lolbin, 20);
        assert_eq!(cfg.rules.alert.threshold, 40);
        assert!(cfg.rules.hunt.lolbins.contains(&"certutil.exe".to_string()));
    }

    #[test]
    fn rules_custom_lolbins() {
        let toml = r#"
            [rules.hunt]
            lolbins = ["custom.exe", "another.exe"]
        "#;
        let cfg: SensorConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.rules.hunt.lolbins, vec!["custom.exe", "another.exe"]);
        // suspicious_parents still has defaults
        assert!(cfg.rules.hunt.suspicious_parents.contains(&"winword.exe".to_string()));
    }

    #[test]
    fn rules_roundtrip() {
        let cfg = SensorConfig::default();
        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let cfg2: SensorConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg.rules.score.detection, cfg2.rules.score.detection);
        assert_eq!(cfg.rules.hunt.lolbins.len(), cfg2.rules.hunt.lolbins.len());
        assert_eq!(cfg.rules.alert.threshold, cfg2.rules.alert.threshold);
    }
}
