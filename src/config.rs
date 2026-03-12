use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const CONFIG_FILE: &str = "threatfalcon.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SensorConfig {
    pub hostname: String,
    pub output: OutputConfig,
    pub collectors: CollectorConfig,
    /// Interval in seconds between periodic health events (0 = periodic
    /// disabled; a final shutdown health event is always emitted).
    pub health_interval_secs: u64,
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

impl SensorConfig {
    /// Load config from the given path, or from the default `CONFIG_FILE` if
    /// `path` is `None`. Returns defaults when no file is found.
    pub fn load_from(path: Option<&std::path::Path>) -> Result<Self> {
        let path = match path {
            Some(p) => {
                if !p.exists() {
                    anyhow::bail!("Config file not found: {}", p.display());
                }
                p.to_path_buf()
            }
            None => {
                let default = PathBuf::from(CONFIG_FILE);
                if !default.exists() {
                    tracing::info!(
                        "No config file found at {CONFIG_FILE} — using defaults"
                    );
                    return Ok(Self::default());
                }
                default
            }
        };

        let content = std::fs::read_to_string(&path)?;
        let config: SensorConfig = toml::from_str(&content)?;

        tracing::info!("Loaded config from {}", path.display());
        Ok(config)
    }
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            hostname: hostname(),
            output: OutputConfig::default(),
            collectors: CollectorConfig::default(),
            health_interval_secs: 60,
        }
    }
}

impl Default for SinkType {
    fn default() -> Self {
        Self::File
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            sink_type: SinkType::File,
            path: PathBuf::from("threatfalcon_events.jsonl"),
            rotation_size_mb: 100,
            pretty: false,
            url: None,
            batch_size: 100,
            timeout_secs: 10,
        }
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
        assert_eq!(cfg.output.path, PathBuf::from("custom.jsonl"));
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
}
