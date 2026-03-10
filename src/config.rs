use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorConfig {
    pub hostname: String,
    pub output: OutputConfig,
    pub collectors: CollectorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub path: PathBuf,
    pub format: OutputFormat,
    pub rotation_size_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    JsonLines,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorConfig {
    pub etw: EtwConfig,
    pub sysmon: SysmonConfig,
    pub evasion: EvasionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwConfig {
    pub enabled: bool,
    pub providers: Vec<EtwProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwProviderConfig {
    pub name: String,
    pub guid: String,
    pub level: u8,
    pub keywords: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysmonConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    pub enabled: bool,
    pub scan_interval_ms: u64,
    pub detect_etw_patching: bool,
    pub detect_amsi_bypass: bool,
    pub detect_unhooking: bool,
    pub detect_direct_syscall: bool,
}

impl SensorConfig {
    pub fn load() -> Result<Self> {
        // TODO: Load from TOML/YAML config file
        Ok(Self::default())
    }
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            hostname: hostname(),
            output: OutputConfig {
                path: PathBuf::from("threatfalcon_events.jsonl"),
                format: OutputFormat::JsonLines,
                rotation_size_mb: 100,
            },
            collectors: CollectorConfig {
                etw: EtwConfig {
                    enabled: true,
                    providers: default_etw_providers(),
                },
                sysmon: SysmonConfig {
                    enabled: false,
                },
                evasion: EvasionConfig {
                    enabled: true,
                    scan_interval_ms: 5000,
                    detect_etw_patching: true,
                    detect_amsi_bypass: true,
                    detect_unhooking: true,
                    detect_direct_syscall: true,
                },
            },
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
