use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unified telemetry event from all collection sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub source: EventSource,
    pub category: EventCategory,
    pub severity: Severity,
    pub data: EventData,
    /// Present only on detection events — provides structured context
    /// for why this event was flagged as suspicious.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<RuleMetadata>,
}

/// Structured metadata attached to detection events for explainability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub mitre: MitreRef,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
}

/// MITRE ATT&CK reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreRef {
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl ThreatEvent {
    /// Create a telemetry event (no rule metadata).
    pub fn new(
        hostname: &str,
        source: EventSource,
        category: EventCategory,
        severity: Severity,
        data: EventData,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            hostname: hostname.to_string(),
            source,
            category,
            severity,
            data,
            rule: None,
        }
    }

    /// Create a detection event with rule metadata.
    #[allow(dead_code)] // used by collectors on Windows only
    pub fn with_rule(
        hostname: &str,
        source: EventSource,
        category: EventCategory,
        severity: Severity,
        data: EventData,
        rule: RuleMetadata,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            hostname: hostname.to_string(),
            source,
            category,
            severity,
            data,
            rule: Some(rule),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventSource {
    Etw { provider: String },
    Sysmon { event_id: u16 },
    EvasionDetector,
    Sensor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventCategory {
    Process,
    File,
    Network,
    Registry,
    ImageLoad,
    Dns,
    Evasion,
    Script,
    Health,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventData {
    ProcessCreate {
        pid: u32,
        ppid: u32,
        image_path: String,
        command_line: String,
        user: String,
        integrity_level: String,
        hashes: Option<String>,
    },
    ProcessTerminate {
        pid: u32,
        image_path: String,
    },
    FileCreate {
        pid: u32,
        path: String,
        operation: FileOperation,
    },
    FileDelete {
        pid: u32,
        path: String,
    },
    NetworkConnect {
        pid: u32,
        image_path: String,
        protocol: String,
        src_addr: String,
        src_port: u16,
        dst_addr: String,
        dst_port: u16,
        direction: NetworkDirection,
    },
    RegistryEvent {
        pid: u32,
        operation: RegistryOperation,
        key: String,
        value_name: Option<String>,
        value_data: Option<String>,
    },
    ImageLoad {
        pid: u32,
        image_path: String,
        image_name: String,
        signed: bool,
        signature: Option<String>,
        hashes: Option<String>,
    },
    DnsQuery {
        pid: u32,
        query_name: String,
        query_type: String,
        response: Option<String>,
    },
    ScriptBlock {
        pid: u32,
        script_engine: String,
        content: String,
    },
    AmsiScan {
        pid: u32,
        app_name: String,
        content_name: String,
        content_size: u32,
        scan_result: u32,
    },
    EvasionDetected {
        technique: EvasionTechnique,
        pid: Option<u32>,
        process_name: Option<String>,
        details: String,
    },
    CreateRemoteThread {
        source_pid: u32,
        target_pid: u32,
        start_address: String,
        source_image: String,
        target_image: String,
    },
    ProcessAccess {
        source_pid: u32,
        target_pid: u32,
        granted_access: u32,
        source_image: String,
        target_image: String,
    },
    PipeEvent {
        pid: u32,
        pipe_name: String,
        operation: PipeOperation,
        image_path: String,
    },
    SensorHealth {
        uptime_secs: u64,
        events_total: u64,
        events_dropped: u64,
        collectors: Vec<CollectorStatus>,
    },
}

/// Status of a single collector, included in health events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorStatus {
    pub name: String,
    pub state: CollectorState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CollectorState {
    Running,
    Stopped,
    Disabled,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileOperation {
    Create,
    Modify,
    Rename,
    SetInfo,
    StreamCreate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryOperation {
    CreateKey,
    DeleteKey,
    SetValue,
    DeleteValue,
    RenameKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvasionTechnique {
    EtwPatching,
    AmsiBypass,
    NtdllUnhooking,
    DirectSyscall,
    ProcessHollowing,
    ProcessHerpaderping,
    DllSearchOrderHijack,
    ParentPidSpoofing,
    /// Technique could not be determined from available evidence.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PipeOperation {
    Created,
    Connected,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_event_serialization() {
        let event = ThreatEvent::new(
            "TEST-HOST",
            EventSource::Sensor,
            EventCategory::Health,
            Severity::Info,
            EventData::SensorHealth {
                uptime_secs: 120,
                events_total: 5000,
                events_dropped: 3,
                collectors: vec![
                    CollectorStatus {
                        name: "ETW".into(),
                        state: CollectorState::Running,
                    },
                    CollectorStatus {
                        name: "Sysmon".into(),
                        state: CollectorState::Disabled,
                    },
                ],
            },
        );

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"SensorHealth\""));
        assert!(json.contains("\"uptime_secs\":120"));
        assert!(json.contains("\"events_total\":5000"));
        assert!(json.contains("\"events_dropped\":3"));
        assert!(json.contains("\"Running\""));
        assert!(json.contains("\"Disabled\""));
        // rule should not be present for health events
        assert!(!json.contains("\"rule\""));
    }

    #[test]
    fn health_event_roundtrip() {
        let event = ThreatEvent::new(
            "HOST",
            EventSource::Sensor,
            EventCategory::Health,
            Severity::Info,
            EventData::SensorHealth {
                uptime_secs: 60,
                events_total: 100,
                events_dropped: 0,
                collectors: vec![],
            },
        );

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ThreatEvent = serde_json::from_str(&json).unwrap();

        match deserialized.data {
            EventData::SensorHealth {
                uptime_secs,
                events_total,
                events_dropped,
                collectors,
            } => {
                assert_eq!(uptime_secs, 60);
                assert_eq!(events_total, 100);
                assert_eq!(events_dropped, 0);
                assert!(collectors.is_empty());
            }
            _ => panic!("expected SensorHealth"),
        }
        assert!(deserialized.rule.is_none());
    }
}
