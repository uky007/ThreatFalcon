use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Shared identity that every event is stamped with.
#[derive(Debug, Clone)]
pub struct AgentInfo {
    pub hostname: String,
    pub agent_id: Uuid,
}

/// Unified telemetry event from all collection sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub agent_id: Uuid,
    pub sensor_version: String,
    pub source: EventSource,
    pub category: EventCategory,
    pub severity: Severity,
    pub data: EventData,
    /// Present only on detection events — provides structured context
    /// for why this event was flagged as suspicious.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<RuleMetadata>,
    /// Process identity and metadata for the process that produced this
    /// event. Populated by the sensor's process context cache from
    /// ProcessCreate observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_context: Option<ProcessContext>,
}

/// Stable process identity and cached metadata, attached to events by the
/// sensor's enrichment pipeline. `process_key` is derived from PID +
/// creation timestamp to survive PID reuse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessContext {
    pub process_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
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
        agent: &AgentInfo,
        source: EventSource,
        category: EventCategory,
        severity: Severity,
        data: EventData,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            hostname: agent.hostname.clone(),
            agent_id: agent.agent_id,
            sensor_version: env!("CARGO_PKG_VERSION").to_string(),
            source,
            category,
            severity,
            data,
            rule: None,
            process_context: None,
        }
    }

    /// Create a detection event with rule metadata.
    #[allow(dead_code)] // used by collectors on Windows only
    pub fn with_rule(
        agent: &AgentInfo,
        source: EventSource,
        category: EventCategory,
        severity: Severity,
        data: EventData,
        rule: RuleMetadata,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            hostname: agent.hostname.clone(),
            agent_id: agent.agent_id,
            sensor_version: env!("CARGO_PKG_VERSION").to_string(),
            source,
            category,
            severity,
            data,
            rule: Some(rule),
            process_context: None,
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
        /// OS-level process creation timestamp (Windows FILETIME from ETW).
        /// Used to derive `process_key` for stable identity across PID reuse.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        create_time: Option<u64>,
    },
    ProcessTerminate {
        pid: u32,
        image_path: String,
        /// OS-level process creation timestamp, matching the corresponding
        /// ProcessCreate event for correlation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        create_time: Option<u64>,
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
        /// Script file path (if available from ETW ScriptBlockLogging).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        script_path: Option<String>,
        /// GUID linking multi-part script blocks from the same script.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        script_block_id: Option<String>,
    },
    AmsiScan {
        pid: u32,
        app_name: String,
        content_name: String,
        content_size: u32,
        scan_result: u32,
        /// Human-readable AMSI_RESULT name (e.g. "AMSI_RESULT_DETECTED").
        #[serde(default)]
        scan_result_name: String,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        sink: Option<SinkStatus>,
    },
}

/// Status of a single collector, included in health events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorStatus {
    pub name: String,
    pub state: CollectorState,
}

/// Status of the output sink, included in health events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkStatus {
    pub sink_type: String,
    pub events_dropped: u64,
    /// Number of spool files currently on disk awaiting re-delivery.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub spool_files: u64,
    /// Total bytes of spooled data currently on disk.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub spool_bytes: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
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

/// Map an AMSI_RESULT numeric value to a human-readable name.
///
/// Values follow the Windows AMSI_RESULT enum:
/// <https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result>
#[allow(dead_code)] // used by ETW collector on Windows; tested cross-platform
pub fn amsi_result_name(result: u32) -> &'static str {
    match result {
        0 => "AMSI_RESULT_CLEAN",
        1 => "AMSI_RESULT_NOT_DETECTED",
        16384..=20479 => "AMSI_RESULT_BLOCKED_BY_ADMIN",
        32768.. => "AMSI_RESULT_DETECTED",
        _ => "AMSI_RESULT_NOT_DETECTED",
    }
}

impl EventData {
    /// Return the PID of the process that performed the action, if applicable.
    /// ProcessCreate and ProcessTerminate are excluded — they are handled
    /// separately by the process cache (insert / evict).
    pub fn acting_pid(&self) -> Option<u32> {
        match self {
            Self::FileCreate { pid, .. }
            | Self::FileDelete { pid, .. }
            | Self::NetworkConnect { pid, .. }
            | Self::RegistryEvent { pid, .. }
            | Self::ImageLoad { pid, .. }
            | Self::DnsQuery { pid, .. }
            | Self::ScriptBlock { pid, .. }
            | Self::AmsiScan { pid, .. }
            | Self::PipeEvent { pid, .. } => Some(*pid),
            Self::EvasionDetected { pid, .. } => *pid,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent() -> AgentInfo {
        AgentInfo {
            hostname: "TEST-HOST".into(),
            agent_id: Uuid::nil(),
        }
    }

    #[test]
    fn health_event_serialization() {
        let event = ThreatEvent::new(
            &test_agent(),
            EventSource::Sensor,
            EventCategory::Health,
            Severity::Info,
            EventData::SensorHealth {
                uptime_secs: 120,
                events_total: 5000,
                events_dropped: 3,
                sink: None,
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
        assert!(json.contains("\"agent_id\""));
        assert!(json.contains("\"sensor_version\""));
        // rule should not be present for health events
        assert!(!json.contains("\"rule\""));
    }

    #[test]
    fn health_event_roundtrip() {
        let event = ThreatEvent::new(
            &test_agent(),
            EventSource::Sensor,
            EventCategory::Health,
            Severity::Info,
            EventData::SensorHealth {
                uptime_secs: 60,
                events_total: 100,
                events_dropped: 0,
                collectors: vec![],
                sink: None,
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
                ..
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

    // --- Rule metadata policy tests ------------------------------------------
    // These tests codify the telemetry vs detection boundary and ensure
    // consistency of rule properties across collectors.

    #[test]
    fn telemetry_event_has_no_rule() {
        let event = ThreatEvent::new(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Windows-Kernel-Process".into(),
            },
            EventCategory::Process,
            Severity::Info,
            EventData::ProcessCreate {
                pid: 1,
                ppid: 0,
                image_path: "cmd.exe".into(),
                command_line: "cmd.exe".into(),
                user: String::new(),
                integrity_level: String::new(),
                hashes: None,
                create_time: None,
            },
        );
        assert!(event.rule.is_none(), "telemetry events must not carry rules");
    }

    #[test]
    fn detection_event_has_rule() {
        let event = ThreatEvent::with_rule(
            &test_agent(),
            EventSource::Etw {
                provider: "Microsoft-Windows-Threat-Intelligence".into(),
            },
            EventCategory::Evasion,
            Severity::High,
            EventData::EvasionDetected {
                technique: EvasionTechnique::Unknown,
                pid: Some(1),
                process_name: None,
                details: "test".into(),
            },
            RuleMetadata {
                id: "TF-TI-001".into(),
                name: "test".into(),
                description: "test".into(),
                mitre: MitreRef {
                    tactic: "Defense Evasion".into(),
                    technique_id: "T1055".into(),
                    technique_name: "Process Injection".into(),
                },
                confidence: Confidence::Medium,
                evidence: vec!["test".into()],
            },
        );
        assert!(event.rule.is_some(), "detection events must carry rules");
    }

    #[test]
    fn rule_metadata_roundtrip() {
        let event = ThreatEvent::with_rule(
            &test_agent(),
            EventSource::EvasionDetector,
            EventCategory::Evasion,
            Severity::Critical,
            EventData::EvasionDetected {
                technique: EvasionTechnique::EtwPatching,
                pid: Some(100),
                process_name: None,
                details: "patched".into(),
            },
            RuleMetadata {
                id: "TF-EVA-001".into(),
                name: "ETW Event Write Patching".into(),
                description: "desc".into(),
                mitre: MitreRef {
                    tactic: "Defense Evasion".into(),
                    technique_id: "T1562.006".into(),
                    technique_name: "Impair Defenses: Indicator Blocking".into(),
                },
                confidence: Confidence::High,
                evidence: vec!["byte 0xC3".into()],
            },
        );

        let json = serde_json::to_string(&event).unwrap();
        let rt: ThreatEvent = serde_json::from_str(&json).unwrap();

        let rule = rt.rule.unwrap();
        assert_eq!(rule.id, "TF-EVA-001");
        assert_eq!(rule.confidence, Confidence::High);
        assert_eq!(rule.mitre.technique_id, "T1562.006");
        assert_eq!(rule.evidence.len(), 1);
    }

    #[test]
    fn severity_ordering() {
        // Verify severity enum ordering: Info < Low < Medium < High < Critical
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn rule_metadata_json_excludes_null_rule() {
        // ThreatEvent::new() produces rule: None which should be omitted
        let event = ThreatEvent::new(
            &test_agent(),
            EventSource::Sensor,
            EventCategory::Health,
            Severity::Info,
            EventData::SensorHealth {
                uptime_secs: 0,
                events_total: 0,
                events_dropped: 0,
                collectors: vec![],
                sink: None,
            },
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("rule"),
            "rule:None must be omitted from JSON via skip_serializing_if"
        );
    }

    // --- AMSI result name tests -----------------------------------------------

    #[test]
    fn amsi_result_name_clean() {
        assert_eq!(amsi_result_name(0), "AMSI_RESULT_CLEAN");
    }

    #[test]
    fn amsi_result_name_not_detected() {
        assert_eq!(amsi_result_name(1), "AMSI_RESULT_NOT_DETECTED");
    }

    #[test]
    fn amsi_result_name_blocked_by_admin() {
        assert_eq!(amsi_result_name(16384), "AMSI_RESULT_BLOCKED_BY_ADMIN");
        assert_eq!(amsi_result_name(20479), "AMSI_RESULT_BLOCKED_BY_ADMIN");
    }

    #[test]
    fn amsi_result_name_detected() {
        assert_eq!(amsi_result_name(32768), "AMSI_RESULT_DETECTED");
        assert_eq!(amsi_result_name(65535), "AMSI_RESULT_DETECTED");
    }
}
