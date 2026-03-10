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
}

impl ThreatEvent {
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventSource {
    Etw { provider: String },
    Sysmon { event_id: u16 },
    EvasionDetector,
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
    DllSearchOrderHijack,
    ParentPidSpoofing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PipeOperation {
    Created,
    Connected,
}
