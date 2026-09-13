//! Audit event identity is not process lifetime identity. Do not fabricate a
//! ProcessGuid or join audit PIDs to Windows/macOS feeds or /proc snapshots.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AuditStamp {
    pub seconds: i64,
    pub nanoseconds: u32,
    pub serial: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditValue {
    pub value: String,
    /// Audit hex encoding decoded only for documented string fields. Hex syscall
    /// arguments/architecture are never interpreted as strings or addresses.
    pub audit_hex_encoded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_utf8_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub native_type: u16,
    pub fields: BTreeMap<String, AuditValue>,
    /// Values never stored; names and counts make privacy filtering explicit.
    pub omitted_fields: Vec<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCompletion {
    EndOfEvent,
    Standalone,
    Timeout,
    Capacity,
    Shutdown,
    InputEnd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxAuditEvent {
    /// None for offline exports: current machine boot ID must not be assigned to
    /// old records. Caller-supplied live identity describes the audited kernel.
    pub boot_id: Option<Uuid>,
    pub collection_session_uuid: Uuid,
    pub transport: String,
    pub stamp: AuditStamp,
    pub completion: AuditCompletion,
    pub records: Vec<AuditRecord>,
    pub issues: Vec<String>,
}

impl LinuxAuditEvent {
    pub fn pid(&self) -> Option<u32> {
        let mut syscalls = self.records.iter().filter(|r| r.native_type == 1300);
        let first = syscalls.next()?;
        if syscalls.next().is_some() {
            return None;
        }
        first.fields.get("pid")?.value.parse().ok()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LinuxAuditStats {
    pub collection_session_uuid: Uuid,
    pub receive_buffer_bytes: u32,
    /// Read-only multicast doesn't query/control auditd or kernel audit policy.
    pub audit_configuration_verified: bool,
    pub records_received: u64,
    pub records_filtered: u64,
    pub fields_omitted: u64,
    pub malformed_records: u64,
    pub malformed_datagrams: u64,
    /// Notifications, NOT an exact lost-event count.
    pub socket_overruns: u64,
    pub truncated_datagrams: u64,
    pub events_without_eoe: u64,
    pub capacity_flushes: u64,
    pub late_records: u64,
}

impl LinuxAuditStats {
    pub fn quality_uncertain(&self) -> bool {
        self.malformed_records > 0
            || self.malformed_datagrams > 0
            || self.socket_overruns > 0
            || self.truncated_datagrams > 0
            || self.events_without_eoe > 0
            || self.capacity_flushes > 0
            || self.late_records > 0
    }
}
