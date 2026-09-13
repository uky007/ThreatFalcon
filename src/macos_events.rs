//! Platform-native semantics: exec replaces an image; it is not a Windows
//! ProcessCreate. Audit pidversion changes on exec AND on PID reuse.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosText {
    pub value: String,
    /// Preserves the bounded original bytes when they are not valid UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_utf8_hex: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[repr(C)]
pub struct MacosIdentity {
    pub pid: u32,
    pub pidversion: u32,
    pub euid: u32,
    pub ruid: u32,
    pub egid: u32,
    pub rgid: u32,
    pub auid: u32,
    pub asid: u32,
}

impl MacosIdentity {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn process_key(&self, agent: Uuid, boot: Uuid) -> String {
        format!("macos-es:{agent}:{boot}:{}:{}", self.pid, self.pidversion)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosFile {
    pub path: MacosText,
    pub path_truncated_by_os: bool,
    pub inode: u64,
    pub device: i32,
    pub mode: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosProcess {
    pub identity: MacosIdentity,
    pub parent: Option<MacosIdentity>,
    pub responsible: Option<MacosIdentity>,
    pub ppid: u32,
    pub original_ppid: u32,
    pub start_time: Option<DateTime<Utc>>,
    pub executable: MacosFile,
    /// Native flags at event time; not an independent trust/notarization verdict.
    pub codesigning_flags: u32,
    pub is_platform_binary: bool,
    pub is_es_client: bool,
    /// Code-directory hash, NOT a whole-file hash.
    pub cdhash: String,
    pub signing_id: MacosText,
    pub team_id: MacosText,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MacosEventKind {
    Exec,
    Fork,
    Exit,
    Create,
    Rename,
    Unlink,
    Close,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosRecord {
    pub boot_session_uuid: Uuid,
    /// Sequence numbers are scoped to this subscription, not the boot or host.
    pub collection_session_uuid: Uuid,
    pub message_version: u32,
    pub native_event_type: u32,
    pub kind: MacosEventKind,
    pub original_time: bool,
    pub time_seconds: i64,
    pub time_nanoseconds: i64,
    pub mach_time: u64,
    pub seq_num: Option<u64>,
    pub global_seq_num: Option<u64>,
    /// Pre-exec actor for Exec; parent for Fork; acting process otherwise.
    pub actor: MacosProcess,
    /// Post-exec image / fork child; no PID-only joining.
    pub target: Option<MacosProcess>,
    pub file: Option<MacosFile>,
    /// Existing destination file, or directory when destination_is_new_path.
    pub destination: Option<MacosFile>,
    pub destination_name: Option<MacosText>,
    pub destination_is_new_path: bool,
    pub modified: Option<bool>,
    pub was_mapped_writable: Option<bool>,
    /// Native wait(2) status, not a decoded exit code.
    pub exit_status: Option<i32>,
    pub result_type: u32,
    pub result_value: u32,
    pub issues: Vec<String>,
}

impl MacosRecord {
    pub fn subject(&self) -> &MacosProcess {
        if matches!(self.kind, MacosEventKind::Exec | MacosEventKind::Fork) {
            self.target.as_ref().unwrap_or(&self.actor)
        } else {
            &self.actor
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EndpointSecurityStats {
    pub collection_session_uuid: Uuid,
    /// Lower bound: gaps after the first observed sequence, not outage recovery.
    pub sequence_drops: u64,
    pub sequence_discontinuities: u64,
    pub sequence_unavailable: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_identity_separates_exec_reuse_hosts_and_boots() {
        let first = MacosIdentity {
            pid: 123,
            pidversion: 4,
            ..Default::default()
        };
        let next = MacosIdentity {
            pidversion: 5,
            ..first
        };
        let agent = Uuid::new_v4();
        let boot = Uuid::new_v4();
        let key = first.process_key(agent, boot);
        assert_ne!(key, next.process_key(agent, boot));
        assert_ne!(key, first.process_key(Uuid::new_v4(), boot));
        assert_ne!(key, first.process_key(agent, Uuid::new_v4()));
    }
}
