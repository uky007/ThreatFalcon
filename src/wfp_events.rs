//! WFP audit decisions are neither established flows nor threat verdicts.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WfpDecision {
    Permitted,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WfpConnectionAudit {
    pub decision: WfpDecision,
    /// EventData.ProcessID, NOT System.Execution.ProcessID. No lifetime ID.
    pub pid: Option<u32>,
    /// Native device path; never resolved using a later filesystem snapshot.
    pub application: Option<String>,
    // Source/destination retain the native field labels; no local/remote swap.
    pub source_address: Option<String>,
    pub source_port: Option<u16>,
    pub destination_address: Option<String>,
    pub destination_port: Option<u16>,
    pub protocol: Option<u8>,
    /// Unlocalized provider token. Unknown tokens are not guessed.
    pub direction_token: Option<String>,
    pub filter_runtime_id: Option<u64>,
    pub layer_runtime_id: Option<u64>,
    /// Names only, never values (including remote user/machine identifiers).
    pub omitted_fields: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WfpAuditStats {
    /// Subscription success does not verify audit policy or complete coverage.
    pub audit_policy_verified: bool,
    pub records_read: u64,
    pub fields_omitted: u64,
}
