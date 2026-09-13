//! Synthetic defensive telemetry only. These are not captured Windows events
//! and cannot establish real-world detection rate or false-positive rate.
use crate::collectors::sysmon_parser::{map_to_threat_event, parse_sysmon_xml};
use crate::events::*;
use uuid::Uuid;
pub const ACTOR: &str = "11111111-1111-1111-1111-111111111111";
pub const TARGET: &str = "22222222-2222-2222-2222-222222222222";
pub const OTHER: &str = "33333333-3333-3333-3333-333333333333";

pub fn sysmon(id: u16, seconds: i64, process: &str) -> ThreatEvent {
    let time = chrono::DateTime::from_timestamp(1_750_000_000 + seconds, 0).unwrap();
    let prefix = if matches!(id, 8 | 10) {
        "SourceProcess"
    } else {
        "Process"
    };
    let xml = format!(
        r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/>
        <EventID>{id}</EventID><Version>5</Version></System><EventData>
        <Data Name="UtcTime">{time}</Data><Data Name="{prefix}GUID">{{{process}}}</Data>
        <Data Name="{prefix}Id">100</Data><Data Name="TargetProcessGUID">{{{TARGET}}}</Data>
        <Data Name="TargetProcessId">200</Data><Data Name="GrantedAccess">0x1fffff</Data>
        <Data Name="StartAddress">0x10000</Data><Data Name="SourceImage">C:\fixture\source.exe</Data>
        <Data Name="TargetImage">C:\fixture\target.exe</Data>
        <Data Name="ParentProcessGuid">{{{OTHER}}}</Data><Data Name="ParentProcessId">50</Data>
        <Data Name="ParentImage">C:\Program Files\Office\WINWORD.EXE</Data>
        <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
        <Data Name="CommandLine">powershell.exe -NoProfile</Data>
        <Data Name="Initiated">true</Data><Data Name="Protocol">tcp</Data>
        <Data Name="SourceIp">10.0.0.1</Data><Data Name="SourcePort">50000</Data>
        <Data Name="DestinationIp">192.0.2.10</Data><Data Name="DestinationPort">443</Data>
        </EventData></Event>"#,
        time = time.to_rfc3339()
    );
    map_to_threat_event(
        &parse_sysmon_xml(&xml).unwrap(),
        &AgentInfo {
            hostname: "synthetic-fixture".into(),
            agent_id: Uuid::from_u128(1),
        },
    )
    .unwrap()
}
