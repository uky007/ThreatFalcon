//! Cross-platform Sysmon XML parser and event mapper.
//!
//! This module is intentionally NOT gated behind `cfg(windows)` so that the
//! parsing and mapping logic can be tested on any platform.
#![allow(dead_code)] // Used by sysmon.rs on Windows only; tested on all platforms

use std::collections::HashMap;

use crate::events::*;

// ---------------------------------------------------------------------------
// Parsed event with typed accessors
// ---------------------------------------------------------------------------

/// A Sysmon event parsed from EvtRender XML.
pub struct SysmonParsedEvent {
    pub event_id: u16,
    fields: HashMap<String, String>,
}

impl SysmonParsedEvent {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|s| s.as_str())
    }

    pub fn get_string(&self, key: &str) -> String {
        self.fields.get(key).cloned().unwrap_or_default()
    }

    pub fn get_u32(&self, key: &str) -> u32 {
        self.fields
            .get(key)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    pub fn get_u16(&self, key: &str) -> u16 {
        self.fields
            .get(key)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    pub fn get_hex_u32(&self, key: &str) -> u32 {
        self.fields
            .get(key)
            .and_then(|s| {
                let s = s.trim_start_matches("0x").trim_start_matches("0X");
                u32::from_str_radix(s, 16).ok()
            })
            .unwrap_or(0)
    }

    pub fn get_bool(&self, key: &str) -> bool {
        self.fields
            .get(key)
            .map(|s| s.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// XML parsing
// ---------------------------------------------------------------------------

/// Parse Sysmon XML (rendered by EvtRender) into a structured event.
pub fn parse_sysmon_xml(xml: &str) -> Option<SysmonParsedEvent> {
    let event_id = extract_event_id(xml)?;
    let fields = extract_event_data_fields(xml);
    Some(SysmonParsedEvent { event_id, fields })
}

fn extract_event_id(xml: &str) -> Option<u16> {
    let tag = "<EventID>";
    let close = "</EventID>";
    let start = xml.find(tag)? + tag.len();
    let end = xml[start..].find(close)?;
    xml[start..start + end].trim().parse().ok()
}

/// Extract all `<Data Name="key">value</Data>` elements within `<EventData>`.
fn extract_event_data_fields(xml: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();

    let section_start = match xml.find("<EventData>") {
        Some(pos) => pos,
        None => return fields,
    };
    let section = match xml[section_start..].find("</EventData>") {
        Some(end) => &xml[section_start..section_start + end],
        None => return fields,
    };

    let name_marker = "Name=\"";
    let mut pos = 0;

    while let Some(rel) = section[pos..].find(name_marker) {
        let name_start = pos + rel + name_marker.len();

        // Extract field name up to closing quote
        let name_end = match section[name_start..].find('"') {
            Some(e) => name_start + e,
            None => break,
        };
        let name = &section[name_start..name_end];

        // Find the '>' that closes this <Data> opening tag
        let after_attr = name_end + 1;
        let gt_pos = match section[after_attr..].find('>') {
            Some(e) => after_attr + e,
            None => break,
        };

        // Self-closing tag: <Data Name="X"/> — skip
        let between = &section[after_attr..gt_pos];
        if between.trim_end().ends_with('/') {
            pos = gt_pos + 1;
            continue;
        }

        let val_start = gt_pos + 1;

        // Find </Data>
        let val_end = match section[val_start..].find("</Data>") {
            Some(e) => val_start + e,
            None => break,
        };

        let raw_value = &section[val_start..val_end];
        if !raw_value.is_empty() {
            fields.insert(name.to_string(), decode_xml_entities(raw_value));
        }

        pos = val_end + "</Data>".len();
    }

    fields
}

fn decode_xml_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

// ---------------------------------------------------------------------------
// Event mapping: SysmonParsedEvent → ThreatEvent
// ---------------------------------------------------------------------------

/// Convert a parsed Sysmon event into a unified `ThreatEvent`.
pub fn map_to_threat_event(
    parsed: &SysmonParsedEvent,
    hostname: &str,
) -> Option<ThreatEvent> {
    let eid = parsed.event_id;
    let source = EventSource::Sysmon { event_id: eid };

    let (cat, sev, data) = match eid {
        // Event 1: Process Create
        1 => (
            EventCategory::Process,
            Severity::Info,
            EventData::ProcessCreate {
                pid: parsed.get_u32("ProcessId"),
                ppid: parsed.get_u32("ParentProcessId"),
                image_path: parsed.get_string("Image"),
                command_line: parsed.get_string("CommandLine"),
                user: parsed.get_string("User"),
                integrity_level: parsed.get_string("IntegrityLevel"),
                hashes: parsed.get("Hashes").map(String::from),
            },
        ),

        // Event 3: Network Connection
        3 => {
            let direction = if parsed.get_bool("Initiated") {
                NetworkDirection::Outbound
            } else {
                NetworkDirection::Inbound
            };
            (
                EventCategory::Network,
                Severity::Info,
                EventData::NetworkConnect {
                    pid: parsed.get_u32("ProcessId"),
                    image_path: parsed.get_string("Image"),
                    protocol: parsed.get_string("Protocol"),
                    src_addr: parsed.get_string("SourceIp"),
                    src_port: parsed.get_u16("SourcePort"),
                    dst_addr: parsed.get_string("DestinationIp"),
                    dst_port: parsed.get_u16("DestinationPort"),
                    direction,
                },
            )
        }

        // Event 5: Process Terminated
        5 => (
            EventCategory::Process,
            Severity::Info,
            EventData::ProcessTerminate {
                pid: parsed.get_u32("ProcessId"),
                image_path: parsed.get_string("Image"),
            },
        ),

        // Event 6: Driver Loaded
        6 => {
            let image = parsed.get_string("ImageLoaded");
            let name = image
                .rsplit('\\')
                .next()
                .unwrap_or(&image)
                .to_string();
            (
                EventCategory::ImageLoad,
                Severity::Info,
                EventData::ImageLoad {
                    pid: 0,
                    image_path: image,
                    image_name: name,
                    signed: parsed.get_bool("Signed"),
                    signature: parsed.get("Signature").map(String::from),
                    hashes: parsed.get("Hashes").map(String::from),
                },
            )
        }

        // Event 7: Image Loaded (DLL)
        7 => {
            let image = parsed.get_string("ImageLoaded");
            let name = image
                .rsplit('\\')
                .next()
                .unwrap_or(&image)
                .to_string();
            (
                EventCategory::ImageLoad,
                Severity::Info,
                EventData::ImageLoad {
                    pid: parsed.get_u32("ProcessId"),
                    image_path: image,
                    image_name: name,
                    signed: parsed.get_bool("Signed"),
                    signature: parsed.get("Signature").map(String::from),
                    hashes: parsed.get("Hashes").map(String::from),
                },
            )
        }

        // Event 8: CreateRemoteThread
        8 => (
            EventCategory::Process,
            Severity::High,
            EventData::CreateRemoteThread {
                source_pid: parsed.get_u32("SourceProcessId"),
                target_pid: parsed.get_u32("TargetProcessId"),
                start_address: parsed.get_string("StartAddress"),
                source_image: parsed.get_string("SourceImage"),
                target_image: parsed.get_string("TargetImage"),
            },
        ),

        // Event 10: ProcessAccess
        10 => (
            EventCategory::Process,
            Severity::Medium,
            EventData::ProcessAccess {
                source_pid: parsed.get_u32("SourceProcessId"),
                target_pid: parsed.get_u32("TargetProcessId"),
                granted_access: parsed.get_hex_u32("GrantedAccess"),
                source_image: parsed.get_string("SourceImage"),
                target_image: parsed.get_string("TargetImage"),
            },
        ),

        // Event 11: FileCreate
        11 => (
            EventCategory::File,
            Severity::Info,
            EventData::FileCreate {
                pid: parsed.get_u32("ProcessId"),
                path: parsed.get_string("TargetFilename"),
                operation: FileOperation::Create,
            },
        ),

        // Events 12/13/14: Registry
        12 | 13 | 14 => {
            let op = match eid {
                12 => RegistryOperation::CreateKey,
                13 => RegistryOperation::SetValue,
                14 => RegistryOperation::RenameKey,
                _ => unreachable!(),
            };
            let value_data = if eid == 13 {
                parsed.get("Details").map(String::from)
            } else {
                None
            };
            (
                EventCategory::Registry,
                Severity::Info,
                EventData::RegistryEvent {
                    pid: parsed.get_u32("ProcessId"),
                    operation: op,
                    key: parsed.get_string("TargetObject"),
                    value_name: None,
                    value_data,
                },
            )
        }

        // Event 15: FileCreateStreamHash (Alternate Data Stream)
        15 => (
            EventCategory::File,
            Severity::Medium,
            EventData::FileCreate {
                pid: parsed.get_u32("ProcessId"),
                path: parsed.get_string("TargetFilename"),
                operation: FileOperation::StreamCreate,
            },
        ),

        // Events 17/18: Pipe Created/Connected
        17 | 18 => {
            let op = if eid == 17 {
                PipeOperation::Created
            } else {
                PipeOperation::Connected
            };
            (
                EventCategory::Process,
                Severity::Info,
                EventData::PipeEvent {
                    pid: parsed.get_u32("ProcessId"),
                    pipe_name: parsed.get_string("PipeName"),
                    operation: op,
                    image_path: parsed.get_string("Image"),
                },
            )
        }

        // Event 22: DNS Query
        22 => (
            EventCategory::Dns,
            Severity::Info,
            EventData::DnsQuery {
                pid: parsed.get_u32("ProcessId"),
                query_name: parsed.get_string("QueryName"),
                query_type: parsed.get_string("QueryType"),
                response: parsed.get("QueryResults").map(String::from),
            },
        ),

        // Events 23/26: FileDelete (archived / detected)
        23 | 26 => (
            EventCategory::File,
            Severity::Info,
            EventData::FileDelete {
                pid: parsed.get_u32("ProcessId"),
                path: parsed.get_string("TargetFilename"),
            },
        ),

        // Event 25: Process Tampering — branch on Type for accurate mapping
        25 => {
            let tampering_type = parsed.get_string("Type");
            let target_pid = parsed.get_u32("ProcessId");
            let image = parsed.get("Image").map(String::from);

            // Map Type to specific MITRE technique
            let (rule_id, rule_name, description, technique_id, technique_name, technique) =
                match tampering_type.as_str() {
                    "Image is replaced" => (
                        "TF-SYS-001a",
                        "Process Hollowing Detected (Sysmon)",
                        "The process image was replaced after creation, \
                         indicating process hollowing.",
                        "T1055.012",
                        "Process Injection: Process Hollowing",
                        EvasionTechnique::ProcessHollowing,
                    ),
                    "Image is locked for access" => (
                        "TF-SYS-001b",
                        "Process Herpaderping Detected (Sysmon)",
                        "The process image file was locked, preventing \
                         inspection — consistent with process herpaderping.",
                        "T1055",
                        "Process Injection",
                        EvasionTechnique::ProcessHerpaderping,
                    ),
                    _ => (
                        "TF-SYS-001",
                        "Process Tampering Detected (Sysmon)",
                        "Sysmon detected an unrecognized process tampering \
                         type. The specific technique could not be determined.",
                        "T1055",
                        "Process Injection",
                        EvasionTechnique::Unknown,
                    ),
                };

            let rule = RuleMetadata {
                id: rule_id.into(),
                name: rule_name.into(),
                description: description.into(),
                mitre: MitreRef {
                    tactic: "Defense Evasion".into(),
                    technique_id: technique_id.into(),
                    technique_name: technique_name.into(),
                },
                confidence: Confidence::High,
                evidence: vec![
                    "Sysmon Event ID 25 (ProcessTampering)".into(),
                    format!("Tampering type: {tampering_type}"),
                    format!("Target PID: {target_pid}"),
                    format!("Image: {}", image.as_deref().unwrap_or("unknown")),
                ],
            };
            return Some(ThreatEvent::with_rule(
                hostname,
                source,
                EventCategory::Evasion,
                Severity::Critical,
                EventData::EvasionDetected {
                    technique,
                    pid: Some(target_pid),
                    process_name: image,
                    details: format!("Sysmon ProcessTampering: {tampering_type}"),
                },
                rule,
            ));
        }

        _ => return None,
    };

    Some(ThreatEvent::new(hostname, source, cat, sev, data))
}

// ---------------------------------------------------------------------------
// Tests (run on any platform)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_process_create() -> &'static str {
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
    <EventID>1</EventID>
    <Level>4</Level>
  </System>
  <EventData>
    <Data Name="ProcessId">4728</Data>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c "echo hello &amp; world"</Data>
    <Data Name="ParentProcessId">1024</Data>
    <Data Name="User">DESKTOP-ABC\Admin</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="Hashes">SHA256=ABCDEF1234567890</Data>
  </EventData>
</Event>"#
    }

    #[test]
    fn parse_event_id() {
        let parsed = parse_sysmon_xml(sample_process_create()).unwrap();
        assert_eq!(parsed.event_id, 1);
    }

    #[test]
    fn parse_fields() {
        let parsed = parse_sysmon_xml(sample_process_create()).unwrap();
        assert_eq!(parsed.get_u32("ProcessId"), 4728);
        assert_eq!(parsed.get_u32("ParentProcessId"), 1024);
        assert_eq!(
            parsed.get_string("Image"),
            r"C:\Windows\System32\cmd.exe"
        );
        assert_eq!(parsed.get_string("User"), r"DESKTOP-ABC\Admin");
    }

    #[test]
    fn xml_entity_decoding() {
        let parsed = parse_sysmon_xml(sample_process_create()).unwrap();
        assert_eq!(
            parsed.get_string("CommandLine"),
            r#"cmd.exe /c "echo hello & world""#
        );
    }

    #[test]
    fn all_xml_entities() {
        let xml = r#"<Event>
  <System><EventID>1</EventID></System>
  <EventData>
    <Data Name="ProcessId">1</Data>
    <Data Name="Image">test.exe</Data>
    <Data Name="CommandLine">a &lt;b&gt; &amp; &quot;c&quot; &apos;d&apos;</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        assert_eq!(
            parsed.get_string("CommandLine"),
            "a <b> & \"c\" 'd'"
        );
    }

    #[test]
    fn self_closing_data_tag() {
        let xml = r#"<Event>
  <System><EventID>1</EventID></System>
  <EventData>
    <Data Name="ProcessId">100</Data>
    <Data Name="Image">test.exe</Data>
    <Data Name="CommandLine"/>
    <Data Name="User">admin</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        assert!(parsed.get("CommandLine").is_none());
        assert_eq!(parsed.get_string("User"), "admin");
    }

    #[test]
    fn map_process_create() {
        let parsed = parse_sysmon_xml(sample_process_create()).unwrap();
        let event = map_to_threat_event(&parsed, "test-host").unwrap();

        assert_eq!(event.hostname, "test-host");
        assert!(matches!(
            event.source,
            EventSource::Sysmon { event_id: 1 }
        ));
        match &event.data {
            EventData::ProcessCreate {
                pid,
                ppid,
                image_path,
                command_line,
                ..
            } => {
                assert_eq!(*pid, 4728);
                assert_eq!(*ppid, 1024);
                assert_eq!(image_path, r"C:\Windows\System32\cmd.exe");
                assert!(command_line.contains("hello & world"));
            }
            _ => panic!("expected ProcessCreate"),
        }
    }

    #[test]
    fn map_network_connect_outbound() {
        let xml = r#"<Event>
  <System><EventID>3</EventID></System>
  <EventData>
    <Data Name="ProcessId">1234</Data>
    <Data Name="Image">C:\malware.exe</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="Initiated">true</Data>
    <Data Name="SourceIp">192.168.1.100</Data>
    <Data Name="SourcePort">54321</Data>
    <Data Name="DestinationIp">10.0.0.1</Data>
    <Data Name="DestinationPort">443</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        match &event.data {
            EventData::NetworkConnect {
                pid,
                dst_port,
                direction,
                ..
            } => {
                assert_eq!(*pid, 1234);
                assert_eq!(*dst_port, 443);
                assert!(matches!(direction, NetworkDirection::Outbound));
            }
            _ => panic!("expected NetworkConnect"),
        }
    }

    #[test]
    fn map_network_connect_inbound() {
        let xml = r#"<Event>
  <System><EventID>3</EventID></System>
  <EventData>
    <Data Name="ProcessId">5678</Data>
    <Data Name="Image">C:\svchost.exe</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="Initiated">false</Data>
    <Data Name="SourceIp">10.0.0.5</Data>
    <Data Name="SourcePort">80</Data>
    <Data Name="DestinationIp">10.0.0.1</Data>
    <Data Name="DestinationPort">49152</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        match &event.data {
            EventData::NetworkConnect { direction, .. } => {
                assert!(matches!(direction, NetworkDirection::Inbound));
            }
            _ => panic!("expected NetworkConnect"),
        }
    }

    #[test]
    fn map_file_delete() {
        let xml = r#"<Event>
  <System><EventID>23</EventID></System>
  <EventData>
    <Data Name="ProcessId">999</Data>
    <Data Name="TargetFilename">C:\Users\victim\secrets.txt</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        match &event.data {
            EventData::FileDelete { pid, path } => {
                assert_eq!(*pid, 999);
                assert_eq!(path, r"C:\Users\victim\secrets.txt");
            }
            _ => panic!("expected FileDelete"),
        }
    }

    #[test]
    fn map_ads_stream_create() {
        let xml = r#"<Event>
  <System><EventID>15</EventID></System>
  <EventData>
    <Data Name="ProcessId">100</Data>
    <Data Name="TargetFilename">C:\temp\file.txt:Zone.Identifier</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        match &event.data {
            EventData::FileCreate {
                operation, path, ..
            } => {
                assert!(matches!(operation, FileOperation::StreamCreate));
                assert!(path.contains("Zone.Identifier"));
            }
            _ => panic!("expected FileCreate"),
        }
    }

    #[test]
    fn map_process_access_hex() {
        let xml = r#"<Event>
  <System><EventID>10</EventID></System>
  <EventData>
    <Data Name="SourceProcessId">100</Data>
    <Data Name="TargetProcessId">200</Data>
    <Data Name="GrantedAccess">0x1F0FFF</Data>
    <Data Name="SourceImage">C:\mimikatz.exe</Data>
    <Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        match &event.data {
            EventData::ProcessAccess {
                granted_access, ..
            } => {
                assert_eq!(*granted_access, 0x1F0FFF);
            }
            _ => panic!("expected ProcessAccess"),
        }
    }

    #[test]
    fn map_driver_loaded() {
        let xml = r#"<Event>
  <System><EventID>6</EventID></System>
  <EventData>
    <Data Name="ImageLoaded">C:\Windows\System32\drivers\evil.sys</Data>
    <Data Name="Hashes">SHA256=DEADBEEF</Data>
    <Data Name="Signed">false</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        match &event.data {
            EventData::ImageLoad {
                image_name, signed, ..
            } => {
                assert_eq!(image_name, "evil.sys");
                assert!(!signed);
            }
            _ => panic!("expected ImageLoad"),
        }
    }

    #[test]
    fn process_tampering_hollowing() {
        let xml = r#"<Event>
  <System><EventID>25</EventID></System>
  <EventData>
    <Data Name="ProcessId">9999</Data>
    <Data Name="Image">C:\malware\hollowed.exe</Data>
    <Data Name="Type">Image is replaced</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        match &event.data {
            EventData::EvasionDetected { technique, .. } => {
                assert!(matches!(technique, EvasionTechnique::ProcessHollowing));
            }
            _ => panic!("expected EvasionDetected"),
        }
        let rule = event.rule.as_ref().expect("rule metadata should be present");
        assert_eq!(rule.id, "TF-SYS-001a");
        assert_eq!(rule.mitre.technique_id, "T1055.012");
        assert!(rule.name.contains("Hollowing"));
    }

    #[test]
    fn process_tampering_herpaderping() {
        let xml = r#"<Event>
  <System><EventID>25</EventID></System>
  <EventData>
    <Data Name="ProcessId">8888</Data>
    <Data Name="Image">C:\malware\herp.exe</Data>
    <Data Name="Type">Image is locked for access</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        match &event.data {
            EventData::EvasionDetected { technique, .. } => {
                assert!(matches!(technique, EvasionTechnique::ProcessHerpaderping));
            }
            _ => panic!("expected EvasionDetected"),
        }
        let rule = event.rule.as_ref().expect("rule metadata should be present");
        assert_eq!(rule.id, "TF-SYS-001b");
        assert_eq!(rule.mitre.technique_id, "T1055");
        assert!(rule.name.contains("Herpaderping"));
    }

    #[test]
    fn process_tampering_unknown_type() {
        let xml = r#"<Event>
  <System><EventID>25</EventID></System>
  <EventData>
    <Data Name="ProcessId">7777</Data>
    <Data Name="Image">C:\unknown.exe</Data>
    <Data Name="Type">Something new</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        match &event.data {
            EventData::EvasionDetected { technique, .. } => {
                assert!(matches!(technique, EvasionTechnique::Unknown));
            }
            _ => panic!("expected EvasionDetected"),
        }
        let rule = event.rule.as_ref().expect("rule metadata should be present");
        assert_eq!(rule.id, "TF-SYS-001");
        assert_eq!(rule.mitre.technique_id, "T1055");
        assert!(rule.evidence.iter().any(|e| e.contains("Something new")));
    }

    #[test]
    fn telemetry_events_have_no_rule() {
        let xml = r#"<Event>
  <System><EventID>1</EventID></System>
  <EventData>
    <Data Name="ProcessId">1234</Data>
    <Data Name="ParentProcessId">5678</Data>
    <Data Name="Image">C:\test.exe</Data>
    <Data Name="CommandLine">test.exe</Data>
    <Data Name="User">SYSTEM</Data>
    <Data Name="IntegrityLevel">High</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        assert!(event.rule.is_none(), "telemetry events should not have rule metadata");
    }

    #[test]
    fn unknown_event_returns_none() {
        let xml = r#"<Event>
  <System><EventID>999</EventID></System>
  <EventData></EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        assert!(map_to_threat_event(&parsed, "host").is_none());
    }

    // --- Rule metadata consistency tests -------------------------------------

    #[test]
    fn sysmon_detection_severity_is_critical() {
        // All Sysmon detection rules (Event 25) should be Critical severity
        // because Sysmon directly observes the tampering at kernel level.
        let xml = r#"<Event>
  <System><EventID>25</EventID></System>
  <EventData>
    <Data Name="ProcessId">100</Data>
    <Data Name="Image">C:\test.exe</Data>
    <Data Name="Type">Image is replaced</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        assert_eq!(event.severity, Severity::Critical);
    }

    #[test]
    fn sysmon_detection_confidence_is_high() {
        // Sysmon Event 25 is a direct kernel observation — High confidence.
        let xml = r#"<Event>
  <System><EventID>25</EventID></System>
  <EventData>
    <Data Name="ProcessId">100</Data>
    <Data Name="Image">C:\test.exe</Data>
    <Data Name="Type">Image is replaced</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        let rule = event.rule.unwrap();
        assert_eq!(rule.confidence, Confidence::High);
    }

    #[test]
    fn sysmon_all_rules_have_defense_evasion_tactic() {
        for tampering_type in &["Image is replaced", "Image is locked for access", "Unknown type"] {
            let xml = format!(
                r#"<Event>
  <System><EventID>25</EventID></System>
  <EventData>
    <Data Name="ProcessId">1</Data>
    <Data Name="Image">C:\test.exe</Data>
    <Data Name="Type">{}</Data>
  </EventData>
</Event>"#,
                tampering_type
            );
            let parsed = parse_sysmon_xml(&xml).unwrap();
            let event = map_to_threat_event(&parsed, "host").unwrap();
            let rule = event.rule.unwrap();
            assert_eq!(
                rule.mitre.tactic, "Defense Evasion",
                "rule {} should have Defense Evasion tactic",
                rule.id
            );
        }
    }

    #[test]
    fn sysmon_evidence_includes_event_source() {
        // All Sysmon detection rules should include the Sysmon event ID
        // in evidence for traceability.
        let xml = r#"<Event>
  <System><EventID>25</EventID></System>
  <EventData>
    <Data Name="ProcessId">1</Data>
    <Data Name="Image">C:\test.exe</Data>
    <Data Name="Type">Image is replaced</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        let rule = event.rule.unwrap();
        assert!(
            rule.evidence.iter().any(|e| e.contains("Event ID 25")),
            "evidence should include Sysmon event ID"
        );
    }

    #[test]
    fn sysmon_suspicious_telemetry_elevated_severity() {
        // CreateRemoteThread (Event 8) is telemetry with elevated severity
        // — it's a suspicious signal but not a detection.
        let xml = r#"<Event>
  <System><EventID>8</EventID></System>
  <EventData>
    <Data Name="SourceProcessId">100</Data>
    <Data Name="TargetProcessId">200</Data>
    <Data Name="StartAddress">0x7FFB00001000</Data>
    <Data Name="SourceImage">C:\inject.exe</Data>
    <Data Name="TargetImage">C:\victim.exe</Data>
  </EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        let event = map_to_threat_event(&parsed, "host").unwrap();
        assert!(event.rule.is_none(), "CreateRemoteThread is telemetry, not detection");
        assert_eq!(event.severity, Severity::High, "suspicious telemetry has elevated severity");
    }
}
