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

    pub fn optional_bool(&self, key: &str) -> Option<bool> {
        match self.get(key)?.to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// XML parsing
// ---------------------------------------------------------------------------

/// Parse one rendered Event using XML syntax, not substring matching. No DTD,
/// external entities, duplicate fields, or unbounded nesting are accepted.
pub fn parse_sysmon_xml(xml: &str) -> Option<SysmonParsedEvent> {
    use quick_xml::events::Event;
    if xml.len() > 1024 * 1024 {
        return None;
    }
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().expand_empty_elements = true;
    let mut stack: Vec<String> = Vec::new();
    let mut active: Option<String> = None;
    let mut value = String::new();
    let mut fields = HashMap::new();
    let mut seen_fields = std::collections::HashSet::new();
    let mut event_id = None;
    let mut roots = 0;
    loop {
        match reader.read_event().ok()? {
            Event::Start(tag) => {
                let name = std::str::from_utf8(tag.local_name().as_ref())
                    .ok()?
                    .to_string();
                if stack.is_empty() {
                    if name != "Event" {
                        return None;
                    }
                    roots += 1;
                    if roots > 1 {
                        return None;
                    }
                }
                if active.is_some() || stack.len() >= 16 {
                    return None;
                }
                let attrs: HashMap<String, String> = tag
                    .attributes()
                    .map(|a| {
                        let a = a.ok()?;
                        Some((
                            std::str::from_utf8(a.key.as_ref()).ok()?.to_string(),
                            a.unescape_value().ok()?.into_owned(),
                        ))
                    })
                    .collect::<Option<_>>()?;
                let parent = stack.last().map(String::as_str);
                if parent == Some("System") {
                    match name.as_str() {
                        "TimeCreated" => {
                            if let Some(time) = attrs.get("SystemTime") {
                                fields.insert("System.TimeCreated".into(), time.clone());
                            }
                        }
                        "Provider" => {
                            for (k, v) in &attrs {
                                fields.insert(format!("System.Provider.{k}"), v.clone());
                            }
                        }
                        "EventID" | "EventRecordID" | "Version" | "Computer" => {
                            active = Some(format!("System.{name}"));
                            value.clear();
                        }
                        _ => {}
                    }
                } else if parent == Some("EventData") && name == "Data" {
                    let key = attrs.get("Name")?.clone();
                    if key.starts_with("System.") {
                        return None;
                    }
                    active = Some(key);
                    value.clear();
                }
                stack.push(name);
            }
            Event::Text(text) => {
                if active.is_some() {
                    value.push_str(&text.xml_content().ok()?);
                } else if !text.iter().all(|b| b.is_ascii_whitespace()) && stack.is_empty() {
                    return None;
                }
            }
            Event::CData(text) => {
                if active.is_some() {
                    value.push_str(&text.decode().ok()?);
                }
            }
            Event::GeneralRef(reference) => {
                let ch = if let Some(ch) = reference.resolve_char_ref().ok()? {
                    ch
                } else {
                    match reference.decode().ok()?.as_ref() {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => return None,
                    }
                };
                if active.is_some() {
                    value.push(ch);
                }
            }
            Event::End(_) => {
                if let Some(key) = active.take() {
                    if !seen_fields.insert(key.clone()) {
                        return None;
                    }
                    if key == "System.EventID" {
                        if event_id.replace(value.trim().parse().ok()?).is_some() {
                            return None;
                        }
                    } else if !value.is_empty() && fields.insert(key, value.clone()).is_some() {
                        return None;
                    }
                }
                stack.pop()?;
                if fields.len() > 256 {
                    return None;
                }
            }
            Event::DocType(_) => return None,
            Event::Eof => break,
            _ => {}
        }
    }
    if !stack.is_empty() || roots != 1 {
        return None;
    }
    // The live subscription is already scoped to Sysmon; reject explicitly
    // conflicting provider identities in imported fixtures/exported XML too.
    if fields
        .get("System.Provider.Name")
        .is_some_and(|s| s != "Microsoft-Windows-Sysmon")
    {
        return None;
    }
    if fields.get("System.Provider.Guid").is_some_and(|s| {
        uuid::Uuid::parse_str(s).ok()
            != uuid::Uuid::parse_str("5770385f-c22a-43e0-bf4c-06f5698ffbd9").ok()
    }) {
        return None;
    }
    Some(SysmonParsedEvent {
        event_id: event_id?,
        fields,
    })
}

// ---------------------------------------------------------------------------
// Event mapping: SysmonParsedEvent → ThreatEvent
// ---------------------------------------------------------------------------

/// Convert a parsed Sysmon event into a unified `ThreatEvent`.
pub fn map_to_threat_event(parsed: &SysmonParsedEvent, agent: &AgentInfo) -> Option<ThreatEvent> {
    let mut event = map_payload(parsed, agent)?;
    let mut origin = EventProvenance {
        provider_guid: "5770385f-c22a-43e0-bf4c-06f5698ffbd9".into(),
        event_id: parsed.event_id,
        version: parsed
            .get("System.Version")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        record_id: parsed
            .get("System.EventRecordID")
            .and_then(|v| v.parse().ok()),
        fields: parsed
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        ..Default::default()
    };
    // UtcTime is the operation time. SystemTime is only a fallback.
    let original = parsed
        .get("UtcTime")
        .and_then(parse_utc)
        .or_else(|| parsed.get("System.TimeCreated").and_then(parse_utc));
    if let Some(time) = original {
        event.timestamp = time;
        origin.original_time = true;
    } else {
        origin.issues.push("missing_or_invalid_source_time".into());
    }
    if parsed
        .get("UtcTime")
        .is_some_and(|s| parse_utc(s).is_none())
    {
        origin.issues.push("invalid_utc_time".into());
    }
    let guid = |names: &[&str]| {
        names
            .iter()
            .find_map(|name| parsed.get(name))
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .filter(|g| !g.is_nil())
    };
    origin.process_guid = guid(&[
        "ProcessGuid",
        "ProcessGUID",
        "SourceProcessGUID",
        "SourceProcessGuid",
    ]);
    origin.parent_process_guid = guid(&["ParentProcessGuid", "ParentProcessGUID"]);
    origin.target_process_guid = guid(&["TargetProcessGUID", "TargetProcessGuid"]);
    if matches!(
        parsed.event_id,
        1 | 3 | 5 | 7 | 8 | 10 | 11 | 12 | 13 | 14 | 15 | 17 | 18 | 22 | 23 | 25 | 26
    ) && origin.process_guid.is_none()
    {
        origin.issues.push("missing_or_invalid_process_guid".into());
    }
    if matches!(parsed.event_id, 8 | 10) && origin.target_process_guid.is_none() {
        origin.issues.push("missing_or_invalid_target_guid".into());
    }
    let pid_fields: &[&str] = match parsed.event_id {
        8 | 10 => &["SourceProcessId", "TargetProcessId"],
        1 | 3 | 5 | 7 | 11 | 12 | 13 | 14 | 15 | 17 | 18 | 22 | 23 | 25 | 26 => &["ProcessId"],
        _ => &[],
    };
    for field in pid_fields {
        if parsed
            .get(field)
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|pid| *pid > 0)
            .is_none()
        {
            origin.issues.push(format!("invalid_field:{field}"));
        }
    }
    if parsed.event_id == 3 {
        for field in ["SourceIp", "DestinationIp"] {
            if parsed
                .get(field)
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .is_none()
            {
                origin.issues.push(format!("invalid_field:{field}"));
            }
        }
        for field in ["SourcePort", "DestinationPort"] {
            if parsed
                .get(field)
                .and_then(|s| s.parse::<u16>().ok())
                .is_none()
            {
                origin.issues.push(format!("invalid_field:{field}"));
            }
        }
        if parsed.optional_bool("Initiated").is_none() {
            origin.issues.push("invalid_field:Initiated".into());
        }
    }
    if parsed.event_id == 255 {
        origin.issues.push("upstream_sysmon_error".into());
        event.severity = Severity::Medium;
    }
    event.provenance = Some(origin);
    Some(event)
}

fn parse_utc(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|t| t.to_utc())
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|t| t.and_utc())
        })
}

fn map_payload(parsed: &SysmonParsedEvent, agent: &AgentInfo) -> Option<ThreatEvent> {
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
                create_time: None,
            },
        ),

        // Event 3: Network Connection
        3 => {
            let direction = match parsed.optional_bool("Initiated") {
                Some(true) => NetworkDirection::Outbound,
                Some(false) => NetworkDirection::Inbound,
                None => NetworkDirection::Unknown,
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
                create_time: None,
            },
        ),

        // Event 6: Driver Loaded
        6 => {
            let image = parsed.get_string("ImageLoaded");
            let name = image.rsplit('\\').next().unwrap_or(&image).to_string();
            (
                EventCategory::ImageLoad,
                Severity::Info,
                EventData::ImageLoad {
                    pid: 0,
                    image_path: image,
                    image_name: name,
                    signed: parsed.optional_bool("Signed"),
                    signature: parsed.get("Signature").map(String::from),
                    hashes: parsed.get("Hashes").map(String::from),
                },
            )
        }

        // Event 7: Image Loaded (DLL)
        7 => {
            let image = parsed.get_string("ImageLoaded");
            let name = image.rsplit('\\').next().unwrap_or(&image).to_string();
            (
                EventCategory::ImageLoad,
                Severity::Info,
                EventData::ImageLoad {
                    pid: parsed.get_u32("ProcessId"),
                    image_path: image,
                    image_name: name,
                    signed: parsed.optional_bool("Signed"),
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
                12 => match parsed.get("EventType") {
                    Some("DeleteKey") => RegistryOperation::DeleteKey,
                    Some("DeleteValue") => RegistryOperation::DeleteValue,
                    Some("CreateKey") => RegistryOperation::CreateKey,
                    _ => return Some(native_event(parsed, agent, "unknown_registry_operation")),
                },
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
                agent,
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

        _ => return Some(native_event(parsed, agent, "unmapped_sysmon_event")),
    };

    Some(ThreatEvent::new(agent, source, cat, sev, data))
}

fn native_event(parsed: &SysmonParsedEvent, agent: &AgentInfo, reason: &str) -> ThreatEvent {
    ThreatEvent::new(
        agent,
        EventSource::Sysmon {
            event_id: parsed.event_id,
        },
        EventCategory::Telemetry,
        Severity::Info,
        EventData::NativeTelemetry {
            pid: parsed.get("ProcessId").and_then(|s| s.parse().ok()),
            reason: reason.into(),
            payload_hex: None,
        },
    )
}

// ---------------------------------------------------------------------------
// Tests (run on any platform)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_agent() -> AgentInfo {
        AgentInfo {
            hostname: "test-host".into(),
            agent_id: Uuid::nil(),
        }
    }

    #[test]
    fn preserves_native_time_record_id_and_guids() {
        let xml = r#"<Event><System><EventID>8</EventID><EventRecordID>4321</EventRecordID><Version>2</Version>
            <TimeCreated SystemTime='2026-09-12T12:30:00Z'/></System><EventData>
            <Data Name='UtcTime'>2026-09-12 12:29:59.1234567</Data>
            <Data Name='SourceProcessGUID'>{11111111-1111-1111-1111-111111111111}</Data>
            <Data Name='TargetProcessGUID'>{22222222-2222-2222-2222-222222222222}</Data>
            <Data Name='SourceProcessId'>12</Data><Data Name='TargetProcessId'>34</Data>
            </EventData></Event>"#;
        let e = map_to_threat_event(&parse_sysmon_xml(xml).unwrap(), &test_agent()).unwrap();
        assert_eq!(
            e.timestamp.to_rfc3339(),
            "2026-09-12T12:29:59.123456700+00:00"
        );
        let p = e.provenance.unwrap();
        assert_eq!(p.record_id, Some(4321));
        assert_eq!(p.version, 2);
        assert!(p.original_time);
        assert!(p.issues.is_empty());
        assert!(p.target_process_guid.is_some());
    }
    #[test]
    fn xml_is_decoded_exactly_once_including_numeric_entities() {
        let xml = r#"<Event><System><EventID>1</EventID></System><EventData>
            <Data Name='CommandLine'>&amp;lt;&#x41;&#65;<![CDATA[&literal;]]></Data></EventData></Event>"#;
        assert_eq!(
            parse_sysmon_xml(xml).unwrap().get("CommandLine"),
            Some("&lt;AA&literal;")
        );
    }
    #[test]
    fn rejects_ambiguous_or_malformed_xml_without_entity_expansion() {
        for xml in ["<Event><System><EventID>1</EventID></System>",
            "<!DOCTYPE Event [<!ENTITY e SYSTEM 'file:///fixture'>]><Event><System><EventID>1</EventID></System></Event>",
            "<Event><System><EventID>1</EventID><EventID>3</EventID></System></Event>",
            "<Event><System><EventID>1</EventID></System><EventData><Data Name='ProcessId'>1</Data><Data Name='ProcessId'>2</Data></EventData></Event>",
            "<Event><System><Provider Name='not-Sysmon'/><EventID>1</EventID></System></Event>"] {
            assert!(parse_sysmon_xml(xml).is_none(),"{xml}");
        }
    }
    #[test]
    fn missing_signature_remains_unknown_and_delete_is_not_create() {
        let xml="<Event><System><EventID>7</EventID></System><EventData><Data Name='ProcessId'>10</Data></EventData></Event>";
        let e = map_to_threat_event(&parse_sysmon_xml(xml).unwrap(), &test_agent()).unwrap();
        assert!(matches!(e.data, EventData::ImageLoad { signed: None, .. }));
        let xml="<Event><System><EventID>12</EventID></System><EventData><Data Name='EventType'>DeleteKey</Data></EventData></Event>";
        let e = map_to_threat_event(&parse_sysmon_xml(xml).unwrap(), &test_agent()).unwrap();
        assert!(matches!(
            e.data,
            EventData::RegistryEvent {
                operation: RegistryOperation::DeleteKey,
                ..
            }
        ));
    }

    #[test]
    fn upstream_errors_are_quality_failures_and_duplicate_empty_fields_are_rejected() {
        let xml="<Event><System><EventID>255</EventID></System><EventData><Data Name='Description'>fixture error</Data></EventData></Event>";
        let event = map_to_threat_event(&parse_sysmon_xml(xml).unwrap(), &test_agent()).unwrap();
        assert!(event
            .provenance
            .unwrap()
            .issues
            .contains(&"upstream_sysmon_error".to_string()));
        let xml="<Event><System><EventID>1</EventID></System><EventData><Data Name='ProcessId'/><Data Name='ProcessId'>10</Data></EventData></Event>";
        assert!(parse_sysmon_xml(xml).is_none());
    }

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
        assert_eq!(parsed.get_string("Image"), r"C:\Windows\System32\cmd.exe");
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
        assert_eq!(parsed.get_string("CommandLine"), "a <b> & \"c\" 'd'");
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();

        assert_eq!(event.hostname, "test-host");
        assert!(matches!(event.source, EventSource::Sysmon { event_id: 1 }));
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
        match &event.data {
            EventData::ProcessAccess { granted_access, .. } => {
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
        match &event.data {
            EventData::ImageLoad {
                image_name, signed, ..
            } => {
                assert_eq!(image_name, "evil.sys");
                assert_eq!(*signed, Some(false));
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
        match &event.data {
            EventData::EvasionDetected { technique, .. } => {
                assert!(matches!(technique, EvasionTechnique::ProcessHollowing));
            }
            _ => panic!("expected EvasionDetected"),
        }
        let rule = event
            .rule
            .as_ref()
            .expect("rule metadata should be present");
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
        match &event.data {
            EventData::EvasionDetected { technique, .. } => {
                assert!(matches!(technique, EvasionTechnique::ProcessHerpaderping));
            }
            _ => panic!("expected EvasionDetected"),
        }
        let rule = event
            .rule
            .as_ref()
            .expect("rule metadata should be present");
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
        match &event.data {
            EventData::EvasionDetected { technique, .. } => {
                assert!(matches!(technique, EvasionTechnique::Unknown));
            }
            _ => panic!("expected EvasionDetected"),
        }
        let rule = event
            .rule
            .as_ref()
            .expect("rule metadata should be present");
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
        assert!(
            event.rule.is_none(),
            "telemetry events should not have rule metadata"
        );
    }

    #[test]
    fn unknown_event_preserves_native_evidence() {
        let xml = r#"<Event>
  <System><EventID>999</EventID></System>
  <EventData></EventData>
</Event>"#;
        let parsed = parse_sysmon_xml(xml).unwrap();
        assert!(matches!(
            map_to_threat_event(&parsed, &test_agent()).unwrap().data,
            EventData::NativeTelemetry { .. }
        ));
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
        let rule = event.rule.unwrap();
        assert_eq!(rule.confidence, Confidence::High);
    }

    #[test]
    fn sysmon_all_rules_have_defense_evasion_tactic() {
        for tampering_type in &[
            "Image is replaced",
            "Image is locked for access",
            "Unknown type",
        ] {
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
            let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
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
        let event = map_to_threat_event(&parsed, &test_agent()).unwrap();
        assert!(
            event.rule.is_none(),
            "CreateRemoteThread is telemetry, not detection"
        );
        assert_eq!(
            event.severity,
            Severity::High,
            "suspicious telemetry has elevated severity"
        );
    }
}
