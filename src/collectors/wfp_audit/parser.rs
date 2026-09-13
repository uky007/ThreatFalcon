//! Strict, bounded parser for local EvtRender XML, not localized message text.
//! No proprietary Falcon structures, guessed offsets, payload capture or PID joins.
use crate::{events::*, wfp_events::*};
use anyhow::{ensure, Context, Result};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_XML_BYTES: usize = 64 * 1024;
const MAX_VALUE_BYTES: usize = 4096;
pub const PROVIDER_GUID: &str = "54849625-5478-4994-a5ba-3e3b0328c30d";
const PROVIDER_NAME: &str = "Microsoft-Windows-Security-Auditing";
const EVENT_NAMESPACE: &str = "http://schemas.microsoft.com/win/2004/08/events/event";

fn retained(key: &str) -> bool {
    matches!(
        key,
        "ProcessID"
            | "Application"
            | "Direction"
            | "SourceAddress"
            | "SourcePort"
            | "DestAddress"
            | "DestPort"
            | "Protocol"
            | "FilterRTID"
            | "LayerName"
            | "LayerRTID"
    )
}

pub fn parse(xml: &str, agent: &AgentInfo) -> Result<ThreatEvent> {
    use quick_xml::events::Event;
    ensure!(xml.len() <= MAX_XML_BYTES, "wfp_xml_too_large");
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().expand_empty_elements = true;
    let mut stack: Vec<String> = vec![];
    let mut seen = BTreeSet::new();
    let mut fields = BTreeMap::new();
    let mut omitted = vec![];
    let mut active: Option<(String, bool)> = None;
    let mut value = String::new();
    let mut roots = 0;
    let mut field_count = 0;
    loop {
        match reader.read_event().context("wfp_invalid_xml")? {
            Event::Start(tag) => {
                // EvtRender uses this unprefixed namespace form. Reject foreign
                // namespace rebinding/wrappers instead of local-name guessing.
                let name = std::str::from_utf8(tag.name().as_ref())?.to_owned();
                ensure!(
                    !name.contains(':') && stack.len() < 4 && active.is_none(),
                    "wfp_invalid_xml_structure"
                );
                let mut attrs = BTreeMap::new();
                for attr in tag.attributes() {
                    let attr = attr.context("wfp_invalid_attribute")?;
                    let key = std::str::from_utf8(attr.key.as_ref())?.to_owned();
                    let val = attr.unescape_value()?.into_owned();
                    ensure!(
                        key.len() <= 64
                            && val.len() <= MAX_VALUE_BYTES
                            && valid_xml_text(&val)
                            && attrs.len() < 16
                            && !attrs.contains_key(&key),
                        "wfp_invalid_attribute"
                    );
                    attrs.insert(key, val);
                }
                let parent = stack.last().map(String::as_str);
                if stack.is_empty() {
                    roots += 1;
                    ensure!(
                        roots == 1
                            && name == "Event"
                            && attrs.get("xmlns").map(String::as_str) == Some(EVENT_NAMESPACE),
                        "wfp_invalid_root"
                    );
                    ensure!(attrs.len() == 1, "wfp_invalid_root_attributes");
                } else {
                    ensure!(
                        !attrs.keys().any(|k| k == "xmlns" || k.contains(':')),
                        "wfp_namespace_override"
                    );
                    match (stack.len(), parent) {
                        (1, Some("Event")) => {
                            ensure!(
                                matches!(name.as_str(), "System" | "EventData")
                                    && attrs.is_empty()
                                    && seen.insert(name.clone()),
                                "wfp_duplicate_or_invalid_section"
                            );
                        }
                        (2, Some("System")) => {
                            ensure!(
                                seen.insert(format!("System.{name}")),
                                "wfp_duplicate_system_field"
                            );
                            match name.as_str() {
                                "Provider" => {
                                    for key in ["Name", "Guid"] {
                                        fields.insert(
                                            format!("System.Provider.{key}"),
                                            attrs.get(key).context("wfp_missing_provider")?.clone(),
                                        );
                                    }
                                }
                                "TimeCreated" => {
                                    fields.insert(
                                        "System.TimeCreated".into(),
                                        attrs
                                            .get("SystemTime")
                                            .context("wfp_missing_time")?
                                            .clone(),
                                    );
                                }
                                "Execution" => {
                                    for key in ["ProcessID", "ThreadID"] {
                                        if let Some(v) = attrs.get(key) {
                                            fields.insert(
                                                format!("System.Execution.{key}"),
                                                v.clone(),
                                            );
                                        }
                                    }
                                }
                                "EventID" | "Version" | "Opcode" | "EventRecordID" | "Computer"
                                | "Channel" => {
                                    active = Some((format!("System.{name}"), true));
                                    value.clear();
                                }
                                "Level" | "Task" | "Keywords" => {
                                    active = Some((format!("System.{name}"), false));
                                    value.clear();
                                }
                                "Correlation" | "Security" => {}
                                _ => anyhow::bail!("wfp_unknown_system_structure"),
                            }
                        }
                        (2, Some("EventData")) if name == "Data" => {
                            field_count += 1;
                            ensure!(
                                field_count <= 64 && attrs.len() == 1,
                                "wfp_invalid_data_fields"
                            );
                            let key = attrs.get("Name").context("wfp_missing_field_name")?;
                            ensure!(
                                !key.is_empty()
                                    && key.len() <= 64
                                    && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                                    && seen.insert(format!("Data.{key}")),
                                "wfp_duplicate_or_invalid_field"
                            );
                            let keep = retained(key);
                            if !keep {
                                omitted.push(key.clone());
                            }
                            active = Some((key.clone(), keep));
                            value.clear();
                        }
                        _ => anyhow::bail!("wfp_invalid_xml_structure"),
                    }
                }
                stack.push(name);
            }
            Event::Text(text) => {
                let text = text.xml_content()?;
                if active.is_some() {
                    value.push_str(&text);
                } else {
                    ensure!(text.trim().is_empty(), "wfp_unexpected_text");
                }
            }
            Event::CData(text) => {
                ensure!(active.is_some(), "wfp_unexpected_cdata");
                value.push_str(&text.decode()?);
            }
            Event::GeneralRef(reference) => {
                ensure!(active.is_some(), "wfp_unexpected_reference");
                let ch = if let Some(ch) = reference.resolve_char_ref()? {
                    ch
                } else {
                    match reference.decode()?.as_ref() {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => anyhow::bail!("wfp_unknown_entity"),
                    }
                };
                value.push(ch);
            }
            Event::End(_) => {
                if let Some((key, keep)) = active.take() {
                    if keep {
                        ensure!(
                            fields.insert(key, value.clone()).is_none(),
                            "wfp_duplicate_field"
                        );
                    }
                    value.clear();
                }
                stack.pop().context("wfp_unbalanced_xml")?;
            }
            Event::DocType(_) | Event::PI(_) => anyhow::bail!("wfp_disallowed_xml"),
            Event::Decl(_) if roots > 0 => anyhow::bail!("wfp_misplaced_declaration"),
            Event::Eof => break,
            _ => {}
        }
        ensure!(
            value.len() <= MAX_VALUE_BYTES && valid_xml_text(&value),
            "wfp_invalid_or_oversized_value"
        );
    }
    ensure!(
        roots == 1 && stack.is_empty() && seen.contains("System") && seen.contains("EventData"),
        "wfp_incomplete_xml"
    );
    let get = |key: &str| fields.get(key).map(String::as_str);
    ensure!(
        get("System.Provider.Name") == Some(PROVIDER_NAME)
            && get("System.Provider.Guid").and_then(|v| uuid::Uuid::parse_str(v).ok())
                == uuid::Uuid::parse_str(PROVIDER_GUID).ok()
            && get("System.Channel") == Some("Security"),
        "wfp_wrong_provider_or_channel"
    );
    ensure!(
        get("System.Computer").is_some_and(|s| !s.trim().is_empty()),
        "wfp_missing_computer"
    );
    let event_id: u16 = decimal(get("System.EventID"))?;
    let decision = match event_id {
        5156 => WfpDecision::Permitted,
        5157 => WfpDecision::Blocked,
        _ => anyhow::bail!("wfp_unsupported_event"),
    };
    let version: u8 = decimal(get("System.Version"))?;
    let opcode: u8 = decimal(get("System.Opcode"))?;
    let record_id: u64 = decimal(get("System.EventRecordID"))?;
    ensure!(record_id > 0, "wfp_invalid_record_id");
    let time = chrono::DateTime::parse_from_rfc3339(
        get("System.TimeCreated").context("wfp_missing_time")?,
    )?
    .with_timezone(&chrono::Utc);
    let mut issues = vec![];
    let mut record = WfpConnectionAudit {
        decision,
        pid: None,
        application: None,
        source_address: None,
        source_port: None,
        destination_address: None,
        destination_port: None,
        protocol: None,
        direction_token: None,
        filter_runtime_id: None,
        layer_runtime_id: None,
        omitted_fields: omitted,
    };
    // Microsoft examples show v1 while their text lists v0. Both use the
    // documented core fields. Future versions retain evidence but aren't guessed.
    if version <= 1 {
        record.pid = number(get("ProcessID"), "ProcessID", &mut issues).and_then(|v| {
            match u32::try_from(v) {
                Ok(v) => Some(v),
                Err(_) => {
                    issues.push("wfp_invalid_ProcessID".into());
                    None
                }
            }
        });
        record.application = get("Application")
            .filter(|v| !v.is_empty() && *v != "-")
            .map(str::to_owned);
        if record.application.is_none() {
            issues.push("wfp_missing_application".into());
        }
        record.source_address = address(get("SourceAddress"), "SourceAddress", &mut issues);
        record.destination_address = address(get("DestAddress"), "DestAddress", &mut issues);
        record.source_port = bounded_number(get("SourcePort"), "SourcePort", &mut issues);
        record.destination_port = bounded_number(get("DestPort"), "DestPort", &mut issues);
        record.protocol = bounded_number(get("Protocol"), "Protocol", &mut issues);
        record.filter_runtime_id = number(get("FilterRTID"), "FilterRTID", &mut issues);
        record.layer_runtime_id = number(get("LayerRTID"), "LayerRTID", &mut issues);
        record.direction_token = get("Direction")
            .filter(|v| !v.is_empty())
            .map(str::to_owned);
        if record.direction_token.is_none() {
            issues.push("wfp_missing_direction".into());
        }
    } else {
        issues.push("wfp_unsupported_event_version".into());
    }
    let mut event = ThreatEvent::new(
        agent,
        EventSource::WindowsSecurity { event_id },
        EventCategory::Network,
        Severity::Info,
        EventData::WfpConnectionAudit {
            record: Box::new(record),
        },
    );
    event.timestamp = time;
    event.provenance = Some(EventProvenance {
        provider_guid: PROVIDER_GUID.into(),
        event_id,
        version,
        opcode,
        record_id: Some(record_id),
        original_time: true,
        fields,
        issues,
        ..Default::default()
    });
    Ok(event)
}

fn number(value: Option<&str>, name: &str, issues: &mut Vec<String>) -> Option<u64> {
    let parsed = value.and_then(|v| {
        if let Some(v) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
            (!v.is_empty() && v.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| u64::from_str_radix(v, 16).ok())
                .flatten()
        } else {
            (!v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                .then(|| v.parse().ok())
                .flatten()
        }
    });
    if parsed.is_none() {
        issues.push(format!("wfp_missing_or_invalid_{name}"));
    }
    parsed
}
fn bounded_number<T: TryFrom<u64>>(
    value: Option<&str>,
    name: &str,
    issues: &mut Vec<String>,
) -> Option<T> {
    number(value, name, issues).and_then(|v| {
        T::try_from(v).ok().or_else(|| {
            issues.push(format!("wfp_invalid_{name}"));
            None
        })
    })
}
fn address(value: Option<&str>, name: &str, issues: &mut Vec<String>) -> Option<String> {
    let result = value
        .filter(|v| v.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_owned);
    if result.is_none() {
        issues.push(format!("wfp_missing_or_invalid_{name}"));
    }
    result
}

fn decimal<T: std::str::FromStr>(value: Option<&str>) -> Result<T> {
    let value = value.context("wfp_missing_system_number")?;
    ensure!(
        !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
        "wfp_invalid_system_number"
    );
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("wfp_system_number_out_of_range"))
}

fn valid_xml_text(value: &str) -> bool {
    value.chars().all(|c| matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}'))
}

#[cfg(test)]
mod tests;
