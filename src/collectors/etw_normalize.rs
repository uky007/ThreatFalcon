//! Version-aware TDH decoding lives in tdh.rs; this layer never reads byte offsets.
#![allow(dead_code)] // Production callers run on Windows; fixtures run everywhere.

use crate::events::*;
use chrono::{DateTime, Utc};

pub const PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
pub const NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
pub const POWERSHELL: &str = "a0c1853b-5c40-4b15-8766-3cf1c58f985a";
pub const DNS: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";

pub fn filetime(ticks: u64) -> Option<DateTime<Utc>> {
    // Reject pre-Unix timestamps; neither sensor process starts nor event
    // timestamps should precede 1970. Checked arithmetic also rejects overflow.
    let ticks = ticks.checked_sub(116_444_736_000_000_000)?;
    DateTime::from_timestamp(
        (ticks / 10_000_000).try_into().ok()?,
        ((ticks % 10_000_000) * 100) as u32,
    )
}

pub fn number(s: &str) -> Option<u64> {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map_or_else(|| s.parse().ok(), |hex| u64::from_str_radix(hex, 16).ok())
}

pub fn normalize(
    agent: &AgentInfo,
    provider_name: String,
    header_pid: u32,
    ticks: u64,
    mut origin: EventProvenance,
    payload_hex: Option<String>,
) -> ThreatEvent {
    let time = filetime(ticks);
    origin.original_time = time.is_some();
    if time.is_none() {
        origin.issues.push("invalid_source_time".into());
    }
    let mapped = if origin.issues.is_empty() {
        map(&origin, header_pid)
    } else {
        None
    };
    let (category, data) = mapped.unwrap_or_else(|| {
        origin.issues.push("not_normalized".into());
        (
            EventCategory::Telemetry,
            EventData::NativeTelemetry {
                pid: (header_pid != u32::MAX).then_some(header_pid),
                reason: "schema_or_semantics_unavailable".into(),
                payload_hex,
            },
        )
    });
    let mut event = ThreatEvent::new(
        agent,
        EventSource::Etw {
            provider: provider_name,
        },
        category,
        Severity::Info,
        data,
    );
    if let Some(time) = time {
        event.timestamp = time;
    }
    event.provenance = Some(origin);
    event
}

fn map(p: &EventProvenance, header_pid: u32) -> Option<(EventCategory, EventData)> {
    let field = |names: &[&str]| -> Option<String> {
        names.iter().find_map(|name| {
            p.fields
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        })
    };
    let n = |names: &[&str]| field(names).as_deref().and_then(number);
    let pid = || n(&["ProcessID", "PID"]).and_then(|v| u32::try_from(v).ok());
    match p.provider_guid.as_str() {
        PROCESS => match p.event_id {
            1 => Some((
                EventCategory::Process,
                EventData::ProcessCreate {
                    pid: pid()?,
                    ppid: n(&["ParentProcessID"])?.try_into().ok()?,
                    image_path: field(&["ImageName"]).filter(|s| !s.is_empty())?,
                    command_line: field(&["CommandLine"]).unwrap_or_default(),
                    user: String::new(),
                    integrity_level: String::new(),
                    hashes: None,
                    create_time: n(&["CreateTime"]).filter(|t| filetime(*t).is_some()),
                },
            )),
            2 => Some((
                EventCategory::Process,
                EventData::ProcessTerminate {
                    pid: pid()?,
                    image_path: field(&["ImageName"]).unwrap_or_default(),
                    create_time: n(&["CreateTime"]).filter(|t| filetime(*t).is_some()),
                },
            )),
            5 => {
                let image = field(&["ImageName"]).filter(|s| !s.is_empty())?;
                // SE_SIGNING_LEVEL isn't a certificate validity check. Unchecked,
                // custom, and unrecognized levels remain unknown.
                let signed = match n(&["SignatureLevel"]) {
                    Some(1) => Some(false),
                    Some(4 | 6 | 7 | 8 | 12 | 14) => Some(true),
                    _ => None,
                };
                Some((
                    EventCategory::ImageLoad,
                    EventData::ImageLoad {
                        pid: pid()?,
                        image_name: image.rsplit('\\').next()?.to_string(),
                        image_path: image,
                        signed,
                        signature: field(&["SignatureType"]),
                        hashes: None,
                    },
                ))
            }
            _ => None,
        },
        NETWORK => {
            // Numeric IDs differed between the old parser and Windows schemas.
            // Require an explicit native operation name; never infer Connect from Send.
            let operation = field(&["@opcode_name"])
                .unwrap_or_default()
                .to_ascii_lowercase();
            let task = field(&["@task_name"])
                .unwrap_or_default()
                .to_ascii_lowercase();
            let name = field(&["@event_name"])
                .unwrap_or_default()
                .to_ascii_lowercase();
            let words: Vec<&str> = name.split(|c: char| !c.is_ascii_alphanumeric()).collect();
            let has = |v: &str| operation == v || task == v || words.contains(&v);
            let direction = if has("send") || has("connect") {
                NetworkDirection::Outbound
            } else if has("recv") || has("receive") || has("accept") {
                NetworkDirection::Inbound
            } else {
                return None;
            };
            let protocol = if task.contains("tcp") || name.contains("tcp") {
                "TCP"
            } else if task.contains("udp") || name.contains("udp") {
                "UDP"
            } else {
                return None;
            };
            let src_addr = field(&["saddr", "SourceAddress"])?;
            let dst_addr = field(&["daddr", "DestinationAddress"])?;
            src_addr.parse::<std::net::IpAddr>().ok()?;
            dst_addr.parse::<std::net::IpAddr>().ok()?;
            let src_port = n(&["sport", "SourcePort"])?.try_into().ok()?;
            let dst_port = n(&["dport", "DestinationPort"])?.try_into().ok()?;
            let data = if has("connect") || has("accept") {
                EventData::NetworkConnect {
                    pid: pid()?,
                    image_path: String::new(),
                    protocol: protocol.into(),
                    src_addr,
                    src_port,
                    dst_addr,
                    dst_port,
                    direction,
                }
            } else {
                EventData::NetworkTraffic {
                    pid: pid()?,
                    protocol: protocol.into(),
                    src_addr,
                    src_port,
                    dst_addr,
                    dst_port,
                    direction,
                    bytes: n(&["size", "TransferSize"])?,
                }
            };
            Some((EventCategory::Network, data))
        }
        POWERSHELL if p.event_id == 4104 => Some((
            EventCategory::Script,
            EventData::ScriptBlock {
                pid: header_pid,
                script_engine: "PowerShell".into(),
                content: field(&["ScriptBlockText"])?,
                script_path: field(&["Path"]),
                script_block_id: field(&["ScriptBlockId"]),
            },
        )),
        DNS if matches!(p.event_id, 3006 | 3008) => Some((
            EventCategory::Dns,
            EventData::DnsQuery {
                pid: header_pid,
                query_name: field(&["QueryName"])?,
                query_type: field(&["QueryType"])?,
                response: field(&["QueryResults"]),
            },
        )),
        // Unsupported providers, including restricted TI schemas, retain their
        // native fields. An operation is not automatically a malware detection.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn origin(guid: &str, id: u16, fields: &[(&str, &str)]) -> EventProvenance {
        EventProvenance {
            provider_guid: guid.into(),
            event_id: id,
            version: 99,
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        }
    }
    fn event(p: EventProvenance) -> ThreatEvent {
        normalize(
            &AgentInfo {
                hostname: "fixture".into(),
                agent_id: uuid::Uuid::nil(),
            },
            "fixture".into(),
            999,
            133_000_000_000_000_000,
            p,
            Some("abcd".into()),
        )
    }
    #[test]
    fn original_time_and_native_version_survive() {
        let e = event(origin(
            PROCESS,
            1,
            &[
                ("ProcessID", "42"),
                ("ParentProcessID", "1"),
                ("ImageName", "test.exe"),
            ],
        ));
        assert!(matches!(e.data, EventData::ProcessCreate { pid: 42, .. }));
        assert_eq!(e.timestamp, filetime(133_000_000_000_000_000).unwrap());
        assert_eq!(e.provenance.unwrap().version, 99);
    }
    #[test]
    fn incomplete_schema_never_fabricates_process() {
        assert!(matches!(
            event(origin(PROCESS, 1, &[("ProcessID", "42")])).data,
            EventData::NativeTelemetry { .. }
        ));
        assert!(filetime(0).is_none());
    }
    #[test]
    fn send_is_traffic_and_uses_payload_pid() {
        let e = event(origin(
            NETWORK,
            10,
            &[
                ("PID", "42"),
                ("@opcode_name", "Send"),
                ("@task_name", "TcpIp"),
                ("saddr", "10.0.0.1"),
                ("daddr", "192.0.2.1"),
                ("sport", "1234"),
                ("dport", "443"),
                ("size", "4096"),
            ],
        ));
        assert!(matches!(
            e.data,
            EventData::NetworkTraffic {
                pid: 42,
                bytes: 4096,
                ..
            }
        ));
    }
    #[test]
    fn unchecked_signature_is_unknown() {
        for (level, expected) in [
            ("0", None),
            ("1", Some(false)),
            ("6", Some(true)),
            ("255", None),
        ] {
            let e = event(origin(
                PROCESS,
                5,
                &[
                    ("ProcessID", "42"),
                    ("ImageName", "a.dll"),
                    ("SignatureLevel", level),
                ],
            ));
            assert!(matches!(e.data, EventData::ImageLoad { signed, .. } if signed==expected));
        }
    }
    #[test]
    fn full_guid_not_prefix() {
        assert!(matches!(
            event(origin("22fb2cd6-0000-0000-0000-000000000000", 1, &[])).data,
            EventData::NativeTelemetry { .. }
        ));
    }
}
