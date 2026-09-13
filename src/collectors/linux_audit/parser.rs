//! Bounded RAW audit grammar and privacy projection. No -i/enriched syslog
//! guessing, raw argv/proctitle storage, filesystem lookups or syscall execution.
use crate::linux_events::{AuditRecord, AuditStamp, AuditValue};
use anyhow::{ensure, Context, Result};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_FIELDS: usize = 128;
const MAX_VALUE_BYTES: usize = 4096;

pub fn supported(kind: u16) -> bool {
    matches!(
        kind,
        1006 | 1300 | 1302 | 1305 | 1306 | 1307 | 1309 | 1320 | 1327
    )
}
pub fn standalone(kind: u16) -> bool {
    matches!(kind, 1006 | 1305)
}

pub fn parse(kind: u16, payload: &[u8]) -> Result<(AuditStamp, AuditRecord)> {
    ensure!(payload.len() <= MAX_RECORD_BYTES, "audit_record_too_large");
    let payload = payload.strip_suffix(&[0]).unwrap_or(payload);
    ensure!(!payload.contains(&0), "audit_embedded_nul");
    let text = std::str::from_utf8(payload).context("audit_invalid_transport_utf8")?;
    let text = text.trim_end_matches(['\r', '\n']);
    let text = text.strip_prefix("msg=").unwrap_or(text);
    let (stamp, body) = text
        .strip_prefix("audit(")
        .context("audit_missing_header")?
        .split_once("):")
        .context("audit_missing_header_end")?;
    let (time, serial) = stamp.split_once(':').context("audit_missing_serial")?;
    let (seconds, fraction) = time.split_once('.').context("audit_missing_fraction")?;
    ensure!(
        !seconds.is_empty()
            && seconds.bytes().all(|c| c.is_ascii_digit())
            && !serial.is_empty()
            && serial.bytes().all(|c| c.is_ascii_digit())
            && (1..=9).contains(&fraction.len())
            && fraction.bytes().all(|c| c.is_ascii_digit()),
        "audit_invalid_stamp"
    );
    let seconds = seconds.parse::<i64>()?;
    let nanoseconds = fraction.parse::<u32>()? * 10_u32.pow(9 - fraction.len() as u32);
    ensure!(
        chrono::DateTime::from_timestamp(seconds, nanoseconds).is_some(),
        "audit_invalid_timestamp"
    );
    let stamp = AuditStamp {
        seconds,
        nanoseconds,
        serial: serial.parse()?,
    };
    let mut record = AuditRecord {
        native_type: kind,
        fields: BTreeMap::new(),
        omitted_fields: vec![],
        issues: vec![],
    };
    let mut body = body.trim_start();
    let mut count = 0;
    let mut keys = BTreeSet::new();
    while !body.is_empty() {
        count += 1;
        ensure!(count <= MAX_FIELDS, "audit_too_many_fields");
        let key_end = body.find('=').context("audit_field_without_value")?;
        let key = &body[..key_end];
        ensure!(
            !key.is_empty()
                && key.len() <= 64
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'[' | b']')),
            "audit_invalid_field_name"
        );
        ensure!(keys.insert(key), "audit_duplicate_field");
        body = &body[key_end + 1..];
        let (value, quoted, rest) =
            if let Some(quote @ (b'"' | b'\'')) = body.as_bytes().first().copied() {
                let end = body[1..]
                    .find(quote as char)
                    .context("audit_unterminated_quote")?
                    + 1;
                (&body[1..end], true, &body[end + 1..])
            } else {
                let end = body.find(char::is_whitespace).unwrap_or(body.len());
                (&body[..end], false, &body[end..])
            };
        ensure!(!value.is_empty() || quoted, "audit_empty_unquoted_value");
        ensure!(
            rest.is_empty() || rest.starts_with(char::is_whitespace),
            "audit_invalid_field_separator"
        );
        body = rest.trim_start();
        if allowed(kind, key) {
            ensure!(value.len() <= MAX_VALUE_BYTES * 2, "audit_value_too_large");
            let is_hex_string = !quoted && is_string(kind, key) && value != "(null)";
            let value = if is_hex_string {
                let bytes = unhex(value)?;
                ensure!(bytes.len() <= MAX_VALUE_BYTES, "audit_value_too_large");
                match String::from_utf8(bytes) {
                    Ok(value) => AuditValue {
                        value,
                        audit_hex_encoded: true,
                        invalid_utf8_hex: None,
                    },
                    Err(e) => {
                        record.issues.push("audit_string_invalid_utf8".into());
                        AuditValue {
                            value: String::from_utf8_lossy(e.as_bytes()).into_owned(),
                            audit_hex_encoded: true,
                            invalid_utf8_hex: Some(value.to_ascii_lowercase()),
                        }
                    }
                }
            } else {
                ensure!(value.len() <= MAX_VALUE_BYTES, "audit_value_too_large");
                AuditValue {
                    value: value.into(),
                    audit_hex_encoded: false,
                    invalid_utf8_hex: None,
                }
            };
            ensure!(
                record.fields.insert(key.into(), value).is_none(),
                "audit_duplicate_field"
            );
        } else {
            record.omitted_fields.push(key.into());
        }
    }
    Ok((stamp, record))
}

fn allowed(kind: u16, key: &str) -> bool {
    match kind {
        1300 => matches!(
            key,
            "arch"
                | "syscall"
                | "success"
                | "exit"
                | "items"
                | "ppid"
                | "pid"
                | "auid"
                | "uid"
                | "gid"
                | "euid"
                | "suid"
                | "fsuid"
                | "egid"
                | "sgid"
                | "fsgid"
                | "tty"
                | "ses"
                | "comm"
                | "exe"
                | "key"
        ),
        1302 => matches!(
            key,
            "item" | "name" | "inode" | "dev" | "mode" | "ouid" | "ogid" | "rdev" | "nametype"
        ),
        1305 => matches!(
            key,
            "auid" | "ses" | "op" | "key" | "list" | "res" | "enabled" | "old"
        ),
        1006 => matches!(
            key,
            "pid" | "uid" | "old-auid" | "auid" | "old-ses" | "ses" | "res"
        ),
        1306 => key == "saddr", // Original bytes only; no invented connect/direction semantics.
        1307 => key == "cwd",
        1309 => key == "argc", // Every aN / aN_len / aN[N] intentionally omitted.
        _ => false,            // Includes PROCTITLE. No raw payload fallback leaks secrets.
    }
}
fn is_string(kind: u16, key: &str) -> bool {
    matches!(
        (kind, key),
        (1300, "comm" | "exe" | "key") | (1302, "name") | (1307, "cwd") | (1305, "key")
    )
}
fn unhex(value: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "audit_invalid_hex_string"
    );
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).map_err(Into::into))
        .collect()
}

/// Native Netlink headers use host byte order and the Linux UAPI layout. Validate
/// the entire datagram before yielding any borrowed records to the decoder.
pub fn frames(packet: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    ensure!(
        !packet.is_empty() && packet.len() <= 128 * 1024,
        "audit_invalid_datagram_size"
    );
    let mut offset = 0;
    let mut result = Vec::new();
    while offset < packet.len() {
        ensure!(
            result.len() < 128 && packet.len() - offset >= 16,
            "audit_bad_netlink_header"
        );
        let header = &packet[offset..offset + 16];
        let length = u32::from_ne_bytes(header[..4].try_into()?) as usize;
        let kind = u16::from_ne_bytes(header[4..6].try_into()?);
        ensure!(
            length >= 16 && length <= packet.len() - offset,
            "audit_bad_netlink_length"
        );
        ensure!(length - 16 <= MAX_RECORD_BYTES, "audit_record_too_large");
        result.push((kind, &packet[offset + 16..offset + length]));
        if offset + length == packet.len() {
            break;
        }
        let aligned = length
            .checked_add(3)
            .context("audit_netlink_length_overflow")?
            & !3;
        ensure!(
            aligned <= packet.len() - offset,
            "audit_missing_netlink_padding"
        );
        offset += aligned;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_fields_time_and_hex_strings_are_preserved_without_arguments() {
        let (stamp, event) = parse(1300, b"audit(1700000000.123:42): arch=c000003e syscall=59 pid=42 exe=2F62696E2F7368 comm=7368 a0=SECRET success=yes").unwrap();
        assert_eq!(stamp.nanoseconds, 123_000_000);
        assert_eq!(stamp.serial, 42);
        assert_eq!(event.fields["exe"].value, "/bin/sh");
        assert_eq!(event.fields["arch"].value, "c000003e");
        assert_eq!(event.omitted_fields, ["a0"]);
        assert!(!serde_json::to_string(&event).unwrap().contains("SECRET"));
    }
    #[test]
    fn execve_and_proctitle_never_store_secret_values() {
        for (kind, body) in [
            (
                1309,
                "argc=2 a0=7368 a1=534543524554 a2_len=20 a2[0]=534543524554",
            ),
            (1327, "proctitle=534543524554"),
        ] {
            let (_, event) =
                parse(kind, format!("audit(1700000000.1:1): {body}").as_bytes()).unwrap();
            let json = serde_json::to_string(&event).unwrap();
            assert!(!json.contains("534543524554"));
            assert!(!json.contains("SECRET"));
        }
    }
    #[test]
    fn quotes_spaces_japanese_and_invalid_utf8_hex() {
        let (_, record) = parse(
            1302,
            "audit(1700000000.123456789:1): item=0 name=\"/tmp/日本語 file\" nametype=CREATE"
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(record.fields["name"].value, "/tmp/日本語 file");
        let (_, record) = parse(1302, b"audit(1700000000.1:1): name=61FF").unwrap();
        assert_eq!(
            record.fields["name"].invalid_utf8_hex.as_deref(),
            Some("61ff")
        );
        assert_eq!(record.issues, ["audit_string_invalid_utf8"]);
    }
    #[test]
    fn malformed_and_oversized_data_is_rejected_without_echoing_payload() {
        for body in [
            "pid=1 pid=2",
            "name=XYZ",
            "name=\"unfinished",
            "name=\"ok\"pid=1",
            "bad field=secret",
        ] {
            let error =
                parse(1302, format!("audit(1700000000.1:1): {body}").as_bytes()).unwrap_err();
            assert!(!error.to_string().contains("secret"));
        }
        for header in [
            "audit(-1.1:1):",
            "audit(1.0000000001:1):",
            "audit(1.1:):",
            "audit(1.x:1):",
            "prefix audit(1.1:1):",
        ] {
            assert!(parse(1300, header.as_bytes()).is_err());
        }
        assert!(parse(1300, &vec![b'x'; MAX_RECORD_BYTES + 1]).is_err());
        assert!(parse(1300, b"audit(1.1:1): pid=1\0x").is_err());
    }
    #[test]
    fn all_datagram_lengths_are_validated_before_any_emission() {
        assert!(frames(&[]).is_err());
        let mut bytes = vec![0; 20];
        bytes[..4].copy_from_slice(&20_u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&1300_u16.to_ne_bytes());
        bytes[16..].copy_from_slice(b"test");
        assert_eq!(frames(&bytes).unwrap(), [(1300, b"test".as_slice())]);
        bytes.push(1);
        assert!(frames(&bytes).is_err());
        bytes[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(frames(&bytes).is_err());
        bytes[..4].copy_from_slice(&0_u32.to_ne_bytes());
        assert!(frames(&bytes).is_err());
    }
    #[test]
    fn field_count_text_caps_and_aligned_multiframe_datagrams_are_bounded() {
        let fields = (0..=MAX_FIELDS)
            .map(|i| format!("a{i}=private "))
            .collect::<String>();
        assert!(parse(1309, format!("audit(1.1:1): {fields}").as_bytes()).is_err());
        let oversized = format!("audit(1.1:1): name=\"{}\"", "x".repeat(MAX_VALUE_BYTES + 1));
        assert!(parse(1302, oversized.as_bytes()).is_err());
        let mut packet = vec![0; 40];
        packet[..4].copy_from_slice(&17u32.to_ne_bytes());
        packet[4..6].copy_from_slice(&1300u16.to_ne_bytes());
        packet[16] = b'a';
        packet[20..24].copy_from_slice(&20u32.to_ne_bytes());
        packet[24..26].copy_from_slice(&1320u16.to_ne_bytes());
        packet[36..].copy_from_slice(b"done");
        assert_eq!(
            frames(&packet).unwrap(),
            [(1300, b"a".as_slice()), (1320, b"done".as_slice())]
        );
        packet[20..24].copy_from_slice(&15u32.to_ne_bytes());
        assert!(frames(&packet).is_err());
    }
}
