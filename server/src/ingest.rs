//! Request body decoding and batch validation.
//!
//! The sensor's HTTP sink POSTs a JSON array of `ThreatEvent` objects,
//! optionally gzip-compressed. Each element is checked against the event
//! envelope (the fields every `ThreatEvent` has) and stored byte-for-byte
//! as one JSONL line. Payload contents (`data`) are not interpreted beyond
//! the `type` tag, so newer sensors with new event types keep working.
//!
//! The sensor treats any 2xx response as delivery of the whole batch, so
//! elements that fail validation are never dropped: they are returned as
//! quarantine records and stored next to the events.

use std::borrow::Cow;
use std::cell::Cell;
use std::fmt;
use std::io::Read;

use serde::de::{self, DeserializeSeed, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::value::RawValue;

/// Number of per-element validation errors echoed back to the client.
pub const MAX_REPORTED_ERRORS: usize = 10;
/// Larger `SensorHealth` payloads are stored but not kept in agent status.
const MAX_HEALTH_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentEncoding {
    Identity,
    Gzip,
}

/// Errors that make the whole request unusable (nothing can be stored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestError {
    UnsupportedMediaType(String),
    PayloadTooLarge(String),
    BadRequest(String),
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedMediaType(m) | Self::PayloadTooLarge(m) | Self::BadRequest(m) => {
                f.write_str(m)
            }
        }
    }
}

impl std::error::Error for IngestError {}

pub fn parse_content_encoding(value: Option<&str>) -> Result<ContentEncoding, IngestError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(ContentEncoding::Identity);
    };
    if value.eq_ignore_ascii_case("identity") {
        Ok(ContentEncoding::Identity)
    } else if value.eq_ignore_ascii_case("gzip") || value.eq_ignore_ascii_case("x-gzip") {
        Ok(ContentEncoding::Gzip)
    } else {
        Err(IngestError::UnsupportedMediaType(format!(
            "unsupported Content-Encoding {value:?} (use gzip or none)"
        )))
    }
}

pub fn check_content_type(value: Option<&str>) -> Result<(), IngestError> {
    let Some(value) = value else {
        return Ok(());
    };
    let media_type = value.split(';').next().unwrap_or("").trim();
    if media_type.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(IngestError::UnsupportedMediaType(format!(
            "unsupported Content-Type {media_type:?} (expected application/json)"
        )))
    }
}

/// Decode the request body, enforcing `max_decoded` on the result so that a
/// small compressed body cannot expand without bound.
pub fn decode_body(
    body: &[u8],
    encoding: ContentEncoding,
    max_decoded: usize,
) -> Result<Cow<'_, [u8]>, IngestError> {
    let too_large =
        || IngestError::PayloadTooLarge(format!("decoded payload exceeds {max_decoded} bytes"));
    match encoding {
        ContentEncoding::Identity => {
            if body.len() > max_decoded {
                return Err(too_large());
            }
            Ok(Cow::Borrowed(body))
        }
        ContentEncoding::Gzip => {
            let limit = u64::try_from(max_decoded)
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            let mut out = Vec::with_capacity(body.len().saturating_mul(4).min(max_decoded));
            flate2::read::MultiGzDecoder::new(body)
                .take(limit)
                .read_to_end(&mut out)
                .map_err(|e| IngestError::BadRequest(format!("invalid gzip body: {e}")))?;
            if out.len() > max_decoded {
                return Err(too_large());
            }
            Ok(Cow::Owned(out))
        }
    }
}

/// Fields extracted from a batch for agent status reporting.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BatchSummary {
    pub hostname: Option<String>,
    pub agent_id: Option<String>,
    pub sensor_version: Option<String>,
    pub last_event_timestamp: Option<String>,
    /// `data` of the last `SensorHealth` event in the batch.
    pub health: Option<serde_json::Value>,
}

/// A valid event, ready to be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedEvent<'a> {
    /// The event's `id`, used for duplicate suppression.
    pub id: u128,
    /// The event as one line of JSON (no trailing newline).
    pub line: Cow<'a, str>,
}

/// An array element that failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedElement<'a> {
    /// Position in the batch.
    pub index: usize,
    pub reason: String,
    /// The element as one line of JSON.
    pub json: Cow<'a, str>,
}

#[derive(Debug, Clone, Default)]
pub struct Batch<'a> {
    /// Valid events in batch order.
    pub events: Vec<ValidatedEvent<'a>>,
    /// Elements to quarantine.
    pub rejected: Vec<RejectedElement<'a>>,
    pub summary: BatchSummary,
}

impl Batch<'_> {
    /// The first few validation errors, for the response body.
    pub fn errors(&self) -> Vec<String> {
        self.rejected
            .iter()
            .take(MAX_REPORTED_ERRORS)
            .map(|r| format!("event[{}]: {}", r.index, r.reason))
            .collect()
    }
}

/// Parse and validate a decoded batch payload.
pub fn parse_batch(payload: &[u8], max_events: usize) -> Result<Batch<'_>, IngestError> {
    let too_many = Cell::new(false);
    let mut de = serde_json::Deserializer::from_slice(payload);
    let items = BoundedRawArray {
        max: max_events,
        exceeded: &too_many,
    }
    .deserialize(&mut de)
    .and_then(|items| de.end().map(|()| items))
    .map_err(|e| {
        if too_many.get() {
            IngestError::PayloadTooLarge(format!("batch exceeds {max_events} events"))
        } else {
            IngestError::BadRequest(format!("body is not a JSON array of events: {e}"))
        }
    })?;

    let mut batch = Batch::default();
    for (index, raw) in items.into_iter().enumerate() {
        match validate_event(raw) {
            Ok(event) => {
                let summary = &mut batch.summary;
                summary.hostname = Some(event.hostname);
                summary.agent_id = Some(event.agent_id);
                summary.sensor_version = Some(event.sensor_version);
                summary.last_event_timestamp = Some(event.timestamp);
                if event.health.is_some() {
                    summary.health = event.health;
                }
                batch.events.push(ValidatedEvent {
                    id: event.id,
                    line: event.line,
                });
            }
            Err(reason) => batch.rejected.push(RejectedElement {
                index,
                reason,
                json: single_line(raw.get()),
            }),
        }
    }
    Ok(batch)
}

/// Format quarantine records (one JSON object per line, each ending with a
/// newline) for the rejected elements of a batch.
pub fn quarantine_lines(
    rejected: &[RejectedElement<'_>],
    agent: &str,
    received_at: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    for r in rejected {
        // `r.json` is valid single-line JSON, so it can be embedded as is.
        let line = format!(
            "{{\"received_at\":{},\"agent\":{},\"index\":{},\"reason\":{},\"element\":{}}}\n",
            json_string(received_at),
            json_string(agent),
            r.index,
            json_string(&r.reason),
            r.json
        );
        out.extend_from_slice(line.as_bytes());
    }
    out
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// JSONL needs one value per line. In valid JSON, CR and LF can only occur
/// as insignificant whitespace (inside strings they must be escaped), so
/// replacing them with spaces is lossless.
fn single_line(text: &str) -> Cow<'_, str> {
    if text.contains(['\n', '\r']) {
        Cow::Owned(text.replace(['\n', '\r'], " "))
    } else {
        Cow::Borrowed(text)
    }
}

/// Required `ThreatEvent` envelope fields. Unknown fields are allowed;
/// duplicated fields are rejected by serde.
#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow)]
    id: Cow<'a, str>,
    #[serde(borrow)]
    timestamp: Cow<'a, str>,
    #[serde(borrow)]
    hostname: Cow<'a, str>,
    #[serde(borrow)]
    agent_id: Cow<'a, str>,
    #[serde(borrow)]
    sensor_version: Cow<'a, str>,
    #[serde(borrow)]
    source: &'a RawValue,
    #[serde(borrow)]
    category: Cow<'a, str>,
    #[serde(borrow)]
    severity: Cow<'a, str>,
    #[serde(borrow)]
    data: &'a RawValue,
}

#[derive(Deserialize)]
struct DataTag<'a> {
    #[serde(rename = "type", borrow)]
    kind: Cow<'a, str>,
}

struct ValidEvent<'a> {
    id: u128,
    line: Cow<'a, str>,
    hostname: String,
    agent_id: String,
    sensor_version: String,
    timestamp: String,
    health: Option<serde_json::Value>,
}

fn validate_event(raw: &RawValue) -> Result<ValidEvent<'_>, String> {
    let text = raw.get();
    if !text.starts_with('{') {
        return Err("event is not a JSON object".into());
    }
    let env: Envelope = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let id = uuid::Uuid::try_parse(&env.id).map_err(|_| "`id` is not a UUID".to_string())?;
    uuid::Uuid::try_parse(&env.agent_id).map_err(|_| "`agent_id` is not a UUID".to_string())?;
    chrono::DateTime::parse_from_rfc3339(&env.timestamp)
        .map_err(|_| "`timestamp` is not an RFC 3339 timestamp".to_string())?;
    let source = env.source.get();
    if !(source.starts_with('"') || source.starts_with('{')) {
        return Err("`source` must be a string or an object".into());
    }
    if env.category.is_empty() || env.severity.is_empty() {
        return Err("`category` and `severity` must not be empty".into());
    }
    let data = env.data.get();
    if !data.starts_with('{') {
        return Err("`data` is not a JSON object".into());
    }
    let tag: DataTag = serde_json::from_str(data).map_err(|e| format!("`data`: {e}"))?;

    let health =
        if env.category == "Health" && tag.kind == "SensorHealth" && data.len() <= MAX_HEALTH_BYTES
        {
            serde_json::from_str(data).ok()
        } else {
            None
        };

    Ok(ValidEvent {
        id: id.as_u128(),
        line: single_line(text),
        hostname: env.hostname.into_owned(),
        agent_id: env.agent_id.into_owned(),
        sensor_version: env.sensor_version.into_owned(),
        timestamp: env.timestamp.into_owned(),
        health,
    })
}

/// Deserializes a JSON array into borrowed raw elements, failing as soon as
/// it holds more than `max` elements (instead of allocating for all of
/// them first).
struct BoundedRawArray<'c> {
    max: usize,
    exceeded: &'c Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for BoundedRawArray<'_> {
    type Value = Vec<&'de RawValue>;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for BoundedRawArray<'_> {
    type Value = Vec<&'de RawValue>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON array of events")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(self.max).min(1024));
        while let Some(item) = seq.next_element::<&'de RawValue>()? {
            if items.len() == self.max {
                self.exceeded.set(true);
                return Err(de::Error::custom(format!("more than {} events", self.max)));
            }
            items.push(item);
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const AGENT: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn event(id: &str) -> String {
        format!(
            r#"{{"id":"{id}","timestamp":"2026-11-15T00:00:00Z","hostname":"HOST01","agent_id":"{AGENT}","sensor_version":"0.5.0","source":{{"Etw":{{"provider":"Microsoft-Windows-Kernel-Process"}}}},"category":"Process","severity":"Info","data":{{"type":"ProcessCreate","pid":1,"ppid":0,"image_path":"C:\\x.exe","command_line":"x","user":"","integrity_level":"","hashes":null}},"process_context":{{"process_key":"1:0"}}}}"#
        )
    }

    fn health_event(id: &str) -> String {
        format!(
            r#"{{"id":"{id}","timestamp":"2026-11-15T00:01:00Z","hostname":"HOST01","agent_id":"{AGENT}","sensor_version":"0.5.0","source":"Sensor","category":"Health","severity":"Info","data":{{"type":"SensorHealth","uptime_secs":60,"events_total":10,"events_dropped":0,"collectors":[{{"name":"ETW","state":"Running"}}]}}}}"#
        )
    }

    fn id(n: u32) -> String {
        format!("00000000-0000-4000-8000-{n:012}")
    }

    fn uuid_u128(s: &str) -> u128 {
        uuid::Uuid::parse_str(s).unwrap().as_u128()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn content_encoding_parsing() {
        assert_eq!(parse_content_encoding(None), Ok(ContentEncoding::Identity));
        assert_eq!(
            parse_content_encoding(Some("")),
            Ok(ContentEncoding::Identity)
        );
        assert_eq!(
            parse_content_encoding(Some("identity")),
            Ok(ContentEncoding::Identity)
        );
        assert_eq!(
            parse_content_encoding(Some("gzip")),
            Ok(ContentEncoding::Gzip)
        );
        assert_eq!(
            parse_content_encoding(Some(" GZIP ")),
            Ok(ContentEncoding::Gzip)
        );
        assert_eq!(
            parse_content_encoding(Some("x-gzip")),
            Ok(ContentEncoding::Gzip)
        );
        assert!(parse_content_encoding(Some("br")).is_err());
        assert!(parse_content_encoding(Some("gzip, br")).is_err());
    }

    #[test]
    fn content_type_checking() {
        assert!(check_content_type(None).is_ok());
        assert!(check_content_type(Some("application/json")).is_ok());
        assert!(check_content_type(Some("Application/JSON; charset=utf-8")).is_ok());
        assert!(check_content_type(Some("text/plain")).is_err());
    }

    #[test]
    fn decodes_identity_and_gzip() {
        let body = b"[1,2,3]";
        assert_eq!(
            &*decode_body(body, ContentEncoding::Identity, 100).unwrap(),
            body
        );
        let gz = gzip(body);
        assert_eq!(
            &*decode_body(&gz, ContentEncoding::Gzip, 100).unwrap(),
            body
        );
    }

    #[test]
    fn decode_enforces_limits() {
        assert!(matches!(
            decode_body(b"0123456789", ContentEncoding::Identity, 5),
            Err(IngestError::PayloadTooLarge(_))
        ));
        // 10 MiB of zeros compresses to a few KB but must not be inflated past the cap.
        let bomb = gzip(&vec![0u8; 10 * 1024 * 1024]);
        assert!(bomb.len() < 64 * 1024);
        assert!(matches!(
            decode_body(&bomb, ContentEncoding::Gzip, 1024 * 1024),
            Err(IngestError::PayloadTooLarge(_))
        ));
        assert!(matches!(
            decode_body(b"not gzip", ContentEncoding::Gzip, 1024),
            Err(IngestError::BadRequest(_))
        ));
    }

    #[test]
    fn decode_reads_concatenated_gzip_members() {
        let mut gz = gzip(b"[1,");
        gz.extend(gzip(b"2]"));
        assert_eq!(
            &*decode_body(&gz, ContentEncoding::Gzip, 100).unwrap(),
            b"[1,2]"
        );
    }

    #[test]
    fn parses_valid_batch_and_preserves_bytes() {
        let e1 = event(&id(1));
        let e2 = health_event(&id(2));
        let payload = format!("[{e1},{e2}]");
        let batch = parse_batch(payload.as_bytes(), 100).unwrap();
        assert!(batch.rejected.is_empty());
        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.events[0].line, e1);
        assert_eq!(batch.events[1].line, e2);
        assert_eq!(batch.events[0].id, uuid_u128(&id(1)));
        assert_eq!(batch.summary.hostname.as_deref(), Some("HOST01"));
        assert_eq!(batch.summary.agent_id.as_deref(), Some(AGENT));
        assert_eq!(batch.summary.sensor_version.as_deref(), Some("0.5.0"));
        assert_eq!(
            batch.summary.last_event_timestamp.as_deref(),
            Some("2026-11-15T00:01:00Z")
        );
        let health = batch.summary.health.unwrap();
        assert_eq!(health["uptime_secs"], 60);
        assert_eq!(health["collectors"][0]["state"], "Running");
    }

    #[test]
    fn empty_array_is_accepted() {
        let batch = parse_batch(b" [ ] ", 10).unwrap();
        assert!(batch.events.is_empty());
        assert!(batch.rejected.is_empty());
    }

    #[test]
    fn rejects_non_array_bodies() {
        for body in [&b"{}"[..], b"", b"null", b"[1,", b"[]x", b"not json"] {
            assert!(
                matches!(parse_batch(body, 10), Err(IngestError::BadRequest(_))),
                "body {:?} should be rejected",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn enforces_event_count_limit() {
        let payload = format!("[{},{},{}]", event(&id(1)), event(&id(2)), event(&id(3)));
        assert!(parse_batch(payload.as_bytes(), 3).is_ok());
        assert!(matches!(
            parse_batch(payload.as_bytes(), 2),
            Err(IngestError::PayloadTooLarge(_))
        ));
        // Cheap elements must hit the limit too, before being collected.
        let many = format!("[{}]", vec!["{}"; 1000].join(","));
        assert!(matches!(
            parse_batch(many.as_bytes(), 10),
            Err(IngestError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn invalid_elements_are_kept_for_quarantine() {
        let good = event(&id(1));
        let missing_id = good.replacen(&format!("\"id\":\"{}\",", id(1)), "", 1);
        let bad_uuid = event("not-a-uuid");
        let bad_ts = good.replace("2026-11-15T00:00:00Z", "yesterday");
        let data_not_object = good.replacen("\"data\":{", "\"data\":[{", 1).replacen(
            "\"hashes\":null},",
            "\"hashes\":null}],",
            1,
        );
        let dup_field = good.replacen("{\"id\"", "{\"hostname\":\"EVIL\",\"id\"", 1);
        let payload = format!(
            "[{good},{missing_id},{bad_uuid},{bad_ts},42,\"s\",{dup_field},{data_not_object}]"
        );
        let batch = parse_batch(payload.as_bytes(), 100).unwrap();
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.events[0].line, good);
        assert_eq!(batch.rejected.len(), 7);
        let indexes: Vec<usize> = batch.rejected.iter().map(|r| r.index).collect();
        assert_eq!(indexes, vec![1, 2, 3, 4, 5, 6, 7]);
        // The original element text is preserved for the quarantine.
        assert_eq!(batch.rejected[0].json, missing_id);
        assert_eq!(batch.rejected[3].json, "42");
        assert_eq!(batch.rejected[4].json, "\"s\"");
        assert!(batch
            .rejected
            .iter()
            .any(|r| r.reason.contains("duplicate field")));
        assert!(batch.errors()[0].starts_with("event[1]:"));
    }

    #[test]
    fn all_invalid_batch_is_not_an_error() {
        let batch = parse_batch(b"[1,2,{}]", 100).unwrap();
        assert!(batch.events.is_empty());
        assert_eq!(batch.rejected.len(), 3);
        assert_eq!(batch.errors().len(), 3);
    }

    #[test]
    fn caps_reported_errors() {
        let good = event(&id(1));
        let payload = format!("[{good},{}]", vec!["1"; 50].join(","));
        let batch = parse_batch(payload.as_bytes(), 100).unwrap();
        assert_eq!(batch.rejected.len(), 50);
        assert_eq!(batch.errors().len(), MAX_REPORTED_ERRORS);
    }

    #[test]
    fn multiline_elements_become_one_line_without_other_changes() {
        let compact = event(&id(7));
        let pretty = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(&compact).unwrap(),
        )
        .unwrap()
        .replace('\n', "\r\n");
        assert!(pretty.contains('\n'));
        let payload = format!("[\r\n{pretty}\n, [1,\n2]]");
        let batch = parse_batch(payload.as_bytes(), 10).unwrap();
        let line = &batch.events[0].line;
        assert!(!line.contains(['\n', '\r']));
        assert_eq!(line.len(), pretty.len(), "only CR/LF bytes are replaced");
        let reparsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(reparsed["id"], id(7));
        assert_eq!(batch.rejected[0].json, "[1, 2]");
    }

    #[test]
    fn unknown_fields_and_event_types_are_kept() {
        let future = event(&id(9))
            .replace("\"ProcessCreate\"", "\"SomethingNew\"")
            .replacen("{\"id\"", "{\"future_field\":{\"a\":1},\"id\"", 1);
        let payload = format!("[{future}]");
        let batch = parse_batch(payload.as_bytes(), 10).unwrap();
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.events[0].line, future);
    }

    #[test]
    fn quarantine_records_are_one_json_object_per_line() {
        let payload = format!("[{},{{\"x\":\"a\\nb\"}},\n42]", event(&id(1)));
        let batch = parse_batch(payload.as_bytes(), 10).unwrap();
        let out = quarantine_lines(&batch.rejected, "lab-ws01", "2026-11-15T00:00:00.000Z");
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(text.ends_with('\n'));
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["agent"], "lab-ws01");
        assert_eq!(first["index"], 1);
        assert_eq!(first["received_at"], "2026-11-15T00:00:00.000Z");
        assert_eq!(first["element"]["x"], "a\nb");
        assert!(first["reason"].as_str().unwrap().contains("missing field"));
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["element"], 42);
        assert_eq!(second["reason"], "event is not a JSON object");
    }
}
