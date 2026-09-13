use super::*;

fn origin(provider: &str, number: &str, total: &str) -> EventProvenance {
    EventProvenance {
        provider_guid: provider.into(),
        event_id: 4104,
        version: 1,
        opcode: 15,
        fields: [
            ("MessageNumber", number),
            ("MessageTotal", total),
            ("ScriptBlockId", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            ("ScriptBlockText", "Write-Output 'テスト'"),
            ("Path", "C:\\test.ps1"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect(),
        ..Default::default()
    }
}
fn decode(p: EventProvenance, pid: u32) -> ThreatEvent {
    normalize(
        &AgentInfo {
            hostname: "synthetic-windows".into(),
            agent_id: uuid::Uuid::from_u128(123),
        },
        if p.provider_guid == POWERSHELL_CORE {
            "PowerShellCore"
        } else {
            "Microsoft-Windows-PowerShell"
        }
        .into(),
        pid,
        133_000_000_000_000_000,
        p,
        Some("00".into()),
    )
}
pub(crate) fn fixture(provider: &str, number: &str, total: &str) -> ThreatEvent {
    decode(origin(provider, number, total), 4242)
}

#[test]
fn powershell_both_providers_preserve_fragment_metadata_and_logged_text() {
    for (provider, engine) in [
        (POWERSHELL, "PowerShell"),
        (POWERSHELL_CORE, "PowerShellCore"),
    ] {
        let event = fixture(provider, "2", "3");
        assert_eq!(event.data.script_fragment_position(), Some((2, 3)));
        let EventData::ScriptBlock {
            script_engine,
            content,
            script_path,
            script_block_id,
            pid,
            ..
        } = &event.data
        else {
            panic!("not a script fragment");
        };
        assert_eq!(script_engine, engine);
        assert_eq!(content, "Write-Output 'テスト'");
        assert_eq!(script_path.as_deref(), Some("C:\\test.ps1"));
        assert_eq!(
            script_block_id.as_deref(),
            Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        );
        assert_eq!(*pid, 4242);
        assert_eq!(event.severity, Severity::Info);
        assert!(event.process_context.is_none());
        assert_eq!(event.timestamp, filetime(133_000_000_000_000_000).unwrap());
        assert_ne!(Some(event.timestamp), event.observed_at);
        let p = event.provenance.as_ref().unwrap();
        assert_eq!((p.version, p.opcode), (1, 15));
        assert_eq!(p.fields["MessageTotal"], "3");
        assert!(p.original_time && p.issues.is_empty());
        assert!(p.process_guid.is_none());
        assert!(script_identity(&event).is_some());
    }
}

#[test]
fn powershell_invalid_positions_preserve_native_evidence_not_fake_one_of_one() {
    for (number, total) in [
        ("0", "0"),
        ("0", "1"),
        ("2", "1"),
        ("-1", "1"),
        ("1", "-2"),
        ("+1", "1"),
        ("1", "2147483648"),
        ("1", "0x2"),
        ("", "1"),
        ("1", "oops"),
    ] {
        let event = fixture(POWERSHELL_CORE, number, total);
        assert!(
            matches!(event.data, EventData::NativeTelemetry { .. }),
            "{number}/{total}"
        );
        assert!(event.data.script_fragment_position().is_none());
        let p = event.provenance.unwrap();
        assert_eq!(p.fields["MessageNumber"], number);
        assert_eq!(p.fields["MessageTotal"], total);
        assert!(p.issues.iter().any(|s| s.starts_with("powershell_")));
    }
    // Keep a valid large count as metadata only: no allocation based on it.
    assert_eq!(
        fixture(POWERSHELL_CORE, "1", "2147483647")
            .data
            .script_fragment_position(),
        Some((1, i32::MAX as u32))
    );
}

#[test]
fn powershell_missing_ambiguous_and_invalid_identity_fields_are_not_guessed() {
    for key in [
        "MessageNumber",
        "MessageTotal",
        "ScriptBlockId",
        "ScriptBlockText",
    ] {
        let mut p = origin(POWERSHELL, "1", "1");
        p.fields.remove(key);
        assert!(matches!(
            decode(p, 4242).data,
            EventData::NativeTelemetry { .. }
        ));
    }
    for id in ["", "not-a-guid", "00000000-0000-0000-0000-000000000000"] {
        let mut p = origin(POWERSHELL_CORE, "1", "1");
        p.fields.insert("ScriptBlockId".into(), id.into());
        assert!(matches!(
            decode(p, 4242).data,
            EventData::NativeTelemetry { .. }
        ));
    }
    for key in [
        "messagenumber",
        "messagetotal",
        "scriptblockid",
        "scriptblocktext",
        "path",
    ] {
        let mut p = origin(POWERSHELL_CORE, "1", "1");
        p.fields.insert(key.into(), "conflicting".into());
        assert!(matches!(
            decode(p, 4242).data,
            EventData::NativeTelemetry { .. }
        ));
    }
    for pid in [0, u32::MAX] {
        assert!(matches!(
            decode(origin(POWERSHELL_CORE, "1", "1"), pid).data,
            EventData::NativeTelemetry { .. }
        ));
    }
}

#[test]
fn powershell_provider_guid_and_event_id_are_authoritative() {
    let mut p = origin(POWERSHELL_CORE, "1", "1");
    p.provider_guid = "00000000-0000-0000-0000-000000000001".into();
    assert!(matches!(
        decode(p, 4242).data,
        EventData::NativeTelemetry { .. }
    ));
    let mut p = origin(POWERSHELL_CORE, "1", "1");
    p.event_id = 4105;
    assert!(!is_powershell_script(&decode(p, 4242)));
}

#[test]
fn powershell_opaque_logged_content_is_not_decrypted_or_rewritten() {
    for text in [
        "",
        "-----BEGIN CMS-----\nSYNTHETIC-NOT-REAL-CIPHERTEXT\n-----END CMS-----",
        "日本語 ␀ \r\n 'quoted'",
    ] {
        let mut p = origin(POWERSHELL_CORE, "1", "1");
        p.fields.insert("ScriptBlockText".into(), text.into());
        let event = decode(p, 4242);
        let EventData::ScriptBlock { content, .. } = &event.data else {
            panic!("not a script fragment");
        };
        assert_eq!(content, text);
        assert_eq!(event.provenance.unwrap().fields["ScriptBlockText"], text);
    }
}

#[test]
fn powershell_legacy_and_invalid_json_positions_remain_unknown() {
    let mut value = serde_json::to_value(fixture(POWERSHELL_CORE, "1", "1")).unwrap();
    value["data"]
        .as_object_mut()
        .unwrap()
        .remove("message_number");
    value["data"]
        .as_object_mut()
        .unwrap()
        .remove("message_total");
    let event: ThreatEvent = serde_json::from_value(value.clone()).unwrap();
    assert!(event.data.script_fragment_position().is_none());
    assert!(script_identity(&event).is_none());
    for (n, total) in [(0, 1), (2, 1), (1, u32::MAX)] {
        value["data"]["message_number"] = n.into();
        value["data"]["message_total"] = total.into();
        let event: ThreatEvent = serde_json::from_value(value.clone()).unwrap();
        assert!(event.data.script_fragment_position().is_none());
    }
}

#[test]
fn powershell_script_identity_requires_host_provider_pid_script_id_and_source_time() {
    let event = fixture(POWERSHELL_CORE, "1", "2");
    let key = script_identity(&event).unwrap();
    let mut other = event.clone();
    other.agent_id = uuid::Uuid::from_u128(456);
    assert_ne!(script_identity(&other), Some(key.clone()));
    let other = fixture(POWERSHELL, "1", "2");
    assert_ne!(script_identity(&other), Some(key.clone()));
    let mut other = event.clone();
    other.provenance.as_mut().unwrap().original_time = false;
    assert!(script_identity(&other).is_none());
    let other = decode(origin(POWERSHELL_CORE, "1", "2"), 4343);
    assert_ne!(script_identity(&other), Some(key.clone()));
    let mut p = origin(POWERSHELL_CORE, "1", "2");
    p.fields
        .insert("ScriptBlockId".into(), uuid::Uuid::from_u128(3).to_string());
    assert_ne!(script_identity(&decode(p, 4242)), Some(key));
}

#[tokio::test]
async fn powershell_delivery_analysis_and_index_keep_fragments_without_pid_join() {
    use crate::{
        config::OutputConfig,
        detection::Detector,
        index::{EventIndex, IndexFilter},
        output::{FileSink, Sink},
        process_cache::ProcessCache,
    };
    let first = fixture(POWERSHELL_CORE, "2", "2");
    let second = fixture(POWERSHELL_CORE, "1", "2");
    let agent = AgentInfo {
        hostname: first.hostname.clone(),
        agent_id: first.agent_id,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let mut sink = FileSink::new(&OutputConfig {
        path: path.clone(),
        ..Default::default()
    })
    .unwrap();
    let mut cache = ProcessCache::new(100);
    let mut detector = Detector::default();
    let mut legacy = ThreatEvent::new(
        &agent,
        EventSource::Etw {
            provider: "synthetic-process".into(),
        },
        EventCategory::Process,
        Severity::Info,
        EventData::ProcessCreate {
            pid: 4242,
            ppid: 1,
            image_path: "UNRELATED-PROCESS".into(),
            command_line: "UNRELATED-COMMAND".into(),
            user: String::new(),
            integrity_level: String::new(),
            hashes: None,
            create_time: Some(1),
        },
    );
    cache.enrich(&mut legacy);
    for event in [first, second] {
        crate::sensor::deliver(event, &mut cache, &mut detector, &mut sink)
            .await
            .unwrap();
    }
    sink.flush().await.unwrap();
    let jsonl = std::fs::read_to_string(&path).unwrap();
    assert!(!jsonl.contains("UNRELATED"));
    let events: Vec<ThreatEvent> = jsonl
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].data.script_fragment_position(), Some((2, 2)));
    assert_eq!(events[1].data.script_fragment_position(), Some((1, 2)));
    assert!(events.iter().all(|event| event.process_context.is_none()));
    let report = crate::analysis::analyze(std::io::Cursor::new(jsonl)).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.analysis.eligible_events, 0);
    assert_eq!(report.agents[&agent.agent_id].script_multipart_events, 2);
    assert_eq!(report.agents[&agent.agent_id].powershell_4104_events, 2);
    assert!(report
        .limitations
        .contains(&"script_fragments_are_not_reassembled_or_deduplicated"));
    let index = EventIndex::open(&path).unwrap();
    assert_eq!(index.build(&path).unwrap().new_events, 2);
    assert_eq!(
        index
            .query_locations(&IndexFilter {
                pid: Some(4242),
                source_type: Some("PowerShellCore".into()),
                ..Default::default()
            })
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn powershell_invalid_metadata_affects_analysis_and_etw_health_quality() {
    let event = fixture(POWERSHELL_CORE, "0", "0");
    let mut json = serde_json::to_string(&event).unwrap();
    json.push('\n');
    let report = crate::analysis::analyze(std::io::Cursor::new(json)).unwrap();
    let coverage = &report.agents[&event.agent_id];
    assert_eq!(coverage.powershell_unparsed_events, 1);
    assert!(coverage.recorded_loss_or_degradation);
    let health = crate::collectors::health::RuntimeHealth::new("ETW");
    health.starting();
    health.running();
    health.decoded(
        matches!(event.data, EventData::NativeTelemetry { .. }),
        event
            .provenance
            .as_ref()
            .is_some_and(|p| !p.issues.is_empty()),
    );
    assert_eq!(health.snapshot(0).state, CollectorState::Degraded);
    assert_eq!(health.snapshot(0).decode_failures, 1);
}
