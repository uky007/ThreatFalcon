use super::*;

fn agent() -> AgentInfo {
    AgentInfo {
        hostname: "synthetic-host".into(),
        agent_id: uuid::Uuid::from_u128(1),
    }
}
// Independently authored synthetic event, not a captured endpoint or attack sample.
fn sample() -> String {
    format!(
        r#"<Event xmlns="{EVENT_NAMESPACE}"><System>
<Provider Name="{PROVIDER_NAME}" Guid="{{{PROVIDER_GUID}}}"/>
<EventID>5156</EventID><Version>1</Version><Level>0</Level><Task>12810</Task>
<Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords>
<TimeCreated SystemTime="2026-09-13T01:02:03.1234567Z"/><EventRecordID>9001</EventRecordID>
<Correlation/><Execution ProcessID="4" ThreadID="88"/><Channel>Security</Channel>
<Computer>synthetic-host</Computer><Security/></System><EventData>
<Data Name="ProcessID">4242</Data><Data Name="Application">\device\harddiskvolume3\test\日本語.exe</Data>
<Data Name="Direction">%%14592</Data><Data Name="SourceAddress">192.0.2.1</Data>
<Data Name="SourcePort">51000</Data><Data Name="DestAddress">198.51.100.2</Data>
<Data Name="DestPort">443</Data><Data Name="Protocol">6</Data>
<Data Name="FilterRTID">1234</Data><Data Name="LayerName">%%14610</Data><Data Name="LayerRTID">48</Data>
<Data Name="RemoteUserID">SECRET-USER</Data><Data Name="RemoteMachineID">SECRET-MACHINE</Data>
</EventData></Event>"#
    )
}
fn payload(event: &ThreatEvent) -> &WfpConnectionAudit {
    let EventData::WfpConnectionAudit { record } = &event.data else {
        panic!("not WFP audit")
    };
    record
}

#[test]
fn source_identity_time_and_native_field_semantics_are_preserved() {
    let event = parse(&sample(), &agent()).unwrap();
    assert!(matches!(
        event.source,
        EventSource::WindowsSecurity { event_id: 5156 }
    ));
    assert_eq!(event.severity, Severity::Info);
    assert_eq!(event.timestamp.timestamp_subsec_nanos(), 123_456_700);
    let p = event.provenance.as_ref().unwrap();
    assert_eq!(p.record_id, Some(9001));
    assert_eq!(p.opcode, 0);
    assert_eq!(p.fields["System.Execution.ProcessID"], "4");
    assert!(p.original_time && p.issues.is_empty());
    assert!(p.process_guid.is_none());
    let r = payload(&event);
    assert_eq!(r.pid, Some(4242));
    assert_eq!(r.source_port, Some(51000));
    assert_eq!(r.destination_port, Some(443));
    assert_eq!(r.protocol, Some(6));
    assert_eq!(r.direction_token.as_deref(), Some("%%14592"));
    assert_eq!(r.decision, WfpDecision::Permitted);
    assert_eq!(
        r.application.as_deref(),
        Some(r"\device\harddiskvolume3\test\日本語.exe")
    );
    assert!(event.process_context.is_none());
}

#[test]
fn blocked_v0_ipv6_and_explicit_hex_pid_are_supported_without_threat_verdict() {
    let xml = sample()
        .replace("<EventID>5156", "<EventID>5157")
        .replace("<Version>1", "<Version>0")
        .replace(">4242<", ">0x1092<")
        .replace("192.0.2.1", "2001:db8::1")
        .replace("198.51.100.2", "::1");
    let event = parse(&xml, &agent()).unwrap();
    assert_eq!(event.severity, Severity::Info);
    assert_eq!(payload(&event).decision, WfpDecision::Blocked);
    assert_eq!(payload(&event).pid, Some(4242));
    assert_eq!(
        payload(&event).source_address.as_deref(),
        Some("2001:db8::1")
    );
    assert_eq!(payload(&event).destination_address.as_deref(), Some("::1"));
}

#[test]
fn provider_template_versions_and_pid_spellings_preserve_actor_identity() {
    for (id, last_version) in [(5156, 2), (5157, 4)] {
        for version in 0..=last_version {
            let mut xml = sample()
                .replace("<EventID>5156", &format!("<EventID>{id}"))
                .replace("<Version>1", &format!("<Version>{version}"));
            let pid_name = if (id, version) == (5156, 1) {
                xml = xml.replace("Name=\"ProcessID\"", "Name=\"ProcessId\"");
                "ProcessId"
            } else {
                "ProcessID"
            };
            // Modern templates add profile/filter fields. Retain their names,
            // not their potentially private values, under the existing policy.
            xml = xml.replace(
                "</EventData>",
                concat!(
                    "<Data Name=\"InterfaceIndex\">6</Data>",
                    "<Data Name=\"FilterOrigin\">SECRET-FILTER</Data>",
                    "<Data Name=\"OriginalProfile\">%%14644</Data>",
                    "<Data Name=\"CurrentProfile\">%%14644</Data>",
                    "<Data Name=\"IsLoopback\">%%1826</Data>",
                    "<Data Name=\"HasRemoteDynamicKeywordAddress\">%%1826</Data>",
                    "</EventData>"
                ),
            );
            let event = parse(&xml, &agent()).unwrap();
            assert_eq!(payload(&event).pid, Some(4242), "{id} v{version}");
            assert_eq!(payload(&event).destination_port, Some(443));
            assert_eq!(
                payload(&event).decision,
                if id == 5156 {
                    WfpDecision::Permitted
                } else {
                    WfpDecision::Blocked
                }
            );
            let p = event.provenance.as_ref().unwrap();
            assert!(p.issues.is_empty(), "{id} v{version}: {:?}", p.issues);
            assert_eq!(p.fields[pid_name], "4242");
            assert_eq!(p.fields["System.Execution.ProcessID"], "4");
            assert!(!payload(&event)
                .omitted_fields
                .iter()
                .any(|name| name == pid_name));
            assert!(!serde_json::to_string(&event).unwrap().contains("SECRET"));
        }
    }
}

#[test]
fn ambiguous_pid_aliases_are_not_resolved_by_precedence() {
    for alternate in ["4242", "99", "invalid"] {
        let xml = sample().replace(
            "</EventData>",
            &format!("<Data Name=\"ProcessId\">{alternate}</Data></EventData>"),
        );
        let event = parse(&xml, &agent()).unwrap();
        assert!(payload(&event).pid.is_none());
        assert!(event
            .provenance
            .unwrap()
            .issues
            .contains(&"wfp_ambiguous_process_id".into()));
    }
}

#[test]
fn alternate_pid_spelling_keeps_numeric_validation_and_no_publisher_fallback() {
    for pid in ["-1", "4294967296", "invalid"] {
        let xml = sample()
            .replace("Name=\"ProcessID\"", "Name=\"ProcessId\"")
            .replace(">4242<", &format!(">{pid}<"));
        let event = parse(&xml, &agent()).unwrap();
        assert!(payload(&event).pid.is_none());
        assert!(!event.provenance.unwrap().issues.is_empty());
    }
    let xml = sample()
        .replace("Name=\"ProcessID\"", "Name=\"ProcessId\"")
        .replace(">4242<", ">0x1092<");
    assert_eq!(payload(&parse(&xml, &agent()).unwrap()).pid, Some(4242));
}

#[test]
fn invalid_numbers_never_become_zero_or_publisher_pid() {
    for invalid in [
        "",
        "-",
        "-1",
        "+1",
        "109a",
        "0x",
        "4294967296",
        "18446744073709551616",
    ] {
        let event = parse(
            &sample().replace(">4242<", &format!(">{invalid}<")),
            &agent(),
        )
        .unwrap();
        assert!(payload(&event).pid.is_none(), "{invalid}");
        assert!(!event.provenance.unwrap().issues.is_empty());
    }
    let event = parse(
        &sample().replace("<Data Name=\"ProcessID\">4242</Data>", ""),
        &agent(),
    )
    .unwrap();
    assert!(payload(&event).pid.is_none());
    let event = parse(&sample().replace(">4242<", ">0<"), &agent()).unwrap();
    assert_eq!(payload(&event).pid, Some(0)); // Only an explicit native zero.
    let event = parse(
        &sample().replace(">443<", ">65536<").replace(">6<", ">256<"),
        &agent(),
    )
    .unwrap();
    assert!(payload(&event).destination_port.is_none());
    assert!(payload(&event).protocol.is_none());
}

#[test]
fn missing_or_invalid_fields_are_explicit_and_unknown_direction_is_not_guessed() {
    let xml = sample()
        .replace("198.51.100.2", "not-an-ip")
        .replace("%%14592", "%%99999")
        .replace("<Data Name=\"SourcePort\">51000</Data>", "");
    let event = parse(&xml, &agent()).unwrap();
    assert!(payload(&event).destination_address.is_none());
    assert!(payload(&event).source_port.is_none());
    assert_eq!(payload(&event).direction_token.as_deref(), Some("%%99999"));
    assert_eq!(event.provenance.unwrap().fields["DestAddress"], "not-an-ip");
}

#[test]
fn future_version_preserves_allowlisted_evidence_without_guessing_typed_fields() {
    let event = parse(
        &sample()
            .replace("<Version>1", "<Version>9")
            .replace("<Opcode>0", "<Opcode>7"),
        &agent(),
    )
    .unwrap();
    assert!(payload(&event).pid.is_none());
    assert!(payload(&event).application.is_none());
    assert!(payload(&event).destination_port.is_none());
    assert_eq!(
        event.provenance.as_ref().unwrap().fields["ProcessID"],
        "4242"
    );
    assert_eq!(event.provenance.as_ref().unwrap().opcode, 7);
    assert_eq!(
        event.provenance.unwrap().issues,
        ["wfp_unsupported_event_version"]
    );
}

#[test]
fn version_support_is_specific_to_the_event_id() {
    for (id, version) in [(5156, 3), (5157, 5)] {
        let xml = sample()
            .replace("<EventID>5156", &format!("<EventID>{id}"))
            .replace("<Version>1", &format!("<Version>{version}"));
        let event = parse(&xml, &agent()).unwrap();
        assert!(payload(&event).pid.is_none());
        assert_eq!(
            event.provenance.unwrap().issues,
            ["wfp_unsupported_event_version"]
        );
    }
}

#[test]
fn omitted_field_values_are_not_serialized_even_when_unknown_or_entity_encoded() {
    let xml = sample().replace(
        "</EventData>",
        "<Data Name=\"FutureField\">SECRET&#45;EXTRA</Data></EventData>",
    );
    let event = parse(&xml, &agent()).unwrap();
    assert_eq!(
        payload(&event).omitted_fields,
        ["RemoteUserID", "RemoteMachineID", "FutureField"]
    );
    let json = serde_json::to_string(&event).unwrap();
    assert!(!json.contains("SECRET"));
    assert!(!event
        .provenance
        .unwrap()
        .fields
        .contains_key("RemoteUserID"));
}

#[test]
fn wrong_source_identity_time_and_system_numbers_are_rejected() {
    for xml in [
        sample().replace(PROVIDER_NAME, "Another-Provider"),
        sample().replace(PROVIDER_GUID, "00000000-0000-0000-0000-000000000000"),
        sample().replace("<Channel>Security", "<Channel>Application"),
        sample().replace("<EventID>5156", "<EventID>5158"),
        sample().replace("<Version>1</Version>", ""),
        sample().replace("<Version>1", "<Version>+1"),
        sample().replace("<EventRecordID>9001", "<EventRecordID>0"),
        sample().replace("2026-09-13T01:02:03.1234567Z", "not-a-time"),
        sample().replace("<Computer>synthetic-host</Computer>", "<Computer/>"),
    ] {
        assert!(parse(&xml, &agent()).is_err());
    }
}

#[test]
fn ambiguous_xml_namespaces_duplicates_entities_and_oversize_are_rejected() {
    for xml in [
        sample().replace(EVENT_NAMESPACE, "urn:foreign"),
        sample().replace("<System>", "<System xmlns=\"urn:foreign\">"),
        sample()
            .replace("<EventData>", "<Wrapper><EventData>")
            .replace("</EventData>", "</EventData></Wrapper>"),
        sample().replace("</System>", "<EventID>5157</EventID></System>"),
        sample().replace(
            "</EventData>",
            "<Data Name=\"ProcessID\">99</Data></EventData>",
        ),
        sample().replace(
            "</EventData>",
            "<Data Name=\"RemoteUserID\">OTHER</Data></EventData>",
        ),
        sample().replace("</EventData>", "</EventData><EventData/>"),
        sample().replace(">4242<", "><Nested/>4242<"),
        sample().replace(">4242<", ">&unknown;<"),
        sample().replace(">4242<", ">&#0;<"),
        sample().replace(">4242<", ">&#65535;<"),
        sample().replace("ProcessID=\"4\"", "ProcessID=\"&#0;\""),
        format!("<!DOCTYPE Event [<!ENTITY test 'x'>]>{}", sample()),
        format!("<?instruction x?>{}", sample()),
        format!("{}{}", sample(), sample()),
        sample().replace("</Event>", ""),
        sample().replace("%%14592", &"x".repeat(MAX_VALUE_BYTES + 1)),
        "x".repeat(MAX_XML_BYTES + 1),
    ] {
        assert!(parse(&xml, &agent()).is_err());
    }
}

#[test]
fn xml_entities_are_decoded_once_and_cdata_is_bounded() {
    let event = parse(
        &sample().replace("%%14592", "&amp;lt;1&#50;&#x33;"),
        &agent(),
    )
    .unwrap();
    assert_eq!(payload(&event).direction_token.as_deref(), Some("&lt;123"));
    let event = parse(
        &sample().replace("%%14592", "<![CDATA[%%14592]]>"),
        &agent(),
    )
    .unwrap();
    assert_eq!(payload(&event).direction_token.as_deref(), Some("%%14592"));
}

#[tokio::test]
async fn delivery_analysis_and_index_preserve_evidence_without_pid_join() {
    use crate::{
        config::OutputConfig,
        detection::Detector,
        index::{EventIndex, IndexFilter},
        output::{FileSink, Sink},
        process_cache::ProcessCache,
    };
    let agent = agent();
    let event = parse(&sample(), &agent).unwrap();
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
            provider: "synthetic".into(),
        },
        EventCategory::Process,
        Severity::Info,
        EventData::ProcessCreate {
            pid: 4242,
            ppid: 1,
            image_path: "WRONG-PROCESS".into(),
            command_line: "WRONG-COMMAND".into(),
            user: String::new(),
            integrity_level: String::new(),
            hashes: None,
            create_time: Some(1),
        },
    );
    cache.enrich(&mut legacy);
    crate::sensor::deliver(event, &mut cache, &mut detector, &mut sink)
        .await
        .unwrap();
    sink.flush().await.unwrap();
    let jsonl = std::fs::read_to_string(&path).unwrap();
    for secret in ["SECRET", "WRONG-PROCESS", "WRONG-COMMAND"] {
        assert!(!jsonl.contains(secret));
    }
    let event: ThreatEvent = serde_json::from_str(jsonl.trim()).unwrap();
    assert!(event.process_context.is_none());
    assert_eq!(event.data.acting_pid(), Some(4242));
    assert_eq!(payload(&event).decision, WfpDecision::Permitted);
    let report = crate::analysis::analyze(std::io::Cursor::new(jsonl)).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.analysis.eligible_events, 0);
    let coverage = &report.agents[&agent.agent_id];
    assert_eq!(coverage.windows_security_event_ids[&5156], 1);
    assert_eq!(coverage.source_time_events, 1);
    assert_eq!(coverage.stable_process_guid_events, 0);
    assert!(coverage.wfp_audit_coverage_unknown);
    assert!(report
        .limitations
        .contains(&"wfp_audit_detection_rules_not_implemented"));
    let index = EventIndex::open(&path).unwrap();
    assert_eq!(index.build(&path).unwrap().new_events, 1);
    for (pid, count) in [(4242, 1), (4, 0)] {
        assert_eq!(
            index
                .query_locations(&IndexFilter {
                    pid: Some(pid),
                    source_type: Some("windowssecurity".into()),
                    ..Default::default()
                })
                .unwrap()
                .len(),
            count
        );
    }
}
