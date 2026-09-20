use super::*;
use crate::collectors::etw_normalize::{
    powershell_tests::fixture, script_identity, POWERSHELL_CORE,
};

fn all() -> CaptureOptions {
    CaptureOptions {
        process_start_key: true,
        event_key: true,
        stack_trace: true,
    }
}
fn builder() -> Builder {
    Builder::new(Uuid::from_u128(123), 4242, 777, all())
}
fn stack(width: usize, frames: usize) -> Vec<u8> {
    let mut bytes = 99u64.to_le_bytes().to_vec();
    for i in 0..frames {
        bytes.extend_from_slice(&(0x1122334455667700u64 + i as u64).to_le_bytes()[..width]);
    }
    bytes
}
fn event() -> ThreatEvent {
    let mut e = fixture(POWERSHELL_CORE, "1", "1");
    let mut b = builder();
    b.push(PROCESS_START_KEY, Some(&123456u64.to_le_bytes()));
    b.push(EVENT_KEY, Some(&987654u64.to_le_bytes()));
    b.push(STACK64, Some(&stack(8, 3)));
    e.provenance.as_mut().unwrap().etw_extended = Some(b.finish());
    e
}

#[test]
fn exact_keys_and_native_stack_order_are_preserved() {
    let e = event();
    let m = e
        .provenance
        .as_ref()
        .unwrap()
        .etw_extended
        .as_ref()
        .unwrap();
    assert_eq!(m.process_start_key, Some(123456));
    assert_eq!(m.event_key, Some(987654));
    assert_eq!(m.header_tid, 777);
    assert!(m.issues.is_empty());
    assert_eq!(
        m.stacks[0].addresses,
        vec![0x1122334455667700, 0x1122334455667701, 0x1122334455667702]
    );
    assert_eq!(m.stacks[0].match_id, 99);
    assert_eq!(m.stacks[0].pointer_width, 8);
    assert!(publisher_identity(&e).is_some());
}

#[test]
fn stack32_is_decoded_by_item_type_not_host_architecture() {
    let mut b = builder();
    b.push(STACK32, Some(&stack(4, 2)));
    let m = b.finish();
    assert_eq!(m.stacks[0].pointer_width, 4);
    assert_eq!(m.stacks[0].addresses, vec![0x55667700, 0x55667701]);
}

#[test]
fn missing_and_zero_keys_are_not_fabricated_identities() {
    let m = builder().finish();
    assert_eq!(m.process_start_key, None);
    assert_eq!(m.issues.len(), 3);
    let mut e = event();
    let mut b = builder();
    b.push(PROCESS_START_KEY, Some(&0u64.to_le_bytes()));
    e.provenance.as_mut().unwrap().etw_extended = Some(b.finish());
    assert_eq!(
        e.provenance
            .as_ref()
            .unwrap()
            .etw_extended
            .as_ref()
            .unwrap()
            .process_start_key,
        Some(0)
    );
    assert!(publisher_identity(&e).is_none());
}

#[test]
fn scalar_sizes_and_duplicates_fail_closed() {
    for kind in [PROCESS_START_KEY, EVENT_KEY] {
        for size in 0..20 {
            let mut b = builder();
            b.push(kind, Some(&vec![1u8; size]));
            let m = b.finish();
            let v = if kind == PROCESS_START_KEY {
                m.process_start_key
            } else {
                m.event_key
            };
            assert_eq!(v.is_some(), size == 8);
        }
        let mut b = builder();
        for _ in 0..3 {
            b.push(kind, Some(&123u64.to_le_bytes()));
        }
        let m = b.finish();
        assert_eq!(m.process_start_key, None);
        assert_eq!(m.event_key, None);
        assert!(m.issues.iter().any(|s| s.ends_with("_duplicate")));
    }
}

#[test]
fn stack_size_checks_reject_partial_headers_frames_and_oversize() {
    for kind in [STACK32, STACK64] {
        for size in [0, 1, 7, 8, 9, 11, MAX_ITEM_BYTES + 1] {
            let mut b = builder();
            b.push(kind, Some(&vec![0; size]));
            assert!(b.finish().stacks.is_empty(), "kind={kind} size={size}");
        }
        let mut b = builder();
        b.push(kind, None);
        assert!(b.finish().stacks.is_empty());
    }
}

#[test]
fn frame_limits_preserve_counts_and_do_not_claim_complete_stacks() {
    for width in [4, 8] {
        for count in [1, 128, 129, 192, 193] {
            let mut b = builder();
            b.push(
                if width == 4 { STACK32 } else { STACK64 },
                Some(&stack(width, count)),
            );
            let m = b.finish();
            if count == 193 {
                assert!(m.stacks.is_empty());
                continue;
            }
            let s = &m.stacks[0];
            assert_eq!(s.addresses.len(), count.min(MAX_FRAMES));
            assert_eq!(s.original_frame_count as usize, count);
            assert_eq!(s.locally_truncated, count > MAX_FRAMES);
            assert_eq!(s.capture_limit_reached, count == ETW_FRAME_LIMIT);
        }
    }
}

#[test]
fn stack_parts_are_not_merged_and_count_is_bounded() {
    let mut b = builder();
    for _ in 0..MAX_ITEMS {
        b.push(STACK64, Some(&stack(8, 2)));
    }
    let m = b.finish();
    assert_eq!(m.stacks.len(), MAX_STACKS);
    assert!(m.issues.iter().any(|s| s == "stack_count_limit"));
}

#[test]
fn unknown_and_unrequested_extension_values_are_never_retained() {
    let mut b = Builder::new(Uuid::new_v4(), 1, 2, CaptureOptions::default());
    for kind in [2, 2, PROCESS_START_KEY, EVENT_KEY, STACK64] {
        b.push(kind, Some(b"SENSITIVE-EXTENSION-VALUE"));
    }
    let m = b.finish();
    assert_eq!(
        m.omitted_types,
        vec![2, PROCESS_START_KEY, EVENT_KEY, STACK64]
    );
    assert!(m.issues.is_empty());
    assert!(m.stacks.is_empty());
    assert!(!serde_json::to_string(&m).unwrap().contains("SENSITIVE"));
}

#[test]
fn item_limit_invalidates_identity_without_unbounded_type_storage() {
    let mut b = builder();
    b.push(PROCESS_START_KEY, Some(&1u64.to_le_bytes()));
    for kind in 100..1000 {
        b.push(kind, None);
    }
    let mut e = event();
    let m = b.finish();
    assert!(m.omitted_types.len() < MAX_ITEMS);
    e.provenance.as_mut().unwrap().etw_extended = Some(m);
    assert!(publisher_identity(&e).is_none());
}

#[test]
fn publisher_identity_never_crosses_agent_capture_pid_or_start_key() {
    let e = event();
    let identity = publisher_identity(&e).unwrap();
    for which in 0..4 {
        let mut other = e.clone();
        let m = other
            .provenance
            .as_mut()
            .unwrap()
            .etw_extended
            .as_mut()
            .unwrap();
        match which {
            0 => other.agent_id = Uuid::new_v4(),
            1 => m.capture_id = Uuid::new_v4(),
            2 => m.header_pid += 1,
            _ => m.process_start_key = Some(5678),
        }
        assert_ne!(publisher_identity(&other).as_ref(), Some(&identity));
    }
}

#[test]
fn unknown_identity_fields_do_not_fall_back_to_pid_or_event_key() {
    for which in 0..8 {
        let mut e = event();
        let p = e.provenance.as_mut().unwrap();
        let m = p.etw_extended.as_mut().unwrap();
        match which {
            0 => e.agent_id = Uuid::nil(),
            1 => m.capture_id = Uuid::nil(),
            2 => m.header_pid = 0,
            3 => m.header_pid = u32::MAX,
            4 => m.process_start_key = None,
            5 => m.requested.process_start_key = false,
            6 => p.original_time = false,
            _ => e.source = EventSource::Sysmon { event_id: 1 },
        }
        assert!(publisher_identity(&e).is_none(), "case {which}");
    }
}

#[test]
fn stack_failure_does_not_erase_valid_payload_or_publisher_identity() {
    let mut e = event();
    let m = e
        .provenance
        .as_mut()
        .unwrap()
        .etw_extended
        .as_mut()
        .unwrap();
    m.stacks.clear();
    m.issues.push("stack_unavailable".into());
    assert!(publisher_identity(&e).is_some());
    assert!(matches!(
        e.data,
        crate::events::EventData::ScriptBlock { .. }
    ));
}

#[test]
fn native_script_groups_use_capture_and_publisher_key_and_never_mix_legacy() {
    let e = event();
    let key = script_identity(&e).unwrap();
    for which in 0..5 {
        let mut other = e.clone();
        let p = other.provenance.as_mut().unwrap();
        let m = p.etw_extended.as_mut().unwrap();
        match which {
            0 => m.capture_id = Uuid::new_v4(),
            1 => m.process_start_key = Some(999),
            2 => m.process_start_key = None,
            3 => m.header_pid = 999,
            _ => p.etw_extended = None,
        }
        assert_ne!(script_identity(&other).as_ref(), Some(&key));
    }
}

#[test]
fn process_cache_never_promotes_publisher_key_to_actor_context() {
    let mut e = event();
    e.data = crate::events::EventData::ProcessCreate {
        pid: 555,
        ppid: 444,
        image_path: "owned.exe".into(),
        command_line: String::new(),
        user: String::new(),
        integrity_level: String::new(),
        hashes: None,
        create_time: None,
    };
    e.process_context = Some(crate::events::ProcessContext {
        process_key: "untrusted-legacy-key".into(),
        image_path: None,
        command_line: None,
        user: None,
        integrity_level: None,
        ppid: None,
    });
    crate::process_cache::ProcessCache::new(10).enrich(&mut e);
    assert!(e.process_context.is_none());
    assert_eq!(publisher_identity(&e).unwrap().pid, 4242);
    assert!(matches!(
        e.data,
        crate::events::EventData::ProcessCreate { pid: 555, .. }
    ));
}

#[test]
fn mixed_capture_profile_cannot_keep_stale_legacy_lifecycle_metadata() {
    use crate::events::EventData;
    let mut native = event();
    native.data = EventData::ProcessCreate {
        pid: 555,
        ppid: 444,
        image_path: "owned.exe".into(),
        command_line: String::new(),
        user: String::new(),
        integrity_level: String::new(),
        hashes: None,
        create_time: Some(133_000_000_000_000_000),
    };
    native.provenance.as_mut().unwrap().provider_guid =
        crate::collectors::etw_normalize::PROCESS.into();
    native.provenance.as_mut().unwrap().event_id = 1;
    let mut legacy = native.clone();
    legacy.provenance.as_mut().unwrap().etw_extended = None;
    let mut cache = crate::process_cache::ProcessCache::new(10);
    cache.enrich(&mut legacy);
    assert!(legacy.process_context.is_some());
    cache.enrich(&mut native);
    assert!(native.process_context.is_none());
    let mut activity = legacy.clone();
    activity.process_context = None;
    activity.data = EventData::AmsiScan {
        pid: 555,
        app_name: "owned".into(),
        content_name: "test".into(),
        content_size: 0,
        scan_result: 0,
        scan_result_name: String::new(),
    };
    cache.enrich(&mut activity);
    assert!(activity.process_context.is_none());
}

#[test]
fn extended_metadata_roundtrips_and_old_events_stay_compatible() {
    let e = event();
    let restored: ThreatEvent = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
    assert_eq!(publisher_identity(&e), publisher_identity(&restored));
    let mut json = serde_json::to_value(e).unwrap();
    json["provenance"]
        .as_object_mut()
        .unwrap()
        .remove("etw_extended");
    let old: ThreatEvent = serde_json::from_value(json).unwrap();
    assert!(!has_extended_metadata(&old));
}

#[test]
fn health_counts_observed_and_queue_results_separately() {
    let health = crate::collectors::health::RuntimeHealth::new("ETW");
    health.starting();
    health.providers(vec![crate::events::ProviderStatus {
        name: "test".into(),
        guid: format!("{{{}}}", POWERSHELL_CORE.to_ascii_uppercase()),
        enabled: true,
        error_code: None,
        telemetry: Some(ProviderTelemetry {
            requested: all(),
            ..Default::default()
        }),
    }]);
    health.running();
    let mut e = event();
    health.etw_observed(&e);
    health.etw_queue_result(POWERSHELL_CORE, true);
    e.provenance
        .as_mut()
        .unwrap()
        .etw_extended
        .as_mut()
        .unwrap()
        .issues
        .push("stack_unavailable".into());
    health.etw_observed(&e);
    health.etw_queue_result(POWERSHELL_CORE, false);
    let s = health.snapshot(1);
    let t = s.providers[0].telemetry.as_ref().unwrap();
    assert_eq!(
        (t.observed, t.normalized, t.queue_admitted, t.queue_dropped),
        (2, 2, 1, 1)
    );
    assert_eq!(t.metadata_issue_events, 1);
    assert!(t.last_observed_at.is_some());
    assert_eq!(s.state, crate::events::CollectorState::Degraded);
    assert_eq!(s.events_observed, 2);
    // Extension failure is not a TDH payload decode failure.
    assert_eq!(s.decode_failures, 0);
}

#[test]
fn config_is_opt_in_bounded_and_rejects_ambiguous_capture_policies() {
    use crate::config::SensorConfig;
    let mut config = SensorConfig::default();
    assert!(config
        .collectors
        .etw
        .providers
        .iter()
        .all(|p| !p.extended.enabled()));
    config.collectors.etw.providers[0].extended = all();
    config.validate().unwrap();
    let mut duplicate = config.collectors.etw.providers[0].clone();
    duplicate.guid = format!("{{{}}}", duplicate.guid.to_ascii_lowercase());
    duplicate.extended = CaptureOptions::default();
    config.collectors.etw.providers.push(duplicate);
    assert!(config.validate().is_err());
    config.collectors.etw.providers = vec![config.collectors.etw.providers[0].clone(); 65];
    assert!(config.validate().is_err());
    assert!(
        toml::from_str::<CaptureOptions>("stack_trace = true\nread_process_memory = true").is_err()
    );
}

#[test]
fn context_profile_is_local_and_never_enables_restricted_ti_or_scanners() {
    let config: crate::config::SensorConfig =
        toml::from_str(include_str!("../../../configs/windows-etw-context.toml")).unwrap();
    config.validate().unwrap();
    assert_eq!(config.collectors.etw.providers.len(), 1);
    assert_eq!(config.collectors.etw.providers[0].extended, all());
    assert_eq!(config.output.sink_type, crate::config::SinkType::File);
    assert!(config.output.url.is_none());
    assert!(
        !config.collectors.sysmon.enabled
            && !config.collectors.wfp_audit.enabled
            && !config.collectors.evasion.enabled
            && !config.collectors.macos.enabled
            && !config.collectors.linux_audit.enabled
    );
}
