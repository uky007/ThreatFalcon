//! Built-in rule contracts. Observed input types are not verified endpoint coverage.
use crate::events::*;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub struct RuleSpec {
    pub id: &'static str,
    pub version: u16,
    pub title_en: &'static str,
    pub title_ja: &'static str,
    pub required_sysmon_event_ids: &'static [u16],
    pub supporting_sysmon_event_ids: &'static [u16],
    pub network_protocols: &'static [&'static str],
    pub false_positive_examples: &'static [&'static str],
    pub technique_id: &'static str,
}

pub const RULES: [RuleSpec; 3] = [
    RuleSpec {
        id: "TF-COR-001",
        version: 1,
        title_en: "Remote thread followed by target network activity",
        title_ja: "リモートスレッド生成後の対象プロセスの通信",
        required_sysmon_event_ids: &[8, 3],
        supporting_sysmon_event_ids: &[10],
        network_protocols: &["TCP", "UDP"],
        false_positive_examples: &["debuggers", "security_software"],
        technique_id: "T1055",
    },
    RuleSpec {
        id: "TF-COR-002",
        version: 1,
        title_en: "Office-spawned script host made a network connection",
        title_ja: "Officeが起動したスクリプト実行プロセスの通信",
        required_sysmon_event_ids: &[1, 3],
        supporting_sysmon_event_ids: &[],
        network_protocols: &["TCP", "UDP"],
        false_positive_examples: &["approved_office_automation"],
        technique_id: "T1059",
    },
    RuleSpec {
        id: "TF-COR-003",
        version: 1,
        title_en: "Periodic outbound TCP connections",
        title_ja: "周期的な外向きTCP接続",
        required_sysmon_event_ids: &[3],
        supporting_sysmon_event_ids: &[],
        network_protocols: &["TCP"],
        false_positive_examples: &["scheduled_updates", "monitoring_agents"],
        technique_id: "T1071",
    },
];

/// Shared provenance gate with the detector; no trust is derived from a PID,
/// ETW publisher, envelope arrival time or the mere presence of an EventID.
pub fn sysmon_provenance(event: &ThreatEvent) -> Option<&EventProvenance> {
    let p = event.provenance.as_ref()?;
    (event.schema_version >= 2
        && p.original_time
        && p.issues.is_empty()
        && p.provider_guid
            .eq_ignore_ascii_case("5770385f-c22a-43e0-bf4c-06f5698ffbd9")
        && matches!(event.source, EventSource::Sysmon { event_id } if event_id == p.event_id)
        && p.process_guid.is_some_and(|g| !g.is_nil()))
    .then_some(p)
}

/// Count usable input *types*, not rule matches, independent samples, or all
/// generated events. Predicate/timing/agent/process correlation is still required.
pub fn input_event_id(event: &ThreatEvent) -> Option<u16> {
    let p = sysmon_provenance(event)?;
    if event.agent_id.is_nil() {
        return None;
    }
    let actor = p.process_guid?;
    let valid = match (&event.data, p.event_id) {
        (EventData::ProcessCreate { image_path, .. }, 1) => {
            !image_path.is_empty()
                && p.parent_process_guid
                    .is_some_and(|g| !g.is_nil() && g != actor)
                && p.fields.get("ParentImage").is_some_and(|s| !s.is_empty())
        }
        (EventData::CreateRemoteThread { .. }, 8) | (EventData::ProcessAccess { .. }, 10) => p
            .target_process_guid
            .is_some_and(|g| !g.is_nil() && g != actor),
        (
            EventData::NetworkConnect {
                dst_addr,
                dst_port,
                protocol,
                direction: NetworkDirection::Outbound,
                ..
            },
            3,
        ) => {
            dst_addr
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
                && *dst_port > 0
                && (protocol.eq_ignore_ascii_case("tcp") || protocol.eq_ignore_ascii_case("udp"))
        }
        _ => false,
    };
    valid.then_some(p.event_id)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputState {
    RequiredTypesObserved,
    InsufficientEvidence,
}

#[derive(Debug, Serialize)]
pub struct RuleInputAssessment {
    pub rule: &'static RuleSpec,
    pub state: InputState,
    pub unobserved_required_event_ids: Vec<u16>,
    pub observed_input_counts: BTreeMap<u16, u64>,
    pub coverage_verified: bool,
}

pub fn assess(counts: &BTreeMap<u16, u64>, tcp_connections: u64) -> Vec<RuleInputAssessment> {
    RULES
        .iter()
        .map(|rule| {
            let count = |id: &u16| {
                if *id == 3 && rule.network_protocols == ["TCP"] {
                    tcp_connections
                } else {
                    counts.get(id).copied().unwrap_or(0)
                }
            };
            let unobserved: Vec<_> = rule
                .required_sysmon_event_ids
                .iter()
                .copied()
                .filter(|id| count(id) == 0)
                .collect();
            RuleInputAssessment {
                rule,
                state: if unobserved.is_empty() {
                    InputState::RequiredTypesObserved
                } else {
                    InputState::InsufficientEvidence
                },
                unobserved_required_event_ids: unobserved,
                observed_input_counts: rule
                    .required_sysmon_event_ids
                    .iter()
                    .chain(rule.supporting_sysmon_event_ids)
                    .map(|id| (*id, count(id)))
                    .collect(),
                coverage_verified: false,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{sysmon, ACTOR, TARGET};

    #[test]
    fn no_input_is_not_ready_and_supporting_access_is_not_required() {
        assert!(assess(&BTreeMap::new(), 0)
            .iter()
            .all(|r| matches!(r.state, InputState::InsufficientEvidence) && !r.coverage_verified));
        let reports = assess(&BTreeMap::from([(3, 1), (8, 1)]), 1);
        assert!(matches!(
            reports[0].state,
            InputState::RequiredTypesObserved
        ));
        assert_eq!(reports[0].observed_input_counts[&10], 0);
        assert_eq!(reports[1].unobserved_required_event_ids, [1]);
        assert!(reports.iter().all(|r| !r.coverage_verified));
    }

    #[test]
    fn unusable_or_mismatched_source_evidence_is_not_counted() {
        for mutation in 0..10 {
            let mut event = sysmon(8, 0, ACTOR);
            assert_eq!(input_event_id(&event), Some(8));
            let p = event.provenance.as_mut().unwrap();
            match mutation {
                0 => event.schema_version = 1,
                1 => p.original_time = false,
                2 => p.issues.push("missing_field".into()),
                3 => p.process_guid = Some(uuid::Uuid::nil()),
                4 => p.target_process_guid = p.process_guid,
                5 => p.event_id = 3,
                6 => p.provider_guid = "unknown".into(),
                7 => event.source = EventSource::Sensor,
                8 => event.agent_id = uuid::Uuid::nil(),
                _ => p.target_process_guid = None,
            }
            assert_eq!(input_event_id(&event), None, "mutation {mutation}");
        }
    }

    #[test]
    fn benign_parent_counts_as_type_observed_but_udp_is_not_tcp() {
        let mut event = sysmon(1, 0, TARGET);
        event
            .provenance
            .as_mut()
            .unwrap()
            .fields
            .insert("ParentImage".into(), "explorer.exe".into());
        assert_eq!(input_event_id(&event), Some(1));
        event.provenance.as_mut().unwrap().parent_process_guid = None;
        assert_eq!(input_event_id(&event), None);
        let mut event = sysmon(3, 1, TARGET);
        if let EventData::NetworkConnect { protocol, .. } = &mut event.data {
            *protocol = "UDP".into();
        }
        assert_eq!(input_event_id(&event), Some(3));
        let reports = assess(&BTreeMap::from([(1, 1), (3, 1), (8, 1)]), 0);
        assert!(matches!(
            reports[0].state,
            InputState::RequiredTypesObserved
        ));
        assert!(matches!(
            reports[1].state,
            InputState::RequiredTypesObserved
        ));
        assert_eq!(reports[2].unobserved_required_event_ids, [3]);
    }

    #[test]
    fn inward_or_invalid_connections_do_not_supply_outbound_input() {
        for mutation in 0..5 {
            let mut event = sysmon(3, 0, TARGET);
            if let EventData::NetworkConnect {
                dst_addr,
                dst_port,
                direction,
                protocol,
                ..
            } = &mut event.data
            {
                match mutation {
                    0 => *dst_addr = "127.0.0.1".into(),
                    1 => *dst_addr = "not-an-address".into(),
                    2 => *dst_port = 0,
                    3 => *direction = NetworkDirection::Inbound,
                    _ => *protocol = "unknown".into(),
                }
            }
            assert_eq!(input_event_id(&event), None);
        }
    }
}
