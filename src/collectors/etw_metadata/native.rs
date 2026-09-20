//! Reads only ETW-owned buffers, during their event callback lifetime.
use super::*;
use windows::Win32::System::Diagnostics::Etw::*;

pub fn parameters(options: CaptureOptions) -> ENABLE_TRACE_PARAMETERS {
    ENABLE_TRACE_PARAMETERS {
        Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
        EnableProperty: if options.process_start_key {
            EVENT_ENABLE_PROPERTY_PROCESS_START_KEY
        } else {
            0
        } | if options.event_key {
            EVENT_ENABLE_PROPERTY_EVENT_KEY
        } else {
            0
        } | if options.stack_trace {
            EVENT_ENABLE_PROPERTY_STACK_TRACE
        } else {
            0
        },
        ..Default::default()
    }
}

/// Safety: `record` and all non-null ETW-owned pointers must be valid for this
/// callback. Size checks cannot establish the validity of arbitrary pointers.
pub unsafe fn capture(
    record: &EVENT_RECORD,
    capture_id: Uuid,
    options: CaptureOptions,
) -> ExtendedMetadata {
    let mut builder = Builder::new(
        capture_id,
        record.EventHeader.ProcessId,
        record.EventHeader.ThreadId,
        options,
    );
    let count = record.ExtendedDataCount as usize;
    if count > MAX_ITEMS {
        builder.issue("extended_item_count_limit");
        return builder.finish();
    }
    if count > 0 && record.ExtendedData.is_null() {
        builder.issue("extended_null_table");
        return builder.finish();
    }
    for i in 0..count {
        let item = unsafe { record.ExtendedData.add(i).read_unaligned() };
        // Do not even dereference extensions outside the explicit allowlist.
        let bytes = if !builder.wanted(item.ExtType)
            || item.DataSize == 0
            || item.DataSize as usize > MAX_ITEM_BYTES
            || item.DataPtr == 0
            || usize::try_from(item.DataPtr).is_err()
        {
            None
        } else {
            Some(unsafe {
                std::slice::from_raw_parts(item.DataPtr as *const u8, item.DataSize as usize)
            })
        };
        builder.push(item.ExtType, bytes);
    }
    builder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_constants_and_enable_parameters_match_sdk() {
        assert_eq!(STACK32 as u32, EVENT_HEADER_EXT_TYPE_STACK_TRACE32);
        assert_eq!(STACK64 as u32, EVENT_HEADER_EXT_TYPE_STACK_TRACE64);
        assert_eq!(EVENT_KEY as u32, EVENT_HEADER_EXT_TYPE_EVENT_KEY);
        assert_eq!(
            PROCESS_START_KEY as u32,
            EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY
        );
        let p = parameters(CaptureOptions {
            process_start_key: true,
            event_key: true,
            stack_trace: true,
        });
        assert_eq!(p.EnableProperty, 0x184);
        assert_eq!(p.Version, 2);
        assert!(p.EnableFilterDesc.is_null());
        assert_eq!(parameters(CaptureOptions::default()).EnableProperty, 0);
    }

    #[test]
    fn native_buffers_are_copied_and_unknown_pointers_never_read() {
        let bytes = 123u64.to_le_bytes();
        let items = [
            EVENT_HEADER_EXTENDED_DATA_ITEM {
                ExtType: PROCESS_START_KEY,
                DataSize: 8,
                DataPtr: bytes.as_ptr() as u64,
                ..Default::default()
            },
            EVENT_HEADER_EXTENDED_DATA_ITEM {
                ExtType: 2,
                DataSize: 200,
                DataPtr: 1,
                ..Default::default()
            },
        ];
        let mut record = EVENT_RECORD::default();
        record.ExtendedDataCount = 2;
        record.ExtendedData = items.as_ptr() as *mut _;
        let options = CaptureOptions {
            process_start_key: true,
            ..Default::default()
        };
        let metadata = unsafe { capture(&record, Uuid::new_v4(), options) };
        assert_eq!(metadata.process_start_key, Some(123));
        assert_eq!(metadata.omitted_types, vec![2]);
        assert!(metadata.issues.is_empty());
        record.ExtendedData = std::ptr::null_mut();
        assert!(unsafe { capture(&record, Uuid::new_v4(), options) }
            .issues
            .iter()
            .any(|s| s == "extended_null_table"));
        record.ExtendedDataCount = u16::MAX;
        assert!(unsafe { capture(&record, Uuid::new_v4(), options) }
            .issues
            .iter()
            .any(|s| s == "extended_item_count_limit"));
    }

    /// A private benign publisher, not malware or a protected provider. Must be
    /// explicitly opted into on an authorized Windows VM; never changes policy.
    #[tokio::test]
    #[ignore = "requires authorized Windows VM and TF_WINDOWS_EXTENDED_TEST=1"]
    async fn windows_extended_etw_owned_publisher_smoke() {
        use crate::collectors::{etw::EtwCollector, Collector};
        use crate::config::{EtwConfig, EtwProviderConfig};
        use crate::events::AgentInfo;
        use windows::core::GUID;
        assert_eq!(
            std::env::var("TF_WINDOWS_EXTENDED_TEST").as_deref(),
            Ok("1")
        );
        let guid = GUID::from_u128(0x86228bf3_6b1e_4aac_9b80_579726343ba1);
        struct Registration(u64);
        impl Drop for Registration {
            fn drop(&mut self) {
                unsafe {
                    EventUnregister(REGHANDLE(self.0 as i64));
                }
            }
        }
        let mut raw = 0;
        assert_eq!(unsafe { EventRegister(&guid, None, None, &mut raw) }, 0);
        let registration = Registration(raw);
        let options = CaptureOptions {
            process_start_key: true,
            event_key: true,
            stack_trace: true,
        };
        let mut collector = EtwCollector::new(
            EtwConfig {
                enabled: true,
                providers: vec![EtwProviderConfig {
                    name: "ThreatFalcon-Owned-Validation".into(),
                    guid: "86228bf3-6b1e-4aac-9b80-579726343ba1".into(),
                    level: 5,
                    keywords: u64::MAX,
                    extended: options,
                }],
            },
            AgentInfo {
                hostname: "CONTROLLED-ETW-TEST".into(),
                agent_id: Uuid::new_v4(),
            },
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        collector
            .start(tx)
            .await
            .expect("owned ETW session must start");
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut timer = tokio::time::interval(std::time::Duration::from_millis(100));
            loop {
                tokio::select! {
                    _ = timer.tick() => {
                        let descriptor = EVENT_DESCRIPTOR { Id: 1, Level: 4, Keyword: 1, ..Default::default() };
                        anyhow::ensure!(unsafe { EventWrite(REGHANDLE(registration.0 as i64), &descriptor, None) } == 0, "owned publisher write failed");
                    }
                    event = rx.recv() => {
                        let event = event.ok_or_else(|| anyhow::anyhow!("collector channel closed"))?;
                        if event.provenance.as_ref().is_some_and(|p| p.provider_guid == "86228bf3-6b1e-4aac-9b80-579726343ba1") {
                            return Ok::<_, anyhow::Error>(event);
                        }
                    }
                }
            }
        }).await;
        let stopped = collector.stop().await;
        stopped.expect("owned ETW session must stop cleanly");
        let event = result
            .expect("no owned event within timeout")
            .expect("owned event must arrive");
        let metadata = event
            .provenance
            .as_ref()
            .unwrap()
            .etw_extended
            .as_ref()
            .unwrap();
        assert_eq!(metadata.header_pid, std::process::id());
        assert!(publisher_identity(&event).is_some());
        assert!(metadata.event_key.is_some());
        assert!(
            !metadata.stacks.is_empty(),
            "stack absence is not a successful capability test"
        );
        assert!(metadata.issues.is_empty());
        let status = collector.status().unwrap();
        let counters = status.providers[0].telemetry.as_ref().unwrap();
        assert!(counters.observed > 0 && counters.queue_admitted > 0);
        // This smoke test proves only our own EventWrite path on the tested OS.
    }
}
