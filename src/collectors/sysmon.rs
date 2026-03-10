use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::info;

use crate::config::SysmonConfig;
use crate::events::ThreatEvent;

use super::Collector;

/// Reads Sysmon events from the Windows Event Log channel
/// `Microsoft-Windows-Sysmon/Operational` using push-based EvtSubscribe.
///
/// Supported Sysmon Event IDs:
///   1  - Process Create
///   3  - Network Connection
///   5  - Process Terminated
///   6  - Driver Loaded
///   7  - Image Loaded
///   8  - CreateRemoteThread
///  10  - ProcessAccess
///  11  - FileCreate
///  12  - Registry Object Create/Delete
///  13  - Registry Value Set
///  14  - Registry Key Rename
///  15  - FileCreateStreamHash (ADS)
///  17  - Pipe Created
///  18  - Pipe Connected
///  22  - DNS Query
///  23  - FileDelete (archived)
///  25  - Process Tampering
///  26  - FileDeleteDetected
pub struct SysmonCollector {
    config: SysmonConfig,
    hostname: String,
    #[cfg(target_os = "windows")]
    stop_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl SysmonCollector {
    pub fn new(config: SysmonConfig, hostname: String) -> Self {
        Self {
            config,
            hostname,
            #[cfg(target_os = "windows")]
            stop_flag: None,
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use windows::core::PCWSTR;
    use windows::Win32::System::EventLog::*;

    const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

    /// Use EvtSubscribe for push-based event delivery, avoiding the duplicate
    /// re-read problem of poll-based EvtQuery.
    pub fn start_subscription(
        hostname: String,
        tx: mpsc::Sender<ThreatEvent>,
    ) -> Result<Arc<AtomicBool>> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();

        tokio::task::spawn_blocking(move || {
            subscribe_events(&hostname, tx, stop_clone);
        });

        Ok(stop)
    }

    fn subscribe_events(
        hostname: &str,
        tx: mpsc::Sender<ThreatEvent>,
        stop: Arc<AtomicBool>,
    ) {
        let channel_wide: Vec<u16> = SYSMON_CHANNEL
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let query_wide: Vec<u16> = "*"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Use a Win32 event object so the callback can signal us.
        let signal = unsafe {
            windows::Win32::System::Threading::CreateEventW(
                None, true, false, None,
            )
        };
        let signal = match signal {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(error = %e, "CreateEventW failed");
                return;
            }
        };

        let ctx = Box::new(SubscribeContext {
            hostname: hostname.to_string(),
            tx,
        });
        let ctx_ptr = Box::into_raw(ctx);

        let sub = unsafe {
            EvtSubscribe(
                EVT_HANDLE::default(),      // local session
                signal,
                PCWSTR(channel_wide.as_ptr()),
                PCWSTR(query_wide.as_ptr()),
                EVT_HANDLE::default(),      // no bookmark — start from now
                Some(ctx_ptr as *const std::ffi::c_void),
                Some(subscription_callback),
                EvtSubscribeToFutureEvents.0,
            )
        };

        let sub_handle = match sub {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(error = %e, "EvtSubscribe failed (is Sysmon installed?)");
                unsafe { drop(Box::from_raw(ctx_ptr)); }
                return;
            }
        };

        // Wait until told to stop
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        unsafe {
            let _ = EvtClose(sub_handle);
            drop(Box::from_raw(ctx_ptr));
        }
    }

    struct SubscribeContext {
        hostname: String,
        tx: mpsc::Sender<ThreatEvent>,
    }

    unsafe extern "system" fn subscription_callback(
        action: EVT_SUBSCRIBE_NOTIFY_ACTION,
        usercontext: *const std::ffi::c_void,
        event: EVT_HANDLE,
    ) -> u32 {
        if action != EvtSubscribeActionDeliver {
            return 0;
        }

        let ctx = unsafe { &*(usercontext as *const SubscribeContext) };

        if let Some(te) = render_and_map(event, &ctx.hostname) {
            let _ = ctx.tx.try_send(te);
        }
        0
    }

    /// Render a Sysmon event to XML and map it to a ThreatEvent.
    fn render_and_map(
        evt: EVT_HANDLE,
        hostname: &str,
    ) -> Option<ThreatEvent> {
        let xml = render_event_xml(evt)?;
        let parsed = super::super::sysmon_parser::parse_sysmon_xml(&xml)?;
        super::super::sysmon_parser::map_to_threat_event(&parsed, hostname)
    }

    /// Render the event as XML via EvtRender.
    fn render_event_xml(evt: EVT_HANDLE) -> Option<String> {
        let mut buf_size = 0u32;
        let mut prop_count = 0u32;

        // First call to get required buffer size
        let _ = unsafe {
            EvtRender(
                EVT_HANDLE::default(),
                evt,
                EvtRenderEventXml.0,
                0,
                None,
                &mut buf_size,
                &mut prop_count,
            )
        };

        if buf_size == 0 {
            return None;
        }

        let mut buf = vec![0u16; (buf_size as usize) / 2 + 1];
        let result = unsafe {
            EvtRender(
                EVT_HANDLE::default(),
                evt,
                EvtRenderEventXml.0,
                buf_size,
                Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
                &mut buf_size,
                &mut prop_count,
            )
        };

        if result.is_err() {
            return None;
        }

        // Find null terminator
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..len]))
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {}

#[async_trait]
impl Collector for SysmonCollector {
    fn name(&self) -> &str {
        "Sysmon"
    }

    fn enabled(&self) -> bool {
        self.config.enabled
    }

    async fn start(&mut self, _tx: mpsc::Sender<ThreatEvent>) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let flag = platform::start_subscription(
                self.hostname.clone(),
                _tx,
            )?;
            self.stop_flag = Some(flag);
            info!("Sysmon collector started (push-based subscription)");
        }

        #[cfg(not(target_os = "windows"))]
        tracing::warn!("Sysmon collector is only available on Windows");

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        if let Some(flag) = self.stop_flag.take() {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        info!("Sysmon collector stopped");
        Ok(())
    }
}
