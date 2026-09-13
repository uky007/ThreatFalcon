use anyhow::Result;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

use crate::config::EtwConfig;
use crate::events::{AgentInfo, CollectorStatus, ThreatEvent};

use super::health::RuntimeHealth;
use super::Collector;

pub struct EtwCollector {
    config: EtwConfig,
    #[allow(dead_code)] // used on Windows only
    agent: AgentInfo,
    dropped: Arc<AtomicU64>,
    health: RuntimeHealth,
    #[cfg(target_os = "windows")]
    session: Option<platform::Session>,
}

impl EtwCollector {
    pub fn new(config: EtwConfig, agent: AgentInfo) -> Self {
        Self {
            config,
            agent,
            dropped: Arc::new(AtomicU64::new(0)),
            health: RuntimeHealth::new("ETW"),
            #[cfg(target_os = "windows")]
            session: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-platform ETW data parsing utilities
// ---------------------------------------------------------------------------
// Used by platform module on Windows and by tests on all platforms.
#[allow(dead_code)]
pub(crate) mod parser {
    /// Cursor-based binary reader for ETW EVENT_RECORD.UserData payloads.
    pub struct UserDataReader<'a> {
        data: &'a [u8],
        pos: usize,
        pointer_size: usize,
    }

    impl<'a> UserDataReader<'a> {
        pub fn new(data: &'a [u8], pointer_size: usize) -> Self {
            Self {
                data,
                pos: 0,
                pointer_size,
            }
        }

        pub fn read_u8(&mut self) -> Option<u8> {
            if self.pos >= self.data.len() {
                return None;
            }
            let v = self.data[self.pos];
            self.pos += 1;
            Some(v)
        }

        pub fn read_u16(&mut self) -> Option<u16> {
            if self.pos + 2 > self.data.len() {
                return None;
            }
            let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
            self.pos += 2;
            Some(v)
        }

        pub fn read_u16_be(&mut self) -> Option<u16> {
            if self.pos + 2 > self.data.len() {
                return None;
            }
            let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
            self.pos += 2;
            Some(v)
        }

        pub fn read_u32(&mut self) -> Option<u32> {
            if self.pos + 4 > self.data.len() {
                return None;
            }
            let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().ok()?);
            self.pos += 4;
            Some(v)
        }

        pub fn read_u64(&mut self) -> Option<u64> {
            if self.pos + 8 > self.data.len() {
                return None;
            }
            let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().ok()?);
            self.pos += 8;
            Some(v)
        }

        pub fn read_pointer(&mut self) -> Option<u64> {
            match self.pointer_size {
                4 => self.read_u32().map(|v| v as u64),
                _ => self.read_u64(),
            }
        }

        pub fn read_ipv4(&mut self) -> Option<String> {
            if self.pos + 4 > self.data.len() {
                return None;
            }
            let b = &self.data[self.pos..self.pos + 4];
            self.pos += 4;
            Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
        }

        pub fn read_ipv6(&mut self) -> Option<String> {
            if self.pos + 16 > self.data.len() {
                return None;
            }
            let b = &self.data[self.pos..self.pos + 16];
            self.pos += 16;
            let addr = std::net::Ipv6Addr::from([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
                b[13], b[14], b[15],
            ]);
            Some(addr.to_string())
        }

        /// Read a null-terminated UTF-16LE string (win:UnicodeString in ETW).
        pub fn read_utf16_nul(&mut self) -> String {
            let start = self.pos;
            while self.pos + 2 <= self.data.len() {
                let c = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
                self.pos += 2;
                if c == 0 {
                    return self.decode_utf16(start, self.pos - 2);
                }
            }
            // No terminator — consume remaining bytes
            let end = self.pos;
            self.decode_utf16(start, end)
        }

        fn decode_utf16(&self, start: usize, end: usize) -> String {
            let wide: Vec<u16> = self.data[start..end]
                .chunks_exact(2)
                .map(|ch| u16::from_le_bytes([ch[0], ch[1]]))
                .collect();
            String::from_utf16_lossy(&wide)
        }

        pub fn position(&self) -> usize {
            self.pos
        }

        pub fn remaining(&self) -> usize {
            self.data.len().saturating_sub(self.pos)
        }

        /// Read exactly `n` bytes as UTF-16LE, decode, and strip trailing NULs.
        pub fn read_utf16_bytes(&mut self, n: usize) -> String {
            let end = (self.pos + n).min(self.data.len());
            let result = self.decode_utf16(self.pos, end);
            self.pos = end;
            result.trim_end_matches('\0').to_string()
        }

        #[allow(dead_code)]
        pub fn skip(&mut self, n: usize) {
            self.pos = (self.pos + n).min(self.data.len());
        }
    }

    pub fn dns_query_type_name(qtype: u16) -> String {
        match qtype {
            1 => "A".into(),
            2 => "NS".into(),
            5 => "CNAME".into(),
            6 => "SOA".into(),
            12 => "PTR".into(),
            15 => "MX".into(),
            16 => "TXT".into(),
            28 => "AAAA".into(),
            33 => "SRV".into(),
            255 => "ANY".into(),
            _ => format!("TYPE{qtype}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Windows implementation: real-time ETW trace session
// ---------------------------------------------------------------------------
#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use crate::events::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use windows::core::GUID;
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Diagnostics::Etw::*;

    use windows::Win32::System::Threading::CreateMutexW;

    const SESSION_NAME: &str = "ThreatFalcon-ETW";
    const INSTANCE_MUTEX_NAME: &str = "Global\\ThreatFalcon-ETW";

    /// Acquire a system-wide named mutex to prevent multiple instances.
    ///
    /// The mutex is automatically released by the OS when the owning process
    /// exits (including crashes), which avoids both stale-lock and PID-reuse
    /// problems inherent in PID lock files.
    ///
    /// Returns the raw HANDLE on success.  The caller must keep it alive for
    /// the lifetime of the ETW session.
    fn acquire_instance_lock() -> Result<isize> {
        let wide: Vec<u16> = INSTANCE_MUTEX_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateMutexW(
                None,
                true, // bInitialOwner
                windows::core::PCWSTR(wide.as_ptr()),
            )
        };

        match handle {
            Ok(h) => {
                // CreateMutexW succeeds even when the mutex already exists
                // (it opens it).  Distinguish via GetLastError.
                let last_err = unsafe { GetLastError() };
                if last_err == WIN32_ERROR(183) {
                    // ERROR_ALREADY_EXISTS — another instance holds the mutex
                    unsafe {
                        let _ = CloseHandle(h);
                    }
                    anyhow::bail!("Another ThreatFalcon instance is already running");
                }
                Ok(h.0 as isize)
            }
            Err(e) => {
                anyhow::bail!("Failed to create instance mutex: {e}");
            }
        }
    }

    fn release_instance_lock(handle: isize) {
        if handle != 0 {
            unsafe {
                let _ = CloseHandle(HANDLE(handle as *mut std::ffi::c_void));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Existing session management (unchanged)
    // -----------------------------------------------------------------------

    fn parse_guid(s: &str) -> Result<GUID> {
        let s = s.trim_matches(|c| c == '{' || c == '}');
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5
            || !parts
                .iter()
                .zip([8, 4, 4, 4, 12])
                .all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            anyhow::bail!("Invalid GUID format: {}", s);
        }
        let d1 = u32::from_str_radix(parts[0], 16)?;
        let d2 = u16::from_str_radix(parts[1], 16)?;
        let d3 = u16::from_str_radix(parts[2], 16)?;
        let d4_hex = format!("{}{}", parts[3], parts[4]);
        let mut d4 = [0u8; 8];
        for (i, byte) in d4.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&d4_hex[i * 2..i * 2 + 2], 16)?;
        }
        Ok(GUID {
            data1: d1,
            data2: d2,
            data3: d3,
            data4: d4,
        })
    }

    struct CallbackContext {
        agent: crate::events::AgentInfo,
        tx: mpsc::Sender<ThreatEvent>,
        dropped: Arc<AtomicU64>,
        decoder: std::sync::Mutex<super::super::tdh::Decoder>,
        health: RuntimeHealth,
    }

    // The C header requires an aligned properties structure followed by room
    // for both names. Vec<u8> does not guarantee the required alignment.
    #[repr(C)]
    struct TraceProperties {
        props: EVENT_TRACE_PROPERTIES,
        logger_name: [u16; 1024],
        file_name: [u16; 1024],
    }

    impl TraceProperties {
        fn new() -> Self {
            let mut buffer = Self {
                props: EVENT_TRACE_PROPERTIES::default(),
                logger_name: [0; 1024],
                file_name: [0; 1024],
            };
            buffer.props.Wnode.BufferSize = std::mem::size_of::<Self>() as u32;
            buffer.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            buffer.props.LoggerNameOffset = std::mem::offset_of!(Self, logger_name) as u32;
            buffer.props.LogFileNameOffset = std::mem::offset_of!(Self, file_name) as u32;
            buffer
        }

        fn stats(&self) -> crate::events::EtwSessionStats {
            crate::events::EtwSessionStats {
                events_lost: self.props.EventsLost as u64,
                log_buffers_lost: self.props.LogBuffersLost as u64,
                realtime_buffers_lost: self.props.RealTimeBuffersLost as u64,
                collected_at: chrono::Utc::now(),
            }
        }
    }

    pub struct Session {
        handle: CONTROLTRACE_HANDLE,
        instance_lock: isize,
        trace: Option<PROCESSTRACE_HANDLE>,
        worker: Option<tokio::task::JoinHandle<()>>,
        stopping: Arc<AtomicBool>,
        health: super::RuntimeHealth,
    }

    impl Session {
        pub fn refresh_statistics(&self) {
            if self.handle.Value == 0 {
                return;
            }
            let mut buffer = TraceProperties::new();
            let status = unsafe {
                ControlTraceW(
                    self.handle,
                    windows::core::PCWSTR::null(),
                    &mut buffer.props,
                    EVENT_TRACE_CONTROL_QUERY,
                )
            };
            if status.0 == 0 {
                self.health.statistics(buffer.stats());
            } else {
                self.health.statistics_failed(status.0);
            }
            if !self.stopping.load(Ordering::Acquire)
                && self.worker.as_ref().is_some_and(|w| w.is_finished())
                && self.health.snapshot(0).state != CollectorState::Error
            {
                self.health.fail("etw_consumer_ended", None);
            }
        }

        fn stop_trace(&mut self) -> Result<()> {
            if self.handle.Value == 0 {
                return Ok(());
            }
            let mut buffer = TraceProperties::new();
            let status = unsafe {
                ControlTraceW(
                    self.handle,
                    windows::core::PCWSTR::null(),
                    &mut buffer.props,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };
            if status.0 == 0 {
                self.health.statistics(buffer.stats());
                self.handle = CONTROLTRACE_HANDLE::default();
                Ok(())
            } else {
                self.health.fail("etw_stop_failed", Some(status.0));
                anyhow::bail!("ControlTraceW(STOP) failed: {}", status.0)
            }
        }

        pub async fn stop(&mut self) -> Result<()> {
            self.stopping.store(true, Ordering::Release);
            let result = self.stop_trace();
            // CloseTrace unblocks ProcessTrace if stopping the session failed.
            if result.is_err() {
                if let Some(trace) = self.trace.take() {
                    unsafe {
                        let _ = CloseTrace(trace);
                    }
                }
            }
            if let Some(worker) = self.worker.as_mut() {
                match tokio::time::timeout(std::time::Duration::from_secs(5), worker).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        self.health.fail("collector_worker_failed", None);
                        return Err(e.into());
                    }
                    Err(e) => {
                        self.health.fail("collector_stop_timeout", None);
                        return Err(e.into());
                    }
                }
            }
            self.worker = None;
            if result.is_ok() {
                self.health.stopped();
            }
            result
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            self.stopping.store(true, Ordering::Release);
            let _ = self.stop_trace();
            if let Some(trace) = self.trace.take() {
                unsafe {
                    let _ = CloseTrace(trace);
                }
            }
            release_instance_lock(self.instance_lock);
        }
    }

    /// Return only once OpenTrace succeeds. Session owns cleanup on every
    /// failure path and never stops a session without owning the instance lock.
    pub fn start_session(
        providers: &[crate::config::EtwProviderConfig],
        agent: crate::events::AgentInfo,
        tx: mpsc::Sender<ThreatEvent>,
        dropped: Arc<AtomicU64>,
        health: super::RuntimeHealth,
    ) -> Result<Session> {
        let guids: Vec<GUID> = providers
            .iter()
            .map(|p| parse_guid(&p.guid))
            .collect::<Result<_>>()?;
        let mut session = Session {
            handle: CONTROLTRACE_HANDLE::default(),
            instance_lock: acquire_instance_lock()?,
            trace: None,
            worker: None,
            stopping: Arc::new(AtomicBool::new(false)),
            health,
        };
        let session_name_wide: Vec<u16> = SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let start = |handle: &mut CONTROLTRACE_HANDLE| {
            let mut buffer = TraceProperties::new();
            buffer.props.Wnode.ClientContext = 1; // QPC
            buffer.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            buffer.props.LogFileNameOffset = 0; // real-time only; no ETL file
            unsafe {
                StartTraceW(
                    handle,
                    windows::core::PCWSTR(session_name_wide.as_ptr()),
                    &mut buffer.props,
                )
            }
        };
        let mut status = start(&mut session.handle);

        // ERROR_ALREADY_EXISTS (183): a stale session from a previous crash.
        // We hold the named mutex, so no other live instance owns this
        // session — safe to stop and retry.
        if status.0 == 183 {
            tracing::warn!("Stale ETW session found — stopping and retrying");
            let mut buffer = TraceProperties::new();
            unsafe {
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    windows::core::PCWSTR(session_name_wide.as_ptr()),
                    &mut buffer.props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            status = start(&mut session.handle);
        }

        if status != WIN32_ERROR(0) {
            session.handle = CONTROLTRACE_HANDLE::default();
            session.health.fail("etw_start_failed", Some(status.0));
            anyhow::bail!("StartTraceW failed: {status:?}");
        }

        // ---- enable providers -----------------------------------------------
        let mut provider_statuses = Vec::new();
        for (p, guid) in providers.iter().zip(&guids) {
            let status = unsafe {
                EnableTraceEx2(
                    session.handle,
                    guid,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                    p.level,
                    p.keywords,
                    0,
                    0,
                    None,
                )
            };
            if status != WIN32_ERROR(0) {
                tracing::warn!(
                    provider = %p.name,
                    error = ?status,
                    "EnableTraceEx2 failed"
                );
            } else {
                tracing::info!(provider = %p.name, "ETW provider enabled");
            }
            provider_statuses.push(crate::events::ProviderStatus {
                name: p.name.clone(),
                guid: p.guid.clone(),
                enabled: status.0 == 0,
                error_code: (status.0 != 0).then_some(status.0),
            });
        }
        let any_enabled = provider_statuses.iter().any(|p| p.enabled);
        session.health.providers(provider_statuses);
        if !any_enabled {
            session.health.fail("etw_no_providers", None);
            anyhow::bail!("No ETW providers could be enabled");
        }

        // ---- consume events in a blocking thread ----------------------------
        let ctx_ptr = Box::into_raw(Box::new(CallbackContext {
            agent,
            tx,
            dropped,
            decoder: std::sync::Mutex::new(super::super::tdh::Decoder::default()),
            health: session.health.clone(),
        }));
        let mut logfile = EVENT_TRACE_LOGFILEW::default();
        logfile.LoggerName = windows::core::PWSTR(session_name_wide.as_ptr() as *mut u16);
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Context = ctx_ptr as *mut std::ffi::c_void;
        logfile.Anonymous2.EventRecordCallback = Some(event_callback);
        let trace = unsafe { OpenTraceW(&mut logfile) };
        if trace.Value == u64::MAX {
            let error = unsafe { GetLastError() }.0;
            unsafe {
                drop(Box::from_raw(ctx_ptr));
            }
            session.health.fail("etw_open_failed", Some(error));
            anyhow::bail!("OpenTraceW failed: {error}");
        }
        session.trace = Some(trace);
        session.health.running();
        let health = session.health.clone();
        let stopping = session.stopping.clone();
        // The context is owned solely by this worker after OpenTrace succeeds.
        let context_address = ctx_ptr as usize;
        session.worker = Some(tokio::task::spawn_blocking(move || {
            let status = unsafe { ProcessTrace(&[trace], None, None) };
            if !stopping.load(Ordering::Acquire) {
                health.fail("etw_consumer_ended", Some(status.0));
            }
            unsafe {
                drop(Box::from_raw(context_address as *mut CallbackContext));
            }
        }));
        Ok(session)
    }

    // -----------------------------------------------------------------------
    // Event callback & mapping — now with UserData parsing
    // -----------------------------------------------------------------------

    unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
        let rec = unsafe { &*record };
        let ctx = unsafe { &*(rec.UserContext as *const CallbackContext) };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            ctx.decoder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .decode(rec, &ctx.agent)
        }));
        if let Ok(event) = result {
            ctx.health.decoded(
                matches!(event.data, EventData::NativeTelemetry { .. }),
                event
                    .provenance
                    .as_ref()
                    .is_some_and(|p| p.issues.iter().any(|i| i.starts_with("tdh_"))),
            );
            if let Err(_) = ctx.tx.try_send(event) {
                let n = ctx.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_power_of_two() || n % 1000 == 0 {
                    tracing::warn!(
                        total_dropped = n,
                        "ETW events dropped due to channel backpressure"
                    );
                }
            }
        } else {
            ctx.health.fail("etw_decoder_panic", None);
            ctx.health.lost_before_queue();
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {}

#[async_trait]
impl Collector for EtwCollector {
    fn name(&self) -> &str {
        "ETW"
    }

    fn enabled(&self) -> bool {
        self.config.enabled
    }

    fn supported(&self) -> bool {
        cfg!(target_os = "windows")
    }

    fn status(&self) -> Option<CollectorStatus> {
        #[cfg(target_os = "windows")]
        if let Some(session) = &self.session {
            session.refresh_statistics();
        }
        Some(self.health.snapshot(self.dropped_events()))
    }

    async fn start(&mut self, _tx: mpsc::Sender<ThreatEvent>) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            if self.session.is_some() {
                anyhow::bail!("ETW collector already started");
            }
            self.dropped.store(0, Ordering::Relaxed);
            self.health.starting();
            let session = platform::start_session(
                &self.config.providers,
                self.agent.clone(),
                _tx,
                self.dropped.clone(),
                self.health.clone(),
            )?;
            self.session = Some(session);
            info!(
                "ETW collector started with {} providers",
                self.config.providers.len()
            );
        }

        #[cfg(not(target_os = "windows"))]
        tracing::warn!("ETW collector is only available on Windows");

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        if let Some(mut session) = self.session.take() {
            session.stop().await?;
        }

        info!("ETW collector stopped");
        Ok(())
    }

    fn dropped_events(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::parser::*;

    // --- Helper: encode a UTF-16LE null-terminated string into bytes ----------
    fn utf16_nul(s: &str) -> Vec<u8> {
        let mut buf: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        buf.extend_from_slice(&[0, 0]); // null terminator
        buf
    }

    // --- UserDataReader integer tests ----------------------------------------

    #[test]
    fn read_u16_le() {
        let data = [0x34, 0x12];
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_u16(), Some(0x1234));
    }

    #[test]
    fn read_u16_be() {
        let data = [0x00, 0x50]; // port 80
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_u16_be(), Some(80));
    }

    #[test]
    fn read_u32_le() {
        let data = 1234u32.to_le_bytes();
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_u32(), Some(1234));
    }

    #[test]
    fn read_u64_le() {
        let data = 0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes();
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_u64(), Some(0xDEAD_BEEF_CAFE_BABE));
    }

    #[test]
    fn read_pointer_64bit() {
        let data = 0x7FFE_0000_0000u64.to_le_bytes();
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_pointer(), Some(0x7FFE_0000_0000));
    }

    #[test]
    fn read_pointer_32bit() {
        let data = 0x7FFE_0000u32.to_le_bytes();
        let mut r = UserDataReader::new(&data, 4);
        assert_eq!(r.read_pointer(), Some(0x7FFE_0000));
    }

    #[test]
    fn read_past_end_returns_none() {
        let data = [0x01]; // only 1 byte, not enough for u16
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_u16(), None);
        assert_eq!(r.read_u32(), None);
        assert_eq!(r.read_u64(), None);
    }

    // --- UserDataReader IP address tests -------------------------------------

    #[test]
    fn read_ipv4() {
        let data = [192, 168, 1, 100];
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_ipv4(), Some("192.168.1.100".into()));
    }

    #[test]
    fn read_ipv6_loopback() {
        let mut data = [0u8; 16];
        data[15] = 1; // ::1
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_ipv6(), Some("::1".into()));
    }

    // --- UserDataReader UTF-16 string tests ----------------------------------

    #[test]
    fn read_utf16_nul_simple() {
        let data = utf16_nul("cmd.exe");
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_utf16_nul(), "cmd.exe");
    }

    #[test]
    fn read_utf16_nul_empty_string() {
        let data = [0, 0]; // just null terminator
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_utf16_nul(), "");
    }

    #[test]
    fn read_utf16_nul_no_terminator() {
        // "AB" without null terminator — reader should consume all bytes
        let data = [0x41, 0x00, 0x42, 0x00];
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_utf16_nul(), "AB");
    }

    #[test]
    fn read_multiple_strings() {
        let mut data = utf16_nul("hello");
        data.extend_from_slice(&utf16_nul("world"));
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_utf16_nul(), "hello");
        assert_eq!(r.read_utf16_nul(), "world");
    }

    // --- Composite fixture: ProcessCreate-like payload -----------------------

    #[test]
    fn fixture_process_create_payload() {
        // Simulate Kernel-Process event ID 1 (ProcessCreate) UserData:
        //   PID(u32), CreateTime(u64), PPID(u32), SessionID(u32),
        //   Flags(u32), ImageName(wstr), CommandLine(wstr)
        let mut data = Vec::new();
        data.extend_from_slice(&1234u32.to_le_bytes()); // PID
        data.extend_from_slice(&0u64.to_le_bytes()); // CreateTime
        data.extend_from_slice(&4321u32.to_le_bytes()); // PPID
        data.extend_from_slice(&1u32.to_le_bytes()); // SessionID
        data.extend_from_slice(&0u32.to_le_bytes()); // Flags
        data.extend_from_slice(&utf16_nul(r"C:\Windows\System32\cmd.exe"));
        data.extend_from_slice(&utf16_nul("cmd.exe /c whoami"));

        let mut r = UserDataReader::new(&data, 8);
        let pid = r.read_u32().unwrap();
        let _create_time = r.read_u64().unwrap();
        let ppid = r.read_u32().unwrap();
        let _session_id = r.read_u32().unwrap();
        let _flags = r.read_u32().unwrap();
        let image = r.read_utf16_nul();
        let cmdline = r.read_utf16_nul();

        assert_eq!(pid, 1234);
        assert_eq!(ppid, 4321);
        assert_eq!(image, r"C:\Windows\System32\cmd.exe");
        assert_eq!(cmdline, "cmd.exe /c whoami");
    }

    // --- Composite fixture: TCP IPv4 network payload -------------------------

    #[test]
    fn fixture_tcp_ipv4_payload() {
        // Simulate Kernel-Network event ID 10 (TcpSendIPv4) UserData:
        //   PID(u32), Size(u32), DstAddr(4), SrcAddr(4),
        //   DstPort(u16 BE), SrcPort(u16 BE)
        let mut data = Vec::new();
        data.extend_from_slice(&100u32.to_le_bytes()); // PID
        data.extend_from_slice(&512u32.to_le_bytes()); // Size
        data.extend_from_slice(&[93, 184, 216, 34]); // DstAddr: 93.184.216.34
        data.extend_from_slice(&[192, 168, 1, 10]); // SrcAddr: 192.168.1.10
        data.extend_from_slice(&443u16.to_be_bytes()); // DstPort (BE)
        data.extend_from_slice(&50000u16.to_be_bytes()); // SrcPort (BE)

        let mut r = UserDataReader::new(&data, 8);
        let _pid = r.read_u32().unwrap();
        let _size = r.read_u32().unwrap();
        let dst_addr = r.read_ipv4().unwrap();
        let src_addr = r.read_ipv4().unwrap();
        let dst_port = r.read_u16_be().unwrap();
        let src_port = r.read_u16_be().unwrap();

        assert_eq!(dst_addr, "93.184.216.34");
        assert_eq!(src_addr, "192.168.1.10");
        assert_eq!(dst_port, 443);
        assert_eq!(src_port, 50000);
    }

    // --- Composite fixture: DNS query payload --------------------------------

    #[test]
    fn fixture_dns_query_payload() {
        // Simulate DNS-Client event 3006 UserData:
        //   QueryName(wstr), QueryType(u16 LE)
        let mut data = utf16_nul("example.com");
        data.extend_from_slice(&1u16.to_le_bytes()); // A record

        let mut r = UserDataReader::new(&data, 8);
        let query_name = r.read_utf16_nul();
        let query_type = r.read_u16().unwrap();

        assert_eq!(query_name, "example.com");
        assert_eq!(dns_query_type_name(query_type), "A");
    }

    // --- Composite fixture: Registry SetValue payload ------------------------

    #[test]
    fn fixture_registry_set_value_payload() {
        // Simulate Kernel-Registry event ID 5 (SetValueKey) UserData:
        //   KeyObject(ptr), Status(u32), Type(u32), DataSize(u32),
        //   KeyName(wstr), ValueName(wstr)
        let mut data = Vec::new();
        data.extend_from_slice(&0x1234_5678_9ABCu64.to_le_bytes()); // KeyObject (64-bit ptr)
        data.extend_from_slice(&0u32.to_le_bytes()); // Status
        data.extend_from_slice(&1u32.to_le_bytes()); // Type (REG_SZ)
        data.extend_from_slice(&64u32.to_le_bytes()); // DataSize
        data.extend_from_slice(&utf16_nul(r"HKLM\SOFTWARE\Test"));
        data.extend_from_slice(&utf16_nul("MyValue"));

        let mut r = UserDataReader::new(&data, 8);
        let _key_object = r.read_pointer().unwrap();
        let _status = r.read_u32().unwrap();
        let _value_type = r.read_u32().unwrap();
        let _data_size = r.read_u32().unwrap();
        let key = r.read_utf16_nul();
        let value_name = r.read_utf16_nul();

        assert_eq!(key, r"HKLM\SOFTWARE\Test");
        assert_eq!(value_name, "MyValue");
    }

    // --- dns_query_type_name tests -------------------------------------------

    #[test]
    fn dns_type_known() {
        assert_eq!(dns_query_type_name(1), "A");
        assert_eq!(dns_query_type_name(28), "AAAA");
        assert_eq!(dns_query_type_name(5), "CNAME");
        assert_eq!(dns_query_type_name(15), "MX");
        assert_eq!(dns_query_type_name(33), "SRV");
        assert_eq!(dns_query_type_name(255), "ANY");
    }

    #[test]
    fn dns_type_unknown() {
        assert_eq!(dns_query_type_name(99), "TYPE99");
        assert_eq!(dns_query_type_name(0), "TYPE0");
    }

    // --- Composite fixture: ImageLoad (Kernel-Process ID 5) ------------------

    #[test]
    fn fixture_image_load_payload_64bit() {
        // Simulate Kernel-Process event ID 5 (ImageLoad) UserData on 64-bit:
        //   ProcessId(u32), ImageBase(ptr64), ImageSize(ptr64),
        //   ImageCheckSum(u32), TimeDateStamp(u32), DefaultBase(ptr64),
        //   SignatureLevel(u8), SignatureType(u8), padding(2),
        //   FileName(wstr)
        let mut data = Vec::new();
        data.extend_from_slice(&4200u32.to_le_bytes()); // ProcessId
        data.extend_from_slice(&0x7FFB_1234_0000u64.to_le_bytes()); // ImageBase
        data.extend_from_slice(&0x0010_0000u64.to_le_bytes()); // ImageSize
        data.extend_from_slice(&0xABCD_1234u32.to_le_bytes()); // CheckSum
        data.extend_from_slice(&0x6000_0000u32.to_le_bytes()); // TimeDateStamp
        data.extend_from_slice(&0x1800_0000_0000u64.to_le_bytes()); // DefaultBase
        data.push(6); // SignatureLevel
        data.push(2); // SignatureType
        data.extend_from_slice(&[0, 0]); // padding
        data.extend_from_slice(&utf16_nul(
            r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll",
        ));

        let mut r = UserDataReader::new(&data, 8);
        let process_id = r.read_u32().unwrap();
        let image_base = r.read_pointer().unwrap();
        let _image_size = r.read_pointer().unwrap();
        let _checksum = r.read_u32().unwrap();
        let _timestamp = r.read_u32().unwrap();
        let _default_base = r.read_pointer().unwrap();
        let sig_level = r.read_u8().unwrap();
        let sig_type = r.read_u8().unwrap();
        r.skip(2);
        let file_name = r.read_utf16_nul();

        assert_eq!(process_id, 4200);
        assert_eq!(image_base, 0x7FFB_1234_0000);
        assert_eq!(sig_level, 6);
        assert_eq!(sig_type, 2);
        assert_eq!(
            file_name,
            r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll"
        );
        // Verify image_name extraction logic
        let image_name = file_name
            .rsplit('\\')
            .next()
            .unwrap_or(&file_name)
            .to_string();
        assert_eq!(image_name, "ntdll.dll");
    }

    #[test]
    fn fixture_image_load_payload_32bit() {
        // ImageLoad on 32-bit: pointers are 4 bytes
        let mut data = Vec::new();
        data.extend_from_slice(&500u32.to_le_bytes()); // ProcessId
        data.extend_from_slice(&0x7700_0000u32.to_le_bytes()); // ImageBase (32-bit ptr)
        data.extend_from_slice(&0x0008_0000u32.to_le_bytes()); // ImageSize (32-bit ptr)
        data.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        data.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        data.extend_from_slice(&0x7700_0000u32.to_le_bytes()); // DefaultBase (32-bit ptr)
        data.push(0); // SignatureLevel
        data.push(0); // SignatureType
        data.extend_from_slice(&[0, 0]); // padding
        data.extend_from_slice(&utf16_nul(r"C:\Windows\System32\kernel32.dll"));

        let mut r = UserDataReader::new(&data, 4);
        let process_id = r.read_u32().unwrap();
        let image_base = r.read_pointer().unwrap();
        let _image_size = r.read_pointer().unwrap();
        let _checksum = r.read_u32().unwrap();
        let _timestamp = r.read_u32().unwrap();
        let _default_base = r.read_pointer().unwrap();
        let _sig_level = r.read_u8().unwrap();
        let _sig_type = r.read_u8().unwrap();
        r.skip(2);
        let file_name = r.read_utf16_nul();

        assert_eq!(process_id, 500);
        assert_eq!(image_base, 0x7700_0000);
        assert!(file_name.ends_with("kernel32.dll"));
    }

    // --- Composite fixture: UDP IPv4 network payload -------------------------

    #[test]
    fn fixture_udp_ipv4_payload() {
        // Simulate Kernel-Network event ID 15 (UdpSendIPv4) UserData:
        //   PID(u32), Size(u32), DstAddr(4), SrcAddr(4),
        //   DstPort(u16 BE), SrcPort(u16 BE)
        let mut data = Vec::new();
        data.extend_from_slice(&200u32.to_le_bytes()); // PID
        data.extend_from_slice(&64u32.to_le_bytes()); // Size
        data.extend_from_slice(&[8, 8, 8, 8]); // DstAddr: 8.8.8.8
        data.extend_from_slice(&[10, 0, 0, 1]); // SrcAddr: 10.0.0.1
        data.extend_from_slice(&53u16.to_be_bytes()); // DstPort (BE)
        data.extend_from_slice(&12345u16.to_be_bytes()); // SrcPort (BE)

        let mut r = UserDataReader::new(&data, 8);
        let _pid = r.read_u32().unwrap();
        let _size = r.read_u32().unwrap();
        let dst_addr = r.read_ipv4().unwrap();
        let src_addr = r.read_ipv4().unwrap();
        let dst_port = r.read_u16_be().unwrap();
        let src_port = r.read_u16_be().unwrap();

        assert_eq!(dst_addr, "8.8.8.8");
        assert_eq!(src_addr, "10.0.0.1");
        assert_eq!(dst_port, 53);
        assert_eq!(src_port, 12345);
    }

    // --- Composite fixture: UDP IPv6 network payload -------------------------

    #[test]
    fn fixture_udp_ipv6_payload() {
        // Simulate Kernel-Network event ID 16 (UdpSendIPv6) UserData:
        //   PID(u32), Size(u32), DstAddr(16), SrcAddr(16),
        //   DstPort(u16 BE), SrcPort(u16 BE)
        let mut data = Vec::new();
        data.extend_from_slice(&300u32.to_le_bytes()); // PID
        data.extend_from_slice(&128u32.to_le_bytes()); // Size
                                                       // DstAddr: 2001:4860:4860::8888
        let dst_v6: [u8; 16] = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x88, 0x88,
        ];
        data.extend_from_slice(&dst_v6);
        // SrcAddr: ::1
        let mut src_v6 = [0u8; 16];
        src_v6[15] = 1;
        data.extend_from_slice(&src_v6);
        data.extend_from_slice(&53u16.to_be_bytes()); // DstPort (BE)
        data.extend_from_slice(&54321u16.to_be_bytes()); // SrcPort (BE)

        let mut r = UserDataReader::new(&data, 8);
        let _pid = r.read_u32().unwrap();
        let _size = r.read_u32().unwrap();
        let dst_addr = r.read_ipv6().unwrap();
        let src_addr = r.read_ipv6().unwrap();
        let dst_port = r.read_u16_be().unwrap();
        let src_port = r.read_u16_be().unwrap();

        assert_eq!(dst_addr, "2001:4860:4860::8888");
        assert_eq!(src_addr, "::1");
        assert_eq!(dst_port, 53);
        assert_eq!(src_port, 54321);
    }

    // --- Composite fixture: TCP IPv6 network payload -------------------------

    #[test]
    fn fixture_tcp_ipv6_payload() {
        // Simulate Kernel-Network event ID 11 (TcpSendIPv6) UserData
        let mut data = Vec::new();
        data.extend_from_slice(&400u32.to_le_bytes()); // PID
        data.extend_from_slice(&1024u32.to_le_bytes()); // Size
                                                        // DstAddr: fe80::1
        let mut dst_v6 = [0u8; 16];
        dst_v6[0] = 0xfe;
        dst_v6[1] = 0x80;
        dst_v6[15] = 1;
        data.extend_from_slice(&dst_v6);
        // SrcAddr: fe80::2
        let mut src_v6 = [0u8; 16];
        src_v6[0] = 0xfe;
        src_v6[1] = 0x80;
        src_v6[15] = 2;
        data.extend_from_slice(&src_v6);
        data.extend_from_slice(&80u16.to_be_bytes()); // DstPort
        data.extend_from_slice(&60000u16.to_be_bytes()); // SrcPort

        let mut r = UserDataReader::new(&data, 8);
        let _pid = r.read_u32().unwrap();
        let _size = r.read_u32().unwrap();
        let dst_addr = r.read_ipv6().unwrap();
        let src_addr = r.read_ipv6().unwrap();
        let dst_port = r.read_u16_be().unwrap();
        let src_port = r.read_u16_be().unwrap();

        assert_eq!(dst_addr, "fe80::1");
        assert_eq!(src_addr, "fe80::2");
        assert_eq!(dst_port, 80);
        assert_eq!(src_port, 60000);
    }

    // --- Composite fixture: TI common header parsing -------------------------

    /// Build a TI common header (64-bit): CallingProcessId(ptr),
    /// CallingProcessCreateTime(u64), CallingProcessStartKey(u64),
    /// CallingProcessSignatureLevel(u8),
    /// CallingProcessSectionSignatureLevel(u8),
    /// CallingProcessProtection(u8), CallingThreadId(u32),
    /// CallingThreadCreateTime(u64)
    fn build_ti_common_header(calling_pid: u32, calling_tid: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        // CallingProcessId is win:Pointer (8 bytes on 64-bit)
        buf.extend_from_slice(&(calling_pid as u64).to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes()); // CallingProcessCreateTime
        buf.extend_from_slice(&0u64.to_le_bytes()); // CallingProcessStartKey
        buf.push(6); // CallingProcessSignatureLevel
        buf.push(6); // CallingProcessSectionSignatureLevel
        buf.push(0x31); // CallingProcessProtection (PsProtectedSignerAntimalware-Light)
        buf.extend_from_slice(&calling_tid.to_le_bytes()); // CallingThreadId
        buf.extend_from_slice(&0u64.to_le_bytes()); // CallingThreadCreateTime
        buf
    }

    /// Build TI target process header (64-bit): TargetProcessId(ptr),
    /// TargetProcessCreateTime(u64), TargetProcessStartKey(u64),
    /// TargetProcessSignatureLevel(u8),
    /// TargetProcessSectionSignatureLevel(u8),
    /// TargetProcessProtection(u8)
    fn build_ti_target_header(target_pid: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        // TargetProcessId is win:Pointer (8 bytes on 64-bit)
        buf.extend_from_slice(&(target_pid as u64).to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes()); // TargetProcessCreateTime
        buf.extend_from_slice(&0u64.to_le_bytes()); // TargetProcessStartKey
        buf.push(0); // TargetProcessSignatureLevel
        buf.push(0); // TargetProcessSectionSignatureLevel
        buf.push(0); // TargetProcessProtection
        buf
    }

    #[test]
    fn fixture_ti_common_header_parse() {
        let data = build_ti_common_header(1234, 5678);
        let mut r = UserDataReader::new(&data, 8);

        let calling_pid = r.read_pointer().unwrap() as u32;
        let _create_time = r.read_u64().unwrap();
        let _start_key = r.read_u64().unwrap();
        let sig_level = r.read_u8().unwrap();
        let sec_sig_level = r.read_u8().unwrap();
        let protection = r.read_u8().unwrap();
        let calling_tid = r.read_u32().unwrap();
        let _thread_create_time = r.read_u64().unwrap();

        assert_eq!(calling_pid, 1234);
        assert_eq!(calling_tid, 5678);
        assert_eq!(sig_level, 6);
        assert_eq!(sec_sig_level, 6);
        assert_eq!(protection, 0x31);
    }

    // --- Composite fixture: TI ALLOCVM_REMOTE (ID 1) -------------------------

    #[test]
    fn fixture_ti_allocvm_remote() {
        // TI event ID 1: common header + target header +
        //   BaseAddress(ptr), RegionSize(ptr), AllocationType(u32),
        //   Protection(u32)
        let mut data = build_ti_common_header(100, 200);
        data.extend(build_ti_target_header(999));
        data.extend_from_slice(&0x1000_0000u64.to_le_bytes()); // BaseAddress
        data.extend_from_slice(&0x2000u64.to_le_bytes()); // RegionSize
        data.extend_from_slice(&0x3000u32.to_le_bytes()); // AllocationType
        data.extend_from_slice(&0x40u32.to_le_bytes()); // Protection (PAGE_EXECUTE_READWRITE)

        let mut r = UserDataReader::new(&data, 8);
        let calling_pid = r.read_pointer().unwrap() as u32;
        let _ct = r.read_u64().unwrap();
        let _sk = r.read_u64().unwrap();
        let _sl = r.read_u8().unwrap();
        let _ssl = r.read_u8().unwrap();
        let _prot = r.read_u8().unwrap();
        let calling_tid = r.read_u32().unwrap();
        let _tct = r.read_u64().unwrap();
        // Target header
        let target_pid = r.read_pointer().unwrap() as u32;
        let _tpc = r.read_u64().unwrap();
        let _tpk = r.read_u64().unwrap();
        let _tsl = r.read_u8().unwrap();
        let _tssl = r.read_u8().unwrap();
        let _tp = r.read_u8().unwrap();
        // Event-specific
        let base = r.read_pointer().unwrap();
        let size = r.read_pointer().unwrap();
        let _alloc_type = r.read_u32().unwrap();
        let protection = r.read_u32().unwrap();

        assert_eq!(calling_pid, 100);
        assert_eq!(calling_tid, 200);
        assert_eq!(target_pid, 999);
        assert_eq!(base, 0x1000_0000);
        assert_eq!(size, 0x2000);
        assert_eq!(protection, 0x40); // PAGE_EXECUTE_READWRITE
    }

    // --- Composite fixture: TI PROTECTVM_REMOTE (ID 2) -----------------------

    #[test]
    fn fixture_ti_protectvm_remote() {
        // TI event ID 2: common + target +
        //   BaseAddress(ptr), RegionSize(ptr), NewProtection(u32),
        //   OldProtection(u32)
        let mut data = build_ti_common_header(500, 501);
        data.extend(build_ti_target_header(600));
        data.extend_from_slice(&0x7FFE_0000u64.to_le_bytes()); // BaseAddress
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // RegionSize
        data.extend_from_slice(&0x20u32.to_le_bytes()); // NewProtection (PAGE_EXECUTE_READ)
        data.extend_from_slice(&0x04u32.to_le_bytes()); // OldProtection (PAGE_READWRITE)

        let mut r = UserDataReader::new(&data, 8);
        // Skip common header
        let _cp = r.read_pointer().unwrap();
        let _ct = r.read_u64().unwrap();
        let _sk = r.read_u64().unwrap();
        let _sl = r.read_u8().unwrap();
        let _ssl = r.read_u8().unwrap();
        let _p = r.read_u8().unwrap();
        let _tid = r.read_u32().unwrap();
        let _tct = r.read_u64().unwrap();
        // Skip target header
        let target_pid = r.read_pointer().unwrap() as u32;
        let _tc = r.read_u64().unwrap();
        let _tk = r.read_u64().unwrap();
        let _tsl = r.read_u8().unwrap();
        let _tssl = r.read_u8().unwrap();
        let _tp = r.read_u8().unwrap();
        // Event-specific
        let base = r.read_pointer().unwrap();
        let size = r.read_pointer().unwrap();
        let new_protection = r.read_u32().unwrap();
        let old_protection = r.read_u32().unwrap();

        assert_eq!(target_pid, 600);
        assert_eq!(base, 0x7FFE_0000);
        assert_eq!(size, 0x1000);
        assert_eq!(new_protection, 0x20);
        assert_eq!(old_protection, 0x04);
    }

    // --- Composite fixture: TI QUEUEAPC_REMOTE (ID 4) ------------------------

    #[test]
    fn fixture_ti_queueapc_remote() {
        // TI event ID 4: common header + target header +
        //   TargetThreadId(u32), ApcRoutine(ptr)
        let mut data = build_ti_common_header(800, 801);
        data.extend(build_ti_target_header(900));
        data.extend_from_slice(&1234u32.to_le_bytes()); // TargetThreadId
        data.extend_from_slice(&0x7FFB_DEAD_0000u64.to_le_bytes()); // ApcRoutine

        let mut r = UserDataReader::new(&data, 8);
        // Common
        let calling_pid = r.read_pointer().unwrap() as u32;
        let _ct = r.read_u64().unwrap();
        let _sk = r.read_u64().unwrap();
        let _sl = r.read_u8().unwrap();
        let _ssl = r.read_u8().unwrap();
        let _p = r.read_u8().unwrap();
        let _tid = r.read_u32().unwrap();
        let _tct = r.read_u64().unwrap();
        // Target
        let target_pid = r.read_pointer().unwrap() as u32;
        let _tc = r.read_u64().unwrap();
        let _tk = r.read_u64().unwrap();
        let _tsl = r.read_u8().unwrap();
        let _tssl = r.read_u8().unwrap();
        let _tp = r.read_u8().unwrap();
        // Event-specific
        let target_thread_id = r.read_u32().unwrap();
        let apc_routine = r.read_pointer().unwrap();

        assert_eq!(calling_pid, 800);
        assert_eq!(target_pid, 900);
        assert_eq!(target_thread_id, 1234);
        assert_eq!(apc_routine, 0x7FFB_DEAD_0000);
    }

    // --- Composite fixture: TI SETCONTEXT_REMOTE (ID 5) ----------------------

    #[test]
    fn fixture_ti_setcontext_remote() {
        // TI event ID 5: common header + target header +
        //   TargetThreadId(u32), ContextFlags(u32)
        let mut data = build_ti_common_header(700, 701);
        data.extend(build_ti_target_header(750));
        data.extend_from_slice(&4321u32.to_le_bytes()); // TargetThreadId
        data.extend_from_slice(&0x10001Fu32.to_le_bytes()); // ContextFlags (CONTEXT_ALL)

        let mut r = UserDataReader::new(&data, 8);
        // Common
        let calling_pid = r.read_pointer().unwrap() as u32;
        let _ct = r.read_u64().unwrap();
        let _sk = r.read_u64().unwrap();
        let _sl = r.read_u8().unwrap();
        let _ssl = r.read_u8().unwrap();
        let _p = r.read_u8().unwrap();
        let _tid = r.read_u32().unwrap();
        let _tct = r.read_u64().unwrap();
        // Target
        let target_pid = r.read_pointer().unwrap() as u32;
        let _tc = r.read_u64().unwrap();
        let _tk = r.read_u64().unwrap();
        let _tsl = r.read_u8().unwrap();
        let _tssl = r.read_u8().unwrap();
        let _tp = r.read_u8().unwrap();
        // Event-specific
        let target_thread_id = r.read_u32().unwrap();
        let context_flags = r.read_u32().unwrap();

        assert_eq!(calling_pid, 700);
        assert_eq!(target_pid, 750);
        assert_eq!(target_thread_id, 4321);
        assert_eq!(context_flags, 0x10001F);
    }

    // --- Composite fixture: TI ALLOCVM_LOCAL (ID 6) --------------------------

    #[test]
    fn fixture_ti_allocvm_local() {
        // TI event ID 6: common header (no target) +
        //   BaseAddress(ptr), RegionSize(ptr), AllocationType(u32),
        //   Protection(u32)
        let mut data = build_ti_common_header(1500, 1501);
        data.extend_from_slice(&0x0040_0000u64.to_le_bytes()); // BaseAddress
        data.extend_from_slice(&0x4000u64.to_le_bytes()); // RegionSize
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // AllocationType
        data.extend_from_slice(&0x04u32.to_le_bytes()); // Protection (PAGE_READWRITE)

        let mut r = UserDataReader::new(&data, 8);
        // Common header
        let calling_pid = r.read_pointer().unwrap() as u32;
        let _ct = r.read_u64().unwrap();
        let _sk = r.read_u64().unwrap();
        let _sl = r.read_u8().unwrap();
        let _ssl = r.read_u8().unwrap();
        let _p = r.read_u8().unwrap();
        let _tid = r.read_u32().unwrap();
        let _tct = r.read_u64().unwrap();
        // No target header for local events
        // Event-specific
        let base = r.read_pointer().unwrap();
        let size = r.read_pointer().unwrap();
        let _alloc_type = r.read_u32().unwrap();
        let protection = r.read_u32().unwrap();

        assert_eq!(calling_pid, 1500);
        assert_eq!(base, 0x0040_0000);
        assert_eq!(size, 0x4000);
        assert_eq!(protection, 0x04);
    }

    // --- Composite fixture: Registry CreateKey (ID 1) ------------------------

    #[test]
    fn fixture_registry_create_key_payload() {
        // Kernel-Registry event ID 1 (CreateKey):
        //   BaseObject(ptr), KeyObject(ptr), Status(u32), Disposition(u32),
        //   BaseName(wstr), RelativeName(wstr)
        let mut data = Vec::new();
        data.extend_from_slice(&0xFFFF_F800_0000u64.to_le_bytes()); // BaseObject
        data.extend_from_slice(&0xFFFF_F801_0000u64.to_le_bytes()); // KeyObject
        data.extend_from_slice(&0u32.to_le_bytes()); // Status (SUCCESS)
        data.extend_from_slice(&1u32.to_le_bytes()); // Disposition (REG_CREATED_NEW_KEY)
        data.extend_from_slice(&utf16_nul(r"\REGISTRY\MACHINE\SOFTWARE"));
        data.extend_from_slice(&utf16_nul("TestApp"));

        let mut r = UserDataReader::new(&data, 8);
        let _base_obj = r.read_pointer().unwrap();
        let _key_obj = r.read_pointer().unwrap();
        let _status = r.read_u32().unwrap();
        let _disposition = r.read_u32().unwrap(); // CreateKey has Disposition
        let base = r.read_utf16_nul();
        let rel = r.read_utf16_nul();

        let key = if base.is_empty() {
            rel
        } else if rel.is_empty() {
            base
        } else {
            format!("{base}\\{rel}")
        };
        assert_eq!(key, r"\REGISTRY\MACHINE\SOFTWARE\TestApp");
    }

    // --- Composite fixture: Registry DeleteKey (ID 3) ------------------------

    #[test]
    fn fixture_registry_delete_key_payload() {
        // Kernel-Registry event ID 3 (DeleteKey):
        //   KeyObject(ptr), Status(u32), KeyName(wstr)
        let mut data = Vec::new();
        data.extend_from_slice(&0xDEAD_BEEFu64.to_le_bytes()); // KeyObject
        data.extend_from_slice(&0u32.to_le_bytes()); // Status
        data.extend_from_slice(&utf16_nul(r"\REGISTRY\USER\S-1-5-21\Volatile"));

        let mut r = UserDataReader::new(&data, 8);
        let _key_obj = r.read_pointer().unwrap();
        let _status = r.read_u32().unwrap();
        let key = r.read_utf16_nul();

        assert_eq!(key, r"\REGISTRY\USER\S-1-5-21\Volatile");
    }

    // --- Composite fixture: Registry DeleteValue (ID 6) ----------------------

    #[test]
    fn fixture_registry_delete_value_payload() {
        // Kernel-Registry event ID 6 (DeleteValueKey):
        //   KeyObject(ptr), Status(u32), KeyName(wstr), ValueName(wstr)
        let mut data = Vec::new();
        data.extend_from_slice(&0x1234u64.to_le_bytes()); // KeyObject
        data.extend_from_slice(&0u32.to_le_bytes()); // Status
        data.extend_from_slice(&utf16_nul(r"HKLM\SOFTWARE\Evil"));
        data.extend_from_slice(&utf16_nul("RunOnce"));

        let mut r = UserDataReader::new(&data, 8);
        let _key_obj = r.read_pointer().unwrap();
        let _status = r.read_u32().unwrap();
        let key = r.read_utf16_nul();
        let value_name = r.read_utf16_nul();

        assert_eq!(key, r"HKLM\SOFTWARE\Evil");
        assert_eq!(value_name, "RunOnce");
    }

    // --- Composite fixture: ProcessStop (Kernel-Process ID 2) ----------------

    #[test]
    fn fixture_process_stop_payload() {
        // Kernel-Process event ID 2 (ProcessStop):
        //   PID(u32), CreateTime(u64), ExitTime(u64), ExitCode(u32),
        //   ImageName(wstr)
        let mut data = Vec::new();
        data.extend_from_slice(&5678u32.to_le_bytes()); // PID
        data.extend_from_slice(&1000u64.to_le_bytes()); // CreateTime
        data.extend_from_slice(&2000u64.to_le_bytes()); // ExitTime
        data.extend_from_slice(&0u32.to_le_bytes()); // ExitCode
        data.extend_from_slice(&utf16_nul(r"C:\Windows\System32\notepad.exe"));

        let mut r = UserDataReader::new(&data, 8);
        let pid = r.read_u32().unwrap();
        let _create_time = r.read_u64().unwrap();
        let _exit_time = r.read_u64().unwrap();
        let exit_code = r.read_u32().unwrap();
        let image = r.read_utf16_nul();

        assert_eq!(pid, 5678);
        assert_eq!(exit_code, 0);
        assert_eq!(image, r"C:\Windows\System32\notepad.exe");
    }

    // --- Composite fixture: PowerShell ScriptBlock (ID 4104) -----------------

    #[test]
    fn fixture_powershell_scriptblock_payload() {
        // PowerShell event ID 4104:
        //   MessageNumber(i32), MessageTotal(i32), ScriptBlockText(wstr)
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // MessageNumber
        data.extend_from_slice(&1u32.to_le_bytes()); // MessageTotal
        data.extend_from_slice(&utf16_nul("Invoke-Mimikatz"));

        let mut r = UserDataReader::new(&data, 8);
        let _msg_num = r.read_u32().unwrap();
        let _msg_total = r.read_u32().unwrap();
        let content = r.read_utf16_nul();

        assert_eq!(content, "Invoke-Mimikatz");
    }

    // --- Composite fixture: AMSI scan (ID 1101) ------------------------------

    #[test]
    fn fixture_amsi_scan_payload() {
        // AMSI event ID 1101:
        //   session(ptr), scanStatus(u32), appname(wstr),
        //   contentname(wstr), contentsize(u32)
        let mut data = Vec::new();
        data.extend_from_slice(&0xABCD_0000u64.to_le_bytes()); // session (ptr)
        data.extend_from_slice(&32768u32.to_le_bytes()); // scanStatus (AMSI_RESULT_DETECTED)
        data.extend_from_slice(&utf16_nul("PowerShell"));
        data.extend_from_slice(&utf16_nul("malware.ps1"));
        data.extend_from_slice(&256u32.to_le_bytes()); // contentsize

        let mut r = UserDataReader::new(&data, 8);
        let _session = r.read_pointer().unwrap();
        let scan_result = r.read_u32().unwrap();
        let app_name = r.read_utf16_nul();
        let content_name = r.read_utf16_nul();
        let content_size = r.read_u32().unwrap();

        assert_eq!(scan_result, 32768);
        assert_eq!(app_name, "PowerShell");
        assert_eq!(content_name, "malware.ps1");
        assert_eq!(content_size, 256);
        // Severity should be High when scan_result >= 32768
        assert!(scan_result >= 32768);
    }

    // --- UserDataReader: read_u8 test ----------------------------------------

    #[test]
    fn read_u8_basic() {
        let data = [0xFF, 0x42];
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.read_u8(), Some(0xFF));
        assert_eq!(r.read_u8(), Some(0x42));
        assert_eq!(r.read_u8(), None);
    }

    // --- UserDataReader: skip test -------------------------------------------

    #[test]
    fn skip_advances_position() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut r = UserDataReader::new(&data, 8);
        r.skip(4);
        assert_eq!(r.read_u32(), Some(0x08070605));
    }

    #[test]
    fn skip_past_end_clamps() {
        let data = [0x01, 0x02];
        let mut r = UserDataReader::new(&data, 8);
        r.skip(100); // should clamp to data.len()
        assert_eq!(r.read_u8(), None);
    }

    // --- ImageLoad: signature level interpretation ---------------------------

    #[test]
    fn fixture_image_load_signed_detection() {
        // sig_level >= 4 means signed; sig_type maps to signer name
        let mut data = Vec::new();
        data.extend_from_slice(&1000u32.to_le_bytes()); // ProcessId
        data.extend_from_slice(&0x7FFB_0000_0000u64.to_le_bytes()); // ImageBase
        data.extend_from_slice(&0x0001_0000u64.to_le_bytes()); // ImageSize
        data.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        data.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        data.extend_from_slice(&0u64.to_le_bytes()); // DefaultBase
        data.push(6); // SignatureLevel (Windows signed)
        data.push(4); // SignatureType (CatalogNotCached)
        data.extend_from_slice(&[0, 0]); // padding
        data.extend_from_slice(&utf16_nul(r"C:\Windows\System32\ntdll.dll"));

        let mut r = UserDataReader::new(&data, 8);
        let _pid = r.read_u32().unwrap();
        let _base = r.read_pointer().unwrap();
        let _size = r.read_pointer().unwrap();
        let _chk = r.read_u32().unwrap();
        let _ts = r.read_u32().unwrap();
        let _db = r.read_pointer().unwrap();
        let sig_level = r.read_u8().unwrap();
        let sig_type = r.read_u8().unwrap();

        assert_eq!(sig_level, 6);
        assert!(sig_level >= 4, "sig_level >= 4 means signed");
        assert_eq!(sig_type, 4);
    }

    #[test]
    fn fixture_image_load_unsigned() {
        let mut data = Vec::new();
        data.extend_from_slice(&2000u32.to_le_bytes()); // ProcessId
        data.extend_from_slice(&0x0040_0000u64.to_le_bytes()); // ImageBase
        data.extend_from_slice(&0x0001_0000u64.to_le_bytes()); // ImageSize
        data.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        data.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        data.extend_from_slice(&0u64.to_le_bytes()); // DefaultBase
        data.push(1); // SignatureLevel (Unsigned)
        data.push(0); // SignatureType (None)
        data.extend_from_slice(&[0, 0]); // padding
        data.extend_from_slice(&utf16_nul(r"C:\Temp\malware.dll"));

        let mut r = UserDataReader::new(&data, 8);
        let _pid = r.read_u32().unwrap();
        let _base = r.read_pointer().unwrap();
        let _size = r.read_pointer().unwrap();
        let _chk = r.read_u32().unwrap();
        let _ts = r.read_u32().unwrap();
        let _db = r.read_pointer().unwrap();
        let sig_level = r.read_u8().unwrap();

        assert!(sig_level < 4, "sig_level < 4 means unsigned");
    }

    // --- Registry: RenameKey (ID 4) ------------------------------------------

    #[test]
    fn fixture_registry_rename_key_payload() {
        // Kernel-Registry event ID 4 (RenameKey):
        //   KeyObject(ptr), Status(u32), OldKeyName(wstr), NewKeyName(wstr)
        let mut data = Vec::new();
        data.extend_from_slice(&0xAAAA_BBBBu64.to_le_bytes()); // KeyObject
        data.extend_from_slice(&0u32.to_le_bytes()); // Status
        data.extend_from_slice(&utf16_nul(r"HKLM\SOFTWARE\OldApp"));
        data.extend_from_slice(&utf16_nul(r"HKLM\SOFTWARE\NewApp"));

        let mut r = UserDataReader::new(&data, 8);
        let _key_obj = r.read_pointer().unwrap();
        let _status = r.read_u32().unwrap();
        let old_name = r.read_utf16_nul();
        let new_name = r.read_utf16_nul();

        assert_eq!(old_name, r"HKLM\SOFTWARE\OldApp");
        assert_eq!(new_name, r"HKLM\SOFTWARE\NewApp");
    }

    // --- Registry: SetValue with captured data (REG_SZ) ----------------------

    #[test]
    fn fixture_registry_set_value_with_data() {
        // SetValueKey with REG_SZ CapturedData
        let mut data = Vec::new();
        data.extend_from_slice(&0x1234u64.to_le_bytes()); // KeyObject
        data.extend_from_slice(&0u32.to_le_bytes()); // Status
        data.extend_from_slice(&1u32.to_le_bytes()); // Type (REG_SZ)
        data.extend_from_slice(&64u32.to_le_bytes()); // DataSize
        data.extend_from_slice(&utf16_nul(r"HKLM\SOFTWARE\Test"));
        data.extend_from_slice(&utf16_nul("MyValue"));
        // CapturedDataSize(u16) + CapturedData (UTF-16LE "hello")
        let captured = utf16_nul("hello");
        data.extend_from_slice(&(captured.len() as u16).to_le_bytes());
        data.extend_from_slice(&captured);

        let mut r = UserDataReader::new(&data, 8);
        let _key_obj = r.read_pointer().unwrap();
        let _status = r.read_u32().unwrap();
        let reg_type = r.read_u32().unwrap();
        let _data_size = r.read_u32().unwrap();
        let key = r.read_utf16_nul();
        let value_name = r.read_utf16_nul();
        // CapturedData
        let cap_size = r.read_u16().unwrap() as usize;
        let value_data = r.read_utf16_bytes(cap_size);

        assert_eq!(reg_type, 1); // REG_SZ
        assert_eq!(key, r"HKLM\SOFTWARE\Test");
        assert_eq!(value_name, "MyValue");
        assert_eq!(value_data, "hello");
    }

    // --- DNS: QueryCompleted with response -----------------------------------

    #[test]
    fn fixture_dns_query_completed_with_response() {
        // DNS-Client event 3008 (QueryCompleted):
        //   QueryName(wstr), QueryType(u16), QueryOptions(u32),
        //   QueryStatus(u32), QueryResults(wstr)
        let mut data = utf16_nul("evil.example.com");
        data.extend_from_slice(&1u16.to_le_bytes()); // QueryType = A
        data.extend_from_slice(&0u32.to_le_bytes()); // QueryOptions
        data.extend_from_slice(&0u32.to_le_bytes()); // QueryStatus = SUCCESS
        data.extend_from_slice(&utf16_nul("1.2.3.4;5.6.7.8"));

        let mut r = UserDataReader::new(&data, 8);
        let query_name = r.read_utf16_nul();
        let query_type = r.read_u16().unwrap();
        let _options = r.read_u32().unwrap();
        let status = r.read_u32().unwrap();
        let response = if status == 0 && r.remaining() > 0 {
            let s = r.read_utf16_nul();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        };

        assert_eq!(query_name, "evil.example.com");
        assert_eq!(dns_query_type_name(query_type), "A");
        assert_eq!(status, 0);
        assert_eq!(response, Some("1.2.3.4;5.6.7.8".into()));
    }

    #[test]
    fn fixture_dns_query_completed_no_response() {
        // DNS-Client event 3008 with failed status (no results)
        let mut data = utf16_nul("nx.example.com");
        data.extend_from_slice(&1u16.to_le_bytes()); // QueryType = A
        data.extend_from_slice(&0u32.to_le_bytes()); // QueryOptions
        data.extend_from_slice(&0x2328u32.to_le_bytes()); // QueryStatus = DNS_ERROR_RCODE_NXDOMAIN (9003)

        let mut r = UserDataReader::new(&data, 8);
        let query_name = r.read_utf16_nul();
        let _query_type = r.read_u16().unwrap();
        let _options = r.read_u32().unwrap();
        let status = r.read_u32().unwrap();
        let response = if status == 0 && r.remaining() > 0 {
            let s = r.read_utf16_nul();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        };

        assert_eq!(query_name, "nx.example.com");
        assert_ne!(status, 0);
        assert!(response.is_none());
    }

    // --- File: SetInfo (ID 13) and Rename (ID 14) ----------------------------

    #[test]
    fn fixture_file_setinfo_payload() {
        // Kernel-File event ID 13 (SetInfo):
        //   IrpPtr(ptr), FileObject(ptr), TTID(u32), InfoClass(u32),
        //   FileName(wstr)
        let mut data = Vec::new();
        data.extend_from_slice(&0xFFFF_0000u64.to_le_bytes()); // IrpPtr
        data.extend_from_slice(&0xAAAA_0000u64.to_le_bytes()); // FileObject
        data.extend_from_slice(&100u32.to_le_bytes()); // TTID
        data.extend_from_slice(&4u32.to_le_bytes()); // InfoClass
        data.extend_from_slice(&utf16_nul(r"C:\Users\Admin\file.txt"));

        let mut r = UserDataReader::new(&data, 8);
        let _irp = r.read_pointer().unwrap();
        let _fobj = r.read_pointer().unwrap();
        let _ttid = r.read_u32().unwrap();
        let _info_class = r.read_u32().unwrap();
        let path = r.read_utf16_nul();

        assert_eq!(path, r"C:\Users\Admin\file.txt");
    }

    #[test]
    fn fixture_file_rename_payload() {
        // Kernel-File event ID 14 (Rename):
        //   IrpPtr(ptr), FileObject(ptr), TTID(u32), InfoClass(u32),
        //   FileName(wstr)
        let mut data = Vec::new();
        data.extend_from_slice(&0xBBBB_0000u64.to_le_bytes()); // IrpPtr
        data.extend_from_slice(&0xCCCC_0000u64.to_le_bytes()); // FileObject
        data.extend_from_slice(&200u32.to_le_bytes()); // TTID
        data.extend_from_slice(&10u32.to_le_bytes()); // InfoClass (FileRenameInformation)
        data.extend_from_slice(&utf16_nul(r"C:\Users\Admin\renamed.txt"));

        let mut r = UserDataReader::new(&data, 8);
        let _irp = r.read_pointer().unwrap();
        let _fobj = r.read_pointer().unwrap();
        let _ttid = r.read_u32().unwrap();
        let _info_class = r.read_u32().unwrap();
        let path = r.read_utf16_nul();

        assert_eq!(path, r"C:\Users\Admin\renamed.txt");
    }

    // --- TI: SuspendThread (ID 9) / ResumeThread (ID 10) --------------------

    #[test]
    fn fixture_ti_suspend_thread_remote() {
        // TI event ID 9: common header + target header + TargetThreadId(u32)
        let mut data = build_ti_common_header(300, 301);
        data.extend(build_ti_target_header(400));
        data.extend_from_slice(&5555u32.to_le_bytes()); // TargetThreadId

        let mut r = UserDataReader::new(&data, 8);
        // Common
        let calling_pid = r.read_pointer().unwrap() as u32;
        let _ct = r.read_u64().unwrap();
        let _sk = r.read_u64().unwrap();
        let _sl = r.read_u8().unwrap();
        let _ssl = r.read_u8().unwrap();
        let _p = r.read_u8().unwrap();
        let _tid = r.read_u32().unwrap();
        let _tct = r.read_u64().unwrap();
        // Target
        let target_pid = r.read_pointer().unwrap() as u32;
        let _tc = r.read_u64().unwrap();
        let _tk = r.read_u64().unwrap();
        let _tsl = r.read_u8().unwrap();
        let _tssl = r.read_u8().unwrap();
        let _tp = r.read_u8().unwrap();
        // Event-specific
        let target_tid = r.read_u32().unwrap();

        assert_eq!(calling_pid, 300);
        assert_eq!(target_pid, 400);
        assert_eq!(target_tid, 5555);
    }

    #[test]
    fn fixture_ti_resume_thread_remote() {
        // TI event ID 10: same layout as ID 9
        let mut data = build_ti_common_header(600, 601);
        data.extend(build_ti_target_header(700));
        data.extend_from_slice(&7777u32.to_le_bytes()); // TargetThreadId

        let mut r = UserDataReader::new(&data, 8);
        let calling_pid = r.read_pointer().unwrap() as u32;
        let _ct = r.read_u64().unwrap();
        let _sk = r.read_u64().unwrap();
        let _sl = r.read_u8().unwrap();
        let _ssl = r.read_u8().unwrap();
        let _p = r.read_u8().unwrap();
        let _tid = r.read_u32().unwrap();
        let _tct = r.read_u64().unwrap();
        let target_pid = r.read_pointer().unwrap() as u32;
        let _tc = r.read_u64().unwrap();
        let _tk = r.read_u64().unwrap();
        let _tsl = r.read_u8().unwrap();
        let _tssl = r.read_u8().unwrap();
        let _tp = r.read_u8().unwrap();
        let target_tid = r.read_u32().unwrap();

        assert_eq!(calling_pid, 600);
        assert_eq!(target_pid, 700);
        assert_eq!(target_tid, 7777);
    }

    // --- UserDataReader: remaining() and read_utf16_bytes() ------------------

    #[test]
    fn remaining_tracks_correctly() {
        let data = [0u8; 16];
        let mut r = UserDataReader::new(&data, 8);
        assert_eq!(r.remaining(), 16);
        r.read_u32().unwrap();
        assert_eq!(r.remaining(), 12);
        r.read_u64().unwrap();
        assert_eq!(r.remaining(), 4);
    }

    #[test]
    fn read_utf16_bytes_fixed_length() {
        // "AB" in UTF-16LE = [0x41, 0x00, 0x42, 0x00]
        let data = [0x41, 0x00, 0x42, 0x00, 0x43, 0x00];
        let mut r = UserDataReader::new(&data, 8);
        let s = r.read_utf16_bytes(4); // read 4 bytes = 2 chars
        assert_eq!(s, "AB");
        assert_eq!(r.remaining(), 2);
    }

    // =========================================================================
    // Edge-case fixture tests: Unicode, long paths, boundary values, 32-bit
    // =========================================================================

    // --- ProcessCreate with CJK/Unicode command line -------------------------

    #[test]
    fn fixture_process_create_unicode_cmdline() {
        let mut data = Vec::new();
        data.extend_from_slice(&42u32.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&utf16_nul(r"C:\Program Files\ツール\app.exe"));
        data.extend_from_slice(&utf16_nul("app.exe --name=日本語テスト --flag=αβγ"));

        let mut r = UserDataReader::new(&data, 8);
        let pid = r.read_u32().unwrap();
        let _ct = r.read_u64().unwrap();
        let _ppid = r.read_u32().unwrap();
        let _sid = r.read_u32().unwrap();
        let _flags = r.read_u32().unwrap();
        let image = r.read_utf16_nul();
        let cmdline = r.read_utf16_nul();

        assert_eq!(pid, 42);
        assert!(image.contains("ツール"));
        assert!(cmdline.contains("日本語テスト"));
        assert!(cmdline.contains("αβγ"));
    }

    // --- ProcessCreate with very long path (> 260 chars) ---------------------

    #[test]
    fn fixture_process_create_long_path() {
        let long_dir = "A".repeat(250);
        let long_path = format!(r"C:\Users\Admin\{long_dir}\deeply\nested\app.exe");
        assert!(long_path.len() > 260);

        let mut data = Vec::new();
        data.extend_from_slice(&99u32.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&utf16_nul(&long_path));
        data.extend_from_slice(&utf16_nul("app.exe"));

        let mut r = UserDataReader::new(&data, 8);
        let _pid = r.read_u32().unwrap();
        let _ct = r.read_u64().unwrap();
        let _ppid = r.read_u32().unwrap();
        let _sid = r.read_u32().unwrap();
        let _flags = r.read_u32().unwrap();
        let image = r.read_utf16_nul();
        let cmdline = r.read_utf16_nul();

        assert_eq!(image, long_path);
        assert_eq!(cmdline, "app.exe");
    }

    // --- ImageLoad on 32-bit with Unicode filename ---------------------------

    #[test]
    fn fixture_image_load_32bit_unicode() {
        let mut data = Vec::new();
        data.extend_from_slice(&300u32.to_le_bytes());
        data.extend_from_slice(&0x1000_0000u32.to_le_bytes()); // ImageBase (32-bit)
        data.extend_from_slice(&0x0004_0000u32.to_le_bytes()); // ImageSize (32-bit)
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0x1000_0000u32.to_le_bytes()); // DefaultBase (32-bit)
        data.push(4); // SignatureLevel (Authenticode)
        data.push(1); // SignatureType (Embedded)
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&utf16_nul(r"C:\プログラム\テスト.dll"));

        let mut r = UserDataReader::new(&data, 4);
        let pid = r.read_u32().unwrap();
        let _base = r.read_pointer().unwrap();
        let _size = r.read_pointer().unwrap();
        let _chk = r.read_u32().unwrap();
        let _ts = r.read_u32().unwrap();
        let _db = r.read_pointer().unwrap();
        let sig_level = r.read_u8().unwrap();
        let sig_type = r.read_u8().unwrap();
        r.skip(2);
        let file_name = r.read_utf16_nul();

        assert_eq!(pid, 300);
        assert!(sig_level >= 4, "signed");
        assert_eq!(sig_type, 1);
        let image_name = file_name.rsplit('\\').next().unwrap_or(&file_name);
        assert_eq!(image_name, "テスト.dll");
    }

    // --- ImageLoad with no backslash (bare filename) -------------------------

    #[test]
    fn fixture_image_load_bare_filename() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0x0040_0000u64.to_le_bytes());
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.push(0);
        data.push(0);
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&utf16_nul("shellcode.bin"));

        let mut r = UserDataReader::new(&data, 8);
        let _pid = r.read_u32().unwrap();
        let _base = r.read_pointer().unwrap();
        let _size = r.read_pointer().unwrap();
        let _chk = r.read_u32().unwrap();
        let _ts = r.read_u32().unwrap();
        let _db = r.read_pointer().unwrap();
        let sig_level = r.read_u8().unwrap();
        let _sig_type = r.read_u8().unwrap();
        r.skip(2);
        let file_name = r.read_utf16_nul();

        assert!(sig_level < 4, "unsigned");
        // No backslash → image_name == full path
        let image_name = file_name.rsplit('\\').next().unwrap_or(&file_name);
        assert_eq!(image_name, "shellcode.bin");
        assert_eq!(image_name, file_name);
    }

    // --- File NameCreate (ID 10) with long UNC path --------------------------

    #[test]
    fn fixture_file_name_create_unc_path() {
        let unc_path = format!(r"\\?\UNC\server\share\{}\file.dat", "subdir\\".repeat(40));
        let mut data = Vec::new();
        data.extend_from_slice(&0xDEAD_BEEFu64.to_le_bytes()); // FileObject
        data.extend_from_slice(&utf16_nul(&unc_path));

        let mut r = UserDataReader::new(&data, 8);
        let _fobj = r.read_pointer().unwrap();
        let path = r.read_utf16_nul();

        assert!(path.starts_with(r"\\?\UNC\server\share\"));
        assert!(path.ends_with("file.dat"));
        assert!(path.len() > 260);
    }

    // --- File Rename (ID 14) 32-bit pointers ---------------------------------

    #[test]
    fn fixture_file_rename_32bit() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xAAAA_0000u32.to_le_bytes()); // IrpPtr (32-bit)
        data.extend_from_slice(&0xBBBB_0000u32.to_le_bytes()); // FileObject (32-bit)
        data.extend_from_slice(&500u32.to_le_bytes());
        data.extend_from_slice(&10u32.to_le_bytes());
        data.extend_from_slice(&utf16_nul(r"D:\Data\old_name.log"));

        let mut r = UserDataReader::new(&data, 4);
        let _irp = r.read_pointer().unwrap();
        let _fobj = r.read_pointer().unwrap();
        let _ttid = r.read_u32().unwrap();
        let _info_class = r.read_u32().unwrap();
        let path = r.read_utf16_nul();

        assert_eq!(path, r"D:\Data\old_name.log");
    }

    // --- Registry OpenKey (ID 2): no Disposition field -----------------------

    #[test]
    fn fixture_registry_open_key_payload() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xF000u64.to_le_bytes()); // BaseObject
        data.extend_from_slice(&0xF001u64.to_le_bytes()); // KeyObject
        data.extend_from_slice(&0u32.to_le_bytes()); // Status
                                                     // No Disposition for OpenKey (ID 2) — unlike CreateKey (ID 1)
        data.extend_from_slice(&utf16_nul(r"\REGISTRY\MACHINE\SYSTEM"));
        data.extend_from_slice(&utf16_nul(r"CurrentControlSet\Services\LanmanServer"));

        let mut r = UserDataReader::new(&data, 8);
        let _base = r.read_pointer().unwrap();
        let _key = r.read_pointer().unwrap();
        let _status = r.read_u32().unwrap();
        let base_name = r.read_utf16_nul();
        let rel_name = r.read_utf16_nul();

        let key = format!("{base_name}\\{rel_name}");
        assert_eq!(
            key,
            r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer"
        );
    }

    // --- Registry SetValue with REG_DWORD (no captured string data) ----------

    #[test]
    fn fixture_registry_set_value_dword_no_capture() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x5678u64.to_le_bytes()); // KeyObject
        data.extend_from_slice(&0u32.to_le_bytes()); // Status
        data.extend_from_slice(&4u32.to_le_bytes()); // Type (REG_DWORD)
        data.extend_from_slice(&4u32.to_le_bytes()); // DataSize
        data.extend_from_slice(&utf16_nul(r"HKLM\SOFTWARE\App"));
        data.extend_from_slice(&utf16_nul("EnableFeature"));
        // CapturedDataSize present but type is DWORD → parser should skip
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes()); // raw DWORD value

        let mut r = UserDataReader::new(&data, 8);
        let _key_obj = r.read_pointer().unwrap();
        let _status = r.read_u32().unwrap();
        let reg_type = r.read_u32().unwrap();
        let _data_size = r.read_u32().unwrap();
        let key = r.read_utf16_nul();
        let value_name = r.read_utf16_nul();

        // For REG_DWORD (type=4), the parser should NOT attempt UTF-16 decode
        let vd = if matches!(reg_type, 1 | 2) {
            if let Some(cap_size) = r.read_u16() {
                let cap = cap_size as usize;
                if cap > 0 && r.remaining() >= cap {
                    Some(r.read_utf16_bytes(cap))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        assert_eq!(reg_type, 4);
        assert_eq!(key, r"HKLM\SOFTWARE\App");
        assert_eq!(value_name, "EnableFeature");
        assert!(
            vd.is_none(),
            "REG_DWORD should not produce string value_data"
        );
    }

    // --- Registry SetValue with empty CapturedData ---------------------------

    #[test]
    fn fixture_registry_set_value_empty_captured_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x9999u64.to_le_bytes()); // KeyObject
        data.extend_from_slice(&0u32.to_le_bytes()); // Status
        data.extend_from_slice(&1u32.to_le_bytes()); // REG_SZ
        data.extend_from_slice(&0u32.to_le_bytes()); // DataSize=0
        data.extend_from_slice(&utf16_nul(r"HKLM\SOFTWARE\Empty"));
        data.extend_from_slice(&utf16_nul("EmptyVal"));
        // CapturedDataSize=0
        data.extend_from_slice(&0u16.to_le_bytes());

        let mut r = UserDataReader::new(&data, 8);
        let _key_obj = r.read_pointer().unwrap();
        let _status = r.read_u32().unwrap();
        let reg_type = r.read_u32().unwrap();
        let _data_size = r.read_u32().unwrap();
        let _key = r.read_utf16_nul();
        let _value_name = r.read_utf16_nul();

        let vd = if matches!(reg_type, 1 | 2) {
            if let Some(cap_size) = r.read_u16() {
                let cap = cap_size as usize;
                if cap > 0 && r.remaining() >= cap {
                    Some(r.read_utf16_bytes(cap))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        assert!(vd.is_none(), "empty CapturedData should yield None");
    }

    // --- Registry SetValue with Unicode value data ---------------------------

    #[test]
    fn fixture_registry_set_value_unicode_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1111u64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes()); // REG_SZ
        data.extend_from_slice(&100u32.to_le_bytes());
        data.extend_from_slice(&utf16_nul(r"HKLM\SOFTWARE\Intl"));
        data.extend_from_slice(&utf16_nul("DisplayName"));
        let captured = utf16_nul("日本語の値データ");
        data.extend_from_slice(&(captured.len() as u16).to_le_bytes());
        data.extend_from_slice(&captured);

        let mut r = UserDataReader::new(&data, 8);
        let _key_obj = r.read_pointer().unwrap();
        let _status = r.read_u32().unwrap();
        let reg_type = r.read_u32().unwrap();
        let _data_size = r.read_u32().unwrap();
        let _key = r.read_utf16_nul();
        let _value_name = r.read_utf16_nul();
        let cap_size = r.read_u16().unwrap() as usize;
        let vd = r.read_utf16_bytes(cap_size);

        assert_eq!(reg_type, 1);
        assert_eq!(vd, "日本語の値データ");
    }

    // --- DNS QueryCompleted with AAAA record type ----------------------------

    #[test]
    fn fixture_dns_query_completed_aaaa() {
        let mut data = utf16_nul("ipv6.example.com");
        data.extend_from_slice(&28u16.to_le_bytes()); // AAAA
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // SUCCESS
        data.extend_from_slice(&utf16_nul("2001:db8::1"));

        let mut r = UserDataReader::new(&data, 8);
        let name = r.read_utf16_nul();
        let qtype = r.read_u16().unwrap();
        let _opts = r.read_u32().unwrap();
        let status = r.read_u32().unwrap();
        let resp = if status == 0 && r.remaining() > 0 {
            let s = r.read_utf16_nul();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        };

        assert_eq!(name, "ipv6.example.com");
        assert_eq!(dns_query_type_name(qtype), "AAAA");
        assert_eq!(resp, Some("2001:db8::1".into()));
    }

    // --- DNS QueryCompleted with multi-answer response -----------------------

    #[test]
    fn fixture_dns_query_completed_multi_answer() {
        // Windows DNS-Client separates multiple answers with semicolons
        let mut data = utf16_nul("cdn.example.com");
        data.extend_from_slice(&1u16.to_le_bytes()); // A
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&utf16_nul("10.0.0.1;10.0.0.2;10.0.0.3;10.0.0.4"));

        let mut r = UserDataReader::new(&data, 8);
        let _name = r.read_utf16_nul();
        let _qtype = r.read_u16().unwrap();
        let _opts = r.read_u32().unwrap();
        let status = r.read_u32().unwrap();
        let resp = if status == 0 && r.remaining() > 0 {
            let s = r.read_utf16_nul();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        };

        let resp = resp.unwrap();
        let answers: Vec<&str> = resp.split(';').collect();
        assert_eq!(answers.len(), 4);
        assert_eq!(answers[0], "10.0.0.1");
        assert_eq!(answers[3], "10.0.0.4");
    }

    // --- DNS QueryCompleted with empty result string -------------------------

    #[test]
    fn fixture_dns_query_completed_empty_result() {
        // Status=0 but QueryResults is an empty string
        let mut data = utf16_nul("empty.example.com");
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // SUCCESS
        data.extend_from_slice(&utf16_nul("")); // empty result string

        let mut r = UserDataReader::new(&data, 8);
        let _name = r.read_utf16_nul();
        let _qtype = r.read_u16().unwrap();
        let _opts = r.read_u32().unwrap();
        let status = r.read_u32().unwrap();
        let resp = if status == 0 && r.remaining() > 0 {
            let s = r.read_utf16_nul();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        } else {
            None
        };

        assert_eq!(status, 0);
        assert!(resp.is_none(), "empty result string should be None");
    }

    // --- DNS QueryInitiated with IDN/Unicode domain --------------------------

    #[test]
    fn fixture_dns_query_unicode_domain() {
        let mut data = utf16_nul("例え.jp");
        data.extend_from_slice(&1u16.to_le_bytes()); // A

        let mut r = UserDataReader::new(&data, 8);
        let name = r.read_utf16_nul();
        let qtype = r.read_u16().unwrap();

        assert_eq!(name, "例え.jp");
        assert_eq!(dns_query_type_name(qtype), "A");
    }

    // --- TI ALLOCVM_REMOTE 32-bit (ptr_size=4) -------------------------------

    fn build_ti_common_header_32(calling_pid: u32, calling_tid: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        // CallingProcessId is win:Pointer (4 bytes on 32-bit)
        buf.extend_from_slice(&calling_pid.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.push(6);
        buf.push(6);
        buf.push(0x31);
        buf.extend_from_slice(&calling_tid.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf
    }

    fn build_ti_target_header_32(target_pid: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&target_pid.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.push(0);
        buf.push(0);
        buf.push(0);
        buf
    }

    #[test]
    fn fixture_ti_allocvm_remote_32bit() {
        let mut data = build_ti_common_header_32(100, 200);
        data.extend(build_ti_target_header_32(999));
        data.extend_from_slice(&0x1000_0000u32.to_le_bytes()); // BaseAddress (32-bit)
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // RegionSize (32-bit)
        data.extend_from_slice(&0x3000u32.to_le_bytes()); // AllocationType
        data.extend_from_slice(&0x40u32.to_le_bytes()); // Protection

        let mut r = UserDataReader::new(&data, 4);
        let calling_pid = r.read_pointer().unwrap() as u32;
        let _ct = r.read_u64().unwrap();
        let _sk = r.read_u64().unwrap();
        let _sl = r.read_u8().unwrap();
        let _ssl = r.read_u8().unwrap();
        let _p = r.read_u8().unwrap();
        let _tid = r.read_u32().unwrap();
        let _tct = r.read_u64().unwrap();
        let target_pid = r.read_pointer().unwrap() as u32;
        let _tc = r.read_u64().unwrap();
        let _tk = r.read_u64().unwrap();
        let _tsl = r.read_u8().unwrap();
        let _tssl = r.read_u8().unwrap();
        let _tp = r.read_u8().unwrap();
        let base = r.read_pointer().unwrap();
        let size = r.read_pointer().unwrap();
        let _alloc = r.read_u32().unwrap();
        let prot = r.read_u32().unwrap();

        assert_eq!(calling_pid, 100);
        assert_eq!(target_pid, 999);
        assert_eq!(base, 0x1000_0000);
        assert_eq!(size, 0x2000);
        assert_eq!(prot, 0x40);
    }

    // --- TI MAPVIEW_REMOTE (ID 3) --------------------------------------------

    #[test]
    fn fixture_ti_mapview_remote() {
        let mut data = build_ti_common_header(200, 201);
        data.extend(build_ti_target_header(300));
        data.extend_from_slice(&0x7FFE_0000_0000u64.to_le_bytes()); // BaseAddress
        data.extend_from_slice(&0x0010_0000u64.to_le_bytes()); // ViewSize
        data.extend_from_slice(&0x08000000u32.to_le_bytes()); // AllocationType (SEC_IMAGE)
        data.extend_from_slice(&0x02u32.to_le_bytes()); // Protection (PAGE_READONLY)

        let mut r = UserDataReader::new(&data, 8);
        let calling_pid = r.read_pointer().unwrap() as u32;
        let _ct = r.read_u64().unwrap();
        let _sk = r.read_u64().unwrap();
        let _sl = r.read_u8().unwrap();
        let _ssl = r.read_u8().unwrap();
        let _p = r.read_u8().unwrap();
        let _tid = r.read_u32().unwrap();
        let _tct = r.read_u64().unwrap();
        let target_pid = r.read_pointer().unwrap() as u32;
        let _tc = r.read_u64().unwrap();
        let _tk = r.read_u64().unwrap();
        let _tsl = r.read_u8().unwrap();
        let _tssl = r.read_u8().unwrap();
        let _tp = r.read_u8().unwrap();
        let base = r.read_pointer().unwrap();
        let size = r.read_pointer().unwrap();
        let alloc_type = r.read_u32().unwrap();
        let prot = r.read_u32().unwrap();

        assert_eq!(calling_pid, 200);
        assert_eq!(target_pid, 300);
        assert_eq!(base, 0x7FFE_0000_0000);
        assert_eq!(size, 0x0010_0000);
        assert_eq!(alloc_type, 0x08000000); // SEC_IMAGE
        assert_eq!(prot, 0x02);
    }

    // --- TI PROTECTVM_LOCAL (ID 7) -------------------------------------------

    #[test]
    fn fixture_ti_protectvm_local() {
        let mut data = build_ti_common_header(4000, 4001);
        // No target header for local events
        data.extend_from_slice(&0x0040_0000u64.to_le_bytes()); // BaseAddress
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // RegionSize
        data.extend_from_slice(&0x20u32.to_le_bytes()); // PAGE_EXECUTE_READ
        data.extend_from_slice(&0x04u32.to_le_bytes()); // Old: PAGE_READWRITE

        let mut r = UserDataReader::new(&data, 8);
        let calling_pid = r.read_pointer().unwrap() as u32;
        let _ct = r.read_u64().unwrap();
        let _sk = r.read_u64().unwrap();
        let _sl = r.read_u8().unwrap();
        let _ssl = r.read_u8().unwrap();
        let _p = r.read_u8().unwrap();
        let _tid = r.read_u32().unwrap();
        let _tct = r.read_u64().unwrap();
        // No target header — go straight to event-specific
        let base = r.read_pointer().unwrap();
        let size = r.read_pointer().unwrap();
        let new_prot = r.read_u32().unwrap();
        let old_prot = r.read_u32().unwrap();

        assert_eq!(calling_pid, 4000);
        assert_eq!(base, 0x0040_0000);
        assert_eq!(size, 0x1000);
        assert_eq!(new_prot, 0x20); // PAGE_EXECUTE_READ
        assert_eq!(old_prot, 0x04); // PAGE_READWRITE
    }

    // --- TI MAPVIEW_LOCAL (ID 8) ---------------------------------------------

    #[test]
    fn fixture_ti_mapview_local() {
        let mut data = build_ti_common_header(5000, 5001);
        data.extend_from_slice(&0x7FF8_0000_0000u64.to_le_bytes());
        data.extend_from_slice(&0x0020_0000u64.to_le_bytes());
        data.extend_from_slice(&0x08000000u32.to_le_bytes()); // SEC_IMAGE
        data.extend_from_slice(&0x20u32.to_le_bytes()); // PAGE_EXECUTE_READ

        let mut r = UserDataReader::new(&data, 8);
        let calling_pid = r.read_pointer().unwrap() as u32;
        let _ct = r.read_u64().unwrap();
        let _sk = r.read_u64().unwrap();
        let _sl = r.read_u8().unwrap();
        let _ssl = r.read_u8().unwrap();
        let _p = r.read_u8().unwrap();
        let _tid = r.read_u32().unwrap();
        let _tct = r.read_u64().unwrap();
        let base = r.read_pointer().unwrap();
        let size = r.read_pointer().unwrap();
        let alloc_type = r.read_u32().unwrap();
        let prot = r.read_u32().unwrap();

        assert_eq!(calling_pid, 5000);
        assert_eq!(base, 0x7FF8_0000_0000);
        assert_eq!(size, 0x0020_0000);
        assert_eq!(alloc_type, 0x08000000);
        assert_eq!(prot, 0x20);
    }

    // --- TI with max PID values (boundary) -----------------------------------

    #[test]
    fn fixture_ti_max_pid_boundary() {
        // PID values near u32::MAX edge — verify no truncation issues
        let mut data = build_ti_common_header(u32::MAX - 1, u32::MAX);
        data.extend(build_ti_target_header(u32::MAX));
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // BaseAddress
        data.extend_from_slice(&0x1000u64.to_le_bytes()); // RegionSize
        data.extend_from_slice(&0x3000u32.to_le_bytes()); // AllocationType
        data.extend_from_slice(&0x40u32.to_le_bytes()); // Protection

        let mut r = UserDataReader::new(&data, 8);
        let calling_pid = r.read_pointer().unwrap() as u32;
        let _ct = r.read_u64().unwrap();
        let _sk = r.read_u64().unwrap();
        let _sl = r.read_u8().unwrap();
        let _ssl = r.read_u8().unwrap();
        let _p = r.read_u8().unwrap();
        let calling_tid = r.read_u32().unwrap();
        let _tct = r.read_u64().unwrap();
        let target_pid = r.read_pointer().unwrap() as u32;

        assert_eq!(calling_pid, u32::MAX - 1);
        assert_eq!(calling_tid, u32::MAX);
        assert_eq!(target_pid, u32::MAX);
    }

    // --- Empty UserData graceful handling ------------------------------------

    #[test]
    fn empty_user_data_reader() {
        let data: &[u8] = &[];
        let mut r = UserDataReader::new(data, 8);
        assert_eq!(r.remaining(), 0);
        assert_eq!(r.read_u8(), None);
        assert_eq!(r.read_u16(), None);
        assert_eq!(r.read_u32(), None);
        assert_eq!(r.read_u64(), None);
        assert_eq!(r.read_pointer(), None);
        assert_eq!(r.read_ipv4(), None);
        assert_eq!(r.read_ipv6(), None);
        assert_eq!(r.read_utf16_nul(), "");
        assert_eq!(r.read_utf16_bytes(0), "");
    }

    // --- read_utf16_bytes with odd byte count --------------------------------

    #[test]
    fn read_utf16_bytes_odd_count() {
        // 5 bytes: "A\0B\0" + trailing 0x43 (odd, not a full u16)
        let data = [0x41, 0x00, 0x42, 0x00, 0x43];
        let mut r = UserDataReader::new(&data, 8);
        // Reading 5 bytes: chunks_exact(2) will produce "AB", dropping byte 0x43
        let s = r.read_utf16_bytes(5);
        assert_eq!(s, "AB");
        assert_eq!(r.remaining(), 0);
    }

    // --- Network: all-zeros IP address (0.0.0.0) -----------------------------

    #[test]
    fn fixture_tcp_ipv4_zero_addr() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // PID=0 (System)
        data.extend_from_slice(&0u32.to_le_bytes()); // Size
        data.extend_from_slice(&[0, 0, 0, 0]); // DstAddr: 0.0.0.0
        data.extend_from_slice(&[0, 0, 0, 0]); // SrcAddr: 0.0.0.0
        data.extend_from_slice(&0u16.to_be_bytes()); // DstPort=0
        data.extend_from_slice(&0u16.to_be_bytes()); // SrcPort=0

        let mut r = UserDataReader::new(&data, 8);
        let _pid = r.read_u32().unwrap();
        let _size = r.read_u32().unwrap();
        let dst = r.read_ipv4().unwrap();
        let src = r.read_ipv4().unwrap();
        let dp = r.read_u16_be().unwrap();
        let sp = r.read_u16_be().unwrap();

        assert_eq!(dst, "0.0.0.0");
        assert_eq!(src, "0.0.0.0");
        assert_eq!(dp, 0);
        assert_eq!(sp, 0);
    }

    // --- Network: max port numbers (65535) -----------------------------------

    #[test]
    fn fixture_tcp_ipv4_max_ports() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&[255, 255, 255, 255]); // 255.255.255.255
        data.extend_from_slice(&[127, 0, 0, 1]); // 127.0.0.1
        data.extend_from_slice(&65535u16.to_be_bytes());
        data.extend_from_slice(&65535u16.to_be_bytes());

        let mut r = UserDataReader::new(&data, 8);
        let _pid = r.read_u32().unwrap();
        let _size = r.read_u32().unwrap();
        let dst = r.read_ipv4().unwrap();
        let src = r.read_ipv4().unwrap();
        let dp = r.read_u16_be().unwrap();
        let sp = r.read_u16_be().unwrap();

        assert_eq!(dst, "255.255.255.255");
        assert_eq!(src, "127.0.0.1");
        assert_eq!(dp, 65535);
        assert_eq!(sp, 65535);
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::*;
    use crate::events::{CollectorState, EventData};

    /// Run alone in an elevated, disposable Windows VM. Only a benign process
    /// is started; this is a real ETW integration check, not a detection test.
    #[tokio::test]
    #[ignore = "requires an elevated isolated Windows VM; see docs/SENSOR_HEALTH.md"]
    async fn windows_etw_process_smoke() {
        let mut config = EtwConfig::default();
        config
            .providers
            .retain(|p| p.name == "Microsoft-Windows-Kernel-Process");
        assert_eq!(config.providers.len(), 1);
        let agent = AgentInfo {
            hostname: "ETW-TEST".into(),
            agent_id: uuid::Uuid::new_v4(),
        };
        let mut collector = EtwCollector::new(config.clone(), agent.clone());
        let (tx, mut rx) = mpsc::channel(10_000);
        collector.start(tx.clone()).await.unwrap();
        let mut second = EtwCollector::new(config, agent);
        assert!(second.start(tx).await.is_err());
        // Stopping a failed second instance must not stop the active session.
        second.stop().await.unwrap();
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/C", "exit", "0"])
            .spawn()
            .unwrap();
        let child_pid = child.id();
        child.wait().unwrap();
        let observation = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while let Some(event) = rx.recv().await {
                if matches!(event.data, EventData::ProcessCreate { pid, .. } if pid == child_pid) {
                    return Some(event);
                }
            }
            None
        })
        .await;
        let live = collector.status().unwrap();
        collector.stop().await.unwrap();
        let final_status = collector.status().unwrap();
        let event = observation
            .ok()
            .flatten()
            .expect("expected the benign child process in real ETW telemetry");
        let origin = event
            .provenance
            .as_ref()
            .expect("missing native provenance");
        assert!(origin.original_time);
        assert!(origin.issues.is_empty(), "{:?}", origin.issues);
        assert_eq!(origin.provider_guid, super::super::etw_normalize::PROCESS);
        assert_eq!(origin.event_id, 1);
        assert!(!origin.fields.is_empty());
        assert!(
            (event.observed_at.unwrap() - event.timestamp)
                .num_seconds()
                .abs()
                < 30
        );
        assert!(
            matches!(event.data,EventData::ProcessCreate {image_path,create_time:Some(_),..}
            if image_path.to_ascii_lowercase().ends_with("cmd.exe"))
        );
        assert!(live.etw.is_some());
        assert!(live.statistics_error.is_none());
        assert!(live.providers.iter().all(|p| p.enabled));
        assert_eq!(final_status.state, CollectorState::Stopped);
        assert!(final_status.etw.is_some());
    }
}
