use anyhow::Result;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

use crate::config::EtwConfig;
use crate::events::ThreatEvent;

use super::Collector;

pub struct EtwCollector {
    config: EtwConfig,
    #[allow(dead_code)] // used on Windows only
    hostname: String,
    dropped: Arc<AtomicU64>,
    #[cfg(target_os = "windows")]
    stop_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    #[cfg(target_os = "windows")]
    instance_lock: Option<isize>,
}

impl EtwCollector {
    pub fn new(config: EtwConfig, hostname: String) -> Self {
        Self {
            config,
            hostname,
            dropped: Arc::new(AtomicU64::new(0)),
            #[cfg(target_os = "windows")]
            stop_flag: None,
            #[cfg(target_os = "windows")]
            instance_lock: None,
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
            let v = u32::from_le_bytes(
                self.data[self.pos..self.pos + 4].try_into().ok()?,
            );
            self.pos += 4;
            Some(v)
        }

        pub fn read_u64(&mut self) -> Option<u64> {
            if self.pos + 8 > self.data.len() {
                return None;
            }
            let v = u64::from_le_bytes(
                self.data[self.pos..self.pos + 8].try_into().ok()?,
            );
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
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9],
                b[10], b[11], b[12], b[13], b[14], b[15],
            ]);
            Some(addr.to_string())
        }

        /// Read a null-terminated UTF-16LE string (win:UnicodeString in ETW).
        pub fn read_utf16_nul(&mut self) -> String {
            let start = self.pos;
            while self.pos + 2 <= self.data.len() {
                let c = u16::from_le_bytes([
                    self.data[self.pos],
                    self.data[self.pos + 1],
                ]);
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

        /// Read exactly `n` bytes as UTF-16LE and decode (no null terminator).
        pub fn read_utf16_bytes(&mut self, n: usize) -> String {
            let end = (self.pos + n).min(self.data.len());
            let result = self.decode_utf16(self.pos, end);
            self.pos = end;
            result
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
    use super::parser::{UserDataReader, dns_query_type_name};
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
                    unsafe { let _ = CloseHandle(h); }
                    anyhow::bail!(
                        "Another ThreatFalcon instance is already running"
                    );
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

    /// Extract the UserData payload from an EVENT_RECORD as a byte slice.
    ///
    /// # Safety
    /// The EVENT_RECORD must contain a valid UserData pointer.
    unsafe fn user_data_slice<'a>(rec: &'a EVENT_RECORD) -> Option<&'a [u8]> {
        let ptr = rec.UserData as *const u8;
        let len = rec.UserDataLength as usize;
        if ptr.is_null() || len == 0 {
            return None;
        }
        Some(std::slice::from_raw_parts(ptr, len))
    }

    /// Determine pointer size from EVENT_HEADER flags.
    fn ptr_size(rec: &EVENT_RECORD) -> usize {
        const FLAG_32BIT: u16 = 0x0020;
        const FLAG_64BIT: u16 = 0x0040;
        let flags = rec.EventHeader.Flags;
        if flags & FLAG_64BIT != 0 {
            8
        } else if flags & FLAG_32BIT != 0 {
            4
        } else {
            8 // default to 64-bit on modern Windows
        }
    }

    // -----------------------------------------------------------------------
    // Existing session management (unchanged)
    // -----------------------------------------------------------------------

    fn parse_guid(s: &str) -> Result<GUID> {
        let s = s.trim_matches(|c| c == '{' || c == '}');
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 {
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
        hostname: String,
        tx: mpsc::Sender<ThreatEvent>,
        stop: Arc<AtomicBool>,
        dropped: Arc<AtomicU64>,
    }

    /// Start an ETW real-time trace session, enable the configured providers,
    /// and spawn a blocking thread that consumes events.
    ///
    /// Returns `(stop_flag, instance_lock_handle)`.  The caller must keep
    /// `instance_lock_handle` alive for the session's lifetime and pass it
    /// to `stop_session()` on shutdown.
    pub fn start_session(
        providers: &[crate::config::EtwProviderConfig],
        hostname: String,
        tx: mpsc::Sender<ThreatEvent>,
        dropped: Arc<AtomicU64>,
    ) -> Result<(Arc<AtomicBool>, isize)> {
        let stop = Arc::new(AtomicBool::new(false));

        // ---- multi-instance guard via named mutex ---------------------------
        let instance_lock = acquire_instance_lock()?;

        // ---- allocate EVENT_TRACE_PROPERTIES --------------------------------
        let session_name_wide: Vec<u16> = SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let init_props = |buf: &mut Vec<u8>| {
            let extra = session_name_wide.len() * 2;
            let total =
                std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + extra;
            buf.resize(total, 0);
            buf.fill(0);
            let props = unsafe {
                &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES)
            };
            props.Wnode.BufferSize = total as u32;
            props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            props.Wnode.ClientContext = 1; // QPC
            props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            props.LoggerNameOffset =
                std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            props
        };

        let mut buf = Vec::new();
        let props = init_props(&mut buf);

        // ---- start trace ----------------------------------------------------
        let mut handle = CONTROLTRACE_HANDLE::default();
        let mut status = unsafe {
            StartTraceW(
                &mut handle,
                windows::core::PCWSTR(session_name_wide.as_ptr()),
                props,
            )
        };

        // ERROR_ALREADY_EXISTS (183): a stale session from a previous crash.
        // We hold the named mutex, so no other live instance owns this
        // session — safe to stop and retry.
        if status.0 == 183 {
            tracing::warn!(
                "Stale ETW session found — stopping and retrying"
            );
            stop_trace();

            let props = init_props(&mut buf);
            status = unsafe {
                StartTraceW(
                    &mut handle,
                    windows::core::PCWSTR(session_name_wide.as_ptr()),
                    props,
                )
            };
        }

        if status != WIN32_ERROR(0) {
            anyhow::bail!("StartTraceW failed: {status:?}");
        }

        // ---- enable providers -----------------------------------------------
        for p in providers {
            let guid = parse_guid(&p.guid)?;
            let status = unsafe {
                EnableTraceEx2(
                    handle,
                    &guid,
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
        }

        // ---- consume events in a blocking thread ----------------------------
        let stop_clone = stop.clone();

        tokio::task::spawn_blocking(move || {
            let session_wide: Vec<u16> = SESSION_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let ctx = Box::new(CallbackContext {
                hostname,
                tx,
                stop: stop_clone,
                dropped,
            });
            let ctx_ptr = Box::into_raw(ctx);

            let mut logfile = EVENT_TRACE_LOGFILEW::default();
            logfile.LoggerName =
                windows::core::PWSTR(session_wide.as_ptr() as *mut u16);
            logfile.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME
                    | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Context = ctx_ptr as *mut std::ffi::c_void;
            logfile.Anonymous2.EventRecordCallback =
                Some(event_callback);

            let trace = unsafe { OpenTraceW(&mut logfile) };
            if trace.Value == u64::MAX {
                tracing::error!("OpenTraceW failed");
                unsafe {
                    drop(Box::from_raw(ctx_ptr));
                }
                return;
            }

            let status = unsafe { ProcessTrace(&[trace], None, None) };
            if status != WIN32_ERROR(0) {
                tracing::warn!(error = ?status, "ProcessTrace ended");
            }

            unsafe {
                let _ = CloseTrace(trace);
                drop(Box::from_raw(ctx_ptr));
            }
        });

        Ok((stop, instance_lock))
    }

    /// Stop the ETW trace (causes ProcessTrace to return) without releasing
    /// the instance lock.  Used internally for stale-session cleanup.
    fn stop_trace() {
        let session_name_wide: Vec<u16> = SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let total = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024;
        let mut buf = vec![0u8; total];
        let props =
            unsafe { &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
        props.Wnode.BufferSize = total as u32;

        unsafe {
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                windows::core::PCWSTR(session_name_wide.as_ptr()),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
    }

    /// Stop the ETW trace session and release the instance lock.
    pub fn stop_session(instance_lock: isize) {
        stop_trace();
        release_instance_lock(instance_lock);
    }

    // -----------------------------------------------------------------------
    // Event callback & mapping — now with UserData parsing
    // -----------------------------------------------------------------------

    unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
        let rec = unsafe { &*record };
        let ctx =
            unsafe { &*(rec.UserContext as *const CallbackContext) };

        if ctx.stop.load(Ordering::Relaxed) {
            return;
        }

        let pid = rec.EventHeader.ProcessId;
        let provider = rec.EventHeader.ProviderId;
        let event_id = rec.EventHeader.EventDescriptor.Id;

        let provider_name = provider_display_name(&provider);

        if let Some(event) =
            unsafe { map_event(rec, provider_name, event_id, pid, &ctx.hostname) }
        {
            if let Err(_) = ctx.tx.try_send(event) {
                let n = ctx.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_power_of_two() || n % 1000 == 0 {
                    tracing::warn!(
                        total_dropped = n,
                        "ETW events dropped due to channel backpressure"
                    );
                }
            }
        }
    }

    fn provider_display_name(guid: &GUID) -> &'static str {
        match guid.data1 {
            0x22FB2CD6 => "Microsoft-Windows-Kernel-Process",
            0xEDD08927 => "Microsoft-Windows-Kernel-File",
            0x7DD42A49 => "Microsoft-Windows-Kernel-Network",
            0x70EB4F03 => "Microsoft-Windows-Kernel-Registry",
            0x1C95126E => "Microsoft-Windows-DNS-Client",
            0xA0C1853B => "Microsoft-Windows-PowerShell",
            0x2A576B87 => "Microsoft-Antimalware-Scan-Interface",
            0xF4E1897C => "Microsoft-Windows-Threat-Intelligence",
            _ => "Unknown",
        }
    }

    /// Map SE_SIGNING_TYPE to a human-readable signer name.
    fn signature_type_name(sig_type: u8) -> String {
        match sig_type {
            0 => "None".into(),
            1 => "Embedded".into(),
            2 => "Cached".into(),
            3 => "CatalogCached".into(),
            4 => "CatalogNotCached".into(),
            5 => "CatalogHint".into(),
            6 => "PackageCatalog".into(),
            _ => format!("Type{sig_type}"),
        }
    }

    /// Map a raw ETW event into a `ThreatEvent`, parsing UserData payload.
    ///
    /// # Safety
    /// `rec` must point to a valid EVENT_RECORD with valid UserData.
    unsafe fn map_event(
        rec: &EVENT_RECORD,
        provider: &str,
        event_id: u16,
        pid: u32,
        hostname: &str,
    ) -> Option<ThreatEvent> {
        let data = unsafe { user_data_slice(rec) };
        let ps = ptr_size(rec);

        let (cat, sev, event_data) = match provider {
            // -----------------------------------------------------------
            // Kernel-Process
            // -----------------------------------------------------------
            "Microsoft-Windows-Kernel-Process" => match event_id {
                1 => {
                    // ProcessStart v2+: PID(u32), CreateTime(u64),
                    //   ParentPID(u32), SessionID(u32), Flags(u32),
                    //   ImageName(wstr), CommandLine(wstr)
                    let (process_id, ppid, image, cmdline) = data
                        .and_then(|d| {
                            let mut r = UserDataReader::new(d, ps);
                            let process_id = r.read_u32()?;
                            let _create_time = r.read_u64()?;
                            let ppid = r.read_u32()?;
                            let _session_id = r.read_u32()?;
                            let _flags = r.read_u32()?;
                            let image = r.read_utf16_nul();
                            let cmdline = r.read_utf16_nul();
                            Some((process_id, ppid, image, cmdline))
                        })
                        .unwrap_or((pid, 0, String::new(), String::new()));
                    (
                        EventCategory::Process,
                        Severity::Info,
                        EventData::ProcessCreate {
                            pid: process_id,
                            ppid,
                            image_path: image,
                            command_line: cmdline,
                            user: String::new(),
                            integrity_level: String::new(),
                            hashes: None,
                        },
                    )
                }
                2 => {
                    // ProcessStop: PID(u32), CreateTime(u64),
                    //   ExitTime(u64), ExitCode(u32), ImageName(wstr)
                    let (process_id, image) = data
                        .and_then(|d| {
                            let mut r = UserDataReader::new(d, ps);
                            let process_id = r.read_u32()?;
                            let _create_time = r.read_u64()?;
                            let _exit_time = r.read_u64()?;
                            let _exit_code = r.read_u32()?;
                            let image = r.read_utf16_nul();
                            Some((process_id, image))
                        })
                        .unwrap_or((pid, String::new()));
                    (
                        EventCategory::Process,
                        Severity::Info,
                        EventData::ProcessTerminate {
                            pid: process_id,
                            image_path: image,
                        },
                    )
                }
                5 => {
                    // ImageLoad: ProcessId(u32), ImageBase(ptr),
                    //   ImageSize(ptr), ImageCheckSum(u32),
                    //   TimeDateStamp(u32), DefaultBase(ptr),
                    //   SignatureLevel(u8), SignatureType(u8),
                    //   ...padding/flags..., FileName(wstr)
                    let (process_id, sig_level, sig_type, file_name) = data
                        .and_then(|d| {
                            let mut r = UserDataReader::new(d, ps);
                            let process_id = r.read_u32()?;
                            let _image_base = r.read_pointer()?;
                            let _image_size = r.read_pointer()?;
                            let _checksum = r.read_u32()?;
                            let _timestamp = r.read_u32()?;
                            let _default_base = r.read_pointer()?;
                            let sig_level = r.read_u8()?;
                            let sig_type = r.read_u8()?;
                            r.skip(2); // padding/flags
                            let file_name = r.read_utf16_nul();
                            Some((process_id, sig_level, sig_type, file_name))
                        })
                        .unwrap_or((pid, 0, 0, String::new()));
                    let image_name = file_name
                        .rsplit('\\')
                        .next()
                        .unwrap_or(&file_name)
                        .to_string();
                    // SE_SIGNING_LEVEL: 0=Unchecked, 1=Unsigned,
                    // 4+=Authenticode/Microsoft/Windows
                    let signed = sig_level >= 4;
                    let signature = if signed {
                        Some(signature_type_name(sig_type))
                    } else {
                        None
                    };
                    (
                        EventCategory::ImageLoad,
                        Severity::Info,
                        EventData::ImageLoad {
                            pid: process_id,
                            image_path: file_name,
                            image_name,
                            signed,
                            signature,
                            hashes: None,
                        },
                    )
                }
                _ => return None,
            },

            // -----------------------------------------------------------
            // Kernel-File
            // -----------------------------------------------------------
            "Microsoft-Windows-Kernel-File" => match event_id {
                10 => {
                    // NameCreate: FileObject(ptr), FileName(wstr)
                    let path = data
                        .and_then(|d| {
                            let mut r = UserDataReader::new(d, ps);
                            r.read_pointer()?;
                            Some(r.read_utf16_nul())
                        })
                        .unwrap_or_default();
                    (
                        EventCategory::File,
                        Severity::Info,
                        EventData::FileCreate {
                            pid,
                            path,
                            operation: FileOperation::Create,
                        },
                    )
                }
                11 => {
                    // NameDelete: FileObject(ptr), FileName(wstr)
                    let path = data
                        .and_then(|d| {
                            let mut r = UserDataReader::new(d, ps);
                            r.read_pointer()?;
                            Some(r.read_utf16_nul())
                        })
                        .unwrap_or_default();
                    (
                        EventCategory::File,
                        Severity::Info,
                        EventData::FileDelete { pid, path },
                    )
                }
                12 => {
                    // Create: IrpPtr(ptr), FileObject(ptr), TTID(u32),
                    //   CreateOptions(u32), CreateAttributes(u32),
                    //   ShareAccess(u32), OpenPath(wstr)
                    let path = data
                        .and_then(|d| {
                            let mut r = UserDataReader::new(d, ps);
                            r.read_pointer()?; // IrpPtr
                            r.read_pointer()?; // FileObject
                            r.read_u32()?; // TTID
                            r.read_u32()?; // CreateOptions
                            r.read_u32()?; // CreateAttributes
                            r.read_u32()?; // ShareAccess
                            Some(r.read_utf16_nul())
                        })
                        .unwrap_or_default();
                    (
                        EventCategory::File,
                        Severity::Info,
                        EventData::FileCreate {
                            pid,
                            path,
                            operation: FileOperation::Create,
                        },
                    )
                }
                13 => {
                    // SetInfo: IrpPtr(ptr), FileObject(ptr), TTID(u32),
                    //   InfoClass(u32), FileName(wstr)
                    let path = data
                        .and_then(|d| {
                            let mut r = UserDataReader::new(d, ps);
                            r.read_pointer()?; // IrpPtr
                            r.read_pointer()?; // FileObject
                            r.read_u32()?; // TTID
                            r.read_u32()?; // InfoClass
                            Some(r.read_utf16_nul())
                        })
                        .unwrap_or_default();
                    (
                        EventCategory::File,
                        Severity::Info,
                        EventData::FileCreate {
                            pid,
                            path,
                            operation: FileOperation::SetInfo,
                        },
                    )
                }
                14 => {
                    // Rename: IrpPtr(ptr), FileObject(ptr), TTID(u32),
                    //   InfoClass(u32), FileName(wstr)
                    let path = data
                        .and_then(|d| {
                            let mut r = UserDataReader::new(d, ps);
                            r.read_pointer()?; // IrpPtr
                            r.read_pointer()?; // FileObject
                            r.read_u32()?; // TTID
                            r.read_u32()?; // InfoClass
                            Some(r.read_utf16_nul())
                        })
                        .unwrap_or_default();
                    (
                        EventCategory::File,
                        Severity::Info,
                        EventData::FileCreate {
                            pid,
                            path,
                            operation: FileOperation::Rename,
                        },
                    )
                }
                _ => return None,
            },

            // -----------------------------------------------------------
            // Kernel-Network
            // -----------------------------------------------------------
            "Microsoft-Windows-Kernel-Network" => match event_id {
                // TcpSendIPv4 (10) / TcpRecvIPv4 (12):
                //   PID(u32), size(u32), daddr(4), saddr(4),
                //   dport(u16 BE), sport(u16 BE), ...
                10 | 12 => {
                    let parsed = data.and_then(|d| {
                        let mut r = UserDataReader::new(d, ps);
                        let _pid = r.read_u32()?;
                        let _size = r.read_u32()?;
                        let daddr = r.read_ipv4()?;
                        let saddr = r.read_ipv4()?;
                        let dport = r.read_u16_be()?;
                        let sport = r.read_u16_be()?;
                        Some((saddr, sport, daddr, dport))
                    });
                    let (src_addr, src_port, dst_addr, dst_port) =
                        parsed.unwrap_or_default();
                    let direction = if event_id == 10 {
                        NetworkDirection::Outbound
                    } else {
                        NetworkDirection::Inbound
                    };
                    (
                        EventCategory::Network,
                        Severity::Info,
                        EventData::NetworkConnect {
                            pid,
                            image_path: String::new(),
                            protocol: "TCP".into(),
                            src_addr,
                            src_port,
                            dst_addr,
                            dst_port,
                            direction,
                        },
                    )
                }
                // TcpSendIPv6 (11) / TcpRecvIPv6 (13)
                11 | 13 => {
                    let parsed = data.and_then(|d| {
                        let mut r = UserDataReader::new(d, ps);
                        let _pid = r.read_u32()?;
                        let _size = r.read_u32()?;
                        let daddr = r.read_ipv6()?;
                        let saddr = r.read_ipv6()?;
                        let dport = r.read_u16_be()?;
                        let sport = r.read_u16_be()?;
                        Some((saddr, sport, daddr, dport))
                    });
                    let (src_addr, src_port, dst_addr, dst_port) =
                        parsed.unwrap_or_default();
                    let direction = if event_id == 11 {
                        NetworkDirection::Outbound
                    } else {
                        NetworkDirection::Inbound
                    };
                    (
                        EventCategory::Network,
                        Severity::Info,
                        EventData::NetworkConnect {
                            pid,
                            image_path: String::new(),
                            protocol: "TCPv6".into(),
                            src_addr,
                            src_port,
                            dst_addr,
                            dst_port,
                            direction,
                        },
                    )
                }
                // UdpSendIPv4 (15) / UdpRecvIPv4 (17)
                15 | 17 => {
                    let parsed = data.and_then(|d| {
                        let mut r = UserDataReader::new(d, ps);
                        let _pid = r.read_u32()?;
                        let _size = r.read_u32()?;
                        let daddr = r.read_ipv4()?;
                        let saddr = r.read_ipv4()?;
                        let dport = r.read_u16_be()?;
                        let sport = r.read_u16_be()?;
                        Some((saddr, sport, daddr, dport))
                    });
                    let (src_addr, src_port, dst_addr, dst_port) =
                        parsed.unwrap_or_default();
                    let direction = if event_id == 15 {
                        NetworkDirection::Outbound
                    } else {
                        NetworkDirection::Inbound
                    };
                    (
                        EventCategory::Network,
                        Severity::Info,
                        EventData::NetworkConnect {
                            pid,
                            image_path: String::new(),
                            protocol: "UDP".into(),
                            src_addr,
                            src_port,
                            dst_addr,
                            dst_port,
                            direction,
                        },
                    )
                }
                // UdpSendIPv6 (16) / UdpRecvIPv6 (18)
                16 | 18 => {
                    let parsed = data.and_then(|d| {
                        let mut r = UserDataReader::new(d, ps);
                        let _pid = r.read_u32()?;
                        let _size = r.read_u32()?;
                        let daddr = r.read_ipv6()?;
                        let saddr = r.read_ipv6()?;
                        let dport = r.read_u16_be()?;
                        let sport = r.read_u16_be()?;
                        Some((saddr, sport, daddr, dport))
                    });
                    let (src_addr, src_port, dst_addr, dst_port) =
                        parsed.unwrap_or_default();
                    let direction = if event_id == 16 {
                        NetworkDirection::Outbound
                    } else {
                        NetworkDirection::Inbound
                    };
                    (
                        EventCategory::Network,
                        Severity::Info,
                        EventData::NetworkConnect {
                            pid,
                            image_path: String::new(),
                            protocol: "UDPv6".into(),
                            src_addr,
                            src_port,
                            dst_addr,
                            dst_port,
                            direction,
                        },
                    )
                }
                _ => return None,
            },

            // -----------------------------------------------------------
            // Kernel-Registry
            // -----------------------------------------------------------
            "Microsoft-Windows-Kernel-Registry" => {
                let operation = match event_id {
                    1 => RegistryOperation::CreateKey,
                    2 => RegistryOperation::CreateKey, // OpenKey
                    3 => RegistryOperation::DeleteKey,
                    4 => RegistryOperation::RenameKey,
                    5 => RegistryOperation::SetValue,
                    6 => RegistryOperation::DeleteValue,
                    _ => return None,
                };

                let (key, value_name, value_data) = data
                    .and_then(|d| {
                        let mut r = UserDataReader::new(d, ps);
                        match event_id {
                            1 | 2 => {
                                // CreateKey/OpenKey: BaseObject(ptr),
                                //   KeyObject(ptr), Status(u32),
                                //   [Disposition(u32) for event 1],
                                //   BaseName(wstr), RelativeName(wstr)
                                r.read_pointer()?;
                                r.read_pointer()?;
                                r.read_u32()?;
                                if event_id == 1 {
                                    r.read_u32()?;
                                }
                                let base = r.read_utf16_nul();
                                let rel = r.read_utf16_nul();
                                let key = if base.is_empty() {
                                    rel
                                } else if rel.is_empty() {
                                    base
                                } else {
                                    format!("{base}\\{rel}")
                                };
                                Some((key, None, None))
                            }
                            3 => {
                                // DeleteKey: KeyObject(ptr), Status(u32),
                                //   KeyName(wstr)
                                r.read_pointer()?;
                                r.read_u32()?;
                                Some((r.read_utf16_nul(), None, None))
                            }
                            4 => {
                                // RenameKey: KeyObject(ptr), Status(u32),
                                //   OldKeyName(wstr), NewKeyName(wstr)
                                r.read_pointer()?;
                                r.read_u32()?;
                                let old_name = r.read_utf16_nul();
                                let new_name = r.read_utf16_nul();
                                Some((old_name, Some(new_name), None))
                            }
                            5 => {
                                // SetValueKey: KeyObject(ptr), Status(u32),
                                //   Type(u32), DataSize(u32),
                                //   KeyName(wstr), ValueName(wstr),
                                //   CapturedDataSize(u16), CapturedData(bytes)
                                r.read_pointer()?;
                                r.read_u32()?; // Status
                                let reg_type = r.read_u32()?;
                                let _data_size = r.read_u32()?;
                                let key = r.read_utf16_nul();
                                let vn = r.read_utf16_nul();
                                // Try to capture REG_SZ (1) / REG_EXPAND_SZ (2)
                                // value data from CapturedData if present
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
                                Some((key, Some(vn), vd))
                            }
                            6 => {
                                // DeleteValueKey: KeyObject(ptr),
                                //   Status(u32), KeyName(wstr),
                                //   ValueName(wstr)
                                r.read_pointer()?;
                                r.read_u32()?;
                                let key = r.read_utf16_nul();
                                let vn = r.read_utf16_nul();
                                Some((key, Some(vn), None))
                            }
                            _ => None,
                        }
                    })
                    .unwrap_or_default();

                (
                    EventCategory::Registry,
                    Severity::Info,
                    EventData::RegistryEvent {
                        pid,
                        operation,
                        key,
                        value_name,
                        value_data,
                    },
                )
            }

            // -----------------------------------------------------------
            // DNS-Client
            // -----------------------------------------------------------
            "Microsoft-Windows-DNS-Client" => match event_id {
                3006 => {
                    // QueryInitiated: QueryName(wstr), QueryType(u16)
                    let (query_name, query_type) = data
                        .and_then(|d| {
                            let mut r = UserDataReader::new(d, ps);
                            let name = r.read_utf16_nul();
                            let qtype = r.read_u16()?;
                            Some((name, qtype))
                        })
                        .unwrap_or_default();
                    (
                        EventCategory::Dns,
                        Severity::Info,
                        EventData::DnsQuery {
                            pid,
                            query_name,
                            query_type: dns_query_type_name(query_type),
                            response: None,
                        },
                    )
                }
                3008 => {
                    // QueryCompleted: QueryName(wstr), QueryType(u16),
                    //   QueryOptions(u32), QueryStatus(u32),
                    //   QueryResults(wstr)
                    let (query_name, query_type, response) = data
                        .and_then(|d| {
                            let mut r = UserDataReader::new(d, ps);
                            let name = r.read_utf16_nul();
                            let qtype = r.read_u16()?;
                            let _options = r.read_u32()?;
                            let status = r.read_u32()?;
                            let resp = if status == 0 && r.remaining() > 0 {
                                let s = r.read_utf16_nul();
                                if s.is_empty() { None } else { Some(s) }
                            } else {
                                None
                            };
                            Some((name, qtype, resp))
                        })
                        .unwrap_or_default();
                    (
                        EventCategory::Dns,
                        Severity::Info,
                        EventData::DnsQuery {
                            pid,
                            query_name,
                            query_type: dns_query_type_name(query_type),
                            response,
                        },
                    )
                }
                _ => return None,
            },

            // -----------------------------------------------------------
            // PowerShell ScriptBlockLogging
            // -----------------------------------------------------------
            "Microsoft-Windows-PowerShell" => match event_id {
                4104 => {
                    // MessageNumber(i32), MessageTotal(i32),
                    // ScriptBlockText(wstr), ScriptBlockId(wstr),
                    // Path(wstr)
                    let content = data
                        .and_then(|d| {
                            let mut r = UserDataReader::new(d, ps);
                            r.read_u32()?; // MessageNumber
                            r.read_u32()?; // MessageTotal
                            Some(r.read_utf16_nul())
                        })
                        .unwrap_or_default();
                    (
                        EventCategory::Script,
                        Severity::Medium,
                        EventData::ScriptBlock {
                            pid,
                            script_engine: "PowerShell".into(),
                            content,
                        },
                    )
                }
                _ => return None,
            },

            // -----------------------------------------------------------
            // AMSI
            // -----------------------------------------------------------
            "Microsoft-Antimalware-Scan-Interface" => match event_id {
                1101 => {
                    // session(ptr), scanStatus(u32), appname(wstr),
                    // contentname(wstr), contentsize(u32), ...
                    let parsed = data.and_then(|d| {
                        let mut r = UserDataReader::new(d, ps);
                        r.read_pointer()?; // session
                        let scan_result = r.read_u32()?;
                        let app_name = r.read_utf16_nul();
                        let content_name = r.read_utf16_nul();
                        let content_size = r.read_u32().unwrap_or(0);
                        Some((app_name, content_name, content_size, scan_result))
                    });
                    let (app_name, content_name, content_size, scan_result) =
                        parsed.unwrap_or_default();
                    let severity = if scan_result >= 32768 {
                        Severity::High
                    } else {
                        Severity::Info
                    };
                    (
                        EventCategory::Script,
                        severity,
                        EventData::AmsiScan {
                            pid,
                            app_name,
                            content_name,
                            content_size,
                            scan_result,
                        },
                    )
                }
                _ => return None,
            },

            // -----------------------------------------------------------
            // Threat Intelligence
            //
            // UserData layout (community-documented, best-effort):
            //   Common header (all TI events):
            //     CallingProcessId(u32), CallingProcessCreateTime(u64),
            //     CallingProcessStartKey(u64),
            //     CallingProcessSignatureLevel(u8),
            //     CallingProcessSectionSignatureLevel(u8),
            //     CallingProcessProtection(u8),
            //     CallingThreadId(u32),
            //     CallingThreadCreateTime(u64)
            //   Remote events (IDs 1-5) add target process header:
            //     TargetProcessId(u32), TargetProcessCreateTime(u64),
            //     TargetProcessStartKey(u64),
            //     TargetProcessSignatureLevel(u8),
            //     TargetProcessSectionSignatureLevel(u8),
            //     TargetProcessProtection(u8)
            //   Then event-specific fields (BaseAddress, RegionSize, etc.)
            // -----------------------------------------------------------
            "Microsoft-Windows-Threat-Intelligence" => {
                return Some(map_ti_event(data, event_id, pid, hostname, ps));
            }

            _ => return None,
        };

        Some(ThreatEvent::new(
            hostname,
            EventSource::Etw {
                provider: provider.to_string(),
            },
            cat,
            sev,
            event_data,
        ))
    }

    /// Parse a Threat Intelligence ETW event with per-event-ID handling.
    ///
    /// The TI provider requires PPL or elevated privileges to receive events.
    /// Field layouts are based on community research and may vary across
    /// Windows versions; parsing is best-effort with graceful fallback.
    fn map_ti_event(
        data: Option<&[u8]>,
        event_id: u16,
        pid: u32,
        hostname: &str,
        ps: usize,
    ) -> ThreatEvent {
        // Try to parse the common TI header present in all events.
        // CallingProcessId is win:Pointer (ptr-sized), not u32.
        let header = data.and_then(|d| {
            let mut r = UserDataReader::new(d, ps);
            let calling_pid = r.read_pointer()? as u32;
            let _calling_create_time = r.read_u64()?;
            let _calling_start_key = r.read_u64()?;
            let _calling_sig_level = r.read_u8()?;
            let _calling_sec_sig_level = r.read_u8()?;
            let _calling_protection = r.read_u8()?;
            let calling_tid = r.read_u32()?;
            let _calling_thread_create_time = r.read_u64()?;
            Some((calling_pid, calling_tid, r.position()))
        });
        let (calling_pid, _calling_tid, header_end) =
            header.unwrap_or((pid, 0, 0));

        // For remote operations (IDs 1-5, 9-10), parse the target process
        // fields. TargetProcessId is also win:Pointer.
        let target = if matches!(event_id, 1..=5 | 9..=10) {
            data.and_then(|d| {
                if header_end >= d.len() {
                    return None;
                }
                let mut r = UserDataReader::new(&d[header_end..], ps);
                let target_pid = r.read_pointer()? as u32;
                let _target_create_time = r.read_u64()?;
                let _target_start_key = r.read_u64()?;
                let _target_sig_level = r.read_u8()?;
                let _target_sec_sig_level = r.read_u8()?;
                let _target_protection = r.read_u8()?;
                Some((target_pid, header_end + r.position()))
            })
        } else {
            None
        };
        let (target_pid, post_target) = target.unwrap_or((0, header_end));

        // Parse event-specific fields (address, size, protection).
        let specifics = data.and_then(|d| {
            if post_target >= d.len() {
                return None;
            }
            let mut r = UserDataReader::new(&d[post_target..], ps);
            match event_id {
                // ALLOCVM_REMOTE / ALLOCVM_LOCAL
                1 | 6 => {
                    let base = r.read_pointer()?;
                    let size = r.read_pointer()?;
                    let _alloc_type = r.read_u32()?;
                    let protection = r.read_u32()?;
                    Some((base, size, protection))
                }
                // PROTECTVM_REMOTE / PROTECTVM_LOCAL
                2 | 7 => {
                    let base = r.read_pointer()?;
                    let size = r.read_pointer()?;
                    let protection = r.read_u32()?;
                    let _old_protection = r.read_u32()?;
                    Some((base, size, protection))
                }
                // MAPVIEW_REMOTE / MAPVIEW_LOCAL
                3 | 8 => {
                    let base = r.read_pointer()?;
                    let size = r.read_pointer()?;
                    let _alloc_type = r.read_u32()?;
                    let protection = r.read_u32()?;
                    Some((base, size, protection))
                }
                // QUEUEAPC_REMOTE
                4 => {
                    let _target_tid = r.read_u32()?;
                    let apc_routine = r.read_pointer()?;
                    Some((apc_routine, 0, 0))
                }
                // SETTHREADCONTEXT_REMOTE
                5 => {
                    let _target_tid = r.read_u32()?;
                    let context_flags = r.read_u32()?;
                    Some((0, 0, context_flags))
                }
                // SUSPEND_THREAD_REMOTE / RESUME_THREAD_REMOTE
                // Target thread ID only
                9 | 10 => {
                    let target_tid = r.read_u32()?;
                    Some((target_tid as u64, 0, 0))
                }
                _ => None,
            }
        });

        let (rule_id, name, description, technique_id, technique_name) = match event_id {
            1 => (
                "TF-TI-001",
                "Remote Virtual Memory Allocation",
                "A process allocated virtual memory in another process \
                 (NtAllocateVirtualMemory). This is a common step in \
                 process injection techniques.",
                "T1055",
                "Process Injection",
            ),
            2 => (
                "TF-TI-002",
                "Remote Memory Protection Change",
                "A process changed memory protection in another process \
                 (NtProtectVirtualMemory). Often used to make injected \
                 code executable.",
                "T1055",
                "Process Injection",
            ),
            3 => (
                "TF-TI-003",
                "Remote Section Mapping",
                "A process mapped a section into another process \
                 (NtMapViewOfSection). Used in section-based injection \
                 and process hollowing.",
                "T1055",
                "Process Injection",
            ),
            4 => (
                "TF-TI-004",
                "Remote APC Queue",
                "A process queued an APC to a thread in another process \
                 (NtQueueApcThread). This is the APC injection technique.",
                "T1055.004",
                "Process Injection: Asynchronous Procedure Call",
            ),
            5 => (
                "TF-TI-005",
                "Remote Thread Context Modification",
                "A process modified the thread context of another process \
                 (NtSetContextThread). Used in thread execution hijacking.",
                "T1055.003",
                "Process Injection: Thread Execution Hijacking",
            ),
            6 => (
                "TF-TI-006",
                "Local Virtual Memory Allocation (TI)",
                "TI provider reported a local memory allocation flagged \
                 for monitoring. May indicate self-injection or \
                 memory manipulation.",
                "T1055",
                "Process Injection",
            ),
            7 => (
                "TF-TI-007",
                "Local Memory Protection Change (TI)",
                "TI provider reported a local memory protection change. \
                 May indicate code unpacking or self-modification.",
                "T1027.002",
                "Obfuscated Files or Information: Software Packing",
            ),
            8 => (
                "TF-TI-008",
                "Local Section Mapping (TI)",
                "TI provider reported a local section mapping flagged \
                 for monitoring.",
                "T1055",
                "Process Injection",
            ),
            9 => (
                "TF-TI-009",
                "Remote Thread Suspension",
                "A process suspended a thread in another process \
                 (NtSuspendThread). Used in process injection to \
                 freeze a target before modifying its state.",
                "T1055",
                "Process Injection",
            ),
            10 => (
                "TF-TI-010",
                "Remote Thread Resume",
                "A process resumed a thread in another process \
                 (NtResumeThread). Often follows injection setup \
                 to trigger execution of injected code.",
                "T1055",
                "Process Injection",
            ),
            _ => (
                "TF-TI-000",
                "Threat Intelligence ETW Event",
                "Windows Threat Intelligence ETW provider emitted an \
                 unrecognized event type.",
                "N/A",
                "Unknown",
            ),
        };

        let mut evidence = vec![
            format!("TI event ID: {event_id}"),
            format!("Calling PID: {calling_pid}"),
        ];
        if matches!(event_id, 1..=5 | 9..=10) && target_pid > 0 {
            evidence.push(format!("Target PID: {target_pid}"));
        }
        if let Some((base, size, protection)) = specifics {
            match event_id {
                4 => {
                    // QUEUEAPC: base=ApcRoutine, size/protection unused
                    evidence.push(format!("ApcRoutine: 0x{base:X}"));
                }
                5 => {
                    // SETCONTEXT: protection=ContextFlags, base/size unused
                    evidence.push(format!("ContextFlags: 0x{protection:08X}"));
                }
                9 | 10 => {
                    // SUSPEND/RESUME: base=TargetThreadId
                    evidence.push(format!("Target TID: {base}"));
                }
                _ => {
                    evidence.push(format!("BaseAddress: 0x{base:X}"));
                    evidence.push(format!("RegionSize: 0x{size:X}"));
                    evidence.push(format!("Protection: 0x{protection:08X}"));
                }
            }
        }

        let details = if matches!(event_id, 1..=5 | 9..=10) && target_pid > 0 {
            format!("{name}: PID {calling_pid} → PID {target_pid}")
        } else {
            format!("{name}: PID {calling_pid}")
        };

        ThreatEvent::with_rule(
            hostname,
            EventSource::Etw {
                provider: "Microsoft-Windows-Threat-Intelligence".into(),
            },
            EventCategory::Evasion,
            Severity::High,
            EventData::EvasionDetected {
                technique: EvasionTechnique::Unknown,
                pid: Some(calling_pid),
                process_name: None,
                details,
            },
            RuleMetadata {
                id: rule_id.into(),
                name: name.into(),
                description: description.into(),
                mitre: MitreRef {
                    tactic: "Defense Evasion".into(),
                    technique_id: technique_id.into(),
                    technique_name: technique_name.into(),
                },
                confidence: Confidence::Medium,
                evidence,
            },
        )
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

    async fn start(&mut self, _tx: mpsc::Sender<ThreatEvent>) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let (flag, lock) = platform::start_session(
                &self.config.providers,
                self.hostname.clone(),
                _tx,
                self.dropped.clone(),
            )?;
            self.stop_flag = Some(flag);
            self.instance_lock = Some(lock);
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
        {
            // Signal background thread to stop processing events
            if let Some(flag) = self.stop_flag.take() {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            // Stop the ETW session and release the instance lock
            let lock = self.instance_lock.take().unwrap_or(0);
            platform::stop_session(lock);
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
        let mut buf: Vec<u8> = s
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
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
        data.extend_from_slice(&0u64.to_le_bytes());    // CreateTime
        data.extend_from_slice(&4321u32.to_le_bytes()); // PPID
        data.extend_from_slice(&1u32.to_le_bytes());    // SessionID
        data.extend_from_slice(&0u32.to_le_bytes());    // Flags
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
        data.extend_from_slice(&100u32.to_le_bytes());  // PID
        data.extend_from_slice(&512u32.to_le_bytes());  // Size
        data.extend_from_slice(&[93, 184, 216, 34]);    // DstAddr: 93.184.216.34
        data.extend_from_slice(&[192, 168, 1, 10]);     // SrcAddr: 192.168.1.10
        data.extend_from_slice(&443u16.to_be_bytes());  // DstPort (BE)
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
        data.extend_from_slice(&0u32.to_le_bytes());                // Status
        data.extend_from_slice(&1u32.to_le_bytes());                // Type (REG_SZ)
        data.extend_from_slice(&64u32.to_le_bytes());               // DataSize
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
        data.extend_from_slice(&utf16_nul(r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll"));

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
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x88, 0x88,
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
        assert!(value_data.starts_with("hello"));
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
            if s.is_empty() { None } else { Some(s) }
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
            if s.is_empty() { None } else { Some(s) }
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
}
