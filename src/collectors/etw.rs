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
                    5 => RegistryOperation::SetValue,
                    6 => RegistryOperation::DeleteValue,
                    _ => return None,
                };

                let (key, value_name) = data
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
                                Some((key, None))
                            }
                            3 => {
                                // DeleteKey: KeyObject(ptr), Status(u32),
                                //   KeyName(wstr)
                                r.read_pointer()?;
                                r.read_u32()?;
                                Some((r.read_utf16_nul(), None))
                            }
                            5 => {
                                // SetValueKey: KeyObject(ptr), Status(u32),
                                //   Type(u32), DataSize(u32),
                                //   KeyName(wstr), ValueName(wstr)
                                r.read_pointer()?;
                                r.read_u32()?;
                                r.read_u32()?;
                                r.read_u32()?;
                                let key = r.read_utf16_nul();
                                let vn = r.read_utf16_nul();
                                Some((key, Some(vn)))
                            }
                            6 => {
                                // DeleteValueKey: KeyObject(ptr),
                                //   Status(u32), KeyName(wstr),
                                //   ValueName(wstr)
                                r.read_pointer()?;
                                r.read_u32()?;
                                let key = r.read_utf16_nul();
                                let vn = r.read_utf16_nul();
                                Some((key, Some(vn)))
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
                        value_data: None,
                    },
                )
            }

            // -----------------------------------------------------------
            // DNS-Client
            // -----------------------------------------------------------
            "Microsoft-Windows-DNS-Client" => match event_id {
                3006 | 3008 => {
                    // QueryCompleted/QueryInitiated:
                    //   QueryName(wstr), QueryType(u16), ...
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
            // -----------------------------------------------------------
            "Microsoft-Windows-Threat-Intelligence" => {
                let rule = RuleMetadata {
                    id: "TF-TI-001".into(),
                    name: "Threat Intelligence ETW Event".into(),
                    description: "Windows Threat Intelligence ETW provider \
                        emitted an event. The specific technique cannot be \
                        determined without parsing the TI event payload; \
                        this rule captures the raw signal for triage."
                        .into(),
                    mitre: MitreRef {
                        tactic: "Defense Evasion".into(),
                        technique_id: "N/A".into(),
                        technique_name: "Unknown — TI payload not parsed".into(),
                    },
                    confidence: Confidence::Medium,
                    evidence: vec![
                        format!("TI ETW event ID: {event_id}"),
                        format!("Source PID: {pid}"),
                        "Specific technique unknown — TI UserData not yet parsed".into(),
                    ],
                };
                let event = ThreatEvent::with_rule(
                    hostname,
                    EventSource::Etw {
                        provider: provider.to_string(),
                    },
                    EventCategory::Evasion,
                    Severity::High,
                    EventData::EvasionDetected {
                        technique: EvasionTechnique::Unknown,
                        pid: Some(pid),
                        process_name: None,
                        details: format!("TI ETW event {event_id}"),
                    },
                    rule,
                );
                return Some(event);
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
}
