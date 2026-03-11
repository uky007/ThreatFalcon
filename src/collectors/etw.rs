use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::info;

use crate::config::EtwConfig;
use crate::events::ThreatEvent;

use super::Collector;

const SESSION_NAME: &str = "ThreatFalcon-ETW";

pub struct EtwCollector {
    config: EtwConfig,
    hostname: String,
    #[cfg(target_os = "windows")]
    stop_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl EtwCollector {
    pub fn new(config: EtwConfig, hostname: String) -> Self {
        Self {
            config,
            hostname,
            #[cfg(target_os = "windows")]
            stop_flag: None,
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

    // -----------------------------------------------------------------------
    // UserDataReader: cursor-based binary reader for EVENT_RECORD.UserData
    // -----------------------------------------------------------------------

    struct UserDataReader<'a> {
        data: &'a [u8],
        pos: usize,
        pointer_size: usize,
    }

    impl<'a> UserDataReader<'a> {
        fn new(data: &'a [u8], pointer_size: usize) -> Self {
            Self {
                data,
                pos: 0,
                pointer_size,
            }
        }

        fn read_u16(&mut self) -> Option<u16> {
            if self.pos + 2 > self.data.len() {
                return None;
            }
            let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
            self.pos += 2;
            Some(v)
        }

        fn read_u16_be(&mut self) -> Option<u16> {
            if self.pos + 2 > self.data.len() {
                return None;
            }
            let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
            self.pos += 2;
            Some(v)
        }

        fn read_u32(&mut self) -> Option<u32> {
            if self.pos + 4 > self.data.len() {
                return None;
            }
            let v = u32::from_le_bytes(
                self.data[self.pos..self.pos + 4].try_into().ok()?,
            );
            self.pos += 4;
            Some(v)
        }

        fn read_u64(&mut self) -> Option<u64> {
            if self.pos + 8 > self.data.len() {
                return None;
            }
            let v = u64::from_le_bytes(
                self.data[self.pos..self.pos + 8].try_into().ok()?,
            );
            self.pos += 8;
            Some(v)
        }

        fn read_pointer(&mut self) -> Option<u64> {
            match self.pointer_size {
                4 => self.read_u32().map(|v| v as u64),
                _ => self.read_u64(),
            }
        }

        fn read_ipv4(&mut self) -> Option<String> {
            if self.pos + 4 > self.data.len() {
                return None;
            }
            let b = &self.data[self.pos..self.pos + 4];
            self.pos += 4;
            Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
        }

        fn read_ipv6(&mut self) -> Option<String> {
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
        fn read_utf16_nul(&mut self) -> String {
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

        fn skip(&mut self, n: usize) {
            self.pos = (self.pos + n).min(self.data.len());
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

    fn dns_query_type_name(qtype: u16) -> String {
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
        dropped: AtomicU64,
    }

    /// Start an ETW real-time trace session, enable the configured providers,
    /// and spawn a blocking thread that consumes events.
    pub fn start_session(
        providers: &[crate::config::EtwProviderConfig],
        hostname: String,
        tx: mpsc::Sender<ThreatEvent>,
    ) -> Result<Arc<AtomicBool>> {
        let stop = Arc::new(AtomicBool::new(false));

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

        // ERROR_ALREADY_EXISTS (183): a session with the same name exists,
        // likely from a previous crash. Stop it and retry once.
        if status.0 == 183 {
            tracing::warn!(
                "ETW session already exists — stopping stale session"
            );
            stop_session();

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
        let session_name_owned = SESSION_NAME.to_string();

        tokio::task::spawn_blocking(move || {
            let session_wide: Vec<u16> = session_name_owned
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let ctx = Box::new(CallbackContext {
                hostname,
                tx,
                stop: stop_clone,
                dropped: AtomicU64::new(0),
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
                CloseTrace(trace);
                drop(Box::from_raw(ctx_ptr));
            }
        });

        Ok(stop)
    }

    /// Stop the ETW trace session (causes ProcessTrace to return).
    pub fn stop_session() {
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
            ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                windows::core::PCWSTR(session_name_wide.as_ptr()),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
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
            "Microsoft-Windows-Threat-Intelligence" => (
                EventCategory::Evasion,
                Severity::High,
                EventData::EvasionDetected {
                    technique: EvasionTechnique::ProcessHollowing,
                    pid: Some(pid),
                    process_name: None,
                    details: format!("TI ETW event {event_id}"),
                },
            ),

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
            let flag = platform::start_session(
                &self.config.providers,
                self.hostname.clone(),
                _tx,
            )?;
            self.stop_flag = Some(flag);
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
            // Stop the ETW session — this causes ProcessTrace() to return
            platform::stop_session();
        }

        info!("ETW collector stopped");
        Ok(())
    }
}
