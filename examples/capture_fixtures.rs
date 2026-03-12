//! Capture raw ETW event payloads for fixture tests.
//!
//! Run on a Windows machine with admin privileges:
//!   cargo run --example capture_fixtures
//!
//! Captures UserData from targeted ETW providers and writes hex-encoded
//! fixtures to stdout. Copy the output into test fixtures.
//!
//! Targeted providers and event IDs:
//!   - Microsoft-Windows-Kernel-Process: 1 (ProcessCreate), 2 (ProcessStop), 5 (ImageLoad)
//!   - Microsoft-Windows-Kernel-File: 10, 11, 12, 13, 14
//!   - Microsoft-Windows-Kernel-Network: 10-18
//!   - Microsoft-Windows-Kernel-Registry: 1-6
//!   - Microsoft-Windows-DNS-Client: 3006, 3008
//!   - Microsoft-Windows-Threat-Intelligence: 1-10

#[cfg(target_os = "windows")]
mod capture {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;
    use windows::core::GUID;
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Diagnostics::Etw::*;

    const SESSION_NAME: &str = "ThreatFalcon-FixtureCapture";
    const MAX_EVENTS: u32 = 200;

    struct CaptureContext {
        count: AtomicU32,
        stop: Arc<AtomicBool>,
    }

    pub fn run() {
        println!("// ThreatFalcon ETW fixture capture");
        println!("// Run on Windows with admin privileges");
        println!("// OS: {}", std::env::consts::OS);
        println!();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();

        // Ctrl+C handler
        ctrlc::set_handler(move || {
            stop_clone.store(true, Ordering::SeqCst);
        })
        .expect("Failed to set Ctrl+C handler");

        // Providers to capture (subset — no TI since it requires PPL)
        let providers = vec![
            // Kernel-Process
            ("22FB2CD6-6757-4FCB-B826-A443BB184F30", "Kernel-Process", 0x10u64),
            // Kernel-File
            ("EDD08927-9CC4-4E65-B970-C2560FB5C289", "Kernel-File", 0x10u64),
            // Kernel-Network
            ("7DD42A49-5329-4832-8DFD-43D979153A88", "Kernel-Network", 0x10u64),
            // Kernel-Registry
            ("70EB4F03-C1DE-4F73-A051-33D13D5413BD", "Kernel-Registry", 0x10u64),
            // DNS-Client
            ("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D", "DNS-Client", 0xFFFFFFFFFFFFFFFFu64),
        ];

        // Allocate session
        let session_wide: Vec<u16> = SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let extra = session_wide.len() * 2;
        let total = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + extra;
        let mut buf = vec![0u8; total];
        let props = unsafe {
            &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES)
        };
        props.Wnode.BufferSize = total as u32;
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props.Wnode.ClientContext = 1;
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props.LoggerNameOffset =
            std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        let mut handle = CONTROLTRACE_HANDLE::default();
        let status = unsafe {
            StartTraceW(
                &mut handle,
                windows::core::PCWSTR(session_wide.as_ptr()),
                props,
            )
        };
        if status != WIN32_ERROR(0) {
            eprintln!("StartTraceW failed: {status:?}");
            return;
        }

        // Enable providers
        for (guid_str, name, keywords) in &providers {
            let guid = parse_guid(guid_str);
            let status = unsafe {
                EnableTraceEx2(
                    handle,
                    &guid,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                    5, // TRACE_LEVEL_VERBOSE
                    *keywords,
                    0,
                    0,
                    None,
                )
            };
            if status == WIN32_ERROR(0) {
                eprintln!("Enabled: {name}");
            } else {
                eprintln!("Failed to enable {name}: {status:?}");
            }
        }

        // Consume events
        let ctx = Box::new(CaptureContext {
            count: AtomicU32::new(0),
            stop: stop.clone(),
        });
        let ctx_ptr = Box::into_raw(ctx);

        let consume_wide: Vec<u16> = SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut logfile = EVENT_TRACE_LOGFILEW::default();
        logfile.LoggerName =
            windows::core::PWSTR(consume_wide.as_ptr() as *mut u16);
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Context = ctx_ptr as *mut std::ffi::c_void;
        logfile.Anonymous2.EventRecordCallback = Some(capture_callback);

        let trace = unsafe { OpenTraceW(&mut logfile) };
        if trace.Value == u64::MAX {
            eprintln!("OpenTraceW failed");
            unsafe { drop(Box::from_raw(ctx_ptr)); }
            return;
        }

        eprintln!("Capturing up to {MAX_EVENTS} events (Ctrl+C to stop)...");

        let status = unsafe { ProcessTrace(&[trace], None, None) };
        if status != WIN32_ERROR(0) {
            eprintln!("ProcessTrace ended: {status:?}");
        }

        unsafe {
            let _ = CloseTrace(trace);
            drop(Box::from_raw(ctx_ptr));
        }

        // Stop session
        let total = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 1024;
        let mut buf = vec![0u8; total];
        let props = unsafe {
            &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES)
        };
        props.Wnode.BufferSize = total as u32;
        unsafe {
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                windows::core::PCWSTR(session_wide.as_ptr()),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
        }

        eprintln!("Done.");
    }

    unsafe extern "system" fn capture_callback(record: *mut EVENT_RECORD) {
        let rec = unsafe { &*record };
        let ctx = unsafe { &*(rec.UserContext as *const CaptureContext) };

        if ctx.stop.load(Ordering::Relaxed) {
            return;
        }

        let n = ctx.count.fetch_add(1, Ordering::Relaxed);
        if n >= MAX_EVENTS {
            ctx.stop.store(true, Ordering::SeqCst);
            return;
        }

        let provider = rec.EventHeader.ProviderId;
        let event_id = rec.EventHeader.EventDescriptor.Id;
        let pid = rec.EventHeader.ProcessId;
        let flags = rec.EventHeader.Flags;

        let ptr = rec.UserData as *const u8;
        let len = rec.UserDataLength as usize;
        let data = if !ptr.is_null() && len > 0 {
            unsafe { std::slice::from_raw_parts(ptr, len) }
        } else {
            &[]
        };

        let provider_name = match provider.data1 {
            0x22FB2CD6 => "Kernel-Process",
            0xEDD08927 => "Kernel-File",
            0x7DD42A49 => "Kernel-Network",
            0x70EB4F03 => "Kernel-Registry",
            0x1C95126E => "DNS-Client",
            0xF4E1897C => "Threat-Intelligence",
            _ => return,
        };

        // Filter to event IDs we care about
        let dominated = match provider_name {
            "Kernel-Process" => matches!(event_id, 1 | 2 | 5),
            "Kernel-File" => matches!(event_id, 10..=14),
            "Kernel-Network" => matches!(event_id, 10..=18),
            "Kernel-Registry" => matches!(event_id, 1..=6),
            "DNS-Client" => matches!(event_id, 3006 | 3008),
            "Threat-Intelligence" => matches!(event_id, 1..=10),
            _ => false,
        };
        if !dominated {
            return;
        }

        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        let ptr_size = if flags & 0x0040 != 0 {
            8
        } else if flags & 0x0020 != 0 {
            4
        } else {
            8
        };

        println!(
            "// provider={provider_name} event_id={event_id} pid={pid} \
             ptr_size={ptr_size} len={len}"
        );
        println!("const {provider_name}_{event_id}_{n}: &str = \"{hex}\";");
        println!();
    }

    fn parse_guid(s: &str) -> GUID {
        let s = s.trim_matches(|c| c == '{' || c == '}');
        let parts: Vec<&str> = s.split('-').collect();
        let d1 = u32::from_str_radix(parts[0], 16).unwrap();
        let d2 = u16::from_str_radix(parts[1], 16).unwrap();
        let d3 = u16::from_str_radix(parts[2], 16).unwrap();
        let d4_hex = format!("{}{}", parts[3], parts[4]);
        let mut d4 = [0u8; 8];
        for (i, byte) in d4.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&d4_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        GUID {
            data1: d1,
            data2: d2,
            data3: d3,
            data4: d4,
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod capture {
    pub fn run() {
        eprintln!("This tool must be run on Windows with admin privileges.");
        eprintln!("It captures raw ETW event payloads for fixture tests.");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  cargo run --example capture_fixtures > fixtures.txt");
        std::process::exit(1);
    }
}

fn main() {
    capture::run();
}
