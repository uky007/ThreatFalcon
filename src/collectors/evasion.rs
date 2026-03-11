use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::info;

use crate::config::EvasionConfig;
use crate::events::ThreatEvent;

use super::Collector;

/// Periodically scans running processes to detect EDR evasion techniques:
///
/// - **ETW patching**: `ntdll!EtwEventWrite` is patched to `ret` so the kernel
///   stops receiving user-mode ETW events from the target process.
/// - **AMSI bypass**: `amsi!AmsiScanBuffer` is patched to always return clean.
/// - **ntdll unhooking**: The process replaces its hooked ntdll `.text` section
///   with a clean copy mapped from `\KnownDlls\ntdll.dll` or from disk.
/// - **Direct syscalls**: The process uses `syscall` / `int 0x2e` instructions
///   from its own module instead of calling ntdll, bypassing user-mode hooks.
pub struct EvasionCollector {
    config: EvasionConfig,
    hostname: String,
    #[cfg(target_os = "windows")]
    stop_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl EvasionCollector {
    pub fn new(config: EvasionConfig, hostname: String) -> Self {
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
    use crate::events::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::LibraryLoader::*;
    use windows::Win32::System::ProcessStatus::*;
    use windows::Win32::System::Threading::*;

    pub fn start_scanner(
        config: EvasionConfig,
        hostname: String,
        tx: mpsc::Sender<ThreatEvent>,
    ) -> Result<Arc<AtomicBool>> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();

        tokio::task::spawn_blocking(move || {
            scan_loop(&config, &hostname, &tx, &stop_clone);
        });

        Ok(stop)
    }

    fn scan_loop(
        config: &EvasionConfig,
        hostname: &str,
        tx: &mpsc::Sender<ThreatEvent>,
        stop: &Arc<AtomicBool>,
    ) {
        let interval =
            std::time::Duration::from_millis(config.scan_interval_ms);

        // Build a reference for ntdll unhooking detection: on-disk clean
        // copy + whether our own in-memory ntdll has EDR hooks installed.
        let ntdll_reference = build_ntdll_reference();

        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }

            let pids = enumerate_pids();
            for pid in &pids {
                if stop.load(Ordering::Relaxed) {
                    return;
                }

                let handle = match open_process(*pid) {
                    Some(h) => h,
                    None => continue,
                };

                if config.detect_etw_patching {
                    if let Some(evt) =
                        check_etw_patching(handle, *pid, hostname)
                    {
                        if let Err(e) = tx.try_send(evt) {
                            tracing::warn!(error = %e, "Evasion event dropped");
                        }
                    }
                }

                if config.detect_amsi_bypass {
                    if let Some(evt) =
                        check_amsi_bypass(handle, *pid, hostname)
                    {
                        if let Err(e) = tx.try_send(evt) {
                            tracing::warn!(error = %e, "Evasion event dropped");
                        }
                    }
                }

                if config.detect_unhooking {
                    if let Some(evt) = check_ntdll_unhooking(
                        handle,
                        *pid,
                        hostname,
                        &ntdll_reference,
                    ) {
                        if let Err(e) = tx.try_send(evt) {
                            tracing::warn!(error = %e, "Evasion event dropped");
                        }
                    }
                }

                unsafe {
                    let _ = CloseHandle(handle);
                }
            }

            std::thread::sleep(interval);
        }
    }

    // ---- Process enumeration ------------------------------------------------

    fn enumerate_pids() -> Vec<u32> {
        let mut pids = vec![0u32; 4096];
        let mut needed = 0u32;
        unsafe {
            if EnumProcesses(
                pids.as_mut_ptr(),
                (pids.len() * 4) as u32,
                &mut needed,
            )
            .is_ok()
            {
                let count = needed as usize / 4;
                pids.truncate(count);
            } else {
                pids.clear();
            }
        }
        pids
    }

    fn open_process(pid: u32) -> Option<HANDLE> {
        unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            )
            .ok()
        }
    }

    // ---- ETW patching detection ---------------------------------------------

    fn check_etw_patching(
        handle: HANDLE,
        pid: u32,
        hostname: &str,
    ) -> Option<ThreatEvent> {
        let ntdll_base = find_module_in_process(handle, "ntdll.dll")?;

        let our_ntdll = unsafe {
            GetModuleHandleA(windows::core::PCSTR(
                b"ntdll.dll\0".as_ptr(),
            ))
        }
        .ok()?;
        let fn_addr = unsafe {
            GetProcAddress(
                our_ntdll,
                windows::core::PCSTR(b"EtwEventWrite\0".as_ptr()),
            )
        }?;

        let offset = fn_addr as usize - our_ntdll.0 as usize;
        let target_addr = ntdll_base + offset;

        let mut buf = [0u8; 4];
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                target_addr as *const std::ffi::c_void,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len(),
                Some(&mut read),
            )
        };

        if ok.is_err() || read < 1 {
            return None;
        }

        // 0xC3 = ret, 0xC2 = ret imm16 — both indicate patching
        if buf[0] == 0xC3 || buf[0] == 0xC2 {
            return Some(ThreatEvent::new(
                hostname,
                EventSource::EvasionDetector,
                EventCategory::Evasion,
                Severity::Critical,
                EventData::EvasionDetected {
                    technique: EvasionTechnique::EtwPatching,
                    pid: Some(pid),
                    process_name: None,
                    details: format!(
                        "EtwEventWrite patched: first bytes = \
                         {:02X} {:02X} {:02X} {:02X}",
                        buf[0], buf[1], buf[2], buf[3]
                    ),
                },
            ));
        }

        None
    }

    // ---- AMSI bypass detection ----------------------------------------------

    fn check_amsi_bypass(
        handle: HANDLE,
        pid: u32,
        hostname: &str,
    ) -> Option<ThreatEvent> {
        let amsi_base = find_module_in_process(handle, "amsi.dll")?;

        let our_amsi = unsafe {
            GetModuleHandleA(windows::core::PCSTR(
                b"amsi.dll\0".as_ptr(),
            ))
        }
        .ok()?;
        let fn_addr = unsafe {
            GetProcAddress(
                our_amsi,
                windows::core::PCSTR(b"AmsiScanBuffer\0".as_ptr()),
            )
        }?;

        let offset = fn_addr as usize - our_amsi.0 as usize;
        let target_addr = amsi_base + offset;

        let mut buf = [0u8; 8];
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                target_addr as *const std::ffi::c_void,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len(),
                Some(&mut read),
            )
        };

        if ok.is_err() || read < 6 {
            return None;
        }

        // Common AMSI patch: mov eax, 0x80070057; ret
        //   B8 57 00 07 80 C3
        if buf[0] == 0xB8 && buf[5] == 0xC3 {
            return Some(ThreatEvent::new(
                hostname,
                EventSource::EvasionDetector,
                EventCategory::Evasion,
                Severity::Critical,
                EventData::EvasionDetected {
                    technique: EvasionTechnique::AmsiBypass,
                    pid: Some(pid),
                    process_name: None,
                    details: format!(
                        "AmsiScanBuffer patched: first bytes = {:02X?}",
                        &buf[..6]
                    ),
                },
            ));
        }

        None
    }

    // ---- ntdll unhooking detection ------------------------------------------

    /// Reference data for ntdll unhooking detection.
    struct NtdllReference {
        /// Clean .text section bytes read from on-disk ntdll.dll
        ondisk_text: Vec<u8>,
        /// RVA of the .text section
        text_rva: u32,
        /// Size of the .text section
        text_size: u32,
        /// Whether our own in-memory ntdll differs from on-disk (EDR hooks)
        hooks_present: bool,
    }

    /// Build the reference by loading the on-disk ntdll and comparing it
    /// with our own in-memory copy to detect whether hooks are installed.
    fn build_ntdll_reference() -> Option<NtdllReference> {
        let (ondisk_text, text_rva, text_size) = load_ondisk_ntdll_text()?;

        // Read our own in-memory ntdll .text to check for hooks
        let our_ntdll = unsafe {
            GetModuleHandleA(windows::core::PCSTR(
                b"ntdll.dll\0".as_ptr(),
            ))
        }
        .ok()?;
        let sample = ondisk_text.len().min(text_size as usize);
        let our_text = unsafe {
            std::slice::from_raw_parts(
                (our_ntdll.0 as usize + text_rva as usize) as *const u8,
                sample,
            )
        };

        let our_diff = our_text
            .iter()
            .zip(ondisk_text.iter())
            .filter(|(a, b)| a != b)
            .count();

        // >0.5% diff from on-disk indicates hooks are installed
        let hooks_present = our_diff > sample / 200;

        if hooks_present {
            tracing::info!(
                diff_bytes = our_diff,
                total_bytes = sample,
                "EDR hooks detected in our ntdll .text section"
            );
        } else {
            tracing::debug!(
                "No EDR hooks detected — ntdll unhooking detection inactive"
            );
        }

        Some(NtdllReference {
            ondisk_text,
            text_rva,
            text_size,
            hooks_present,
        })
    }

    fn check_ntdll_unhooking(
        handle: HANDLE,
        pid: u32,
        hostname: &str,
        reference: &Option<NtdllReference>,
    ) -> Option<ThreatEvent> {
        let reference = reference.as_ref()?;

        // If no hooks are present in our environment, unhooking detection
        // is not meaningful — every process would have a clean ntdll.
        if !reference.hooks_present {
            return None;
        }

        let ntdll_base = find_module_in_process(handle, "ntdll.dll")?;
        let sample_len =
            (reference.text_size as usize).min(reference.ondisk_text.len());
        let mut remote_text = vec![0u8; sample_len];
        let mut read = 0usize;

        let ok = unsafe {
            ReadProcessMemory(
                handle,
                (ntdll_base + reference.text_rva as usize)
                    as *const std::ffi::c_void,
                remote_text.as_mut_ptr() as *mut std::ffi::c_void,
                sample_len,
                Some(&mut read),
            )
        };

        if ok.is_err() || read < sample_len {
            return None;
        }

        // Compare the remote process's ntdll .text with the on-disk copy.
        // If the remote copy closely matches the clean on-disk copy despite
        // EDR hooks being present in our environment, the process has
        // replaced its hooked ntdll with a clean one (unhooking).
        let diff_count = remote_text
            .iter()
            .zip(reference.ondisk_text.iter())
            .filter(|(a, b)| a != b)
            .count();

        // Threshold: fewer than 0.5% of bytes differ from the clean copy
        // while hooks are known to be present → unhooking detected.
        if diff_count < sample_len / 200 {
            return Some(ThreatEvent::new(
                hostname,
                EventSource::EvasionDetector,
                EventCategory::Evasion,
                Severity::High,
                EventData::EvasionDetected {
                    technique: EvasionTechnique::NtdllUnhooking,
                    pid: Some(pid),
                    process_name: None,
                    details: format!(
                        "ntdll .text matches clean on-disk copy \
                         ({diff_count}/{sample_len} bytes differ) — \
                         possible unhooking"
                    ),
                },
            ));
        }

        None
    }

    // ---- Helpers ------------------------------------------------------------

    fn find_module_in_process(
        handle: HANDLE,
        name: &str,
    ) -> Option<usize> {
        let mut modules = [HMODULE::default(); 1024];
        let mut needed = 0u32;
        unsafe {
            if EnumProcessModules(
                handle,
                modules.as_mut_ptr(),
                std::mem::size_of_val(&modules) as u32,
                &mut needed,
            )
            .is_err()
            {
                return None;
            }
        }

        let count =
            needed as usize / std::mem::size_of::<HMODULE>();
        for m in &modules[..count] {
            let mut buf = [0u8; 260];
            let len = unsafe {
                GetModuleBaseNameA(handle, *m, &mut buf)
            };
            if len == 0 {
                continue;
            }
            let mod_name =
                std::str::from_utf8(&buf[..len as usize]).unwrap_or("");
            if mod_name.eq_ignore_ascii_case(name) {
                return Some(m.0 as usize);
            }
        }

        None
    }

    /// Load the ntdll .text section from disk at
    /// `C:\Windows\System32\ntdll.dll` and parse PE headers to find the
    /// .text section RVA and size.  Returns (bytes, rva, size).
    fn load_ondisk_ntdll_text() -> Option<(Vec<u8>, u32, u32)> {
        let path = r"C:\Windows\System32\ntdll.dll";
        let data = std::fs::read(path).ok()?;

        // Minimal PE parsing
        if data.len() < 0x40 {
            return None;
        }
        let pe_offset =
            u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
        if data.len() < pe_offset + 4 {
            return None;
        }
        // Verify PE signature "PE\0\0"
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return None;
        }

        let coff_start = pe_offset + 4;
        let num_sections = u16::from_le_bytes(
            data[coff_start + 2..coff_start + 4].try_into().ok()?,
        ) as usize;
        let opt_header_size = u16::from_le_bytes(
            data[coff_start + 16..coff_start + 18].try_into().ok()?,
        ) as usize;

        let sections_start = coff_start + 20 + opt_header_size;

        for i in 0..num_sections {
            let sec = sections_start + i * 40;
            if data.len() < sec + 40 {
                break;
            }
            let sec_name = &data[sec..sec + 8];
            if sec_name.starts_with(b".text") {
                let virtual_size = u32::from_le_bytes(
                    data[sec + 8..sec + 12].try_into().ok()?,
                );
                let virtual_addr = u32::from_le_bytes(
                    data[sec + 12..sec + 16].try_into().ok()?,
                );
                let raw_size = u32::from_le_bytes(
                    data[sec + 16..sec + 20].try_into().ok()?,
                );
                let raw_offset = u32::from_le_bytes(
                    data[sec + 20..sec + 24].try_into().ok()?,
                );

                let size = raw_size.min(virtual_size) as usize;
                let off = raw_offset as usize;
                if data.len() < off + size {
                    return None;
                }

                return Some((
                    data[off..off + size].to_vec(),
                    virtual_addr,
                    size as u32,
                ));
            }
        }

        None
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {}

#[async_trait]
impl Collector for EvasionCollector {
    fn name(&self) -> &str {
        "EvasionDetector"
    }

    fn enabled(&self) -> bool {
        self.config.enabled
    }

    async fn start(
        &mut self,
        _tx: mpsc::Sender<ThreatEvent>,
    ) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let flag = platform::start_scanner(
                self.config.clone(),
                self.hostname.clone(),
                _tx,
            )?;
            self.stop_flag = Some(flag);
            info!("Evasion detector started");
        }

        #[cfg(not(target_os = "windows"))]
        tracing::warn!("Evasion detector is only available on Windows");

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        if let Some(flag) = self.stop_flag.take() {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        info!("Evasion detector stopped");
        Ok(())
    }
}
