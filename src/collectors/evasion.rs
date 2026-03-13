use anyhow::Result;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

use crate::config::EvasionConfig;
use crate::events::{AgentInfo, ThreatEvent};

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
    #[allow(dead_code)] // used on Windows only
    agent: AgentInfo,
    dropped: Arc<AtomicU64>,
    #[cfg(target_os = "windows")]
    stop_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl EvasionCollector {
    pub fn new(config: EvasionConfig, agent: AgentInfo) -> Self {
        Self {
            config,
            agent,
            dropped: Arc::new(AtomicU64::new(0)),
            #[cfg(target_os = "windows")]
            stop_flag: None,
        }
    }
}

// ---- Direct syscall stub scanner (cross-platform, testable) ----------------

/// A syscall stub match found in a byte stream.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields read in tests and on Windows
struct SyscallStubMatch {
    /// Byte offset of the stub within the scanned region.
    offset: usize,
    /// The syscall instruction type found.
    instruction: SyscallInstruction,
    /// System service number from the `mov eax, <SSN>` instruction.
    ssn: u32,
    /// Raw bytes of the matched stub for evidence.
    raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyscallInstruction {
    /// `syscall` — opcode 0F 05
    Syscall,
    /// `int 0x2e` — opcode CD 2E
    Int2E,
}

impl std::fmt::Display for SyscallInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syscall => write!(f, "syscall (0F 05)"),
            Self::Int2E => write!(f, "int 0x2e (CD 2E)"),
        }
    }
}

/// System DLLs that legitimately contain `syscall`/`int 0x2e` stubs.
#[allow(dead_code)] // used on Windows and in tests
const SYSCALL_WHITELISTED_MODULES: &[&str] = &["ntdll.dll", "win32u.dll"];

#[allow(dead_code)] // used on Windows and in tests
fn is_syscall_whitelisted(name: &str) -> bool {
    SYSCALL_WHITELISTED_MODULES
        .iter()
        .any(|s| name.eq_ignore_ascii_case(s))
}

/// Scan a byte slice for direct syscall stub patterns.
///
/// Detects the canonical stub prologue used by SysWhispers and similar tools:
///
/// ```text
/// 4C 8B D1          mov r10, rcx      (or 49 89 CA)
/// B8 xx xx xx xx    mov eax, <SSN>
/// ...               (up to MAX_GAP bytes of intervening instructions)
/// 0F 05             syscall            (or CD 2E — int 0x2e)
/// ```
///
/// The scanner allows a gap between `mov eax` and the syscall instruction
/// to handle the Wow64 compatibility-check variant that inserts a
/// `test byte ptr [SharedUserData], 1; jne` sequence.
#[allow(dead_code)] // used on Windows and in tests
fn scan_for_syscall_stubs(data: &[u8]) -> Vec<SyscallStubMatch> {
    /// Max bytes between `mov eax, SSN` and `syscall`/`int 0x2e`.
    /// 12 covers the Wow64 test+jne sequence (10 bytes).
    const MAX_GAP: usize = 12;

    let mut matches = Vec::new();
    if data.len() < 10 {
        return matches;
    }

    let mut i = 0;
    while i + 9 < data.len() {
        // Step 1: mov r10, rcx  (4C 8B D1 or 49 89 CA)
        let is_mov_r10 =
            (data[i] == 0x4C && data[i + 1] == 0x8B && data[i + 2] == 0xD1)
                || (data[i] == 0x49 && data[i + 1] == 0x89 && data[i + 2] == 0xCA);
        if !is_mov_r10 {
            i += 1;
            continue;
        }

        // Step 2: mov eax, imm32  (B8 xx xx xx xx)
        if i + 7 >= data.len() || data[i + 3] != 0xB8 {
            i += 1;
            continue;
        }

        let ssn = u32::from_le_bytes([
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]);

        // Step 3: scan forward for syscall/int 0x2e within MAX_GAP
        let scan_end = (i + 8 + MAX_GAP).min(data.len().saturating_sub(1));
        let mut found = false;
        for j in (i + 8)..=scan_end {
            if j + 1 >= data.len() {
                break;
            }
            let instr = if data[j] == 0x0F && data[j + 1] == 0x05 {
                Some(SyscallInstruction::Syscall)
            } else if data[j] == 0xCD && data[j + 1] == 0x2E {
                Some(SyscallInstruction::Int2E)
            } else {
                None
            };

            if let Some(instruction) = instr {
                let mut end = j + 2;
                // Include trailing ret (C3) if present
                if end < data.len() && data[end] == 0xC3 {
                    end += 1;
                }
                matches.push(SyscallStubMatch {
                    offset: i,
                    instruction,
                    ssn,
                    raw_bytes: data[i..end].to_vec(),
                });
                found = true;
                i = end;
                break;
            }
        }

        if !found {
            i += 1;
        }
    }

    matches
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
        agent: crate::events::AgentInfo,
        tx: mpsc::Sender<ThreatEvent>,
        dropped: Arc<AtomicU64>,
    ) -> Result<Arc<AtomicBool>> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();

        tokio::task::spawn_blocking(move || {
            scan_loop(&config, &agent, &tx, &stop_clone, &dropped);
        });

        Ok(stop)
    }

    fn scan_loop(
        config: &EvasionConfig,
        agent: &crate::events::AgentInfo,
        tx: &mpsc::Sender<ThreatEvent>,
        stop: &Arc<AtomicBool>,
        dropped: &Arc<AtomicU64>,
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
                        check_etw_patching(handle, *pid, agent)
                    {
                        if let Err(e) = tx.try_send(evt) {
                            dropped.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(error = %e, "Evasion event dropped");
                        }
                    }
                }

                if config.detect_amsi_bypass {
                    if let Some(evt) =
                        check_amsi_bypass(handle, *pid, agent)
                    {
                        if let Err(e) = tx.try_send(evt) {
                            dropped.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(error = %e, "Evasion event dropped");
                        }
                    }
                }

                if config.detect_unhooking {
                    if let Some(evt) = check_ntdll_unhooking(
                        handle,
                        *pid,
                        agent,
                        &ntdll_reference,
                    ) {
                        if let Err(e) = tx.try_send(evt) {
                            dropped.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(error = %e, "Evasion event dropped");
                        }
                    }
                }

                if config.detect_direct_syscall {
                    if let Some(evt) =
                        check_direct_syscall(handle, *pid, agent)
                    {
                        if let Err(e) = tx.try_send(evt) {
                            dropped.fetch_add(1, Ordering::Relaxed);
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
        agent: &crate::events::AgentInfo,
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
            let evidence = vec![
                format!("EtwEventWrite first bytes: {:02X} {:02X} {:02X} {:02X}", buf[0], buf[1], buf[2], buf[3]),
                format!("ntdll base in target: 0x{ntdll_base:X}"),
                format!("function offset: 0x{offset:X}"),
            ];
            return Some(ThreatEvent::with_rule(
                agent,
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
                RuleMetadata {
                    id: "TF-EVA-001".into(),
                    name: "ETW Event Write Patching".into(),
                    description: "ntdll!EtwEventWrite has been patched to \
                        return immediately, disabling user-mode ETW telemetry \
                        for this process."
                        .into(),
                    mitre: MitreRef {
                        tactic: "Defense Evasion".into(),
                        technique_id: "T1562.006".into(),
                        technique_name: "Impair Defenses: Indicator Blocking".into(),
                    },
                    confidence: Confidence::High,
                    evidence,
                },
            ));
        }

        None
    }

    // ---- AMSI bypass detection ----------------------------------------------

    fn check_amsi_bypass(
        handle: HANDLE,
        pid: u32,
        agent: &crate::events::AgentInfo,
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
            let evidence = vec![
                format!("AmsiScanBuffer first bytes: {:02X?}", &buf[..6]),
                format!("amsi.dll base in target: 0x{amsi_base:X}"),
                format!("function offset: 0x{offset:X}"),
            ];
            return Some(ThreatEvent::with_rule(
                agent,
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
                RuleMetadata {
                    id: "TF-EVA-002".into(),
                    name: "AMSI Scan Buffer Bypass".into(),
                    description: "amsi!AmsiScanBuffer has been patched to \
                        return a hardcoded result, bypassing script content \
                        inspection."
                        .into(),
                    mitre: MitreRef {
                        tactic: "Defense Evasion".into(),
                        technique_id: "T1562.001".into(),
                        technique_name: "Impair Defenses: Disable or Modify Tools".into(),
                    },
                    confidence: Confidence::High,
                    evidence,
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
        /// Whether EDR hooks are detected in the current environment.
        ///
        /// We compare our own in-memory ntdll against the on-disk copy.
        /// If they differ significantly, EDR hooks are installed. Without
        /// this guard, every unhooked process (including legitimate ones
        /// that EDR never injected into) would trigger a false positive.
        ///
        /// Known limitation: if the EDR exempts our sensor process from
        /// hooking, this will be false and unhooking detection inactive.
        /// This is a deliberate trade-off — false negatives in that edge
        /// case are preferable to mass false positives.
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
                "EDR hooks detected in our ntdll — unhooking detection active"
            );
        } else {
            tracing::warn!(
                "No EDR hooks detected in our ntdll — unhooking detection \
                 will be inactive. If an EDR is installed but exempts this \
                 sensor, this is a known limitation."
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
        agent: &crate::events::AgentInfo,
        reference: &Option<NtdllReference>,
    ) -> Option<ThreatEvent> {
        let reference = reference.as_ref()?;

        // Without hooks in our environment, a "clean" ntdll in a target
        // process is expected, not suspicious.  Skip to avoid false positives.
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
            let pct = if sample_len > 0 {
                (diff_count as f64 / sample_len as f64) * 100.0
            } else {
                0.0
            };
            let evidence = vec![
                format!("{diff_count}/{sample_len} bytes differ from clean on-disk copy ({pct:.2}%)"),
                format!("ntdll base in target: 0x{ntdll_base:X}"),
                format!(".text RVA: 0x{:X}, size: {sample_len}", reference.text_rva),
                "EDR hooks confirmed present in sensor's own ntdll".into(),
            ];
            return Some(ThreatEvent::with_rule(
                agent,
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
                RuleMetadata {
                    id: "TF-EVA-003".into(),
                    name: "ntdll User-Mode Hook Removal".into(),
                    description: "The process's ntdll .text section closely \
                        matches the clean on-disk copy despite EDR hooks \
                        being present in the environment, indicating the \
                        process has replaced its hooked ntdll."
                        .into(),
                    mitre: MitreRef {
                        tactic: "Defense Evasion".into(),
                        technique_id: "T1562.001".into(),
                        technique_name: "Impair Defenses: Disable or Modify Tools".into(),
                    },
                    confidence: Confidence::Medium,
                    evidence,
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

    // ---- Direct syscall detection ----------------------------------------------

    /// Maximum bytes to read from a remote module's .text section.
    const MAX_TEXT_READ: usize = 1024 * 1024; // 1 MB

    fn check_direct_syscall(
        handle: HANDLE,
        pid: u32,
        agent: &crate::events::AgentInfo,
    ) -> Option<ThreatEvent> {
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
            let mut name_buf = [0u8; 260];
            let len = unsafe {
                GetModuleBaseNameA(handle, *m, &mut name_buf)
            };
            if len == 0 {
                continue;
            }
            let mod_name =
                std::str::from_utf8(&name_buf[..len as usize])
                    .unwrap_or("");

            // Skip DLLs that legitimately contain syscall stubs
            if super::is_syscall_whitelisted(mod_name) {
                continue;
            }

            let module_base = m.0 as usize;
            let (text, _text_rva) =
                match read_remote_text_section(handle, module_base) {
                    Some(t) => t,
                    None => continue,
                };

            let stubs = super::scan_for_syscall_stubs(&text);
            if stubs.is_empty() {
                continue;
            }

            let first = &stubs[0];
            let evidence = vec![
                format!(
                    "module: {} at base 0x{:X}",
                    mod_name, module_base
                ),
                format!(
                    "{} syscall stub(s) found in .text section",
                    stubs.len()
                ),
                format!(
                    "first stub at .text+0x{:X}: {}",
                    first.offset, first.instruction
                ),
                format!("SSN: 0x{:X}", first.ssn),
                format!("stub bytes: {:02X?}", first.raw_bytes),
            ];

            return Some(ThreatEvent::with_rule(
                agent,
                EventSource::EvasionDetector,
                EventCategory::Evasion,
                Severity::High,
                EventData::EvasionDetected {
                    technique: EvasionTechnique::DirectSyscall,
                    pid: Some(pid),
                    process_name: None,
                    details: format!(
                        "{} direct syscall stub(s) in module {}: \
                         process bypasses ntdll user-mode hooks",
                        stubs.len(),
                        mod_name,
                    ),
                },
                RuleMetadata {
                    id: "TF-EVA-004".into(),
                    name: "Direct Syscall Stub".into(),
                    description: "A non-system module contains \
                        syscall/int 0x2e stubs with the canonical \
                        mov r10,rcx; mov eax,SSN prologue used by \
                        tools like SysWhispers. The process makes \
                        direct system calls that bypass ntdll \
                        user-mode hooks installed by security tools."
                        .into(),
                    mitre: MitreRef {
                        tactic: "Defense Evasion".into(),
                        technique_id: "T1562.001".into(),
                        technique_name:
                            "Impair Defenses: Disable or Modify Tools"
                                .into(),
                    },
                    confidence: Confidence::High,
                    evidence,
                },
            ));
        }

        None
    }

    /// Read the .text section of a remote module by parsing its PE
    /// header from the target process's memory.  Returns `(bytes, rva)`.
    fn read_remote_text_section(
        handle: HANDLE,
        module_base: usize,
    ) -> Option<(Vec<u8>, u32)> {
        // Read DOS header (first 64 bytes)
        let mut dos = [0u8; 64];
        let mut read = 0usize;
        unsafe {
            ReadProcessMemory(
                handle,
                module_base as *const std::ffi::c_void,
                dos.as_mut_ptr() as *mut std::ffi::c_void,
                64,
                Some(&mut read),
            )
            .ok()?;
        }
        if read < 64 || dos[0] != b'M' || dos[1] != b'Z' {
            return None;
        }

        let pe_offset = u32::from_le_bytes(
            dos[0x3C..0x40].try_into().ok()?,
        ) as usize;

        // Read PE + COFF + optional header + section headers
        let header_size = 4 + 20 + 240 + 40 * 96;
        let mut pe_buf = vec![0u8; header_size];
        unsafe {
            ReadProcessMemory(
                handle,
                (module_base + pe_offset) as *const std::ffi::c_void,
                pe_buf.as_mut_ptr() as *mut std::ffi::c_void,
                header_size,
                Some(&mut read),
            )
            .ok()?;
        }
        if read < 28 || &pe_buf[0..4] != b"PE\0\0" {
            return None;
        }

        let coff_start = 4;
        let num_sections = u16::from_le_bytes(
            pe_buf[coff_start + 2..coff_start + 4].try_into().ok()?,
        ) as usize;
        let opt_header_size = u16::from_le_bytes(
            pe_buf[coff_start + 16..coff_start + 18]
                .try_into()
                .ok()?,
        ) as usize;

        let sections_start = coff_start + 20 + opt_header_size;

        for i in 0..num_sections {
            let sec = sections_start + i * 40;
            if pe_buf.len() < sec + 40 {
                break;
            }
            if pe_buf[sec..sec + 8].starts_with(b".text") {
                let virtual_size = u32::from_le_bytes(
                    pe_buf[sec + 8..sec + 12].try_into().ok()?,
                );
                let virtual_addr = u32::from_le_bytes(
                    pe_buf[sec + 12..sec + 16].try_into().ok()?,
                );

                let size =
                    (virtual_size as usize).min(MAX_TEXT_READ);
                let text_addr =
                    module_base + virtual_addr as usize;

                let mut text = vec![0u8; size];
                let ok = unsafe {
                    ReadProcessMemory(
                        handle,
                        text_addr as *const std::ffi::c_void,
                        text.as_mut_ptr()
                            as *mut std::ffi::c_void,
                        size,
                        Some(&mut read),
                    )
                };

                if ok.is_err() || read < size {
                    return None;
                }

                return Some((text, virtual_addr));
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
                self.agent.clone(),
                _tx,
                self.dropped.clone(),
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

    fn dropped_events(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- syscall stub scanner tests ----------------------------------------

    #[test]
    fn detect_classic_syscall_stub() {
        // SysWhispers2 classic: mov r10,rcx; mov eax,0x18; syscall; ret
        let data = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, 0x18
            0x0F, 0x05, // syscall
            0xC3, // ret
        ];
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 0);
        assert_eq!(matches[0].ssn, 0x18);
        assert_eq!(matches[0].instruction, SyscallInstruction::Syscall);
        assert_eq!(matches[0].raw_bytes, data.to_vec());
    }

    #[test]
    fn detect_int2e_stub() {
        let data = [
            0x4C, 0x8B, 0xD1,
            0xB8, 0x50, 0x00, 0x00, 0x00,
            0xCD, 0x2E, // int 0x2e
            0xC3,
        ];
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].instruction, SyscallInstruction::Int2E);
        assert_eq!(matches[0].ssn, 0x50);
    }

    #[test]
    fn detect_alternate_mov_r10_encoding() {
        // 49 89 CA is the alternate encoding of mov r10, rcx
        let data = [
            0x49, 0x89, 0xCA,
            0xB8, 0x26, 0x00, 0x00, 0x00,
            0x0F, 0x05,
            0xC3,
        ];
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].ssn, 0x26);
    }

    #[test]
    fn detect_wow64_variant_with_gap() {
        // Wow64 compat check inserts test+jne between mov eax and syscall
        let data = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, 0x18
            0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, // test byte ptr [7FFE0308h], 1
            0x75, 0x03, // jne +3
            0x0F, 0x05, // syscall
            0xC3, // ret
        ];
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].ssn, 0x18);
        assert_eq!(matches[0].instruction, SyscallInstruction::Syscall);
    }

    #[test]
    fn no_match_on_regular_code() {
        let data = [
            0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
            0x48, 0x89, 0x6C, 0x24, 0x10, // mov [rsp+10], rbp
            0x48, 0x89, 0x74, 0x24, 0x18, // mov [rsp+18], rsi
            0x57, // push rdi
            0x41, 0x56, // push r14
            0xC3, // ret
        ];
        assert!(scan_for_syscall_stubs(&data).is_empty());
    }

    #[test]
    fn empty_input() {
        assert!(scan_for_syscall_stubs(&[]).is_empty());
    }

    #[test]
    fn short_input_no_panic() {
        assert!(scan_for_syscall_stubs(&[0x4C, 0x8B]).is_empty());
    }

    #[test]
    fn multiple_stubs_detected() {
        let mut data = Vec::new();
        // Stub 1: SSN 0x18
        data.extend_from_slice(&[
            0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00,
            0x0F, 0x05, 0xC3,
        ]);
        // Padding
        data.extend_from_slice(&[0xCC; 5]);
        // Stub 2: SSN 0x3A
        data.extend_from_slice(&[
            0x4C, 0x8B, 0xD1, 0xB8, 0x3A, 0x00, 0x00, 0x00,
            0x0F, 0x05, 0xC3,
        ]);

        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].ssn, 0x18);
        assert_eq!(matches[1].ssn, 0x3A);
    }

    #[test]
    fn no_match_without_mov_eax() {
        // mov r10,rcx present but no mov eax before syscall
        let data = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0x90, 0x90, 0x90, 0x90, 0x90, // nops
            0x0F, 0x05, // syscall
        ];
        assert!(scan_for_syscall_stubs(&data).is_empty());
    }

    #[test]
    fn no_match_when_gap_too_large() {
        let mut data = vec![
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, 0x18
        ];
        // 20 nops — exceeds MAX_GAP of 12
        data.extend_from_slice(&[0x90; 20]);
        data.extend_from_slice(&[0x0F, 0x05]); // syscall

        assert!(scan_for_syscall_stubs(&data).is_empty());
    }

    #[test]
    fn stub_without_trailing_ret() {
        let data = [
            0x4C, 0x8B, 0xD1,
            0xB8, 0x18, 0x00, 0x00, 0x00,
            0x0F, 0x05,
            0x90, // nop instead of ret
        ];
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        // raw_bytes should NOT include the trailing nop
        assert_eq!(matches[0].raw_bytes.len(), 10);
    }

    #[test]
    fn stub_embedded_in_larger_code() {
        let mut data = Vec::new();
        // Preamble: random code
        data.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 28h
        data.extend_from_slice(&[0x48, 0x8B, 0xC1]); // mov rax, rcx
        // Syscall stub at offset 7
        data.extend_from_slice(&[
            0x4C, 0x8B, 0xD1, 0xB8, 0x55, 0x00, 0x00, 0x00,
            0x0F, 0x05, 0xC3,
        ]);
        // Epilogue
        data.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 28h
        data.extend_from_slice(&[0xC3]); // ret

        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 7);
        assert_eq!(matches[0].ssn, 0x55);
    }

    #[test]
    fn instruction_display() {
        assert_eq!(
            format!("{}", SyscallInstruction::Syscall),
            "syscall (0F 05)"
        );
        assert_eq!(
            format!("{}", SyscallInstruction::Int2E),
            "int 0x2e (CD 2E)"
        );
    }

    // ---- whitelist tests ---------------------------------------------------

    #[test]
    fn whitelist_system_dlls() {
        assert!(is_syscall_whitelisted("ntdll.dll"));
        assert!(is_syscall_whitelisted("NTDLL.DLL"));
        assert!(is_syscall_whitelisted("win32u.dll"));
        assert!(is_syscall_whitelisted("Win32u.DLL"));
    }

    #[test]
    fn whitelist_rejects_non_system() {
        assert!(!is_syscall_whitelisted("malware.dll"));
        assert!(!is_syscall_whitelisted("myapp.exe"));
        assert!(!is_syscall_whitelisted("kernel32.dll"));
    }
}
