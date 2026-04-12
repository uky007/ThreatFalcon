use anyhow::Result;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

use crate::config::EvasionConfig;
use crate::events::{AgentInfo, Confidence, ThreatEvent};

use super::Collector;

// ---------------------------------------------------------------------------
// Scan request channel: ETW → Evasion
// ---------------------------------------------------------------------------

/// Requests sent from the ETW collector to trigger immediate scans.
#[derive(Debug)]
#[allow(dead_code)]
pub enum ScanRequest {
    /// A new process was created — scan its memory immediately.
    ProcessCreated { pid: u32 },
    /// A new module was loaded — scan the on-disk PE for syscall stubs.
    ImageLoaded { pid: u32, image_path: String },
    /// A Threat Intelligence event fired — check if the calling process
    /// imports the syscall function from ntdll.  If not, it used a
    /// direct syscall.
    ThreatIntelligence {
        calling_pid: u32,
        /// The Nt* function that was called (e.g. "NtAllocateVirtualMemory").
        function_name: String,
        /// Original TI event ID for evidence.
        ti_event_id: u16,
    },
}

/// Create a scan request channel pair.
///
/// Uses `std::sync::mpsc::sync_channel` (bounded) to prevent
/// unbounded memory growth when the consumer falls behind under
/// ProcessCreate/ImageLoad/TI event bursts.  Excess requests are
/// silently dropped by the ETW sender (try_send).
const SCAN_REQUEST_CAPACITY: usize = 4096;

pub fn scan_request_channel() -> (
    std::sync::mpsc::SyncSender<ScanRequest>,
    std::sync::mpsc::Receiver<ScanRequest>,
) {
    std::sync::mpsc::sync_channel(SCAN_REQUEST_CAPACITY)
}

/// Periodically scans running processes to detect EDR evasion techniques,
/// and handles on-demand scan requests from the ETW collector.
///
/// Detection layers:
/// 1. **Periodic memory scan**: polls all processes every `scan_interval_ms`
/// 2. **ProcessCreate scan**: immediate memory scan on new process creation
/// 3. **ImageLoad disk scan**: scans on-disk PE when a new module loads
/// 4. **TI × import correlation**: checks if a TI-flagged syscall was
///    imported from ntdll (if not → direct syscall evidence)
pub struct EvasionCollector {
    config: EvasionConfig,
    #[allow(dead_code)] // used on Windows only
    agent: AgentInfo,
    dropped: Arc<AtomicU64>,
    /// Receiver for on-demand scan requests from ETW collector.
    /// Wrapped in Mutex because Collector trait requires Sync, but
    /// std::sync::mpsc::Receiver is !Sync.  The Mutex is only locked
    /// once in start() to take the receiver.
    #[allow(dead_code)]
    scan_rx: std::sync::Mutex<Option<std::sync::mpsc::Receiver<ScanRequest>>>,
    #[cfg(target_os = "windows")]
    stop_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl EvasionCollector {
    pub fn new(
        config: EvasionConfig,
        agent: AgentInfo,
        scan_rx: std::sync::mpsc::Receiver<ScanRequest>,
    ) -> Self {
        Self {
            config,
            agent,
            dropped: Arc::new(AtomicU64::new(0)),
            scan_rx: std::sync::Mutex::new(Some(scan_rx)),
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
    /// True when the stub ends with an indirect jump (`jmp [rip+disp]`,
    /// `jmp r11`, etc.) rather than an inline `syscall`/`int 0x2e`.
    /// Indirect matches have lower confidence because the jump target
    /// cannot be verified from a static byte scan alone.
    indirect: bool,
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

/// Maximum plausible syscall service number.
///
/// Windows has ~500 syscalls; the highest SSN observed in recent builds
/// is around 0x200.  Anything above this threshold is almost certainly
/// a coincidental byte pattern, not a real syscall stub.
#[allow(dead_code)]
const MAX_PLAUSIBLE_SSN: u32 = 0x600;

/// Scan a byte slice for direct syscall stub patterns.
///
/// Detects two prologue orders used by SysWhispers and similar tools:
///
/// **Order A** (SysWhispers canonical):
/// ```text
/// 4C 8B D1          mov r10, rcx      (or 49 89 CA)
/// B8 xx xx xx xx    mov eax, <SSN>
/// ```
///
/// **Order B** (reversed, used by some toolkits):
/// ```text
/// B8 xx xx xx xx    mov eax, <SSN>
/// 4C 8B D1          mov r10, rcx      (or 49 89 CA)
/// ```
///
/// After the prologue, the scanner looks for one of:
/// - `0F 05`  — `syscall`
/// - `CD 2E`  — `int 0x2e`
/// - `FF 25`  — `jmp [rip+disp32]` (indirect syscall via ntdll)
/// - `41 FF E3` / `41 FF E1` — `jmp r11` / `jmp r9` (register indirect)
///
/// within a small gap.  An SSN range check (< MAX_PLAUSIBLE_SSN)
/// eliminates false positives from coincidental byte sequences.
#[allow(dead_code)] // used on Windows and in tests
fn scan_for_syscall_stubs(data: &[u8]) -> Vec<SyscallStubMatch> {
    /// Max bytes between the prologue end and the syscall/jmp instruction.
    /// 12 covers the Wow64 test+jne sequence (10 bytes).
    const MAX_GAP: usize = 12;

    let mut matches = Vec::new();
    if data.len() < 10 {
        return matches;
    }

    let mut i = 0;
    while i + 9 < data.len() {
        // Try both prologue orders:
        //   Order A: mov r10, rcx (3 bytes) + mov eax, SSN (5 bytes) = 8 bytes
        //   Order B: mov eax, SSN (5 bytes) + mov r10, rcx (3 bytes) = 8 bytes
        let (ssn, prologue_end) = if is_mov_r10_rcx(data, i)
            && i + 7 < data.len()
            && data[i + 3] == 0xB8
        {
            // Order A: mov r10, rcx; mov eax, SSN
            let ssn = u32::from_le_bytes([
                data[i + 4],
                data[i + 5],
                data[i + 6],
                data[i + 7],
            ]);
            (ssn, i + 8)
        } else if data[i] == 0xB8
            && i + 7 < data.len()
            && is_mov_r10_rcx(data, i + 5)
        {
            // Order B: mov eax, SSN; mov r10, rcx
            let ssn = u32::from_le_bytes([
                data[i + 1],
                data[i + 2],
                data[i + 3],
                data[i + 4],
            ]);
            (ssn, i + 8)
        } else {
            i += 1;
            continue;
        };

        // Reject implausible SSNs to eliminate false positives
        if ssn > MAX_PLAUSIBLE_SSN {
            i += 1;
            continue;
        }

        // Scan forward for syscall/int 2e/indirect jmp within MAX_GAP
        let scan_end = (prologue_end + MAX_GAP).min(data.len().saturating_sub(1));
        let mut found = false;
        let mut j = prologue_end;
        while j <= scan_end {
            if j + 1 >= data.len() {
                break;
            }

            // (instruction, end_position, is_indirect)
            let instr = if data[j] == 0x0F && data[j + 1] == 0x05 {
                Some((SyscallInstruction::Syscall, j + 2, false))
            } else if data[j] == 0xCD && data[j + 1] == 0x2E {
                Some((SyscallInstruction::Int2E, j + 2, false))
            } else if data[j] == 0xFF && data[j + 1] == 0x25 && j + 5 < data.len() {
                // jmp [rip+disp32] — possible indirect syscall
                Some((SyscallInstruction::Syscall, j + 6, true))
            } else if j + 2 < data.len()
                && data[j] == 0x41
                && data[j + 1] == 0xFF
                && (data[j + 2] == 0xE3 || data[j + 2] == 0xE1)
            {
                // jmp r11 / jmp r9 — possible register-indirect syscall
                Some((SyscallInstruction::Syscall, j + 3, true))
            } else {
                None
            };

            if let Some((instruction, end_pos, is_indirect)) = instr {
                let mut end = end_pos;
                // Include trailing ret (C3) if present
                if end < data.len() && data[end] == 0xC3 {
                    end += 1;
                }
                matches.push(SyscallStubMatch {
                    offset: i,
                    instruction,
                    ssn,
                    raw_bytes: data[i..end].to_vec(),
                    indirect: is_indirect,
                });
                found = true;
                i = end;
                break;
            }

            j += 1;
        }

        if !found {
            i += 1;
        }
    }

    matches
}

/// Check if bytes at `pos` are `mov r10, rcx` (4C 8B D1 or 49 89 CA).
#[inline]
#[allow(dead_code)]
fn is_mov_r10_rcx(data: &[u8], pos: usize) -> bool {
    pos + 2 < data.len()
        && ((data[pos] == 0x4C && data[pos + 1] == 0x8B && data[pos + 2] == 0xD1)
            || (data[pos] == 0x49 && data[pos + 1] == 0x89 && data[pos + 2] == 0xCA))
}

/// Detect known AMSI bypass patterns in the first bytes of AmsiScanBuffer.
///
/// Returns `(description, confidence)` if a patch pattern is recognized.
/// Extracted from the platform module for cross-platform testing.
#[allow(dead_code)] // used on Windows; tested cross-platform
fn detect_amsi_patch_pattern(
    bytes: &[u8],
) -> Option<(&'static str, Confidence)> {
    if bytes.len() < 2 {
        return None;
    }

    // Pattern 1: mov eax, imm32; ret  (B8 xx xx xx xx C3)
    // Most common — forces a specific HRESULT return.
    // 0x80070057 = E_INVALIDARG (classic AmsiScanBuffer bypass)
    // 0x00000001 = S_FALSE, etc.
    if bytes.len() >= 6 && bytes[0] == 0xB8 && bytes[5] == 0xC3 {
        let imm =
            u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        return Some((
            match imm {
                0x80070057 => "mov eax, 0x80070057 (E_INVALIDARG); ret",
                0x00000001 => "mov eax, 1 (S_FALSE); ret",
                _ => "mov eax, <imm32>; ret — forced return value",
            },
            Confidence::High,
        ));
    }

    // Pattern 2: xor eax, eax; ret  (31 C0 C3  or  33 C0 C3)
    // Returns S_OK (0), telling caller the scan completed successfully
    // with no detection.
    if bytes.len() >= 3
        && (bytes[0] == 0x31 || bytes[0] == 0x33)
        && bytes[1] == 0xC0
        && bytes[2] == 0xC3
    {
        return Some((
            "xor eax, eax; ret — returns S_OK (scan always clean)",
            Confidence::High,
        ));
    }

    // Pattern 3: immediate ret (C3)
    // Skips the function body entirely; return value is whatever
    // happened to be in eax — usually succeeds with garbage result.
    if bytes[0] == 0xC3 {
        return Some((
            "ret — immediate return, function body skipped",
            Confidence::Medium,
        ));
    }

    // Pattern 4: nop; ret  (90 C3)
    if bytes.len() >= 2 && bytes[0] == 0x90 && bytes[1] == 0xC3 {
        return Some((
            "nop; ret — function body replaced with no-op",
            Confidence::Medium,
        ));
    }

    None
}

/// Map TI event IDs to the Nt* function that was called.
#[allow(dead_code)]
pub fn ti_event_to_function(event_id: u16) -> Option<&'static str> {
    match event_id {
        1 | 6 => Some("NtAllocateVirtualMemory"),
        2 | 7 => Some("NtProtectVirtualMemory"),
        3 | 8 => Some("NtMapViewOfSection"),
        4 => Some("NtQueueApcThread"),
        5 => Some("NtSetContextThread"),
        9 => Some("NtSuspendThread"),
        10 => Some("NtResumeThread"),
        _ => None,
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
        agent: crate::events::AgentInfo,
        tx: mpsc::Sender<ThreatEvent>,
        dropped: Arc<AtomicU64>,
        scan_rx: std::sync::mpsc::Receiver<super::ScanRequest>,
    ) -> Result<Arc<AtomicBool>> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();

        tokio::task::spawn_blocking(move || {
            scan_loop(&config, &agent, &tx, &stop_clone, &dropped, scan_rx);
        });

        Ok(stop)
    }

    fn emit(
        tx: &mpsc::Sender<ThreatEvent>,
        dropped: &Arc<AtomicU64>,
        evt: ThreatEvent,
    ) {
        if let Err(e) = tx.try_send(evt) {
            dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(error = %e, "Evasion event dropped");
        }
    }

    fn scan_loop(
        config: &EvasionConfig,
        agent: &crate::events::AgentInfo,
        tx: &mpsc::Sender<ThreatEvent>,
        stop: &Arc<AtomicBool>,
        dropped: &Arc<AtomicU64>,
        scan_rx: std::sync::mpsc::Receiver<super::ScanRequest>,
    ) {
        let interval =
            std::time::Duration::from_millis(config.scan_interval_ms);

        let ntdll_reference = build_ntdll_reference();
        let amsi_reference = build_amsi_reference();

        let mut last_sweep = std::time::Instant::now()
            .checked_sub(interval)
            .unwrap_or_else(std::time::Instant::now);

        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }

            // --- Drain pending requests BEFORE the sweep ---
            // This ensures ProcessCreate/ImageLoad/TI requests that
            // arrived since the last cycle are handled immediately,
            // not delayed behind a full process enumeration.
            drain_scan_requests(
                &scan_rx, config, agent, tx, dropped,
            );

            // --- Periodic full sweep (only when interval elapsed) ---
            if last_sweep.elapsed() >= interval {
                let pids = enumerate_pids();
                for pid in &pids {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }

                    // Drain requests between processes so short-lived
                    // processes don't expire while we scan others.
                    drain_scan_requests(
                        &scan_rx, config, agent, tx, dropped,
                    );

                    scan_single_process(
                        *pid, config, agent, tx, dropped,
                        &ntdll_reference, &amsi_reference,
                    );
                }
                last_sweep = std::time::Instant::now();
            }

            // Wait for the next request or timeout for the next sweep.
            let remaining = interval
                .checked_sub(last_sweep.elapsed())
                .unwrap_or(std::time::Duration::ZERO);
            if remaining > std::time::Duration::ZERO {
                match scan_rx.recv_timeout(remaining) {
                    Ok(req) => {
                        handle_scan_request(req, config, agent, tx, dropped);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Normal: sweep interval elapsed
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        // ETW sender dropped (shutdown or crash).
                        // Fall back to sleep-based periodic scanning.
                        tracing::warn!(
                            "Scan request channel disconnected — \
                             falling back to periodic-only scanning"
                        );
                        // Continue with periodic sweeps only; use
                        // sleep instead of recv_timeout from now on.
                        loop {
                            if stop.load(Ordering::Relaxed) {
                                return;
                            }
                            std::thread::sleep(interval);
                            drain_scan_requests(
                                &scan_rx, config, agent, tx, dropped,
                            );
                            let pids = enumerate_pids();
                            for pid in &pids {
                                if stop.load(Ordering::Relaxed) {
                                    return;
                                }
                                scan_single_process(
                                    *pid, config, agent, tx, dropped,
                                    &ntdll_reference, &amsi_reference,
                                );
                            }
                            last_sweep = std::time::Instant::now();
                        }
                    }
                }
            }
        }
    }

    /// Process all pending scan requests from the ETW collector.
    fn scan_single_process(
        pid: u32,
        config: &EvasionConfig,
        agent: &crate::events::AgentInfo,
        tx: &tokio::sync::mpsc::Sender<ThreatEvent>,
        dropped: &Arc<AtomicU64>,
        ntdll_reference: &Option<NtdllReference>,
        amsi_reference: &Option<AmsiReference>,
    ) {
        let handle = match open_process(pid) {
            Some(h) => h,
            None => return,
        };

        if config.detect_etw_patching {
            if let Some(evt) = check_etw_patching(handle, pid, agent, ntdll_reference) {
                emit(tx, dropped, evt);
            }
        }
        if config.detect_amsi_bypass {
            if let Some(evt) = check_amsi_bypass(handle, pid, agent, amsi_reference) {
                emit(tx, dropped, evt);
            }
        }
        if config.detect_unhooking {
            if let Some(evt) = check_ntdll_unhooking(handle, pid, agent, ntdll_reference) {
                emit(tx, dropped, evt);
            }
        }
        if config.detect_direct_syscall {
            if let Some(evt) = check_direct_syscall(handle, pid, agent) {
                emit(tx, dropped, evt);
            }
        }

        unsafe { let _ = CloseHandle(handle); }
    }

    fn drain_scan_requests(
        scan_rx: &std::sync::mpsc::Receiver<super::ScanRequest>,
        config: &EvasionConfig,
        agent: &crate::events::AgentInfo,
        tx: &tokio::sync::mpsc::Sender<ThreatEvent>,
        dropped: &Arc<AtomicU64>,
    ) {
        while let Ok(req) = scan_rx.try_recv() {
            handle_scan_request(req, config, agent, tx, dropped);
        }
    }

    fn handle_scan_request(
        req: super::ScanRequest,
        config: &EvasionConfig,
        agent: &crate::events::AgentInfo,
        tx: &mpsc::Sender<ThreatEvent>,
        dropped: &Arc<AtomicU64>,
    ) {
        use super::ScanRequest;
        match req {
            ScanRequest::ProcessCreated { pid } => {
                if !config.detect_direct_syscall {
                    return;
                }
                let handle = match open_process(pid) {
                    Some(h) => h,
                    None => return,
                };
                if let Some(evt) = check_direct_syscall(handle, pid, agent) {
                    emit(tx, dropped, evt);
                }
                unsafe { let _ = CloseHandle(handle); }
            }
            ScanRequest::ImageLoaded { pid: _, image_path } => {
                if !config.detect_direct_syscall {
                    return;
                }
                if let Some(evt) = scan_disk_pe(&image_path, agent) {
                    emit(tx, dropped, evt);
                }
            }
            ScanRequest::ThreatIntelligence {
                calling_pid,
                function_name,
                ti_event_id,
            } => {
                if !config.detect_direct_syscall {
                    return;
                }
                if let Some(evt) = check_ti_import_correlation(
                    calling_pid,
                    &function_name,
                    ti_event_id,
                    agent,
                ) {
                    emit(tx, dropped, evt);
                }
            }
        }
    }

    // ---- ImageLoad disk PE scan -----------------------------------------------

    /// Scan an on-disk PE file for direct syscall stubs.
    ///
    /// Called when ETW reports a new module load (ImageLoad event).
    /// Reads the file from disk, parses the PE, and scans the first
    /// executable section.  Returns a detection event if stubs are found.
    fn scan_disk_pe(
        image_path: &str,
        agent: &crate::events::AgentInfo,
    ) -> Option<ThreatEvent> {
        // Convert NT device path to DOS path if needed
        let path = normalize_nt_path(image_path);

        // Skip system DLLs only if loaded from a system directory.
        // Basename-only check would let an attacker name a payload
        // "ntdll.dll" and bypass scanning entirely.
        let basename = path.rsplit('\\').next().unwrap_or(&path);
        if super::is_syscall_whitelisted(basename) && is_system_path(&path) {
            return None;
        }

        let data = std::fs::read(&path).ok()?;
        let pe = crate::pe::PeHeaders::parse(&data)?;

        // Scan ALL executable sections — stubs can live in any of them
        let sections = pe.all_executable_sections();
        if sections.is_empty() {
            return None;
        }

        let mut stubs = Vec::new();
        let mut scanned_section_name = String::new();
        let mut scanned_section_size = 0usize;
        for section in &sections {
            if let Some(section_data) = pe.read_section_data(&data, section) {
                let found = super::scan_for_syscall_stubs(section_data);
                if !found.is_empty() && stubs.is_empty() {
                    scanned_section_name = section.name.clone();
                    scanned_section_size = section_data.len();
                }
                stubs.extend(found);
            }
        }

        if stubs.is_empty() {
            return None;
        }

        let has_direct = stubs.iter().any(|s| !s.indirect);
        if !has_direct {
            // Indirect-only on disk: emit as telemetry
            return Some(ThreatEvent::new(
                agent,
                EventSource::EvasionDetector,
                EventCategory::Evasion,
                Severity::Info,
                EventData::EvasionDetected {
                    technique: EvasionTechnique::DirectSyscall,
                    pid: None,
                    process_name: Some(basename.to_string()),
                    details: format!(
                        "{} indirect syscall stub(s) found on disk in {}",
                        stubs.len(), basename,
                    ),
                },
            ));
        }

        let first = &stubs[0];
        Some(ThreatEvent::with_rule(
            agent,
            EventSource::EvasionDetector,
            EventCategory::Evasion,
            Severity::High,
            EventData::EvasionDetected {
                technique: EvasionTechnique::DirectSyscall,
                pid: None,
                process_name: Some(basename.to_string()),
                details: format!(
                    "{} direct syscall stub(s) found on disk in {}",
                    stubs.len(), basename,
                ),
            },
            RuleMetadata {
                id: "TF-EVA-005".into(),
                name: "Direct Syscall Stub in Loaded Module (Disk Scan)".into(),
                description: "A newly loaded module contains syscall/int 0x2e \
                    stubs on disk, detected at ImageLoad time. This does not \
                    require the process to remain running."
                    .into(),
                mitre: MitreRef {
                    tactic: "Defense Evasion".into(),
                    technique_id: "T1562.001".into(),
                    technique_name:
                        "Impair Defenses: Disable or Modify Tools".into(),
                },
                confidence: Confidence::High,
                evidence: vec![
                    format!("file: {}", path),
                    format!("section: {} ({} bytes)", scanned_section_name, scanned_section_size),
                    format!("{} syscall stub(s) found", stubs.len()),
                    format!("first stub at section+0x{:X}: {}", first.offset, first.instruction),
                    format!("SSN: 0x{:X}", first.ssn),
                    format!("stub bytes: {:02X?}", first.raw_bytes),
                ],
            },
        ))
    }

    /// Convert `\Device\HarddiskVolumeN\...` to `X:\...` using
    /// QueryDosDevice.  Falls back to the original path if conversion
    /// fails.
    /// Check if a file path is in a system directory.
    fn is_system_path(path: &str) -> bool {
        let path_lower = path.to_ascii_lowercase();
        let sys_root = std::env::var("SystemRoot")
            .unwrap_or_else(|_| r"C:\Windows".to_string())
            .to_ascii_lowercase();
        path_lower.starts_with(&format!(r"{}\system32\", sys_root))
            || path_lower.starts_with(&format!(r"{}\syswow64\", sys_root))
    }

    fn normalize_nt_path(path: &str) -> String {
        if !path.starts_with("\\Device\\") {
            return path.to_string();
        }

        // Extract the volume part: \Device\HarddiskVolume3
        let rest = &path["\\Device\\".len()..];
        let vol_end = rest.find('\\').unwrap_or(rest.len());
        let volume = &path[..("\\Device\\".len() + vol_end)];
        let remainder = &path[("\\Device\\".len() + vol_end)..];

        // Try drive letters A-Z
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let wide_drive: Vec<u16> = drive
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut buf = [0u16; 260];
            let len = unsafe {
                windows::Win32::Storage::FileSystem::QueryDosDeviceW(
                    windows::core::PCWSTR(wide_drive.as_ptr()),
                    Some(&mut buf),
                )
            };
            if len == 0 {
                continue;
            }
            // QueryDosDevice returns a double-null terminated multi-sz
            let device = String::from_utf16_lossy(
                &buf[..buf.iter().position(|&c| c == 0).unwrap_or(len as usize)],
            );
            if device.eq_ignore_ascii_case(volume) {
                return format!("{drive}{remainder}");
            }
        }

        path.to_string()
    }

    // ---- TI × import correlation ----------------------------------------------

    /// Check if a TI-flagged syscall was imported by ANY loaded module.
    ///
    /// Scans all modules in the process for ntdll imports of the
    /// function.  If no module imports it, emits **telemetry** (not an
    /// alert) — the absence of a static import is a weak signal
    /// because the function can also be reached via kernel32 wrappers,
    /// delay-loading, or GetProcAddress.
    fn check_ti_import_correlation(
        calling_pid: u32,
        function_name: &str,
        ti_event_id: u16,
        agent: &crate::events::AgentInfo,
    ) -> Option<ThreatEvent> {
        let handle = open_process(calling_pid)?;

        // Enumerate ALL loaded modules
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
                let _ = CloseHandle(handle);
                return None;
            }
        }

        let count = (needed as usize / std::mem::size_of::<HMODULE>())
            .min(modules.len());

        // Check if ANY module statically imports the function from ntdll
        let mut found_import = false;
        let mut exe_name = String::new();
        for (idx, m) in modules[..count].iter().enumerate() {
            let mut path_buf = [0u8; 520];
            let path_len = unsafe {
                GetModuleFileNameExA(handle, *m, &mut path_buf)
            };
            if path_len == 0 {
                continue;
            }
            let mod_path = std::str::from_utf8(&path_buf[..path_len as usize])
                .unwrap_or("");

            if idx == 0 {
                exe_name = mod_path
                    .rsplit('\\')
                    .next()
                    .unwrap_or(mod_path)
                    .to_string();
            }

            // Read on-disk PE and check imports
            if let Ok(pe_data) = std::fs::read(mod_path) {
                if let Some(pe) = crate::pe::PeHeaders::parse(&pe_data) {
                    if pe.has_import(&pe_data, "ntdll.dll", function_name) {
                        found_import = true;
                        break;
                    }
                }
            }
        }

        unsafe { let _ = CloseHandle(handle); }

        if found_import {
            return None;
        }

        // No module imports the function — emit as telemetry (Info,
        // no rule metadata).  This is a weak signal: kernel32 wrappers,
        // delay-loading, and GetProcAddress can all reach Nt* functions
        // without a static ntdll import.
        Some(ThreatEvent::new(
            agent,
            EventSource::EvasionDetector,
            EventCategory::Evasion,
            Severity::Info,
            EventData::EvasionDetected {
                technique: EvasionTechnique::DirectSyscall,
                pid: Some(calling_pid),
                process_name: Some(exe_name),
                details: format!(
                    "PID {} called {} (TI event {}) — no loaded module \
                     statically imports it from ntdll.dll (weak signal, \
                     may be kernel32 wrapper or GetProcAddress)",
                    calling_pid, function_name, ti_event_id,
                ),
            },
        ))
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
        ntdll_ref: &Option<NtdllReference>,
    ) -> Option<ThreatEvent> {
        let ntdll_ref = ntdll_ref.as_ref()?;
        let rva = ntdll_ref.etw_write_rva?;
        let ntdll_base = find_module_in_process(handle, "ntdll.dll")?;
        let target_addr = ntdll_base + rva as usize;

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
                format!("function RVA: 0x{rva:X} (from export table)"),
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
        amsi_ref: &Option<AmsiReference>,
    ) -> Option<ThreatEvent> {
        let amsi_ref = amsi_ref.as_ref()?;
        let amsi_base = find_module_in_process(handle, "amsi.dll")?;
        let target_addr = amsi_base + amsi_ref.scan_buffer_rva as usize;

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

        // Detect known AMSI bypass patterns in the first bytes of
        // AmsiScanBuffer.  Each pattern is a (description, confidence)
        // pair so evidence is self-documenting.
        let patch = detect_amsi_patch_pattern(&buf[..read]);

        if let Some((description, confidence)) = patch {
            let evidence = vec![
                format!("AmsiScanBuffer first bytes: {:02X?}", &buf[..read.min(8)]),
                format!("decoded: {description}"),
                format!("amsi.dll base in target: 0x{amsi_base:X}"),
                format!("function RVA: 0x{:X} (from export table)", amsi_ref.scan_buffer_rva),
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
                        "AmsiScanBuffer patched: {description} (bytes: {:02X?})",
                        &buf[..read.min(8)]
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
                    confidence,
                    evidence,
                },
            ));
        }

        None
    }

    // ---- ntdll unhooking detection ------------------------------------------

    /// Reference data for ntdll unhooking and ETW patching detection.
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
        /// RVA of `EtwEventWrite` from the export table.
        /// Used by ETW patching detection to locate the function in
        /// target processes without calling GetProcAddress per-process.
        etw_write_rva: Option<u32>,
    }

    /// Reference data for AMSI bypass detection.
    struct AmsiReference {
        /// RVA of `AmsiScanBuffer` from the on-disk amsi.dll export table.
        scan_buffer_rva: u32,
    }

    /// Build the ntdll reference by parsing the on-disk PE headers and
    /// export table, then comparing .text with our in-memory copy to
    /// detect whether hooks are installed.
    fn build_ntdll_reference() -> Option<NtdllReference> {
        let path = r"C:\Windows\System32\ntdll.dll";
        let data = std::fs::read(path).ok()?;
        let pe = crate::pe::PeHeaders::parse(&data)?;
        let text = pe.text_section()?;
        let ondisk_text = pe.read_section_data(&data, text)?.to_vec();
        let text_rva = text.virtual_address;
        let text_size = ondisk_text.len() as u32;

        // Resolve EtwEventWrite RVA from export table (replaces per-process
        // GetProcAddress calls with a single on-disk parse at startup).
        let etw_write_rva = pe.find_export_rva(&data, "EtwEventWrite");
        if etw_write_rva.is_some() {
            tracing::info!(
                rva = format_args!("0x{:X}", etw_write_rva.unwrap()),
                "EtwEventWrite located via export table"
            );
        } else {
            tracing::warn!("EtwEventWrite not found in ntdll export table");
        }

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
            etw_write_rva,
        })
    }

    /// Build the AMSI reference by parsing amsi.dll's export table from
    /// disk. This avoids the need for the sensor to have amsi.dll loaded
    /// (it is typically only loaded by PowerShell/.NET hosts).
    fn build_amsi_reference() -> Option<AmsiReference> {
        let path = r"C:\Windows\System32\amsi.dll";
        let data = std::fs::read(path).ok()?;
        let pe = crate::pe::PeHeaders::parse(&data)?;
        let rva = pe.find_export_rva(&data, "AmsiScanBuffer")?;
        tracing::info!(
            rva = format_args!("0x{rva:X}"),
            "AmsiScanBuffer located via export table"
        );
        Some(AmsiReference {
            scan_buffer_rva: rva,
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
            (needed as usize / std::mem::size_of::<HMODULE>())
                .min(modules.len());
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

    // load_ondisk_ntdll_text removed — PE parsing now handled by
    // build_ntdll_reference() via crate::pe::PeHeaders.

    // ---- Direct syscall detection ----------------------------------------------

    /// Check if a module should be skipped for syscall scanning.
    ///
    /// Requires **both** a whitelisted basename (ntdll.dll, win32u.dll)
    /// **and** a verified system-directory path. A DLL named `ntdll.dll`
    /// loaded from a non-system location will NOT be whitelisted.
    fn is_system_syscall_module(
        handle: HANDLE,
        module: HMODULE,
        basename: &str,
    ) -> bool {
        if !super::is_syscall_whitelisted(basename) {
            return false;
        }

        // Verify the module is loaded from a system directory
        let mut path_buf = [0u8; 520];
        let len = unsafe {
            GetModuleFileNameExA(handle, module, &mut path_buf)
        };
        if len == 0 {
            // Can't verify path — don't whitelist (safe default)
            return false;
        }
        let path = std::str::from_utf8(&path_buf[..len as usize])
            .unwrap_or("");
        let path_lower = path.to_ascii_lowercase();

        let sys_root = std::env::var("SystemRoot")
            .unwrap_or_else(|_| r"C:\Windows".to_string())
            .to_ascii_lowercase();

        let basename_lower = basename.to_ascii_lowercase();
        path_lower == format!(r"{}\system32\{}", sys_root, basename_lower)
            || path_lower
                == format!(r"{}\syswow64\{}", sys_root, basename_lower)
    }

    /// Maximum bytes to read from a remote module's .text section.
    const MAX_TEXT_READ: usize = 1024 * 1024; // 1 MB

    /// A candidate match from one module, used to rank results.
    struct SyscallCandidate {
        mod_name: String,
        module_base: usize,
        stubs: Vec<super::SyscallStubMatch>,
        has_direct: bool,
    }

    impl SyscallCandidate {
        /// Higher = more suspicious.
        fn rank(&self) -> u32 {
            let mut r = self.stubs.len() as u32;
            if self.has_direct {
                r += 1000; // direct stubs always outrank indirect
            }
            r
        }
    }

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
            (needed as usize / std::mem::size_of::<HMODULE>())
                .min(modules.len());

        // Scan ALL modules and collect candidates instead of
        // returning on the first match.  This ensures a high-
        // confidence direct-stub module is not masked by an
        // earlier low-confidence indirect-only module.
        let mut candidates: Vec<SyscallCandidate> = Vec::new();

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

            if is_system_syscall_module(handle, *m, mod_name) {
                continue;
            }

            let module_base = m.0 as usize;
            let sections = read_remote_executable_sections(handle, module_base);
            if sections.is_empty() {
                continue;
            }

            let mut stubs = Vec::new();
            for (text, _rva) in &sections {
                stubs.extend(super::scan_for_syscall_stubs(text));
            }
            if stubs.is_empty() {
                continue;
            }

            let has_direct = stubs.iter().any(|s| !s.indirect);

            candidates.push(SyscallCandidate {
                mod_name: mod_name.to_string(),
                module_base,
                stubs,
                has_direct,
            });
        }

        if candidates.is_empty() {
            return None;
        }

        // Pick the highest-ranked candidate (direct > indirect,
        // then by stub count).
        candidates.sort_by(|a, b| b.rank().cmp(&a.rank()));
        let best = &candidates[0];

        let all_indirect = !best.has_direct;
        let first = &best.stubs[0];

        let details = format!(
            "{} suspicious {} stub(s) \
             found in non-system module {}",
            best.stubs.len(),
            if all_indirect { "indirect syscall" } else { "direct syscall" },
            best.mod_name,
        );

        // Indirect-only matches are emitted as telemetry (no rule
        // metadata) because the jump targets cannot be verified
        // statically.  Only direct syscall/int 0x2e stubs produce
        // a TF-EVA-004 detection alert.
        if all_indirect {
            return Some(ThreatEvent::new(
                agent,
                EventSource::EvasionDetector,
                EventCategory::Evasion,
                Severity::Info,
                EventData::EvasionDetected {
                    technique: EvasionTechnique::DirectSyscall,
                    pid: Some(pid),
                    process_name: None,
                    details,
                },
            ));
        }

        let evidence = vec![
            format!(
                "module: {} at base 0x{:X}",
                best.mod_name, best.module_base
            ),
            format!(
                "{} syscall stub(s) found in .text section",
                best.stubs.len()
            ),
            format!(
                "first stub at .text+0x{:X}: {}",
                first.offset, first.instruction
            ),
            format!("SSN: 0x{:X}", first.ssn),
            format!("stub bytes: {:02X?}", first.raw_bytes),
        ];

        Some(ThreatEvent::with_rule(
            agent,
            EventSource::EvasionDetector,
            EventCategory::Evasion,
            Severity::High,
            EventData::EvasionDetected {
                technique: EvasionTechnique::DirectSyscall,
                pid: Some(pid),
                process_name: None,
                details,
            },
            RuleMetadata {
                id: "TF-EVA-004".into(),
                name: "Suspicious Direct Syscall Stub".into(),
                description:
                    "A non-system module contains \
                     syscall/int 0x2e instruction sequences \
                     with the mov r10,rcx; mov eax,SSN prologue \
                     characteristic of tools like SysWhispers. \
                     This pattern is commonly used to invoke \
                     system calls without going through ntdll, \
                     but the sensor has not confirmed execution."
                        .into(),
                mitre: MitreRef {
                    tactic: "Defense Evasion".into(),
                    technique_id: "T1562.001".into(),
                    technique_name:
                        "Impair Defenses: Disable or Modify Tools"
                            .into(),
                },
                confidence: Confidence::Medium,
                evidence,
            },
        ))
    }

    /// Read the .text section of a remote module by parsing its PE
    /// headers from the target process's memory.  Returns `(bytes, rva)`.
    ///
    /// Uses a two-pass approach: first reads the DOS header to locate
    /// the PE signature (e_lfanew), then computes the exact header size
    /// needed for COFF + optional header + all section headers, and
    /// reads that amount.  This handles PEs with large DOS stubs or
    /// many sections that would exceed a fixed 4 KB buffer.
    /// Read all executable sections from a remote module's in-memory PE.
    /// Returns a vec of `(bytes, rva)` pairs.
    fn read_remote_executable_sections(
        handle: HANDLE,
        module_base: usize,
    ) -> Vec<(Vec<u8>, u32)> {
        let pe = match parse_remote_pe_headers(handle, module_base) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let mut results = Vec::new();
        for section in pe.all_executable_sections() {
            let size = (section.virtual_size as usize).min(MAX_TEXT_READ);
            if size < 10 {
                continue;
            }
            let addr = module_base + section.virtual_address as usize;
            let mut buf = vec![0u8; size];
            let mut read = 0usize;
            let _ = unsafe {
                ReadProcessMemory(
                    handle,
                    addr as *const std::ffi::c_void,
                    buf.as_mut_ptr() as *mut std::ffi::c_void,
                    size,
                    Some(&mut read),
                )
            };
            if read >= 10 {
                buf.truncate(read);
                results.push((buf, section.virtual_address));
            }
        }
        results
    }

    /// Parse PE headers from a remote process module.
    fn parse_remote_pe_headers(
        handle: HANDLE,
        module_base: usize,
    ) -> Option<crate::pe::PeHeaders> {
        const DOS_HEADER_SIZE: usize = 64;
        let mut dos_buf = [0u8; DOS_HEADER_SIZE];
        let mut read = 0usize;
        unsafe {
            ReadProcessMemory(
                handle,
                module_base as *const std::ffi::c_void,
                dos_buf.as_mut_ptr() as *mut std::ffi::c_void,
                DOS_HEADER_SIZE,
                Some(&mut read),
            )
            .ok()?;
        }
        if read < DOS_HEADER_SIZE || dos_buf[0] != b'M' || dos_buf[1] != b'Z' {
            return None;
        }
        let e_lfanew =
            u32::from_le_bytes(dos_buf[60..64].try_into().ok()?) as usize;
        if e_lfanew < 4 {
            return None;
        }

        const PE_SIG_COFF: usize = 4 + 20;
        let coff_end = e_lfanew + PE_SIG_COFF;
        let mut probe_buf = vec![0u8; coff_end];
        let mut probe_read = 0usize;
        unsafe {
            ReadProcessMemory(
                handle,
                module_base as *const std::ffi::c_void,
                probe_buf.as_mut_ptr() as *mut std::ffi::c_void,
                coff_end,
                Some(&mut probe_read),
            )
            .ok()?;
        }
        if probe_read < coff_end {
            return None;
        }

        let num_sections = u16::from_le_bytes(
            probe_buf[e_lfanew + 6..e_lfanew + 8].try_into().ok()?,
        ) as usize;
        let opt_header_size = u16::from_le_bytes(
            probe_buf[e_lfanew + 20..e_lfanew + 22].try_into().ok()?,
        ) as usize;

        const SECTION_ENTRY_SIZE: usize = 40;
        let headers_needed = e_lfanew
            + PE_SIG_COFF
            + opt_header_size
            + num_sections * SECTION_ENTRY_SIZE;

        if headers_needed > 1024 * 1024 {
            return None;
        }

        let mut header_buf = vec![0u8; headers_needed];
        let mut header_read = 0usize;
        unsafe {
            ReadProcessMemory(
                handle,
                module_base as *const std::ffi::c_void,
                header_buf.as_mut_ptr() as *mut std::ffi::c_void,
                headers_needed,
                Some(&mut header_read),
            )
            .ok()?;
        }
        if header_read < headers_needed {
            return None;
        }

        crate::pe::PeHeaders::parse(&header_buf[..header_read])
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
            let scan_rx = self.scan_rx.lock().unwrap().take().expect(
                "EvasionCollector::start called twice or scan_rx not set"
            );
            let flag = platform::start_scanner(
                self.config.clone(),
                self.agent.clone(),
                _tx,
                self.dropped.clone(),
                scan_rx,
            )?;
            self.stop_flag = Some(flag);
            info!(
                "Evasion detector started (periodic + ProcessCreate + \
                 ImageLoad + TI correlation)"
            );
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
        assert!(!matches[0].indirect);
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

    // ---- SSN range check tests -----------------------------------------------

    #[test]
    fn reject_implausible_ssn() {
        // msedgewebview2.exe false positive: SSN = 0x0FC0940F (way too high)
        let data = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x0F, 0x94, 0xC0, 0x0F, // mov eax, 0x0FC0940F
            0x0F, 0x05, // syscall (actually data bytes)
            0xC3,
        ];
        assert!(
            scan_for_syscall_stubs(&data).is_empty(),
            "SSN > MAX_PLAUSIBLE_SSN must be rejected"
        );
    }

    #[test]
    fn accept_plausible_ssn() {
        // Real NtWriteVirtualMemory SSN = 0x3A
        let data = [
            0x4C, 0x8B, 0xD1,
            0xB8, 0x3A, 0x00, 0x00, 0x00,
            0x0F, 0x05, 0xC3,
        ];
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].ssn, 0x3A);
    }

    // ---- reversed prologue tests ---------------------------------------------

    #[test]
    fn detect_reversed_prologue() {
        // mov eax, SSN; mov r10, rcx; syscall; ret
        let data = [
            0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, 0x18
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0x0F, 0x05, // syscall
            0xC3,
        ];
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].ssn, 0x18);
    }

    #[test]
    fn detect_reversed_prologue_alternate_encoding() {
        // mov eax, SSN; 49 89 CA (mov r10, rcx alternate); syscall; ret
        let data = [
            0xB8, 0x26, 0x00, 0x00, 0x00,
            0x49, 0x89, 0xCA,
            0x0F, 0x05,
            0xC3,
        ];
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].ssn, 0x26);
    }

    // ---- indirect syscall tests ----------------------------------------------

    #[test]
    fn detect_indirect_syscall_jmp_rip() {
        // mov r10, rcx; mov eax, SSN; jmp [rip+disp32]
        let data = [
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, 0x18
            0xFF, 0x25, 0x42, 0x00, 0x00, 0x00, // jmp [rip+0x42]
        ];
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].ssn, 0x18);
        assert!(matches[0].indirect, "jmp [rip+disp] must be flagged indirect");
    }

    #[test]
    fn detect_indirect_syscall_jmp_r11() {
        // mov r10, rcx; mov eax, SSN; jmp r11
        let data = [
            0x4C, 0x8B, 0xD1,
            0xB8, 0x3A, 0x00, 0x00, 0x00,
            0x41, 0xFF, 0xE3, // jmp r11
        ];
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].ssn, 0x3A);
        assert!(matches[0].indirect, "jmp r11 must be flagged indirect");
    }

    #[test]
    fn detect_indirect_syscall_jmp_r9() {
        // Some tools use r9 for the ntdll syscall address
        let data = [
            0xB8, 0x50, 0x00, 0x00, 0x00, // mov eax, 0x50
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0x41, 0xFF, 0xE1, // jmp r9
        ];
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].ssn, 0x50);
        assert!(matches[0].indirect, "jmp r9 must be flagged indirect");
    }

    #[test]
    fn single_indirect_stub_not_enough() {
        // A single indirect match should be filtered out by
        // check_direct_syscall (requires >=2 for indirect-only).
        // Here we just verify the scanner still flags it as indirect.
        let data = [
            0x4C, 0x8B, 0xD1,
            0xB8, 0x18, 0x00, 0x00, 0x00,
            0x41, 0xFF, 0xE3,
        ];
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].indirect);
        // The check_direct_syscall caller would drop this single match.
    }

    #[test]
    fn mixed_direct_and_indirect_stubs() {
        // One direct + one indirect: has_direct=true, should report
        // at full confidence.
        let mut data = Vec::new();
        // Direct stub
        data.extend_from_slice(&[
            0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00,
            0x0F, 0x05, 0xC3,
        ]);
        data.extend_from_slice(&[0xCC; 5]); // padding
        // Indirect stub
        data.extend_from_slice(&[
            0x4C, 0x8B, 0xD1, 0xB8, 0x3A, 0x00, 0x00, 0x00,
            0x41, 0xFF, 0xE3,
        ]);
        let matches = scan_for_syscall_stubs(&data);
        assert_eq!(matches.len(), 2);
        assert!(!matches[0].indirect, "first is direct");
        assert!(matches[1].indirect, "second is indirect");
    }

    // ---- AMSI bypass pattern tests ------------------------------------------

    #[test]
    fn amsi_patch_classic_e_invalidarg() {
        // mov eax, 0x80070057; ret
        let bytes = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3, 0x00, 0x00];
        let (desc, conf) = detect_amsi_patch_pattern(&bytes).unwrap();
        assert!(desc.contains("E_INVALIDARG"));
        assert_eq!(conf, Confidence::High);
    }

    #[test]
    fn amsi_patch_s_false() {
        // mov eax, 1 (S_FALSE); ret
        let bytes = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x00, 0x00];
        let (desc, conf) = detect_amsi_patch_pattern(&bytes).unwrap();
        assert!(desc.contains("S_FALSE"));
        assert_eq!(conf, Confidence::High);
    }

    #[test]
    fn amsi_patch_mov_eax_arbitrary() {
        // mov eax, 0xDEADBEEF; ret
        let bytes = [0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xC3, 0x00, 0x00];
        let (desc, conf) = detect_amsi_patch_pattern(&bytes).unwrap();
        assert!(desc.contains("forced return value"));
        assert_eq!(conf, Confidence::High);
    }

    #[test]
    fn amsi_patch_xor_eax_ret() {
        // xor eax, eax; ret  (31 C0 C3)
        let bytes = [0x31, 0xC0, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (desc, conf) = detect_amsi_patch_pattern(&bytes).unwrap();
        assert!(desc.contains("S_OK"));
        assert_eq!(conf, Confidence::High);

        // Alternate encoding: 33 C0 C3
        let bytes2 = [0x33, 0xC0, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (desc2, _) = detect_amsi_patch_pattern(&bytes2).unwrap();
        assert!(desc2.contains("S_OK"));
    }

    #[test]
    fn amsi_patch_immediate_ret() {
        // C3 (ret)
        let bytes = [0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (desc, conf) = detect_amsi_patch_pattern(&bytes).unwrap();
        assert!(desc.contains("immediate return"));
        assert_eq!(conf, Confidence::Medium);
    }

    #[test]
    fn amsi_patch_nop_ret() {
        // nop; ret (90 C3)
        let bytes = [0x90, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let (desc, conf) = detect_amsi_patch_pattern(&bytes).unwrap();
        assert!(desc.contains("no-op"));
        assert_eq!(conf, Confidence::Medium);
    }

    #[test]
    fn amsi_patch_no_match_normal_prologue() {
        // Normal function prologue: sub rsp, 28h; mov ...
        let bytes = [0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0xC1, 0x00];
        assert!(detect_amsi_patch_pattern(&bytes).is_none());
    }

    #[test]
    fn amsi_patch_too_short() {
        assert!(detect_amsi_patch_pattern(&[]).is_none());
        assert!(detect_amsi_patch_pattern(&[0x00]).is_none());
    }
}
