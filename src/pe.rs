//! Minimal PE header parser for on-disk and in-memory PE images.
//!
//! Provides structured access to PE headers, section tables, and the export
//! directory without depending on Windows APIs. All parsing operates on
//! `&[u8]` slices, making it cross-platform and testable.
//!
//! Used by the evasion collector on Windows; cross-platform tests exercise
//! all functionality.

/// IMAGE_SCN_CNT_CODE
pub const SCN_CNT_CODE: u32 = 0x0000_0020;
/// IMAGE_SCN_MEM_EXECUTE
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// IMAGE_SCN_MEM_READ
pub const SCN_MEM_READ: u32 = 0x4000_0000;
/// IMAGE_SCN_MEM_WRITE
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Data directory index for the export table.
const DIR_ENTRY_EXPORT: usize = 0;
/// Data directory index for the import table.
const DIR_ENTRY_IMPORT: usize = 1;

/// COFF machine type for x86.
#[allow(dead_code)]
pub const MACHINE_I386: u16 = 0x014C;
/// COFF machine type for AMD64.
#[allow(dead_code)]
pub const MACHINE_AMD64: u16 = 0x8664;

// ---------------------------------------------------------------------------
// Helper readers
// ---------------------------------------------------------------------------

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    let b = data.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn read_cstring(data: &[u8], off: usize) -> Option<String> {
    let start = data.get(off..)?;
    let end = start.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&start[..end]).ok().map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Parsed PE image headers.
#[derive(Debug, Clone)]
pub struct PeHeaders {
    /// COFF machine type.
    pub machine: u16,
    /// True for PE32+ (64-bit), false for PE32.
    pub is_64bit: bool,
    /// ImageBase from the optional header.
    pub image_base: u64,
    /// SizeOfImage from the optional header.
    pub size_of_image: u32,
    /// AddressOfEntryPoint RVA.
    pub entry_point_rva: u32,
    /// Windows subsystem from the optional header.
    pub subsystem: u16,
    /// Parsed section headers.
    pub sections: Vec<SectionHeader>,
    /// Data directory entries: (rva, size).
    data_directories: Vec<(u32, u32)>,
}

/// Parsed PE section header.
#[derive(Debug, Clone)]
pub struct SectionHeader {
    /// Section name (up to 8 ASCII chars, NUL-trimmed).
    pub name: String,
    /// Size when loaded into memory.
    pub virtual_size: u32,
    /// RVA when loaded.
    pub virtual_address: u32,
    /// Size of section data in the file.
    pub raw_data_size: u32,
    /// File offset of section data.
    pub raw_data_offset: u32,
    /// Section characteristic flags.
    pub characteristics: u32,
}

impl SectionHeader {
    /// Section has the executable memory flag (`IMAGE_SCN_MEM_EXECUTE`).
    pub fn is_executable(&self) -> bool {
        self.characteristics & SCN_MEM_EXECUTE != 0
    }

    /// Section has the writable memory flag (`IMAGE_SCN_MEM_WRITE`).
    #[allow(dead_code)]
    pub fn is_writable(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }

    /// Section contains code (`IMAGE_SCN_CNT_CODE`).
    pub fn contains_code(&self) -> bool {
        self.characteristics & SCN_CNT_CODE != 0
    }
}

/// A named export from a PE image.
#[derive(Debug, Clone, Serialize)]
pub struct ExportEntry {
    /// Export ordinal (biased by ordinal base).
    pub ordinal: u16,
    /// Export name, if present (ordinal-only exports have `None`).
    pub name: Option<String>,
    /// RVA of the exported function.
    pub rva: u32,
    /// True if this is a forwarder (RVA points within the export directory).
    pub is_forward: bool,
}

/// All imports from a single DLL.
#[derive(Debug, Clone, Serialize)]
pub struct ImportEntry {
    /// The DLL name (e.g., "KERNEL32.dll").
    pub dll_name: String,
    /// Functions imported from this DLL.
    pub functions: Vec<ImportedFunction>,
}

/// A single imported function from a DLL.
#[derive(Debug, Clone, Serialize)]
pub struct ImportedFunction {
    /// Function name, if imported by name (None for ordinal-only imports).
    pub name: Option<String>,
    /// Ordinal value, if imported by ordinal (None for name imports).
    pub ordinal: Option<u16>,
    /// Hint value from the Import Lookup Table.
    pub hint: u16,
}

use serde::Serialize;

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

impl PeHeaders {
    /// Parse PE headers from a buffer starting at the DOS header.
    ///
    /// Works for both on-disk PE files and in-memory mapped images (the
    /// header pages are identical in both layouts).
    pub fn parse(data: &[u8]) -> Option<Self> {
        // DOS header — minimum 64 bytes, MZ signature.
        if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
            return None;
        }

        let pe_offset = read_u32(data, 0x3C)? as usize;

        // PE signature "PE\0\0"
        if data.len() < pe_offset + 4 {
            return None;
        }
        if data.get(pe_offset..pe_offset + 4)? != b"PE\0\0" {
            return None;
        }

        let coff = pe_offset + 4;
        if data.len() < coff + 20 {
            return None;
        }
        let machine = read_u16(data, coff)?;
        let num_sections = read_u16(data, coff + 2)? as usize;
        let opt_header_size = read_u16(data, coff + 16)? as usize;

        // Optional header
        let opt = coff + 20;
        if data.len() < opt + opt_header_size.max(2) {
            return None;
        }

        let magic = read_u16(data, opt)?;
        let is_64bit = match magic {
            0x010B => false, // PE32
            0x020B => true,  // PE32+
            _ => return None,
        };

        let entry_point_rva = read_u32(data, opt + 16)?;

        let (image_base, num_dd_off, dd_off) = if is_64bit {
            (
                read_u64(data, opt + 24)?,
                opt + 108,
                opt + 112,
            )
        } else {
            (
                read_u32(data, opt + 28)? as u64,
                opt + 92,
                opt + 96,
            )
        };

        let size_of_image = read_u32(data, opt + 56)?;
        let subsystem = read_u16(data, opt + 68)?;

        // Data directories
        let num_dd = read_u32(data, num_dd_off).unwrap_or(0) as usize;
        let mut data_directories = Vec::with_capacity(num_dd);
        for i in 0..num_dd {
            let ent = dd_off + i * 8;
            let rva = read_u32(data, ent).unwrap_or(0);
            let size = read_u32(data, ent + 4).unwrap_or(0);
            data_directories.push((rva, size));
        }

        // Section headers
        let sec_start = opt + opt_header_size;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = sec_start + i * 40;
            if data.len() < s + 40 {
                break;
            }

            let name_bytes = &data[s..s + 8];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = std::str::from_utf8(&name_bytes[..name_end])
                .unwrap_or("")
                .to_string();

            sections.push(SectionHeader {
                name,
                virtual_size: read_u32(data, s + 8)?,
                virtual_address: read_u32(data, s + 12)?,
                raw_data_size: read_u32(data, s + 16)?,
                raw_data_offset: read_u32(data, s + 20)?,
                characteristics: read_u32(data, s + 36)?,
            });
        }

        Some(Self {
            machine,
            is_64bit,
            image_base,
            size_of_image,
            entry_point_rva,
            subsystem,
            sections,
            data_directories,
        })
    }

    /// Find a section by exact name.
    pub fn find_section(&self, name: &str) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Return the `.text` section, if present.
    pub fn text_section(&self) -> Option<&SectionHeader> {
        self.find_section(".text")
    }

    /// Return the first executable section, regardless of name.
    ///
    /// Falls back from `.text` to any section with
    /// `IMAGE_SCN_MEM_EXECUTE` or `IMAGE_SCN_CNT_CODE` flags.
    /// This handles UPX-packed PEs (UPX0/UPX1), custom-linked
    /// binaries, and other non-standard section names.
    pub fn first_executable_section(&self) -> Option<&SectionHeader> {
        self.text_section().or_else(|| {
            self.sections
                .iter()
                .find(|s| s.is_executable() || s.contains_code())
        })
    }

    /// Return all executable sections.
    ///
    /// Stubs can live in any executable section (e.g. UPX1 after
    /// UPX0, or a custom `.stub` section).  Scanning only the first
    /// executable section misses these.
    pub fn all_executable_sections(&self) -> Vec<&SectionHeader> {
        self.sections
            .iter()
            .filter(|s| s.is_executable() || s.contains_code())
            .collect()
    }

    /// Read the raw bytes of a section from an on-disk PE buffer.
    ///
    /// Uses `min(raw_data_size, virtual_size)` to avoid reading file-alignment
    /// padding beyond the actual section content.
    pub fn read_section_data<'a>(
        &self,
        data: &'a [u8],
        section: &SectionHeader,
    ) -> Option<&'a [u8]> {
        let off = section.raw_data_offset as usize;
        let size = section.raw_data_size.min(section.virtual_size) as usize;
        data.get(off..off + size)
    }

    /// Convert an RVA to a file offset using the section table.
    pub fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        for sec in &self.sections {
            let start = sec.virtual_address;
            let end = start + sec.virtual_size.max(sec.raw_data_size);
            if rva >= start && rva < end {
                let delta = (rva - start) as usize;
                return Some(sec.raw_data_offset as usize + delta);
            }
        }
        None
    }

    /// Return the export data directory entry `(rva, size)`, if present.
    pub fn export_directory(&self) -> Option<(u32, u32)> {
        self.data_directories
            .get(DIR_ENTRY_EXPORT)
            .copied()
            .filter(|(rva, size)| *rva != 0 && *size != 0)
    }

    /// Parse the export directory from an on-disk PE buffer.
    pub fn parse_exports(&self, data: &[u8]) -> Option<Vec<ExportEntry>> {
        let (export_rva, export_size) = self.export_directory()?;
        let export_end = export_rva + export_size;
        let dir = self.rva_to_file_offset(export_rva)?;

        // Export directory table fields
        let ordinal_base = read_u32(data, dir + 16)? as u16;
        let num_functions = read_u32(data, dir + 20)? as usize;
        let num_names = read_u32(data, dir + 24)? as usize;
        let func_table_rva = read_u32(data, dir + 28)?;
        let name_table_rva = read_u32(data, dir + 32)?;
        let ord_table_rva = read_u32(data, dir + 36)?;

        let func_off = self.rva_to_file_offset(func_table_rva)?;
        let name_off = self.rva_to_file_offset(name_table_rva)?;
        let ord_off = self.rva_to_file_offset(ord_table_rva)?;

        // Build name → function-index map
        let mut name_for_index =
            std::collections::HashMap::<u16, String>::with_capacity(num_names);
        for i in 0..num_names {
            let n_rva = read_u32(data, name_off + i * 4)?;
            let n_off = self.rva_to_file_offset(n_rva)?;
            let name = read_cstring(data, n_off)?;
            let idx = read_u16(data, ord_off + i * 2)?;
            name_for_index.insert(idx, name);
        }

        let mut exports = Vec::with_capacity(num_functions);
        for i in 0..num_functions {
            let func_rva = read_u32(data, func_off + i * 4)?;
            let is_forward = func_rva >= export_rva && func_rva < export_end;
            let ordinal = ordinal_base.wrapping_add(i as u16);
            let name = name_for_index.remove(&(i as u16));

            exports.push(ExportEntry {
                ordinal,
                name,
                rva: func_rva,
                is_forward,
            });
        }

        Some(exports)
    }

    /// Find the RVA of a named export.
    pub fn find_export_rva(&self, data: &[u8], name: &str) -> Option<u32> {
        self.parse_exports(data)?
            .iter()
            .find(|e| e.name.as_deref() == Some(name))
            .map(|e| e.rva)
    }

    /// Return the import data directory entry `(rva, size)`, if present.
    pub fn import_directory(&self) -> Option<(u32, u32)> {
        self.data_directories
            .get(DIR_ENTRY_IMPORT)
            .copied()
            .filter(|(rva, size)| *rva != 0 && *size != 0)
    }

    /// Parse the import directory from an on-disk PE buffer.
    pub fn parse_imports(&self, data: &[u8]) -> Option<Vec<ImportEntry>> {
        let (import_rva, _import_size) = self.import_directory()?;
        let dir = self.rva_to_file_offset(import_rva)?;

        let mut entries = Vec::new();
        // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes, terminated by all-zeros.
        // Safety cap: 4096 descriptors.
        for i in 0..4096 {
            let desc = dir + i * 20;
            if desc + 20 > data.len() {
                break;
            }
            let ilt_rva = read_u32(data, desc)?;
            let name_rva = read_u32(data, desc + 12)?;
            let iat_rva = read_u32(data, desc + 16)?;

            // All-zero terminator.
            if name_rva == 0 {
                break;
            }

            let dll_name_off = self.rva_to_file_offset(name_rva)?;
            let dll_name = read_cstring(data, dll_name_off)?;

            // Prefer OriginalFirstThunk (ILT); fall back to FirstThunk (IAT).
            let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
            if thunk_rva == 0 {
                entries.push(ImportEntry {
                    dll_name,
                    functions: Vec::new(),
                });
                continue;
            }

            let thunk_off = self.rva_to_file_offset(thunk_rva)?;
            let entry_size: usize = if self.is_64bit { 8 } else { 4 };
            let ordinal_flag: u64 = if self.is_64bit {
                1u64 << 63
            } else {
                1u64 << 31
            };

            let mut functions = Vec::new();
            // Safety cap: 65536 functions per DLL.
            for j in 0..65536usize {
                let t = thunk_off + j * entry_size;
                let value = if self.is_64bit {
                    read_u64(data, t)?
                } else {
                    read_u32(data, t)? as u64
                };
                if value == 0 {
                    break;
                }
                if value & ordinal_flag != 0 {
                    // Import by ordinal.
                    functions.push(ImportedFunction {
                        name: None,
                        ordinal: Some((value & 0xFFFF) as u16),
                        hint: 0,
                    });
                } else {
                    // Import by name — value is RVA to IMAGE_IMPORT_BY_NAME.
                    let hna_rva = value as u32;
                    let hna_off = self.rva_to_file_offset(hna_rva)?;
                    let hint = read_u16(data, hna_off).unwrap_or(0);
                    let func_name = read_cstring(data, hna_off + 2)?;
                    functions.push(ImportedFunction {
                        name: Some(func_name),
                        ordinal: None,
                        hint,
                    });
                }
            }

            entries.push(ImportEntry {
                dll_name,
                functions,
            });
        }

        Some(entries)
    }

    /// Check if a PE imports a specific function from a specific DLL.
    ///
    /// Both `dll_name` and `func_name` are compared case-insensitively.
    /// Used by TI × import correlation to detect direct syscalls:
    /// if a process calls NtAllocateVirtualMemory (via TI event) but
    /// does not import it from ntdll.dll, it used a direct syscall.
    #[allow(dead_code)]
    pub fn has_import(&self, data: &[u8], dll_name: &str, func_name: &str) -> bool {
        let imports = match self.parse_imports(data) {
            Some(i) => i,
            None => return false,
        };
        imports.iter().any(|entry| {
            entry.dll_name.eq_ignore_ascii_case(dll_name)
                && entry.functions.iter().any(|f| {
                    f.name
                        .as_deref()
                        .map_or(false, |n| n.eq_ignore_ascii_case(func_name))
                })
        })
    }

    /// Human-readable machine architecture name.
    pub fn machine_name(&self) -> &'static str {
        match self.machine {
            MACHINE_I386 => "PE32 (i386)",
            MACHINE_AMD64 => "PE32+ (AMD64)",
            0x01C4 => "PE32 (ARM)",
            0xAA64 => "PE32+ (ARM64)",
            _ => "Unknown",
        }
    }

    /// Human-readable subsystem name.
    pub fn subsystem_name(&self) -> &'static str {
        match self.subsystem {
            0 => "Unknown",
            1 => "Native",
            2 => "Windows GUI",
            3 => "Windows CUI",
            5 => "OS/2 CUI",
            7 => "POSIX CUI",
            8 => "Native Windows",
            9 => "Windows CE GUI",
            10 => "EFI Application",
            11 => "EFI Boot Service Driver",
            12 => "EFI Runtime Driver",
            14 => "Xbox",
            _ => "Other",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Test PE builder ---------------------------------------------------

    /// Section characteristics for executable code.
    const CODE_CHARS: u32 = SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ;
    /// Section characteristics for initialized data.
    const DATA_CHARS: u32 = SCN_MEM_READ | SCN_MEM_WRITE;

    struct BuildSection {
        name: [u8; 8],
        data: Vec<u8>,
        virtual_address: u32,
        characteristics: u32,
    }

    /// Build a minimal PE64 binary for testing.
    fn build_pe64(sections: &[BuildSection]) -> Vec<u8> {
        build_pe(true, sections, &[])
    }

    /// Build a minimal PE32 binary for testing.
    fn build_pe32(sections: &[BuildSection]) -> Vec<u8> {
        build_pe(false, sections, &[])
    }

    /// Build a PE with optional exports.
    fn build_pe64_with_exports(
        sections: &[BuildSection],
        exports: &[(&str, u32)],
    ) -> Vec<u8> {
        build_pe(true, sections, exports)
    }

    fn make_section(name: &str, data: &[u8], va: u32, chars: u32) -> BuildSection {
        let mut name_buf = [0u8; 8];
        let len = name.len().min(8);
        name_buf[..len].copy_from_slice(&name.as_bytes()[..len]);
        BuildSection {
            name: name_buf,
            data: data.to_vec(),
            virtual_address: va,
            characteristics: chars,
        }
    }

    fn build_pe(
        is_64bit: bool,
        sections: &[BuildSection],
        exports: &[(&str, u32)],
    ) -> Vec<u8> {
        let pe_offset: usize = 64;
        let coff = pe_offset + 4;
        let opt = coff + 20;
        let num_dd: usize = 16;
        let opt_size: usize = if is_64bit {
            112 + num_dd * 8 // PE32+: 112 base + data dirs
        } else {
            96 + num_dd * 8 // PE32: 96 base + data dirs
        };
        let sec_start = opt + opt_size;
        let headers_end = sec_start + sections.len() * 40;
        let file_align: usize = 512;
        let data_start = (headers_end + file_align - 1) / file_align * file_align;

        // Calculate raw offsets for each section
        let mut raw_offsets = Vec::new();
        let mut cursor = data_start;
        for sec in sections {
            raw_offsets.push(cursor);
            cursor += (sec.data.len() + file_align - 1) / file_align * file_align;
        }

        // Build export section data if needed
        let export_sec_va: u32 = 0x8000; // place exports at a high VA
        let (export_data, export_rva, export_size) = if exports.is_empty() {
            (Vec::new(), 0u32, 0u32)
        } else {
            build_export_section(exports, export_sec_va)
        };

        // If we have exports, add the export section
        let total_sections = if exports.is_empty() {
            sections.len()
        } else {
            sections.len() + 1
        };
        // Recalculate with extra section header
        let sec_start_final = opt + opt_size;
        let headers_end_final = sec_start_final + total_sections * 40;
        let data_start_final =
            (headers_end_final + file_align - 1) / file_align * file_align;

        // Recalculate raw offsets
        raw_offsets.clear();
        cursor = data_start_final;
        for sec in sections {
            raw_offsets.push(cursor);
            cursor += (sec.data.len() + file_align - 1) / file_align * file_align;
        }
        let export_raw_offset = if !exports.is_empty() {
            let off = cursor;
            cursor += (export_data.len() + file_align - 1) / file_align * file_align;
            off
        } else {
            0
        };

        let total_size = cursor;
        let mut buf = vec![0u8; total_size];

        // --- DOS header ---
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());

        // --- PE signature ---
        buf[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

        // --- COFF header ---
        let machine: u16 = if is_64bit { MACHINE_AMD64 } else { MACHINE_I386 };
        buf[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
        buf[coff + 2..coff + 4]
            .copy_from_slice(&(total_sections as u16).to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());

        // --- Optional header ---
        let magic: u16 = if is_64bit { 0x020B } else { 0x010B };
        buf[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        // AddressOfEntryPoint
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());

        if is_64bit {
            // ImageBase (8 bytes at +24)
            buf[opt + 24..opt + 32]
                .copy_from_slice(&0x0000000180000000u64.to_le_bytes());
            // SectionAlignment
            buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
            // FileAlignment
            buf[opt + 36..opt + 40]
                .copy_from_slice(&(file_align as u32).to_le_bytes());
            // SizeOfImage
            buf[opt + 56..opt + 60].copy_from_slice(&0x10000u32.to_le_bytes());
            // SizeOfHeaders
            buf[opt + 60..opt + 64]
                .copy_from_slice(&(data_start_final as u32).to_le_bytes());
            // NumberOfRvaAndSizes
            buf[opt + 108..opt + 112].copy_from_slice(&(num_dd as u32).to_le_bytes());

            // Data directory entry 0 (export)
            if !exports.is_empty() {
                let dd = opt + 112;
                buf[dd..dd + 4].copy_from_slice(&export_rva.to_le_bytes());
                buf[dd + 4..dd + 8].copy_from_slice(&export_size.to_le_bytes());
            }
        } else {
            // PE32: ImageBase (4 bytes at +28)
            buf[opt + 28..opt + 32].copy_from_slice(&0x10000000u32.to_le_bytes());
            buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
            buf[opt + 36..opt + 40]
                .copy_from_slice(&(file_align as u32).to_le_bytes());
            buf[opt + 56..opt + 60].copy_from_slice(&0x10000u32.to_le_bytes());
            buf[opt + 60..opt + 64]
                .copy_from_slice(&(data_start_final as u32).to_le_bytes());
            buf[opt + 92..opt + 96].copy_from_slice(&(num_dd as u32).to_le_bytes());

            if !exports.is_empty() {
                let dd = opt + 96;
                buf[dd..dd + 4].copy_from_slice(&export_rva.to_le_bytes());
                buf[dd + 4..dd + 8].copy_from_slice(&export_size.to_le_bytes());
            }
        }

        // --- Section headers ---
        for (i, sec) in sections.iter().enumerate() {
            let s = sec_start_final + i * 40;
            buf[s..s + 8].copy_from_slice(&sec.name);
            buf[s + 8..s + 12]
                .copy_from_slice(&(sec.data.len() as u32).to_le_bytes());
            buf[s + 12..s + 16].copy_from_slice(&sec.virtual_address.to_le_bytes());
            let raw_size =
                (sec.data.len() + file_align - 1) / file_align * file_align;
            buf[s + 16..s + 20].copy_from_slice(&(raw_size as u32).to_le_bytes());
            buf[s + 20..s + 24]
                .copy_from_slice(&(raw_offsets[i] as u32).to_le_bytes());
            buf[s + 36..s + 40].copy_from_slice(&sec.characteristics.to_le_bytes());
        }

        // Export section header (if present)
        if !exports.is_empty() {
            let idx = sections.len();
            let s = sec_start_final + idx * 40;
            buf[s..s + 8].copy_from_slice(b".edata\0\0");
            buf[s + 8..s + 12]
                .copy_from_slice(&(export_data.len() as u32).to_le_bytes());
            buf[s + 12..s + 16].copy_from_slice(&export_sec_va.to_le_bytes());
            let raw_size =
                (export_data.len() + file_align - 1) / file_align * file_align;
            buf[s + 16..s + 20].copy_from_slice(&(raw_size as u32).to_le_bytes());
            buf[s + 20..s + 24]
                .copy_from_slice(&(export_raw_offset as u32).to_le_bytes());
            buf[s + 36..s + 40].copy_from_slice(&SCN_MEM_READ.to_le_bytes());
        }

        // --- Section data ---
        for (i, sec) in sections.iter().enumerate() {
            let off = raw_offsets[i];
            buf[off..off + sec.data.len()].copy_from_slice(&sec.data);
        }

        // Export section data
        if !exports.is_empty() {
            buf[export_raw_offset..export_raw_offset + export_data.len()]
                .copy_from_slice(&export_data);
        }

        buf
    }

    /// Build export section data and return (data, rva, size).
    fn build_export_section(
        exports: &[(&str, u32)],
        section_va: u32,
    ) -> (Vec<u8>, u32, u32) {
        let num_funcs = exports.len();
        let num_names = exports.len();

        // Layout within the section:
        // [0..40]                          Export directory (40 bytes)
        // [40..40+4*N]                     Function table
        // [40+4*N..40+4*N+4*N]            Name pointer table
        // [40+8*N..40+8*N+2*N]            Ordinal table
        // [40+10*N..]                      Strings (dll name + function names)
        let func_off: usize = 40;
        let name_ptr_off: usize = func_off + 4 * num_funcs;
        let ord_off: usize = name_ptr_off + 4 * num_names;
        let strings_off: usize = ord_off + 2 * num_names;

        // Pre-compute string offsets
        let dll_name = "test.dll\0";
        let mut str_cursor = strings_off;
        let dll_name_off = str_cursor;
        str_cursor += dll_name.len();

        let mut name_offsets = Vec::new();
        for (name, _) in exports {
            name_offsets.push(str_cursor);
            str_cursor += name.len() + 1; // +1 for NUL
        }

        let total_size = str_cursor;
        let mut data = vec![0u8; total_size];

        // Export directory
        // +12: Name RVA
        let name_rva = section_va + dll_name_off as u32;
        data[12..16].copy_from_slice(&name_rva.to_le_bytes());
        // +16: OrdinalBase = 1
        data[16..20].copy_from_slice(&1u32.to_le_bytes());
        // +20: NumberOfFunctions
        data[20..24].copy_from_slice(&(num_funcs as u32).to_le_bytes());
        // +24: NumberOfNames
        data[24..28].copy_from_slice(&(num_names as u32).to_le_bytes());
        // +28: AddressOfFunctions RVA
        data[28..32]
            .copy_from_slice(&(section_va + func_off as u32).to_le_bytes());
        // +32: AddressOfNames RVA
        data[32..36]
            .copy_from_slice(&(section_va + name_ptr_off as u32).to_le_bytes());
        // +36: AddressOfNameOrdinals RVA
        data[36..40]
            .copy_from_slice(&(section_va + ord_off as u32).to_le_bytes());

        // Function table
        for (i, (_, rva)) in exports.iter().enumerate() {
            let off = func_off + i * 4;
            data[off..off + 4].copy_from_slice(&rva.to_le_bytes());
        }

        // Name pointer table
        for (i, name_off) in name_offsets.iter().enumerate() {
            let off = name_ptr_off + i * 4;
            let rva = section_va + *name_off as u32;
            data[off..off + 4].copy_from_slice(&rva.to_le_bytes());
        }

        // Ordinal table
        for i in 0..num_names {
            let off = ord_off + i * 2;
            data[off..off + 2].copy_from_slice(&(i as u16).to_le_bytes());
        }

        // DLL name string
        data[dll_name_off..dll_name_off + dll_name.len()]
            .copy_from_slice(dll_name.as_bytes());

        // Function name strings
        for (i, (name, _)) in exports.iter().enumerate() {
            let off = name_offsets[i];
            data[off..off + name.len()].copy_from_slice(name.as_bytes());
            data[off + name.len()] = 0; // NUL
        }

        (data, section_va, total_size as u32)
    }

    // ---- Header parsing tests ----------------------------------------------

    #[test]
    fn parse_pe64_single_text_section() {
        let text_data = vec![0xCC; 256]; // int3 padding
        let pe = build_pe64(&[make_section(".text", &text_data, 0x1000, CODE_CHARS)]);

        let headers = PeHeaders::parse(&pe).unwrap();
        assert!(headers.is_64bit);
        assert_eq!(headers.machine, MACHINE_AMD64);
        assert_eq!(headers.image_base, 0x0000000180000000);
        assert_eq!(headers.sections.len(), 1);

        let text = headers.text_section().unwrap();
        assert_eq!(text.name, ".text");
        assert_eq!(text.virtual_address, 0x1000);
        assert_eq!(text.virtual_size, 256);
        assert!(text.is_executable());
        assert!(text.contains_code());
        assert!(!text.is_writable());
    }

    #[test]
    fn parse_pe32_single_text_section() {
        let text_data = vec![0x90; 128];
        let pe = build_pe32(&[make_section(".text", &text_data, 0x1000, CODE_CHARS)]);

        let headers = PeHeaders::parse(&pe).unwrap();
        assert!(!headers.is_64bit);
        assert_eq!(headers.machine, MACHINE_I386);
        assert_eq!(headers.image_base, 0x10000000);
        assert_eq!(headers.sections.len(), 1);

        let text = headers.text_section().unwrap();
        assert_eq!(text.virtual_size, 128);
    }

    #[test]
    fn parse_multiple_sections() {
        let pe = build_pe64(&[
            make_section(".text", &[0xCC; 100], 0x1000, CODE_CHARS),
            make_section(".rdata", &[0; 64], 0x2000, SCN_MEM_READ),
            make_section(".data", &[0; 32], 0x3000, DATA_CHARS),
        ]);

        let headers = PeHeaders::parse(&pe).unwrap();
        assert_eq!(headers.sections.len(), 3);
        assert_eq!(headers.sections[0].name, ".text");
        assert_eq!(headers.sections[1].name, ".rdata");
        assert_eq!(headers.sections[2].name, ".data");

        assert!(headers.sections[0].is_executable());
        assert!(!headers.sections[1].is_executable());
        assert!(headers.sections[2].is_writable());
    }

    #[test]
    fn read_section_data_returns_correct_bytes() {
        let text_data: Vec<u8> = (0..64).collect();
        let pe = build_pe64(&[make_section(".text", &text_data, 0x1000, CODE_CHARS)]);

        let headers = PeHeaders::parse(&pe).unwrap();
        let text = headers.text_section().unwrap();
        let bytes = headers.read_section_data(&pe, text).unwrap();

        assert_eq!(bytes.len(), 64);
        assert_eq!(bytes, &text_data[..]);
    }

    #[test]
    fn rva_to_file_offset_maps_correctly() {
        let pe = build_pe64(&[
            make_section(".text", &[0; 256], 0x1000, CODE_CHARS),
            make_section(".data", &[0; 128], 0x2000, DATA_CHARS),
        ]);

        let headers = PeHeaders::parse(&pe).unwrap();

        // RVA 0x1000 → beginning of .text raw data
        let text_raw = headers.sections[0].raw_data_offset as usize;
        assert_eq!(headers.rva_to_file_offset(0x1000), Some(text_raw));

        // RVA 0x1080 → 0x80 bytes into .text
        assert_eq!(headers.rva_to_file_offset(0x1080), Some(text_raw + 0x80));

        // RVA 0x2000 → beginning of .data
        let data_raw = headers.sections[1].raw_data_offset as usize;
        assert_eq!(headers.rva_to_file_offset(0x2000), Some(data_raw));

        // RVA outside any section
        assert_eq!(headers.rva_to_file_offset(0x5000), None);
    }

    #[test]
    fn section_name_exactly_8_chars() {
        let pe = build_pe64(&[make_section(".textbss", &[0; 32], 0x1000, CODE_CHARS)]);
        let headers = PeHeaders::parse(&pe).unwrap();
        assert_eq!(headers.sections[0].name, ".textbss");
        // .text search should NOT match .textbss
        assert!(headers.text_section().is_none());
        assert!(headers.find_section(".textbss").is_some());
    }

    #[test]
    fn entry_point_rva_parsed() {
        let pe = build_pe64(&[make_section(".text", &[0; 16], 0x1000, CODE_CHARS)]);
        let headers = PeHeaders::parse(&pe).unwrap();
        assert_eq!(headers.entry_point_rva, 0x1000);
    }

    // ---- Invalid input tests -----------------------------------------------

    #[test]
    fn empty_buffer_returns_none() {
        assert!(PeHeaders::parse(&[]).is_none());
    }

    #[test]
    fn no_mz_signature_returns_none() {
        let mut pe = build_pe64(&[make_section(".text", &[0; 16], 0x1000, CODE_CHARS)]);
        pe[0] = b'X';
        assert!(PeHeaders::parse(&pe).is_none());
    }

    #[test]
    fn no_pe_signature_returns_none() {
        let mut pe = build_pe64(&[make_section(".text", &[0; 16], 0x1000, CODE_CHARS)]);
        let pe_off = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
        pe[pe_off] = b'X';
        assert!(PeHeaders::parse(&pe).is_none());
    }

    #[test]
    fn truncated_buffer_returns_none() {
        let pe = build_pe64(&[make_section(".text", &[0; 16], 0x1000, CODE_CHARS)]);
        // Truncate before section headers
        assert!(PeHeaders::parse(&pe[..80]).is_none());
    }

    #[test]
    fn bad_magic_returns_none() {
        let mut pe = build_pe64(&[make_section(".text", &[0; 16], 0x1000, CODE_CHARS)]);
        let pe_off = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap()) as usize;
        let opt = pe_off + 4 + 20;
        pe[opt] = 0xFF;
        pe[opt + 1] = 0xFF;
        assert!(PeHeaders::parse(&pe).is_none());
    }

    // ---- Export table tests ------------------------------------------------

    #[test]
    fn parse_exports_basic() {
        let pe = build_pe64_with_exports(
            &[make_section(".text", &[0xCC; 64], 0x1000, CODE_CHARS)],
            &[("FuncA", 0x1000), ("FuncB", 0x1020)],
        );

        let headers = PeHeaders::parse(&pe).unwrap();
        let exports = headers.parse_exports(&pe).unwrap();

        assert_eq!(exports.len(), 2);

        let func_a = exports.iter().find(|e| e.name.as_deref() == Some("FuncA")).unwrap();
        assert_eq!(func_a.rva, 0x1000);
        assert!(!func_a.is_forward);

        let func_b = exports.iter().find(|e| e.name.as_deref() == Some("FuncB")).unwrap();
        assert_eq!(func_b.rva, 0x1020);
    }

    #[test]
    fn find_export_rva_by_name() {
        let pe = build_pe64_with_exports(
            &[make_section(".text", &[0; 64], 0x1000, CODE_CHARS)],
            &[
                ("EtwEventWrite", 0x1000),
                ("NtAllocateVirtualMemory", 0x1040),
                ("AmsiScanBuffer", 0x1080),
            ],
        );

        let headers = PeHeaders::parse(&pe).unwrap();

        assert_eq!(headers.find_export_rva(&pe, "EtwEventWrite"), Some(0x1000));
        assert_eq!(
            headers.find_export_rva(&pe, "NtAllocateVirtualMemory"),
            Some(0x1040)
        );
        assert_eq!(headers.find_export_rva(&pe, "AmsiScanBuffer"), Some(0x1080));
        assert_eq!(headers.find_export_rva(&pe, "NonExistent"), None);
    }

    #[test]
    fn no_export_directory_returns_none() {
        let pe = build_pe64(&[make_section(".text", &[0; 16], 0x1000, CODE_CHARS)]);
        let headers = PeHeaders::parse(&pe).unwrap();
        assert!(headers.export_directory().is_none());
        assert!(headers.parse_exports(&pe).is_none());
    }

    #[test]
    fn export_ordinal_base() {
        let pe = build_pe64_with_exports(
            &[make_section(".text", &[0; 32], 0x1000, CODE_CHARS)],
            &[("Foo", 0x1000)],
        );

        let headers = PeHeaders::parse(&pe).unwrap();
        let exports = headers.parse_exports(&pe).unwrap();

        // Our builder uses ordinal base 1, so first export has ordinal 1
        assert_eq!(exports[0].ordinal, 1);
    }

    #[test]
    fn forwarder_detection() {
        // A forwarder has its RVA pointing within the export directory.
        // Our builder places the export section at VA 0x8000.
        // If we set a function RVA within the export directory range,
        // it should be detected as a forwarder.
        let pe = build_pe64_with_exports(
            &[make_section(".text", &[0; 16], 0x1000, CODE_CHARS)],
            &[
                ("RealFunc", 0x1000),
                ("ForwardedFunc", 0x8000), // points into the export section
            ],
        );

        let headers = PeHeaders::parse(&pe).unwrap();
        let exports = headers.parse_exports(&pe).unwrap();

        let real = exports.iter().find(|e| e.name.as_deref() == Some("RealFunc")).unwrap();
        assert!(!real.is_forward);

        let fwd = exports
            .iter()
            .find(|e| e.name.as_deref() == Some("ForwardedFunc"))
            .unwrap();
        assert!(fwd.is_forward);
    }

    // ---- Import table tests ------------------------------------------------

    /// Imports for the test builder: (dll_name, &[(function_name, hint)]).
    struct TestImportDll<'a> {
        dll_name: &'a str,
        functions: &'a [(&'a str, u16)],
    }

    /// Build a PE64 binary with an import section for testing.
    fn build_pe64_with_imports(imports: &[TestImportDll<'_>]) -> Vec<u8> {
        build_pe_with_imports(true, imports)
    }

    /// Build a PE32 binary with an import section for testing.
    fn build_pe32_with_imports(imports: &[TestImportDll<'_>]) -> Vec<u8> {
        build_pe_with_imports(false, imports)
    }

    fn build_pe_with_imports(is_64bit: bool, imports: &[TestImportDll<'_>]) -> Vec<u8> {
        let import_sec_va: u32 = 0x9000;
        let import_data = build_import_section(is_64bit, imports, import_sec_va);

        let text_sec = make_section(".text", &[0xCC; 64], 0x1000, CODE_CHARS);
        let idata_sec = make_section(".idata", &import_data.data, import_sec_va, SCN_MEM_READ);

        let user_sections = [text_sec, idata_sec];

        // Build PE with import data directory set.
        let pe_offset: usize = 64;
        let coff = pe_offset + 4;
        let opt = coff + 20;
        let num_dd: usize = 16;
        let opt_size = if is_64bit {
            112 + num_dd * 8
        } else {
            96 + num_dd * 8
        };
        let sec_start = opt + opt_size;
        let headers_end = sec_start + user_sections.len() * 40;
        let file_align: usize = 512;
        let data_start = (headers_end + file_align - 1) / file_align * file_align;

        let mut raw_offsets = Vec::new();
        let mut cursor = data_start;
        for sec in &user_sections {
            raw_offsets.push(cursor);
            cursor += (sec.data.len() + file_align - 1) / file_align * file_align;
        }

        let total_size = cursor;
        let mut buf = vec![0u8; total_size];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());

        // PE signature
        buf[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

        // COFF header
        let machine: u16 = if is_64bit { MACHINE_AMD64 } else { MACHINE_I386 };
        buf[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
        buf[coff + 2..coff + 4]
            .copy_from_slice(&(user_sections.len() as u16).to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());

        // Optional header
        let magic: u16 = if is_64bit { 0x020B } else { 0x010B };
        buf[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point

        if is_64bit {
            buf[opt + 24..opt + 32]
                .copy_from_slice(&0x0000000180000000u64.to_le_bytes());
            buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
            buf[opt + 36..opt + 40]
                .copy_from_slice(&(file_align as u32).to_le_bytes());
            buf[opt + 56..opt + 60].copy_from_slice(&0x10000u32.to_le_bytes());
            buf[opt + 60..opt + 64]
                .copy_from_slice(&(data_start as u32).to_le_bytes());
            // Subsystem = Windows CUI (3)
            buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
            buf[opt + 108..opt + 112].copy_from_slice(&(num_dd as u32).to_le_bytes());

            // Data directory entry 1 (import)
            let dd = opt + 112 + 8; // entry 1 is at offset 8 from dd start
            buf[dd..dd + 4].copy_from_slice(&import_data.dir_rva.to_le_bytes());
            buf[dd + 4..dd + 8].copy_from_slice(&import_data.dir_size.to_le_bytes());
        } else {
            buf[opt + 28..opt + 32].copy_from_slice(&0x10000000u32.to_le_bytes());
            buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
            buf[opt + 36..opt + 40]
                .copy_from_slice(&(file_align as u32).to_le_bytes());
            buf[opt + 56..opt + 60].copy_from_slice(&0x10000u32.to_le_bytes());
            buf[opt + 60..opt + 64]
                .copy_from_slice(&(data_start as u32).to_le_bytes());
            buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
            buf[opt + 92..opt + 96].copy_from_slice(&(num_dd as u32).to_le_bytes());

            let dd = opt + 96 + 8;
            buf[dd..dd + 4].copy_from_slice(&import_data.dir_rva.to_le_bytes());
            buf[dd + 4..dd + 8].copy_from_slice(&import_data.dir_size.to_le_bytes());
        }

        // Section headers
        for (i, sec) in user_sections.iter().enumerate() {
            let s = sec_start + i * 40;
            buf[s..s + 8].copy_from_slice(&sec.name);
            buf[s + 8..s + 12]
                .copy_from_slice(&(sec.data.len() as u32).to_le_bytes());
            buf[s + 12..s + 16].copy_from_slice(&sec.virtual_address.to_le_bytes());
            let raw_size =
                (sec.data.len() + file_align - 1) / file_align * file_align;
            buf[s + 16..s + 20].copy_from_slice(&(raw_size as u32).to_le_bytes());
            buf[s + 20..s + 24]
                .copy_from_slice(&(raw_offsets[i] as u32).to_le_bytes());
            buf[s + 36..s + 40].copy_from_slice(&sec.characteristics.to_le_bytes());
        }

        // Section data
        for (i, sec) in user_sections.iter().enumerate() {
            let off = raw_offsets[i];
            buf[off..off + sec.data.len()].copy_from_slice(&sec.data);
        }

        buf
    }

    struct ImportSectionData {
        data: Vec<u8>,
        dir_rva: u32,
        dir_size: u32,
    }

    /// Build import section data.
    fn build_import_section(
        is_64bit: bool,
        imports: &[TestImportDll<'_>],
        section_va: u32,
    ) -> ImportSectionData {
        let entry_size: usize = if is_64bit { 8 } else { 4 };
        let num_descs = imports.len();
        // IMAGE_IMPORT_DESCRIPTOR array: num_descs + 1 (null terminator), each 20 bytes.
        let desc_area = (num_descs + 1) * 20;

        // Calculate ILT areas for each DLL.
        let mut ilt_offsets = Vec::new();
        let mut cursor = desc_area;
        for imp in imports {
            ilt_offsets.push(cursor);
            cursor += (imp.functions.len() + 1) * entry_size; // +1 for null terminator
        }

        // Hint/Name entries and DLL name strings.
        let mut hna_entries: Vec<(usize, u16, &str)> = Vec::new(); // (offset, hint, name)
        let mut dll_name_offsets = Vec::new();
        for imp in imports {
            for &(name, hint) in imp.functions {
                hna_entries.push((cursor, hint, name));
                cursor += 2 + name.len() + 1; // hint(2) + name + NUL
                // Align to 2
                if cursor % 2 != 0 {
                    cursor += 1;
                }
            }
            dll_name_offsets.push(cursor);
            cursor += imp.dll_name.len() + 1; // name + NUL
        }

        let total_size = cursor;
        let mut data = vec![0u8; total_size];

        // Write descriptors.
        let mut hna_idx = 0;
        for (i, imp) in imports.iter().enumerate() {
            let d = i * 20;
            let ilt_rva = section_va + ilt_offsets[i] as u32;
            let name_rva = section_va + dll_name_offsets[i] as u32;

            // OriginalFirstThunk (ILT RVA)
            data[d..d + 4].copy_from_slice(&ilt_rva.to_le_bytes());
            // Name RVA
            data[d + 12..d + 16].copy_from_slice(&name_rva.to_le_bytes());
            // FirstThunk (IAT RVA) — same as ILT for on-disk image
            data[d + 16..d + 20].copy_from_slice(&ilt_rva.to_le_bytes());

            // Write ILT entries.
            for (j, &(_name, _hint)) in imp.functions.iter().enumerate() {
                let t = ilt_offsets[i] + j * entry_size;
                let (off, hint, name) = hna_entries[hna_idx];
                hna_idx += 1;

                // RVA to hint/name entry (import by name, not ordinal).
                let hna_rva = (section_va + off as u32) as u64;
                if is_64bit {
                    data[t..t + 8].copy_from_slice(&hna_rva.to_le_bytes());
                } else {
                    data[t..t + 4]
                        .copy_from_slice(&(hna_rva as u32).to_le_bytes());
                }

                // Write hint/name entry.
                data[off..off + 2].copy_from_slice(&hint.to_le_bytes());
                data[off + 2..off + 2 + name.len()].copy_from_slice(name.as_bytes());
                data[off + 2 + name.len()] = 0; // NUL
            }
            // ILT null terminator is already zero.

            // Write DLL name string.
            let noff = dll_name_offsets[i];
            data[noff..noff + imp.dll_name.len()]
                .copy_from_slice(imp.dll_name.as_bytes());
            data[noff + imp.dll_name.len()] = 0;
        }
        // Null terminator descriptor is already zeros.

        ImportSectionData {
            dir_rva: section_va,
            dir_size: desc_area as u32,
            data,
        }
    }

    #[test]
    fn parse_imports_single_dll() {
        let pe = build_pe64_with_imports(&[TestImportDll {
            dll_name: "KERNEL32.dll",
            functions: &[("VirtualAlloc", 10), ("CreateFileW", 20)],
        }]);

        let headers = PeHeaders::parse(&pe).unwrap();
        let imports = headers.parse_imports(&pe).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].dll_name, "KERNEL32.dll");
        assert_eq!(imports[0].functions.len(), 2);
        assert_eq!(imports[0].functions[0].name.as_deref(), Some("VirtualAlloc"));
        assert_eq!(imports[0].functions[0].hint, 10);
        assert_eq!(imports[0].functions[1].name.as_deref(), Some("CreateFileW"));
        assert_eq!(imports[0].functions[1].hint, 20);
    }

    #[test]
    fn parse_imports_multiple_dlls() {
        let pe = build_pe64_with_imports(&[
            TestImportDll {
                dll_name: "KERNEL32.dll",
                functions: &[("VirtualAlloc", 10)],
            },
            TestImportDll {
                dll_name: "NTDLL.dll",
                functions: &[("NtCreateSection", 5), ("RtlInitUnicodeString", 8)],
            },
        ]);

        let headers = PeHeaders::parse(&pe).unwrap();
        let imports = headers.parse_imports(&pe).unwrap();

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].dll_name, "KERNEL32.dll");
        assert_eq!(imports[0].functions.len(), 1);
        assert_eq!(imports[1].dll_name, "NTDLL.dll");
        assert_eq!(imports[1].functions.len(), 2);
    }

    #[test]
    fn parse_imports_pe32() {
        let pe = build_pe32_with_imports(&[TestImportDll {
            dll_name: "USER32.dll",
            functions: &[("MessageBoxA", 1), ("GetWindowTextW", 2)],
        }]);

        let headers = PeHeaders::parse(&pe).unwrap();
        assert!(!headers.is_64bit);
        let imports = headers.parse_imports(&pe).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].dll_name, "USER32.dll");
        assert_eq!(imports[0].functions.len(), 2);
        assert_eq!(imports[0].functions[0].name.as_deref(), Some("MessageBoxA"));
    }

    #[test]
    fn no_import_directory_returns_none() {
        let pe = build_pe64(&[make_section(".text", &[0; 16], 0x1000, CODE_CHARS)]);
        let headers = PeHeaders::parse(&pe).unwrap();
        assert!(headers.import_directory().is_none());
        assert!(headers.parse_imports(&pe).is_none());
    }

    #[test]
    fn subsystem_parsed() {
        let pe = build_pe64_with_imports(&[TestImportDll {
            dll_name: "KERNEL32.dll",
            functions: &[("ExitProcess", 0)],
        }]);
        let headers = PeHeaders::parse(&pe).unwrap();
        assert_eq!(headers.subsystem, 3); // Windows CUI
        assert_eq!(headers.subsystem_name(), "Windows CUI");
    }

    #[test]
    fn machine_name_variants() {
        let pe64 = build_pe64(&[make_section(".text", &[0; 16], 0x1000, CODE_CHARS)]);
        let h64 = PeHeaders::parse(&pe64).unwrap();
        assert_eq!(h64.machine_name(), "PE32+ (AMD64)");

        let pe32 = build_pe32(&[make_section(".text", &[0; 16], 0x1000, CODE_CHARS)]);
        let h32 = PeHeaders::parse(&pe32).unwrap();
        assert_eq!(h32.machine_name(), "PE32 (i386)");
    }

    // ---- first_executable_section tests ------------------------------------

    #[test]
    fn first_exec_finds_text() {
        let pe = build_pe64(&[
            make_section(".text", &[0xCC; 32], 0x1000, CODE_CHARS),
            make_section(".data", &[0; 16], 0x2000, DATA_CHARS),
        ]);
        let h = PeHeaders::parse(&pe).unwrap();
        let sec = h.first_executable_section().unwrap();
        assert_eq!(sec.name, ".text");
    }

    #[test]
    fn first_exec_finds_upx0() {
        // UPX-packed PEs have UPX0 (RWX) and UPX1 (RWX).
        // No .text section exists.
        let rwx = SCN_MEM_READ | SCN_MEM_WRITE | SCN_MEM_EXECUTE;
        let pe = build_pe64(&[
            make_section("UPX0", &[0; 32], 0x1000, rwx | 0x80), // +uninitialized
            make_section("UPX1", &[0xCC; 64], 0x58000, rwx),
            make_section("UPX2", &[0; 16], 0x9B000, DATA_CHARS),
        ]);
        let h = PeHeaders::parse(&pe).unwrap();
        assert!(h.text_section().is_none(), ".text should not exist");
        let sec = h.first_executable_section().unwrap();
        assert_eq!(sec.name, "UPX0");
    }

    #[test]
    fn first_exec_prefers_text_over_others() {
        // .text exists alongside other executable sections
        let rwx = SCN_MEM_READ | SCN_MEM_WRITE | SCN_MEM_EXECUTE;
        let pe = build_pe64(&[
            make_section(".init", &[0; 16], 0x1000, CODE_CHARS),
            make_section(".text", &[0xCC; 32], 0x2000, CODE_CHARS),
            make_section("UPX0", &[0; 16], 0x3000, rwx),
        ]);
        let h = PeHeaders::parse(&pe).unwrap();
        let sec = h.first_executable_section().unwrap();
        assert_eq!(sec.name, ".text");
    }

    #[test]
    fn first_exec_none_for_data_only() {
        let pe = build_pe64(&[
            make_section(".rdata", &[0; 16], 0x1000, SCN_MEM_READ),
            make_section(".data", &[0; 16], 0x2000, DATA_CHARS),
        ]);
        let h = PeHeaders::parse(&pe).unwrap();
        assert!(h.first_executable_section().is_none());
    }
}
