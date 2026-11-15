//! Decoding of `Microsoft-Windows-Kernel-File` and
//! `Microsoft-Windows-Kernel-Registry` events.
//!
//! Field layouts follow the providers' manifests: Kernel-File events are
//! version 1 on Windows 10/11 (version 0 on older systems), Kernel-Registry
//! events are version 0.
//!
//! Only creations and modifications are reported. Opening or closing a file
//! or key is not, but those events are still decoded: they maintain a map
//! from the kernel object (`FILE_OBJECT`, registry key object) to its name,
//! because the events for writes, value changes and deletions identify the
//! file or key by that object and often carry no name of their own.
//!
//! Reported:
//! - file created (`CreateNewFile`), first modification through a handle
//!   (`Write`, or a size change via `SetInformation`), first attribute or
//!   timestamp change through a handle (`SetInformation` with
//!   `FileBasicInformation`), deletion (`DeletePath`), rename (`RenamePath`;
//!   `path` is the old name, `new_path` the new one)
//! - registry key created (`CreateKey` that created a new key), key deleted,
//!   value set, value deleted; failed operations are not reported

use std::collections::HashMap;

use super::etw::parser::UserDataReader;
use crate::events::{EventData, FileOperation, RegistryOperation};

/// Entries per generation in each object map (two generations are kept).
const MAP_GENERATION: usize = 32 * 1024;

// Kernel-File event IDs
const FILE_CREATE: u16 = 12;
const FILE_CLOSE: u16 = 14;
const FILE_WRITE: u16 = 16;
const FILE_SET_INFORMATION: u16 = 17;
const FILE_DELETE_PATH: u16 = 26;
const FILE_RENAME_PATH: u16 = 27;
const FILE_CREATE_NEW_FILE: u16 = 30;

// FILE_INFORMATION_CLASS values seen in SetInformation
const FILE_BASIC_INFORMATION: u32 = 4;
const FILE_ALLOCATION_INFORMATION: u32 = 19;
const FILE_END_OF_FILE_INFORMATION: u32 = 20;

// Kernel-Registry event IDs
const REG_CREATE_KEY: u16 = 1;
const REG_OPEN_KEY: u16 = 2;
const REG_DELETE_KEY: u16 = 3;
const REG_SET_VALUE_KEY: u16 = 5;
const REG_DELETE_VALUE_KEY: u16 = 6;
const REG_CLOSE_KEY: u16 = 13;

/// CreateKey `Disposition` when the key did not exist before.
const REG_CREATED_NEW_KEY: u32 = 1;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;

struct OpenFile {
    path: String,
    /// A modification through this handle was already reported (or the
    /// file was created through it, which covers its first writes).
    modified: bool,
    /// An attribute/timestamp change through this handle was already
    /// reported.
    info_changed: bool,
}

/// Names of open files and keys by kernel object, and the decoding of the
/// events that refer to them. One instance per ETW session.
pub struct KernelObjects {
    files: GenMap<OpenFile>,
    keys: GenMap<String>,
}

impl Default for KernelObjects {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelObjects {
    pub fn new() -> Self {
        Self {
            files: GenMap::new(MAP_GENERATION),
            keys: GenMap::new(MAP_GENERATION),
        }
    }

    /// Decode a Kernel-File event; returns what to report, if anything.
    pub fn file_event(
        &mut self,
        event_id: u16,
        version: u8,
        data: &[u8],
        pointer_size: usize,
        pid: u32,
    ) -> Option<EventData> {
        let mut r = UserDataReader::new(data, pointer_size);
        let v0 = version == 0;
        match event_id {
            FILE_CREATE | FILE_CREATE_NEW_FILE => {
                // v1: Irp, FileObject, IssuingThreadId(u32), CreateOptions,
                //     CreateAttributes, ShareAccess, FileName
                // v0: Irp, ThreadId(ptr), FileObject, CreateOptions, ...
                r.read_pointer()?;
                if v0 {
                    r.read_pointer()?;
                }
                let file_object = r.read_pointer()?;
                if !v0 {
                    r.read_u32()?;
                }
                r.read_u32()?; // CreateOptions
                r.read_u32()?; // CreateAttributes
                r.read_u32()?; // ShareAccess
                let path = r.read_utf16_nul();
                if path.is_empty() {
                    return None;
                }
                // Create (12) is every open and is not reported; the name is
                // kept for later writes. CreateNewFile (30) follows it when
                // the open created the file.
                let created = event_id == FILE_CREATE_NEW_FILE;
                let open = |path| OpenFile {
                    path,
                    modified: created,
                    info_changed: false,
                };
                if created {
                    self.files.insert(file_object, open(path.clone()));
                    Some(file(pid, path, FileOperation::Create, None))
                } else {
                    self.files.insert(file_object, open(path));
                    None
                }
            }
            FILE_WRITE => {
                // v1: ByteOffset(u64), Irp, FileObject, FileKey,
                //     IssuingThreadId(u32), IOSize, IOFlags, ExtraFlags
                // v0: ByteOffset(u64), Irp, ThreadId(ptr), FileObject, ...
                r.read_u64()?;
                r.read_pointer()?;
                if v0 {
                    r.read_pointer()?;
                }
                let file_object = r.read_pointer()?;
                self.modified(file_object, pid)
            }
            FILE_SET_INFORMATION => {
                let (file_object, info_class) = read_info_header(&mut r, v0)?;
                match info_class {
                    FILE_END_OF_FILE_INFORMATION | FILE_ALLOCATION_INFORMATION => {
                        self.modified(file_object, pid)
                    }
                    FILE_BASIC_INFORMATION => {
                        let open = self.files.get_mut(file_object)?;
                        if open.info_changed {
                            return None;
                        }
                        open.info_changed = true;
                        Some(file(pid, open.path.clone(), FileOperation::SetInfo, None))
                    }
                    _ => None,
                }
            }
            FILE_DELETE_PATH => {
                let (file_object, _) = read_info_header(&mut r, v0)?;
                let mut path = r.read_utf16_nul();
                if path.is_empty() {
                    path = self.file_path(file_object).unwrap_or_default();
                }
                (!path.is_empty()).then_some(EventData::FileDelete { pid, path })
            }
            FILE_RENAME_PATH => {
                let (file_object, _) = read_info_header(&mut r, v0)?;
                // FilePath is the new name (checked on Windows 11 26200);
                // the old one is the name the file was opened under.
                let new_name = r.read_utf16_nul();
                let old_name = self.file_path(file_object);
                if !new_name.is_empty() {
                    // Later writes through this handle are to the new name.
                    if let Some(open) = self.files.get_mut(file_object) {
                        open.path = new_name.clone();
                    }
                }
                let new_path = (!new_name.is_empty()
                    && old_name.as_deref() != Some(new_name.as_str()))
                .then_some(new_name);
                // Opened before the sensor started: the old name is unknown.
                let path = old_name.unwrap_or_default();
                (!path.is_empty() || new_path.is_some())
                    .then(|| file(pid, path, FileOperation::Rename, new_path))
            }
            FILE_CLOSE => {
                // v1: Irp, FileObject, FileKey, IssuingThreadId(u32)
                // v0: Irp, ThreadId(ptr), FileObject, FileKey
                r.read_pointer()?;
                if v0 {
                    r.read_pointer()?;
                }
                let file_object = r.read_pointer()?;
                self.files.remove(file_object);
                None
            }
            _ => None,
        }
    }

    /// Decode a Kernel-Registry event; returns what to report, if anything.
    pub fn registry_event(
        &mut self,
        event_id: u16,
        data: &[u8],
        pointer_size: usize,
        pid: u32,
    ) -> Option<EventData> {
        let mut r = UserDataReader::new(data, pointer_size);
        match event_id {
            REG_CREATE_KEY | REG_OPEN_KEY => {
                // BaseObject(ptr), KeyObject(ptr), Status(u32),
                // Disposition(u32), BaseName(wstr), RelativeName(wstr)
                let base_object = r.read_pointer()?;
                let key_object = r.read_pointer()?;
                let status = r.read_u32()?;
                let disposition = r.read_u32()?;
                let base_name = r.read_utf16_nul();
                let relative_name = r.read_utf16_nul();
                if !nt_success(status) {
                    return None;
                }
                let base = if base_name.is_empty() && base_object != 0 {
                    self.key_path(base_object).unwrap_or_default()
                } else {
                    base_name
                };
                let key = join_key(&base, &relative_name);
                if key.is_empty() {
                    return None;
                }
                if event_id == REG_CREATE_KEY && disposition == REG_CREATED_NEW_KEY {
                    self.keys.insert(key_object, key.clone());
                    Some(registry(pid, RegistryOperation::CreateKey, key, None, None))
                } else {
                    self.keys.insert(key_object, key);
                    None
                }
            }
            REG_DELETE_KEY => {
                // KeyObject(ptr), Status(u32), KeyName(wstr)
                let key_object = r.read_pointer()?;
                let status = r.read_u32()?;
                let name = r.read_utf16_nul();
                if !nt_success(status) {
                    return None;
                }
                let key = self.resolve_key(key_object, name);
                Some(registry(pid, RegistryOperation::DeleteKey, key, None, None))
            }
            REG_SET_VALUE_KEY => {
                // KeyObject(ptr), Status(u32), Type(u32), DataSize(u32),
                // KeyName(wstr), ValueName(wstr), CapturedDataSize(u16),
                // CapturedData, PreviousDataType, ...
                let key_object = r.read_pointer()?;
                let status = r.read_u32()?;
                let value_type = r.read_u32()?;
                r.read_u32()?; // DataSize
                let name = r.read_utf16_nul();
                let value_name = r.read_utf16_nul();
                if !nt_success(status) {
                    return None;
                }
                // String data (REG_SZ / REG_EXPAND_SZ) as far as captured
                let mut value_data = None;
                if matches!(value_type, REG_SZ | REG_EXPAND_SZ) {
                    if let Some(captured) = r.read_u16().map(usize::from) {
                        if captured > 0 && r.remaining() >= captured {
                            value_data = Some(r.read_utf16_bytes(captured));
                        }
                    }
                }
                let key = self.resolve_key(key_object, name);
                Some(registry(
                    pid,
                    RegistryOperation::SetValue,
                    key,
                    Some(value_name),
                    value_data,
                ))
            }
            REG_DELETE_VALUE_KEY => {
                // KeyObject(ptr), Status(u32), KeyName(wstr), ValueName(wstr)
                let key_object = r.read_pointer()?;
                let status = r.read_u32()?;
                let name = r.read_utf16_nul();
                let value_name = r.read_utf16_nul();
                if !nt_success(status) {
                    return None;
                }
                let key = self.resolve_key(key_object, name);
                Some(registry(
                    pid,
                    RegistryOperation::DeleteValue,
                    key,
                    Some(value_name),
                    None,
                ))
            }
            REG_CLOSE_KEY => {
                // KeyObject(ptr), Status(u32), KeyName(wstr)
                let key_object = r.read_pointer()?;
                self.keys.remove(key_object);
                None
            }
            _ => None,
        }
    }

    /// Report the first modification through a handle.
    fn modified(&mut self, file_object: u64, pid: u32) -> Option<EventData> {
        let open = self.files.get_mut(file_object)?;
        if open.modified {
            return None;
        }
        open.modified = true;
        Some(file(pid, open.path.clone(), FileOperation::Modify, None))
    }

    fn file_path(&mut self, file_object: u64) -> Option<String> {
        self.files
            .get_mut(file_object)
            .map(|open| open.path.clone())
    }

    fn key_path(&mut self, key_object: u64) -> Option<String> {
        self.keys.get_mut(key_object).cloned()
    }

    /// The event's key name, or the name the key object was opened under.
    fn resolve_key(&mut self, key_object: u64, name: String) -> String {
        if name.is_empty() {
            self.key_path(key_object).unwrap_or_default()
        } else {
            name
        }
    }
}

/// FileObject and InfoClass of SetInformation-style events.
///
/// v1: Irp, FileObject, FileKey, ExtraInformation(ptr),
///     IssuingThreadId(u32), InfoClass(u32)[, FilePath]
/// v0: Irp, ThreadId(ptr), FileObject, FileKey, ExtraInformation(ptr),
///     InfoClass(u32)[, FilePath]
fn read_info_header(r: &mut UserDataReader<'_>, v0: bool) -> Option<(u64, u32)> {
    r.read_pointer()?;
    if v0 {
        r.read_pointer()?;
    }
    let file_object = r.read_pointer()?;
    r.read_pointer()?; // FileKey
    r.read_pointer()?; // ExtraInformation
    if !v0 {
        r.read_u32()?;
    }
    let info_class = r.read_u32()?;
    Some((file_object, info_class))
}

fn nt_success(status: u32) -> bool {
    (status as i32) >= 0
}

fn join_key(base: &str, relative: &str) -> String {
    match (base.is_empty(), relative.is_empty()) {
        (true, _) => relative.to_string(),
        (false, true) => base.to_string(),
        (false, false) => format!(
            "{}\\{}",
            base.trim_end_matches('\\'),
            relative.trim_start_matches('\\')
        ),
    }
}

fn file(pid: u32, path: String, operation: FileOperation, new_path: Option<String>) -> EventData {
    EventData::FileCreate {
        pid,
        path,
        operation,
        new_path,
    }
}

fn registry(
    pid: u32,
    operation: RegistryOperation,
    key: String,
    value_name: Option<String>,
    value_data: Option<String>,
) -> EventData {
    EventData::RegistryEvent {
        pid,
        operation,
        key,
        value_name,
        value_data,
    }
}

/// A map with a size bound. Entries go into the current generation; when it
/// is full it becomes the previous one, and the old previous one is dropped.
/// Lookups move entries back to the current generation, so objects that stay
/// in use are kept.
struct GenMap<V> {
    current: HashMap<u64, V>,
    previous: HashMap<u64, V>,
    limit: usize,
}

impl<V> GenMap<V> {
    fn new(limit: usize) -> Self {
        Self {
            current: HashMap::new(),
            previous: HashMap::new(),
            limit: limit.max(1),
        }
    }

    fn insert(&mut self, key: u64, value: V) {
        self.previous.remove(&key);
        if self.current.len() >= self.limit && !self.current.contains_key(&key) {
            self.previous = std::mem::take(&mut self.current);
        }
        self.current.insert(key, value);
    }

    fn get_mut(&mut self, key: u64) -> Option<&mut V> {
        if let Some(value) = self.previous.remove(&key) {
            self.insert(key, value);
        }
        self.current.get_mut(&key)
    }

    fn remove(&mut self, key: u64) {
        self.current.remove(&key);
        self.previous.remove(&key);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.current.len() + self.previous.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PS: usize = 8;

    /// Little-endian payload builder for synthetic event user data.
    #[derive(Default)]
    struct Payload(Vec<u8>);

    impl Payload {
        fn ptr(mut self, v: u64) -> Self {
            self.0.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn u16(mut self, v: u16) -> Self {
            self.0.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn u32(mut self, v: u32) -> Self {
            self.0.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn u64(mut self, v: u64) -> Self {
            self.0.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn wstr(mut self, s: &str) -> Self {
            for unit in s.encode_utf16() {
                self.0.extend_from_slice(&unit.to_le_bytes());
            }
            self.0.extend_from_slice(&[0, 0]);
            self
        }
        fn bytes(mut self, b: &[u8]) -> Self {
            self.0.extend_from_slice(b);
            self
        }
    }

    // --- Kernel-File (version 1 layouts) ---------------------------------

    fn create_v1(event_id: u16, file_object: u64, path: &str) -> (u16, Vec<u8>) {
        let p = Payload::default()
            .ptr(0x1111) // Irp
            .ptr(file_object)
            .u32(42) // IssuingThreadId
            .u32(0x0100_0000) // CreateOptions (FILE_OPEN)
            .u32(0x80) // CreateAttributes
            .u32(7) // ShareAccess
            .wstr(path);
        (event_id, p.0)
    }

    fn write_v1(file_object: u64) -> Vec<u8> {
        Payload::default()
            .u64(0) // ByteOffset
            .ptr(0x2222) // Irp
            .ptr(file_object)
            .ptr(0x3333) // FileKey
            .u32(42) // IssuingThreadId
            .u32(4096) // IOSize
            .u32(0) // IOFlags
            .u32(0) // ExtraFlags
            .0
    }

    fn info_v1(file_object: u64, info_class: u32, path: Option<&str>) -> Vec<u8> {
        let p = Payload::default()
            .ptr(0x2222) // Irp
            .ptr(file_object)
            .ptr(0x3333) // FileKey
            .ptr(0) // ExtraInformation
            .u32(42) // IssuingThreadId
            .u32(info_class);
        match path {
            Some(path) => p.wstr(path).0,
            None => p.0,
        }
    }

    fn close_v1(file_object: u64) -> Vec<u8> {
        Payload::default()
            .ptr(0x2222) // Irp
            .ptr(file_object)
            .ptr(0x3333) // FileKey
            .u32(42) // IssuingThreadId
            .0
    }

    fn file_ev(o: &mut KernelObjects, id: u16, data: &[u8]) -> Option<EventData> {
        o.file_event(id, 1, data, PS, 100)
    }

    fn file_op(ev: &EventData) -> (String, FileOperation, Option<String>) {
        match ev {
            EventData::FileCreate {
                path,
                operation,
                new_path,
                ..
            } => (path.clone(), *operation, new_path.clone()),
            other => panic!("expected FileCreate, got {other:?}"),
        }
    }

    const DOC: &str = r"\Device\HarddiskVolume3\Users\a\doc.txt";

    #[test]
    fn opening_a_file_is_not_reported() {
        let mut o = KernelObjects::new();
        let (id, data) = create_v1(FILE_CREATE, 0xA0, DOC);
        assert!(file_ev(&mut o, id, &data).is_none());
        assert!(file_ev(&mut o, FILE_CLOSE, &close_v1(0xA0)).is_none());
    }

    #[test]
    fn first_write_through_a_handle_is_a_modification() {
        let mut o = KernelObjects::new();
        let (id, data) = create_v1(FILE_CREATE, 0xA0, DOC);
        file_ev(&mut o, id, &data);

        let ev = file_ev(&mut o, FILE_WRITE, &write_v1(0xA0)).expect("modification");
        assert_eq!(file_op(&ev), (DOC.to_string(), FileOperation::Modify, None));
        assert_eq!(ev.acting_pid(), Some(100));
        // Further writes through the same handle are not reported again
        assert!(file_ev(&mut o, FILE_WRITE, &write_v1(0xA0)).is_none());
        // A size change through it neither
        let eof = info_v1(0xA0, FILE_END_OF_FILE_INFORMATION, None);
        assert!(file_ev(&mut o, FILE_SET_INFORMATION, &eof).is_none());

        // After close, the object is forgotten (and may be reused)
        file_ev(&mut o, FILE_CLOSE, &close_v1(0xA0));
        assert!(file_ev(&mut o, FILE_WRITE, &write_v1(0xA0)).is_none());
    }

    #[test]
    fn writes_through_unknown_handles_are_ignored() {
        let mut o = KernelObjects::new();
        assert!(file_ev(&mut o, FILE_WRITE, &write_v1(0xBEEF)).is_none());
    }

    #[test]
    fn new_file_is_reported_once_as_created() {
        let mut o = KernelObjects::new();
        let (id, data) = create_v1(FILE_CREATE, 0xA0, DOC);
        assert!(file_ev(&mut o, id, &data).is_none());
        let (id, data) = create_v1(FILE_CREATE_NEW_FILE, 0xA0, DOC);
        let ev = file_ev(&mut o, id, &data).expect("created");
        assert_eq!(file_op(&ev), (DOC.to_string(), FileOperation::Create, None));
        // Writing the new file's content is not reported separately
        assert!(file_ev(&mut o, FILE_WRITE, &write_v1(0xA0)).is_none());
    }

    #[test]
    fn size_change_is_a_modification() {
        let mut o = KernelObjects::new();
        let (id, data) = create_v1(FILE_CREATE, 0xA0, DOC);
        file_ev(&mut o, id, &data);
        let eof = info_v1(0xA0, FILE_END_OF_FILE_INFORMATION, None);
        let ev = file_ev(&mut o, FILE_SET_INFORMATION, &eof).expect("modification");
        assert_eq!(file_op(&ev).1, FileOperation::Modify);
    }

    #[test]
    fn attribute_change_is_reported_once_per_handle() {
        let mut o = KernelObjects::new();
        let (id, data) = create_v1(FILE_CREATE, 0xA0, DOC);
        file_ev(&mut o, id, &data);
        let basic = info_v1(0xA0, FILE_BASIC_INFORMATION, None);
        let ev = file_ev(&mut o, FILE_SET_INFORMATION, &basic).expect("set info");
        assert_eq!(
            file_op(&ev),
            (DOC.to_string(), FileOperation::SetInfo, None)
        );
        assert!(file_ev(&mut o, FILE_SET_INFORMATION, &basic).is_none());
        // Other information classes (e.g. FilePositionInformation) are not edits
        let position = info_v1(0xA0, 14, None);
        assert!(file_ev(&mut o, FILE_SET_INFORMATION, &position).is_none());
    }

    #[test]
    fn delete_reports_the_events_path() {
        let mut o = KernelObjects::new();
        let del = info_v1(0xA0, 13, Some(DOC)); // FileDispositionInformation
        match file_ev(&mut o, FILE_DELETE_PATH, &del) {
            Some(EventData::FileDelete { pid, path }) => {
                assert_eq!(pid, 100);
                assert_eq!(path, DOC);
            }
            other => panic!("expected FileDelete, got {other:?}"),
        }
    }

    #[test]
    fn rename_reports_old_and_new_name() {
        let mut o = KernelObjects::new();
        let (id, data) = create_v1(FILE_CREATE, 0xA0, DOC);
        file_ev(&mut o, id, &data);
        let new = r"\Device\HarddiskVolume3\Users\a\doc.txt.locked";
        let ev = file_ev(&mut o, FILE_RENAME_PATH, &info_v1(0xA0, 10, Some(new))).expect("rename");
        assert_eq!(
            file_op(&ev),
            (
                DOC.to_string(),
                FileOperation::Rename,
                Some(new.to_string())
            )
        );

        // The handle now refers to the new name
        let ev = file_ev(&mut o, FILE_WRITE, &write_v1(0xA0)).expect("modification");
        assert_eq!(file_op(&ev).0, new);

        // Renamed again to the same name: no new name to report
        let ev = file_ev(&mut o, FILE_RENAME_PATH, &info_v1(0xA0, 10, Some(new))).expect("rename");
        assert_eq!(file_op(&ev), (new.to_string(), FileOperation::Rename, None));

        // Unknown handle: only the new name is known
        let ev = file_ev(&mut o, FILE_RENAME_PATH, &info_v1(0xB0, 10, Some(new))).expect("rename");
        assert_eq!(
            file_op(&ev),
            (String::new(), FileOperation::Rename, Some(new.to_string()))
        );
        assert!(file_ev(&mut o, FILE_RENAME_PATH, &info_v1(0xB0, 10, Some(""))).is_none());
    }

    #[test]
    fn handle_cleanup_and_name_events_are_not_reported() {
        // Before this decoder, Cleanup (13) and Close (14) were reported as
        // SetInfo/Rename and NameDelete (11) as a file deletion.
        let mut o = KernelObjects::new();
        let (id, data) = create_v1(FILE_CREATE, 0xA0, DOC);
        file_ev(&mut o, id, &data);
        let name = Payload::default().ptr(0x3333).wstr(DOC).0;
        for id in [10u16, 11, 13, 14, 15, 24] {
            assert!(file_ev(&mut o, id, &close_v1(0xA0)).is_none(), "event {id}");
            assert!(file_ev(&mut o, id, &name).is_none(), "event {id}");
        }
    }

    #[test]
    fn version_0_layouts_are_decoded() {
        let mut o = KernelObjects::new();
        let create = Payload::default()
            .ptr(0x1111) // Irp
            .ptr(0x4444) // ThreadId
            .ptr(0xA0) // FileObject
            .u32(0)
            .u32(0)
            .u32(0)
            .wstr(DOC)
            .0;
        assert!(o.file_event(FILE_CREATE, 0, &create, PS, 7).is_none());
        let write = Payload::default()
            .u64(0)
            .ptr(0x2222) // Irp
            .ptr(0x4444) // ThreadId
            .ptr(0xA0) // FileObject
            .ptr(0x3333) // FileKey
            .u32(10)
            .u32(0)
            .0;
        let ev = o
            .file_event(FILE_WRITE, 0, &write, PS, 7)
            .expect("modification");
        assert_eq!(file_op(&ev), (DOC.to_string(), FileOperation::Modify, None));
    }

    #[test]
    fn truncated_payloads_are_ignored() {
        let mut o = KernelObjects::new();
        assert!(file_ev(&mut o, FILE_CREATE, &[1, 2, 3]).is_none());
        assert!(file_ev(&mut o, FILE_WRITE, &[]).is_none());
        assert!(o
            .registry_event(REG_SET_VALUE_KEY, &[0; 5], PS, 1)
            .is_none());
    }

    #[test]
    fn pointer_size_4_layouts_are_decoded() {
        let mut o = KernelObjects::new();
        let create = Payload::default()
            .u32(0x1111) // Irp
            .u32(0xA0) // FileObject
            .u32(42)
            .u32(0)
            .u32(0)
            .u32(0)
            .wstr(DOC)
            .0;
        assert!(o.file_event(FILE_CREATE, 1, &create, 4, 7).is_none());
        let write = Payload::default()
            .u64(0)
            .u32(0x2222)
            .u32(0xA0)
            .u32(0x3333)
            .u32(42)
            .u32(10)
            .u32(0)
            .u32(0)
            .0;
        let ev = o
            .file_event(FILE_WRITE, 1, &write, 4, 7)
            .expect("modification");
        assert_eq!(file_op(&ev).0, DOC);
    }

    // --- Kernel-Registry ---------------------------------------------------

    const RUN: &str = r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

    /// CreateKey / OpenKey payload (both have the same fields).
    fn open_key(
        base: u64,
        key: u64,
        status: u32,
        disposition: u32,
        base_name: &str,
        rel: &str,
    ) -> Vec<u8> {
        Payload::default()
            .ptr(base)
            .ptr(key)
            .u32(status)
            .u32(disposition)
            .wstr(base_name)
            .wstr(rel)
            .0
    }

    fn set_value(
        key: u64,
        status: u32,
        reg_type: u32,
        key_name: &str,
        value: &str,
        data: &str,
    ) -> Vec<u8> {
        let utf16: Vec<u8> = data.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        Payload::default()
            .ptr(key)
            .u32(status)
            .u32(reg_type)
            .u32(utf16.len() as u32)
            .wstr(key_name)
            .wstr(value)
            .u16(utf16.len() as u16)
            .bytes(&utf16)
            .u32(0) // PreviousDataType
            .u32(0) // PreviousDataSize
            .u16(0) // PreviousDataCapturedSize
            .0
    }

    fn reg(ev: Option<EventData>) -> (RegistryOperation, String, Option<String>, Option<String>) {
        match ev {
            Some(EventData::RegistryEvent {
                operation,
                key,
                value_name,
                value_data,
                ..
            }) => (operation, key, value_name, value_data),
            other => panic!("expected RegistryEvent, got {other:?}"),
        }
    }

    #[test]
    fn opening_a_key_is_not_reported_but_names_its_values() {
        let mut o = KernelObjects::new();
        // OpenKey has a Disposition field too; before this decoder it was
        // misread and reported as CreateKey with an empty name.
        let open = open_key(0, 0xC0, 0, 0, "", RUN);
        assert!(o.registry_event(REG_OPEN_KEY, &open, PS, 1).is_none());

        // SetValueKey usually carries no key name: resolved from the open
        let set = set_value(0xC0, 0, REG_SZ, "", "Updater", r"C:\Users\a\evil.exe");
        assert_eq!(
            reg(o.registry_event(REG_SET_VALUE_KEY, &set, PS, 1)),
            (
                RegistryOperation::SetValue,
                RUN.to_string(),
                Some("Updater".to_string()),
                Some(r"C:\Users\a\evil.exe".to_string())
            )
        );

        // After CloseKey the object is forgotten
        let close = Payload::default().ptr(0xC0).u32(0).wstr("").0;
        assert!(o.registry_event(REG_CLOSE_KEY, &close, PS, 1).is_none());
        let (_, key, _, _) = reg(o.registry_event(REG_SET_VALUE_KEY, &set, PS, 1));
        assert_eq!(key, "");
    }

    #[test]
    fn create_key_is_reported_only_when_the_key_is_new() {
        let mut o = KernelObjects::new();
        let existing = open_key(0, 0xC0, 0, 2, "", RUN); // REG_OPENED_EXISTING_KEY
        assert!(o.registry_event(REG_CREATE_KEY, &existing, PS, 1).is_none());
        let created = open_key(0xC0, 0xC1, 0, REG_CREATED_NEW_KEY, "", "Sub");
        assert_eq!(
            reg(o.registry_event(REG_CREATE_KEY, &created, PS, 1)),
            (
                RegistryOperation::CreateKey,
                format!(r"{RUN}\Sub"),
                None,
                None
            )
        );
    }

    #[test]
    fn relative_names_join_the_base_name() {
        let mut o = KernelObjects::new();
        let created = open_key(
            0xB0,
            0xC1,
            0,
            REG_CREATED_NEW_KEY,
            r"\REGISTRY\MACHINE\SOFTWARE\",
            "Vendor",
        );
        let (_, key, _, _) = reg(o.registry_event(REG_CREATE_KEY, &created, PS, 1));
        assert_eq!(key, r"\REGISTRY\MACHINE\SOFTWARE\Vendor");
    }

    #[test]
    fn failed_registry_operations_are_not_reported() {
        let mut o = KernelObjects::new();
        let denied = 0xC000_0022; // STATUS_ACCESS_DENIED
        let create = open_key(0, 0xC0, denied, 0, "", RUN);
        assert!(o.registry_event(REG_CREATE_KEY, &create, PS, 1).is_none());
        let set = set_value(0xC0, denied, REG_SZ, RUN, "v", "x");
        assert!(o.registry_event(REG_SET_VALUE_KEY, &set, PS, 1).is_none());
        let del = Payload::default().ptr(0xC0).u32(denied).wstr(RUN).0;
        assert!(o.registry_event(REG_DELETE_KEY, &del, PS, 1).is_none());
    }

    #[test]
    fn delete_key_and_value_use_the_event_name_or_the_open() {
        let mut o = KernelObjects::new();
        let open = open_key(0, 0xC0, 0, 0, "", RUN);
        o.registry_event(REG_OPEN_KEY, &open, PS, 1);

        let del_value = Payload::default()
            .ptr(0xC0)
            .u32(0)
            .wstr("")
            .wstr("Updater")
            .0;
        assert_eq!(
            reg(o.registry_event(REG_DELETE_VALUE_KEY, &del_value, PS, 1)),
            (
                RegistryOperation::DeleteValue,
                RUN.to_string(),
                Some("Updater".to_string()),
                None
            )
        );

        let named = Payload::default()
            .ptr(0xD0)
            .u32(0)
            .wstr(r"\REGISTRY\USER\x")
            .0;
        let (op, key, _, _) = reg(o.registry_event(REG_DELETE_KEY, &named, PS, 1));
        assert_eq!(
            (op, key.as_str()),
            (RegistryOperation::DeleteKey, r"\REGISTRY\USER\x")
        );
    }

    #[test]
    fn non_string_values_have_no_data() {
        let mut o = KernelObjects::new();
        let set = set_value(0xC0, 0, 4, RUN, "Flags", "ignored"); // REG_DWORD
        let (_, _, name, data) = reg(o.registry_event(REG_SET_VALUE_KEY, &set, PS, 1));
        assert_eq!(name.as_deref(), Some("Flags"));
        assert_eq!(data, None);
    }

    #[test]
    fn query_and_other_key_events_are_not_reported() {
        // QueryKey (4) used to be reported as RenameKey with garbage names.
        let mut o = KernelObjects::new();
        let query = Payload::default()
            .ptr(0xC0)
            .u32(0)
            .u32(7)
            .u32(4)
            .wstr(RUN)
            .0;
        for id in [4u16, 7, 8, 9, 10, 11, 12, 14, 15] {
            assert!(o.registry_event(id, &query, PS, 1).is_none(), "event {id}");
        }
    }

    // --- GenMap ----------------------------------------------------------

    #[test]
    fn gen_map_is_bounded_and_keeps_entries_in_use() {
        let mut m = GenMap::new(2);
        m.insert(1, "a");
        m.insert(2, "b");
        m.insert(3, "c"); // rotates: {3} + previous {1, 2}
        assert_eq!(m.len(), 3);
        assert_eq!(m.get_mut(1).copied(), Some("a")); // promoted: {3, 1} + {2}
        m.insert(4, "d"); // rotates: {4} + previous {3, 1}; 2 dropped
        assert_eq!(m.get_mut(2), None);
        assert_eq!(m.get_mut(1).copied(), Some("a"));
        assert!(m.len() <= 4);
        m.remove(1);
        assert_eq!(m.get_mut(1), None);
    }
}
