//! Per-agent JSONL storage.
//!
//! Layout (the events files are compatible with the sensor's file sink, so
//! the investigation CLI and `threatfalcon alert`'s rotation detection work
//! unchanged):
//!
//! ```text
//! <data_dir>/agents/<agent>/events.jsonl       active file
//! <data_dir>/agents/<agent>/events.jsonl.N     rotated files, higher N = newer
//! <data_dir>/agents/<agent>/rejected.jsonl(.N) quarantined elements that
//!                                              failed validation
//! ```
//!
//! Guarantees, given that the sensor re-sends a batch until it gets a 2xx:
//!
//! - Durability: a batch is acknowledged only after its lines are fsynced,
//!   and after the directory entries of newly created files and directories
//!   are fsynced too.
//! - No duplicates: events are deduplicated by event id against a window of
//!   the most recent ids of the agent. The window is rebuilt from the tail
//!   of the stored files when the writer opens, so a batch that is re-sent
//!   after a restart (lost acknowledgement) or after a crash that left part
//!   of it on disk is not stored twice.
//! - Whole lines: an interrupted write can only leave a partial last line,
//!   which is truncated when the file is opened (it was never acknowledged).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use serde::Deserialize;

use crate::ingest::ValidatedEvent;

pub const EVENTS_FILE: &str = "events.jsonl";
pub const QUARANTINE_FILE: &str = "rejected.jsonl";
/// Event ids remembered per agent for duplicate suppression (~12 MB).
pub const DEFAULT_DEDUP_WINDOW: usize = 200_000;
/// Upper bound on how much of the newest stored data is read to rebuild the
/// id window (reading stops once the window is full; 200,000 typical
/// sensor events are about 80 MB).
const SEED_SCAN_BYTES: u64 = 128 * 1024 * 1024;
const AGENTS_DIR: &str = "agents";
const LOCK_FILE: &str = ".lock";

#[derive(Debug, Clone)]
pub struct StoreSettings {
    /// Rotate before a write would push a file past this size. 0 disables
    /// rotation.
    pub rotation_bytes: u64,
    /// Rotated files kept per agent and file kind. 0 keeps everything.
    pub max_rotated_files: u32,
    pub fsync: bool,
    /// Event ids remembered per agent. 0 disables duplicate suppression.
    pub dedup_window: usize,
    /// Writes that would leave less free space than this on the data volume
    /// are refused (after retention had a chance to free space). 0 disables.
    pub min_free_bytes: u64,
    /// How free space is measured.
    pub free_space: FreeSpace,
}

/// Measures the free space available for a directory (statvfs by default;
/// replaceable so tests can simulate a small disk).
#[derive(Clone)]
pub struct FreeSpace(Arc<FreeSpaceFn>);

type FreeSpaceFn = dyn Fn(&Path) -> io::Result<u64> + Send + Sync;

impl FreeSpace {
    pub fn new(f: impl Fn(&Path) -> io::Result<u64> + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    fn of(&self, dir: &Path) -> io::Result<u64> {
        (self.0)(dir)
    }
}

impl Default for FreeSpace {
    fn default() -> Self {
        Self::new(|dir| {
            let st = rustix::fs::statvfs(dir)?;
            Ok(st.f_bavail.saturating_mul(st.f_frsize))
        })
    }
}

impl std::fmt::Debug for FreeSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FreeSpace")
    }
}

/// A write was refused because the data volume is low on free space. Kept
/// distinct from I/O failures: the writer's state is intact.
#[derive(Debug)]
pub struct LowDisk {
    pub available: u64,
    pub needed: u64,
    pub reserve: u64,
}

impl std::fmt::Display for LowDisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "low disk space: {} bytes free, {} needed plus a reserve of {}",
            self.available, self.needed, self.reserve
        )
    }
}

impl std::error::Error for LowDisk {}

/// True if `e` is a [`LowDisk`] refusal rather than an I/O failure.
pub fn is_low_disk(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<LowDisk>())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriteOutcome {
    /// Events appended to the events file.
    pub stored: usize,
    /// Events skipped because they were already stored.
    pub duplicates: usize,
}

type WriterSlot = Arc<Mutex<Option<AgentWriter>>>;

pub struct Store {
    agents_dir: PathBuf,
    settings: StoreSettings,
    writers: Mutex<HashMap<Arc<str>, WriterSlot>>,
    /// Held for the lifetime of the store so that two server processes
    /// never write to the same data directory.
    _lock: File,
}

impl Store {
    pub fn open(data_dir: &Path, settings: StoreSettings) -> io::Result<Self> {
        create_dir_synced(data_dir, settings.fsync)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o640)
            .open(data_dir.join(LOCK_FILE))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |e| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "data directory {} is locked by another process ({e})",
                        data_dir.display()
                    ),
                )
            },
        )?;
        let agents_dir = data_dir.join(AGENTS_DIR);
        create_dir_synced(&agents_dir, settings.fsync)?;
        Ok(Self {
            agents_dir,
            settings,
            writers: Mutex::new(HashMap::new()),
            _lock: lock,
        })
    }

    pub fn agent_dir(&self, agent: &str) -> PathBuf {
        self.agents_dir.join(agent)
    }

    /// Modification time of an agent's active events file, used to report
    /// a last-seen time for agents that have not connected since startup.
    pub fn last_write_time(&self, agent: &str) -> Option<SystemTime> {
        fs::metadata(self.agent_dir(agent).join(EVENTS_FILE))
            .and_then(|m| m.modified())
            .ok()
    }

    /// Bytes available to unprivileged users on the data volume.
    pub fn available_bytes(&self) -> io::Result<u64> {
        self.settings.free_space.of(&self.agents_dir)
    }

    /// Run `f` with the agent's writer, opening it on first use. Blocking.
    /// Writers of different agents open (and rebuild their id windows)
    /// concurrently. After an I/O error the writer is dropped, so the next
    /// call rebuilds its state (file sizes, id window) from what is on disk;
    /// a low-disk refusal leaves it intact.
    pub fn with_writer<T>(
        &self,
        agent: &Arc<str>,
        f: impl FnOnce(&mut AgentWriter) -> io::Result<T>,
    ) -> io::Result<T> {
        let slot = {
            let mut writers = self.writers.lock().unwrap_or_else(PoisonError::into_inner);
            writers.entry(agent.clone()).or_default().clone()
        };
        let mut guard = slot.lock().unwrap_or_else(PoisonError::into_inner);
        let writer = match &mut *guard {
            Some(writer) => writer,
            empty => empty.insert(AgentWriter::open(
                self.agent_dir(agent),
                self.settings.clone(),
            )?),
        };
        let result = f(writer);
        if result.as_ref().is_err_and(|e| !is_low_disk(e)) {
            *guard = None;
        }
        result
    }
}

/// Writes one agent's events and quarantine records.
pub struct AgentWriter {
    dir: PathBuf,
    settings: StoreSettings,
    events: JsonlFile,
    /// Opened on first use, so agents without rejected elements have no file.
    quarantine: Option<JsonlFile>,
    window: IdWindow,
}

impl AgentWriter {
    pub fn open(dir: PathBuf, settings: StoreSettings) -> io::Result<Self> {
        create_dir_synced(&dir, settings.fsync)?;
        let events = JsonlFile::open(&dir, EVENTS_FILE, &settings)?;
        let mut window = IdWindow::new(settings.dedup_window);
        if settings.dedup_window > 0 {
            seed_window(&dir, &mut window, SEED_SCAN_BYTES)?;
        }
        Ok(Self {
            dir,
            settings,
            events,
            quarantine: None,
            window,
        })
    }

    /// Store a validated batch: events not seen before go to the events
    /// file, `quarantine` (pre-formatted lines) to the quarantine file.
    /// Returns once everything is durable.
    pub fn write_batch(
        &mut self,
        events: &[ValidatedEvent<'_>],
        quarantine: &[u8],
    ) -> io::Result<WriteOutcome> {
        let mut outcome = WriteOutcome::default();
        let mut lines = Vec::new();
        let mut new_ids = Vec::new();
        let mut in_batch = HashSet::new();
        let dedup = self.window.capacity > 0;
        for event in events {
            if dedup && (self.window.contains(event.id) || !in_batch.insert(event.id)) {
                outcome.duplicates += 1;
                continue;
            }
            lines.extend_from_slice(event.line.as_bytes());
            lines.push(b'\n');
            new_ids.push(event.id);
        }

        if lines.is_empty() && quarantine.is_empty() {
            return Ok(outcome);
        }

        // Rotations that are due happen first (they prune the oldest
        // generations), so that the free-space check sees the space they
        // release. Otherwise a full disk would block the very rotation that
        // frees it.
        if !lines.is_empty() {
            self.events.prepare(lines.len() as u64)?;
        }
        if !quarantine.is_empty() {
            if self.quarantine.is_none() {
                self.quarantine =
                    Some(JsonlFile::open(&self.dir, QUARANTINE_FILE, &self.settings)?);
            }
            if let Some(file) = &mut self.quarantine {
                file.prepare(quarantine.len() as u64)?;
            }
        }
        self.ensure_free_space((lines.len() + quarantine.len()) as u64)?;

        if !lines.is_empty() {
            self.events.append(&lines)?;
            // Remember the ids before anything else can fail: the client
            // will re-send the batch and these events must not be stored
            // again.
            outcome.stored = new_ids.len();
            for id in new_ids {
                self.window.insert(id);
            }
        }
        if let (false, Some(file)) = (quarantine.is_empty(), &mut self.quarantine) {
            file.append(quarantine)?;
        }
        Ok(outcome)
    }

    /// Refuse the write (`LowDisk`) if it would leave less than the reserve
    /// free. Before refusing, retention is applied (in case
    /// `max_rotated_files` was lowered), and an agent that already holds its
    /// full number of rotated files gives up its oldest one early: the next
    /// rotation would delete it anyway, and waiting for that rotation would
    /// block ingestion for good.
    fn ensure_free_space(&mut self, needed: u64) -> io::Result<()> {
        let reserve = self.settings.min_free_bytes;
        if reserve == 0 {
            return Ok(());
        }
        let probe = self.settings.free_space.clone();
        let available = || match probe.of(&self.dir) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                tracing::warn!(error = %e, "could not determine free disk space");
                None
            }
        };
        let enough = |avail: Option<u64>| avail.is_none_or(|a| a >= reserve.saturating_add(needed));

        if enough(available()) {
            return Ok(());
        }
        self.events.prune()?;
        if let Some(q) = &self.quarantine {
            q.prune()?;
        }
        loop {
            let avail = available();
            if enough(avail) {
                return Ok(());
            }
            let freed = match self.events.drop_oldest_at_limit()? {
                Some(path) => Some(path),
                None => match &self.quarantine {
                    Some(q) => q.drop_oldest_at_limit()?,
                    None => None,
                },
            };
            match freed {
                Some(path) => tracing::warn!(
                    path = %path.display(),
                    "low disk space: deleted the oldest rotated file early"
                ),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::StorageFull,
                        LowDisk {
                            available: avail.unwrap_or(0),
                            needed,
                            reserve,
                        },
                    ))
                }
            }
        }
    }
}

/// An append-only JSONL file with size-based rotation (`<name>.N`) and
/// retention.
struct JsonlFile {
    dir: PathBuf,
    name: &'static str,
    base: PathBuf,
    file: File,
    /// (device, inode) of `file`, to notice external replacement.
    ident: (u64, u64),
    size: u64,
    /// Highest rotated generation on disk.
    generation: u32,
    settings: StoreSettings,
}

impl JsonlFile {
    fn open(dir: &Path, name: &'static str, settings: &StoreSettings) -> io::Result<Self> {
        create_dir_synced(dir, settings.fsync)?;
        let base = dir.join(name);
        let (file, size) = open_jsonl(&base, settings.fsync)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            name,
            ident: file_ident(&file)?,
            file,
            size,
            generation: rotated_generations(dir, name)?.last().copied().unwrap_or(0),
            base,
            settings: settings.clone(),
        })
    }

    /// Append whole lines (`payload` must end with a newline) and make them
    /// durable. On failure nothing of `payload` is left in the file.
    fn append(&mut self, payload: &[u8]) -> io::Result<()> {
        debug_assert_eq!(payload.last(), Some(&b'\n'));
        let len = payload.len() as u64;
        self.prepare(len)?;

        let result = self.file.write_all(payload).and_then(|()| {
            if self.settings.fsync {
                self.file.sync_data()
            } else {
                Ok(())
            }
        });
        if let Err(e) = result {
            // Do not leave a partial (unacknowledged) batch behind: the
            // client will retry it, and JSONL readers need whole lines.
            if let Err(te) = self.file.set_len(self.size) {
                tracing::error!(
                    path = %self.base.display(),
                    error = %te,
                    "failed to roll back partial write"
                );
            }
            return Err(e);
        }
        self.size += len;
        Ok(())
    }

    /// Get ready to append `len` bytes: reopen the file if it was removed,
    /// and rotate first if the write would push it past the rotation size.
    fn prepare(&mut self, len: u64) -> io::Result<()> {
        self.ensure_current()?;
        if self.settings.rotation_bytes > 0
            && self.size > 0
            && self.size.saturating_add(len) > self.settings.rotation_bytes
        {
            self.rotate()?;
        }
        Ok(())
    }

    /// Under disk pressure: if the file already has its full set of rotated
    /// generations, delete the oldest (which the next rotation would delete).
    /// Returns the deleted path, or `None` if nothing may be deleted.
    fn drop_oldest_at_limit(&self) -> io::Result<Option<PathBuf>> {
        let keep = self.settings.max_rotated_files as usize;
        if keep == 0 {
            return Ok(None);
        }
        let generations = rotated_generations(&self.dir, self.name)?;
        if generations.len() < keep {
            return Ok(None);
        }
        let name = format!("{}.{}", self.name, generations[0]);
        self.remove_generation(&name)?;
        Ok(Some(self.dir.join(name)))
    }

    /// Reopen the file if it, or the whole agent directory, was removed or
    /// replaced behind our back, so that writes never go to an unlinked
    /// inode.
    fn ensure_current(&mut self) -> io::Result<()> {
        match fs::metadata(&self.base) {
            Ok(m) if (m.dev(), m.ino()) == self.ident => return Ok(()),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        tracing::warn!(
            path = %self.base.display(),
            "file was removed or replaced externally; reopening"
        );
        create_dir_synced(&self.dir, self.settings.fsync)?;
        let (file, size) = open_jsonl(&self.base, self.settings.fsync)?;
        self.ident = file_ident(&file)?;
        self.file = file;
        self.size = size;
        self.generation = self.generation.max(
            rotated_generations(&self.dir, self.name)?
                .last()
                .copied()
                .unwrap_or(0),
        );
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        // Re-scan so an externally created file is never overwritten.
        let highest = rotated_generations(&self.dir, self.name)?
            .last()
            .copied()
            .unwrap_or(0);
        let next = self
            .generation
            .max(highest)
            .checked_add(1)
            .ok_or_else(|| io::Error::other("rotation generation overflow"))?;
        let rotated_path = self.dir.join(format!("{}.{next}", self.name));
        if !self.settings.fsync {
            // Make sure the rotated file is complete on disk.
            self.file.sync_data()?;
        }
        match fs::rename(&self.base, &rotated_path) {
            Ok(()) => self.generation = next,
            // A previous rotation renamed the file but failed to reopen.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let (file, size) = open_jsonl(&self.base, false)?;
        self.ident = file_ident(&file)?;
        self.file = file;
        self.size = size;
        // Covers both the rename and the new file.
        sync_dir(&self.dir)?;
        tracing::info!(path = %rotated_path.display(), "rotated file");
        if let Err(e) = self.prune() {
            tracing::warn!(dir = %self.dir.display(), error = %e, "failed to prune rotated files");
        }
        Ok(())
    }

    /// Delete the oldest rotated files beyond `max_rotated_files`, together
    /// with sidecar files such as the CLI's `events.jsonl.N.idx.sqlite`.
    fn prune(&self) -> io::Result<()> {
        let keep = self.settings.max_rotated_files as usize;
        if keep == 0 {
            return Ok(());
        }
        let generations = rotated_generations(&self.dir, self.name)?;
        if generations.len() <= keep {
            return Ok(());
        }
        let doomed = &generations[..generations.len() - keep];
        for gen in doomed {
            let name = format!("{}.{gen}", self.name);
            self.remove_generation(&name)?;
            tracing::info!(dir = %self.dir.display(), file = %name, "deleted old rotated file");
        }
        Ok(())
    }

    /// Delete a rotated file and its sidecars (e.g. `events.jsonl.N.idx.sqlite`).
    fn remove_generation(&self, name: &str) -> io::Result<()> {
        remove_if_exists(&self.dir.join(name))?;
        let sidecar_prefix = format!("{name}.");
        for entry in fs::read_dir(&self.dir)?.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(&sidecar_prefix)
            {
                remove_if_exists(&entry.path())?;
            }
        }
        Ok(())
    }
}

/// Recently stored event ids of one agent (FIFO, bounded).
struct IdWindow {
    capacity: usize,
    order: VecDeque<u128>,
    set: HashSet<u128>,
}

impl IdWindow {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            set: HashSet::new(),
        }
    }

    fn contains(&self, id: u128) -> bool {
        self.set.contains(&id)
    }

    fn insert(&mut self, id: u128) {
        if self.capacity == 0 || !self.set.insert(id) {
            return;
        }
        self.order.push_back(id);
        if self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
    }

    fn len(&self) -> usize {
        self.order.len()
    }
}

/// Fill the window with the ids of the newest stored events: the tail of
/// the active events file, then the newest rotated files, within a read
/// budget.
fn seed_window(dir: &Path, window: &mut IdWindow, budget: u64) -> io::Result<()> {
    let mut files = vec![dir.join(EVENTS_FILE)];
    for gen in rotated_generations(dir, EVENTS_FILE)?.into_iter().rev() {
        files.push(dir.join(format!("{EVENTS_FILE}.{gen}")));
    }
    let mut remaining = budget;
    let mut collected = 0usize;
    let mut chunks = Vec::new(); // newest file first
    for path in files {
        if remaining == 0 || collected >= window.capacity {
            break;
        }
        match tail_event_ids(&path, remaining) {
            Ok((ids, read)) => {
                remaining = remaining.saturating_sub(read);
                collected += ids.len();
                chunks.push(ids);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    // Oldest first, so that eviction order follows storage order.
    for ids in chunks.into_iter().rev() {
        for id in ids {
            window.insert(id);
        }
    }
    if window.len() > 0 {
        tracing::debug!(dir = %dir.display(), ids = window.len(), "rebuilt duplicate-suppression window");
    }
    Ok(())
}

/// Event ids of the complete lines in the last `max_bytes` of a file, in
/// file order, and the number of bytes read.
fn tail_event_ids(path: &Path, max_bytes: u64) -> io::Result<(Vec<u128>, u64)> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut line = Vec::new();
    if start > 0 {
        // Skip the (probably partial) line the window starts in.
        reader.read_until(b'\n', &mut line)?;
    }
    let mut ids = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if line.last() == Some(&b'\n') {
            if let Some(id) = event_id(&line) {
                ids.push(id);
            }
        }
    }
    Ok((ids, len - start))
}

/// The `id` of a stored event line. Lines written by the sensor start with
/// the id, so the common case needs no JSON parsing.
fn event_id(line: &[u8]) -> Option<u128> {
    const PREFIX: &[u8] = b"{\"id\":\"";
    if let Some(rest) = line.strip_prefix(PREFIX) {
        if rest.len() > 36 && rest[36] == b'"' {
            if let Ok(id) = uuid::Uuid::try_parse_ascii(&rest[..36]) {
                return Some(id.as_u128());
            }
        }
    }
    #[derive(Deserialize)]
    struct IdOnly<'a> {
        #[serde(borrow)]
        id: Cow<'a, str>,
    }
    let parsed: IdOnly = serde_json::from_slice(line).ok()?;
    uuid::Uuid::try_parse(&parsed.id)
        .ok()
        .map(|id| id.as_u128())
}

/// Create a directory and any missing parents (mode 0750), fsyncing each
/// parent so the new entries survive a crash.
fn create_dir_synced(path: &Path, fsync: bool) -> io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    create_dir_synced(parent, fsync)?;
    match fs::DirBuilder::new().mode(0o750).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => return Ok(()),
        Err(e) => return Err(e),
    }
    if fsync {
        sync_dir(parent)?;
    }
    Ok(())
}

/// Open (creating if needed) a JSONL file for appending and drop any
/// trailing partial line left by an interrupted write. A newly created file
/// has its directory entry fsynced when `fsync` is set.
fn open_jsonl(path: &Path, fsync: bool) -> io::Result<(File, u64)> {
    let existed = path.exists();
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o640)
        .open(path)?;
    if !existed && fsync {
        if let Some(dir) = path.parent() {
            sync_dir(dir)?;
        }
    }
    let len = file.metadata()?.len();
    let aligned = line_aligned_len(&file, len)?;
    if aligned != len {
        file.set_len(aligned)?;
        file.sync_all()?;
        tracing::warn!(
            path = %path.display(),
            bytes = len - aligned,
            "truncated incomplete trailing line"
        );
    }
    Ok((file, aligned))
}

/// Length of the longest prefix of the file that ends with a newline.
fn line_aligned_len(file: &File, len: u64) -> io::Result<u64> {
    if len == 0 {
        return Ok(0);
    }
    let mut last = [0u8; 1];
    file.read_exact_at(&mut last, len - 1)?;
    if last[0] == b'\n' {
        return Ok(len);
    }
    let mut buf = vec![0u8; 64 * 1024];
    let mut end = len;
    while end > 0 {
        let start = end.saturating_sub(buf.len() as u64);
        let chunk = &mut buf[..(end - start) as usize];
        file.read_exact_at(chunk, start)?;
        if let Some(i) = chunk.iter().rposition(|&b| b == b'\n') {
            return Ok(start + i as u64 + 1);
        }
        end = start;
    }
    Ok(0)
}

fn file_ident(file: &File) -> io::Result<(u64, u64)> {
    let m = file.metadata()?;
    Ok((m.dev(), m.ino()))
}

/// Generations `N` of `<name>.N` files in `dir`, ascending.
fn rotated_generations(dir: &Path, name: &str) -> io::Result<Vec<u32>> {
    let prefix = format!("{name}.");
    let mut generations: Vec<u32> = fs::read_dir(dir)?
        .flatten()
        .filter_map(|entry| {
            let file_name = entry.file_name();
            let suffix = file_name.to_str()?.strip_prefix(&prefix)?.to_owned();
            let canonical = !suffix.is_empty()
                && !suffix.starts_with('0')
                && suffix.bytes().all(|b| b.is_ascii_digit());
            if canonical {
                suffix.parse().ok()
            } else {
                None
            }
        })
        .collect();
    generations.sort_unstable();
    Ok(generations)
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn settings(rotation_bytes: u64, max_rotated_files: u32) -> StoreSettings {
        StoreSettings {
            rotation_bytes,
            max_rotated_files,
            fsync: true,
            dedup_window: DEFAULT_DEDUP_WINDOW,
            min_free_bytes: 0,
            free_space: FreeSpace::default(),
        }
    }

    /// A disk of `capacity` bytes holding only the files under `root`.
    fn small_disk(root: PathBuf, capacity: u64) -> FreeSpace {
        FreeSpace::new(move |_| Ok(capacity.saturating_sub(tree_size(&root))))
    }

    fn tree_size(dir: &Path) -> u64 {
        fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| match e.metadata() {
                        Ok(m) if m.is_dir() => tree_size(&e.path()),
                        Ok(m) => m.len(),
                        Err(_) => 0,
                    })
                    .sum()
            })
            .unwrap_or(0)
    }

    fn id(n: u32) -> String {
        format!("00000000-0000-4000-8000-{n:012}")
    }

    /// A minimal stored line: `{"id":"<uuid>","n":<n>}`.
    fn line(n: u32) -> String {
        format!("{{\"id\":\"{}\",\"n\":{n}}}", id(n))
    }

    fn events(ns: &[u32]) -> Vec<(u128, String)> {
        ns.iter()
            .map(|&n| (uuid::Uuid::parse_str(&id(n)).unwrap().as_u128(), line(n)))
            .collect()
    }

    fn write(w: &mut AgentWriter, ns: &[u32]) -> WriteOutcome {
        let owned = events(ns);
        let batch: Vec<ValidatedEvent> = owned
            .iter()
            .map(|(id, l)| ValidatedEvent {
                id: *id,
                line: Cow::Borrowed(l.as_str()),
            })
            .collect();
        w.write_batch(&batch, b"").unwrap()
    }

    fn lines_of(ns: &[u32]) -> String {
        ns.iter().map(|&n| line(n) + "\n").collect()
    }

    fn read(dir: &Path, name: &str) -> String {
        fs::read_to_string(dir.join(name)).unwrap()
    }

    fn file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn appends_events() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        let mut w = AgentWriter::open(dir.clone(), settings(0, 0)).unwrap();
        assert_eq!(
            write(&mut w, &[1]),
            WriteOutcome {
                stored: 1,
                duplicates: 0
            }
        );
        write(&mut w, &[2, 3]);
        assert_eq!(read(&dir, EVENTS_FILE), lines_of(&[1, 2, 3]));
        // No quarantine file until something is quarantined.
        assert_eq!(file_names(&dir), vec![EVENTS_FILE]);
    }

    #[test]
    fn deduplicates_within_and_across_batches() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        let mut w = AgentWriter::open(dir.clone(), settings(0, 0)).unwrap();
        assert_eq!(
            write(&mut w, &[1, 2, 2]),
            WriteOutcome {
                stored: 2,
                duplicates: 1
            }
        );
        assert_eq!(
            write(&mut w, &[2, 3, 1]),
            WriteOutcome {
                stored: 1,
                duplicates: 2
            }
        );
        assert_eq!(
            write(&mut w, &[1, 2, 3]),
            WriteOutcome {
                stored: 0,
                duplicates: 3
            }
        );
        assert_eq!(read(&dir, EVENTS_FILE), lines_of(&[1, 2, 3]));
    }

    #[test]
    fn dedup_survives_reopen() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        let mut w = AgentWriter::open(dir.clone(), settings(0, 0)).unwrap();
        write(&mut w, &[1, 2, 3]);
        drop(w);
        // A new process gets the retry of a batch whose ack was lost.
        let mut w = AgentWriter::open(dir.clone(), settings(0, 0)).unwrap();
        assert_eq!(
            write(&mut w, &[1, 2, 3]),
            WriteOutcome {
                stored: 0,
                duplicates: 3
            }
        );
        assert_eq!(
            write(&mut w, &[3, 4]),
            WriteOutcome {
                stored: 1,
                duplicates: 1
            }
        );
        assert_eq!(read(&dir, EVENTS_FILE), lines_of(&[1, 2, 3, 4]));
    }

    #[test]
    fn retry_after_crash_mid_write_stores_only_missing_events() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        fs::create_dir_all(&dir).unwrap();
        // A crash while writing batch [1, 2, 3] left events 1 and 2 and part of 3.
        let partial = format!("{}{}", lines_of(&[1, 2]), &line(3)[..10]);
        fs::write(dir.join(EVENTS_FILE), partial).unwrap();
        let mut w = AgentWriter::open(dir.clone(), settings(0, 0)).unwrap();
        assert_eq!(
            write(&mut w, &[1, 2, 3]),
            WriteOutcome {
                stored: 1,
                duplicates: 2
            }
        );
        assert_eq!(read(&dir, EVENTS_FILE), lines_of(&[1, 2, 3]));
    }

    #[test]
    fn window_is_rebuilt_from_rotated_files_too() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        let one = line(1).len() as u64 + 1;
        let mut w = AgentWriter::open(dir.clone(), settings(2 * one, 0)).unwrap();
        write(&mut w, &[1, 2]);
        write(&mut w, &[3, 4]); // rotates: [1, 2] -> events.jsonl.1
        write(&mut w, &[5]); // rotates: [3, 4] -> events.jsonl.2
        drop(w);
        let mut w = AgentWriter::open(dir.clone(), settings(2 * one, 0)).unwrap();
        assert_eq!(
            write(&mut w, &[1, 3, 5, 6]),
            WriteOutcome {
                stored: 1,
                duplicates: 3
            }
        );
    }

    #[test]
    fn seeding_respects_the_read_budget() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(EVENTS_FILE), lines_of(&[1, 2, 3, 4])).unwrap();
        let mut window = IdWindow::new(100);
        // Room for a little more than one line: only the newest id fits.
        seed_window(&dir, &mut window, line(4).len() as u64 + 5).unwrap();
        assert_eq!(window.len(), 1);
        assert!(window.contains(uuid::Uuid::parse_str(&id(4)).unwrap().as_u128()));
    }

    #[test]
    fn window_is_bounded_and_can_be_disabled() {
        let tmp = TempDir::new().unwrap();
        let mut s = settings(0, 0);
        s.dedup_window = 3;
        let mut w = AgentWriter::open(tmp.path().join("a"), s.clone()).unwrap();
        write(&mut w, &[1, 2, 3, 4, 5]);
        assert_eq!(w.window.len(), 3);
        // 1 fell out of the window, 5 did not.
        assert_eq!(
            write(&mut w, &[1, 5]),
            WriteOutcome {
                stored: 1,
                duplicates: 1
            }
        );

        s.dedup_window = 0;
        let mut w = AgentWriter::open(tmp.path().join("b"), s).unwrap();
        assert_eq!(
            write(&mut w, &[1, 1]),
            WriteOutcome {
                stored: 2,
                duplicates: 0
            }
        );
    }

    #[test]
    fn quarantine_goes_to_its_own_file() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        let mut w = AgentWriter::open(dir.clone(), settings(0, 0)).unwrap();
        let ev = events(&[1]);
        let batch = [ValidatedEvent {
            id: ev[0].0,
            line: Cow::Borrowed(ev[0].1.as_str()),
        }];
        let out = w.write_batch(&batch, b"{\"q\":1}\n{\"q\":2}\n").unwrap();
        assert_eq!(
            out,
            WriteOutcome {
                stored: 1,
                duplicates: 0
            }
        );
        w.write_batch(&[], b"{\"q\":3}\n").unwrap();
        assert_eq!(read(&dir, EVENTS_FILE), lines_of(&[1]));
        assert_eq!(
            read(&dir, QUARANTINE_FILE),
            "{\"q\":1}\n{\"q\":2}\n{\"q\":3}\n"
        );
        // Quarantined lines never enter the duplicate-suppression window.
        assert_eq!(w.window.len(), 1);
    }

    #[test]
    fn rotation_matches_sensor_naming() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        let one = line(1).len() as u64 + 1;
        let mut w = AgentWriter::open(dir.clone(), settings(2 * one, 0)).unwrap();
        write(&mut w, &[1]);
        write(&mut w, &[2]); // exactly at the limit
        write(&mut w, &[3]); // would exceed -> rotate first
        write(&mut w, &[4]);
        write(&mut w, &[5]); // rotates again
        assert_eq!(read(&dir, "events.jsonl.1"), lines_of(&[1, 2]));
        assert_eq!(read(&dir, "events.jsonl.2"), lines_of(&[3, 4]));
        assert_eq!(read(&dir, EVENTS_FILE), lines_of(&[5]));
    }

    #[test]
    fn oversized_batch_goes_to_fresh_file() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        let mut w = AgentWriter::open(dir.clone(), settings(4, 0)).unwrap();
        write(&mut w, &[1, 2]); // empty file: no rotation
        write(&mut w, &[3, 4]);
        assert_eq!(read(&dir, "events.jsonl.1"), lines_of(&[1, 2]));
        assert_eq!(read(&dir, EVENTS_FILE), lines_of(&[3, 4]));
    }

    #[test]
    fn continues_generation_numbering_from_disk() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("events.jsonl.3"), "old\n").unwrap();
        fs::write(dir.join("events.jsonl.3.idx.sqlite"), "").unwrap();
        fs::write(dir.join("events.jsonl.03"), "noncanonical\n").unwrap();
        fs::write(dir.join(EVENTS_FILE), "abc\n").unwrap();
        let mut w = AgentWriter::open(dir.clone(), settings(5, 0)).unwrap();
        write(&mut w, &[1]);
        assert_eq!(read(&dir, "events.jsonl.4"), "abc\n");
        assert_eq!(read(&dir, "events.jsonl.3"), "old\n");
        assert_eq!(read(&dir, EVENTS_FILE), lines_of(&[1]));
    }

    #[test]
    fn prunes_oldest_rotated_files_and_sidecars() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        let one = line(1).len() as u64 + 1;
        let mut w = AgentWriter::open(dir.clone(), settings(one, 2)).unwrap();
        for n in 0..6u32 {
            write(&mut w, &[n]);
            if n == 1 {
                fs::write(dir.join("events.jsonl.1.idx.sqlite"), "").unwrap();
            }
        }
        assert_eq!(
            file_names(&dir),
            vec!["events.jsonl", "events.jsonl.4", "events.jsonl.5"]
        );
    }

    #[test]
    fn truncates_partial_trailing_line_on_open() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(EVENTS_FILE), format!("{}part", lines_of(&[1]))).unwrap();
        let mut w = AgentWriter::open(dir.clone(), settings(0, 0)).unwrap();
        assert_eq!(w.events.size, line(1).len() as u64 + 1);
        write(&mut w, &[2]);
        assert_eq!(read(&dir, EVENTS_FILE), lines_of(&[1, 2]));
    }

    #[test]
    fn truncates_file_without_any_newline() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(EVENTS_FILE), vec![b'x'; 200 * 1024]).unwrap();
        let w = AgentWriter::open(dir.clone(), settings(0, 0)).unwrap();
        assert_eq!(w.events.size, 0);
        assert_eq!(fs::metadata(dir.join(EVENTS_FILE)).unwrap().len(), 0);
    }

    #[test]
    fn finds_newline_across_chunk_boundary() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        fs::create_dir_all(&dir).unwrap();
        let mut content = b"first\n".to_vec();
        content.extend(vec![b'y'; 150 * 1024]);
        fs::write(dir.join(EVENTS_FILE), &content).unwrap();
        let w = AgentWriter::open(dir.clone(), settings(0, 0)).unwrap();
        assert_eq!(w.events.size, 6);
    }

    #[test]
    fn reopens_when_file_is_removed_externally() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        let mut w = AgentWriter::open(dir.clone(), settings(0, 0)).unwrap();
        write(&mut w, &[1]);
        fs::remove_file(dir.join(EVENTS_FILE)).unwrap();
        write(&mut w, &[2]);
        assert_eq!(read(&dir, EVENTS_FILE), lines_of(&[2]));
    }

    #[test]
    fn recreates_agent_directory_removed_while_running() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("agents/a");
        let mut w = AgentWriter::open(dir.clone(), settings(0, 0)).unwrap();
        write(&mut w, &[1]);
        w.write_batch(&[], b"{\"q\":1}\n").unwrap();
        fs::remove_dir_all(&dir).unwrap();
        write(&mut w, &[2]);
        w.write_batch(&[], b"{\"q\":2}\n").unwrap();
        assert_eq!(read(&dir, EVENTS_FILE), lines_of(&[2]));
        assert_eq!(read(&dir, QUARANTINE_FILE), "{\"q\":2}\n");
    }

    #[test]
    fn quarantine_only_batch_after_directory_removal() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("agents/a");
        let mut w = AgentWriter::open(dir.clone(), settings(0, 0)).unwrap();
        write(&mut w, &[1]);
        fs::remove_dir_all(&dir).unwrap();
        // No events in this batch, and the quarantine file was never opened.
        w.write_batch(&[], b"{\"q\":1}\n").unwrap();
        assert_eq!(read(&dir, QUARANTINE_FILE), "{\"q\":1}\n");
    }

    #[test]
    fn writer_is_rebuilt_from_disk_after_an_error() {
        let tmp = TempDir::new().unwrap();
        let store = Store::open(tmp.path(), settings(0, 0)).unwrap();
        let agent: Arc<str> = Arc::from("a");
        let ev = events(&[1]);
        let batch = [ValidatedEvent {
            id: ev[0].0,
            line: Cow::Borrowed(ev[0].1.as_str()),
        }];
        store
            .with_writer(&agent, |w| w.write_batch(&batch, b""))
            .unwrap();
        let err = store
            .with_writer(&agent, |_| Err::<(), _>(io::Error::other("boom")))
            .unwrap_err();
        assert_eq!(err.to_string(), "boom");
        // The next call reopens the writer; its window comes back from disk.
        let out = store
            .with_writer(&agent, |w| w.write_batch(&batch, b""))
            .unwrap();
        assert_eq!(
            out,
            WriteOutcome {
                stored: 0,
                duplicates: 1
            }
        );
    }

    #[test]
    fn low_disk_rotation_frees_space_before_the_check() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        let one = line(1).len() as u64 + 1;
        let mut s = settings(2 * one, 2);
        // Room for exactly 6 lines plus a reserve of one line.
        s.min_free_bytes = one;
        s.free_space = small_disk(tmp.path().to_path_buf(), 7 * one);
        let mut w = AgentWriter::open(dir.clone(), s).unwrap();
        // Two rotated generations plus a full active file: the disk is full.
        for n in [1, 2, 3, 4, 5, 6] {
            write(&mut w, &[n]);
        }
        assert_eq!(tree_size(tmp.path()), 6 * one);
        // This write rotates, which prunes events.jsonl.1 (events 1, 2):
        // accepted, not refused.
        assert_eq!(
            write(&mut w, &[7]),
            WriteOutcome {
                stored: 1,
                duplicates: 0
            }
        );
        assert_eq!(
            file_names(&dir),
            vec!["events.jsonl", "events.jsonl.2", "events.jsonl.3"]
        );
    }

    #[test]
    fn low_disk_at_retention_limit_drops_the_oldest_generation_early() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        let one = line(1).len() as u64 + 1;
        let mut s = settings(3 * one, 2);
        s.min_free_bytes = one;
        s.free_space = small_disk(tmp.path().to_path_buf(), 8 * one);
        let mut w = AgentWriter::open(dir.clone(), s).unwrap();
        // .1 = [1,2,3], .2 = [4,5,6], active = [7]: at the limit, 1 line free.
        for n in 1..=7 {
            write(&mut w, &[n]);
        }
        // No rotation is due, but waiting for one would block forever.
        assert_eq!(
            write(&mut w, &[8]),
            WriteOutcome {
                stored: 1,
                duplicates: 0
            }
        );
        assert_eq!(file_names(&dir), vec!["events.jsonl", "events.jsonl.2"]);
        assert_eq!(read(&dir, EVENTS_FILE), lines_of(&[7, 8]));
    }

    #[test]
    fn low_disk_without_reclaimable_data_is_refused_and_writer_kept() {
        let tmp = TempDir::new().unwrap();
        let store_settings = {
            let mut s = settings(0, 50);
            s.min_free_bytes = 1;
            s.free_space = FreeSpace::new(|_| Ok(0));
            s
        };
        let store = Store::open(tmp.path(), store_settings).unwrap();
        let agent: Arc<str> = Arc::from("a");
        let ev = events(&[1]);
        let batch = [ValidatedEvent {
            id: ev[0].0,
            line: Cow::Borrowed(ev[0].1.as_str()),
        }];
        let err = store
            .with_writer(&agent, |w| w.write_batch(&batch, b"{\"q\":1}\n"))
            .unwrap_err();
        assert!(is_low_disk(&err), "{err}");
        assert_eq!(err.kind(), io::ErrorKind::StorageFull);
        assert_eq!(read(&tmp.path().join("agents/a"), EVENTS_FILE), "");
        assert!(
            !tmp.path().join("agents/a").join(QUARANTINE_FILE).exists()
                || read(&tmp.path().join("agents/a"), QUARANTINE_FILE).is_empty()
        );
        // The writer was kept (no re-open storm under sustained disk pressure).
        let slot = store.writers.lock().unwrap().get(&agent).unwrap().clone();
        assert!(slot.lock().unwrap().is_some());
    }

    #[test]
    fn lowered_retention_is_applied_under_disk_pressure() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("a");
        let one = line(1).len() as u64 + 1;
        let mut w = AgentWriter::open(dir.clone(), settings(one, 10)).unwrap();
        for n in 1..=5 {
            write(&mut w, &[n]); // .1 .. .4 plus the active file
        }
        drop(w);
        // Restart with a lower limit on a full disk.
        let mut s = settings(one, 2);
        s.min_free_bytes = one;
        s.free_space = small_disk(tmp.path().to_path_buf(), 5 * one);
        let mut w = AgentWriter::open(dir.clone(), s).unwrap();
        assert_eq!(
            write(&mut w, &[6]),
            WriteOutcome {
                stored: 1,
                duplicates: 0
            }
        );
        let names = file_names(&dir);
        assert_eq!(names.len(), 3, "{names:?}");
    }

    #[test]
    fn free_space_probe_errors_do_not_block_writes() {
        let tmp = TempDir::new().unwrap();
        let mut s = settings(0, 0);
        s.min_free_bytes = 1;
        s.free_space = FreeSpace::new(|_| Err(io::Error::other("statvfs failed")));
        let mut w = AgentWriter::open(tmp.path().join("a"), s).unwrap();
        assert_eq!(
            write(&mut w, &[1]),
            WriteOutcome {
                stored: 1,
                duplicates: 0
            }
        );
    }

    #[test]
    fn extracts_ids_from_stored_lines() {
        let uid = uuid::Uuid::parse_str(&id(7)).unwrap().as_u128();
        assert_eq!(event_id(format!("{}\n", line(7)).as_bytes()), Some(uid));
        // Lines not starting with the id are parsed.
        let reordered = format!("{{\"n\":7, \"id\":\"{}\"}}\n", id(7));
        assert_eq!(event_id(reordered.as_bytes()), Some(uid));
        assert_eq!(event_id(b"{\"id\":\"not-a-uuid\"}\n"), None);
        assert_eq!(event_id(b"garbage\n"), None);
        // An id that only starts like a UUID is not mistaken for one.
        let longer = format!("{{\"id\":\"{}x\"}}\n", id(7));
        assert_eq!(event_id(longer.as_bytes()), None);
    }

    #[test]
    fn creates_missing_parent_directories() {
        let tmp = TempDir::new().unwrap();
        let deep = tmp.path().join("x/y/z");
        create_dir_synced(&deep, true).unwrap();
        assert!(deep.is_dir());
        // Idempotent.
        create_dir_synced(&deep, true).unwrap();
        // Never group-writable or accessible by others.
        assert_eq!(fs::metadata(&deep).unwrap().mode() & 0o027, 0);
    }

    #[test]
    fn store_creates_layout_and_locks_data_dir() {
        let tmp = TempDir::new().unwrap();
        let store = Store::open(tmp.path(), settings(0, 0)).unwrap();
        let agent: Arc<str> = Arc::from("lab-ws01");
        let ev = events(&[1]);
        store
            .with_writer(&agent, |w| {
                w.write_batch(
                    &[ValidatedEvent {
                        id: ev[0].0,
                        line: Cow::Borrowed(ev[0].1.as_str()),
                    }],
                    b"",
                )
            })
            .unwrap();
        assert!(tmp.path().join("agents/lab-ws01/events.jsonl").exists());
        assert!(store.last_write_time("lab-ws01").is_some());
        assert!(store.last_write_time("other").is_none());
        assert!(store.available_bytes().unwrap() > 0);
        // The same writer (and its window) is reused.
        let dup = store
            .with_writer(&agent, |w| {
                w.write_batch(
                    &[ValidatedEvent {
                        id: ev[0].0,
                        line: Cow::Borrowed(ev[0].1.as_str()),
                    }],
                    b"",
                )
            })
            .unwrap();
        assert_eq!(dup.duplicates, 1);
        // A second store on the same directory is refused.
        assert!(Store::open(tmp.path(), settings(0, 0)).is_err());
        drop(store);
        assert!(Store::open(tmp.path(), settings(0, 0)).is_ok());
    }
}
