//! Non-destructive logical-byte budget for a single, administrator-owned log family.
//! The directory must be protected: advisory locks are not a tamper boundary.
use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::path::Path;

use crate::events::FileStorageStatus;

pub struct FileStorage {
    // Persistent sidecar: never unlink it on close (another writer may hold it).
    _lock: File,
    pub generation: u32,
    status: FileStorageStatus,
}

pub fn private_options() -> OpenOptions {
    let options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = options;
        options.mode(0o600);
        options
    }
    #[cfg(not(unix))]
    options
}

pub fn regular_or_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => anyhow::ensure!(
            meta.file_type().is_file(),
            "file_storage_unsafe_path: expected regular file: {}",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

pub fn numbered_segment(name: &str, base: &str) -> Option<u32> {
    // Conservative case-folding also covers common case-insensitive macOS and
    // Windows volumes. On case-sensitive volumes, case-only sibling names are
    // deliberately counted too; an administrator must use distinct log families.
    let (name, base) = (name.to_lowercase(), base.to_lowercase());
    let (name, base) = (name.as_str(), base.as_str());
    let suffix = name.strip_prefix(base)?.strip_prefix('.')?;
    let generation = suffix.parse::<u32>().ok()?;
    (generation > 0 && generation.to_string() == suffix).then_some(generation)
}

impl FileStorage {
    pub fn open(path: &Path, limit_bytes: u64) -> Result<Self> {
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("event output requires a UTF-8 file name")?;
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".writer.lock");
        let lock_path = Path::new(&lock_path);
        regular_or_absent(lock_path)?;
        let lock = private_options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .context("cannot open output writer lock")?;
        lock.try_lock()
            .context("file_storage_locked: output already owned or locking unavailable")?;
        anyhow::ensure!(
            lock.metadata()?.len() == 0,
            "file_storage_unsafe_path: writer lock is not empty"
        );

        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // Query the configured active path directly (including filesystem case
        // resolution), rather than relying on directory entry string equality.
        regular_or_absent(path)?;
        let mut total = match fs::symlink_metadata(path) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e.into()),
        };
        let mut generation = 0;
        for entry in fs::read_dir(parent).context("cannot inventory event output directory")? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(segment) = numbered_segment(name, filename) else {
                continue;
            };
            let meta = fs::symlink_metadata(entry.path())?;
            anyhow::ensure!(
                meta.file_type().is_file(),
                "file_storage_unsafe_path: log family contains non-regular file"
            );
            total = total
                .checked_add(meta.len())
                .context("file storage byte count overflow")?;
            generation = generation.max(segment);
        }
        anyhow::ensure!(limit_bytes == 0 || total <= limit_bytes,
            "file_storage_budget_exceeded: existing={total} limit={limit_bytes}; preserve/archive evidence before restart");
        Ok(Self {
            _lock: lock,
            generation,
            status: FileStorageStatus {
                accounted_bytes: total,
                limit_bytes,
                exhausted: false,
            },
        })
    }

    /// Charge BEFORE touching output. A failed/partial write never releases its
    /// reservation in this run. Restart inventories actual lengths again.
    pub fn reserve(&mut self, bytes: u64) -> Result<()> {
        let next = self
            .status
            .accounted_bytes
            .checked_add(bytes)
            .context("file storage byte count overflow")?;
        if self.status.limit_bytes > 0 && next > self.status.limit_bytes {
            self.status.exhausted = true;
            anyhow::bail!(
                "file_storage_budget_exceeded: accounted={} next={} limit={}; no evidence deleted",
                self.status.accounted_bytes,
                bytes,
                self.status.limit_bytes
            );
        }
        self.status.accounted_bytes = next;
        Ok(())
    }

    pub fn status(&self) -> FileStorageStatus {
        self.status.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_is_exact_namespace_and_reservations_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        for name in [
            "events.jsonl",
            "events.jsonl.1",
            "events.jsonl.3",
            "events.jsonl.01",
            "events.jsonl.backup",
            "other.jsonl.2",
        ] {
            fs::write(dir.path().join(name), b"test\n").unwrap();
        }
        let mut storage = FileStorage::open(&path, 20).unwrap();
        assert_eq!(storage.generation, 3);
        assert_eq!(storage.status().accounted_bytes, 15);
        storage.reserve(5).unwrap();
        assert!(storage.reserve(1).is_err());
        assert!(storage.status().exhausted);
        assert_eq!(storage.status().accounted_bytes, 20);
        assert_eq!(fs::read(&path).unwrap(), b"test\n");
    }

    #[test]
    fn unbounded_is_explicit_but_integer_overflow_is_not_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::open(&dir.path().join("events.jsonl"), 0).unwrap();
        storage.reserve(u64::MAX).unwrap();
        assert!(storage.reserve(1).is_err());
    }

    #[test]
    fn nonregular_segments_are_rejected_without_creating_active_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        fs::create_dir(dir.path().join("events.jsonl.1")).unwrap();
        assert!(FileStorage::open(&path, 100).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn segment_names_are_canonical_and_conservatively_case_folded() {
        assert_eq!(
            numbered_segment("events.jsonl.12", "events.jsonl"),
            Some(12)
        );
        for name in [
            "events.jsonl.0",
            "events.jsonl.01",
            "events.jsonl.+1",
            "events.jsonl.4294967296",
            "events.jsonl.backup",
            "other.jsonl.1",
        ] {
            assert_eq!(numbered_segment(name, "events.jsonl"), None);
        }
        assert_eq!(numbered_segment("EVENTS.JSONL.1", "events.jsonl"), Some(1));
    }

    #[cfg(windows)]
    #[test]
    fn windows_inventory_counts_existing_differently_cased_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("EVENTS.JSONL"), b"old\n").unwrap();
        fs::write(dir.path().join("EVENTS.JSONL.3"), b"old\n").unwrap();
        let storage = FileStorage::open(&dir.path().join("events.jsonl"), 8).unwrap();
        assert_eq!(storage.status().accounted_bytes, 8);
        assert_eq!(storage.generation, 3);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_followed_and_new_lock_is_private() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let outside = dir.path().join("do-not-touch");
        fs::write(&outside, b"private").unwrap();
        symlink(&outside, &path).unwrap();
        assert!(FileStorage::open(&path, 100).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"private");
        assert_eq!(
            fs::metadata(dir.path().join("events.jsonl.writer.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        let other = dir.path().join("other.jsonl");
        symlink(&outside, dir.path().join("other.jsonl.writer.lock")).unwrap();
        assert!(FileStorage::open(&other, 100).is_err());
        assert!(!other.exists());
    }
}
