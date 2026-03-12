//! Disk-backed spool for the HTTP sink.
//!
//! When the HTTP endpoint is unreachable, serialized event batches are
//! written to spool files on disk. When the endpoint recovers, spooled
//! files are drained oldest-first and re-sent.
//!
//! Spool files are written atomically via temp-file + rename, so readers
//! never see partial content. Each file contains a JSON array identical
//! to the HTTP POST body (before any gzip compression).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;

/// Manages a directory of spool files with a size cap.
pub struct DiskSpool {
    dir: PathBuf,
    max_bytes: u64,
    current_bytes: u64,
    file_count: u64,
    /// Monotonic counter appended to timestamps to break ties.
    seq: u64,
}

impl DiskSpool {
    /// Open (or create) a spool directory.  Scans for existing `.spool`
    /// files to initialise byte and file counters.
    pub fn open(dir: &Path, max_mb: u64) -> Result<Self> {
        fs::create_dir_all(dir)?;

        let mut current_bytes = 0u64;
        let mut file_count = 0u64;

        for entry in fs::read_dir(dir)?.flatten() {
            if is_spool_file(&entry) {
                current_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
                file_count += 1;
            }
        }

        tracing::info!(
            dir = %dir.display(),
            files = file_count,
            bytes = current_bytes,
            "Spool directory opened"
        );

        Ok(Self {
            dir: dir.to_path_buf(),
            max_bytes: max_mb * 1024 * 1024,
            current_bytes,
            file_count,
            seq: 0,
        })
    }

    /// Write a payload to a new spool file.  Returns `Err` if the spool
    /// size cap would be exceeded.
    pub fn write(&mut self, payload: &[u8]) -> Result<()> {
        let len = payload.len() as u64;
        if self.current_bytes + len > self.max_bytes {
            anyhow::bail!(
                "spool full ({} bytes, cap {} bytes)",
                self.current_bytes,
                self.max_bytes
            );
        }

        let mut tmp = tempfile::NamedTempFile::new_in(&self.dir)?;
        tmp.write_all(payload)?;
        tmp.as_file().sync_all()?;

        let name = self.next_filename();
        let dest = self.dir.join(&name);
        tmp.persist(&dest)?;

        self.current_bytes += len;
        self.file_count += 1;
        Ok(())
    }

    /// Return paths of pending spool files in FIFO order (oldest first).
    pub fn pending(&self) -> Result<Vec<PathBuf>> {
        let mut files: Vec<PathBuf> = Vec::new();

        for entry in fs::read_dir(&self.dir)?.flatten() {
            if is_spool_file(&entry) {
                files.push(entry.path());
            }
        }

        files.sort();
        Ok(files)
    }

    /// Read the contents of a spool file.
    pub fn read(path: &Path) -> Result<Vec<u8>> {
        Ok(fs::read(path)?)
    }

    /// Remove a spool file after successful delivery.
    pub fn remove(&mut self, path: &Path) -> Result<()> {
        let len = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        fs::remove_file(path)?;
        self.current_bytes = self.current_bytes.saturating_sub(len);
        self.file_count = self.file_count.saturating_sub(1);
        Ok(())
    }

    /// Current total bytes on disk.
    pub fn total_bytes(&self) -> u64 {
        self.current_bytes
    }

    /// Number of pending spool files.
    #[allow(dead_code)] // used in tests and health diagnostics
    pub fn file_count(&self) -> u64 {
        self.file_count
    }

    /// Generate a unique, lexicographically-ordered filename.
    fn next_filename(&mut self) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        self.seq += 1;
        format!("{nanos:020}_{:06}.spool", self.seq)
    }
}

fn is_spool_file(entry: &fs::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|n| n.ends_with(".spool"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn write_and_read_roundtrip() {
        let dir = TempDir::new().unwrap();
        let mut spool = DiskSpool::open(dir.path(), 10).unwrap();

        let payload = b"[{\"id\":\"test\"}]";
        spool.write(payload).unwrap();

        let files = spool.pending().unwrap();
        assert_eq!(files.len(), 1);

        let data = DiskSpool::read(&files[0]).unwrap();
        assert_eq!(data, payload);
    }

    #[test]
    fn fifo_ordering() {
        let dir = TempDir::new().unwrap();
        let mut spool = DiskSpool::open(dir.path(), 10).unwrap();

        spool.write(b"first").unwrap();
        spool.write(b"second").unwrap();
        spool.write(b"third").unwrap();

        let files = spool.pending().unwrap();
        assert_eq!(files.len(), 3);

        // Verify ordering by content
        assert_eq!(DiskSpool::read(&files[0]).unwrap(), b"first");
        assert_eq!(DiskSpool::read(&files[1]).unwrap(), b"second");
        assert_eq!(DiskSpool::read(&files[2]).unwrap(), b"third");
    }

    #[test]
    fn remove_decrements_bytes() {
        let dir = TempDir::new().unwrap();
        let mut spool = DiskSpool::open(dir.path(), 10).unwrap();

        let payload = b"hello spool";
        spool.write(payload).unwrap();
        assert_eq!(spool.total_bytes(), payload.len() as u64);
        assert_eq!(spool.file_count(), 1);

        let files = spool.pending().unwrap();
        spool.remove(&files[0]).unwrap();
        assert_eq!(spool.total_bytes(), 0);
        assert_eq!(spool.file_count(), 0);
    }

    #[test]
    fn max_size_enforcement() {
        let dir = TempDir::new().unwrap();
        // 1 MB cap
        let mut spool = DiskSpool::open(dir.path(), 1).unwrap();

        // Write a payload that's under the cap
        let small = vec![0u8; 100];
        spool.write(&small).unwrap();

        // Write a payload that would exceed the cap
        let big = vec![0u8; 1024 * 1024];
        let result = spool.write(&big);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("spool full"));
    }

    #[test]
    fn open_resumes_from_existing_files() {
        let dir = TempDir::new().unwrap();

        // Create spool files manually
        fs::write(dir.path().join("0001.spool"), "aaa").unwrap();
        fs::write(dir.path().join("0002.spool"), "bbbbb").unwrap();

        let spool = DiskSpool::open(dir.path(), 10).unwrap();
        assert_eq!(spool.file_count(), 2);
        assert_eq!(spool.total_bytes(), 8); // 3 + 5
    }

    #[test]
    fn empty_dir() {
        let dir = TempDir::new().unwrap();
        let spool = DiskSpool::open(dir.path(), 10).unwrap();

        assert_eq!(spool.file_count(), 0);
        assert_eq!(spool.total_bytes(), 0);
        assert!(spool.pending().unwrap().is_empty());
    }

    #[test]
    fn non_spool_files_ignored() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("readme.txt"), "not a spool file").unwrap();
        fs::write(dir.path().join("0001.spool"), "real spool").unwrap();

        let spool = DiskSpool::open(dir.path(), 10).unwrap();
        assert_eq!(spool.file_count(), 1);
        assert_eq!(spool.total_bytes(), 10); // "real spool".len()
    }
}
