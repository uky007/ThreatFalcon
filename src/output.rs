use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::Result;

use crate::config::OutputConfig;
use crate::events::ThreatEvent;

/// Writes events as newline-delimited JSON (JSONL) with size-based rotation.
pub struct EventWriter {
    writer: BufWriter<File>,
    bytes_written: u64,
    rotation_bytes: u64,
    base_path: String,
    generation: u32,
}

impl EventWriter {
    pub fn new(config: &OutputConfig) -> Result<Self> {
        let path = config.path.to_string_lossy().to_string();
        let existing_size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let file = open_append(&path)?;
        let generation = find_max_generation(&path);

        Ok(Self {
            writer: BufWriter::new(file),
            bytes_written: existing_size,
            rotation_bytes: config.rotation_size_mb * 1024 * 1024,
            base_path: path,
            generation,
        })
    }

    pub fn write_event(&mut self, event: &ThreatEvent) -> Result<()> {
        let json = serde_json::to_string(event)?;
        let line = format!("{json}\n");
        let len = line.len() as u64;

        // Rotate *before* writing if appending this event would exceed limit
        if self.rotation_bytes > 0
            && self.bytes_written + len >= self.rotation_bytes
        {
            self.rotate()?;
        }

        self.writer.write_all(line.as_bytes())?;
        self.writer.flush()?;
        self.bytes_written += len;

        Ok(())
    }

    /// Rename the current file to `base_path.N` and start a fresh file at
    /// `base_path`.
    fn rotate(&mut self) -> Result<()> {
        // Flush and drop the current writer so we can rename the file
        self.writer.flush()?;

        self.generation += 1;
        let rotated_path =
            format!("{}.{}", self.base_path, self.generation);
        tracing::info!(
            from = %self.base_path,
            to = %rotated_path,
            "Rotating event log"
        );

        fs::rename(&self.base_path, &rotated_path)?;

        let file = open_append(&self.base_path)?;
        self.writer = BufWriter::new(file);
        self.bytes_written = 0;
        Ok(())
    }
}

/// Scan for existing rotated files (`base_path.1`, `.2`, ...) and return the
/// highest generation number found, so the next rotation won't overwrite them.
fn find_max_generation(base_path: &str) -> u32 {
    let parent = Path::new(base_path)
        .parent()
        .unwrap_or(Path::new("."));
    let filename = match Path::new(base_path).file_name().and_then(|n| n.to_str()) {
        Some(f) => f,
        None => return 0,
    };

    let prefix = format!("{filename}.");
    let mut max_gen = 0u32;

    if let Ok(entries) = fs::read_dir(parent) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(suffix) = name.strip_prefix(&prefix) {
                if let Ok(gen) = suffix.parse::<u32>() {
                    max_gen = max_gen.max(gen);
                }
            }
        }
    }

    max_gen
}

fn open_append(path: &str) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(Path::new(path))?;
    Ok(file)
}
