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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::*;
    use tempfile::TempDir;

    fn test_config(dir: &TempDir, rotation_mb: u64) -> OutputConfig {
        OutputConfig {
            path: dir.path().join("events.jsonl"),
            format: crate::config::OutputFormat::JsonLines,
            rotation_size_mb: rotation_mb,
        }
    }

    fn dummy_event() -> ThreatEvent {
        ThreatEvent::new(
            "TEST",
            EventSource::Sensor,
            EventCategory::Health,
            Severity::Info,
            EventData::SensorHealth {
                uptime_secs: 1,
                events_total: 0,
                events_dropped: 0,
                collectors: vec![],
            },
        )
    }

    #[test]
    fn write_single_event() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir, 100);
        let mut writer = EventWriter::new(&config).unwrap();

        writer.write_event(&dummy_event()).unwrap();

        let content = fs::read_to_string(dir.path().join("events.jsonl")).unwrap();
        assert!(content.contains("\"SensorHealth\""));
        assert!(content.ends_with('\n'));
    }

    #[test]
    fn rotation_creates_numbered_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.jsonl");
        let evt = dummy_event();
        let line_len = serde_json::to_string(&evt).unwrap().len() as u64 + 1;

        // Set rotation so 2 events fit but the 3rd triggers rotation
        let rotation_bytes = line_len * 2 + 1;
        let file = open_append(&path.to_string_lossy()).unwrap();
        let mut writer = EventWriter {
            writer: BufWriter::new(file),
            bytes_written: 0,
            rotation_bytes,
            base_path: path.to_string_lossy().to_string(),
            generation: 0,
        };

        // Write 3 events: first 2 go to the original file, 3rd triggers rotation
        for _ in 0..3 {
            writer.write_event(&evt).unwrap();
        }

        // The rotated file should exist with the first 2 events
        let rotated = dir.path().join("events.jsonl.1");
        assert!(rotated.exists());
        let rotated_lines = fs::read_to_string(&rotated)
            .unwrap()
            .lines()
            .count();
        assert_eq!(rotated_lines, 2);
        // Active file has the 3rd event
        let active_lines = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .count();
        assert_eq!(active_lines, 1);
    }

    #[test]
    fn rotation_disabled_when_zero() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir, 0);
        let mut writer = EventWriter::new(&config).unwrap();

        // Write many events — no rotation should happen
        let evt = dummy_event();
        for _ in 0..50 {
            writer.write_event(&evt).unwrap();
        }

        // Only the active file should exist
        let files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn generation_continues_from_existing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("events.jsonl");

        // Create fake rotated files
        fs::write(dir.path().join("events.jsonl.1"), "old1\n").unwrap();
        fs::write(dir.path().join("events.jsonl.3"), "old3\n").unwrap();
        fs::write(&base, "").unwrap();

        let gen = find_max_generation(&base.to_string_lossy());
        assert_eq!(gen, 3);

        // New rotation should use generation 4
        let file = open_append(&base.to_string_lossy()).unwrap();
        let mut writer = EventWriter {
            writer: BufWriter::new(file),
            bytes_written: 0,
            rotation_bytes: 10, // tiny
            base_path: base.to_string_lossy().to_string(),
            generation: gen,
        };

        let evt = dummy_event();
        writer.write_event(&evt).unwrap();
        writer.write_event(&evt).unwrap();

        assert!(dir.path().join("events.jsonl.4").exists());
        // Old files still intact
        assert!(dir.path().join("events.jsonl.1").exists());
        assert!(dir.path().join("events.jsonl.3").exists());
    }

    #[test]
    fn bytes_written_tracks_correctly() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir, 100);
        let mut writer = EventWriter::new(&config).unwrap();

        assert_eq!(writer.bytes_written, 0);

        let evt = dummy_event();
        let expected_len = serde_json::to_string(&evt).unwrap().len() as u64 + 1;

        writer.write_event(&evt).unwrap();
        assert_eq!(writer.bytes_written, expected_len);

        writer.write_event(&evt).unwrap();
        assert_eq!(writer.bytes_written, expected_len * 2);
    }

    #[test]
    fn existing_file_size_captured() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.jsonl");
        fs::write(&path, "existing content\n").unwrap();
        let existing_len = fs::metadata(&path).unwrap().len();

        let config = OutputConfig {
            path: path.clone(),
            format: crate::config::OutputFormat::JsonLines,
            rotation_size_mb: 100,
        };
        let writer = EventWriter::new(&config).unwrap();
        assert_eq!(writer.bytes_written, existing_len);
    }

    #[test]
    fn multiple_rotations_increment_generation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.jsonl");
        let file = open_append(&path.to_string_lossy()).unwrap();
        let mut writer = EventWriter {
            writer: BufWriter::new(file),
            bytes_written: 0,
            rotation_bytes: 100,
            base_path: path.to_string_lossy().to_string(),
            generation: 0,
        };

        let evt = dummy_event();
        // Write enough for multiple rotations
        for _ in 0..50 {
            writer.write_event(&evt).unwrap();
        }

        assert!(writer.generation >= 2);
        assert!(dir.path().join("events.jsonl.1").exists());
        assert!(dir.path().join("events.jsonl.2").exists());
    }

    #[test]
    fn rotated_file_contains_valid_jsonl() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.jsonl");
        let file = open_append(&path.to_string_lossy()).unwrap();
        let mut writer = EventWriter {
            writer: BufWriter::new(file),
            bytes_written: 0,
            rotation_bytes: 200,
            base_path: path.to_string_lossy().to_string(),
            generation: 0,
        };

        let evt = dummy_event();
        for _ in 0..10 {
            writer.write_event(&evt).unwrap();
        }

        // Read the first rotated file and verify every line is valid JSON
        let rotated = fs::read_to_string(dir.path().join("events.jsonl.1")).unwrap();
        for line in rotated.lines() {
            let parsed: ThreatEvent = serde_json::from_str(line).unwrap();
            assert_eq!(parsed.hostname, "TEST");
        }
    }
}
