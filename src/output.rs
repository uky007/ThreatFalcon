use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;

use crate::config::{OutputConfig, SinkType};
use crate::events::ThreatEvent;

// ---------------------------------------------------------------------------
// Sink trait
// ---------------------------------------------------------------------------

/// Abstraction for event output destinations.
#[async_trait]
pub trait Sink: Send {
    #[allow(dead_code)]
    fn name(&self) -> &str;
    async fn send(&mut self, event: &ThreatEvent) -> Result<()>;
    async fn flush(&mut self) -> Result<()>;
    /// Total number of events this sink failed to deliver.
    fn dropped_events(&self) -> u64;
}

/// Construct the appropriate sink from config.
pub fn create_sink(config: &OutputConfig) -> Result<Box<dyn Sink>> {
    match config.sink_type {
        SinkType::File => Ok(Box::new(FileSink::new(config)?)),
        SinkType::Stdout => Ok(Box::new(StdoutSink::new(config.pretty))),
        SinkType::Http => Ok(Box::new(HttpSink::new(config)?))
    }
}

// ---------------------------------------------------------------------------
// FileSink — JSONL with size-based rotation
// ---------------------------------------------------------------------------

pub struct FileSink {
    writer: BufWriter<File>,
    bytes_written: u64,
    rotation_bytes: u64,
    base_path: String,
    generation: u32,
    events_dropped: u64,
}

impl FileSink {
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
            events_dropped: 0,
        })
    }

    fn rotate(&mut self) -> Result<()> {
        self.writer.flush()?;

        self.generation += 1;
        let rotated_path = format!("{}.{}", self.base_path, self.generation);
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

#[async_trait]
impl Sink for FileSink {
    fn name(&self) -> &str {
        "file"
    }

    async fn send(&mut self, event: &ThreatEvent) -> Result<()> {
        let json = serde_json::to_string(event)?;
        let line = format!("{json}\n");
        let len = line.len() as u64;

        if self.rotation_bytes > 0 && self.bytes_written + len >= self.rotation_bytes {
            if let Err(e) = self.rotate() {
                self.events_dropped += 1;
                return Err(e);
            }
        }

        if let Err(e) = self.writer.write_all(line.as_bytes()).and_then(|_| self.writer.flush()) {
            self.events_dropped += 1;
            return Err(e.into());
        }
        self.bytes_written += len;

        Ok(())
    }

    async fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    fn dropped_events(&self) -> u64 {
        self.events_dropped
    }
}

// ---------------------------------------------------------------------------
// StdoutSink — JSONL to stdout (or injected writer for tests)
// ---------------------------------------------------------------------------

pub struct StdoutSink {
    writer: Box<dyn Write + Send>,
    pretty: bool,
    events_dropped: u64,
}

impl StdoutSink {
    pub fn new(pretty: bool) -> Self {
        Self {
            writer: Box::new(std::io::stdout()),
            pretty,
            events_dropped: 0,
        }
    }
}

#[async_trait]
impl Sink for StdoutSink {
    fn name(&self) -> &str {
        "stdout"
    }

    async fn send(&mut self, event: &ThreatEvent) -> Result<()> {
        let json = if self.pretty {
            serde_json::to_string_pretty(event)?
        } else {
            serde_json::to_string(event)?
        };
        let line = format!("{json}\n");
        if let Err(e) = self.writer.write_all(line.as_bytes()).and_then(|_| self.writer.flush()) {
            self.events_dropped += 1;
            return Err(e.into());
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    fn dropped_events(&self) -> u64 {
        self.events_dropped
    }
}

// ---------------------------------------------------------------------------
// HttpSink — batched JSON array POST with retry
// ---------------------------------------------------------------------------

pub struct HttpSink {
    client: reqwest::Client,
    url: String,
    batch_size: usize,
    buffer: Vec<String>,
    events_dropped: u64,
    retry_count: u32,
    retry_backoff_ms: u64,
    gzip: bool,
    bearer_token: Option<String>,
    headers: HashMap<String, String>,
}

impl HttpSink {
    pub fn new(config: &OutputConfig) -> Result<Self> {
        let url = config
            .url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HTTP sink requires 'url' in [output] config"))?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()?;
        Ok(Self {
            client,
            url: url.clone(),
            batch_size: config.batch_size.max(1),
            buffer: Vec::with_capacity(config.batch_size),
            events_dropped: 0,
            retry_count: config.retry_count.max(1),
            retry_backoff_ms: config.retry_backoff_ms,
            gzip: config.gzip,
            bearer_token: config.bearer_token.clone(),
            headers: config.headers.clone(),
        })
    }

    async fn flush_buffer(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let payload = format!("[{}]", self.buffer.join(","));

        // Optionally gzip-compress the body
        let (body, content_encoding) = if self.gzip {
            use std::io::Write as _;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(payload.as_bytes())?;
            (encoder.finish()?, Some("gzip"))
        } else {
            (payload.into_bytes(), None)
        };

        let mut last_err = None;

        for attempt in 0..self.retry_count as u64 {
            let mut req = self
                .client
                .post(&self.url)
                .header("Content-Type", "application/json")
                .body(body.clone());

            if let Some(encoding) = content_encoding {
                req = req.header("Content-Encoding", encoding);
            }
            if let Some(ref token) = self.bearer_token {
                req = req.bearer_auth(token);
            }
            for (k, v) in &self.headers {
                req = req.header(k, v);
            }

            match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    self.buffer.clear();
                    return Ok(());
                }
                Ok(resp) => {
                    last_err = Some(anyhow::anyhow!(
                        "HTTP POST to {} returned {}",
                        self.url,
                        resp.status()
                    ));
                }
                Err(e) => {
                    last_err = Some(e.into());
                }
            }
            if attempt < (self.retry_count as u64 - 1) {
                tokio::time::sleep(std::time::Duration::from_millis(
                    self.retry_backoff_ms * (attempt + 1),
                ))
                .await;
            }
        }

        // Discard buffer to prevent unbounded growth
        let count = self.buffer.len() as u64;
        self.buffer.clear();
        self.events_dropped += count;
        tracing::warn!(
            events_lost = count,
            retry_count = self.retry_count,
            "HTTP sink discarded events after failed attempts"
        );
        Err(last_err.unwrap())
    }
}

#[async_trait]
impl Sink for HttpSink {
    fn name(&self) -> &str {
        "http"
    }

    async fn send(&mut self, event: &ThreatEvent) -> Result<()> {
        let json = serde_json::to_string(event)?;
        self.buffer.push(json);
        if self.buffer.len() >= self.batch_size {
            self.flush_buffer().await?;
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<()> {
        self.flush_buffer().await
    }

    fn dropped_events(&self) -> u64 {
        self.events_dropped
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

    fn file_config(dir: &TempDir, rotation_mb: u64) -> OutputConfig {
        OutputConfig {
            sink_type: SinkType::File,
            path: dir.path().join("events.jsonl"),
            rotation_size_mb: rotation_mb,
            ..OutputConfig::default()
        }
    }

    fn test_agent() -> AgentInfo {
        AgentInfo {
            hostname: "TEST".into(),
            agent_id: uuid::Uuid::nil(),
        }
    }

    fn dummy_event() -> ThreatEvent {
        ThreatEvent::new(
            &test_agent(),
            EventSource::Sensor,
            EventCategory::Health,
            Severity::Info,
            EventData::SensorHealth {
                uptime_secs: 1,
                events_total: 0,
                events_dropped: 0,
                collectors: vec![],
                sink: None,
            },
        )
    }

    // --- FileSink tests (adapted from EventWriter) ---------------------------

    #[tokio::test]
    async fn file_write_single_event() {
        let dir = TempDir::new().unwrap();
        let config = file_config(&dir, 100);
        let mut sink = FileSink::new(&config).unwrap();

        sink.send(&dummy_event()).await.unwrap();

        let content = fs::read_to_string(dir.path().join("events.jsonl")).unwrap();
        assert!(content.contains("\"SensorHealth\""));
        assert!(content.ends_with('\n'));
    }

    #[tokio::test]
    async fn file_rotation_creates_numbered_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.jsonl");
        let evt = dummy_event();
        let line_len = serde_json::to_string(&evt).unwrap().len() as u64 + 1;

        let rotation_bytes = line_len * 2 + 1;
        let file = open_append(&path.to_string_lossy()).unwrap();
        let mut sink = FileSink {
            writer: BufWriter::new(file),
            bytes_written: 0,
            rotation_bytes,
            base_path: path.to_string_lossy().to_string(),
            generation: 0,
            events_dropped: 0,
        };

        for _ in 0..3 {
            sink.send(&evt).await.unwrap();
        }

        let rotated = dir.path().join("events.jsonl.1");
        assert!(rotated.exists());
        let rotated_lines = fs::read_to_string(&rotated).unwrap().lines().count();
        assert_eq!(rotated_lines, 2);
        let active_lines = fs::read_to_string(&path).unwrap().lines().count();
        assert_eq!(active_lines, 1);
    }

    #[tokio::test]
    async fn file_rotation_disabled_when_zero() {
        let dir = TempDir::new().unwrap();
        let config = file_config(&dir, 0);
        let mut sink = FileSink::new(&config).unwrap();

        let evt = dummy_event();
        for _ in 0..50 {
            sink.send(&evt).await.unwrap();
        }

        let files: Vec<_> = fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert_eq!(files.len(), 1);
    }

    #[tokio::test]
    async fn file_generation_continues_from_existing() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("events.jsonl");

        fs::write(dir.path().join("events.jsonl.1"), "old1\n").unwrap();
        fs::write(dir.path().join("events.jsonl.3"), "old3\n").unwrap();
        fs::write(&base, "").unwrap();

        let gen = find_max_generation(&base.to_string_lossy());
        assert_eq!(gen, 3);

        let file = open_append(&base.to_string_lossy()).unwrap();
        let mut sink = FileSink {
            writer: BufWriter::new(file),
            bytes_written: 0,
            rotation_bytes: 10,
            base_path: base.to_string_lossy().to_string(),
            generation: gen,
            events_dropped: 0,
        };

        let evt = dummy_event();
        sink.send(&evt).await.unwrap();
        sink.send(&evt).await.unwrap();

        assert!(dir.path().join("events.jsonl.4").exists());
        assert!(dir.path().join("events.jsonl.1").exists());
        assert!(dir.path().join("events.jsonl.3").exists());
    }

    #[tokio::test]
    async fn file_bytes_written_tracks_correctly() {
        let dir = TempDir::new().unwrap();
        let config = file_config(&dir, 100);
        let mut sink = FileSink::new(&config).unwrap();

        assert_eq!(sink.bytes_written, 0);

        let evt = dummy_event();
        let expected_len = serde_json::to_string(&evt).unwrap().len() as u64 + 1;

        sink.send(&evt).await.unwrap();
        assert_eq!(sink.bytes_written, expected_len);

        sink.send(&evt).await.unwrap();
        assert_eq!(sink.bytes_written, expected_len * 2);
    }

    #[tokio::test]
    async fn file_existing_size_captured() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.jsonl");
        fs::write(&path, "existing content\n").unwrap();
        let existing_len = fs::metadata(&path).unwrap().len();

        let config = OutputConfig {
            sink_type: SinkType::File,
            path: path.clone(),
            rotation_size_mb: 100,
            ..OutputConfig::default()
        };
        let sink = FileSink::new(&config).unwrap();
        assert_eq!(sink.bytes_written, existing_len);
    }

    #[tokio::test]
    async fn file_multiple_rotations_increment_generation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.jsonl");
        let file = open_append(&path.to_string_lossy()).unwrap();
        let mut sink = FileSink {
            writer: BufWriter::new(file),
            bytes_written: 0,
            rotation_bytes: 100,
            base_path: path.to_string_lossy().to_string(),
            generation: 0,
            events_dropped: 0,
        };

        let evt = dummy_event();
        for _ in 0..50 {
            sink.send(&evt).await.unwrap();
        }

        assert!(sink.generation >= 2);
        assert!(dir.path().join("events.jsonl.1").exists());
        assert!(dir.path().join("events.jsonl.2").exists());
    }

    #[tokio::test]
    async fn file_rotated_contains_valid_jsonl() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events.jsonl");
        let file = open_append(&path.to_string_lossy()).unwrap();
        let mut sink = FileSink {
            writer: BufWriter::new(file),
            bytes_written: 0,
            rotation_bytes: 200,
            base_path: path.to_string_lossy().to_string(),
            generation: 0,
            events_dropped: 0,
        };

        let evt = dummy_event();
        for _ in 0..10 {
            sink.send(&evt).await.unwrap();
        }

        let rotated = fs::read_to_string(dir.path().join("events.jsonl.1")).unwrap();
        for line in rotated.lines() {
            let parsed: ThreatEvent = serde_json::from_str(line).unwrap();
            assert_eq!(parsed.hostname, "TEST");
        }
    }

    // --- StdoutSink tests ----------------------------------------------------

    /// Test writer that captures output into a shared buffer.
    struct TestWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn stdout_sink_writes_jsonl() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut sink = StdoutSink {
            writer: Box::new(TestWriter(buf.clone())),
            pretty: false,
            events_dropped: 0,
        };

        sink.send(&dummy_event()).await.unwrap();

        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(output.contains("\"SensorHealth\""));
        assert!(output.ends_with('\n'));
        // Compact JSONL = single line per event
        assert_eq!(output.lines().count(), 1);
    }

    #[tokio::test]
    async fn stdout_sink_pretty_prints() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut sink = StdoutSink {
            writer: Box::new(TestWriter(buf.clone())),
            pretty: true,
            events_dropped: 0,
        };

        sink.send(&dummy_event()).await.unwrap();

        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(output.contains("\"SensorHealth\""));
        // Pretty JSON spans multiple lines
        assert!(output.lines().count() > 1);
    }

    #[tokio::test]
    async fn stdout_sink_flush_succeeds() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut sink = StdoutSink {
            writer: Box::new(TestWriter(buf.clone())),
            pretty: false,
            events_dropped: 0,
        };
        sink.flush().await.unwrap();
    }

    // --- HttpSink tests ------------------------------------------------------

    fn http_config(url: &str, batch_size: usize) -> OutputConfig {
        OutputConfig {
            sink_type: SinkType::Http,
            url: Some(url.to_string()),
            batch_size,
            timeout_secs: 10,
            ..OutputConfig::default()
        }
    }

    #[tokio::test]
    async fn http_sink_sends_batch() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let config = http_config(&format!("{}/events", server.url()), 2);
        let mut sink = HttpSink::new(&config).unwrap();

        let evt = dummy_event();
        sink.send(&evt).await.unwrap(); // buffered, no POST yet
        assert_eq!(sink.buffer.len(), 1);

        sink.send(&evt).await.unwrap(); // triggers batch POST
        assert_eq!(sink.buffer.len(), 0);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn http_sink_flush_sends_partial() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let config = http_config(&format!("{}/events", server.url()), 100);
        let mut sink = HttpSink::new(&config).unwrap();

        sink.send(&dummy_event()).await.unwrap();
        assert_eq!(sink.buffer.len(), 1);

        sink.flush().await.unwrap(); // force send
        assert_eq!(sink.buffer.len(), 0);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn http_sink_body_is_json_array() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .with_status(200)
            .match_header("Content-Type", "application/json")
            .expect(1)
            .create_async()
            .await;

        let config = http_config(&format!("{}/events", server.url()), 1);
        let mut sink = HttpSink::new(&config).unwrap();

        sink.send(&dummy_event()).await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn http_sink_retries_on_failure() {
        let mut server = mockito::Server::new_async().await;
        // Fail twice, succeed on third
        let mock = server
            .mock("POST", "/events")
            .with_status(500)
            .expect(2)
            .create_async()
            .await;
        let mock_ok = server
            .mock("POST", "/events")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let config = http_config(&format!("{}/events", server.url()), 1);
        let mut sink = HttpSink::new(&config).unwrap();

        sink.send(&dummy_event()).await.unwrap();

        mock.assert_async().await;
        mock_ok.assert_async().await;
    }

    #[tokio::test]
    async fn http_sink_errors_after_retries() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .with_status(500)
            .expect(3) // all 3 attempts fail
            .create_async()
            .await;

        let config = http_config(&format!("{}/events", server.url()), 1);
        let mut sink = HttpSink::new(&config).unwrap();

        let result = sink.send(&dummy_event()).await;
        assert!(result.is_err());
        assert_eq!(sink.buffer.len(), 0);
        assert_eq!(sink.dropped_events(), 1);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn http_sink_dropped_events_tracks_batch_count() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/events")
            .with_status(500)
            .expect_at_least(3)
            .create_async()
            .await;

        let mut config = http_config(&format!("{}/events", server.url()), 5);
        config.timeout_secs = 1;
        let mut sink = HttpSink::new(&config).unwrap();

        assert_eq!(sink.dropped_events(), 0);

        for _ in 0..5 {
            let _ = sink.send(&dummy_event()).await;
        }

        assert_eq!(sink.dropped_events(), 5);
    }

    #[tokio::test]
    async fn http_sink_empty_flush_is_noop() {
        let config = http_config("http://unused.example.com/events", 10);
        let mut sink = HttpSink::new(&config).unwrap();
        sink.flush().await.unwrap();
    }

    #[tokio::test]
    async fn http_sink_bearer_token() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .match_header("Authorization", "Bearer test-token-123")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let mut config = http_config(&format!("{}/events", server.url()), 1);
        config.bearer_token = Some("test-token-123".into());
        let mut sink = HttpSink::new(&config).unwrap();

        sink.send(&dummy_event()).await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn http_sink_custom_headers() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .match_header("X-Sensor-Id", "sensor-001")
            .match_header("X-Api-Key", "key-abc")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let mut config = http_config(&format!("{}/events", server.url()), 1);
        config.headers.insert("X-Sensor-Id".into(), "sensor-001".into());
        config.headers.insert("X-Api-Key".into(), "key-abc".into());
        let mut sink = HttpSink::new(&config).unwrap();

        sink.send(&dummy_event()).await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn http_sink_gzip_sends_compressed() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .match_header("Content-Encoding", "gzip")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let mut config = http_config(&format!("{}/events", server.url()), 1);
        config.gzip = true;
        let mut sink = HttpSink::new(&config).unwrap();

        sink.send(&dummy_event()).await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn http_sink_configurable_retry_count() {
        let mut server = mockito::Server::new_async().await;
        // With retry_count=2, only 2 attempts (not the default 3)
        let mock = server
            .mock("POST", "/events")
            .with_status(500)
            .expect(2)
            .create_async()
            .await;

        let mut config = http_config(&format!("{}/events", server.url()), 1);
        config.retry_count = 2;
        config.retry_backoff_ms = 10; // fast for tests
        let mut sink = HttpSink::new(&config).unwrap();

        let result = sink.send(&dummy_event()).await;
        assert!(result.is_err());
        assert_eq!(sink.dropped_events(), 1);

        mock.assert_async().await;
    }

    // --- create_sink factory tests -------------------------------------------

    #[tokio::test]
    async fn create_sink_file() {
        let dir = TempDir::new().unwrap();
        let config = file_config(&dir, 100);
        let sink = create_sink(&config).unwrap();
        assert_eq!(sink.name(), "file");
    }

    #[test]
    fn create_sink_stdout() {
        let config = OutputConfig {
            sink_type: SinkType::Stdout,
            ..OutputConfig::default()
        };
        let sink = create_sink(&config).unwrap();
        assert_eq!(sink.name(), "stdout");
    }

    #[test]
    fn create_sink_http() {
        let config = OutputConfig {
            sink_type: SinkType::Http,
            url: Some("http://localhost:8080/events".into()),
            ..OutputConfig::default()
        };
        let sink = create_sink(&config).unwrap();
        assert_eq!(sink.name(), "http");
    }

    #[test]
    fn create_sink_http_requires_url() {
        let config = OutputConfig {
            sink_type: SinkType::Http,
            url: None,
            ..OutputConfig::default()
        };
        let result = create_sink(&config);
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("url"), "error should mention missing url: {err}");
    }
}
