use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use reqwest::StatusCode;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::config::{OutputConfig, SinkType};
use crate::events::ThreatEvent;
use crate::spool::DiskSpool;

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
    /// Number of spool files currently on disk (HTTP sink only).
    fn spool_files(&self) -> u64 {
        0
    }
    /// Total spool bytes currently on disk (HTTP sink only).
    fn spool_bytes(&self) -> u64 {
        0
    }
    /// Bytes of sealed batches waiting in memory for delivery (HTTP sink only).
    fn queued_bytes(&self) -> u64 {
        0
    }
    /// Deliver or persist everything still buffered and stop background
    /// work. Called once, when the sensor stops.
    async fn shutdown(&mut self) -> Result<()> {
        self.flush().await
    }
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
// HttpSink — batched JSON array POST, delivered by a background task
// ---------------------------------------------------------------------------
//
// The sensor's event loop calls `send` for every event, so `send` must never
// wait for the network: while the loop waits, the collectors' channel fills
// up and new events are dropped at the source. `send` therefore only
// serializes the event. Every `batch_size` events are sealed into a batch
// (gzip-compressed when enabled) and handed to a delivery task:
//
// - Up to `queue_max_mb` of sealed batches wait in memory. A batch that does
//   not fit goes straight to the disk spool; it is dropped only when there is
//   no spool or the spool is full as well.
// - The delivery task POSTs one batch at a time (`retry_count` attempts).
//   After a failed batch it backs off (1 s, doubling up to 30 s) and then
//   retries that batch before newer ones. With nothing queued it sends the
//   spooled batches, oldest first.
// - A batch the endpoint rejects as malformed or too large (400, 413) can
//   never be delivered: it is dropped and counted instead of being retried
//   forever and holding up everything behind it.
// - `shutdown` keeps delivering for up to `Tuning::shutdown_grace` and then
//   spools whatever is still in memory, so a service stop loses nothing that
//   was buffered.

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Delivery timing (tests shorten it).
#[derive(Debug, Clone, Copy)]
struct Tuning {
    initial_backoff: Duration,
    max_backoff: Duration,
    shutdown_grace: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// A sealed batch: the POST body, gzip-compressed when `gzip` is set.
struct Batch {
    body: Vec<u8>,
    gzip: bool,
    events: u64,
}

/// State shared by the sink (event loop side) and its delivery task.
struct Shared {
    spool: Option<Mutex<DiskSpool>>,
    /// Events given up on: no room to keep them, or rejected by the endpoint.
    dropped: AtomicU64,
    /// Body bytes of batches handed to the delivery task and not yet
    /// delivered, spooled or dropped.
    queued_bytes: AtomicU64,
    /// Counters for sparse logging.
    overflows: AtomicU64,
    drops: AtomicU64,
}

impl Shared {
    fn drop_events(&self, events: u64, reason: &str) {
        let total = self.dropped.fetch_add(events, Ordering::Relaxed) + events;
        let n = self.drops.fetch_add(1, Ordering::Relaxed) + 1;
        if sparse(n) {
            tracing::error!(
                events_lost = events,
                total_dropped = total,
                reason,
                "HTTP sink dropped events"
            );
        }
    }

    /// Keep a batch that cannot be delivered now in the spool, or drop it
    /// when there is no spool or no room. Returns whether it was spooled.
    fn spool_or_drop(&self, batch: &Batch) -> bool {
        let Some(spool) = &self.spool else {
            self.drop_events(batch.events, "no spool_dir configured");
            return false;
        };
        let written = match spool.lock() {
            Ok(mut spool) => spool.write(&batch.body),
            Err(_) => Err(anyhow!("spool lock poisoned")),
        };
        match written {
            Ok(()) => true,
            Err(e) => {
                self.drop_events(batch.events, &format!("not spooled: {e}"));
                false
            }
        }
    }

    /// Spool files waiting for delivery, oldest first.
    fn spool_listing(&self) -> Vec<PathBuf> {
        let Some(spool) = &self.spool else {
            return Vec::new();
        };
        let Ok(spool) = spool.lock() else {
            return Vec::new();
        };
        if spool.file_count() == 0 {
            return Vec::new();
        }
        spool.pending().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Failed to list spool files");
            Vec::new()
        })
    }

    fn remove_spooled(&self, path: &Path) {
        if let Some(Ok(mut spool)) = self.spool.as_ref().map(|s| s.lock()) {
            if let Err(e) = spool.remove(path) {
                tracing::warn!(path = %path.display(), error = %e, "Failed to remove spool file");
            }
        }
    }

    fn spool_stat(&self, stat: fn(&DiskSpool) -> u64) -> u64 {
        match self.spool.as_ref().map(|s| s.lock()) {
            Some(Ok(spool)) => stat(&spool),
            _ => 0,
        }
    }
}

/// Log on the 1st, 2nd, 4th, 8th, ... and every 1000th occurrence.
fn sparse(n: u64) -> bool {
    n.is_power_of_two() || n % 1000 == 0
}

pub struct HttpSink {
    batch_size: usize,
    /// Serialized events not yet sealed into a batch.
    buffer: Vec<String>,
    gzip: bool,
    queue_budget: u64,
    shared: Arc<Shared>,
    /// Hand-off to the delivery task; `None` after shutdown.
    queue: Option<mpsc::UnboundedSender<Batch>>,
    stop: watch::Sender<bool>,
    /// The delivery task until it is spawned (that needs a tokio runtime).
    idle_worker: Option<Worker>,
    task: Option<JoinHandle<()>>,
}

impl HttpSink {
    pub fn new(config: &OutputConfig) -> Result<Self> {
        Self::with_tuning(config, Tuning::default())
    }

    fn with_tuning(config: &OutputConfig, tuning: Tuning) -> Result<Self> {
        let url = config
            .url
            .as_ref()
            .ok_or_else(|| anyhow!("HTTP sink requires 'url' in [output] config"))?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()?;

        let spool = match config.spool_dir {
            Some(ref dir) => Some(Mutex::new(DiskSpool::open(dir, config.spool_max_mb)?)),
            None => None,
        };
        let shared = Arc::new(Shared {
            spool,
            dropped: AtomicU64::new(0),
            queued_bytes: AtomicU64::new(0),
            overflows: AtomicU64::new(0),
            drops: AtomicU64::new(0),
        });

        let (queue_tx, queue_rx) = mpsc::unbounded_channel();
        let (stop_tx, stop_rx) = watch::channel(false);
        let worker = Worker {
            endpoint: Endpoint {
                client,
                url: url.clone(),
                bearer_token: config.bearer_token.clone(),
                headers: config.headers.clone(),
                retry_count: config.retry_count.max(1),
                retry_backoff: Duration::from_millis(config.retry_backoff_ms),
            },
            shared: shared.clone(),
            queue: queue_rx,
            stop: StopSignal {
                rx: stop_rx,
                grace: tuning.shutdown_grace,
                deadline: None,
            },
            retry: None,
            backoff: Backoff::new(tuning.initial_backoff, tuning.max_backoff),
            spooled: VecDeque::new(),
        };

        let batch_size = config.batch_size.max(1);
        let mut sink = Self {
            batch_size,
            buffer: Vec::with_capacity(batch_size),
            gzip: config.gzip,
            queue_budget: config.queue_max_mb.saturating_mul(1024 * 1024),
            shared,
            queue: Some(queue_tx),
            stop: stop_tx,
            idle_worker: Some(worker),
            task: None,
        };
        // Start right away when possible, so batches spooled by an earlier
        // run are delivered even before new events arrive.
        sink.start_worker();
        Ok(sink)
    }

    fn start_worker(&mut self) {
        if self.task.is_some() {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            if let Some(worker) = self.idle_worker.take() {
                self.task = Some(runtime.spawn(worker.run()));
            }
        }
    }

    /// Seal the buffered events into a batch and queue it for delivery.
    fn seal(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let events = self.buffer.len() as u64;
        let body = encode_batch(&self.buffer, self.gzip);
        self.buffer.clear();
        match body {
            Ok(body) => {
                self.enqueue(Batch {
                    body,
                    gzip: self.gzip,
                    events,
                });
                Ok(())
            }
            Err(e) => {
                self.shared.drop_events(events, "batch encoding failed");
                Err(e.into())
            }
        }
    }

    fn enqueue(&mut self, batch: Batch) {
        self.start_worker();
        let len = batch.body.len() as u64;
        let queued = self.shared.queued_bytes.load(Ordering::Relaxed);
        // One batch is always accepted, however small the budget.
        let fits = queued == 0 || queued.saturating_add(len) <= self.queue_budget;
        let batch = match &self.queue {
            Some(queue) if fits && self.task.is_some() => {
                self.shared.queued_bytes.fetch_add(len, Ordering::Relaxed);
                match queue.send(batch) {
                    Ok(()) => return,
                    Err(mpsc::error::SendError(batch)) => {
                        self.shared.queued_bytes.fetch_sub(len, Ordering::Relaxed);
                        batch
                    }
                }
            }
            _ => batch,
        };
        let n = self.shared.overflows.fetch_add(1, Ordering::Relaxed) + 1;
        if sparse(n) {
            tracing::warn!(
                queued_bytes = queued,
                overflowed_batches = n,
                spool = self.shared.spool.is_some(),
                "HTTP delivery is behind the event rate; batches go to the spool"
            );
        }
        self.shared.spool_or_drop(&batch);
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
            self.seal()?;
        }
        Ok(())
    }

    /// Queue the partial batch. Delivery happens in the background.
    async fn flush(&mut self) -> Result<()> {
        self.seal()
    }

    async fn shutdown(&mut self) -> Result<()> {
        let sealed = self.seal();
        // Closing the queue lets the task see every batch, then the end.
        self.queue = None;
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            if let Err(e) = task.await {
                tracing::error!(error = %e, "HTTP delivery task failed");
            }
        }
        sealed
    }

    fn dropped_events(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }

    fn spool_files(&self) -> u64 {
        self.shared.spool_stat(DiskSpool::file_count)
    }

    fn spool_bytes(&self) -> u64 {
        self.shared.spool_stat(DiskSpool::total_bytes)
    }

    fn queued_bytes(&self) -> u64 {
        self.shared.queued_bytes.load(Ordering::Relaxed)
    }
}

/// Serialize `[item,item,...]`, gzip-compressed when asked.
fn encode_batch(items: &[String], gzip: bool) -> std::io::Result<Vec<u8>> {
    fn write_array(out: &mut impl Write, items: &[String]) -> std::io::Result<()> {
        out.write_all(b"[")?;
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                out.write_all(b",")?;
            }
            out.write_all(item.as_bytes())?;
        }
        out.write_all(b"]")
    }

    let len = items.iter().map(|s| s.len() + 1).sum::<usize>() + 1;
    if gzip {
        let mut encoder = GzEncoder::new(Vec::with_capacity(len / 4), Compression::fast());
        write_array(&mut encoder, items)?;
        encoder.finish()
    } else {
        let mut out = Vec::with_capacity(len);
        write_array(&mut out, items)?;
        Ok(out)
    }
}

/// Number of events in a batch body (plain or gzip JSON array); 0 if it
/// cannot be read. Only used to count a rejected spool file as dropped.
fn count_events(body: &[u8]) -> u64 {
    let mut decoded = Vec::new();
    let json = if body.starts_with(&GZIP_MAGIC) {
        let limit = 256 * 1024 * 1024;
        if MultiGzDecoder::new(body)
            .take(limit)
            .read_to_end(&mut decoded)
            .is_err()
        {
            return 0;
        }
        &decoded[..]
    } else {
        body
    };
    serde_json::from_slice::<Vec<serde::de::IgnoredAny>>(json)
        .map(|events| events.len() as u64)
        .unwrap_or(0)
}

/// Statuses that reject the batch itself: sending it again cannot succeed.
/// Everything else (network errors, 401, 5xx, ...) is retried.
fn is_permanent(status: StatusCode) -> bool {
    status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE
}

fn rejection_reason(status: StatusCode, detail: &str) -> String {
    let hint = if status == StatusCode::PAYLOAD_TOO_LARGE {
        " (lower output.batch_size)"
    } else {
        ""
    };
    format!("rejected by the endpoint with {status}{hint}: {detail}")
}

/// Most of a response body that is read (for error details).
const MAX_RESPONSE_BYTES: usize = 8 * 1024;

async fn read_capped(mut resp: reqwest::Response, cap: usize) -> String {
    let mut buf = Vec::new();
    while let Ok(Some(chunk)) = resp.chunk().await {
        let room = cap - buf.len();
        buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if buf.len() == cap {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

struct Endpoint {
    client: reqwest::Client,
    url: String,
    bearer_token: Option<String>,
    headers: HashMap<String, String>,
    retry_count: u32,
    retry_backoff: Duration,
}

/// Outcome of trying to deliver one batch.
enum Delivery {
    Delivered,
    /// The endpoint refused the batch itself (see [`is_permanent`]).
    Rejected(StatusCode, String),
    /// Network error or a status worth retrying later.
    Failed(anyhow::Error),
    /// The shutdown deadline passed first.
    Interrupted,
}

impl Endpoint {
    /// POST a body, with up to `retry_count` attempts.
    async fn post(&self, body: &[u8], gzip: bool) -> Delivery {
        let mut last_err = None;
        for attempt in 0..self.retry_count {
            let mut req = self
                .client
                .post(&self.url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
            if gzip {
                req = req.header(reqwest::header::CONTENT_ENCODING, "gzip");
            }
            if let Some(ref token) = self.bearer_token {
                req = req.bearer_auth(token);
            }
            for (k, v) in &self.headers {
                req = req.header(k, v);
            }

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    // Read the (small) response so the connection is reused.
                    let text = read_capped(resp, MAX_RESPONSE_BYTES).await;
                    if status.is_success() {
                        return Delivery::Delivered;
                    }
                    let detail: String = text.trim().chars().take(200).collect();
                    if is_permanent(status) {
                        return Delivery::Rejected(status, detail);
                    }
                    last_err = Some(anyhow!(
                        "HTTP POST to {} returned {status}: {detail}",
                        self.url
                    ));
                }
                Err(e) => last_err = Some(e.into()),
            }
            if attempt + 1 < self.retry_count {
                tokio::time::sleep(self.retry_backoff * (attempt + 1)).await;
            }
        }
        Delivery::Failed(last_err.unwrap_or_else(|| anyhow!("no delivery attempt made")))
    }
}

struct Backoff {
    initial: Duration,
    max: Duration,
    next: Duration,
}

impl Backoff {
    fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            next: initial,
        }
    }

    fn reset(&mut self) {
        self.next = self.initial;
    }

    fn advance(&mut self) -> Duration {
        let delay = self.next;
        self.next = (self.next * 2).min(self.max);
        delay
    }
}

/// Shutdown request from the sink, and the delivery deadline it starts.
struct StopSignal {
    rx: watch::Receiver<bool>,
    grace: Duration,
    deadline: Option<Instant>,
}

impl StopSignal {
    fn begin(&mut self) {
        if self.deadline.is_none() {
            self.deadline = Some(Instant::now() + self.grace);
        }
    }

    /// Whether shutdown was requested or the sink is gone.
    fn requested(&mut self) -> bool {
        if self.deadline.is_none() {
            let stop = match self.rx.has_changed() {
                Ok(_) => *self.rx.borrow_and_update(),
                Err(_) => true,
            };
            if stop {
                self.begin();
            }
        }
        self.deadline.is_some()
    }

    /// Resolves once shutdown is requested.
    async fn wait(&mut self) {
        while !self.requested() {
            if self.rx.changed().await.is_err() {
                self.begin();
            }
        }
    }
}

enum Item {
    Queued(Batch),
    Spooled(PathBuf),
}

struct Worker {
    endpoint: Endpoint,
    shared: Arc<Shared>,
    queue: mpsc::UnboundedReceiver<Batch>,
    stop: StopSignal,
    /// A queued batch whose delivery failed; retried before newer ones.
    retry: Option<Batch>,
    backoff: Backoff,
    /// Spool files to send, oldest first (re-read from disk when empty).
    spooled: VecDeque<PathBuf>,
}

impl Worker {
    async fn run(mut self) {
        while let Some(item) = self.next_item().await {
            match item {
                Item::Queued(batch) => self.deliver_queued(batch).await,
                Item::Spooled(path) => self.deliver_spooled(path).await,
            }
        }
        self.finish().await;
    }

    /// The next batch to send, or `None` once the sink is shutting down.
    async fn next_item(&mut self) -> Option<Item> {
        loop {
            if self.stop.requested() {
                return None;
            }
            if let Some(batch) = self.retry.take() {
                return Some(Item::Queued(batch));
            }
            match self.queue.try_recv() {
                Ok(batch) => return Some(Item::Queued(batch)),
                Err(mpsc::error::TryRecvError::Disconnected) => return None,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
            if self.spooled.is_empty() {
                self.spooled.extend(self.shared.spool_listing());
            }
            if let Some(path) = self.spooled.pop_front() {
                return Some(Item::Spooled(path));
            }
            tokio::select! {
                batch = self.queue.recv() => return batch.map(Item::Queued),
                _ = self.stop.wait() => {}
            }
        }
    }

    async fn deliver_queued(&mut self, batch: Batch) {
        match self.post(&batch.body, batch.gzip).await {
            Delivery::Delivered => {
                self.release(&batch);
                self.backoff.reset();
            }
            Delivery::Rejected(status, detail) => {
                self.release(&batch);
                self.shared
                    .drop_events(batch.events, &rejection_reason(status, &detail));
            }
            Delivery::Failed(e) => {
                let delay = self.backoff.advance();
                tracing::warn!(
                    error = %e,
                    events = batch.events,
                    retry_in_secs = delay.as_secs_f32(),
                    "HTTP delivery failed; will retry"
                );
                self.retry = Some(batch);
                self.pause(delay).await;
            }
            Delivery::Interrupted => self.retry = Some(batch),
        }
    }

    async fn deliver_spooled(&mut self, path: PathBuf) {
        let body = match DiskSpool::read(&path) {
            Ok(body) => body,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Removing unreadable spool file");
                self.shared.remove_spooled(&path);
                return;
            }
        };
        // Older versions spooled uncompressed bodies; send those as they are.
        let gzip = body.starts_with(&GZIP_MAGIC);
        match self.post(&body, gzip).await {
            Delivery::Delivered => {
                self.shared.remove_spooled(&path);
                self.backoff.reset();
                tracing::debug!(path = %path.display(), "Delivered spooled batch");
            }
            Delivery::Rejected(status, detail) => {
                self.shared.remove_spooled(&path);
                self.shared
                    .drop_events(count_events(&body), &rejection_reason(status, &detail));
            }
            Delivery::Failed(e) => {
                let delay = self.backoff.advance();
                tracing::warn!(
                    error = %e,
                    retry_in_secs = delay.as_secs_f32(),
                    "Spool drain paused, endpoint unavailable"
                );
                self.spooled.push_front(path);
                self.pause(delay).await;
            }
            Delivery::Interrupted => self.spooled.push_front(path),
        }
    }

    /// Deliver what is still in memory until the deadline, then spool the
    /// rest. Spool files stay on disk for the next run.
    async fn finish(&mut self) {
        self.stop.begin();
        self.queue.close();
        let mut batches: Vec<Batch> = self.retry.take().into_iter().collect();
        while let Ok(batch) = self.queue.try_recv() {
            batches.push(batch);
        }

        let (mut delivered, mut spooled, mut reachable) = (0u64, 0u64, true);
        for batch in batches {
            if reachable {
                match self.post(&batch.body, batch.gzip).await {
                    Delivery::Delivered => {
                        self.release(&batch);
                        delivered += batch.events;
                        continue;
                    }
                    Delivery::Rejected(status, detail) => {
                        self.release(&batch);
                        self.shared
                            .drop_events(batch.events, &rejection_reason(status, &detail));
                        continue;
                    }
                    Delivery::Failed(_) | Delivery::Interrupted => reachable = false,
                }
            }
            self.release(&batch);
            if self.shared.spool_or_drop(&batch) {
                spooled += batch.events;
            }
        }
        if delivered + spooled > 0 {
            tracing::info!(
                delivered_events = delivered,
                spooled_events = spooled,
                "HTTP sink flushed on shutdown"
            );
        }
    }

    /// POST a body; once shutdown is requested, give up at its deadline.
    async fn post(&mut self, body: &[u8], gzip: bool) -> Delivery {
        let attempt = self.endpoint.post(body, gzip);
        tokio::pin!(attempt);
        if self.stop.deadline.is_none() {
            tokio::select! {
                delivery = &mut attempt => return delivery,
                _ = self.stop.wait() => {}
            }
        }
        let deadline = self.stop.deadline.unwrap_or_else(Instant::now);
        tokio::time::timeout_at(deadline, attempt)
            .await
            .unwrap_or(Delivery::Interrupted)
    }

    /// Wait before the next attempt; cut short by shutdown.
    async fn pause(&mut self, delay: Duration) {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = self.stop.wait() => {}
        }
    }

    fn release(&self, batch: &Batch) {
        self.shared
            .queued_bytes
            .fetch_sub(batch.body.len() as u64, Ordering::Relaxed);
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
                etw: None,
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

    /// Short backoff and shutdown grace, so failure paths run quickly.
    fn fast() -> Tuning {
        Tuning {
            initial_backoff: Duration::from_millis(20),
            max_backoff: Duration::from_millis(100),
            shutdown_grace: Duration::from_secs(2),
        }
    }

    fn http_sink(config: &OutputConfig) -> HttpSink {
        HttpSink::with_tuning(config, fast()).unwrap()
    }

    /// Poll `cond` until it holds; fail after 10 s.
    async fn eventually(what: &str, cond: impl Fn() -> bool) {
        let start = std::time::Instant::now();
        while !cond() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_matched(mock: &mockito::Mock) {
        let start = std::time::Instant::now();
        while !mock.matched_async().await {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "timed out waiting for the mock to be hit"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn spool_file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".spool"))
            .collect();
        names.sort();
        names
    }

    /// An endpoint that accepts connections and never answers.
    async fn hung_endpoint() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        format!("http://{addr}/events")
    }

    #[tokio::test]
    async fn http_sink_sends_full_batch() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let config = http_config(&format!("{}/events", server.url()), 2);
        let mut sink = http_sink(&config);

        let evt = dummy_event();
        sink.send(&evt).await.unwrap(); // buffered, no POST yet
        assert_eq!(sink.buffer.len(), 1);
        sink.send(&evt).await.unwrap(); // sealed and queued
        assert_eq!(sink.buffer.len(), 0);

        sink.shutdown().await.unwrap();
        mock.assert_async().await;
        assert_eq!(sink.queued_bytes(), 0);
        assert_eq!(sink.dropped_events(), 0);
    }

    #[tokio::test]
    async fn http_sink_flush_delivers_partial_batch_in_background() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let config = http_config(&format!("{}/events", server.url()), 100);
        let mut sink = http_sink(&config);

        sink.send(&dummy_event()).await.unwrap();
        sink.flush().await.unwrap();
        assert!(sink.buffer.is_empty());

        // Delivered without waiting for shutdown.
        wait_matched(&mock).await;
        eventually("queue drained", || sink.queued_bytes() == 0).await;
        sink.shutdown().await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn http_sink_body_is_json_array() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .match_header("Content-Type", "application/json")
            .match_body(mockito::Matcher::Regex(r"^\[\{.*\},\{.*\}\]$".into()))
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let config = http_config(&format!("{}/events", server.url()), 2);
        let mut sink = http_sink(&config);
        sink.send(&dummy_event()).await.unwrap();
        sink.send(&dummy_event()).await.unwrap();
        sink.shutdown().await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn http_sink_retries_within_one_delivery() {
        let mut server = mockito::Server::new_async().await;
        // Fail twice, succeed on the third attempt
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
        let mut sink = http_sink(&config);
        sink.send(&dummy_event()).await.unwrap();
        sink.shutdown().await.unwrap();

        mock.assert_async().await;
        mock_ok.assert_async().await;
        assert_eq!(sink.dropped_events(), 0);
    }

    #[tokio::test]
    async fn endpoint_makes_retry_count_attempts() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .with_status(500)
            .expect(2)
            .create_async()
            .await;

        let endpoint = Endpoint {
            client: reqwest::Client::new(),
            url: format!("{}/events", server.url()),
            bearer_token: None,
            headers: HashMap::new(),
            retry_count: 2,
            retry_backoff: Duration::from_millis(10),
        };
        assert!(matches!(
            endpoint.post(b"[]", false).await,
            Delivery::Failed(_)
        ));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn http_sink_retries_failed_batch_until_endpoint_recovers() {
        let mut server = mockito::Server::new_async().await;
        let mock_fail = server
            .mock("POST", "/events")
            .with_status(503)
            .expect(4)
            .create_async()
            .await;
        let mock_ok = server
            .mock("POST", "/events")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let mut config = http_config(&format!("{}/events", server.url()), 1);
        config.retry_count = 1;
        let mut sink = http_sink(&config);
        sink.send(&dummy_event()).await.unwrap();

        eventually("delivery after the outage", || sink.queued_bytes() == 0).await;
        mock_fail.assert_async().await;
        mock_ok.assert_async().await;
        assert_eq!(sink.dropped_events(), 0);
        sink.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn http_sink_without_spool_drops_undeliverable_events_at_shutdown() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/events")
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let mut config = http_config(&format!("{}/events", server.url()), 5);
        config.retry_backoff_ms = 10;
        let mut sink = http_sink(&config);
        for _ in 0..5 {
            sink.send(&dummy_event()).await.unwrap();
        }
        assert_eq!(
            sink.dropped_events(),
            0,
            "nothing is dropped while retrying"
        );

        sink.shutdown().await.unwrap();
        assert_eq!(sink.dropped_events(), 5);
        assert_eq!(sink.queued_bytes(), 0);
        assert_eq!(sink.spool_files(), 0);
    }

    #[tokio::test]
    async fn http_sink_empty_flush_and_shutdown_are_noops() {
        let config = http_config("http://unused.example.invalid/events", 10);
        let mut sink = http_sink(&config);
        sink.flush().await.unwrap();
        sink.shutdown().await.unwrap();
        assert_eq!(sink.dropped_events(), 0);
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
        let mut sink = http_sink(&config);

        sink.send(&dummy_event()).await.unwrap();
        sink.shutdown().await.unwrap();
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
        let mut sink = http_sink(&config);

        sink.send(&dummy_event()).await.unwrap();
        sink.shutdown().await.unwrap();
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
        let mut sink = http_sink(&config);

        sink.send(&dummy_event()).await.unwrap();
        sink.shutdown().await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn http_sink_shutdown_delivers_queued_batches() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .with_status(200)
            .expect(20)
            .create_async()
            .await;

        let config = http_config(&format!("{}/events", server.url()), 5);
        let mut sink = http_sink(&config);
        for _ in 0..100 {
            sink.send(&dummy_event()).await.unwrap();
        }
        sink.shutdown().await.unwrap();
        mock.assert_async().await;
        assert_eq!(sink.queued_bytes(), 0);
        assert_eq!(sink.dropped_events(), 0);
    }

    #[tokio::test]
    async fn http_sink_drops_rejected_batch_without_retrying() {
        let dir = TempDir::new().unwrap();
        let spool_dir = dir.path().join("spool");
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .with_status(413)
            .with_body(r#"{"error":"payload too large"}"#)
            .expect(1)
            .create_async()
            .await;

        let mut config = http_config_with_spool(&format!("{}/events", server.url()), 3, &spool_dir);
        config.retry_count = 3;
        let mut sink = http_sink(&config);
        for _ in 0..3 {
            sink.send(&dummy_event()).await.unwrap();
        }
        eventually("rejected batch dropped", || sink.dropped_events() == 3).await;
        sink.shutdown().await.unwrap();
        mock.assert_async().await; // one request: a rejection is not retried
        assert_eq!(sink.spool_files(), 0);
        assert_eq!(sink.queued_bytes(), 0);
    }

    #[test]
    fn count_events_reads_plain_and_gzip_bodies() {
        let items = vec![r#"{"a":1}"#.to_string(), r#"{"b":2}"#.to_string()];
        assert_eq!(count_events(&encode_batch(&items, false).unwrap()), 2);
        assert_eq!(count_events(&encode_batch(&items, true).unwrap()), 2);
        assert_eq!(count_events(b"not json"), 0);
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

    // --- HttpSink + spool integration tests ----------------------------------

    fn http_config_with_spool(url: &str, batch_size: usize, spool_dir: &Path) -> OutputConfig {
        OutputConfig {
            sink_type: SinkType::Http,
            url: Some(url.to_string()),
            batch_size,
            timeout_secs: 2,
            retry_count: 1,
            retry_backoff_ms: 10,
            spool_dir: Some(spool_dir.to_path_buf()),
            spool_max_mb: 10,
            ..OutputConfig::default()
        }
    }

    /// Spool `batches` one-event batches through an endpoint that fails.
    async fn spool_batches(spool_dir: &Path, batches: usize, gzip: bool) {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/events")
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;
        let mut config = http_config_with_spool(&format!("{}/events", server.url()), 1, spool_dir);
        config.gzip = gzip;
        let mut sink = http_sink(&config);
        for _ in 0..batches {
            sink.send(&dummy_event()).await.unwrap();
        }
        sink.shutdown().await.unwrap();
        assert_eq!(sink.spool_files(), batches as u64);
        assert_eq!(sink.dropped_events(), 0);
    }

    #[tokio::test]
    async fn http_sink_spools_undeliverable_batches() {
        let dir = TempDir::new().unwrap();
        let spool_dir = dir.path().join("spool");
        spool_batches(&spool_dir, 2, false).await;

        let names = spool_file_names(&spool_dir);
        assert_eq!(names.len(), 2);
        let body = std::fs::read(spool_dir.join(&names[0])).unwrap();
        assert!(body.starts_with(b"[{"), "plain JSON array");
        assert_eq!(count_events(&body), 1);
    }

    #[tokio::test]
    async fn http_sink_spools_compressed_batches_with_gzip() {
        let dir = TempDir::new().unwrap();
        let spool_dir = dir.path().join("spool");
        spool_batches(&spool_dir, 1, true).await;

        let names = spool_file_names(&spool_dir);
        let body = std::fs::read(spool_dir.join(&names[0])).unwrap();
        assert!(body.starts_with(&GZIP_MAGIC));
        assert_eq!(count_events(&body), 1);
    }

    #[tokio::test]
    async fn http_sink_drains_spool_without_new_events() {
        let dir = TempDir::new().unwrap();
        let spool_dir = dir.path().join("spool");
        spool_batches(&spool_dir, 3, true).await;

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .match_header("Content-Encoding", "gzip")
            .with_status(200)
            .expect(3)
            .create_async()
            .await;
        let config = http_config_with_spool(&format!("{}/events", server.url()), 100, &spool_dir);
        let mut sink = http_sink(&config);

        eventually("spool drained", || sink.spool_files() == 0).await;
        mock.assert_async().await;
        assert_eq!(sink.spool_bytes(), 0);
        assert!(spool_file_names(&spool_dir).is_empty());
        sink.shutdown().await.unwrap();
    }

    /// Spool files of earlier versions hold the uncompressed body.
    #[tokio::test]
    async fn http_sink_sends_plain_spool_files_uncompressed() {
        let dir = TempDir::new().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir_all(&spool_dir).unwrap();
        let body = format!("[{}]", serde_json::to_string(&dummy_event()).unwrap());
        std::fs::write(spool_dir.join("00000000000000000001_000001.spool"), &body).unwrap();

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .match_header("Content-Encoding", mockito::Matcher::Missing)
            .match_body(body.as_str())
            .with_status(200)
            .expect(1)
            .create_async()
            .await;
        let mut config =
            http_config_with_spool(&format!("{}/events", server.url()), 100, &spool_dir);
        config.gzip = true;
        let mut sink = http_sink(&config);

        eventually("spool drained", || sink.spool_files() == 0).await;
        mock.assert_async().await;
        sink.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn http_sink_spool_full_drops_events() {
        let dir = TempDir::new().unwrap();
        let spool_dir = dir.path().join("spool");
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/events")
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        // 0 MB cap: no spool write fits
        let mut config = http_config_with_spool(&format!("{}/events", server.url()), 1, &spool_dir);
        config.spool_max_mb = 0;
        let mut sink = http_sink(&config);

        sink.send(&dummy_event()).await.unwrap();
        sink.shutdown().await.unwrap();
        assert_eq!(sink.dropped_events(), 1);
        assert_eq!(sink.spool_files(), 0);
    }

    #[tokio::test]
    async fn http_sink_spool_drain_pauses_on_failure() {
        let dir = TempDir::new().unwrap();
        let spool_dir = dir.path().join("spool");
        spool_batches(&spool_dir, 3, false).await;
        let oldest = spool_file_names(&spool_dir)[0].clone();

        // Accepts one batch, then fails
        let mut server = mockito::Server::new_async().await;
        let mock_ok = server
            .mock("POST", "/events")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;
        let mock_fail = server
            .mock("POST", "/events")
            .with_status(503)
            .expect_at_least(1)
            .create_async()
            .await;
        let config = http_config_with_spool(&format!("{}/events", server.url()), 100, &spool_dir);
        let mut sink = http_sink(&config);

        eventually("one spooled batch delivered", || sink.spool_files() == 2).await;
        wait_matched(&mock_fail).await;
        sink.shutdown().await.unwrap();
        mock_ok.assert_async().await;

        let remaining = spool_file_names(&spool_dir);
        assert_eq!(
            remaining.len(),
            2,
            "the rest stays on disk for the next run"
        );
        assert!(!remaining.contains(&oldest), "the oldest batch goes first");
    }

    #[tokio::test]
    async fn http_sink_removes_rejected_spool_file() {
        let dir = TempDir::new().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir_all(&spool_dir).unwrap();
        let evt = serde_json::to_string(&dummy_event()).unwrap();
        std::fs::write(
            spool_dir.join("00000000000000000001_000001.spool"),
            format!("[{evt},{evt}]"),
        )
        .unwrap();

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/events")
            .with_status(400)
            .expect(1)
            .create_async()
            .await;
        let config = http_config_with_spool(&format!("{}/events", server.url()), 100, &spool_dir);
        let mut sink = http_sink(&config);

        eventually("rejected spool file removed", || sink.spool_files() == 0).await;
        mock.assert_async().await;
        assert_eq!(sink.dropped_events(), 2);
        sink.shutdown().await.unwrap();
    }

    /// The regression this design fixes: with a hung endpoint, the old sink
    /// blocked `send` for the whole request timeout.
    #[tokio::test]
    async fn http_sink_send_never_waits_for_the_network() {
        let dir = TempDir::new().unwrap();
        let spool_dir = dir.path().join("spool");
        let url = hung_endpoint().await;
        let mut config = http_config_with_spool(&url, 10, &spool_dir);
        config.timeout_secs = 30;
        config.queue_max_mb = 0; // one batch in memory, the rest overflows
        let tuning = Tuning {
            shutdown_grace: Duration::from_millis(300),
            ..fast()
        };
        let mut sink = HttpSink::with_tuning(&config, tuning).unwrap();

        let start = std::time::Instant::now();
        for _ in 0..100 {
            sink.send(&dummy_event()).await.unwrap();
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "send blocked for {:?}",
            start.elapsed()
        );
        // The first batch is in flight; the other nine went to the spool.
        assert_eq!(sink.spool_files(), 9);
        assert!(sink.queued_bytes() > 0);
        assert_eq!(sink.dropped_events(), 0);

        let start = std::time::Instant::now();
        sink.shutdown().await.unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "shutdown took {:?}",
            start.elapsed()
        );
        // The in-flight batch was spooled at the deadline.
        assert_eq!(sink.spool_files(), 10);
        assert_eq!(sink.queued_bytes(), 0);
        assert_eq!(sink.dropped_events(), 0);
    }

    /// End-to-end run against a live threatfalcon-server (not run by default):
    ///
    /// ```text
    /// TF_E2E_URL=http://127.0.0.1:8080/api/v1/events TF_E2E_TOKEN=tfs_... \
    /// TF_E2E_EVENTS=300000 TF_E2E_RATE=11000 TF_E2E_SPOOL=/tmp/tf-spool \
    ///   cargo test --bin threatfalcon http_sink_e2e -- --ignored --nocapture
    /// ```
    ///
    /// Sends TF_E2E_EVENTS process events (default 100000) at up to
    /// TF_E2E_RATE events/s (default: as fast as possible; TF_E2E_QUEUE_MB sets
    /// `queue_max_mb`), waits for the
    /// queue and spool to drain and reports how long `send` blocked at most.
    /// Stop and restart the server during the run to exercise an outage.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn http_sink_e2e() {
        let env = |key: &str| std::env::var(key).ok();
        let total: u64 = env("TF_E2E_EVENTS").map_or(100_000, |v| v.parse().unwrap());
        let rate: f64 = env("TF_E2E_RATE").map_or(0.0, |v| v.parse().unwrap());
        let config = OutputConfig {
            sink_type: SinkType::Http,
            url: Some(env("TF_E2E_URL").expect("set TF_E2E_URL")),
            bearer_token: env("TF_E2E_TOKEN"),
            batch_size: 1000,
            gzip: true,
            spool_dir: env("TF_E2E_SPOOL").map(PathBuf::from),
            queue_max_mb: env("TF_E2E_QUEUE_MB").map_or(64, |v| v.parse().unwrap()),
            ..OutputConfig::default()
        };
        let mut sink = HttpSink::new(&config).unwrap();
        let agent = AgentInfo {
            hostname: "E2E-HOST".into(),
            agent_id: uuid::Uuid::new_v4(),
        };
        let report = |sink: &HttpSink, what: &str, start: std::time::Instant| {
            eprintln!(
                "{:>6.1}s {what}: queued_bytes={} spool_files={} dropped={}",
                start.elapsed().as_secs_f64(),
                sink.queued_bytes(),
                sink.spool_files(),
                sink.dropped_events()
            );
        };

        let start = std::time::Instant::now();
        let mut slowest = Duration::ZERO;
        for i in 0..total {
            if rate > 0.0 {
                let due = Duration::from_secs_f64(i as f64 / rate);
                if let Some(wait) = due.checked_sub(start.elapsed()) {
                    tokio::time::sleep(wait).await;
                }
            }
            let event = ThreatEvent::new(
                &agent,
                EventSource::Etw {
                    provider: "Microsoft-Windows-Kernel-Process".into(),
                },
                EventCategory::Process,
                Severity::Info,
                EventData::ProcessCreate {
                    pid: i as u32,
                    ppid: 4,
                    image_path: r"C:\Windows\System32\svchost.exe".into(),
                    command_line: format!(
                        r"C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule {}",
                        "x".repeat(400)
                    ),
                    user: r"NT AUTHORITY\SYSTEM".into(),
                    integrity_level: "System".into(),
                    hashes: None,
                    create_time: None,
                },
            );
            let t = std::time::Instant::now();
            sink.send(&event).await.unwrap();
            slowest = slowest.max(t.elapsed());
            if i > 0 && i % 50_000 == 0 {
                report(&sink, &format!("sent {i}"), start);
            }
        }
        sink.flush().await.unwrap();
        eprintln!("sent {total} events, slowest send() {slowest:?}");

        let drain = std::time::Instant::now();
        while (sink.queued_bytes() > 0 || sink.spool_files() > 0)
            && drain.elapsed() < Duration::from_secs(300)
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        report(&sink, "drained", start);
        sink.shutdown().await.unwrap();
        report(&sink, "shut down", start);
        eprintln!("agent_id {}", agent.agent_id);
    }

    #[tokio::test]
    async fn http_sink_queues_in_memory_then_spools_queue_at_shutdown() {
        let dir = TempDir::new().unwrap();
        let spool_dir = dir.path().join("spool");
        let url = hung_endpoint().await;
        let mut config = http_config_with_spool(&url, 10, &spool_dir);
        config.timeout_secs = 30; // the default queue_max_mb holds every batch
        let tuning = Tuning {
            shutdown_grace: Duration::from_millis(300),
            ..fast()
        };
        let mut sink = HttpSink::with_tuning(&config, tuning).unwrap();

        for _ in 0..100 {
            sink.send(&dummy_event()).await.unwrap();
        }
        assert_eq!(sink.spool_files(), 0);
        assert!(sink.queued_bytes() > 0);

        sink.shutdown().await.unwrap();
        assert_eq!(sink.spool_files(), 10);
        assert_eq!(sink.queued_bytes(), 0);
        assert_eq!(sink.dropped_events(), 0);
    }
}
