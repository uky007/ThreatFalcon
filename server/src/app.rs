//! HTTP layer: the ingest listener (agents, behind the TLS proxy), the
//! loopback-only admin listener (status API, metrics) and the optional read
//! API listener (status and stored events for reader tokens, behind the TLS
//! proxy on a port the network opens only to the readers).

use std::collections::HashSet;
use std::fmt::Write as _;
use std::future::{Future, IntoFuture};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::{Body, Bytes};
use axum::extract::rejection::QueryRejection;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, SecondsFormat, Utc};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch, Semaphore};

use crate::auth::{bearer_token, TokenTable};
use crate::config::ServerConfig;
use crate::export::{self, ExportFilter, ExportQuery};
use crate::ingest::{self, BatchSummary, ContentEncoding, IngestError};
use crate::status::{self, BatchRecord, StatusRegistry};
use crate::store::{FreeSpace, Store, StoreSettings, WriteOutcome, DEFAULT_DEDUP_WINDOW};

/// How long a request waits for a processing slot before getting 503.
const PERMIT_WAIT: Duration = Duration::from_secs(10);
/// How long in-flight requests may run after a shutdown signal.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(20);
/// Event exports running at the same time (each reads files on a blocking
/// thread).
const MAX_CONCURRENT_EXPORTS: usize = 2;

pub struct AppState {
    tokens: TokenTable,
    /// Read API tokens, separate from the agents' tokens.
    readers: TokenTable,
    /// Configured agents: the read API serves only these.
    agent_names: HashSet<String>,
    exports: Arc<Semaphore>,
    store: Store,
    status: StatusRegistry,
    limits: Limits,
    permits: Semaphore,
    metrics: Metrics,
    started_at: DateTime<Utc>,
}

struct Limits {
    max_body_bytes: usize,
    max_decoded_bytes: usize,
    max_events_per_batch: usize,
    request_timeout: Duration,
}

#[derive(Default)]
struct Metrics {
    reader_requests: AtomicU64,
    reader_auth_failures: AtomicU64,
    auth_failures: AtomicU64,
    batches_ok: AtomicU64,
    client_errors: AtomicU64,
    server_errors: AtomicU64,
}

pub struct Server {
    state: Arc<AppState>,
    ingest: TcpListener,
    admin: TcpListener,
    reader: Option<TcpListener>,
}

impl Server {
    /// Open the data directory and bind the listeners.
    pub async fn bind(config: &ServerConfig) -> Result<Self> {
        let store = Store::open(
            &config.data_dir,
            StoreSettings {
                rotation_bytes: config.rotation_bytes(),
                max_rotated_files: config.storage.max_rotated_files,
                fsync: config.storage.fsync,
                dedup_window: DEFAULT_DEDUP_WINDOW,
                min_free_bytes: config.min_free_disk_bytes(),
                free_space: FreeSpace::default(),
            },
        )
        .with_context(|| {
            format!(
                "failed to open data directory {}",
                config.data_dir.display()
            )
        })?;
        let tokens = TokenTable::new(&config.agents)?;
        let status = StatusRegistry::new(
            config
                .agents
                .iter()
                .map(|a| (a.name.as_str(), store.last_write_time(&a.name))),
            config.status.stale_after_secs,
        );
        let ingest = TcpListener::bind(config.listen)
            .await
            .with_context(|| format!("failed to bind ingest listener {}", config.listen))?;
        let admin = TcpListener::bind(config.admin_listen)
            .await
            .with_context(|| format!("failed to bind admin listener {}", config.admin_listen))?;
        let reader = match config.reader_listen {
            Some(addr) => Some(
                TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("failed to bind reader listener {addr}"))?,
            ),
            None => None,
        };

        let state = AppState {
            tokens,
            readers: TokenTable::new(&config.readers)?,
            agent_names: config.agents.iter().map(|a| a.name.clone()).collect(),
            exports: Arc::new(Semaphore::new(MAX_CONCURRENT_EXPORTS)),
            store,
            status,
            limits: Limits {
                max_body_bytes: config.max_body_bytes(),
                max_decoded_bytes: config.max_decompressed_bytes(),
                max_events_per_batch: config.limits.max_events_per_batch,
                request_timeout: Duration::from_secs(config.limits.request_timeout_secs),
            },
            permits: Semaphore::new(config.limits.max_concurrent_requests),
            metrics: Metrics::default(),
            started_at: Utc::now(),
        };
        Ok(Self {
            state: Arc::new(state),
            ingest,
            admin,
            reader,
        })
    }

    pub fn ingest_addr(&self) -> io::Result<SocketAddr> {
        self.ingest.local_addr()
    }

    pub fn admin_addr(&self) -> io::Result<SocketAddr> {
        self.admin.local_addr()
    }

    /// The read API listener's address, if it is enabled.
    pub fn reader_addr(&self) -> Option<SocketAddr> {
        self.reader.as_ref().and_then(|l| l.local_addr().ok())
    }

    /// Serve until `shutdown` resolves, then let in-flight requests finish
    /// (bounded by `SHUTDOWN_GRACE`).
    pub async fn run<F>(self, shutdown: F) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Self {
            state,
            ingest,
            admin,
            reader,
        } = self;
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            shutdown.await;
            let _ = tx.send(true);
        });
        let stopped = |mut rx: watch::Receiver<bool>| async move {
            let _ = rx.wait_for(|stop| *stop).await;
        };

        let ingest = axum::serve(
            ingest,
            ingest_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(stopped(rx.clone()));
        let admin = axum::serve(admin, admin_router(state.clone()))
            .with_graceful_shutdown(stopped(rx.clone()));
        let reader_rx = rx.clone();
        let reader = async move {
            match reader {
                Some(listener) => {
                    axum::serve(
                        listener,
                        reader_router(state).into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(stopped(reader_rx))
                    .await
                }
                None => Ok(()),
            }
        };
        let serve_both =
            async { tokio::try_join!(ingest.into_future(), admin.into_future(), reader) };
        let deadline = async {
            stopped(rx.clone()).await;
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        };

        tokio::select! {
            res = serve_both => { res.context("server error")?; }
            () = deadline => {
                tracing::warn!("graceful shutdown timed out; exiting with requests in flight");
            }
        }
        Ok(())
    }
}

pub fn ingest_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/events", post(ingest_events))
        .route("/healthz", get(|| async { "ok\n" }))
        .fallback(not_found)
        .with_state(state)
}

pub fn admin_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(admin_health))
        .route("/api/v1/agents", get(list_agents))
        .route("/metrics", get(metrics))
        .fallback(not_found)
        .with_state(state)
}

pub fn reader_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/api/v1/agents", get(reader_agents))
        .route("/api/v1/agents/{agent}/events", get(export_events))
        .fallback(not_found)
        .with_state(state)
}

async fn not_found() -> Response {
    error_body(StatusCode::NOT_FOUND, "not found", &[])
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

async fn ingest_events(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let remote = client_addr(peer, &headers);

    // Authenticate before touching the body, so unauthenticated clients
    // cannot make the server buffer or decompress anything.
    let agent = header_str(&headers, header::AUTHORIZATION)
        .and_then(bearer_token)
        .and_then(|token| state.tokens.verify(token));
    let Some(agent) = agent else {
        state.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(remote = %remote, "rejected ingest request: missing or invalid token");
        let mut resp = error_body(
            StatusCode::UNAUTHORIZED,
            "missing or invalid bearer token",
            &[],
        );
        resp.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return resp;
    };

    match handle_batch(&state, &agent, &remote, &headers, body).await {
        Ok(resp) => {
            state.metrics.batches_ok.fetch_add(1, Ordering::Relaxed);
            resp
        }
        Err(failure) => {
            let counter = if failure.status.is_server_error() {
                &state.metrics.server_errors
            } else {
                &state.metrics.client_errors
            };
            counter.fetch_add(1, Ordering::Relaxed);
            state
                .status
                .record_error(&agent, Utc::now(), &remote, failure.message.clone());
            let detail = failure.detail.as_deref().unwrap_or(&failure.message);
            // `detail` may quote request content: log it as an escaped string.
            if failure.status.is_server_error() {
                tracing::error!(agent = %agent, remote = %remote, status = failure.status.as_u16(), error = detail, "ingest failed");
            } else {
                tracing::warn!(agent = %agent, remote = %remote, status = failure.status.as_u16(), error = detail, "ingest request rejected");
            }
            failure.into_response()
        }
    }
}

async fn handle_batch(
    state: &Arc<AppState>,
    agent: &Arc<str>,
    remote: &str,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, Failure> {
    ingest::check_content_type(header_str(headers, header::CONTENT_TYPE))?;
    let encoding = ingest::parse_content_encoding(header_str(headers, header::CONTENT_ENCODING))?;
    let max_body = state.limits.max_body_bytes;
    let declared_len =
        header_str(headers, header::CONTENT_LENGTH).and_then(|v| v.parse::<u64>().ok());
    if declared_len.is_some_and(|len| len > max_body as u64) {
        return Err(Failure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body exceeds {max_body} bytes"),
        ));
    }

    let Ok(Ok(_permit)) = tokio::time::timeout(PERMIT_WAIT, state.permits.acquire()).await else {
        return Err(
            Failure::new(StatusCode::SERVICE_UNAVAILABLE, "server busy, retry later")
                .retry_after(5),
        );
    };

    let body = match tokio::time::timeout(
        state.limits.request_timeout,
        Limited::new(body, max_body).collect(),
    )
    .await
    {
        Err(_) => {
            return Err(Failure::new(
                StatusCode::REQUEST_TIMEOUT,
                "timed out reading request body",
            ))
        }
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return Err(Failure::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("request body exceeds {max_body} bytes"),
            ))
        }
        Ok(Err(e)) => {
            return Err(Failure::new(
                StatusCode::BAD_REQUEST,
                format!("failed to read request body: {e}"),
            ))
        }
        Ok(Ok(collected)) => collected.to_bytes(),
    };
    let wire_bytes = body.len() as u64;

    // Decompression, parsing and disk I/O are blocking work.
    let task_state = state.clone();
    let task_agent = agent.clone();
    let processed = tokio::task::spawn_blocking(move || {
        process_batch(&task_state, &task_agent, &body, encoding)
    })
    .await
    .map_err(|e| Failure::internal(format!("batch processing task failed: {e}")))??;

    let summary = processed.summary;
    let (hostname, agent_id, version) = (
        summary.hostname.clone(),
        summary.agent_id.clone(),
        summary.sensor_version.clone(),
    );
    let first_contact = state.status.record_batch(
        agent,
        Utc::now(),
        BatchRecord {
            remote_addr: remote,
            summary,
            stored: processed.outcome.stored as u64,
            duplicates: processed.outcome.duplicates as u64,
            quarantined: processed.quarantined as u64,
            wire_bytes,
        },
    );
    if first_contact {
        tracing::info!(
            agent = %agent,
            remote = %remote,
            hostname = hostname.as_deref().unwrap_or("-"),
            agent_id = agent_id.as_deref().unwrap_or("-"),
            sensor_version = version.as_deref().unwrap_or("-"),
            "agent connected"
        );
    }
    if processed.quarantined > 0 {
        tracing::warn!(
            agent = %agent,
            stored = processed.outcome.stored,
            quarantined = processed.quarantined,
            first_error = processed.errors.first().map(String::as_str).unwrap_or(""),
            "quarantined invalid events (see rejected.jsonl)"
        );
    }
    tracing::debug!(
        agent = %agent,
        stored = processed.outcome.stored,
        duplicates = processed.outcome.duplicates,
        quarantined = processed.quarantined,
        bytes = wire_bytes,
        "batch processed"
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "accepted": processed.outcome.stored,
            "duplicates": processed.outcome.duplicates,
            "quarantined": processed.quarantined,
            "errors": processed.errors,
        })),
    )
        .into_response())
}

struct Processed {
    summary: BatchSummary,
    outcome: WriteOutcome,
    quarantined: usize,
    errors: Vec<String>,
}

fn process_batch(
    state: &AppState,
    agent: &Arc<str>,
    body: &[u8],
    encoding: ContentEncoding,
) -> Result<Processed, Failure> {
    let payload = ingest::decode_body(body, encoding, state.limits.max_decoded_bytes)?;
    let batch = ingest::parse_batch(&payload, state.limits.max_events_per_batch)?;
    // The sensor considers the whole batch delivered on a 2xx, so invalid
    // elements are kept (quarantined), never dropped.
    let received_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let quarantine = ingest::quarantine_lines(&batch.rejected, agent, &received_at);
    let mut processed = Processed {
        outcome: WriteOutcome::default(),
        quarantined: batch.rejected.len(),
        errors: batch.errors(),
        summary: batch.summary.clone(),
    };
    if batch.events.is_empty() && quarantine.is_empty() {
        return Ok(processed);
    }

    processed.outcome = state
        .store
        .with_writer(agent, |writer| {
            writer.write_batch(&batch.events, &quarantine)
        })
        .map_err(Failure::storage)?;
    Ok(processed)
}

/// Client address: behind the local TLS proxy, the peer is loopback and the
/// proxy reports the real client in `X-Forwarded-For` (last entry).
fn client_addr(peer: SocketAddr, headers: &HeaderMap) -> String {
    if peer.ip().is_loopback() {
        let forwarded = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return ip.to_string();
        }
    }
    peer.ip().to_string()
}

fn header_str(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// An error response, plus what to record about it.
struct Failure {
    status: StatusCode,
    /// Returned to the client and recorded in the agent's status.
    message: String,
    /// Logged instead of `message` when present (may contain internals).
    detail: Option<String>,
    errors: Vec<String>,
    retry_after: Option<u64>,
}

impl Failure {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            detail: None,
            errors: Vec::new(),
            retry_after: None,
        }
    }

    fn internal(detail: String) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error").detail(detail)
    }

    fn storage(e: io::Error) -> Self {
        // Covers both the server's free-space reserve and ENOSPC.
        if e.kind() == io::ErrorKind::StorageFull {
            Self::new(
                StatusCode::INSUFFICIENT_STORAGE,
                "server is low on disk space, retry later",
            )
            .detail(e.to_string())
            .retry_after(60)
        } else {
            Self::new(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
                .detail(format!("storage error: {e}"))
        }
    }

    fn detail(mut self, detail: String) -> Self {
        self.detail = Some(detail);
        self
    }

    fn retry_after(mut self, secs: u64) -> Self {
        self.retry_after = Some(secs);
        self
    }
}

impl From<IngestError> for Failure {
    fn from(e: IngestError) -> Self {
        let status = match &e {
            IngestError::UnsupportedMediaType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            IngestError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            IngestError::BadRequest(_) => StatusCode::BAD_REQUEST,
        };
        Self::new(status, e.to_string())
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let mut resp = error_body(self.status, &self.message, &self.errors);
        if let Some(secs) = self.retry_after {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        resp
    }
}

fn error_body(status: StatusCode, message: &str, errors: &[String]) -> Response {
    let body = if errors.is_empty() {
        json!({ "error": message })
    } else {
        json!({ "error": message, "errors": errors })
    };
    (status, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

async fn admin_health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "version": crate::VERSION,
        "revision": crate::REVISION,
        "started_at": state.started_at,
        "agents_configured": state.tokens.len(),
    }))
}

#[derive(Deserialize)]
struct AgentsQuery {
    format: Option<String>,
}

async fn list_agents(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AgentsQuery>,
) -> Response {
    let now = Utc::now();
    let views = state.status.snapshot(now);
    if query.format.as_deref() == Some("text") {
        return (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            status::render_text(&views, now),
        )
            .into_response();
    }
    Json(json!({
        "generated_at": now,
        "stale_after_secs": state.status.stale_after_secs(),
        "agents": views,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Read API
// ---------------------------------------------------------------------------

/// The reader for a valid reader token (failures are counted and logged).
fn authorize_reader(state: &AppState, peer: SocketAddr, headers: &HeaderMap) -> Option<Arc<str>> {
    state
        .metrics
        .reader_requests
        .fetch_add(1, Ordering::Relaxed);
    let reader = header_str(headers, header::AUTHORIZATION)
        .and_then(bearer_token)
        .and_then(|token| state.readers.verify(token));
    if reader.is_none() {
        state
            .metrics
            .reader_auth_failures
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(remote = %client_addr(peer, headers), "rejected read request: missing or invalid token");
    }
    reader
}

fn unauthorized() -> Response {
    let mut resp = error_body(
        StatusCode::UNAUTHORIZED,
        "missing or invalid bearer token",
        &[],
    );
    resp.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    resp
}

async fn reader_agents(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    query: Query<AgentsQuery>,
) -> Response {
    if authorize_reader(&state, peer, &headers).is_none() {
        return unauthorized();
    }
    list_agents(State(state), query).await
}

/// `GET /api/v1/agents/{agent}/events`: the agent's stored events that match
/// the query, oldest first, as JSON lines (`application/x-ndjson`).
async fn export_events(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(agent): Path<String>,
    headers: HeaderMap,
    query: Result<Query<ExportQuery>, QueryRejection>,
) -> Response {
    // Authenticate before looking at anything else in the request.
    let Some(reader) = authorize_reader(&state, peer, &headers) else {
        return unauthorized();
    };
    let query = match query {
        Ok(Query(query)) => query,
        Err(e) => return error_body(StatusCode::BAD_REQUEST, &e.body_text(), &[]),
    };
    if !state.agent_names.contains(&agent) {
        return error_body(StatusCode::NOT_FOUND, "unknown agent", &[]);
    }
    let filter = match ExportFilter::from_query(query) {
        Ok(filter) => filter,
        Err(message) => return error_body(StatusCode::BAD_REQUEST, &message, &[]),
    };
    let Ok(permit) = state.exports.clone().try_acquire_owned() else {
        return Failure::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many exports in progress, retry later",
        )
        .retry_after(10)
        .into_response();
    };

    let dir = state.store.agent_dir(&agent);
    let remote = client_addr(peer, &headers);
    let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(8);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        match export::export(&dir, &filter, |chunk| tx.blocking_send(Ok(chunk)).is_ok()) {
            Ok(stats) => tracing::info!(
                reader = %reader,
                remote = %remote,
                agent = %agent,
                events = stats.events,
                files = stats.files,
                files_skipped = stats.files_skipped,
                summaries_built = stats.summaries_built,
                limit_reached = stats.limit_reached,
                aborted = stats.aborted,
                "events exported"
            ),
            Err(e) => {
                tracing::error!(reader = %reader, agent = %agent, error = %e, "event export failed");
                // Ends the response with an error, so the client sees an
                // incomplete transfer rather than a short but valid one.
                let _ = tx.blocking_send(Err(e));
            }
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::new(ChunkBody { rx }))
        .unwrap_or_else(|_| error_body(StatusCode::INTERNAL_SERVER_ERROR, "internal error", &[]))
}

/// Response body fed by an export running on a blocking thread.
struct ChunkBody {
    rx: mpsc::Receiver<io::Result<Bytes>>,
}

impl http_body::Body for ChunkBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, io::Error>>> {
        self.rx
            .poll_recv(cx)
            .map(|chunk| chunk.map(|result| result.map(http_body::Frame::data)))
    }
}

async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let now = Utc::now();
    let views = state.status.snapshot(now);
    let m = &state.metrics;
    let mut out = String::new();

    let mut metric = |name: &str, kind: &str, help: &str, samples: &[(String, f64)]| {
        let _ = writeln!(out, "# HELP threatfalcon_server_{name} {help}");
        let _ = writeln!(out, "# TYPE threatfalcon_server_{name} {kind}");
        for (labels, value) in samples {
            let _ = writeln!(out, "threatfalcon_server_{name}{labels} {value}");
        }
    };
    let global = |v: f64| vec![(String::new(), v)];
    let per_agent = |f: &dyn Fn(&status::AgentView) -> Option<f64>| -> Vec<(String, f64)> {
        views
            .iter()
            .filter_map(|v| {
                f(v).map(|x| (format!("{{agent=\"{}\"}}", label_value(&v.status.name)), x))
            })
            .collect()
    };

    metric(
        "build_info",
        "gauge",
        "Build information.",
        &[(
            format!(
                "{{version=\"{}\",revision=\"{}\"}}",
                label_value(crate::VERSION),
                label_value(crate::REVISION)
            ),
            1.0,
        )],
    );
    metric(
        "start_time_seconds",
        "gauge",
        "Server start time (Unix seconds).",
        &global(state.started_at.timestamp() as f64),
    );
    metric(
        "auth_failures_total",
        "counter",
        "Ingest requests rejected for a missing or invalid token.",
        &global(m.auth_failures.load(Ordering::Relaxed) as f64),
    );
    metric(
        "reader_requests_total",
        "counter",
        "Requests to the read API.",
        &global(m.reader_requests.load(Ordering::Relaxed) as f64),
    );
    metric(
        "reader_auth_failures_total",
        "counter",
        "Read API requests rejected for a missing or invalid reader token.",
        &global(m.reader_auth_failures.load(Ordering::Relaxed) as f64),
    );
    metric(
        "batches_ok_total",
        "counter",
        "Ingest requests processed successfully.",
        &global(m.batches_ok.load(Ordering::Relaxed) as f64),
    );
    metric(
        "client_errors_total",
        "counter",
        "Authenticated ingest requests rejected with a 4xx status.",
        &global(m.client_errors.load(Ordering::Relaxed) as f64),
    );
    metric(
        "server_errors_total",
        "counter",
        "Ingest requests that failed with a 5xx status.",
        &global(m.server_errors.load(Ordering::Relaxed) as f64),
    );
    if let Ok(free) = state.store.available_bytes() {
        metric(
            "disk_available_bytes",
            "gauge",
            "Free space on the data volume.",
            &global(free as f64),
        );
    }
    metric(
        "agent_up",
        "gauge",
        "1 if the agent's state is ok: data stored within stale_after_secs and its latest request succeeded.",
        &per_agent(&|v| Some(if v.state == "ok" { 1.0 } else { 0.0 })),
    );
    metric(
        "agent_failing",
        "gauge",
        "1 if the agent is in contact but its requests fail (state failing).",
        &per_agent(&|v| Some(if v.state == "failing" { 1.0 } else { 0.0 })),
    );
    metric(
        "agent_last_seen_timestamp_seconds",
        "gauge",
        "Last time a batch from the agent was stored (Unix seconds).",
        &per_agent(&|v| v.status.last_seen.map(|t| t.timestamp() as f64)),
    );
    metric(
        "agent_last_contact_timestamp_seconds",
        "gauge",
        "Last authenticated request from the agent, successful or not (Unix seconds).",
        &per_agent(&|v| v.status.last_contact.map(|t| t.timestamp() as f64)),
    );
    metric(
        "agent_events_total",
        "counter",
        "Events stored for the agent since server start.",
        &per_agent(&|v| Some(v.status.events as f64)),
    );
    metric(
        "agent_duplicate_events_total",
        "counter",
        "Re-sent events that were already stored.",
        &per_agent(&|v| Some(v.status.duplicate_events as f64)),
    );
    metric(
        "agent_quarantined_events_total",
        "counter",
        "Invalid elements written to the agent's quarantine file since server start.",
        &per_agent(&|v| Some(v.status.quarantined_events as f64)),
    );
    metric(
        "agent_batches_total",
        "counter",
        "Requests from the agent processed successfully since server start.",
        &per_agent(&|v| Some(v.status.batches as f64)),
    );
    metric(
        "agent_failed_requests_total",
        "counter",
        "Authenticated requests from the agent that failed since server start.",
        &per_agent(&|v| Some(v.status.failed_requests as f64)),
    );
    metric(
        "agent_received_bytes_total",
        "counter",
        "Request body bytes of successful requests since server start.",
        &per_agent(&|v| Some(v.status.bytes as f64)),
    );

    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response()
}

fn label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
