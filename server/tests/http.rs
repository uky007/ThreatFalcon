//! End-to-end tests over real TCP connections.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use reqwest::StatusCode;
use serde_json::Value;
use tempfile::TempDir;
use threatfalcon_server::app::Server;
use threatfalcon_server::auth::token_sha256_hex;
use threatfalcon_server::config::ServerConfig;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const TOKEN_1: &str = "tfs_1111111111111111111111111111111111111111111111111111111111111111";
const TOKEN_2: &str = "tfs_2222222222222222222222222222222222222222222222222222222222222222";
const AGENT_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const READER_TOKEN: &str = "tfr_3333333333333333333333333333333333333333333333333333333333333333";

struct TestServer {
    dir: TempDir,
    ingest: String,
    admin: String,
    reader: Option<String>,
    client: reqwest::Client,
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<anyhow::Result<()>>>,
}

impl TestServer {
    async fn start(extra: &str) -> Self {
        Self::start_in(TempDir::new().unwrap(), extra).await
    }

    async fn start_in(dir: TempDir, extra: &str) -> Self {
        let text = format!(
            r#"
listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"
data_dir = "data"
{extra}

[[agents]]
name = "lab-ws01"
token_sha256 = "{}"

[[agents]]
name = "lab-ws02"
token_sha256 = "{}"
"#,
            token_sha256_hex(TOKEN_1),
            token_sha256_hex(TOKEN_2)
        );
        let path = dir.path().join("server.toml");
        fs::write(&path, text).unwrap();
        let config = ServerConfig::load(&path).unwrap();
        let server = Server::bind(&config).await.unwrap();
        let ingest = format!("http://{}", server.ingest_addr().unwrap());
        let admin = format!("http://{}", server.admin_addr().unwrap());
        let reader = server.reader_addr().map(|a| format!("http://{a}"));
        let (tx, rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(server.run(async move {
            let _ = rx.await;
        }));
        Self {
            dir,
            ingest,
            admin,
            reader,
            client: reqwest::Client::new(),
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }

    async fn stop(mut self) -> TempDir {
        self.shutdown.take().unwrap().send(()).unwrap();
        self.handle.take().unwrap().await.unwrap().unwrap();
        self.dir
    }

    fn events_path(&self, agent: &str) -> PathBuf {
        self.dir
            .path()
            .join("data/agents")
            .join(agent)
            .join("events.jsonl")
    }

    fn stored(&self, agent: &str) -> String {
        fs::read_to_string(self.events_path(agent)).unwrap_or_default()
    }

    async fn post(&self, token: Option<&str>, body: impl Into<reqwest::Body>) -> reqwest::Response {
        let mut req = self
            .client
            .post(format!("{}/api/v1/events", self.ingest))
            .header("Content-Type", "application/json")
            .body(body);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        req.send().await.unwrap()
    }

    async fn read(&self, path: &str, token: Option<&str>) -> reqwest::Response {
        let base = self.reader.as_ref().expect("reader listener enabled");
        let mut req = self.client.get(format!("{base}{path}"));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        req.send().await.unwrap()
    }

    async fn read_as_reader(&self, path: &str) -> (StatusCode, String) {
        let resp = self.read(path, Some(READER_TOKEN)).await;
        (resp.status(), resp.text().await.unwrap())
    }

    async fn agents(&self) -> Value {
        self.client
            .get(format!("{}/api/v1/agents", self.admin))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn agent(&self, name: &str) -> Value {
        let all = self.agents().await;
        all["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["name"] == name)
            .cloned()
            .unwrap()
    }
}

fn event(n: u32) -> String {
    format!(
        r#"{{"id":"00000000-0000-4000-8000-{n:012}","timestamp":"2026-11-15T00:00:00Z","hostname":"HOST01","agent_id":"{AGENT_ID}","sensor_version":"0.5.0","source":{{"Etw":{{"provider":"Microsoft-Windows-Kernel-Network"}}}},"category":"Network","severity":"Info","data":{{"type":"NetworkConnect","pid":4,"image_path":"","protocol":"TCP","src_addr":"10.0.0.5","src_port":49152,"dst_addr":"93.184.216.34","dst_port":443,"direction":"Outbound"}}}}"#
    )
}

fn health(n: u32, collector_state: &str) -> String {
    format!(
        r#"{{"id":"00000000-0000-4000-9000-{n:012}","timestamp":"2026-11-15T00:01:00Z","hostname":"HOST01","agent_id":"{AGENT_ID}","sensor_version":"0.5.0","source":"Sensor","category":"Health","severity":"Info","data":{{"type":"SensorHealth","uptime_secs":120,"events_total":5000,"events_dropped":0,"collectors":[{{"name":"ETW","state":"{collector_state}"}}],"sink":{{"sink_type":"http","events_dropped":0}}}}}}"#
    )
}

fn batch(events: &[String]) -> String {
    format!("[{}]", events.join(","))
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[tokio::test]
async fn stores_batches_as_jsonl_per_agent() {
    let srv = TestServer::start("").await;
    let events = vec![event(1), event(2)];
    let resp = srv.post(Some(TOKEN_1), batch(&events)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["accepted"], 2);
    assert_eq!(body["duplicates"], 0);
    assert_eq!(body["quarantined"], 0);

    // Byte-identical lines, one per event.
    assert_eq!(
        srv.stored("lab-ws01"),
        format!("{}\n{}\n", events[0], events[1])
    );
    assert!(!srv.events_path("lab-ws02").exists());

    let resp = srv.post(Some(TOKEN_2), batch(&[event(3)])).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(srv.stored("lab-ws02"), format!("{}\n", event(3)));
    assert_eq!(srv.stored("lab-ws01").lines().count(), 2);

    let a1 = srv.agent("lab-ws01").await;
    assert_eq!(a1["state"], "ok");
    assert_eq!(a1["events"], 2);
    assert_eq!(a1["hostname"], "HOST01");
    assert_eq!(a1["agent_id"], AGENT_ID);
    assert_eq!(a1["sensor_version"], "0.5.0");
    assert_eq!(a1["remote_addr"], "127.0.0.1");
    srv.stop().await;
}

#[tokio::test]
async fn decodes_gzip_bodies() {
    let srv = TestServer::start("").await;
    let payload = batch(&[event(1)]);
    let resp = srv
        .client
        .post(format!("{}/api/v1/events", srv.ingest))
        .bearer_auth(TOKEN_1)
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "gzip")
        .body(gzip(payload.as_bytes()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(srv.stored("lab-ws01"), format!("{}\n", event(1)));
    srv.stop().await;
}

#[tokio::test]
async fn rejects_unauthenticated_requests() {
    let srv = TestServer::start("").await;
    let body = batch(&[event(1)]);

    let resp = srv.post(None, body.clone()).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers()["www-authenticate"], "Bearer");

    let resp = srv.post(Some("tfs_wrong"), body.clone()).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = srv
        .client
        .post(format!("{}/api/v1/events", srv.ingest))
        .header("Authorization", format!("Basic {TOKEN_1}"))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    assert!(!srv.events_path("lab-ws01").exists());
    let metrics = srv
        .client
        .get(format!("{}/metrics", srv.admin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("threatfalcon_server_auth_failures_total 3"),
        "{metrics}"
    );
    // Unauthenticated requests do not show up as agent activity.
    assert_eq!(srv.agent("lab-ws01").await["state"], "never_seen");
    srv.stop().await;
}

#[tokio::test]
async fn resent_batch_is_stored_once() {
    let srv = TestServer::start("").await;
    let body = batch(&[event(1), event(2)]);
    assert_eq!(
        srv.post(Some(TOKEN_1), body.clone()).await.status(),
        StatusCode::OK
    );
    let resp = srv.post(Some(TOKEN_1), body).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["accepted"], 0);
    assert_eq!(body["duplicates"], 2);
    // A re-sent batch that overlaps a new one only stores the new events.
    let resp = srv.post(Some(TOKEN_1), batch(&[event(2), event(3)])).await;
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        (body["accepted"].as_u64(), body["duplicates"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(srv.stored("lab-ws01").lines().count(), 3);
    let a = srv.agent("lab-ws01").await;
    assert_eq!(a["events"], 3);
    assert_eq!(a["duplicate_events"], 3);
    srv.stop().await;
}

fn quarantined(srv: &TestServer, agent: &str) -> Vec<Value> {
    fs::read_to_string(
        srv.dir
            .path()
            .join("data/agents")
            .join(agent)
            .join("rejected.jsonl"),
    )
    .unwrap_or_default()
    .lines()
    .map(|l| serde_json::from_str(l).unwrap())
    .collect()
}

#[tokio::test]
async fn quarantines_invalid_elements_instead_of_dropping_them() {
    let srv = TestServer::start("").await;
    let resp = srv
        .post(Some(TOKEN_1), format!("[{},42,{{\"id\":1}}]", event(1)))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["accepted"], 1);
    assert_eq!(body["quarantined"], 2);
    assert_eq!(body["errors"].as_array().unwrap().len(), 2);
    assert_eq!(srv.stored("lab-ws01"), format!("{}\n", event(1)));

    // Nothing the sensor sent is lost: invalid elements are kept verbatim.
    let q = quarantined(&srv, "lab-ws01");
    assert_eq!(q.len(), 2);
    assert_eq!(q[0]["agent"], "lab-ws01");
    assert_eq!(q[0]["index"], 1);
    assert_eq!(q[0]["element"], 42);
    assert_eq!(q[1]["element"], serde_json::json!({"id": 1}));
    assert!(q[1]["reason"].is_string());
    assert!(q[1]["received_at"].is_string());

    let a = srv.agent("lab-ws01").await;
    assert_eq!(a["quarantined_events"], 2);
    assert!(a["warnings"][0]
        .as_str()
        .unwrap()
        .contains("2 invalid events quarantined"));
    srv.stop().await;
}

#[tokio::test]
async fn all_invalid_batch_is_quarantined_and_acknowledged() {
    // Answering 4xx would leave the batch at the head of the agent's spool
    // forever; it is stored in the quarantine instead.
    let srv = TestServer::start("").await;
    let resp = srv.post(Some(TOKEN_1), "[1,2]").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["accepted"], 0);
    assert_eq!(body["quarantined"], 2);
    assert_eq!(quarantined(&srv, "lab-ws01").len(), 2);
    assert!(srv.stored("lab-ws01").is_empty());
    srv.stop().await;
}

#[tokio::test]
async fn maps_bad_input_to_client_errors() {
    let srv = TestServer::start("[limits]\nmax_body_mb = 1\nmax_decompressed_mb = 1\nmax_events_per_batch = 5\nmin_free_disk_mb = 0").await;

    let cases: Vec<(&str, reqwest::RequestBuilder, StatusCode)> = vec![
        (
            "malformed JSON",
            srv.client
                .post(format!("{}/api/v1/events", srv.ingest))
                .body("[{"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "not an array",
            srv.client
                .post(format!("{}/api/v1/events", srv.ingest))
                .body("{}"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "too many events",
            srv.client
                .post(format!("{}/api/v1/events", srv.ingest))
                .body(batch(&(1..=6).map(event).collect::<Vec<_>>())),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            "body too large",
            srv.client
                .post(format!("{}/api/v1/events", srv.ingest))
                .body(vec![b' '; 2 * 1024 * 1024]),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            "gzip bomb",
            srv.client
                .post(format!("{}/api/v1/events", srv.ingest))
                .header("Content-Encoding", "gzip")
                .body(gzip(&vec![b' '; 8 * 1024 * 1024])),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            "invalid gzip",
            srv.client
                .post(format!("{}/api/v1/events", srv.ingest))
                .header("Content-Encoding", "gzip")
                .body("[]"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "unsupported encoding",
            srv.client
                .post(format!("{}/api/v1/events", srv.ingest))
                .header("Content-Encoding", "br")
                .body("[]"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "unsupported content type",
            srv.client
                .post(format!("{}/api/v1/events", srv.ingest))
                .header("Content-Type", "text/plain")
                .body("[]"),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
    ];
    for (name, req, expected) in cases {
        let resp = req.bearer_auth(TOKEN_1).send().await.unwrap();
        assert_eq!(resp.status(), expected, "{name}");
        let body: Value = resp.json().await.unwrap();
        assert!(body["error"].is_string(), "{name}: {body}");
    }
    assert!(!srv.events_path("lab-ws01").exists() || srv.stored("lab-ws01").is_empty());
    let a = srv.agent("lab-ws01").await;
    assert!(a["last_error"].is_string());
    srv.stop().await;
}

#[tokio::test]
async fn refuses_writes_when_disk_is_low_and_reports_the_agent_as_failing() {
    // Require an absurd amount of free space so the check always trips.
    let srv = TestServer::start("[limits]\nmin_free_disk_mb = 1000000000").await;
    for _ in 0..3 {
        let resp = srv.post(Some(TOKEN_1), batch(&[event(1)])).await;
        assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(resp.headers()["retry-after"], "60");
    }
    assert!(srv.stored("lab-ws01").is_empty());

    // The agent keeps retrying, but nothing is stored: not "ok".
    let a = srv.agent("lab-ws01").await;
    assert_eq!(a["state"], "failing");
    assert_eq!(a["failed_requests"], 3);
    assert!(a["last_seen"].is_null());
    assert!(a["last_contact"].is_string());
    let metrics = srv
        .client
        .get(format!("{}/metrics", srv.admin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for expected in [
        "threatfalcon_server_agent_up{agent=\"lab-ws01\"} 0",
        "threatfalcon_server_agent_failing{agent=\"lab-ws01\"} 1",
        "threatfalcon_server_agent_failed_requests_total{agent=\"lab-ws01\"} 3",
        "threatfalcon_server_server_errors_total 3",
    ] {
        assert!(
            metrics.contains(expected),
            "missing {expected:?} in\n{metrics}"
        );
    }
    assert!(!metrics.contains("agent_last_seen_timestamp_seconds{agent=\"lab-ws01\"}"));
    srv.stop().await;
}

#[tokio::test]
async fn agent_directory_removed_while_running_is_recreated() {
    let srv = TestServer::start("").await;
    assert_eq!(
        srv.post(Some(TOKEN_1), batch(&[event(1)])).await.status(),
        StatusCode::OK
    );
    fs::remove_dir_all(srv.dir.path().join("data/agents/lab-ws01")).unwrap();
    let resp = srv.post(Some(TOKEN_1), batch(&[event(2)])).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(srv.stored("lab-ws01"), format!("{}\n", event(2)));
    srv.stop().await;
}

#[tokio::test]
async fn admin_api_is_not_exposed_on_ingest_listener() {
    let srv = TestServer::start("").await;
    for path in ["/api/v1/agents", "/metrics", "/"] {
        let resp = srv
            .client
            .get(format!("{}{path}", srv.ingest))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
    let resp = srv
        .client
        .get(format!("{}/healthz", srv.ingest))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let text = resp.text().await.unwrap();
    assert_eq!(
        text, "ok\n",
        "public health check must not reveal version details"
    );
    let resp = srv
        .client
        .get(format!("{}/api/v1/events", srv.ingest))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    srv.stop().await;
}

#[tokio::test]
async fn admin_endpoints_report_status() {
    let srv = TestServer::start("").await;
    let health_resp: Value = srv
        .client
        .get(format!("{}/healthz", srv.admin))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health_resp["status"], "ok");
    assert_eq!(health_resp["version"], threatfalcon_server::VERSION);
    assert_eq!(health_resp["revision"], threatfalcon_server::REVISION);
    assert_eq!(health_resp["agents_configured"], 2);

    let resp = srv
        .post(Some(TOKEN_1), batch(&[event(1), health(2, "Error")]))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let a = srv.agent("lab-ws01").await;
    assert_eq!(a["health"]["data"]["uptime_secs"], 120);
    assert_eq!(a["warnings"][0], "collector ETW is Error");
    assert_eq!(srv.agent("lab-ws02").await["state"], "never_seen");

    let text = srv
        .client
        .get(format!("{}/api/v1/agents?format=text", srv.admin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        text.contains("lab-ws01") && text.contains("HOST01"),
        "{text}"
    );
    assert!(
        text.contains("! lab-ws01: collector ETW is Error"),
        "{text}"
    );

    let metrics = srv
        .client
        .get(format!("{}/metrics", srv.admin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for expected in [
        "threatfalcon_server_agent_events_total{agent=\"lab-ws01\"} 2",
        "threatfalcon_server_agent_up{agent=\"lab-ws01\"} 1",
        "threatfalcon_server_agent_up{agent=\"lab-ws02\"} 0",
        "threatfalcon_server_batches_ok_total 1",
        "# TYPE threatfalcon_server_disk_available_bytes gauge",
    ] {
        assert!(
            metrics.contains(expected),
            "missing {expected:?} in\n{metrics}"
        );
    }
    srv.stop().await;
}

#[tokio::test]
async fn uses_forwarded_client_address_from_local_proxy() {
    let srv = TestServer::start("").await;
    let resp = srv
        .client
        .post(format!("{}/api/v1/events", srv.ingest))
        .bearer_auth(TOKEN_1)
        .header("X-Forwarded-For", "192.0.2.1, 203.0.113.9")
        .body(batch(&[event(1)]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(srv.agent("lab-ws01").await["remote_addr"], "203.0.113.9");
    srv.stop().await;
}

#[tokio::test]
async fn concurrent_batches_do_not_interleave() {
    let srv = TestServer::start("").await;
    let mut tasks = Vec::new();
    for b in 0..16u32 {
        let client = srv.client.clone();
        let url = format!("{}/api/v1/events", srv.ingest);
        let body = batch(&(0..50).map(|i| event(b * 1000 + i)).collect::<Vec<_>>());
        tasks.push(tokio::spawn(async move {
            client
                .post(url)
                .bearer_auth(TOKEN_1)
                .body(body)
                .send()
                .await
                .unwrap()
                .status()
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), StatusCode::OK);
    }
    let stored = srv.stored("lab-ws01");
    assert_eq!(stored.lines().count(), 800);
    for line in stored.lines() {
        serde_json::from_str::<Value>(line).expect("every line is a complete JSON object");
    }
    srv.stop().await;
}

#[tokio::test]
async fn restart_keeps_data_and_seeds_last_seen() {
    let srv = TestServer::start("").await;
    assert_eq!(
        srv.post(Some(TOKEN_1), batch(&[event(1)])).await.status(),
        StatusCode::OK
    );
    let dir = srv.stop().await;

    let srv = TestServer::start_in(dir, "").await;
    let a = srv.agent("lab-ws01").await;
    assert_eq!(a["state"], "ok");
    assert_eq!(a["seen_since_start"], false);
    assert_eq!(a["events"], 0);
    // The first batch was acknowledged, but suppose the acknowledgement was
    // lost: the sensor re-sends it to the new process.
    let resp = srv.post(Some(TOKEN_1), batch(&[event(1)])).await;
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        (body["accepted"].as_u64(), body["duplicates"].as_u64()),
        (Some(0), Some(1))
    );
    assert_eq!(
        srv.post(Some(TOKEN_1), batch(&[event(2)])).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        srv.stored("lab-ws01"),
        format!("{}\n{}\n", event(1), event(2))
    );
    assert_eq!(srv.agent("lab-ws01").await["seen_since_start"], true);
    srv.stop().await;
}

#[tokio::test]
async fn second_instance_on_same_data_dir_is_refused() {
    let srv = TestServer::start("").await;
    let path = srv.dir.path().join("server.toml");
    let config = ServerConfig::load(&path).unwrap();
    let err = Server::bind(&config).await.err().expect("must fail");
    assert!(format!("{err:#}").contains("locked"), "{err:#}");
    srv.stop().await;
}

fn reader_config() -> String {
    format!(
        "reader_listen = \"127.0.0.1:0\"\n\n[[readers]]\nname = \"laptop\"\ntoken_sha256 = \"{}\"\n",
        token_sha256_hex(READER_TOKEN)
    )
}

#[tokio::test]
async fn reader_listener_is_off_by_default() {
    let srv = TestServer::start("").await;
    assert!(srv.reader.is_none());
    srv.stop().await;
}

#[tokio::test]
async fn read_api_requires_a_reader_token() {
    let srv = TestServer::start(&reader_config()).await;
    // Open, for checking that the port is reachable
    assert_eq!(srv.read("/healthz", None).await.status(), StatusCode::OK);

    let paths = [
        "/api/v1/agents",
        "/api/v1/agents/lab-ws01/events",
        "/api/v1/agents/lab-ws01/events?bogus=1",
    ];
    for token in [None, Some(TOKEN_1), Some("tfr_wrong")] {
        for path in paths {
            let resp = srv.read(path, token).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path} {token:?}");
        }
    }
    // A reader token cannot ingest
    let resp = srv.post(Some(READER_TOKEN), batch(&[event(1)])).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // The read API is not served by the ingest listener
    let resp = srv
        .client
        .get(format!("{}/api/v1/agents/lab-ws01/events", srv.ingest))
        .bearer_auth(READER_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let metrics = srv
        .client
        .get(format!("{}/metrics", srv.admin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains("threatfalcon_server_reader_auth_failures_total 9"),
        "{metrics}"
    );
    srv.stop().await;
}

#[tokio::test]
async fn read_api_exports_stored_events() {
    let srv = TestServer::start(&reader_config()).await;
    let mut events: Vec<String> = (1..=5).map(event).collect();
    assert_eq!(
        srv.post(Some(TOKEN_1), batch(&events)).await.status(),
        StatusCode::OK
    );
    let health = health(9, "Running");
    assert_eq!(
        srv.post(Some(TOKEN_1), batch(std::slice::from_ref(&health)))
            .await
            .status(),
        StatusCode::OK
    );
    events.push(health.clone());

    let resp = srv
        .read("/api/v1/agents/lab-ws01/events", Some(READER_TOKEN))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "application/x-ndjson");
    let all: String = events.iter().map(|e| format!("{e}\n")).collect();
    assert_eq!(resp.text().await.unwrap(), all);

    let base = "/api/v1/agents/lab-ws01/events";
    assert_eq!(
        srv.read_as_reader(&format!("{base}?category=health"))
            .await
            .1,
        format!("{health}\n")
    );
    assert_eq!(
        srv.read_as_reader(&format!("{base}?limit=2"))
            .await
            .1
            .lines()
            .count(),
        2
    );
    assert_eq!(
        srv.read_as_reader(&format!("{base}?from=2026-11-15T00:00:30Z"))
            .await
            .1,
        format!("{health}\n")
    );
    assert_eq!(
        srv.read_as_reader(&format!("{base}?contains=8000-000000000003"))
            .await
            .1,
        format!("{}\n", event(3))
    );
    assert_eq!(
        srv.read_as_reader(&format!("{base}?min_severity=Medium"))
            .await
            .1,
        ""
    );
    assert_eq!(
        srv.read_as_reader(&format!("{base}?detections=true"))
            .await
            .1,
        ""
    );
    assert_eq!(
        srv.read_as_reader(&format!("{base}?min_severity=info&limit=1"))
            .await
            .1,
        format!("{}\n", event(1))
    );
    // A configured agent without data
    assert_eq!(
        srv.read_as_reader("/api/v1/agents/lab-ws02/events").await,
        (StatusCode::OK, String::new())
    );
    // Errors, once authenticated
    for path in [
        "/api/v1/agents/nobody/events",
        "/api/v1/agents/%2e%2e/events",
    ] {
        assert_eq!(
            srv.read_as_reader(path).await.0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    for query in ["bogus=1", "from=yesterday", "limit=0", "category=File%3B"] {
        assert_eq!(
            srv.read_as_reader(&format!("{base}?{query}")).await.0,
            StatusCode::BAD_REQUEST,
            "{query}"
        );
    }

    // Agent status through the read API
    let (status, body) = srv.read_as_reader("/api/v1/agents").await;
    assert_eq!(status, StatusCode::OK);
    let agents: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(agents["agents"].as_array().unwrap().len(), 2);
    assert!(srv
        .read_as_reader("/api/v1/agents?format=text")
        .await
        .1
        .contains("lab-ws01"));
    srv.stop().await;
}
