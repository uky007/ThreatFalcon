#!/usr/bin/env python3
"""Local-only Linux HTTPS trust, name-validation and spool-recovery check.

Uses only startup/final health with every collector disabled. Trust settings
apply to the child process, never to the host's certificate store.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def openssl(root, *args):
    result = subprocess.run(["openssl", *args], cwd=root, capture_output=True, text=True, timeout=20)
    require(result.returncode == 0, result.stderr)


def make_ca(root, name):
    openssl(root, "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
            "-subj", f"/CN=ThreatFalcon-validation-{name}", "-addext", "basicConstraints=critical,CA:TRUE",
            "-keyout", f"{name}.key", "-out", f"{name}.crt")


def make_server_cert(root, name, address):
    openssl(root, "req", "-new", "-newkey", "rsa:2048", "-noenc", "-subj", "/CN=loopback-validation",
            "-keyout", f"{name}.key", "-out", f"{name}.csr")
    (root / f"{name}.ext").write_text(
        f"subjectAltName=IP:{address}\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
    )
    openssl(root, "x509", "-req", "-in", f"{name}.csr", "-CA", "trusted.crt", "-CAkey", "trusted.key",
            "-CAcreateserial", "-days", "1", "-extfile", f"{name}.ext", "-out", f"{name}.crt")


def start_server(root, name, received):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers.get("Content-Length", "0"))
            require(0 < size <= 1024 * 1024, "Unexpected request size")
            batch = json.loads(self.rfile.read(size))
            received.extend(batch)
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / f"{name}.crt", root / f"{name}.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def config(root, name, port):
    path = root / f"{name}.toml"
    path.write_text(
        f'hostname = "https-validation"\nstate_path = "{name}.state"\nhealth_interval_secs = 0\n'
        f'[output]\ntype = "http"\nurl = "https://127.0.0.1:{port}/health"\n'
        f'batch_size = 1\ntimeout_secs = 2\nretry_count = 1\nspool_dir = "{name}-spool"\n'
        'spool_max_mb = 1\n' + "".join(f"[collectors.{c}]\nenabled = false\n" for c in
            ("linux_audit", "macos", "etw", "sysmon", "wfp_audit", "evasion"))
    )
    return path


def run(binary, root, name, configuration, trust):
    env = dict(os.environ, SSL_CERT_FILE=str(root / f"{trust}.crt"),
               SSL_CERT_DIR=str(root / "empty-ca-dir"), NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    result = subprocess.run([str(binary), "--config", str(configuration)], env=env,
                            capture_output=True, text=True, timeout=20)
    (root / f"{name}.log").write_text(f"exit_code={result.returncode}\n{result.stdout}{result.stderr}")
    require(result.returncode == 0, f"Sensor did not preserve health delivery/spool: {result.stderr}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output-parent", required=True, type=Path)
    args = parser.parse_args()
    require(os.geteuid() != 0, "No administrator privileges are needed")
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="https-validation.", dir=args.output_parent)).resolve()
    print(f"HTTPS artifacts: {root}", flush=True)
    (root / "empty-ca-dir").mkdir(mode=0o700)
    make_ca(root, "trusted")
    make_ca(root, "unrelated")
    make_server_cert(root, "correct-address", "127.0.0.1")
    make_server_cert(root, "wrong-address", "127.0.0.2")
    received, wrong_received = [], []
    server, thread = start_server(root, "correct-address", received)
    wrong_server, wrong_thread = start_server(root, "wrong-address", wrong_received)
    try:
        cfg = config(root, "recovery", server.server_port)
        run(args.binary, root, "untrusted-ca", cfg, "unrelated")
        require(not received, "Server received health despite untrusted CA")
        pending = list((root / "recovery-spool").glob("*.spool"))
        require(len(pending) == 2, "Expected both health records to be spooled on trust failure")
        queued = [e for path in pending for e in json.loads(path.read_text())]
        run(args.binary, root, "trusted-and-recovered", cfg, "trusted")
        require(len(received) == 4, "Expected two new and two recovered health records")
        counts = Counter(e["id"] for e in received)
        require(all(counts[e["id"]] == 1 for e in queued), "Spool replay lost or duplicated records")
        require(not list((root / "recovery-spool").glob("*.spool")), "Delivered spool was not drained")
        wrong_cfg = config(root, "name-mismatch", wrong_server.server_port)
        run(args.binary, root, "trusted-ca-wrong-name", wrong_cfg, "trusted")
        require(not wrong_received, "Server received health despite certificate address mismatch")
        require(len(list((root / "name-mismatch-spool").glob("*.spool"))) == 2,
                "Name-mismatch health was not retained")
        require(all(e["data"]["type"] == "SensorHealth" and e["data"]["events_total"] == 0
                    for e in received), "Unexpected live telemetry in HTTPS test")
        require(all(c["state"] == "Disabled" for e in received for c in e["data"]["collectors"]),
                "A collector was enabled during HTTPS testing")
        summary = {"passed": True, "trusted_ca_delivered": True, "untrusted_ca_rejected": True,
                   "certificate_address_mismatch_rejected": True,
                   "spooled_health_recovered_exactly_once_in_this_run": len(queued),
                   "received_health_records": len(received),
                   "scope": "loopback only; per-process SSL_CERT_FILE; no OS trust-store edits or live collection"}
        (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2), flush=True)
    finally:
        for service, worker in ((server, thread), (wrong_server, wrong_thread)):
            service.shutdown()
            service.server_close()
            worker.join(timeout=3)


if __name__ == "__main__":
    main()
