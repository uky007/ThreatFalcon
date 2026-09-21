#!/usr/bin/env python3
"""Bounded live capture/readback validation; runs as an ordinary user.

The separate admin wrapper supplies a protected sensor with CAP_AUDIT_READ,
two narrowly scoped transient audit rules, and a private writable data directory.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import json
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_events(path, live=False):
    if not path.exists():
        return []
    raw = path.read_bytes()
    if live and not raw.endswith(b"\n"):
        raw = raw[:raw.rfind(b"\n") + 1]
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def field(record, name):
    return record.get("fields", {}).get(name, {}).get("value")


def audit(event):
    return event.get("data", {}).get("record") if event.get("source") == "LinuxAudit" else None


def syscall_record(event):
    records = (audit(event) or {}).get("records", [])
    syscalls = [r for r in records if r["native_type"] == 1300]
    return syscalls[0] if len(syscalls) == 1 else {}


def collector(event):
    return next((c for c in event.get("data", {}).get("collectors", [])
                 if c["name"] == "LinuxAudit"), None)


def run_cli(binary, data, name, *arguments):
    result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True,
                            text=True, timeout=20)
    (data / f"{name}.stdout").write_text(result.stdout)
    (data / f"{name}.stderr").write_text(result.stderr)
    require(result.returncode == 0, f"{name} failed: {result.stderr[-1000:]}")
    return result


def stop_sensor(process):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            return process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise RuntimeError("Sensor did not stop within ten seconds")
    return process.returncode


def capture_round(args, number, expected, arg_marker, env_marker):
    data = args.data
    output = data / "events.jsonl"
    before = len(read_events(output))
    began = time.monotonic()
    with (data / f"sensor-{number}.log").open("w") as log:
        sensor = subprocess.Popen([str(args.binary), "--config", str(args.config)],
                                  stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 8
            while True:
                require(sensor.poll() is None, "Sensor exited before a running-health record")
                fresh = read_events(output, live=True)[before:]
                if any((collector(e) or {}).get("state") == "Running" for e in fresh):
                    break
                require(time.monotonic() < deadline, "No running-health record within eight seconds")
                time.sleep(0.05)

            def launch_true(_):
                env = dict(os.environ, TF_VALIDATION_ENV=env_marker)
                child = subprocess.Popen(["/bin/true", arg_marker], env=env)
                require(child.wait(timeout=5) == 0, "Benign exec failed")
                return {"kind": "exec", "pid": child.pid, "round": number}

            for i in range(8 if number == 1 else 5):
                expected.append(launch_true(i))
            if number == 1:
                with ThreadPoolExecutor(max_workers=4) as pool:
                    expected.extend(pool.map(launch_true, range(32)))
            for i in range(3 if number == 1 else 1):
                work = data / f"work-{number}-{i}"
                work.mkdir(mode=0o700)
                result = subprocess.run([str(args.workload), str(work)], capture_output=True,
                                        text=True, timeout=5)
                require(result.returncode == 0, f"Workload failed: {result.stderr}")
                observations = [json.loads(line) for line in result.stdout.splitlines()]
                require(len(observations) == 6, "Workload did not report all six operations")
                expected.extend(dict(e, round=number, directory=str(work)) for e in observations)
            (data / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
            # Allow periodic file flushing and the collector's two-second assembly timeout.
            time.sleep(2.5)
        finally:
            exit_code = stop_sensor(sensor)
    require(exit_code == 0, f"Sensor round {number} exited {exit_code}")
    fresh = read_events(output)[before:]
    health = [e for e in fresh if collector(e) is not None]
    require(health and collector(health[-1])["state"] == "Stopped", "Missing stopped final health")
    for event in health:
        c = collector(event)
        require(c["state"] in ("Running", "Stopped"), "Collector reported an error")
        require(event["data"]["events_dropped"] == 0, "Output/channel drop reported")
        for counter in ("queue_events_dropped", "events_lost_before_queue", "decode_failures"):
            require(c.get(counter, 0) == 0, f"Collector {counter} was nonzero")
        stats = c.get("linux_audit", {})
        for counter in ("malformed_records", "malformed_datagrams", "socket_overruns",
                        "truncated_datagrams", "events_without_eoe", "capacity_flushes", "late_records"):
            require(stats.get(counter, 0) == 0, f"Linux collector {counter} was nonzero")
    sessions = {audit(e)["collection_session_uuid"] for e in fresh if audit(e)}
    require(len(sessions) == 1, "Expected one live collection session in each run")
    return {"round": number, "elapsed_seconds": round(time.monotonic() - began, 3),
            "session": next(iter(sessions)), "total_saved_events": len(fresh),
            "final_health": health[-1]["data"]}


def check_expected(events, expected, key, boot_id):
    selected = []
    for item in expected:
        candidates = []
        for event in events:
            record = audit(event)
            if not record:
                continue
            sc = syscall_record(event)
            if field(sc, "pid") != str(item["pid"]) or field(sc, "key") != key:
                continue
            if item["kind"] == "exec":
                if not any(r["native_type"] == 1309 for r in record["records"]):
                    continue
            else:
                if field(sc, "syscall") != str(item["syscall"]):
                    continue
                names = {item["path"], str(Path(item["directory"]) / item["path"])}
                if item["path"] and not any(r["native_type"] == 1302 and
                        field(r, "name") in names for r in record["records"]):
                    continue
            candidates.append(event)
        require(len(candidates) == 1, f"Expected exactly one event for {item}; got {len(candidates)}")
        event = candidates[0]
        record = audit(event)
        sc = syscall_record(event)
        require(record["completion"] == "end_of_event" and not record["issues"], "Incomplete event")
        require(all(not r["issues"] for r in record["records"]), "Native record quality issue")
        require(record["boot_id"] == boot_id, "Boot identity mismatch")
        require(record["transport"] == "netlink_multicast", "Unexpected transport")
        require(not event.get("process_context"), "Unverified Linux process context was attached")
        if item["kind"] == "exec":
            require(field(sc, "success") == "yes", "Exec was not successful")
            execve = next(r for r in record["records"] if r["native_type"] == 1309)
            require(field(execve, "argc") == "2", "Exec argument count not preserved")
        else:
            require(field(sc, "success") == ("yes" if item["success"] else "no"), "Wrong syscall success")
            require(field(sc, "exit") == str(item["exit"]), "Wrong syscall result")
            if item["saddr"]:
                require(any(r["native_type"] == 1306 and
                        (field(r, "saddr") or "").lower() == item["saddr"] for r in record["records"]),
                        "Loopback sockaddr bytes not preserved")
        selected.append(event)
    require(len({e["id"] for e in selected}) == len(expected), "One event matched multiple operations")
    return selected


def validate(args):
    require(os.geteuid() != 0, "Run the workload and sensor as an ordinary user")
    os.umask(0o077)
    require(not (args.data / "events.jsonl").exists(), "Use a fresh data directory")
    arg_marker = "TF_ARG_" + uuid.uuid4().hex
    env_marker = "TF_ENV_" + uuid.uuid4().hex
    expected = []
    rounds = [capture_round(args, 1, expected, arg_marker, env_marker)]
    offline_child = subprocess.Popen(["/bin/true", arg_marker])
    require(offline_child.wait(timeout=5) == 0, "Between-runs exec failed")
    rounds.append(capture_round(args, 2, expected, arg_marker, env_marker))
    output = args.data / "events.jsonl"
    events = read_events(output)
    raw = output.read_text()
    (args.data / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    selected = check_expected(events, expected, args.key, boot_id)
    require(rounds[0]["session"] != rounds[1]["session"], "Session identity was reused after restart")
    require(len({e["agent_id"] for e in events}) == 1, "Agent identity was not stable")
    require(all(field(syscall_record(e), "pid") != str(offline_child.pid) for e in events),
            "Unexpected replay of between-runs event")
    for marker in (arg_marker, env_marker):
        require(marker not in raw and marker.encode().hex() not in raw.lower(), "Private marker was persisted")
    for event in events:
        for record in (audit(event) or {}).get("records", []):
            names = set(record["fields"])
            if record["native_type"] == 1300:
                require(not names.intersection({"a0", "a1", "a2", "a3"}), "Raw syscall argument persisted")
            elif record["native_type"] == 1309:
                require(names <= {"argc"}, "EXECVE argument value persisted")
            elif record["native_type"] == 1327:
                require(not names, "PROCTITLE value persisted")

    # Persist completed live checks before offline CLI checks, so a retry needs no sudo.
    capture = {"rounds": rounds, "boot_id": boot_id, "key": args.key,
               "outage_pid": offline_child.pid,
               "outage_event_not_replayed": True, "argv_and_environment_markers_omitted": True}
    (args.data / "capture.json").write_text(json.dumps(capture, indent=2) + "\n")
    saved_count = check_readback(args.binary, args.data, args.data, events, expected, selected)
    summary = {"passed": True, "expected_operations": len(expected),
               "operations": dict(Counter(item["kind"] for item in expected)),
               "matched_operations": len(selected), "saved_linux_events": saved_count,
               "output_bytes": output.stat().st_size, "rounds": rounds,
               "outage_event_not_replayed": True, "argv_and_environment_markers_omitted": True,
               "scan_and_indexed_readback_match": True,
               "scope": "bounded functional test, four-worker exec burst; not sustained-load or losslessness proof"}
    (args.data / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


def check_readback(binary, data, reports, events, expected, selected):
    """Read existing capture data; create/update only the optional index and reports."""
    output = data / "events.jsonl"
    expected_audit = {e["id"]: e for e in events if audit(e)}
    for indexed in (False, True):
        if indexed:
            # query reuses an existing index; it deliberately does not create one.
            run_cli(binary, reports, "index-build", "index", "--input", output)
        arguments = ["query", "--input", output, "--source", "linuxaudit", "--limit", "10000"]
        if not indexed:
            arguments.append("--no-index")
        result = run_cli(binary, reports, f"query-{indexed}", *arguments)
        found = [json.loads(line) for line in result.stdout.splitlines()]
        require(len(found) == len(expected_audit) and {e["id"]: e for e in found} == expected_audit,
                "Query changed or omitted saved records")
        if indexed:
            require("(indexed)" in result.stderr, "Indexed query silently fell back to a scan")
    target = selected[0]
    for indexed in (False, True):
        arguments = ["query", "--input", output, "--source", "linuxaudit", "--pid",
                     str(expected[0]["pid"]), "--limit", "10000"]
        if not indexed:
            arguments.append("--no-index")
        result = run_cli(binary, reports, f"pid-query-{indexed}", *arguments)
        found = [json.loads(line) for line in result.stdout.splitlines()]
        require({e["id"] for e in found} == {target["id"]}, "PID query mismatch")
        if indexed:
            require("(indexed)" in result.stderr, "PID query did not use the index")
        arguments = ["explain", "--input", output, "--event", target["id"], "--json"]
        if not indexed:
            arguments.append("--no-index")
        explanation = json.loads(run_cli(binary, reports, f"explain-{indexed}", *arguments).stdout)
        require(explanation["target_event"] == target, "Explain changed original evidence")
        require(not explanation.get("process_key"), "Explain invented a process-lifetime key")
    for command in ("health", "analyze"):
        for language in ("ja", "en"):
            run_cli(binary, reports, f"{command}-{language}", command,
                    "--input", output, "--lang", language)
    report = json.loads(run_cli(binary, reports, "analysis-json", "analyze",
                                "--input", output, "--json").stdout)
    require(report["malformed_lines"] == 0, "Analyzer found malformed saved JSONL")
    require("linux_detection_rules_not_implemented" in report["limitations"], "Missing Linux limitation")
    require(not report["findings"], "Unexpected Linux threat finding from a collector-only test")
    run_cli(binary, reports, "index-status", "index", "--input", output, "--status")
    return len(expected_audit)


def verify_existing(args):
    """Resume evidence/readback checks without capture privileges or replacing logs."""
    require(os.geteuid() != 0, "Use an ordinary user for saved evidence")
    os.umask(0o077)
    output = args.data / "events.jsonl"
    before_hash = hashlib.sha256(output.read_bytes()).hexdigest()
    expected_path = args.data / "expected.json"
    expected_hash = hashlib.sha256(expected_path.read_bytes()).hexdigest()
    events = read_events(output)
    expected = json.loads(expected_path.read_text())
    require(bool(expected), "Saved workload ground truth is empty")
    pids = {str(item["pid"]) for item in expected}
    keys = {field(syscall_record(e), "key") for e in events if field(syscall_record(e), "pid") in pids}
    boots = {audit(e)["boot_id"] for e in events if audit(e)}
    sessions = {audit(e)["collection_session_uuid"] for e in events if audit(e)}
    require(len(keys) == 1 and None not in keys, "Expected one workload rule key")
    require(len(boots) == 1 and None not in boots, "Expected one captured boot identity")
    require(len(sessions) == 2 and all(uuid.UUID(s).int != 0 for s in sessions), "Expected two capture identities")
    selected = check_expected(events, expected, next(iter(keys)), next(iter(boots)))
    require(len({e["agent_id"] for e in events}) == 1, "Saved agent identity changed")
    stopped = [e for e in events if (collector(e) or {}).get("state") == "Stopped"]
    require(len(stopped) == 2, "Missing stopped health for one of the sensor runs")
    for event in events:
        c = collector(event)
        if c:
            require(c["state"] in ("Running", "Stopped"), "Saved collector error")
            require(event["data"]["events_dropped"] == 0, "Saved output/channel drop")
            require(all(c.get(n, 0) == 0 for n in
                        ("queue_events_dropped", "events_lost_before_queue", "decode_failures")), "Saved collector error counter")
            require(all(c.get("linux_audit", {}).get(n, 0) == 0 for n in
                        ("malformed_records", "malformed_datagrams", "socket_overruns", "truncated_datagrams",
                         "events_without_eoe", "capacity_flushes", "late_records")), "Saved Linux quality counter")
        for r in (audit(event) or {}).get("records", []):
            names = set(r["fields"])
            if r["native_type"] == 1300:
                require(not names.intersection({"a0", "a1", "a2", "a3"}), "Saved syscall arguments")
            elif r["native_type"] == 1309:
                require(names <= {"argc"}, "Saved EXECVE arguments")
            elif r["native_type"] == 1327:
                require(not names, "Saved PROCTITLE value")
    reports = Path(tempfile.mkdtemp(prefix="readback-", dir=args.data))
    print(f"Readback reports: {reports}", flush=True)
    count = check_readback(args.binary, args.data, reports, events, expected, selected)
    require(hashlib.sha256(output.read_bytes()).hexdigest() == before_hash, "Original capture changed")
    require(hashlib.sha256(expected_path.read_bytes()).hexdigest() == expected_hash, "Workload ground truth changed")
    manifest = args.data / "capture.json"
    capture = json.loads(manifest.read_text()) if manifest.exists() else None
    if capture:
        require(capture["boot_id"] in boots and capture["key"] in keys, "Capture manifest identity mismatch")
        require(all(field(syscall_record(e), "pid") != str(capture["outage_pid"]) for e in events),
                "Between-runs event was replayed")
    summary = {"passed": True, "mode": "saved_capture_readback", "expected_operations": len(expected),
               "operations": dict(Counter(item["kind"] for item in expected)), "matched_operations": len(selected),
               "saved_linux_events": count, "saved_health_events": len(events) - count,
               "output_bytes": output.stat().st_size, "capture_sha256": before_hash,
               "ground_truth_sha256": expected_hash, "capture_sessions": len(sessions),
               "clean_stops": len(stopped), "scan_and_indexed_readback_match": True,
               "original_capture_and_ground_truth_unchanged": True,
               "capture_manifest_available": capture is not None,
               "scope": "saved evidence and offline CLI; does not repeat live collection or original private-sentinel checks"}
    (reports / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--workload", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--key")
    parser.add_argument("--verify-existing", action="store_true",
                        help="Verify saved capture/ground truth and finish CLI checks without sudo")
    args = parser.parse_args()
    # Let timeout-triggered termination run the sensor cleanup path.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    if args.verify_existing:
        verify_existing(args)
    else:
        require(args.workload is not None and args.config is not None and args.key,
                "Live mode requires --workload, --config and --key")
        validate(args)


if __name__ == "__main__":
    main()
