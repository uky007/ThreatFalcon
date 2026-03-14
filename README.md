# ThreatFalcon

[![crates.io](https://img.shields.io/crates/v/threatfalcon.svg)](https://crates.io/crates/threatfalcon)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

ThreatFalcon is an experimental Windows endpoint telemetry sensor written in Rust.

The project is aimed at a transparent, explainable, open source sensor that collects host telemetry and normalizes it into structured JSONL events.

## Status

ThreatFalcon is early-stage software.

- Windows is the primary target platform
- ETW collection is implemented
- Sysmon subscription and parsing are implemented, but disabled by default
- Evasion-oriented signal collection is implemented for selected techniques
- Sensor health events are available for local runtime visibility
- Configuration is loaded from `threatfalcon.toml` (TOML format), overridable via `--config`
- Output supports file, stdout, and HTTP POST sinks
- Windows service mode is supported (SCM start/stop via `--service` flag)
- Process context enrichment provides stable process identity across PID reuse
- Local investigation CLI (`query`, `explain`, `bundle`, `stats`, `tail`, `tree`, `inspect`, `ioc`, `hunt`, `score`) reads JSONL output directly
- Optional SQLite index for fast lookups on large JSONL files (transparent fallback to full scan)
- The event schema and collector behavior may still change

## Goals

- Keep the sensor small and auditable
- Use straightforward event models instead of opaque binaries
- Emit machine-readable events that are easy to inspect and test
- Prefer explicit collection and signal logic over black-box behavior
- Maintain a single normalized event model across collection sources

## Current Capabilities

ThreatFalcon currently emits normalized telemetry for:

- process events
- file events
- network events
- registry events
- image load events
- DNS events
- script-related events (PowerShell ScriptBlock with path/ID correlation, AMSI scan with result classification)
- evasion-oriented signal events for selected techniques
- sensor health events (periodic heartbeat with uptime, throughput, and collector status)

It currently collects from:

- ETW
- Sysmon
- an in-process evasion-oriented signal collector

ThreatFalcon normalizes these inputs into a unified `ThreatEvent` model for downstream inspection and comparison.

## Default Behavior

The built-in default configuration currently does the following:

- writes events to `threatfalcon_events.jsonl`
- rotates output at `100 MB`
- enables ETW collection
- disables Sysmon collection by default
- enables evasion-oriented checks
- emits periodic health events every 60 seconds by default
- disk spool for the HTTP sink is disabled by default (opt-in via `spool_dir`)

By default, ThreatFalcon writes events locally only and does not transmit telemetry to a remote service.

### Windows Default Paths

On Windows, when no config file is found, all data paths default under `%ProgramData%\ThreatFalcon\` (typically `C:\ProgramData\ThreatFalcon\`):

| File | Default path (Windows) | Default path (dev / non-Windows) |
|------|------------------------|----------------------------------|
| Config file | `%ProgramData%\ThreatFalcon\threatfalcon.toml` | `./threatfalcon.toml` |
| Agent state | `%ProgramData%\ThreatFalcon\threatfalcon.state` | `./threatfalcon.state` |
| Event output | `%ProgramData%\ThreatFalcon\threatfalcon_events.jsonl` | `./threatfalcon_events.jsonl` |

Config file lookup order (when `--config` is not specified):

1. `./threatfalcon.toml` (current working directory)
2. `%ProgramData%\ThreatFalcon\threatfalcon.toml` (Windows only)
3. Built-in defaults if neither exists

Relative paths in the config file are resolved against the config file's directory, not the process working directory. This ensures consistent behavior between foreground mode and Windows service mode (where cwd is typically `System32`). Explicit absolute paths in the config are never rewritten.

When the HTTP sink is configured with `spool_dir`, failed batches are written to disk instead of dropped. Spooled batches are re-sent on the next successful POST or periodic health flush (every `health_interval_secs`), whichever comes first. This prevents event loss during network outages or server maintenance. Spool size is capped by `spool_max_mb` (default: 256 MB).

The default ETW provider set includes:

- `Microsoft-Windows-Kernel-Process`
- `Microsoft-Windows-Kernel-File`
- `Microsoft-Windows-Kernel-Network`
- `Microsoft-Windows-Kernel-Registry`
- `Microsoft-Windows-DNS-Client`
- `Microsoft-Windows-PowerShell`
- `Microsoft-Antimalware-Scan-Interface`
- `Microsoft-Windows-Threat-Intelligence`

## Architecture

ThreatFalcon is split into a small number of clear components:

- `src/sensor.rs`: collector lifecycle, event channel, shutdown handling
- `src/events.rs`: unified event schema (`ThreatEvent`, `ProcessContext`)
- `src/process_cache.rs`: in-memory process context cache and enrichment
- `src/output.rs`: sink abstraction (file, stdout, HTTP POST)
- `src/collectors/etw.rs`: ETW real-time session and event mapping
- `src/collectors/sysmon.rs`: Sysmon Event Log subscription
- `src/collectors/sysmon_parser.rs`: Sysmon XML parsing and mapping
- `src/pe.rs`: cross-platform PE header parser (sections, imports, exports)
- `src/investigate.rs`: local investigation CLI (query, explain, bundle)
- `src/collectors/evasion.rs`: evasion-oriented process inspection

## Build

Requirements:

- Rust stable
- Windows for real sensor execution

Build locally:

```bash
cargo build --release
```

Run tests:

```bash
cargo test
```

Cross-check Windows compilation from another platform:

```bash
cargo check --target x86_64-pc-windows-msvc
```

## Run

ThreatFalcon is intended to run on Windows.

```bash
cargo run --release
```

### CLI Options

```
threatfalcon [OPTIONS] [COMMAND]

Commands:
  query    Query events from a JSONL telemetry file
  explain  Explain an event with its process context timeline
  bundle   Bundle an event and related context into a single JSON document
  index    Build or manage the SQLite index for fast event lookups
  stats    Show summary statistics for a JSONL telemetry file
  tail     Follow new events appended to a JSONL file (like tail -f)
  tree     Show process tree (parent-child relationships)
  inspect  Inspect a PE file: headers, sections, imports, and exports
  ioc      Extract indicators of compromise (IPs, domains, hashes)
  hunt     Run threat hunting rules against events
  score    Score processes by threat signals (detections, network, LOLBins, etc.)

Options:
  --config <PATH>       Path to config file (default: threatfalcon.toml)
  --stdout              Force output to stdout (overrides config file)
  --output <PATH>       Override output file path (overrides config file)
  --validate-config     Validate config and exit
  --dump-default-config Dump default config as TOML and exit
  --service             Run as a Windows service (used by SCM)
  --install-service     Install as a Windows service and exit
  --uninstall-service   Uninstall the Windows service and exit
  -h, --help            Print help
  -V, --version         Print version
```

Examples:

```bash
# Run with a custom config file
cargo run --release -- --config /path/to/config.toml

# Output events to stdout for quick inspection
cargo run --release -- --stdout

# Write events to a specific file
cargo run --release -- --output /var/log/threatfalcon.jsonl

# Validate a config file without starting the sensor
cargo run --release -- --config myconfig.toml --validate-config

# Dump the built-in default config
cargo run --release -- --dump-default-config > threatfalcon.toml
```

Logging can be controlled with `RUST_LOG`:

```bash
RUST_LOG=info cargo run --release
```

On startup, the sensor initializes enabled collectors, writes newline-delimited JSON events, and stops on `Ctrl-C`.

### Windows Service

ThreatFalcon can run as a Windows service. The `--service` flag connects to the Service Control Manager (SCM) so the sensor starts at boot and stops cleanly on service stop commands.

**Recommended directory layout:**

```
C:\ProgramData\ThreatFalcon\
    threatfalcon.toml              # config
    threatfalcon.state             # agent identity (auto-created)
    threatfalcon_events.jsonl      # event output (file sink)
```

**Install the service:**

```powershell
# Copy the binary
Copy-Item threatfalcon.exe C:\ProgramData\ThreatFalcon\threatfalcon.exe

# Install (config is auto-discovered from ProgramData)
.\threatfalcon.exe --install-service

# Or with a custom config path baked into the service registration
.\threatfalcon.exe --install-service --config C:\ProgramData\ThreatFalcon\threatfalcon.toml
```

`--install-service` registers ThreatFalcon with the Service Control Manager as an auto-start service running as LocalSystem. Equivalent to `sc.exe create` but with correct binary path and arguments.

**Start / stop:**

```powershell
sc.exe start ThreatFalcon
sc.exe stop ThreatFalcon
```

**Remove the service:**

```powershell
.\threatfalcon.exe --uninstall-service
```

`--uninstall-service` stops the service if it is running, polls SCM until the service reaches `Stopped` state (up to 30 seconds), then removes it from SCM.

**Service state transitions:**

```
StartPending → Running → StopPending → Stopped
```

- `StartPending` (wait_hint: 10s): config loading, logging init, sensor creation
- `Running`: event loop active, accepting `Stop` control
- `StopPending` (wait_hint: 15s): reported when SCM sends Stop, before sensor begins flushing sinks and writing final health event
- `Stopped`: exit code distinguishes success (0), config error (1), runtime error (2)

Notes:

- Service mode refuses the `stdout` sink (there is no console) — use `file` or `http`
- `--service`, `--install-service`, and `--uninstall-service` are only available on Windows; on other platforms they exit with an error
- Service exit codes match foreground mode: 0 = success, 1 = config error, 2 = runtime error

## Configuration

ThreatFalcon searches for `threatfalcon.toml` in the current directory first, then `%ProgramData%\ThreatFalcon\` on Windows. If no file is found, built-in defaults are used. Use `--config <path>` to load from a different location, or `--stdout` / `--output <path>` to override the output destination from the command line.

Relative paths (`state_path`, `output.path`, `output.spool_dir`) are resolved against the config file's directory. When using built-in defaults (no config file), they are resolved against the executable's directory.

All sections are optional. Only the fields you want to override need to be specified.

```toml
# Override hostname (default: auto-detected from environment)
hostname = "WORKSTATION-01"

# Periodic health event interval in seconds (default: 60, 0 = periodic disabled)
# A final shutdown health event is always emitted regardless of this setting.
health_interval_secs = 60

# Path to persistent agent state file.
# A stable agent_id is generated on first run and reused across restarts.
# Default: "threatfalcon.state" (relative to config dir; on Windows defaults
# to %ProgramData%\ThreatFalcon\threatfalcon.state)
# state_path = "threatfalcon.state"

# Output sink type: "file" (default), "stdout", or "http"
[output]
# type = "file"
path = "threatfalcon_events.jsonl"
rotation_size_mb = 100
# type = "stdout"
# pretty = true
# type = "http"
# url = "https://example.com/api/events"
# batch_size = 100
# timeout_secs = 10
# bearer_token = "your-token-here"
# retry_count = 3
# retry_backoff_ms = 100
# gzip = false
# spool_dir = "spool"
# spool_max_mb = 256
# [output.headers]
# X-Sensor-Id = "sensor-001"
# X-Api-Key = "key-abc"

[collectors.etw]
enabled = true

# Custom provider list (replaces defaults when specified)
# providers = [
#     { name = "Microsoft-Windows-Kernel-Process", guid = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716", level = 5, keywords = "0xFFFFFFFFFFFFFFFF" },
# ]

[collectors.sysmon]
enabled = false

[collectors.evasion]
enabled = true
scan_interval_ms = 5000
detect_etw_patching = true
detect_amsi_bypass = true
detect_unhooking = true
detect_direct_syscall = true
```

ETW provider `keywords` can be specified as a hex string (`"0xFFFFFFFFFFFFFFFF"`) or an integer.

## Output

Events are written as JSON Lines. Each event includes:

- unique event ID
- UTC timestamp
- hostname
- stable agent ID (persisted across restarts)
- sensor version
- source
- category
- severity
- typed event payload
- process context (when available — see below)

### Process Context Enrichment

The sensor maintains an in-memory process context cache, populated from `ProcessCreate` events. Activity events (file, network, registry, DNS, image load, script, AMSI) are enriched with a `process_context` field that provides:

- **`process_key`**: stable process identity derived from `{pid}:{create_time}`, resilient to PID reuse
- **`image_path`**, **`command_line`**: the executable and its arguments
- **`user`**, **`integrity_level`**: when available from the source
- **`ppid`**: parent process ID

`ProcessCreate` events receive a `process_context` containing only the `process_key` (the remaining fields are already in the event payload). `ProcessTerminate` events receive full context from the cache before the entry is evicted.

The cache is bounded (10,000 entries) and keyed by PID. When a PID is reused, the new `ProcessCreate` replaces the old entry. `ProcessTerminate` events verify `create_time` to avoid evicting a newer process that reused the same PID.

ETW events carry a precise OS-level creation timestamp (`create_time`), which produces PID-reuse-safe process keys. Sysmon events do not carry a comparable timestamp, so the cache applies source priority: an ETW-backed entry is never overwritten or evicted by a Sysmon event that lacks `create_time`. In Sysmon-only mode, process keys use a zero create_time (`{pid}:0`) and PID-reuse protection is best-effort.

Example ProcessCreate event:

```json
{
  "id": "2d8f7b0b-8f6b-4d77-b870-4e8c1a2f0f16",
  "timestamp": "2026-03-11T00:00:00Z",
  "hostname": "HOST01",
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "sensor_version": "0.3.0",
  "source": {
    "Etw": {
      "provider": "Microsoft-Windows-Kernel-Process"
    }
  },
  "category": "Process",
  "severity": "Info",
  "data": {
    "type": "ProcessCreate",
    "pid": 1234,
    "ppid": 4321,
    "image_path": "C:\\Windows\\System32\\cmd.exe",
    "command_line": "cmd.exe /c whoami",
    "user": "",
    "integrity_level": "",
    "hashes": null,
    "create_time": 133579284000000000
  },
  "process_context": {
    "process_key": "1234:133579284000000000"
  }
}
```

Example enriched NetworkConnect event:

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2026-03-11T00:00:01Z",
  "hostname": "HOST01",
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "sensor_version": "0.3.0",
  "source": {
    "Etw": {
      "provider": "Microsoft-Windows-Kernel-Network"
    }
  },
  "category": "Network",
  "severity": "Info",
  "data": {
    "type": "NetworkConnect",
    "pid": 1234,
    "image_path": "",
    "protocol": "TCP",
    "src_addr": "10.0.0.5",
    "src_port": 49152,
    "dst_addr": "93.184.216.34",
    "dst_port": 443,
    "direction": "Outbound"
  },
  "process_context": {
    "process_key": "1234:133579284000000000",
    "image_path": "C:\\Windows\\System32\\cmd.exe",
    "command_line": "cmd.exe /c whoami",
    "ppid": 4321
  }
}
```

## Local Investigation CLI

ThreatFalcon includes built-in investigation commands that read JSONL telemetry output directly — no external SIEM or database required.

### Query

Filter and search events from a JSONL file:

```bash
# All events for a specific PID
threatfalcon query --input events.jsonl --pid 1234

# Events by stable process identity
threatfalcon query --input events.jsonl --process-key "1234:133579284000000000"

# Network events only
threatfalcon query --input events.jsonl --category network

# Detection events by rule ID
threatfalcon query --input events.jsonl --rule-id TF-EVA-001

# Filter by source type (etw, sysmon, evasion) or ETW provider name
threatfalcon query --input events.jsonl --source etw
threatfalcon query --input events.jsonl --source DNS-Client

# Minimum severity filter (Info, Low, Medium, High, Critical)
threatfalcon query --input events.jsonl --severity high

# Case-insensitive text search across serialized event data
threatfalcon query --input events.jsonl --contains "malware.exe"

# Time range filtering (RFC 3339 timestamps)
threatfalcon query --input events.jsonl --from "2026-03-13T00:00:00Z"
threatfalcon query --input events.jsonl --from "2026-03-13T00:00:00Z" --to "2026-03-13T12:00:00Z"

# --since is a backward-compatible alias for --from
threatfalcon query --input events.jsonl --since "2026-03-13T00:00:00Z"

# Combine filters with a result limit
threatfalcon query --input events.jsonl --pid 1234 --category network --severity medium --limit 50
```

Available query filters:

| Flag | Description |
|------|-------------|
| `--pid <N>` | Filter by process ID |
| `--process-key <KEY>` | Filter by stable process key (`pid:create_time`) |
| `--category <CAT>` | Filter by event category (case-insensitive) |
| `--rule-id <ID>` | Filter by detection rule ID |
| `--source <SRC>` | Filter by source type (`etw`, `sysmon`, `evasion`, `sensor`) or ETW provider name substring |
| `--severity <SEV>` | Minimum severity threshold (accepts `info`, `low`, `med`/`medium`, `high`, `crit`/`critical`) |
| `--contains <TEXT>` | Case-insensitive text search across the entire serialized event (Windows paths like `C:\Temp\evil.exe` are matched automatically) |
| `--from <TS>` | Only events after this RFC 3339 timestamp (alias: `--since`) |
| `--to <TS>` | Only events before this RFC 3339 timestamp |
| `--limit <N>` | Maximum number of results (default: 100) |

Output is JSONL (one event per line) for easy piping to `jq`, `grep`, or other tools. The match count is printed to stderr.

### Explain

Show detailed context for a single event, including a process timeline of related activity within a time window:

```bash
# Full event detail + process timeline (±5 minutes by default)
threatfalcon explain --event <UUID> --input events.jsonl

# UUID prefix matching is supported
threatfalcon explain --event a1b2c3d4 --input events.jsonl

# Custom time window
threatfalcon explain --event <UUID> --input events.jsonl --window 10

# Output as structured JSON (useful for piping to jq)
threatfalcon explain --event <UUID> --input events.jsonl --json
```

The human-readable output includes:
- Target event details (ID, timestamp, category, severity, source, process context)
- Process timeline showing all events from the same `process_key` within the window
- Script / AMSI activity section (when the target is a ScriptBlock, AmsiScan, or AMSI bypass detection — shows correlated script executions and AMSI scan results for the same process)
- Detection rule details (if the event is a detection)

The `--json` flag outputs a single JSON object containing:
- `target_event`: the full target event
- `window_minutes`: the time window used
- `process_key`: the target's process key (if available)
- `timeline`: array of related events from the same process within the window
- `script_amsi_activity`: correlated script/AMSI events (when applicable)
- `rule`: detection rule metadata (when the target is a detection)

### Bundle

Package an event and its related context into a single JSON document or zip archive for sharing or archiving:

```bash
# Bundle to stdout (JSON)
threatfalcon bundle --event <UUID> --input events.jsonl

# Bundle to a JSON file
threatfalcon bundle --event <UUID> --input events.jsonl --output bundle.json

# Bundle to a zip archive
threatfalcon bundle --event <UUID> --input events.jsonl --output bundle.zip

# Custom time window
threatfalcon bundle --event <UUID> --input events.jsonl --window 10 --output bundle.zip
```

**JSON output** (default, or when the output path does not end in `.zip`):
- `bundle_version`: schema version (currently 1)
- `target_event`: the event being investigated
- `related_events`: all events sharing the same `process_key` within the time window
- `event_count`: total number of events in the bundle
- Metadata: `created_at`, `process_key`, `window_minutes`

**Zip output** (when the output path ends in `.zip`):

The zip archive contains four files:

| File | Contents |
|------|----------|
| `manifest.json` | Machine-readable metadata (format, version, event ID, process key, window, event count, time range, file list) |
| `target_event.json` | The target event (pretty-printed JSON) |
| `related_events.jsonl` | Related events (one JSON object per line) |
| `bundle.json` | Full combined bundle (identical to the standalone JSON output) |

The zip format is useful for attaching bundles to tickets, sharing with analysts, or archiving investigations. The `manifest.json` enables tooling to identify and process bundles programmatically.

### Index

Build a SQLite sidecar index for fast event lookups on large JSONL files. The JSONL file remains the source of truth — the index is an optional acceleration layer.

```bash
# Build or incrementally update the index
threatfalcon index --input events.jsonl

# Force a full rebuild
threatfalcon index --input events.jsonl --rebuild

# Show index health and coverage
threatfalcon index --input events.jsonl --status
```

The index stores `event_id`, `timestamp`, `pid`, `process_key`, `category`, `source`, `rule_id`, `severity`, and byte offsets back into the JSONL file. This allows `query`, `explain`, and `bundle` to skip full file scans and seek directly to matching events.

**Transparent behavior:**
- If an index exists and is current, `query`/`explain`/`bundle` use it automatically
- If an index exists but is behind (new events appended), it is incrementally updated before querying
- If no index exists, commands fall back to the current full JSONL scan (no index is created implicitly)
- If the index is corrupt, it is deleted and the command falls back to a full scan
- Use `--no-index` on any command to force a full scan (useful for debugging)

The index file is stored alongside the JSONL file as `<filename>.idx.sqlite` (e.g., `events.jsonl.idx.sqlite`).

### Stats

Show summary statistics for a JSONL telemetry file — event counts by category, severity, source, top processes, and detection rule hits:

```bash
# Human-readable summary
threatfalcon stats --input events.jsonl

# Structured JSON output
threatfalcon stats --input events.jsonl --json
```

Example output:

```
=== Event Statistics ===
Total events: 12847
Time range:   2026-03-13 08:00:00 UTC → 2026-03-13 18:30:00 UTC
Duration:     10h 30m

--- By Category ---
  Network          5230
  Process          3412
  File             2108
  Registry          980
  Evasion           117

--- By Severity ---
  Critical            3
  High               42
  Medium            117
  Info            12685

--- By Source ---
  ETW/Microsoft-Windows-Kernel-Network       5230
  ETW/Microsoft-Windows-Kernel-Process       3412
  EvasionDetector                             117

--- Top Processes (by event count) ---
  PID    892    3210 events  C:\Windows\System32\svchost.exe
  PID   4120    1845 events  C:\Program Files\app.exe

--- Detection Rules ---
  TF-EVA-001                42
  TF-EVA-004                 3
```

### Tail

Follow new events appended to a JSONL file in real time (like `tail -f`). Existing content is skipped — only newly appended events are shown:

```bash
# Follow all new events
threatfalcon tail --input events.jsonl

# Follow only high-severity events
threatfalcon tail --input events.jsonl --severity high

# Follow events from a specific PID
threatfalcon tail --input events.jsonl --pid 1234

# Follow with text search
threatfalcon tail --input events.jsonl --contains "malware.exe"

# JSONL output for piping to other tools
threatfalcon tail --input events.jsonl --json | jq '.severity'
```

The human-readable format shows timestamp, severity, category, PID, and a one-line event summary. Press Ctrl+C to stop.

### Tree

Reconstruct and display process trees from `ProcessCreate` events. Show the descendant tree (children, grandchildren, ...) or the ancestor chain (parent, grandparent, ...) of a given process:

```bash
# Show descendants of PID 1234
threatfalcon tree --input events.jsonl --pid 1234

# Show ancestor chain leading to PID 5678
threatfalcon tree --input events.jsonl --pid 5678 --ancestors

# Disambiguate PID reuse with --process-key
threatfalcon tree --input events.jsonl --pid 1234 --process-key "1234:133579284000000000"

# JSON output for programmatic use
threatfalcon tree --input events.jsonl --pid 1234 --json
```

Example output (descendants):

```
=== Process Tree for PID 892 (3 descendants) ===
svchost.exe [PID 892, PPID 600] NT AUTHORITY\SYSTEM  [892:133579284000000000]
├─ taskhostw.exe [PID 3120, PPID 892] DESKTOP\user  [3120:133579285000000000]
└─ RuntimeBroker.exe [PID 4200, PPID 892] DESKTOP\user  [4200:133579286000000000]
   └─ cmd.exe [PID 5100, PPID 4200] DESKTOP\user  [5100:133579287000000000]
```

Example output (ancestors):

```
=== Ancestor Chain for PID 5100 (4 levels) ===
wininit.exe [PID 600, PPID 0] NT AUTHORITY\SYSTEM  [600:133579280000000000]
└─ svchost.exe [PID 892, PPID 600] NT AUTHORITY\SYSTEM  [892:133579284000000000]
   └─ RuntimeBroker.exe [PID 4200, PPID 892] DESKTOP\user  [4200:133579286000000000]
      └─ cmd.exe [PID 5100, PPID 4200] DESKTOP\user  [5100:133579287000000000]
```

When a PID appears in multiple `ProcessCreate` events (PID reuse), the tree selects the most recent instance by default. Use `--process-key` to select a specific instance. Parent-child relationships are resolved using temporal ordering: a child is assigned to the parent instance whose creation time is closest before the child's.

The `--json` flag outputs a nested JSON tree structure where each node contains `pid`, `ppid`, `image_path`, `command_line`, `user`, `timestamp`, `process_key`, and `children`.

### Inspect

Analyze a PE (Portable Executable) file on disk — show headers, sections, imports with suspicious API classification, and exports:

```bash
# Inspect a binary found in events
threatfalcon inspect --file C:\Windows\System32\cmd.exe

# JSON output for programmatic analysis
threatfalcon inspect --file suspicious.exe --json
```

Example output:

```
=== PE Inspection: suspicious.exe ===

[Basic Info]
  Architecture:    PE32+ (AMD64)
  Entry Point:     0x00001000
  Image Base:      0x0000000140000000
  Image Size:      0x00020000
  Subsystem:       Windows CUI

[Sections] (3)
  Name         VirtSize    RawSize  Flags
  .text      0x0000A000 0x0000A000  R-X
  .rdata     0x00003000 0x00003000  R--
  .data      0x00001000 0x00000800  RW-

[Imports] (2 DLLs, 12 functions)
  KERNEL32.dll (8 functions)
    VirtualAllocEx                           [!] Process Injection, Memory Manipulation
    WriteProcessMemory                       [!] Process Injection
    CreateRemoteThread                       [!] Process Injection
    GetProcAddress                           [!] Hooking / Dynamic Resolution
    ...4 more

  NTDLL.dll (4 functions)
    NtUnmapViewOfSection                     [!] Defense Evasion
    ...3 more

[Suspicious API Summary]
  Process Injection                         3 API(s)
  Memory Manipulation                       1 API(s)
  Hooking / Dynamic Resolution              1 API(s)
  Defense Evasion                           1 API(s)

[Exports] (0)
  (none)

[Warnings]
  [!] Section .rwx is writable + executable (RWX)
```

Suspicious API categories:

| Category | Example APIs |
|----------|-------------|
| Process Injection | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx` |
| Code Execution | `CreateProcessW`, `ShellExecuteW`, `WinExec` |
| Memory Manipulation | `VirtualProtect`, `VirtualAlloc`, `NtAllocateVirtualMemory` |
| Hooking / Dynamic Resolution | `GetProcAddress`, `LoadLibraryW`, `SetWindowsHookExW` |
| Credential Access | `CredReadW`, `LsaRetrievePrivateData`, `CryptUnprotectData` |
| Defense Evasion | `NtUnmapViewOfSection`, `NtSetContextThread`, `EtwEventWrite` |

Sections with both writable and executable characteristics are flagged as suspicious (common in packed or self-modifying code).

The `inspect` command works cross-platform — PE files can be analyzed on macOS or Linux (e.g., for post-collection forensic analysis).

### IOC Extraction

Extract indicators of compromise (IPs, domains, file hashes) from telemetry events:

```bash
# Extract all IOCs from an event file
threatfalcon ioc --input events.jsonl

# Show only external IPs
threatfalcon ioc --input events.jsonl --type ip

# Show only domains
threatfalcon ioc --input events.jsonl --type domain

# JSON output for integration with other tools
threatfalcon ioc --input events.jsonl --json
```

Example output:

```
=== IOC Extraction (1523 events scanned) ===

[External IPs] (4)
       8x  93.184.216.34                            (explorer.exe)
       3x  8.8.8.8                                  (svchost.exe)
       2x  185.199.108.133                           (DNS/github.com)
       1x  104.16.132.229                            (chrome.exe)

[Domains] (3)
       5x  evil.example.com
       2x  github.com
       1x  api.example.org

[File Hashes] (2)
       1x  SHA256=abcdef1234567890... (malware.exe)
       1x  MD5=d41d8cd98f00b204...   (rundll32.exe)
```

The IOC extraction covers:

| IOC Type | Source Events | Notes |
|----------|--------------|-------|
| External IPs | `NetworkConnect` | Private, loopback, and link-local addresses excluded |
| External IPs | `DnsQuery` response | IPs resolved from DNS answers |
| Domains | `DnsQuery` | Queried domain names |
| File Hashes | `ProcessCreate`, `ImageLoad` | `SHA256=...`, `MD5=...` format preserved |

Results are deduplicated and sorted by frequency (descending). Use `--limit` to control the number of results per type (default: 50).

### Hunt

Run threat hunting rules against telemetry events to surface suspicious patterns:

```bash
# Run all hunting rules
threatfalcon hunt --input events.jsonl

# Run a specific rule
threatfalcon hunt --input events.jsonl --rule suspicious-parent

# JSON output for integration
threatfalcon hunt --input events.jsonl --json
```

Example output:

```
=== Threat Hunt (2841 events scanned, 3 findings) ===

[High] suspicious-parent (T1204.002)
  PID:     4521
  Process: C:\Windows\System32\cmd.exe
  Detail:  winword.exe spawned cmd.exe (cmd.exe /c whoami)
  Time:    2026-03-13T10:05:12+00:00

[Medium] lolbin (T1218)
  PID:     5102
  Process: C:\Windows\System32\certutil.exe
  Detail:  LOLBin execution: certutil.exe (certutil.exe -urlcache -f ...)
  Time:    2026-03-13T10:07:33+00:00

[Medium] beaconing (T1071.001)
  PID:     3200
  Process: C:\Users\user\malware.exe
  Detail:  42 connections to 185.100.87.174 from malware.exe
  Time:    2026-03-13T09:00:00+00:00
```

Available hunting rules:

| Rule | Severity | MITRE | Description |
|------|----------|-------|-------------|
| `suspicious-parent` | High | T1204.002 | Office/PDF apps spawning shells or scripting engines |
| `lolbin` | Medium | T1218 | Execution of living-off-the-land binaries (certutil, mshta, regsvr32, etc.) |
| `unsigned-dll` | Low | T1574.001 | Unsigned DLL loaded into a process |
| `beaconing` | Medium | T1071.001 | Repeated connections to the same external IP (threshold: 10+) |

Results are sorted by severity (descending), then by timestamp. Use `--limit` to control the maximum number of findings (default: 50).

### Score

Rank processes by aggregated threat signals to prioritize investigation:

```bash
# Score all processes
threatfalcon score --input events.jsonl

# JSON output with full breakdown
threatfalcon score --input events.jsonl --json

# Show only top 5
threatfalcon score --input events.jsonl --limit 5
```

Example output:

```
=== Process Threat Scores (4821 events scanned) ===

[Score:   62]  PID    4521  C:\Users\user\malware.exe
              key: 4521:133579284000000000
              1x detection (+40), LOLBin (+20), 1 external IP(s) (+2)

[Score:   27]  PID    5102  C:\Windows\System32\cmd.exe
              key: 5102:133579285000000000
              suspicious parent (+20), 3 external IP(s) (+6), 1 DNS query(s) (+1)

[Score:   10]  PID    3200  C:\app\helper.exe
              key: 3200:133579282000000000
              2x unsigned DLL (+10)
```

Scoring weights:

| Signal | Points | Source |
|--------|--------|--------|
| Evasion detection (with rule) | +40 per detection | `EvasionDetected` events with `RuleMetadata` |
| Suspicious parent-child | +20 | Office/PDF app spawning shell (same as `hunt`) |
| LOLBin execution | +20 | Living-off-the-land binary (same as `hunt`) |
| Unsigned DLL load | +5 per DLL | `ImageLoad` with `signed: false` |
| External IP connection | +2 per unique IP | `NetworkConnect` to public IPs |
| DNS query | +1 per unique domain | `DnsQuery` events |

Processes with a score of 0 are excluded. Use `--limit` to control the number of results (default: 20).

## Evasion Detection Rules

The evasion collector periodically scans running processes for EDR evasion techniques. Each detection emits a structured `RuleMetadata` with evidence.

| Rule ID | Name | Technique | MITRE | Confidence |
|---------|------|-----------|-------|------------|
| TF-EVA-001 | ETW Event Write Patching | `ntdll!EtwEventWrite` patched to `ret` | T1562.006 | High |
| TF-EVA-002 | AMSI Scan Buffer Bypass | `amsi!AmsiScanBuffer` patched to return clean | T1562.001 | High/Medium |
| TF-EVA-003 | ntdll User-Mode Hook Removal | ntdll `.text` replaced with clean on-disk copy | T1562.001 | Medium |
| TF-EVA-004 | Suspicious Direct Syscall Stub | `syscall`/`int 0x2e` stubs in non-system module | T1562.001 | Medium |

### TF-EVA-004: Direct Syscall Detection

Tools like SysWhispers embed syscall stubs directly in malware modules to bypass ntdll user-mode hooks. TF-EVA-004 detects the canonical stub pattern:

```
mov r10, rcx        ; 4C 8B D1 or 49 89 CA
mov eax, <SSN>      ; B8 xx xx xx xx
[optional gap]      ; up to 12 bytes (Wow64 compat check)
syscall / int 0x2e  ; 0F 05 or CD 2E
```

The scanner enumerates loaded modules per process, skips system DLLs that legitimately contain syscall stubs (ntdll.dll, win32u.dll — verified by full path to `System32`/`SysWOW64`, not just basename), parses each module's PE headers to locate the `.text` section by RVA and characteristics, and matches the stub pattern. Evidence includes the module name, stub offset, SSN value, and raw bytes.

Function locations for ETW patching (`EtwEventWrite`) and AMSI bypass (`AmsiScanBuffer`) detection are resolved from the on-disk PE export table at scanner startup, eliminating per-process `GetProcAddress` calls and enabling AMSI detection even when the sensor process does not have `amsi.dll` loaded.

### TF-EVA-002: AMSI Bypass Detection

TF-EVA-002 detects multiple patterns of `AmsiScanBuffer` patching:

| Pattern | Bytes | Meaning | Confidence |
|---------|-------|---------|------------|
| `mov eax, 0x80070057; ret` | `B8 57 00 07 80 C3` | Force E_INVALIDARG return (classic) | High |
| `mov eax, 1; ret` | `B8 01 00 00 00 C3` | Force S_FALSE return | High |
| `mov eax, <imm32>; ret` | `B8 xx xx xx xx C3` | Force arbitrary return value | High |
| `xor eax, eax; ret` | `31 C0 C3` / `33 C0 C3` | Force S_OK (scan always clean) | High |
| `ret` | `C3` | Immediate return, function body skipped | Medium |
| `nop; ret` | `90 C3` | Function body replaced with no-op | Medium |

Evidence includes the decoded instruction, raw bytes, amsi.dll base address in the target process, and the function RVA from the export table.

### Script / AMSI Correlation

When using `explain` on a ScriptBlock, AmsiScan, or AMSI bypass detection event, ThreatFalcon shows a dedicated "Script / AMSI Activity" section. This section lists all PowerShell script block executions and AMSI scan results from the same process, making the script execution → AMSI scan → bypass chain visible and explainable.

Note: TF-EVA-004 detects the **presence** of syscall stubs in non-system modules. It does not confirm that the stubs were executed or that ntdll hooks were actively bypassed. Confidence is Medium to reflect this distinction.

## Limitations

- No installer or packaging yet (service registration is manual via `sc.exe`)
- Some ETW payload parsing is best-effort and should be validated on real Windows hosts
- Sysmon support depends on Sysmon being installed and configured
- Evasion-oriented checks are heuristic and should be treated as signal, not ground truth

## License

MIT
