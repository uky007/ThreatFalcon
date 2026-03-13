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
- script-related events
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
threatfalcon [OPTIONS]

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

Example ProcessCreate event:

```json
{
  "id": "2d8f7b0b-8f6b-4d77-b870-4e8c1a2f0f16",
  "timestamp": "2026-03-11T00:00:00Z",
  "hostname": "HOST01",
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "sensor_version": "0.2.0",
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
  "sensor_version": "0.2.0",
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

## Evasion Detection Rules

The evasion collector periodically scans running processes for EDR evasion techniques. Each detection emits a structured `RuleMetadata` with evidence.

| Rule ID | Name | Technique | MITRE | Confidence |
|---------|------|-----------|-------|------------|
| TF-EVA-001 | ETW Event Write Patching | `ntdll!EtwEventWrite` patched to `ret` | T1562.006 | High |
| TF-EVA-002 | AMSI Scan Buffer Bypass | `amsi!AmsiScanBuffer` patched to return clean | T1562.001 | High |
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

The scanner enumerates loaded modules per process, skips system DLLs that legitimately contain syscall stubs (ntdll.dll, win32u.dll — verified by full path to `System32`/`SysWOW64`, not just basename), reads the `.text` section of remaining modules, and matches the stub pattern. Evidence includes the module name, stub offset, SSN value, and raw bytes.

Note: TF-EVA-004 detects the **presence** of syscall stubs in non-system modules. It does not confirm that the stubs were executed or that ntdll hooks were actively bypassed. Confidence is Medium to reflect this distinction.

## Limitations

- No installer or packaging yet (service registration is manual via `sc.exe`)
- Some ETW payload parsing is best-effort and should be validated on real Windows hosts
- Sysmon support depends on Sysmon being installed and configured
- Evasion-oriented checks are heuristic and should be treated as signal, not ground truth

## License

MIT
