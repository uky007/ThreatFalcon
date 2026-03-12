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

By default, ThreatFalcon writes events locally only and does not transmit telemetry to a remote service.

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
- `src/events.rs`: unified event schema
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

## Configuration

ThreatFalcon loads `threatfalcon.toml` from the current directory on startup. If the file is not found, built-in defaults are used. Use `--config <path>` to load from a different location, or `--stdout` / `--output <path>` to override the output destination from the command line.

All sections are optional. Only the fields you want to override need to be specified.

```toml
# Override hostname (default: auto-detected from environment)
hostname = "WORKSTATION-01"

# Periodic health event interval in seconds (default: 60, 0 = periodic disabled)
# A final shutdown health event is always emitted regardless of this setting.
health_interval_secs = 60

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
- source
- category
- severity
- typed event payload

Example event shape:

```json
{
  "id": "2d8f7b0b-8f6b-4d77-b870-4e8c1a2f0f16",
  "timestamp": "2026-03-11T00:00:00Z",
  "hostname": "HOST01",
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
    "hashes": null
  }
}
```

## Limitations

- No installer, service wrapper, or packaging yet
- Some ETW payload parsing is best-effort and should be validated on real Windows hosts
- Sysmon support depends on Sysmon being installed and configured
- Evasion-oriented checks are heuristic and should be treated as signal, not ground truth

## License

MIT
