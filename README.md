# ThreatFalcon

ThreatFalcon is an experimental Windows endpoint telemetry sensor written in Rust.

The project is aimed at a transparent, explainable, open source sensor that collects host telemetry and normalizes it into structured JSONL events.

## Status

ThreatFalcon is early-stage software.

- Windows is the primary target platform
- ETW collection is implemented
- Sysmon subscription and parsing are implemented, but disabled by default
- Evasion-detection checks are implemented for selected techniques
- Configuration file loading is not implemented yet
- The event schema and collector behavior may still change

## Goals

- Keep the sensor small and auditable
- Use straightforward event models instead of opaque binaries
- Emit machine-readable events that are easy to inspect and test
- Prefer explicit detection logic over black-box behavior

## Current Capabilities

ThreatFalcon currently normalizes telemetry into a unified `ThreatEvent` model with:

- process events
- file events
- network events
- registry events
- image load events
- DNS events
- script-related events
- evasion-detection events

Collection sources:

- ETW
- Sysmon
- in-process evasion scanner

## Default Behavior

The built-in default configuration currently does the following:

- writes events to `threatfalcon_events.jsonl`
- rotates output at `100 MB`
- enables ETW collection
- disables Sysmon collection by default
- enables evasion checks

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
- `src/output.rs`: JSONL writer and log rotation
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

Logging can be controlled with `RUST_LOG`:

```bash
RUST_LOG=info cargo run --release
```

On startup, the sensor initializes enabled collectors, writes newline-delimited JSON events, and stops on `Ctrl-C`.

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

- No external config file support yet
- No installer, service wrapper, or packaging yet
- Some ETW payload parsing is best-effort and should be validated on real Windows hosts
- Sysmon support depends on Sysmon being installed and configured
- Evasion detection is heuristic and should be treated as signal, not ground truth

## Roadmap

- config file loading
- clearer rule and evidence metadata for detections
- better Windows operational packaging
- more test coverage for collectors and event mapping
- documentation for privacy boundaries and collection scope

## License

MIT
