# Evidence-based detection / 証拠に基づく検知

This is a development implementation, not a production detection-quality claim.
高度な脅威への対応を目指す実装です。実攻撃の検知率・誤検知率を実証した製品ではありません。

## Implemented / 実装したこと

- Schema v2 separates source `timestamp` from `observed_at`. Sysmon UtcTime, record ID, actor/parent/target ProcessGuid and native fields survive normalization. Missing evidence is explicit. Version 1 logs remain readable but cannot support the new correlations.
- ETW callbacks use TDH metadata from the actual event descriptor/version, not fixed payload offsets. Full provider GUIDs are used. QPC timestamps are converted by ProcessTrace to system FILETIME; RAW_TIMESTAMP is not enabled. Native fields and payload bytes are retained when decoding/normalization is unavailable.
- ETW process/image, DNS and PowerShell fields have conservative normalizers. Network events require explicit native operation names: send/receive are `NetworkTraffic`, not `NetworkConnect`. Unknown naming/layout remains native telemetry. File/registry/AMSI/TI currently remain native ETW telemetry; their old offset-based classifications have been removed. Sysmon supplies normalized file/registry/image/cross-process events.
- Image signature state is `true`, `false`, or `null` (unknown), not a forced boolean. V1 false values are not used for unsigned-image alerts/scores. Signing level is not certificate-chain or revocation validation.
- Sysmon XML parsing rejects DTDs, duplicate fields and malformed documents. A GUID-aware cache never substitutes an ETW PID-only match for a Sysmon identity.
- Native-only, decode-failure, transport-drop, late-analysis and analysis-capacity counts are observable. None of these is equivalent to clean evidence.

日本語の要点：発生時刻・元ログID・プロセスGUIDを保持し、署名不明を未署名と扱わず、送受信と接続を分離しました。ETWの未対応スキーマは元データ付きで記録します。SysmonとのPIDだけの結合は行いません。

## Correlations / 相関ルール

All three rules currently require **v2 Sysmon events with native UTC time and ProcessGuid**, on the same agent. ETW-only mode does not satisfy these rules. Findings contain evidence UUIDs, time windows, English/Japanese titles and ATT&CK references; they indicate suspicious behavior, not a proven compromise.

| ID | Evidence / 必要な証拠 | Limits / 限界 |
| --- | --- | --- |
| TF-COR-001 | Event 8 remote thread, then Event 3 outbound connection by that target GUID within 120 seconds. Matching Event 10 access with VM_WRITE + VM_OPERATION, if already available, adds supporting evidence. / リモートスレッド生成後の対象プロセスの通信 | Does not cover every injection technique. Debuggers and security software can match. / 全注入手法の網羅ではない |
| TF-COR-002 | Event 1: Office parent GUID/image and script-host child; child Event 3 within 120 seconds. / Office配下のスクリプト実行と通信 | Legitimate automation can match; filenames are not signer verification. / 正常な自動化でも成立し得る |
| TF-COR-003 | Ten outbound TCP connection events to one address/port/process, mean interval ≥ 10 seconds, interval CV ≤ 0.15, within 10 minutes. / 周期的TCP接続 | Regular update/monitoring traffic can match. No protocol/content proof of C2. / 周期性はC2の証明ではない |

State is bounded to 10,000 host/process timelines, 64 observations each and 50,000 dedup keys. Late arrivals are accepted within a per-process 10-minute window; source ordering, not arrival ordering, determines sequences. Capacity eviction and older arrivals are counted. Opt-in local-file checkpoint mode persists correlation facts, evidence IDs and dedup/suppression state atomically with source progress; other modes and standalone analysis start empty. Findings are not retroactively upgraded when supporting Event 10 arrives after a finding has already been emitted. No automatic blocking/quarantine is performed.

The live sensor and `analyze` use the same detector. `alert` can consume the sensor's emitted detections. `hunt`'s beaconing heuristic now also requires native identities/times and interval regularity (minimum ten samples); other legacy hunt/score rules remain simpler heuristics, not validated advanced-threat classifiers.

`analyze` now reports each rule's required/supporting inputs per agent, counting
only usable typed evidence. `required_types_observed` is **not** verified coverage,
a rule match or production readiness; `insufficient_evidence` is not proof that
policy is disabled. See [rule input contracts](PRODUCTION_HARDENING.md).
ルール別の入力不足を日英で表示します。観測件数は重複排除・相関時間窓適用前の値であり、
検知率や未収集件数の測定ではありません。

## Run a controlled Windows pilot / Windows検証環境での利用

Use `configs/windows-detection.toml` after installing/configuring Sysmon separately. `configs/sysmon-validation.xml` is a high-volume laboratory profile, **not a production filtering policy**. Confirm its schema with the installed Sysmon, inspect existing policy, and approve any replacement separately. ThreatFalcon does not install Sysmon or change endpoint policy automatically. Do not apply broad ProcessAccess/ImageLoad collection to a fleet before performance and data-handling review.

```powershell
.\threatfalcon.exe --config .\configs\windows-detection.toml --validate-config
.\threatfalcon.exe --config .\configs\windows-detection.toml
.\threatfalcon.exe health --input .\configs\threatfalcon_events.jsonl --lang ja
.\threatfalcon.exe analyze --input .\configs\threatfalcon_events.jsonl --lang ja
.\threatfalcon.exe analyze --input .\configs\threatfalcon_events.jsonl --lang en --json
```

Paths in TOML are relative to its directory. Stable agent IDs must be unique per endpoint; do not clone an initialized state file across hosts.

## Replay exported evidence / エクスポートした証拠の解析

`import-sysmon` accepts UTF-8 Event/Events XML, not binary EVTX. Use the source host's stable ID and exact System/Computer name. Mixed-host files are rejected. No collectors start and nothing is sent to a server. XML is limited to 64 MiB / 50,000 events per import, 1 MiB per event; JSONL analysis limits each line to 4 MiB. Split larger exports by host/time. The entire XML import is validated before stdout receives results.

Synthetic end-to-end check, runnable on all development platforms:

```sh
cargo run --locked -- import-sysmon \
  --input tests/fixtures/sysmon-correlation.xml \
  --agent-id aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
  --hostname synthetic-fixture > synthetic.jsonl
cargo run --locked -- analyze --input synthetic.jsonl --lang ja
```

Expected: TF-COR-001 with three original evidence IDs. **This fixture is generated test data, not a captured attack.** It proves the importer/normalizer/correlator integration, not Windows collection quality or detection coverage. No executable attack sample is needed or included.

## Acceptance gates before claiming real-world detection / 実用を名乗るための検証ゲート

1. On each supported Windows build and architecture, run `cargo test --locked windows_etw_process_smoke -- --ignored --test-threads=1`. Confirm the benign process event has native time, descriptor/version, expected PID/image and no decoder issue. A cross-compile alone does not pass this gate.
2. In an authorized Windows lab, compare original Sysmon/ETW observations with sensor output: IDs, fields, ordering, missed records, provider permissions, queue/ETW losses and analysis eviction. Event 3/8/10 absence is **unknown coverage**, not proof that the machine is clean. Sysmon defaults to live-only; [opt-in acknowledged local-file recovery](WINDOWS_RECOVERY.md) adds strict bookmarks and persistent correlation state but does not recover ETW. Run the ignored Sysmon collection/restart tests as well.
3. Use labeled, safely supplied telemetry from representative threat cases and benign workloads. Hold out cases used for evaluation. Measure per-scenario recall, false positives per endpoint-day, evidence completeness and alert latency. Merely listing ATT&CK IDs is not coverage validation.
4. Measure CPU, working set, disk bytes/day, callback latency and loss under normal and peak loads, long runs, restarts, sleep/resume and clock adjustments. Set deployment-specific budgets before acceptance. Resource bounds in code are not performance measurements.
5. Complete source/sensor integrity, signing/update supply-chain, least privilege, tamper resistance, privacy/retention and delivery/recovery review. Missing kernel callbacks, restricted TI access and memory visibility cannot be fixed by adding more string rules.

[2026-09-22のWindows VM検証](WINDOWS_VALIDATION_2026-09-22.md)では、無害な操作による限定的なネイティブ収集・Sysmon再取得・WFP許可／遮断記録の照合が通過しました。Sysmonは`cmd.exe`のプロセス生成に限定した設定であり、上記3ルールに必要な通信・クロスプロセスの証拠は揃えていません。これらの相関検知の実機E2E、実脅威・正常業務データによる検知率・誤検知率の評価は未実施です。検証後はVMを停止し、継続的なThreatFalcon監視は有効化していません。

Windows/GNU向けの型チェックと可搬テストは別の検証として扱います。オンプレミス／クラウド管理サーバー、macOS／Linuxセンサ、独自カーネル収集基盤の完成を意味しません。

Native fields, command lines, paths, scripts and raw payloads may contain confidential information. Keep pilot data local with restrictive ACLs, encryption and a deliberate retention policy. Do not submit collected telemetry to a public issue tracker. TDH decoding is currently synchronous in the callback and complex arrays/structs are retained as native data; benchmark and expand schema support before broad deployment.

## Design references / 一次資料

- Sysmon provides UTC event time and ProcessGuid for correlation, and warns that ProcessAccess can be high-volume: [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
- Actual-record metadata and missing-schema errors: [TdhGetEventInformation](https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgeteventinformation).
- Typed native property formatting: [TdhFormatProperty](https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhformatproperty).
- Default timestamp conversion (unless RAW_TIMESTAMP is requested): [EVENT_TRACE_LOGFILEW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew).

The rules, thresholds and validation gates above are ThreatFalcon design choices, not detection guarantees from Microsoft.
