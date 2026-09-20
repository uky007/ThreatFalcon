# Windows ETW context / Windows ETW拡張コンテキスト

Experimental, explicitly opt-in, passive telemetry. **Native Windows validation is pending.**
This adds evidence and collection diagnostics, not new threat rules, prevention, an ETW-TI
access workaround, a kernel driver, or commercial-EDR-equivalent coverage.

実験的・明示的有効化の受動的な収集機能です。**実Windowsでの検証は未実施です。**
検知ルールの追加や市販EDRと同等の検知能力を意味しません。収集できる情報と、
その意味・不足・保存上限を明確にするための基盤です。

## Research and independent implementation / 調査と独立実装

[FalconForce's MDE Internals research (2021)](https://falconforce.nl/sysmon-vs-microsoft-defender-for-endpoint-mde-internals-0x01/)
motivated examining process identity and the distinction between collection, filtering and retained
telemetry. These are historical observations, not a current Microsoft product specification.
[Elastic's own technical explanation (2024)](https://www.elastic.co/security-labs/threat-command/doubling-down-etw-callstacks)
illustrates the value of call-stack context and the cost of verbose telemetry. Our implementation
does not reproduce Elastic's collection mechanisms, memory enrichment or detection engine.

MDE解析から識別・収集品質、Elasticの開発元解説からスタック文脈の重要性を参考にしました。
以下はMicrosoftの公開APIに基づく独立実装です。独自構造体の推測や非公開オフセット、
保護機構の迂回に依存しません。

- [ENABLE_TRACE_PARAMETERS](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters)
  supplies optional process-start-key, event-key and stack requests to `EnableTraceEx2`.
  Process-start keys are unique within an OS boot, not globally. Stack capture can cause
  events exceeding ETW's 64 KiB limit to be lost and has an upstream frame limit.
- [EVENT_HEADER_EXTENDED_DATA_ITEM](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header_extended_data_item)
  identifies the type and byte size of each extension. We read only explicitly requested types.
- [EVENT_EXTENDED_ITEM_STACK_TRACE64](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace64)
  defines `MatchId` and addresses. Separate user/kernel stack portions can have matching IDs;
  this sensor preserves them separately, without reconstructing a complete stack.
- [EVENT_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header)
  describes publisher context. A process referenced in a payload may be a different process.

## Configuration / 設定

Existing profiles and the default list of eight providers do **not** request extensions.
Each provider can independently enable:

```toml
extended = { process_start_key = true, event_key = true, stack_trace = true }
```

All three default to false. Unknown keys inside `extended` are rejected. With extension requests,
provider GUIDs must be unique and non-nil, including case/braces aliases. At most 64 providers
are accepted. A failed extension-enabled subscription is reported as failed: there is no silent
retry without the requested context. Subscription success alone does not prove event delivery.

初期値はすべて無効です。`extended`の不明な項目と重複したプロバイダ指定は拒否します。
拡張情報を要求した購読に失敗しても、要求を黙って取り消して成功扱いにはしません。
収集対象はプロバイダ単位です。イベントIDごとのスタックフィルタは未実装です。

The isolated [windows-etw-context.toml](../configs/windows-etw-context.toml) profile selects only
the DNS client provider and local file output. It disables Sysmon, WFP audit, evasion scanning,
macOS and Linux collectors. Configure the hostname and protect the config/output directory first.
It neither changes DNS configuration nor generates traffic by itself.

```powershell
.\threatfalcon.exe --config .\configs\windows-etw-context.toml --validate-config
.\threatfalcon.exe --config .\configs\windows-etw-context.toml
```

Stop with Ctrl+C. No service installation is required. Relative paths are resolved against the
config directory. DNS names, stack addresses and identifiers are sensitive; use access controls,
retention limits and redacted exports. Stack capture is not enabled for PowerShell by this sample:
large script events warrant a separate capacity evaluation before adding stack overhead.

専用設定はDNSプロバイダだけをローカル収集します。DNS設定変更・試験通信・サービス導入は
自動実行しません。DNS名・アドレス・識別子の取り扱いを制限してください。PowerShellなどの
大きいイベントでは、スタック追加による欠落と負荷を別途確認する必要があります。

## Stored evidence / 保存する証拠

`provenance.etw_extended` contains:

| Field | Contract / 意味 |
| --- | --- |
| `capture_id` | Fresh UUID for each collector start; **not** an OS boot ID / 収集開始ごとのUUID |
| `header_pid`, `header_tid` | Publisher header values, independent of payload PIDs / 発行元の値 |
| `requested` | Requested options, not proof of capability / 要求内容 |
| `process_start_key` | Exact optional native u64; absent stays null / 取得できた開始キー |
| `event_key` | Exact optional event-instance key; not a process ID / イベントのキー |
| `stacks` | Item width, MatchId, addresses in source order and limit metadata / スタック断片 |
| `omitted_types` | Types of excluded items, not their values / 値を保存しなかった項目の型 |
| `issues` | Stable codes for missing, malformed or limited evidence / 不足・不正・上限の診断 |

Keys/addresses use JSON u64 numbers. Downstream readers must preserve 64-bit integers, rather
than round them through IEEE-754 JavaScript `Number`. Raw numeric fields are evidence, not
cryptographic authentication of a log or publisher. ETW may not provide every requested item.

ETW does not expose a trusted boot identity through these extensions. We deliberately scope a
publisher identity to `(agent_id, capture_id, process_start_key, header_pid)`. It survives PID reuse
within that capture, but **does not join across collector restarts or boots**. Nil identifiers,
unusable PIDs, unavailable/zero/duplicate keys and invalid extension tables cannot establish identity.
Event keys never substitute for process keys. Native values remain separate from normalized payloads.

起動をまたぐ誤相関を防ぐため、OS起動IDの代用品を推測せず、収集セッション内だけで識別します。
発行元の開始キーを操作対象のプロセス識別へ転用しません。PIDだけの既存キャッシュへの結合も
行いません。スタックの問題で有効なTDHペイロードを捨てることはありません。

## Bounds and failure semantics / 上限と失敗時の扱い

- At most 32 extended items inspected; no table dereference on null/excessive count.
- Wanted items are capped at 1544 bytes before reading. Unknown/unrequested pointers are not read.
  This relies on the documented ETW callback lifetime; length checks do not validate arbitrary pointers.
- Keys require exactly eight bytes. Duplicate keys invalidate that key, including identical duplicates.
- Stack widths come from the native item type, not the architecture of the sensor process.
  Header size, frame alignment and the documented maximum of 192 frames are checked.
- At most four stack items, each retaining the first 128 frames. Original count and local truncation
  are recorded. Reaching 192 frames is reported as reaching the upstream limit, not proven truncation.
- No memory reads at captured addresses, symbol downloads, DLL loading, code execution, stack-part
  merging, deduplication, memory-region classification or maliciousness verdicts.
- Missing requested data remains unavailable with an explicit issue. It does not prove tampering.
  Unknown extensions such as SID values are not copied. TDH payload behavior is unchanged.
- ETW session event/buffer losses and queue drops remain distinct. No new total-loss claim or replay
  guarantee is added. Existing collector ownership and stop behavior remain in force.

上限はCPU・メモリ負荷を無制限に増やさないためのものです。切詰めは明示します。
取得できないスタックや解決していないアドレスを「正常」「不正なメモリ」と判定しません。
OSポリシー・権限・署名・ページング設定・他製品の保護設定は変更しません。

## Analysis and health / 分析と稼働状況

```text
threatfalcon analyze --input configs/etw-context-events.jsonl --lang ja
threatfalcon analyze --input configs/etw-context-events.jsonl --lang en
threatfalcon health --input configs/etw-context-events.jsonl --lang ja
threatfalcon query --input configs/etw-context-events.jsonl --source etw
threatfalcon explain --input configs/etw-context-events.jsonl --event <event-uuid> --json
```

Health records now include per-provider `telemetry`: requested options, capture ID, observed and
normalized counts, queue admission/drop counts, publisher identity/stack counts, metadata issue
counts and last observation time. Counters saturate and reset each collector start. A metadata
issue degrades runtime health but is not a threat verdict. `observed` counts decoded callback
records; decoder panics are reflected in the existing collector-level counters instead.

`queue_admitted` is **not durable storage**. `analyze` independently counts records actually present
in its input, including a bounded provider-GUID map. Neither count is a unique-event count or proof
of all generated events. Health-only logs with no source events do not establish coverage.

`explain` adds a separate `publisher_activity` object when native identity is usable. It groups
matching publisher identities within the time window, explicitly not actor identity or causality.
At most 256 matching records (first in input order, displayed sorted by time) are included; matched
count and truncation are explicit. Because the existing index contains payload PIDs, these targets
use the existing full-scan path even when an index is available. Large-log costs still apply.

The actor process timeline stays empty for these targets. Opt-in native PowerShell fragment groups
also require matching capture/publisher identity; missing keys do not fall back to PID or legacy
records. `bundle` preserves target metadata without inventing actor-related events; it does not
currently add the separate publisher activity to its archive. Legacy rules outside these paths are unchanged.

日英の分析・ヘルス表示で、保存済み入力の件数と収集側カウンタを区別します。
`explain`の発行元イベント一覧は、プロセスツリーや攻撃連鎖の証明ではありません。
新しいプロセス識別情報を使えない場合、既存のPID相関に戻すことはありません。

## Validation gates / 検証条件

Development-host verification (2026-09-20):

- macOS: `cargo test --locked --offline --quiet` — 649 passed (483 unit, 7 analysis CLI,
  142 general CLI, 6 ETW context CLI, 11 health CLI); four existing macOS tests ignored.
- Windows x64 GNU and Linux x64 musl: application and test cross-builds passed with
  `RUSTFLAGS=-Dwarnings`. These binaries were **not executed** on Windows/Linux in this change.
- Six Windows/macOS/Linux sample profiles passed `--validate-config`; touched formatted Rust
  files passed rustfmt checks and the patch passed `git diff --check`.

Macで649件のテスト、Windows/Linux向けクロスビルド、6設定の検証が成功しました。
これは実Windowsでの収集・性能・他製品との共存を検証した結果ではありません。

Portable synthetic tests cover item/scalar/stack bounds, both widths, missing and duplicate keys,
unknown-field value exclusion, capture/agent/PID separation, script fragment separation, cache
isolation, JSON compatibility, query/index/explain/bundle paths, bounded publisher output and JA/EN
diagnostics. Windows-only fixture tests check SDK constants and owned native buffers.

An ignored, opt-in Windows test registers a private benign provider and emits empty `EventWrite`
records. It requires actual process/event keys and stack receipt, not just subscription success.
The source deliberately has no manifest, also exercising context capture independently of TDH.
It stops its owned session and unregisters its provider without modifying OS policy or protections.

On an authorized Windows test VM, with no other ThreatFalcon session running:

```powershell
$env:TF_WINDOWS_EXTENDED_TEST = '1'
cargo test --locked windows_extended_etw_owned_publisher_smoke -- --ignored --test-threads=1
```

This test proves only the private publisher path on the tested OS. Before production claims, also:

1. Record Windows build, architecture, effective privileges and selected provider configuration.
2. Validate each selected real provider with benign owned workloads; compare saved IDs, times and
   fields with independent ETW evidence. Mark unsupported/missing extensions explicitly.
3. Test repeated start/stop, denied privileges, slow/full output and sustained benign load. Measure
   CPU, RSS, handles, latency and losses with extension requests both disabled and enabled.
4. Confirm a fresh capture ID after restart, no stale PID joins and correct partial-stack behavior.
5. Test x64 and ARM64 separately before claiming both. A cross-build is not Windows execution.

合成データのテスト、Windows向けビルド、実Windows上の収集成功は別々の検証です。
実プロバイダ・負荷・長時間稼働の結果が揃うまで、実運用品質や高度脅威への網羅性を主張しません。

## Next stages / 次段階

Event-time module mapping and symbol enrichment need their own bounded, race-aware design; a
current on-disk DLL is not necessarily the image that existed when the event occurred. Event-ID
stack filtering, a trusted boot scope and properly validated actor identity are separate future work.
Protected ETW-TI consumption and kernel layers require their legitimate signing/access and Windows
acceptance gates; this feature does not implement or bypass those prerequisites.

モジュールとの対応付け・シンボル解決・メモリ属性・対象プロセス識別の強化は未実装です。
これらを追加する前に、今回の収集を実Windowsで検証します。
