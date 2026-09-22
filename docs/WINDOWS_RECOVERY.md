# Windows source recovery / Windowsの収集再開

Experimental implementation. Portable failure-injection tests and Windows-target type checking do not demonstrate Windows runtime correctness. This is not an exactly-once delivery, power-loss certification, tamper-proofing or advanced-threat coverage claim.

実装・検証途上です。可搬テストとWindows向け型チェックだけでは実機動作を実証できません。完全無損失、重複なし、耐改ざん性、停電耐性、高度脅威の網羅を保証するものではありません。

The [2026-09-22 Windows VM validation](WINDOWS_VALIDATION_2026-09-22.md) passed the
bounded native Sysmon push and unacknowledged-record replay checks after correcting
idle pull waits. This does not replace the fault/load/retention testing described below.

## Source and output contract / 元ログと出力の契約

With `collectors.sysmon.checkpoint_path` set and Sysmon enabled:

1. A single worker opens an agent-bound SQLite checkpoint under an exclusive lock. A different agent, unsupported checkpoint format, missing row or corrupt payload is an error, not a reason to reset progress.
2. An absent initial bookmark starts at the oldest **retained** Sysmon record. On restart, the worker verifies the bookmarked record's native record ID, SystemTime, Computer and event type, then subscribes strictly after it. Expired/replaced/mismatched records stop recovery instead of silently skipping forward.
3. Pull delivery holds at most 32 source records per uncommitted batch. The bounded sensor queue applies backpressure; the next batch is not fetched until the current batch is acknowledged. It is not a byte-budget or Windows EventLog internal-memory guarantee.
   Once the current results are exhausted, the worker waits for a fresh Event Log notification,
   checking shutdown every 100ms. A wait timeout does not cause another `EvtNext` call against
   an exhausted subscription.
4. The sensor writes each source event and the correlations generated from it. Only after the entire batch has succeeded does it flush and `sync_all` the local file. Rotated segments are also synchronized before rotation.
5. Only that success acknowledgement permits a **single SQLite transaction** to update the bookmark/native identity, changed correlation timelines, finding-suppression keys and input-dedup order together. SQLite uses `synchronous=FULL` and a persistent rollback journal. Failed writes, synchronization, parsing, analysis validation or interrupted batches do not advance the bookmark. A DB failure rolls back both the source position and analysis mutations.

日本語の要点：キューに入った時点や読み取った時点では保存位置を進めません。元イベントと生成された検出結果のファイル保存・同期が成功した後だけ、再開位置と相関状態を同じトランザクションで確定します。初回は保持済みの最古レコードから読みます。再起動時に元レコードが失われた、別の記録に置き換わった、保存位置や相関状態が壊れた場合は、自動リセットせずエラーにします。

This is an **at-least-once design while the source records remain available**, with important boundaries:

- A crash after file synchronization but before checkpoint commit can replay the last batch. Ordinary shutdown stops workers before draining accepted events, so its final batch can also be replayed. Up to 32 source records per outstanding batch (plus their findings) may appear again; repeated failures can accumulate duplicates.
- Replayed source envelopes currently receive new UUIDs. For bounded offline deduplication the detector uses agent/provider/native record ID/source time when available. External consumers must also handle replay; UUID alone is insufficient. Never deduplicate by PID alone.
- In checkpoint mode, bounded correlation facts, original evidence UUIDs, finding-suppression keys and input-dedup order are persisted and restored before the first new batch is analyzed. This closes the in-memory-only restart gap for the three current Sysmon rules. It does not extend their 10-minute state window or capacity limits, reconstruct expired evidence, or persist the separate process-context cache. Live-only/HTTP/stdout modes still start with empty analysis state. The standalone `analyze` command also starts with empty state and never reads or mutates the checkpoint DB.
- ETW remains a live feed: this bookmark does not recover ETW buffers, records already overwritten by Windows, events excluded by Sysmon policy, or periods before Sysmon was installed.
- Bookmark verification and subscription creation are separate Windows API operations, not a transaction protecting the channel against a privileged concurrent clear/replacement. This is not protection against an attacker who controls the source or checkpoint.
- A full or failing disk, OS/hardware flush semantics, directory metadata durability, filesystem choice, rotation, concurrent writers, VM snapshots and abrupt power loss require native fault testing. Use a dedicated local disk path and one sensor writer; network shares/removable storage are not validated.
- File rotation alone is **not retention enforcement**. The optional [file-family byte budget](PRODUCTION_HARDENING.md) stops output before exceeding its limit; it never deletes evidence or acknowledges the failed source batch. The operator must retain and protect all segments needed for evidence and analysis; file disappearance after acknowledgement is outside the source protocol.

再読込による重複はあり得ます。再開位置保存モードでは相関状態・証拠ID・重複抑止状態も復元しますが、ルールの時間窓や容量上限は変わりません。ETW、Sysmonの除外対象、Windows側で既に上書きされたログはこの機構では復元できません。

## Analysis persistence / 相関状態の永続化

Normal commits write only changed/deleted process timelines and dedup-key additions/removals, not a full snapshot of every process per batch. State retains at most 10,000 timelines, 64 observations per timeline, and 50,000 dedup keys. Each stored timeline is limited to 64 KiB and validated before use. Counts, identities, source times, version and suppression references are checked; invalid state stops recovery instead of silently starting empty. Counters remain per-run; restoration does not re-count old source records or re-emit already committed findings.

Checkpoint database format is now **3**, with an independently versioned correlator state format. Rule/state semantic changes must bump `STATE_VERSION`. Earlier source-only checkpoint formats are rejected **without migration or deletion**, because their absent analysis history cannot be recovered by a schema change. Preserve old DB/journal/output files and reconstruct a reviewed baseline from available source evidence before an operator-approved transition; no automatic migration/reset tool is implemented.

差分だけを保存し、復元時に形式・件数・プロセスID・時刻・証拠参照を検証します。旧形式には相関状態がないため、形式変更だけで検知履歴を復元したことにはできません。旧DB・ジャーナル・出力を保持して移行方法を判断してください。破棄や自動初期化はしません。

## Configuration / 設定

Use [the recovery pilot profile](../configs/windows-recovery.toml) in an authorized Windows lab. Install/configure Sysmon separately with ProcessCreate and the events required by your detection scenarios. ThreatFalcon never installs Sysmon, clears the channel, changes log retention or replaces policy automatically.

```powershell
.\threatfalcon.exe --config .\configs\windows-recovery.toml --validate-config
.\threatfalcon.exe --config .\configs\windows-recovery.toml
.\threatfalcon.exe health --input .\configs\threatfalcon_events.jsonl --lang ja
.\threatfalcon.exe health --input .\configs\threatfalcon_events.jsonl --lang en
```

Paths are relative to the configuration directory, including the checkpoint. Output/checkpoint/agent-state paths must be distinct. Keep the agent identity stable and unique per host. Protect the checkpoint **and its `-journal` file**, output, configuration and agent-state directory with appropriate ACLs and disk encryption. They are not authenticated against privileged tampering. Do not copy a live SQLite file without a coordinated backup procedure or edit/remove its journal.

Checkpoint mode is currently rejected with stdout or HTTP output. An HTTP response or a normal buffer flush is not this local durability contract. With `checkpoint_path` omitted, Sysmon uses future-only push delivery and queue-full drops are counted; restart recovery is not enabled. Existing configurations retain that behavior.

保存位置を有効にした場合、標準出力とHTTP出力の組合せは設定エラーにします。`checkpoint_path`を省略した既存設定は、従来どおりライブ収集のみです。保存先ディレクトリとSQLiteジャーナルを含めて保護し、実行中のDBやジャーナルを手作業で削除・変更しないでください。

`health --lang ja|en` shows `recovery_mode`, `checkpoint_committed_events` (this run only), `checkpoint_last_commit_at`, and `analysis_status.state_restored` / `restored_timelines`. Restoration is applied immediately before the first batch is analyzed; an idle subscription's startup health need not report it yet. Zero counts do not distinguish idle input from a blocked pipeline; inspect collector state, error codes and logs. `sysmon_recovery_failed` means the worker stopped; it does not claim an exact number of lost source records. Other collectors can continue until the sensor is stopped, so monitor each collector rather than only process liveness. Checkpoint-mode startup allows 30 seconds for bounded state loading and native subscription setup (live-only: 5 seconds); large/cold-state startup still needs native measurement.

If source retention or identity validation fails, preserve the DB, journal and available logs; investigate and export surviving evidence before deciding on a new collection baseline. There is deliberately no automatic “reset and continue” command. Do not delete evidence as a troubleshooting shortcut.

## Output fault handling / 出力障害への対応

- An unterminated JSONL tail is preserved byte-for-byte and separated by a newline before the next append. It may still be incomplete; this does not invent a missing event. Offline readers report malformed lines.
- Unreadable, invalid-UTF8 or invalid-event HTTP spool files are retained. Draining reports an error for operator inspection instead of deleting unknown evidence. An ordinary network outage still uses the configured disk spool/capacity policy; this is not a remote source-checkpoint implementation.
- Startup, periodic and final health write/flush errors make the sensor run fail. Cleanup still stops owned collectors and drains accepted events. When the output itself is broken, final health may be unavailable: retain stderr/service logs and monitor process exit separately.

## Native validation gates / 実機で確認すること

Normal tests never start real collectors. The following ignored tests require an elevated, disposable Windows VM with preinstalled Sysmon and ProcessCreate enabled:

```powershell
cargo test --locked
cargo test --locked windows_sysmon_ -- --ignored --test-threads=1
cargo test --locked windows_etw_process_smoke -- --ignored --test-threads=1
```

The Sysmon push test creates only a benign `cmd.exe /d /c exit 0`, checks native time/GUID/record metadata and stops its subscription. The recovery test reads one recent record to seed its private temporary checkpoint, deliberately withholds acknowledgement of a benign process event, restarts the collector and checks that the same native record is replayed and committed. It neither clears the host log nor installs/reconfigures Sysmon. Temporary test artifacts may contain local telemetry; run on a disposable non-sensitive VM. These tests are not automatically enabled by the existing manual ETW CI job.

Also measure loss and duplicates against native records during restart, disk-full/read-only conditions, rotation, backlog, stale bookmarks, log clearing, service-account permission changes, suspend/resume and VM power interruption. Run long-duration tests with representative benign workloads, including **sensor-generated file/registry activity**; broad lab logging can create feedback and load. Set measurable CPU/memory/disk/latency and false-positive budgets before deployment.

実機テストは用意しましたが、このmacOS開発環境では未実行です。合成イベントのテスト成功を、Windowsでの収集成功・実脅威の検知率として扱わないでください。

Portable regression tests split synthetic sequences at every event boundary and compare all three rules' findings/evidence IDs before and after restoration. They also check committed dedup/suppression, expiry, invalid state, source/analysis transaction rollback, and a file-output → DB → restart → finding path.

A separately ignored, benign synthetic I/O workload can be run without collectors:

```sh
cargo test --locked checkpoint_workload_measurement -- --ignored --nocapture
```

One macOS debug-build run processed 4,096 synthetic events in 128 durably acknowledged batches across 128 process timelines in **3,020 ms**, producing 7,203,745 output bytes and a 2,060,288-byte DB (journal size excluded). No configured analysis-capacity drops occurred. This is one development measurement, **not Windows throughput, peak-load capacity or a performance SLA**. Repeat with representative native workloads and retain hardware/OS/build details before making deployment claims.

## Primary references / 一次資料

- Callback and signal-event modes are mutually exclusive; enumerated pull handles must be closed: [Microsoft EvtSubscribe](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe).
- Native bookmark creation, rendering and restoration: [Microsoft Bookmarking Events](https://learn.microsoft.com/en-us/windows/win32/wes/bookmarking-events).
- Strict subscription and missing-record behavior: [Microsoft EVT_SUBSCRIBE_FLAGS](https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_subscribe_flags).
- Query handles stay on their creating thread; enumeration ownership: [Microsoft EvtQuery](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtquery), [Microsoft EvtNext](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext).
- Durability modes and reusable rollback journals: [SQLite PRAGMA documentation](https://www.sqlite.org/pragma.html#pragma_journal_mode).
- Source and correlator mutations use one transaction; its hardware/filesystem assumptions still matter: [SQLite atomic commit documentation](https://www.sqlite.org/atomiccommit.html).

The acknowledgement barrier, identity checks, batch bound and acceptance criteria are ThreatFalcon design decisions, not guarantees supplied by these sources.
