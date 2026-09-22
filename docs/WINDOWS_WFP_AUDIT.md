# Windows WFP audit sensor / Windows WFP監査センサ

Status: experimental, opt-in, read-only. Bounded native Windows 11 validation passed;
see [2026-09-22 results and limits](WINDOWS_VALIDATION_2026-09-22.md). Broad coverage and production readiness remain unverified.
This adds telemetry, not a detection rule, firewall, WFP callout driver, or commercial EDR equivalent.

状態：実験的・明示的有効化・読み取り専用。Windows 11 VMで許可・遮断の短時間実収集を確認済みです。
収集範囲の網羅性と本番運用品質は未検証です。
検知ルール、ファイアウォール、独自WFPドライバ、市販EDRと同等の機能を追加するものではありません。

## Research boundary / 調査の扱い

The user-provided [Inside the Falcon article](https://0xdbgman.github.io/posts/inside-the-falcon-how-crowdstrike-catches-you/)
motivated a review of layered telemetry. It is third-party reverse engineering, not an authoritative
CrowdStrike specification. Imports or inferred internal structures do not establish active collection
paths, configuration, or completeness. This implementation uses public Microsoft interfaces and
independently authored code; it does not reproduce proprietary structures, offsets or bypass techniques.

提示記事は多層のテレメトリ収集を再検討する参考資料として扱います。第三者解析の記述から、
製品の現行仕様や網羅性までは断定しません。公開APIで裏付けられる収集機能を独立実装します。

## Implemented source / 今回の収集対象

The local `Security` log, provider `Microsoft-Windows-Security-Auditing`, is subscribed through
the documented Event Log polling API. Only WFP authorization audit events
[5156 (permitted)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156)
and [5157 (blocked)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5157)
are selected. The native reader uses
[EvtSubscribe](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe),
[EvtNext](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext), and
[EvtRender](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtrender).

Windowsの接続許可・遮断の監査記録を収集します。Securityログの他のイベント、通信本文、
接続終了、転送量、DNS応答はこの収集器の対象外です。許可はTCP接続成立やデータ送信の証明ではなく、
遮断もマルウェア判定ではありません。両方とも `Severity::Info` の独立した監査データとして保存します。

### Evidence contract / データの意味

- `WindowsSecurity { event_id }` / `WfpConnectionAudit` is distinct from `NetworkConnect` and Sysmon.
  Native event time, provider identity, schema version and record ID accompany the observation time.
- The actor PID comes from `EventData.ProcessID` or the 5156 v1 spelling `EventData.ProcessId`.
  Both names occurring together are ambiguous and leave the actor PID absent with a quality issue.
  `System.Execution.ProcessID` is retained separately
  as publisher metadata; it is never used as the actor. Decimal and explicitly prefixed hexadecimal
  PIDs are accepted. Missing/invalid values stay absent, with quality issues; no default PID/port 0.
- PID alone cannot identify a process lifetime. No PID-only ETW/Sysmon process-cache join is made.
  Filtered record-ID gaps are not missing-event counts, and record IDs are not global stable IDs.
- Application device paths and source/destination labels remain native, without current-filesystem
  lookups or local/remote swaps. Direction and layer names remain unlocalized tokens, not guessed enums.
- Core fields in 5156 versions 0–2 and 5157 versions 0–4 are normalized. Their names and types were
  checked against the installed Microsoft provider templates on Windows 11 build 26200.9457;
  live samples used 5156 v1 and 5157 v3. Other versions preserve allowlisted evidence and report
  an unsupported-version issue without guessing typed fields.
- Only the fields enumerated in `src/collectors/wfp_audit/parser.rs` are retained. Remote user/machine
  identifier values and unknown EventData values are omitted; their field names remain auditable.
  Paths, hostnames, PIDs and addresses are still sensitive: restrict file access, retention and exports.

接続認可の証跡と通信成立・脅威判定を分離します。PIDの再利用による誤相関を避け、
不正値・不足値・未知バージョンを明示します。不要な識別子の値は保存しませんが、
残るパス・ホスト名・アドレスにも適切なアクセス制限と保持期限が必要です。

## Running / 利用方法

The collector defaults to disabled. An operator must authorize access to the local Security log
and configure the Filtering Platform Connection audit subcategory: success for 5156, failure for
5157. This policy can generate high event volume. Review capacity and retention before enabling it.
The sensor neither changes audit policy nor adjusts privileges. See Microsoft's
[audit policy documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-filtering-platform-connection).

初期値は無効です。管理者がSecurityログのアクセス権と監査設定を確認してください。
設定変更はセンサが自動実行しません。成功監査は高頻度のイベントを生むため、容量と負荷を事前評価します。
購読開始に成功しても、監査が有効とは限りません。ゼロ件は安全や網羅性の証明ではありません。

On an authorized Windows test host, after reviewing the profile and operator-managed prerequisites:

```powershell
.\threatfalcon.exe --config .\configs\windows-wfp-audit.toml --validate-config
.\threatfalcon.exe --config .\configs\windows-wfp-audit.toml
```

Stop with Ctrl+C. The sample writes locally and disables every other collector for isolated validation.
Set the hostname appropriately. Relative output/state paths are resolved against the config directory.
Protect that directory before running an elevated process. No service installation or server is required.
To combine this feed with an existing profile later, add `[collectors.wfp_audit]` with `enabled = true`;
that does not extend Sysmon's checkpoint/recovery guarantees to this source.

サンプルは単独検証用で、他の収集器を無効化し、ローカルに出力します。ホスト名を設定し、
実行前に設定・出力先を保護してください。Ctrl+Cで終了します。既存プロファイルへ追加しても、
Sysmonの復旧機構がWFP監査にも適用されるわけではありません。

Read-only investigation works on Windows, macOS and Linux, in Japanese or English:

```text
threatfalcon query --input configs/wfp-audit-events.jsonl --source windowssecurity --pid 4242
threatfalcon analyze --input configs/wfp-audit-events.jsonl --lang ja
threatfalcon analyze --input configs/wfp-audit-events.jsonl --lang en
threatfalcon health --input configs/wfp-audit-events.jsonl --lang ja
```

## Collection quality / 収集品質と限界

- Future-only strict subscription, one owned blocking worker, native batches of 16 handles.
  After draining a batch, notification waits check shutdown every 100ms; a wait timeout does not
  trigger another read of the exhausted subscription. All event/subscription/signal handles have
  scoped cleanup; no FFI callback.
- Render allocation is capped at 131074 bytes of UTF-16 storage. Parsed XML is capped at 64 KiB,
  individual values at 4 KiB, EventData fields at 64. Invalid namespaces, duplicate fields/sections,
  DTDs, processing instructions, unsupported entities and nested scalar markup are rejected.
- When the shared queue has at least 512 occupied slots, this feed drops new admission and increments
  its saturating queue-drop counter. This is an admission threshold, not a per-source reserved queue;
  other collectors can cause it to trigger. OS read/render/parse work is still done, so this is not a
  CPU rate limit. Smaller/full queues and closed receivers are also accounted for.
- Render/parse failures and partial normalization affect health. Error messages are fixed diagnostic
  codes; no raw event XML or omitted values are logged on parse failure.
- `wfp_audit.records_read` counts successfully enumerated records; `fields_omitted` counts fields,
  not records. `audit_policy_verified` stays false. `Running` means the subscription is ready, not
  that coverage is complete. JA/EN diagnostics explicitly say policy/coverage remain unverified.
- No bookmark, restart/outage replay, automatic resubscription, total source-loss counter, packet
  capture, prevention, tamper protection, lifetime process identity, or new detection rule is supplied.
  Subscription/log errors stop this collector and surface in health; gaps are not silently declared clean.

ライブ購読のみで、停止中の再読込はありません。キュー溢れと解析失敗は報告しますが、
OS側を含む総欠落数は測定できません。`Running`は購読準備の完了を意味するだけです。
監査設定・保持期間・元ログの状態を含めて、収集範囲を別途検証してください。

## Next sensor layers / 次の開発段階

These are future design candidates, **not implemented by this change**. Select them by measured gaps
in existing ETW/Sysmon telemetry, not by assuming every callback implies complete visibility.

| Layer / 領域 | Public mechanism / 公開機構 | Acceptance requirement / 受入条件 |
| --- | --- | --- |
| Process lifecycle / プロセス | [Process notifications](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex) | Event-time metadata and validated lifetime identity; no PID-only merge |
| Handle operations / ハンドル操作 | [Object callbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks) | Scope and access semantics, signed image, safe unregister/unload |
| Registry / レジストリ | [Registry callbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex) | Operation/result distinctions; bounded metadata and privacy |
| File operations / ファイル | [Filter Manager minifilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers) | Identity/name-change semantics, recursion avoidance, interoperability |
| Network / 通信 | [WFP callouts](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-windows-filtering-platform-callout-drivers) | Layer-specific authorization versus flow semantics; no unintended blocking |
| Participating script hosts / 対応スクリプトホスト | [AMSI integration](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) | Host/provider scope and signing; content minimization, not every script globally |

Kernel work needs a separate WDK build, narrow device/IPC permissions, bounded nonpaged memory,
versioned records, worker/callback shutdown validation, signing/distribution review, and Windows VM
stability/performance testing before deployment. Do not deploy driver prototypes on the development
host or weaken endpoint protections to make the sensor run. A custom driver is not automatically
required for every gap; Microsoft's [WFP roadmap](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/roadmap-for-developing-wfp-callout-drivers)
also recommends considering whether a user-mode application suffices.

上表は未実装の候補です。独自ドライバは別のWDKビルド・署名・権限制御・安定性検証を要します。
まず既存収集の不足を実測し、必要な層から追加します。保護機能の無効化や開発端末への試作ドライバ導入を
前提にしません。収集を増やすだけでなく、識別の正しさ・欠落の可視化・安全な停止を受入条件にします。

## Validation gates / 検証

Portable tests exercise independently authored synthetic XML (not malware): both event IDs, versions,
IPv4/IPv6, explicit hexadecimal PID, missing/overflow fields, nanosecond source time, strict parsing,
omitted secrets, bounded queue admission and the parse → delivery → local file → analysis/index path.
CLI tests cover JA/EN diagnostics, no-findings semantics and indexed/non-indexed queries.

Development-host verification (2026-09-13): `cargo test --locked --offline --quiet` passed
611 tests (453 unit, 5 analysis CLI, 142 general CLI, 11 health CLI); 4 existing tests remained ignored.
Windows x64 GNU and Linux x64 musl application/test cross-builds passed with `RUSTFLAGS=-Dwarnings`.
The example profile passed config validation. These results do not include native Windows/Linux execution.

開発用Macで611件のテストが成功し、Windows/Linux向けクロスビルドと設定検証も通過しました。
これはWindows/Linux上での実収集検証ではありません。

Windows-specific native code is cross-buildable, but cross-compilation is not a runtime test.
The ignored `native_subscription_probe` opens and closes the local subscription without policy changes;
it tests permissions/lifecycle only and cannot prove coverage.

The [2026-09-22 native validation](WINDOWS_VALIDATION_2026-09-22.md) additionally checked
idle waits, actual permitted/blocked IPv4 records, original Security-log evidence,
normal stop and policy restoration in two bounded runs. It does not complete the
broader validation gates below.

Before claiming live support, validate on an authorized Windows x64 VM and retain redacted evidence:

1. Confirm OS/build, audit success/failure policy, Security log access and retention externally.
   Verify denied access and inactive audit policy are not represented as complete coverage.
2. Generate only benign, owned test traffic. Compare 5156 records in Event Viewer with saved telemetry;
   verify actor versus publisher PID, event time, native paths, IPv4/IPv6 and both language environments.
   Validate 5157 using operator-approved existing test restrictions; the sensor must not change them.
3. Exercise sustained benign load, slow/full/unwritable output, repeated start/stop and restart.
   Measure CPU/RSS/handles/latency, count observed queue drops, and verify future-only restart semantics.
4. On a disposable snapshot only, have the operator exercise Event Log interruptions/retention changes;
   require visible errors, clean handle release and no fabricated exact loss counts.

合成データによる単体・結合テストと、Windows実収集は区別します。VMで許可済みの無害な通信を使い、
元のSecurityログと出力を照合し、負荷・権限不足・停止再開・ログ障害時の品質も検証するまで、
実運用品質や市販EDR相当の可視性を主張しません。
