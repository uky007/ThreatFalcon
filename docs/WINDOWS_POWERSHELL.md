# Windows PowerShell telemetry / PowerShell収集

Experimental sensor support for Windows PowerShell and PowerShell Core (including PowerShell 7).
This change adds source normalization and fragment metadata, **not** script execution, decryption,
reassembly, a new detection rule, or proof of live Windows coverage.

Windows PowerShellおよびPowerShell Core（PowerShell 7を含む）の実験的な収集対応です。
分割されたログを、完全なスクリプトや実行成功の証明と扱わないための変更です。
実Windowsでの収集確認は未実施です。

## Sources / 収集元

The two engines have distinct ETW providers. Windows PowerShell uses
`A0C1853B-5C40-4B15-8766-3CF1C58F985A`, while PowerShell Core uses
`F90714A8-5509-434A-BF6D-B1624C8A19A2`. Both document script-block logging as event 4104.
PowerShell Core's provider registration and logging configuration are operator-managed;
ThreatFalcon does not install a manifest or change policy.
See [Windows PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1)
and [PowerShell Core logging on Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5).

PowerShell 7はWindows PowerShellとは別のプロバイダです。表示名ではなくGUIDとイベントIDで
正規化対象を選びます。プロバイダを有効化できても、マニフェスト登録・ログ設定・収集範囲の
確認が済んだわけではありません。センサから設定変更や署名・保護設定の解除は行いません。

## Data contract / 保存する意味

The official [PowerShell v7.5.0 manifest](https://github.com/PowerShell/PowerShell/blob/v7.5.0/src/PowerShell.Core.Instrumentation/PowerShell.Core.Instrumentation.man)
defines `MessageNumber`, `MessageTotal`, `ScriptBlockText`, `ScriptBlockId`, and `Path` for the
script-block template. The first two are signed 32-bit fields. The
[logging implementation](https://github.com/PowerShell/PowerShell/blob/v7.5.0/src/System.Management.Automation/engine/runtime/CompiledScriptBlock.cs)
emits one-based fragment positions and can transform or protect logged text. ThreatFalcon uses
runtime TDH metadata, not fixed byte offsets or reverse-engineered private structures.

- `ScriptBlock` gains optional `message_number` and `message_total`. Valid positions satisfy
  `1 <= message_number <= message_total <= INT32_MAX`; missing values never become an implicit `1/1`.
- Old JSONL records still deserialize; absent or representable-but-invalid positions are displayed
  as unknown. JSON values with invalid types/ranges are counted as malformed input by analysis.
  A `1/1` record is a single-part **logged event**, not proof of complete source code or execution.
- A valid native record retains the header PID, non-nil ScriptBlock UUID, optional path, text as
  logged, provider GUID, schema version, opcode, source time and observation time.
- Invalid PID, script ID, counts, missing text, case-ambiguous fields or TDH errors fall back to
  `NativeTelemetry` with native evidence and quality codes. No false normalized script is invented.
  Non-fragment diagnostic records with nonpositive counts are not treated as normal script content.
- `script_engine` distinguishes `PowerShell` from `PowerShellCore`; it does not infer an exact
  installed engine version from the provider GUID.
- Neither a count nor a UUID triggers a count-sized allocation. This feature introduces no fragment
  aggregation buffer; existing bounded TDH decoding applies.

分割番号・総数・スクリプトID・元時刻を保持します。不正値や不足値は生データと品質警告に
戻し、存在しない情報を補いません。順序逆転、重複、欠けた断片を自動結合しないため、
完全なスクリプトの再構成や正確な欠落断片数はまだ提供しません。

## Identity and inspection / 識別・調査

The sensor's process cache no longer attaches a different ETW process solely because it has the
same PID as a native PowerShell 4104 event. ScriptBlockId identifies logged script fragments, not a
process lifetime or an invocation count.

For native PowerShell targets, `explain` groups candidate fragments only when agent ID, provider
GUID, header PID and valid ScriptBlockId agree, source time/quality are usable, and the existing
time window includes them. It does not concatenate or deduplicate them, validate a complete set,
or correlate AMSI by PID. Its process timeline stays empty when no trustworthy process lifetime
identity is available; even a legacy cached process key is not used for these native targets.
Native fragments are also excluded from other targets' PID-only explain timelines/AMSI grouping.
`bundle` does not invent related process events for a native script without a lifetime identity.
Older non-native investigation heuristics elsewhere in the application are unchanged.

PID再利用による誤相関を避け、センサのプロセスキャッシュと`explain`での結合を制限します。
同じ端末・プロバイダ・PID・スクリプトIDの断片を表示しますが、同じプロセスの全活動や
スクリプト実行回数を確定するものではありません。`query --pid`は数値による絞り込みです。

`analyze --lang ja|en` now reports counts of single-part events, multipart fragments, unknown
positions, and native PowerShell 4104 records that were not normalized. These are event counts,
not unique-script counts, missing-part counts, or successful-execution counts. Unparsed native
records surface as recorded degradation. The report explicitly states logging-policy,
reassembly, protected-content and execution-proof limitations.

日本語・英語の分析表示に、単一部・複数部・分割情報不明・未正規化の件数を追加しました。
収集できたイベント数であって、固有スクリプト数・欠落数・実行成功数ではありません。

## Controlled configuration / 検証用設定

The built-in provider list is unchanged: PowerShell Core is **opt-in**, so existing installations
do not silently expand script capture. The standalone profile below replaces the default ETW
provider list with the two PowerShell providers and disables other collectors. It captures their
ETW traffic; non-4104 events may remain native telemetry. It is not an Event Log replay reader.

```powershell
.\threatfalcon.exe --config .\configs\windows-powershell.toml --validate-config
.\threatfalcon.exe --config .\configs\windows-powershell.toml
```

Review [the profile](../configs/windows-powershell.toml), set the hostname, protect the executable,
configuration and output directory, and confirm the administrator-managed logging prerequisites
before running on an authorized Windows host. Stop with Ctrl+C. Relative paths resolve against
the configuration directory. Output is local by default; rotation is not a total-retention policy.
When extending another configuration, preserve its existing providers because explicit provider
arrays replace the defaults.

既定の収集範囲は増やしません。専用プロファイルを確認して明示的に使ってください。
マニフェスト登録やログ設定は管理者が管理し、機密情報を含み得る出力を保護します。
別設定に統合する際は、プロバイダ配列が既定値への追加ではなく置換になる点に注意してください。

```text
threatfalcon query --input configs/powershell-events.jsonl --source PowerShellCore --pid 4242
threatfalcon analyze --input configs/powershell-events.jsonl --lang ja
threatfalcon analyze --input configs/powershell-events.jsonl --lang en
threatfalcon explain --input configs/powershell-events.jsonl --event <event-uuid> --json
```

## Privacy / 機密情報

Script logs can contain credentials and other sensitive material. Microsoft recommends considering
Protected Event Logging outside diagnostics; follow the linked official deployment guidance.
ThreatFalcon preserves CMS text if supplied, never decrypts it or requests private keys, and never
evaluates script text. It does not guarantee that the source encrypted an event. Native fields and
fallback payloads can also contain sensitive data; do not rely on the normalized fields alone for
redaction. Access controls, retention and export policy remain operator responsibilities.

スクリプトログには認証情報などが含まれ得ます。保護ログの採用は上記Microsoft資料に沿って
検討してください。センサは暗号文を解読せず秘密鍵も要求しませんが、OS側で暗号化されたかを
保証しません。生フィールド・フォールバックにも機密情報が残り得るため、保存・転送を管理してください。

## Validation gates / 検証範囲

Portable tests cover both provider IDs, fragment positions, missing/invalid/ambiguous metadata,
opaque CMS-like text, Japanese text, old JSONL compatibility, PID-cache isolation, scoped fragment
grouping, file delivery, index/non-index queries and JA/EN analysis. No test evaluates logged content.

Development-host verification (2026-09-13): all 624 ordinary Mac tests passed (464 unit,
7 analysis CLI, 142 general CLI, 11 health CLI; 4 existing Mac tests ignored). Windows x64 GNU
and Linux x64 musl application/test cross-builds passed with `RUSTFLAGS=-Dwarnings`.
The PowerShell and existing Windows profiles passed configuration validation. Native Windows
smoke tests were compiled but not executed; cross-building is not native collection validation.

開発Macで624件のテストが成功し、Windows/Linux向けの警告をエラー扱いにしたクロスビルドも
成功しました。Windows実収集テストはコンパイルのみで、未実行です。

An ignored native smoke test starts only an operator-approved `pwsh.exe` with a benign command,
without profiles or policy changes, then requires a valid 4104 event from that child PID. The child
is bounded by a timeout and killed on cancellation. No event contents are printed, decrypted or
matched as executable code. A successful subscription with no matching event fails the test.

Run only on an authorized isolated Windows VM with PowerShell Core and its logging prerequisites
already configured. Supply the absolute path to the trusted executable:

```powershell
$env:TF_WINDOWS_POWERSHELL_TEST = '1'
$env:TF_PWSH_TEST_EXE = 'C:\Program Files\PowerShell\7\pwsh.exe'
cargo test --locked windows_powershell_core_etw_smoke -- --ignored --test-threads=1
```

This probe proves only one provider/child event path. Native single/multipart capture, engine/build
differences, protected logging, denied access, sustained load/loss and restart behavior still require
Windows acceptance tests. No custom driver or additional threat-detection capability is claimed.

合成データのテストとWindows実収集は区別します。通常無効のスモークテストは無害な子プロセスの
イベント受信を要求しますが、それだけでは長文の全断片・保護ログ・負荷・欠落率・再起動時の
品質を保証しません。ドライバ追加や高度脅威検知の完成を意味する変更ではありません。
