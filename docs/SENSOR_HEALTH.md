# Sensor health / センサの収集品質

## Implemented scope / 実装範囲

Windows collection now reports ETW provider enable results, ETW session loss counters, and collector worker failures. Startup, periodic, and shutdown `SensorHealth` events use the existing local file or optional HTTP destination. macOS/Linux collection and the control server remain planned work. The new `health` command runs on all three OSes and supports Japanese and English; existing investigation commands and runtime logs still use English.

Windowsの収集処理で、ETWプロバイダの有効化結果、ETWセッションの欠落統計、収集ワーカーの異常を報告します。起動時・定期・停止時の`SensorHealth`イベントは、既存のローカルファイルまたは任意のHTTP出力先に保存します。macOS/Linuxの実収集とコントロールサーバは未実装です。新しい`health`コマンドは三つのOSで動作し、日本語・英語を選択できます。既存の調査コマンドと実行ログは英語のままです。

## Use / 使い方

Use [the Windows telemetry profile](../configs/windows-telemetry.toml) for a collection-focused configuration. Relative paths resolve against the config directory. The profile rotates files at 100 MB; it does **not** impose a total retention limit yet.

[Windowsテレメトリ用設定](../configs/windows-telemetry.toml)を配置して実行します。相対パスは設定ファイルのディレクトリ基準です。この設定は100 MBでファイルを分割しますが、総保存容量の制限はまだありません。

```powershell
# Validate, then run in an elevated Windows terminal.
# 設定を検証し、管理者権限のWindows端末で実行します。
.\threatfalcon.exe --config C:\ProgramData\ThreatFalcon\threatfalcon.toml --validate-config
.\threatfalcon.exe --config C:\ProgramData\ThreatFalcon\threatfalcon.toml

# Inspect the most recently appended health record in another terminal.
# 別の端末で、最後に記録されたヘルスイベントを確認します。
.\threatfalcon.exe health --input C:\ProgramData\ThreatFalcon\threatfalcon_events.jsonl --lang ja
.\threatfalcon.exe health --input C:\ProgramData\ThreatFalcon\threatfalcon_events.jsonl --lang en
.\threatfalcon.exe health --input C:\ProgramData\ThreatFalcon\threatfalcon_events.jsonl --json
```

`health` reads existing JSONL and never starts collectors or contacts a server. A record older than `--max-age-secs` (default 180) is marked `stale`; a timestamp more than 60 seconds ahead of the reader is marked `clock_skew`. Neither a recent record nor a zero loss counter proves complete coverage or the absence of threats. With periodic reporting disabled, only startup/shutdown records are available. For combined agent logs, select `--agent-id <UUID>`. Append order determines the latest record, including after clock adjustments; only the specified file is read, not rotated siblings. Malformed or partial JSON lines are counted as `skipped_lines`.

`health`は既存JSONLを読み取り、収集の開始やサーバ通信は行いません。`--max-age-secs`（既定180秒）より古い記録は`stale`、読取端末より60秒以上未来の記録は`clock_skew`として表示します。新しい記録や欠落数ゼロは、全活動の収集や脅威の不在を保証しません。定期出力を無効にした場合は起動・停止時の記録だけになります。複数端末のログでは`--agent-id <UUID>`を指定します。時計変更後も追記順で最新を選択し、指定したファイルだけを読みます。分割済みの他ファイルは検索しません。不正・不完全なJSON行は`skipped_lines`に計上します。

JSON field names, states, and diagnostic codes are language independent. Exit code 0 means the report could be read, including a degraded/stale report; use its fields for monitoring. Missing data, ambiguous agent selection, and file errors return a nonzero exit code.

JSONフィールド名・状態・診断コードは言語に依存しません。終了コード0は品質低下や古い記録も含め、レポートを読み取れたことを表します。監視では各フィールドを評価してください。対象記録なし、端末の指定不足、ファイル読取エラーは非ゼロで終了します。

## Fields and states / フィールドと状態

| Field | Meaning / 意味 |
|---|---|
| `collectors[].state` | `Starting`, `Running`, `Degraded`, `Stopped`, `Disabled`, `Unsupported`, `Error` / 起動中、稼働中、収集品質低下、停止、無効、未対応OS、エラー |
| `queue_events_dropped` | Rejected sends to the internal bounded queue, including after shutdown begins / 内部キュー満杯または停止開始後に受け付けられなかったイベント数 |
| `events_lost_before_queue` | Render/parser/panic losses before queueing, separately included in known drops / キュー投入前の描画・解析・パニックによる既知の欠落 |
| `events_observed`, `events_not_normalized`, `decode_failures` | Callback observations, unnormalized observations, and decoding/quality failures / 観測・未正規化・解析品質不良の累計 |
| `analysis_status` (envelope) | Correlation eligibility, missing evidence, lateness, capacity loss and finding counts / 相関分析の証拠適格性・欠損・遅着・容量超過・検知件数 |
| `analysis_status.state_restored`, `restored_timelines` | Whether persisted correlation state was applied in this run and how many process timelines were restored / 今回の実行で相関状態を復元したか・復元したプロセス時系列数 |
| `recovery_mode` | Sysmon `future_only` or `acknowledged_file_checkpoint` / ライブ収集のみ、またはファイル保存確認後の再開位置更新 |
| `checkpoint_committed_events`, `checkpoint_last_commit_at` | Source records covered by commits in this run and time of last commit; not a completeness proof / 今回の実行で再開位置を確定した元イベント数・最終確定時刻。完全性の証明ではない |
| `providers[]` | Configured provider name/GUID, `enabled`, native enable `error_code` / 設定されたプロバイダ名・GUID、有効化結果、OSエラーコード |
| `etw.events_lost` | ETW `EventsLost`: events / ETW側の欠落イベント数 |
| `etw.realtime_buffers_lost` | ETW `RealTimeBuffersLost`: buffers / リアルタイム配送で失われたバッファ数 |
| `etw.log_buffers_lost` | ETW `LogBuffersLost`: buffers / ログ記録で失われたバッファ数 |
| `etw.collected_at` | Time of the last successful statistics query or stop / 最後に統計取得または停止時統計取得に成功した時刻 |
| `error` | Collector failure code and optional native error number / 収集処理の診断コードと任意のOSエラー番号 |
| `statistics_error` | Query failure; previous sample retained, or `etw` absent if no sample succeeded / 統計取得失敗。前回値を保持し、一度も取得できていない場合は`etw`を省略 |

The top-level `events_dropped` sums known sink losses, collector queue and pre-queue losses, and ETW `EventsLost`. Buffer counts are reported separately because their number of events is unknown. These are per-run/session cumulative counters, not rates. `Degraded` persists for the rest of a run after a cumulative loss; provider failures or failed statistics queries also degrade a running collector. `Running` means the collector worker is active (ETW has opened a consumer, Sysmon has subscribed); successful provider enablement alone does not prove that every event type is available.

最上位の`events_dropped`は、把握できた出力時欠落、コレクタのキュー欠落・キュー投入前の欠落、ETWの`EventsLost`を合計します。バッファ内のイベント数は不明なため、バッファ数は合計しません。これらは実行・セッション単位の累計値で、発生率ではありません。一度累計欠落が出ると、その実行中の状態は`Degraded`になります。プロバイダ有効化失敗や統計取得失敗も稼働中の品質低下として扱います。`Running`はワーカー稼働中（ETWは購読開始成功、Sysmonは購読登録成功）を意味します。有効化成功だけではすべてのイベント種別の取得を確認できません。

New readers accept old health records without the added fields. Consumers that deserialize a fixed state enum must add the new states before reading new records. Zero-valued optional counters may be omitted. Health severity reflects sensor quality, not a malware verdict.

追加フィールドがない旧形式のヘルス記録も読み込めます。状態を固定列挙型で読み込む外部プログラムは、新しい状態への対応が必要です。任意のカウンタがゼロの場合は省略されることがあります。ヘルスイベントのseverityは収集品質を示し、マルウェアの判定ではありません。

## Shutdown / 停止処理

The output sink is opened before any collector starts. Only collectors whose startup succeeded are stopped. At shutdown, the queue is closed to new sends, workers are asked to stop, and accepted events are drained in order with process context enrichment. Final health follows the drain and sink flush. Callbacks rejected after the queue closes increment collector drop counters. Worker shutdown waits up to five seconds per worker; an error is recorded on timeout. A collector error remains visible in final health and causes a nonzero sensor exit. This does not promise lossless delivery from OS buffers during shutdown.

コレクタ起動前に出力先を開き、起動に成功したコレクタだけを停止します。停止開始時にキューへの新規受付を閉じ、ワーカーへ停止を要求し、受け付け済みイベントを順序どおりに処理・プロセス情報付与・出力します。その後に出力をフラッシュし、最終ヘルスイベントを記録します。受付終了後のコールバックはコレクタの欠落数へ計上します。ワーカーの停止待ちは一つにつき最大5秒で、タイムアウトはエラーになります。コレクタの異常は停止成功後も最終ヘルスに残り、センサは非ゼロで終了します。停止時にOSのバッファを含めて無損失で配送する保証ではありません。

## Validation / 検証

For opt-in Sysmon bookmark recovery, replay/duplicate boundaries and its separate native tests, see [Windows recovery](WINDOWS_RECOVERY.md). Output write/flush failures now also cause a nonzero sensor exit after cleanup. If the output is broken, retain stderr/service logs because final health cannot be guaranteed.

Sysmonの再開位置保存、重複再読込の範囲と実機テストは[Windowsの収集再開](WINDOWS_RECOVERY.md)を参照してください。出力の書き込み・フラッシュ失敗時も、後処理後に非ゼロで終了します。出力自体が壊れた場合は最終ヘルスを保存できないため、標準エラー／サービスログも保持してください。

Normal tests use fake collectors and recorded data, so Windows CI does not start a real sensor. CI runs the portable suite on Windows, macOS, and Linux. A separately ignored smoke test observes a benign `cmd.exe` process, queries real ETW statistics, verifies that a second collector cannot stop the first session, and stops the session. Run it alone in an elevated disposable Windows VM, or manually dispatch the CI workflow. It is not a production certification or a long-duration performance test.

通常テストは模擬コレクタと記録データを使い、Windows CIで実センサを起動しません。共通テストはWindows・macOS・Linuxで実行します。別途用意した通常無効のスモークテストは、無害な`cmd.exe`の起動を実ETWで観測し、統計取得、二重起動側が既存セッションを停止しないこと、セッションの停止を確認します。管理者権限の使い捨てWindows VMで単独実行するか、CIを手動実行してください。本番品質認定や長時間性能試験を代替するものではありません。

```powershell
cargo test --locked
cargo test --locked windows_etw_process_smoke -- --ignored --test-threads=1
```

Implementation references / 実装の参考資料:

- Session query and stop / セッション統計取得と停止: [Microsoft ControlTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew).
- Counter units and buffer layout / カウンタの単位とバッファ構造: [Microsoft EVENT_TRACE_PROPERTIES](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties).
- Consumer initialization / 購読の初期化: [Microsoft OpenTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew).
