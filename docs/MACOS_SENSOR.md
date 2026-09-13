# macOS native sensor / macOSネイティブセンサ

## Status / 現状

Experimental native Endpoint Security collector; **not a completed macOS EDR**.
macOSネイティブEndpoint Securityセンサの初期実装です。完成したEDRではありません。
Windows work is preserved on `work/windows-telemetry-foundation` (`e8d8cc7`);
macOS work branches from it on `feat/macos-endpoint-security`. These branches have
not been integrated with the independently advanced `origin/main`.

The Rust sensor uses a small C bridge compiled against Apple's selected SDK.
There are no guessed ES struct offsets, eslogger subprocesses, kernel extensions,
AUTH responses, or security-policy changes. `eslogger` is explicitly not an
application API and has no schema/performance guarantees suitable for this
collector. [Apple WWDC22](https://developer.apple.com/videos/play/wwdc2022/110345/)

## Implemented coverage / 実装した収集範囲

| Native NOTIFY event | Preserved semantics / 保持する情報 |
|---|---|
| exec | Pre-exec actor and post-exec target / 実行前・実行後のイメージ |
| fork | Parent actor and child target / 親と子 |
| exit | Native wait(2) status / ネイティブ終了状態 |
| create | Existing file or directory + new name; native authorization result |
| rename | Source and existing destination or directory + new name |
| unlink | Target file / 削除対象 |
| write | Target file, **not** content or byte count |
| close | modified and version-gated was_mapped_writable (not equivalent) |

Every event retains native time, message/event versions, sequence numbers when
available, actor metadata and optional target metadata. Process identity includes
agent UUID, boot-session UUID, PID and audit-token pidversion. An exec can change
pidversion without changing PID. Parent/responsible audit tokens and process start
time are accessed only when the message version supplies them.

署名情報はイベント時点のcodesigning flags・CDHash・signing ID・team IDを保持します。
CDHashはファイル全体のハッシュではなく、署名フラグも独立した安全性・公証の判定ではありません。
パスはinode/device/mode、OS側の切詰め有無とともに保存します。
名前変更の「ディレクトリ＋新しい名前」を、観測済みの完全パスやファイルと偽って扱いません。
NOTIFYのresultはそのまま保持し、拒否されたcreateを成功と断定しません。

The shared JSON envelope uses source `EndpointSecurity` and data type
`MacosEndpointSecurity`. Windows-specific ProcessCreate/ProcessGuid meanings are
not reused. `process_context` describes the post-exec target / fork child for
lifecycle events and the actor otherwise; the native record always retains both
roles. Windows PID-cache enrichment never overwrites this identity.

`query`, `explain`, `stats`, JSONL replay and indexing can read the new event type.
Source filtering uses `endpointsecurity`. `analyze --lang ja|en`
reports macOS coverage and explicitly states that macOS detection rules are not
implemented. Existing Windows hunt/correlation rules and process-tree views are
**not** macOS detection coverage; reading events is not a threat verdict.

## Permissions / 必要な承認

Native collection needs root, appropriate code signing with Apple's restricted
`com.apple.developer.endpoint-security.client` entitlement, and user/MDM Full
Disk Access authorization. The included plist is a declaration template, not a
grant. Shipping also needs signing/provisioning, notarization and the app/System
Extension installation/approval workflow; those are not implemented here.
[Apple entitlement documentation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)

root権限だけでは不十分です。Apple承認済みの署名・entitlementとフルディスクアクセスが
必要です。SIP・TCC・Gatekeeperを無効化する手順は採用しません。Appleの承認申請や
証明書の選択、フルディスクアクセスの付与は利用者・管理者が行ってください。

On failure, native error codes distinguish root (`es_not_privileged`), entitlement
(`es_not_entitled`), FDA (`es_not_permitted`), client limit and subscription errors.
The first failure does not verify whether the other permissions are present.
`health --lang ja|en` explains these codes; no successful collection is fabricated.

## Build and controlled validation / ビルドと検証

Requires Rust and Xcode Command Line Tools / a macOS SDK. Development validation
has used Apple Silicon macOS 26.6.2; older releases and Intel have not been tested.

```sh
cargo build --locked
cargo test --locked
cargo run --locked -- --config configs/macos-telemetry.toml --validate-config
```

Ordinary tests do not create an ES client. Native bridge tests fabricate SDK
messages and cover all eight event types, version gates, identity, UTF-8/size
limits, queue loss and sequence counters. They are **synthetic**, not captured
attack evidence. The opt-in permission probe below creates/deletes a client
without subscribing to events; it can trigger macOS permission UI:

```sh
cargo test --locked macos_es_permission_probe -- --ignored --nocapture --test-threads=1
```

On this development Mac, the probe returned `5 / es_not_privileged`. The tested
debug binary also had no Endpoint Security entitlement. **Live collection has
not yet been validated.** Root was missing, so later native permission gates
and FDA have not been verified. No SIP/TCC setting, signing identity, service
registration or remote endpoint was changed.

Validation record (2026-09-13): 579 ordinary tests passed; four opt-in tests were
excluded (three macOS native checks and the existing I/O benchmark). Permission
probe and non-root startup/cleanup checks were also explicitly run and passed.
The live smoke test was **not** run. Windows x64 GNU test executables cross-built
with warnings denied; this is not native Windows execution. Configuration and
entitlement-plist syntax validation passed.

このMacで通常テストと実APIの権限不足応答を確認しましたが、実イベント収集は未検証です。
承認・署名を準備した隔離テスト環境では、署名したテスト実行ファイルの
`macos_es_live_smoke` を明示的に実行できます。自分で生成した一時ファイルをtouchし、
exec/create/exitとネイティブ識別情報を確認します。通常テストでは実行されません。

For an authorized foreground run, first copy the executable and configuration
into an administrator-owned, non-user-writable directory, with owner-only
telemetry/state directories, and use the required signed build. Do not execute a
user-writable development checkout as a persistent root service. Start that
binary with `--config <protected-config-path>` and stop with Ctrl-C. The example
profile writes locally; no collector enables remote transmission by default.

```sh
threatfalcon health --input macos-events.jsonl --lang ja
threatfalcon health --input macos-events.jsonl --lang en
threatfalcon analyze --input macos-events.jsonl --lang ja
```

## Quality and privacy boundaries / 品質・プライバシー境界

- Callback data is copied before returning to ES, with 16 KiB per string and
  32 KiB aggregate text limits. Truncation and invalid UTF-8 are explicit;
  bounded invalid bytes are preserved as hex. File content, argv, environment,
  passwords, browser content and memory contents are not read. Paths, numeric
  user IDs and signing metadata remain sensitive.
- Callbacks do not wait for sink IO or scan files. Queue insertion is nonblocking;
  queue drops and decode failures appear in health. The shared queue is bounded
  by 10,000 events, not by bytes; memory/throughput benchmarks remain pending.
- Global sequence gaps take priority over per-event gaps to avoid double counting.
  The first observation is a baseline: reported loss is a lower bound. Resets,
  repeats and unavailable sequences are separately visible. Intentional OS/self
  muting is not reconstructed as missing events.
- Client creation/deletion occur on one owned OS thread. Startup waits for
  subscription. Shutdown disconnects before releasing the callback context;
  deletion failure is an error and retains potentially referenced memory.
- Apple's default mute set is preserved and sensor IO is muted by audit token.
  No authentication decisions or automatic blocks are performed.
- Collection is live-only: **no outage/restart replay**, no retained kernel
  evidence store, no macOS restart-persistent correlation, no exactly-once claim.
  Running health confirms subscription startup, not event completeness or safety.
- Files rotate by size; no total local-retention quota/secure deletion policy has
  been implemented. Protect logs and manage retention before broad deployment.

## Next acceptance gates / 次の受入条件

1. Approved signing/FDA and benign native tests on an isolated Mac; validate each
   root/entitlement/FDA error without weakening policy.
2. Stress/loss tests, stop/restart/resource ownership, older macOS/Intel matrix,
   hardened runtime/System Extension packaging and tamper protection.
3. mmap/task-access/remote-thread, persistence/auth/login/XProtect events with
   availability gates; evidence-backed macOS rules with benign baselines.
4. Separate Network Extension work for network-flow/DNS visibility. ES
   process/file events do **not** provide arbitrary socket telemetry.
5. Signed updates, on-premises/hosted enrollment and retention policy.

高度な脅威への網羅性・検知精度は未達です。この実装の目的は検証可能なネイティブ収集基盤を
用意することであり、全脅威の検出や製品品質を保証することではありません。
