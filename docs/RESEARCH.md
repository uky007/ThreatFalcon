# ThreatFalcon telemetry research / テレメトリ収集リサーチ

Implementation update: [native macOS sensor](MACOS_SENSOR.md) now provides the first
process/file collector. Live validation and macOS detection rules remain pending.
macOSの初期収集基盤を実装しました。実イベント収集・検知品質の検証はこれからです。

## Scope / 対象

ThreatFalcon is a telemetry sensor first. Detection and response decisions must be explainable, auditable, and optional. The first production target is Windows; macOS and Linux are planned through the same normalized event contract.

ThreatFalconはまずテレメトリ収集センサとして開発する。検知・対応の判断は説明可能で監査でき、必要に応じて無効化できることを原則とする。最初の本番対象はWindowsとし、macOS/Linuxは同じ正規化イベント契約で拡張する。

## Platform collection strategy / OS別方針

| Platform | Primary source | Initial event families | Design constraints |
|---|---|---|---|
| Windows | ETW kernel and security providers; optional Sysmon | process, file, registry, image load, network, DNS, script/AMSI | provider permissions, ETW buffer loss, Windows service lifecycle |
| macOS | Endpoint Security; evaluate Network Extension separately for network flows | exec, fork/exit, file, signing, login where supported; network coverage requires separate validation | user approval, system extension/entitlement, OS version differences |
| Linux | auditd for portable baseline; eBPF for richer process/file/network context | exec, credential, file, socket, namespace/container | kernel version, capabilities, verifier and distro packaging |

ETW is appropriate for the Windows baseline because it supports real-time and file consumers, but its session statistics include lost events and buffers; those values must become health telemetry rather than hidden implementation details. macOS Endpoint Security explicitly exposes execution notifications and related file/process event types. Linux eBPF programs are verifier-checked, but deployment depends on kernel features and capabilities, so auditd remains the fallback.

Windowsの基盤にはETWが適している。ETWはリアルタイム／ファイルの両方で利用できる一方、イベントやバッファの欠落統計があるため、内部ログに隠さずヘルステレメトリとして出力する。macOSではEndpoint Securityが実行通知とプロセス・ファイル関連イベントを提供する。LinuxではeBPFが高密度の文脈を提供するが、カーネル機能と権限に依存するため、auditdをフォールバックにする。

macOS network-flow collection needs a separate design using Network Extension; do not assume Endpoint Security covers arbitrary socket connections. Entitlements, deployment, and metadata export constraints must be validated before implementation. See [Apple NEFilterDataProvider](https://developer.apple.com/documentation/networkextension/nefilterdataprovider).

macOSのネットワークフロー収集は、Network Extensionを用いる別設計が必要です。Endpoint Securityだけで任意のソケット接続を取得できる前提にはしません。実装前に権限、配布方法、メタデータ出力の制約を検証します。[Apple NEFilterDataProvider](https://developer.apple.com/documentation/networkextension/nefilterdataprovider)

## Data minimisation / データ最小化

- Collect only fields needed for detection, investigation, or health.
- Make command lines, user names, paths, and network addresses configurable per policy.
- Never transmit remotely by default; local file output remains the default.
- Include a collection status and drop counters so an operator can distinguish “no activity” from “sensor could not observe”.
- Define retention, rotation, access control, and deletion behavior before general release.

## References / 参考資料

- Microsoft Learn, [About Event Tracing](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- Apple Developer, [ES_EVENT_TYPE_NOTIFY_EXEC](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_exec)
- eBPF Docs, [eBPF on Linux](https://docs.ebpf.io/linux/)
