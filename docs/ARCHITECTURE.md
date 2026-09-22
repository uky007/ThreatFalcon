# ThreatFalcon architecture / アーキテクチャ

## Target shape / 目標構成

```text
OS collectors -> normalizer -> bounded queue -> local spool/file
                                      |          \
                                      |           -> HTTPS control server (optional)
                                      -> health and loss metrics
```

The current Rust process already contains the normalizer, bounded queue, health event, file/stdout/HTTP sinks, and investigation CLI. New OS collectors should implement the existing `Collector` trait and emit `ThreatEvent`; detection rules must not read OS-specific structures directly.

現在のRustプロセスには、正規化、有限キュー、ヘルスイベント、file/stdout/HTTP出力、調査CLIがある。新しいOSコレクタは既存の`Collector` traitを実装し、`ThreatEvent`を出力する。検知ルールがOS固有構造を直接参照してはならない。

## Control server boundary / コントロールサーバ境界

The server is optional and must not be required for local collection. Its first responsibilities are:

1. enroll and revoke agents;
2. distribute signed, versioned configuration and detection rules;
3. receive batches with idempotency keys and acknowledgements;
4. expose sensor health, delivery lag, and loss counters;
5. retain an audit trail for configuration changes.

サーバは任意であり、ローカル収集の必須依存にしない。最初の責務は、エージェント登録・失効、署名付き設定／ルール配布、冪等キー付きバッチ受信と確認応答、センサの稼働・遅延・欠落状況、設定変更監査ログとする。

On-premises and hosted deployments should use the same HTTPS API and storage-independent event envelope. The hosted service may add tenancy and billing metadata; the sensor must not depend on those fields.

オンプレミス版とクラウド版は同じHTTPS APIと保存非依存のイベント封筒を使う。クラウド側でテナントや課金情報を追加しても、センサはそれらに依存しない。

## Delivery milestones / 開発マイルストーン

See [hardening contracts](PRODUCTION_HARDENING.md) for strict configuration,
non-destructive storage budgets, rule input assessment, and the trust/privilege/
update/control-plane boundaries that remain unimplemented. The latter are design
requirements, not deployed services or claims of tamper resistance.

### M1 Windows sensor hardening / Windowsセンサ強化

- Implemented: ETW session loss statistics, provider results, runtime diagnostics, shutdown queue drain, and a Japanese/English health CLI. See [SENSOR_HEALTH.md](SENSOR_HEALTH.md).
- 実装済み: ETW欠落統計、プロバイダ結果、実行時診断、停止時のキュー排出、日本語・英語のヘルスCLI。詳細は[SENSOR_HEALTH.md](SENSOR_HEALTH.md)。
- Windows integration tests for service start/stop, stale sessions, rotation, and restart.
- Explicit retention and ACL configuration for local telemetry.
- Signed release artifacts and reproducible build metadata.

### M2 macOS and Linux collectors / macOS・Linuxコレクタ

- macOS Endpoint Security collector behind a platform capability check.
- Linux auditd baseline, then optional eBPF collector with kernel/capability detection.
- Fixture replay tests proving equivalent normalized events across platforms.

### M3 Control plane / コントロールプレーン

- Versioned API and agent enrollment.
- Mutual TLS or device-bound credentials, key rotation, and replay protection.
- Configuration rollback and rule canary rollout.

### M4 Detection knowledge / 検知知識

- Each rule stores rationale, required telemetry, false-positive examples, references, test fixtures, and change history.
- Japanese and English operator explanations are shipped with the rule metadata.
