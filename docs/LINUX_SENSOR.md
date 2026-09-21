# Linux Audit sensor / Linux Auditセンサ

## Status / 現状

Experimental, opt-in collector on `feat/linux-audit-sensor`, based on
`feat/macos-endpoint-security`. Windows/macOS work is preserved. These branches
are not merged with the independently advanced `origin/main`.

Linux向けの初期収集基盤であり、完成したEDRではありません。実機で無害な単発execの
受信・組み立て・停止と基本的なauditd共存を確認済みです。Linux専用の脅威検知ルール、
eBPFによる補完、実機での包括的な収集品質・負荷・検知精度の検証は未完了です。保存・検索・解析
できることと、高度な脅威を検知できることは別です。

## Native source / 収集方式

The collector binds `NETLINK_AUDIT` to `AUDIT_NLGRP_READLOG`, the kernel's
best-effort, read-only multicast group. It never becomes auditd's unicast owner,
sends Audit control requests, enables auditing, adds/deletes rules, modifies
auditd or reads/rotates `audit.log`. Existing auditd can continue operating.
The kernel requires `CAP_AUDIT_READ`; multicast delivery is associated with the
initial network namespace. [Kernel implementation](https://raw.githubusercontent.com/torvalds/linux/master/kernel/audit.c),
[Linux Audit UAPI](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/audit.h)

必要条件はAudit対応カーネル、有効な監査設定、管理者が用意した適切な監査ルール、
ホスト側の名前空間、`CAP_AUDIT_READ`です。起動成功は購読成功だけを意味します。
コンテナ内・別ネットワーク/PID名前空間での運用は未対応です。監査設定照会のための
`CAP_AUDIT_CONTROL`は要求しません。`audit_configuration_verified`は常にfalseで、
カーネル全体のlostカウンタも未取得です。

Only kernel-port-ID-0 datagrams are accepted. The complete Netlink datagram is
length-validated before emitting records. One owned worker holds the socket;
shutdown closes it and flushes pending groups as explicitly partial records.

## Preserved records / 保存するレコード

| Audit type | Preserved evidence / 保持する情報 |
|---|---|
| SYSCALL (1300) | Native arch/syscall number, result, PID/PPID, credentials, session, executable, comm, key |
| EXECVE (1309) | argc only; argument values excluded / 引数値は除外 |
| PATH (1302) | item, path, inode/device/mode/owners, nametype |
| CWD (1307) | Event-time working directory / イベント時点の作業ディレクトリ |
| SOCKADDR (1306) | Original address bytes as hex; no inferred connection direction |
| LOGIN (1006) | Native login UID/session transition fields |
| CONFIG_CHANGE (1305) | Selected native audit configuration-change fields |
| EOE (1320) | End-of-event marker / イベント終端マーカー |
| PROCTITLE (1327) | Presence and omitted field name only; no proctitle value |

Supported types do not imply they are generated without audit rules. Unknown
record types are counted as filtered and discarded. PAM/authentication,
SELinux/AppArmor, BPF, namespaces, io_uring and other records are not covered by
this initial whitelist. SYSCALL numbers remain architecture-dependent native
numbers. PATH is not automatically classified as a successful write; SOCKADDR
is not automatically classified as a successful outbound connection.

Auditの時刻（元の精度を維持）・serial・起動UUID・収集セッションUUIDを保持し、
同一Audit stampの複数レコードを組み立てます。PIDだけでは結合しません。
Audit serialは配信シーケンス番号ではなく、番号の飛びを欠落数に換算しません。
これらは監査イベントの識別情報であり、プロセス生存期間の一意な識別子ではありません。
`ProcessGuid`を捏造せず、WindowsのPIDキャッシュや現在の`/proc`情報を結合しません。

The JSON envelope uses source/data type `LinuxAudit`; `process_context` is absent.
PID queries are numeric filters, not reliable process-lifetime timelines.
`query`, `explain`, `stats`, JSONL analysis and SQLite indexing understand this
data; source filtering uses `linuxaudit`. `analyze --lang ja|en` reports record
coverage and explicitly states that Linux detection rules are unimplemented.
Existing Windows hunt/tree/correlation rules are not Linux detection coverage.

## Privacy and limits / データ最小化と上限

EXECVE arguments (including chunked aN fields), SYSCALL raw a0–a3 values and
PROCTITLE values are never persisted by this collector. Unknown fields are
discarded; only their names/counts remain. No raw-payload error logging or fallback
bypasses this whitelist. Values still transiently pass through the socket receive
buffer; the collector does not configure what auditd independently stores.
File contents and environment variables are not collected.

機密情報が含まれ得るパス、comm、実行ファイル名、監査キー、UID、ソケットアドレスは保存
されます。「引数を除外したので匿名・機密なし」という意味ではありません。出力・転送・
保存期間・アクセス権は管理対象です。hex文字列は指定フィールドだけ復号し、不正UTF-8は
元バイトのhexと品質警告を残します。

Bounds: 128 KiB/datagram, 16 KiB/raw record, 128 fields/record, 4 KiB/decoded
text value, 64 records and 32 KiB serialized-record bytes/group, 256 pending
groups, 4 MiB pending serialized-record bytes, and 512 queued Linux events.
These are payload budgets, not total process RSS guarantees. Groups expire two
seconds after their first record, not after a stream becomes idle. A bounded
1,024-stamp recent-close cache rejects late fragments; duplicates older than this
cache can recur.

EOEの受信は、それ以前の全レコードを受信した証明ではありません。SYSCALL不足・重複、
PATH件数不一致・item重複を記録します。タイムアウト・容量超過・停止時には理由を付けて
部分イベントとして出力します。部分イベントを完全な脅威証拠とは扱えません。

`health --lang ja|en` reports malformed records/datagrams, socket-overrun
notifications, truncated datagrams, groups without EOE, capacity flushes, late
records and event queue drops. Overrun notifications are **not exact lost-event
counts** and must not be added to event-drop totals. Zero counters do not establish
lossless operation. The collector's observed-event counter counts assembled
groups; `records_received` counts raw Audit records.

## Build and controlled use / ビルドと管理下での使用

On Linux, install Rust and a C toolchain (bundled SQLite and ring compile native
code). Linux HTTPS uses rustls and the host's native CA store; provide normal
distro CA certificates and administrator-approved enterprise CAs. Windows/macOS
retain their previous TLS backend. Protect CA-related environment settings along
with service configuration. TLS verification is not disabled.
[reqwest features](https://docs.rs/reqwest/0.12.28/reqwest/#optional-features),
[native certificate loading](https://docs.rs/rustls-native-certs/latest/rustls_native_certs/)

```sh
cargo build --locked
cargo test --locked
cargo run --locked -- --config configs/linux-telemetry.toml --validate-config
```

Ordinary tests do not subscribe to live Audit or change rules. This opt-in probe
opens/closes the subscription without persisting host events. An expected
permission denial passes the probe but does **not** validate collection:

```sh
cargo test --locked linux_audit_permission_probe -- --ignored --nocapture --test-threads=1
```

On an authorized host with administrator-provided exec audit rules, the opt-in
live smoke test launches `/bin/true`, waits for that child's EXECVE evidence,
checks event assembly/boot identity and closes the collector. It does not install
rules or log unrelated host events. It fails if no matching event is received:

```sh
TF_LINUX_AUDIT_LIVE_TEST=1 cargo test --locked linux_audit_live_smoke -- --ignored --nocapture --test-threads=1
```

管理されたLinux検証端末でのみ起動してください。管理者が`auditctl -s`、`auditctl -l`、
カーネル設定、権限、名前空間、収集対象を確認します。監査ルールの変更・サービス登録・
権限付与は自動で行いません。全syscall収集は大きな負荷を生じ得るため、必要な記録を
管理者が選び、負荷試験を行ってください。

Before a privileged run, install executable/configuration in administrator-owned,
non-user-writable locations with owner-only state/output directories. Set the
host name in the profile, then start the protected binary with
`--config <protected-config-path>` and stop with Ctrl-C. Do not run a user-writable
checkout as a persistent root service. Keep telemetry, state, rotation and HTTP
spool paths outside audited file watches: automatic self-process audit exclusion
is not implemented and self-IO can amplify collection load.

After collection, these commands inspect the output without using an index.
`query` reuses and updates an existing index, but does not create one automatically;
run `threatfalcon index --input linux-events.jsonl` first when an index is desired:

```sh
threatfalcon health --input linux-events.jsonl --lang ja
threatfalcon analyze --input linux-events.jsonl --lang en
threatfalcon query --input linux-events.jsonl --source linuxaudit --no-index
```

停止・再起動・ソケット欠落の間のイベント復旧はありません。HTTP spoolは既に収集した
イベントの送信待ちであり、未収集のカーネルイベントの復旧ではありません。

## Validation and remaining gates / 検証と残る受入条件

Update (2026-09-21): [physical Linux validation record](LINUX_VALIDATION_2026-09-21.md).
Commit `d3f4af9` built natively on Kali x86_64 with Rust 1.93.0 and warnings denied:
642 ordinary tests passed. An explicit unprivileged probe observed `EPERM`, and
an actual denied sensor start returned exit code 2 with persisted bilingual-readable
error health. After administrator preparation, the permitted subscription probe
and `/bin/true` live exec smoke test passed, including EOE assembly, boot/session
identity presence and clean stop. The auditd owner PID remained unchanged,
kernel lost counters were zero at both snapshots, and temporary rule/capability
cleanup succeeded. This initial smoke test was followed by bounded live capture
of 69 known operations across two sensor runs: all matched the saved native
evidence, with 79 Linux events and eight health records saved. Full-scan and
indexed queries agreed; PID queries, `explain`, and bilingual health/analysis passed.
The initial E2E run stopped at a harness error (the index had not been created).
After correcting the harness to create it explicitly, offline readback completed
against the unchanged original capture and binary, without sudo or another live run.
Agent identity stayed stable, capture sessions differed, and both stops were clean.
These are bounded functional checks, not losslessness, sustained-load or
detection-quality validation.
An additional 4,096-event synthetic output/checkpoint workload passed. Loopback
HTTPS tests passed for process-local CA trust, rejection of an untrusted CA and
an incorrect certificate address, and replay of two queued health records.
See the validation record for exact scope and [reproduction scripts](../scripts/linux-validation/README.md).

Validation record (2026-09-13): 596 ordinary tests passed on the development Mac
(440 unit, 4 analysis CLI, 142 general CLI, 10 health CLI; 4 opt-in tests excluded).
Linux x64 musl and Windows x64 GNU application/test executables cross-built with
warnings denied. The Linux binary is a static-PIE ELF. Linux profile validation
and `git diff --check` passed. Linux native permission/live smoke tests were
compiled but **not run**. HTTPS/native CA integration on Linux remains untested.

再現用のクロスビルド（Rust Linux musl targetとmusl-crossが導入済みの場合）:

```sh
CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc RUSTFLAGS=-Dwarnings cargo test --locked --target x86_64-unknown-linux-musl --no-run
```

At the 2026-09-13 baseline, native validation was unavailable. Subsequent Docker
regression checks and the 2026-09-21 physical-host checks above are separate
results. The physical-host session additionally verified bounded benign
exec/file/same-UID credential/socket operations alongside auditd as described above.
No malware or attack code was executed.
Native gates remain:

- Broader controlled exec/file/credential/socket coverage, failure/restart
  scenarios beyond two clean stops and sustained auditd coexistence.
- Buffer pressure, kernel backlog loss, slow output, sustained multi-core load
  and administrator-selected policy coverage.
- Distro/kernel/architecture matrix and namespace boundaries; no container claims.
- Stable process-lifetime identity and eBPF supplementation before cross-event
  Linux behavioral correlation; false-positive and detection-quality evaluation.
- Installer, least-privilege service packaging, update integrity and retention.

現段階では本番保護や高度脅威検知を保証しません。Auditの複数レコード構造と監査ルールに
依存する収集モデルは[Linux Audit project](https://github.com/linux-audit/audit-userspace)と
[ausearch documentation](https://raw.githubusercontent.com/linux-audit/audit-userspace/master/docs/ausearch.8)
を参照してください。
