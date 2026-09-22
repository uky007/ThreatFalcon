# Hardening contracts / 運用強化の設計

Status: development implementation. This document distinguishes implemented
local safeguards from deployment decisions and unimplemented production systems.
It is not an EDR certification or a claim of resistance to a compromised OS.

## Trust boundaries / 信頼境界

The administrator controls the executable, configuration, state and data directory.
Other users must not be able to replace these files or any ancestor directory.
Telemetry, imported JSONL/XML and network delivery responses are untrusted inputs.
Native event identity is evidence for correlation, **not cryptographic authenticity**.
An attacker with administrator/kernel access can interfere with the current sensor;
local checks, a checksum, an advisory lock or zero recorded loss cannot disprove that.

管理者が実行ファイル・設定・保存先を保護することを前提にします。現実装は管理者／
カーネル侵害に対する耐改ざん機構ではありません。保存ログの存在・入力種別の観測・
検知ゼロを、完全性や端末の安全性の証明には使いません。

## Implemented local safeguards / 今回実装した境界

### Strict configuration

Every configuration struct rejects unknown fields, including nested collector,
provider, output and rule settings. A missing field still uses the documented
default; a misspelled field does not silently use that default. Existing configs
containing ignored extension fields now fail validation and need explicit migration.
Free-form HTTP header **names** remain intentionally accepted in the header map.
Byte-size conversion is checked for overflow. A file budget on stdout/HTTP is
rejected instead of being silently ignored, including after CLI output overrides.
State/checkpoint paths must not collide with the event output, its writer lock or
numbered segments. This is path validation, not proof against hard-link aliases or
concurrent replacement by someone who can write the protected directory.

`--validate-config` does not start collectors or establish endpoint permissions,
Sysmon policy, storage free space, or protection of the filesystem ACLs.

### Rule input contracts

`src/detection_catalog.rs` owns built-in rule IDs, versions, bilingual titles,
required/supporting Sysmon IDs, network protocols and false-positive examples.
The detector uses the same IDs/titles and provenance gate. Matching semantics and
persisted rule state remain unchanged; changes to those require a state-version
and migration review, not just a title/version edit.

`analyze` adds per-agent `correlation_input_counts`, `correlation_tcp_connections`
and `rule_inputs`. Eligible input types require matching source/provider/EventID,
v2 native time, non-nil process identity, usable typed payload and required
parent/target identities. Unknown/legacy time, bad provenance and mere raw EventID
presence do not fill a prerequisite. Observations from different agents never
fill each other's prerequisites. Supporting Event 10 is not a required input.
UDP supplies sequence rules but not the TCP-periodicity rule.

- `insufficient_evidence`: one or more required input types was not observed with
  usable evidence. This does not prove policy is disabled; the operation may not
  have occurred, or the selected file may not contain it.
- `required_types_observed`: suitable types occurred somewhere in this input for
  that agent. **Not** a rule match, complete policy, live readiness, or validated
  detection rate. Counts are neither deduplicated nor limited to a rule time
  window. A single TCP event can satisfy the type prerequisite, not periodicity.
- `coverage_verified` stays `false`. The actual detector still applies its
  agent/process identity, ordering, predicates, windows and bounded state.

解析結果の「必要な入力種別を観測」は、検知の成立・網羅性の合格判定ではありません。
設定やサービスの稼働状況だけから「検知可能」と表示する設計にはしません。

### Non-destructive storage budget

```toml
[output]
type = "file"
path = "events.jsonl"
rotation_size_mb = 100
max_total_size_mb = 1024
```

Values use MiB (1,048,576 bytes). The budget counts logical file lengths of the
active file and its canonical positive-u32 numbered siblings (`events.jsonl.1`,
`.2`, ...). It does not include indexes, SQLite checkpoints/sidecars, HTTP spools,
other log names, copies renamed to `.backup`/`.01`, allocation overhead or other
applications. It is **not a volume free-space reservation or filesystem quota**.
Use a dedicated, access-controlled directory and monitor volume free space too.
Numbered sibling names are matched case-insensitively, conservatively counting
case-only variants even on case-sensitive volumes. Do not assign overlapping
or case-only-different log-family names to different writers.

The built-in default remains `0` (unbounded) for compatibility. All eight shipped
local collector profiles now opt into 1 GiB; changing these example files does
not deploy them to an endpoint. An operator selects an appropriate budget before
deployment and must not use the sample value as a measured production requirement.

1. Acquire an exclusive, nonblocking OS lock on `<path>.writer.lock` before opening
   or repairing the log. Keep this zero-byte sidecar permanently; **do not remove
   it while any writer may be active**. Lock release follows handle close, not a
   PID file or elapsed-time guess. A second cooperating writer fails, including
   during rotation. See the [Rust File locking contract](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock).
2. Inventory the log family on startup. Enumeration/metadata errors and
   non-regular members fail startup. Existing evidence above budget is preserved.
   Charge a partial-tail separator against the budget before appending it.
3. Reserve each full JSONL record before writing or rotating. Exactly fitting is
   allowed. The first record that would exceed the limit returns
   `file_storage_budget_exceeded`; no automatic deletion, compression or eviction.
4. A budget, write, rotation or synchronization failure makes that sink instance
   terminal. Subsequent sends/checkpoint acknowledgements fail. Existing sensor
   cleanup stops workers and exits nonzero. An unacknowledged batch may replay
   duplicates after recovery; never skip its source progress to regain space.
5. Rotate by exclusively creating a hard link to the synchronized old file,
   unlinking the active name, and creating a fresh active file with `create_new`.
   A destination collision never overwrites previous evidence. Filesystems without
   the needed lock/hard-link support fail explicitly; no unsafe rename fallback.
   Intermediate failures may leave two names for the same evidence; restart
   counts both conservatively. This is not a power-loss/directory-durability proof.

The accounted total is the startup inventory plus reservations for this run.
Deletions outside the writer do not reclaim budget until restart. Concurrent
external writes, log rotation, unlinking the lock, hard-link aliases, older sensor
versions that do not honor locks and hostile directory changes are **unsupported**.
Path checks do not eliminate races in an attacker-writable directory. Local
advisory locking is not a tamper-resistance boundary or distributed-filesystem lock.

New files/locks use mode 0600 on Unix; existing permissions are not silently changed.
Windows inherits the administrator-managed directory ACL; no Windows ACL or disk
encryption policy is installed by this change. Both must be provisioned separately.

Health includes `sink.file_storage.accounted_bytes`, `limit_bytes` (0=unbounded)
and `exhausted`. A health record reports the accounting **before writing itself**.
Reservations for partial/failed writes can make accounting conservative until restart. A full or
broken output cannot guarantee a final health record: retain stderr/service logs
and monitor process exit plus stale/missing heartbeats from outside the sensor.

上限時はログを消すのではなく停止します。停止後に管理者が証拠保全・退避・上限変更を
判断して再起動してください。停止中の未収集分を回復できるかは元ログの保持と収集方式
に依存します。ライブ限定の収集元には停止期間の再取得保証はありません。

## Production designs still requiring implementation / 今後の設計・実装境界

| Area | Required contract | Current boundary / decision needed |
| --- | --- | --- |
| Installation / privilege | Separate installation/update authority from routine collection; explicit protected executable/config/data ACLs; least privilege per source | Current collectors retain their documented privilege requirements. No installer ACL automation or tamper protection. Choose service identity/deployment targets first. |
| Signed releases / updates | Release manifest binds version, platform and artifact digest; pinned trusted signing roots, key rotation/revocation, monotonic rollback protection; stage then verify before activation; audited rollback authorization | Not implemented. A digest alone is not a signature. Select signing ownership, trust roots, recovery and update delivery before installing an updater. No automatic download/execute fallback. |
| Signed configuration / rules | Canonical signed envelope, schema/version/agent scope/expiry, last accepted version persisted, last-known-good config, explicit authorized rollback; staged validation before policy activation | Local strict TOML and built-in rules only. No remote rule interpreter, automatic policy replacement or trust-on-first-use enrollment. |
| Control server / delivery | Enrollment/revocation and device-bound identity; authenticated encrypted delivery, tenant isolation, replay-resistant acknowledgements bound to batch digest; retries remain idempotent | Existing optional HTTP sender is not this management plane. mTLS/enrollment, server-side durable acknowledgements and end-to-end authenticated evidence remain unimplemented. |
| Evidence handling | Operator-defined privacy fields, retention/hold policy, protected/encrypted storage, auditable archival/deletion, separate disk budgets for indexes/checkpoints/spool | This change never deletes evidence and does not encrypt it. Retention period, archival destination, key custody and legal-hold policy require operator decisions. |
| Response | Human-approved action scope, authorization/audit record, bounded rollback, deny arbitrary remote command execution | Detection/investigation only; no automatic isolation, process termination or remediation agent. |

These contracts are design constraints, not deployed components. In particular,
root trust, data export destinations and destructive retention actions are not
chosen implicitly by implementing the local sensor.

## Validation and VM boundary / 検証範囲

The new safeguards are checked with local synthetic telemetry and temporary files:
strict keys, overflow/path collisions, budget boundary/restart/partial tail,
writer ownership across rotation, non-overwriting collisions, failure without source
acknowledgement, invalid/legacy evidence, agent separation, UDP/TCP distinction and
Japanese/English CLI output. No exploit, malware or endpoint-policy change is needed.

2026-09-22 local verification (Rust 1.93.0, base commit `23eeefb` plus these changes):

- `RUSTFLAGS=-Dwarnings cargo test --locked --offline -- --quiet`: 681 passed,
  0 failed, 4 opt-in native tests ignored (509 unit, 9 analysis, 145 CLI,
  6 ETW-context CLI, 12 health CLI). The local HTTP mocks and macOS boot-identity
  query require execution outside the development sandbox; their initial sandbox
  permission failures were not product failures and were rerun successfully.
- `RUSTFLAGS=-Dwarnings cargo check --locked --offline --target x86_64-pc-windows-gnu --tests`:
  passed. This includes the Windows-specific case-insensitive inventory test in
  type checking, **not execution**.
- `git diff --check`: passed. Clippy with warnings denied still fails at existing
  unchanged lint sites; no all-clean Clippy claim is made.

Windows cross-compilation checks types, not native file-lock/hard-link/ACL behavior.
The earlier [Windows validation](WINDOWS_VALIDATION_2026-09-22.md) predates these new
changes. Windows runtime regression, long-run load, unexpected power loss, source
retention loss and real-world detection accuracy remain deferred.

This development does not need the VM to run. No VM is started, deleted or modified;
its disk/evidence can be retained for later native regression. A VM or comparable
Windows machine will still be needed before claiming Windows operational readiness.
