# Linux native validation — 2026-09-21

## Result / 結果

Commit `d3f4af9dd44448c07f180f49b1b770cd743ae6ad` was built and tested on a
physical x86_64 Linux laptop. **642 ordinary tests passed, with no failures.**
The separate unprivileged Audit permission probe passed by observing `EPERM`.
After administrator preparation, the permitted multicast probe and the live
`/bin/true` exec smoke test also passed. This is native Linux execution, not
Docker or CPU emulation.

Linux実機でのビルド・通常テスト・権限不足時の実起動に加え、**69件の既知操作の
実収集・JSONL保存・検索照合、正常停止・再起動時の識別子と、短い試験中のauditd共存を確認しました。**
E2Eの初回は試験スクリプトのインデックス作成漏れで停止しましたが、修正後に同じ保存データの
検索・解析を一般ユーザーで完了しました。修正版の特権付き全体試験を再実行したという意味ではありません。
包括的な収集範囲、負荷・欠落率の評価は未完了です。本番運用品質や脅威検知性能の証明ではありません。

## Environment / 環境

- Kali GNU/Linux Rolling, installed release 2025.3.
- Kernel `6.16.8+kali-amd64`, physical x86_64, 12 logical CPUs, about 14 GiB RAM.
- `CONFIG_AUDIT=y`, `CONFIG_AUDITSYSCALL=y`, `CONFIG_AUDIT_ARCH=y`.
- Rust/Cargo 1.93.0 (`x86_64-unknown-linux-gnu`), GCC 13.4.0.
- General user UID 1000 with no effective capabilities; noninteractive sudo
  requires a password. Audit daemon/tools were initially not installed.

The host could not resolve `static.rust-lang.org`. Official Linux Rust
components were downloaded on the development Mac, checked against the official
SHA-256 files, transferred over SSH, and installed into the private validation
directory. Dependencies were obtained with `cargo vendor --locked --offline`
from the development cache. Builds used the committed lockfile, vendored
sources, `--locked --offline`, and `RUSTFLAGS=-Dwarnings`.

The ordinary and denied-startup checks changed no audit policy or system
services. The administrator then ran the prepared one-off script, installing
auditd and using a temporary rule and capability for the live test, as recorded
below. DNS configuration and sudo policy were not changed. Rust is confined
to the validation directory; shell startup files were not modified.

## Completed checks / 実測結果

| Check | Result |
|---|---|
| Unit tests | 476 passed; 3 opt-in tests ignored |
| Analysis CLI | 7 passed |
| General CLI | 142 passed |
| ETW context offline CLI | 6 passed |
| Health CLI | 11 passed |
| Native development build | Passed, warnings denied |
| `configs/linux-telemetry.toml` validation | Passed |
| Explicit unprivileged Audit probe | Passed; socket `errno=1` / `EPERM` |
| Actual sensor startup without `CAP_AUDIT_READ` | Exit code 2 |
| Persisted startup/final health | 2 JSONL events; `LinuxAudit` remains `Error` with `audit_permission_denied`; zero collected telemetry |
| Reading actual failure output | `health` and `analyze` succeeded in Japanese and English |
| Explicit permitted Audit probe | Passed; multicast subscription opened and closed |
| Live exec smoke test | Passed in 0.10 s; own `/bin/true` child PID and EXECVE record observed |
| Event assembly and shutdown | EOE completion, no group issues, non-nil boot/session IDs, collector `Stopped` |
| Basic auditd coexistence | Owner PID 11829 unchanged before/after; service remained active |
| Kernel counters during this short test | `lost=0` and `backlog=0` at both snapshots |
| Cleanup | Wrapper successfully removed the temporary rule/capability and verified pre/post-test rules match |

The three ordinarily ignored tests are the two native Linux Audit tests and
the synthetic local output/checkpoint workload. Both Linux tests were then run
explicitly; the permission probe was run once without and once with the required
capability. The synthetic workload was subsequently run as described below.
Windows-specific offline tests
passing on Linux do not validate Windows collection.

The EOE marker and zero kernel lost-counter snapshots do not prove lossless
delivery to the multicast subscriber. This single benign exec is not a load
test, and the smoke test does not persist the received live event to JSONL.

Native artifact SHA-256:

```text
33095d1a8c9a4bcb8820906954ec9448443396ea454958a3b5dabdc4829f1a0f  threatfalcon
a0b2ba195683dce971bb3fec8c1444f1f7ca83d2845d4121e577960e0c5988d7  native unit-test executable
```

## Administrator-run live test / 管理者操作を伴う実収集試験

The dedicated host directory contains `run-tests.sh`, the offline toolchain and
dependencies, logs, and `run-admin-smoke.sh` / `admin-live-smoke.sh`.
The user ran the syntax-checked admin wrapper on the host. Its saved log and
the script were subsequently retrieved over SSH and hash-compared with the
development copies. The full saved log confirms the successful test and cleanup.
Copies of the scripts and completed logs are kept under the development
checkout's ignored `target/linux-validation/2026-09-21/` directory.

管理者用の試験スクリプトは端末でsudo認証を受け、次の操作を完了しました。

1. Verify package/test hashes and copy privileged inputs into a root-owned
   directory. Refuse immutable policy and refuse starting a previously inactive
   auditd over existing rules that distro defaults could erase.
2. If absent, install the three prepared packages (`auditd`, `libauparse0t64`,
   `libauplugin1`, version `1:4.1.2-1`) and start auditd. These were obtained
   from the Debian official snapshot and exactly match the host's cached Kali
   APT SHA-256 records. **The packages and auditd service remain installed.**
3. Add one temporary x86_64 `execve` rule limited to UID 1000 executing the
   resolved `/bin/true` executable. Give only `CAP_AUDIT_READ` to a protected
   copy of the test executable and run it as the general user.
4. Run the explicit permission probe and live smoke test. The latter must
   observe its own benign child with EXECVE, boot identity, complete assembly
   and a clean collector stop. Verify the auditd owner PID is unchanged.
5. On exit, remove the exact temporary rule and test capability, compare rules
   against the pre-test snapshot, and retain root-owned diagnostic artifacts.

The distro package installation applies its normal default audit setup; it is
not a persistent ThreatFalcon deployment. The wrapper records output in
`logs/admin-live-smoke.log`. No administrative password is stored or sent to
the assistant. Follow-up SSH checks found auditd active with the same PID,
both original user-owned binaries without file capabilities, and the retained
root-owned test directory protected with mode 0700. The rule comparison and
capability removal are established by the successful privileged cleanup log;
the retained directory is not readable by the general SSH user.

Saved admin log SHA-256:

```text
98228cbf1f1e21e73b843e259559ba056fab967ae7b3eef4dc12e46de2619bd4  admin-live-smoke.log
```

## Additional unprivileged checks / 追加の一般ユーザー検証

The existing `sensor::tests::checkpoint_workload_measurement` was run explicitly
on the physical host and passed. It saved 4,096 synthetic Windows-schema events
in 128 batches, preserved 128 process timelines in the checkpoint, and reported
no detector capacity drops. The measured workload took 3,553 ms; the whole test
took 3.99 s. Output was 7,216,036 bytes and the checkpoint database 2,060,288 bytes.
This exercises local output/checkpoint code and is **not** a Linux Audit capture
benchmark, a Windows endpoint benchmark, or sustained-load validation.

The new unprivileged [HTTPS check](../scripts/linux-validation/https.py) also
passed against the same native binary with every collector disabled:

- A loopback HTTPS server accepted health when the child process explicitly
  trusted its test CA using `SSL_CERT_FILE` / `SSL_CERT_DIR`.
- An unrelated CA and a trusted certificate with the wrong IP address were
  both rejected; no HTTP payload reached either rejected connection.
- Two health records queued during the untrusted-CA run were delivered once
  each when trust was corrected, alongside two new health records. The delivered
  spool was empty afterward; address-mismatch records remained queued.

Only `127.0.0.1` was used. DNS, proxies, system trust stores, audit policy and
services were not changed. Test keys remain in a private host directory; only
the aggregate report/log is retained in the development evidence directory.
This validates process-configured native-CA loading, chain/name rejection and
one spool-recovery scenario; it does not cover all distro CA-store integration
or promise exactly-once delivery across failures.

## Bounded capture/readback suite / 実収集・保存・検索の一貫検証

The user ran the [reusable live suite](../scripts/linux-validation/README.md) on
the host, retaining evidence in `/var/tmp/threatfalcon-e2e.CBQnYy/data`.
Its C helper compiled with warnings denied. Root-owned configuration and two
temporary UID/executable-scoped rules kept the sensor's own output outside the
selected file workload. No persistent policy or service change was requested.

The original run completed both live collection rounds and native-evidence,
identity, health and privacy assertions, but stopped at the indexed-query check:
`Indexed query silently fell back to a scan`. This was a **validation-harness
setup error**, not an observed sensor/index implementation failure. `query`
only reuses an existing index; the harness had omitted `index --input`.
Both original query outputs contained all 79 Linux events, but neither used an
index. The old failure log and protected script were retained unchanged.

The corrected harness explicitly builds the index and still rejects silent
scan fallback. The new `--verify-existing` mode then completed saved-evidence
and CLI checks as the ordinary user, using the same protected native binary
after its capability had been removed. It did not repeat capture, use sudo,
or edit the original JSONL / workload ground truth. New results are under
`data/readback-24tmojg4/`.

| Check | Result |
|---|---|
| Expected native operations | 69 / 69 matched, each to a distinct event |
| Operation mix | 45 execs; four each of create, rename, missing-file open, loopback connect, same-UID `setresuid`, unlink |
| Bounded burst | 32 of the execs used four workers; not a stress test |
| Saved output | 79 Linux events + 8 health events, 288,869 bytes |
| Native evidence | Expected syscall outcomes and path/socket bytes preserved; complete EOE groups, no record issues |
| Identity/restart | One stable agent, one boot identity, two distinct non-nil capture sessions, two clean stops |
| Health | No reported output/queue/pre-queue drops, decode failures, malformed input, socket overruns, truncation, incomplete groups, capacity flushes or late records |
| Scan/indexed readback | Both returned the exact saved 79 Linux events; indexed query explicitly reported `(indexed)` |
| PID query and `explain` | Both modes preserved the expected event; no invented process-lifetime key |
| Index status | 87 events, all 288,869 bytes indexed, `current` |
| Health/analysis | Japanese and English succeeded; JSON analysis had zero malformed lines and explicitly retained the unimplemented-Linux-detection limitation |
| Original data integrity | Capture and expected-operation SHA-256 unchanged by offline retry |

The original live assertions also checked that the known between-runs exec was
not replayed and that generated argv/environment sentinels were absent. These
checks preceded the failure in the original script. That version did not persist
the private sentinels or a capture manifest, so the offline retry does **not**
claim to have independently repeated those exact checks. It did recheck the
saved field whitelist: no raw syscall arguments, EXECVE argument values or
PROCTITLE value. Future runs save a capture-check manifest before CLI checks;
the legacy retry correctly reports `capture_manifest_available: false`.

The wrapper printed identical audit status before/after: owner PID 11829,
`lost=0`, `backlog=0`. Its overall `FAIL` reflected the validation exception;
no rule-comparison error was logged. Follow-up SSH checks found auditd active
with the same PID and no capability on the protected binary. The privileged
cleanup path removes the exact rules and compares snapshots; those root-only
snapshots were not independently readable by the general SSH user. These short
snapshots and complete expected operations do not prove lossless delivery.

Evidence SHA-256:

```text
908a700492f4cbfcd0825feea18803b1510bd1df855d13846dd4da7e4b5ebf25  events.jsonl
61243dd94b6b1e43000a8c5715b59ef30ab696566ed8c8da2442131f6980546f  expected.json
934ff0cc23db03a1344d1a175c85215ae6ba4307abd379adef3dda7764dbc337  workload
c8bd24d1d4117bf4807a934ee96061a4240a2d0de7e51b25e7ac3db6324a4126  original protected validate.py
e9d36687d3cd5a3500f5ded4296d10b4d75d6ce5f707dd30f1086a1e3b461e18  corrected validate.py used for readback
7ec7a2bcb0c580438e88f272b2126d43b992af7b5e5a8fafd08651339708820e  readback summary.json
e74ad56a6a81a5e17f280cbaa33d7b1e762a0f8b623683e74633c1a55a154a55  original e2e.Dkl006.log
```

Aggregate readback reports and the original failure log are retained under the
ignored development evidence directory. Raw host telemetry is not committed.
The sensor source/binary did not change. Three harness regression tests passed
on both the development Mac and the physical Linux host: explicit index setup,
rejecting scan fallback and stopping on index build failure. Shell/Python syntax
checks and `git diff --check` passed. Remaining gates include overload, long runs, broader policy/
operation and failure/restart coverage, and the distro/kernel matrix.

## Scope / 範囲

No malware, exploit, attack simulation, load flood, or external target was used.
No Linux detection rule was added or evaluated. No sensor source-code fix was
needed for the completed checks; reproducible validation scripts were added.
These results establish native build/regression, denied/permitted startup,
bounded benign capture-to-JSONL/readback and clean restart identity behavior
with basic auditd coexistence, not production protection or detection efficacy.
