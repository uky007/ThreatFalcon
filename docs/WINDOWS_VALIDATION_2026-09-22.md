# Windows native validation — 2026-09-22

## Result / 結果

The Windows pull-subscription idle failure and same-size file-rotation failure
were reproduced, fixed and retested on a newly provisioned Windows 11 VM.
Live WFP validation then exposed two schema differences; those were corrected
and the final application/test package was rebuilt and retested.

**Windows: 653 ordinary tests passed, zero failures, 7 opt-in tests ignored.**
Five distinct native checks passed explicitly, including Sysmon unacknowledged
record replay. Both Sysmon checks passed in two consecutive invocations of the
final package. Two independent WFP E2E runs each matched all six owned native
records (three permitted and three blocked), with clean shutdown and zero
reported drops or decode failures.

Windows実機VMで、不具合修正後の通常653件とネイティブ5種類を確認した。
WFPは2回、計12件の既知の無害な操作を元のSecurityログと照合した。
これは短時間の限定検証であり、完全無欠落、脅威検知性能、本番運用品質の証明ではない。

## Environment and provenance / 環境と同一性

- Fresh Japanese Windows 11 Enterprise Evaluation, **10.0.26200.9457**,
  x64 QEMU/KVM guest on the user's Linux laptop; not the former training VM.
- 4 vCPUs, 6 GiB RAM, NTFS guest filesystem. Secure Boot, ready TPM, Defender
  realtime protection and UAC remained enabled. SSH used pinned host keys and
  public-key authentication through a Linux-loopback-only forwarded port.
- Sysmon 15.22, Microsoft-signature verified, with the existing narrow lab
  `cmd.exe` ProcessCreate configuration. No policy expansion for these tests.
- Rust 1.93.0, Windows GNU debug build, `--locked --offline`, `RUSTFLAGS=-Dwarnings`.
- Base commit: `8191dfa3169104a21e33d9d5efc506eb18713730` plus this fix
  (uncommitted when the validation package was built). The manifest records
  the dirty state and hashes of every build input
  under `src/`, `tests/`, Cargo files and `build.rs`; these were checked again
  after validation. Do not label the fixed binary as the unmodified base commit.

Final package SHA-256:

```text
df246947eb2785d9fcffed1046eb6af9080180b1d1165eb9172c7103c7e4150c  windows-tests.zip
dd4f3fd8ded856a005495ffe2127ee2f0bb60ac25de886c5573f2d5ec8314220  threatfalcon.exe
794582d67e86b69274aa8764a6f2f434a4dcb00d3db6f07a19dc6b12b72c0512  source-snapshot.zip
```

## Corrections / 修正内容

1. **Event Log pull waits:** an exhausted subscription was read again after a
   100ms unsignaled wait, reproducing Win32 error 4317. Sysmon and WFP now share
   a notification wait that checks shutdown at bounded intervals but resumes
   reads only after a signal. Actual read failures still surface as errors;
   4317 is not silently ignored. This follows the
   [Microsoft pull-subscription sequence](https://learn.microsoft.com/en-us/windows/win32/wes/subscribing-to-events).
2. **Windows rotation identity:** `tail` and `alert` now compare the volume and
   128-bit file ID, using
   [GetFileInformationByHandleEx / FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info).
   Equal-size, larger and empty replacements are tested, along with append,
   temporarily absent paths and hard links. Unix retains device/inode comparison.
   Filesystems unable to supply Windows IDs retain the previous size fallback;
   this does not certify every filesystem or copy-truncate behavior.
3. **WFP schema compatibility:** live 5156 v1 uses `ProcessId`; live 5157 is v3.
   Core field names/types were checked against the installed Microsoft provider
   metadata for 5156 v0–2 and 5157 v0–4. Both PID spellings are preserved, but
   simultaneous aliases leave PID absent with an ambiguity issue. Unknown
   versions, malformed/overflow PID values and publisher/actor separation remain
   conservative. Additional filter/profile/user values remain omitted.

Provider-template export SHA-256:
`572604fa7b9c48e5a7bf50b650d54ab1a45583c7167bf8dd7b99ba37e724df2d`.
Only 5156 v1 and 5157 v3 were observed live; the other supported versions were
checked against provider templates and synthetic parser tests, not generated live.

## Final verification / 最終確認

| Check | Result |
| --- | --- |
| Windows unit tests | 489 passed; 7 ignored |
| Windows CLI / analysis / health / ETW-context CLI | 140 / 7 / 11 / 6 passed |
| macOS ordinary regression tests | 659 passed; 4 ignored |
| Native ETW process and owned publisher metadata | Both passed |
| WFP subscription idle for 600ms, bounded stop | Passed |
| Sysmon push and unacknowledged checkpoint replay | Both passed twice |
| WFP permitted/blocked E2E | Two runs; 6/6 owned records matched in each |
| WFP final health | Stopped; queue/pre-queue drops and decode failures 0 |
| WFP JA/EN `health` and `analyze` | All commands succeeded |
| Linux validation-harness regression | 3 passed; no native Linux recapture |

The WFP workload used only the owned Linux loopback HTTP endpoint through guest
NAT. The runner temporarily enabled one audit subcategory and applied a rule
limited to the owned `curl.exe` clients, destination and port; it removed the
rule and restored policy afterward. The sensor itself never wrote policy.
Native record ID, version, source time, actor PID (not publisher PID), application,
addresses, ports, protocol and direction matched the stored JSONL. No PID-only
process-lifetime enrichment or threat verdict was inferred. Both runs retained
`audit_policy_verified=false`: the source cannot prove policy/coverage itself.

The first post-wait-fix E2E attempt is retained as a failure: it exposed the PID
spelling and event-version omissions and did not stop gracefully. Its console
helper inherited an ignore-Ctrl+C launch condition. A new helper establishes its
own console and clears that inherited condition before launching the sensor;
the same sensor binary then passed an idle Ctrl+C stop check. No foreground
signal-handling change was made to the product. The earlier no-collector helper
check exited too early and was not counted as a valid stop test. The readback
checker also needed to respect the existing JSON contract that omits empty
`issues`; it still rejects the retained defective run.

## Evidence and limits / 証跡と限界

Private artifacts remain in ignored `target/windows-validation/2026-09-22-fix/`:

- `pass-2/`: final manifest, complete build log, source snapshot and package.
- `portable-fix-20260922T011751Z/`: all ordinary Windows results.
- `native-base-fix-20260922T012007Z/` and
  `sysmon-fix-20260922T012016Z/`, `sysmon-fix-20260922T012026Z/`.
- `wfp-e2e-20260922T012059Z/`, `wfp-e2e-20260922T012212Z/`:
  native XML, output JSONL, workload PIDs, before/after audit evidence, runner
  hashes, JA/EN reports and independent `validation-summary.json` files.
- `wfp-e2e-20260922T010831Z/`: failed intermediate attempt, not overwritten.

Raw telemetry, credentials and machine-specific VM artifacts must not be committed.
Clippy with warnings denied still fails on pre-existing, unchanged code locations;
the complete diagnostic logs are retained. It is not reported as passing, and
unrelated lint cleanup was not mixed into this fix.

The two Windows opt-in tests still not executed are PowerShell Core live capture
and the synthetic checkpoint workload benchmark. Long-duration/load tests,
disk-full/unwritable output, source retention loss, forced power interruption,
broader IPv6 capture and permission transitions remain outside this validation.
Other versions/filesystems and production performance remain unverified.

## Cleanup / 後始末

Final checks confirmed zero temporary firewall rules and owned validation
processes, restored WFP audit policy, and enabled Defender realtime protection,
Secure Boot and ready TPM. The owned HTTP endpoint self-terminated. The Windows
VM shut down normally and its dedicated TPM process exited; disks, snapshots
and evidence remain intact. Linux ended at **75 GiB free / 67% used**, with
9,083 MiB available RAM. No host audit/firewall changes, file cleanup or disk
consolidation were performed. Continuous ThreatFalcon monitoring was not enabled.
