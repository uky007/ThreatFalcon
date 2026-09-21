# Native Linux capture validation

Run only on an authorized x86_64 Linux validation host with auditd already active,
mutable auditing, a C compiler, Python 3, and an ordinary user who can run sudo.
Build ThreatFalcon first, then run:

```sh
bash scripts/linux-validation/run.sh /absolute/path/to/threatfalcon
```

The wrapper compiles the benign helper as the ordinary user, checks script syntax
and the harness regression tests,
and asks for the sudo password in the local terminal. The administrator script
copies inputs to a root-owned directory, checks that hashes did not change during
copying, and grants `CAP_AUDIT_READ` only to the protected sensor. It installs two
temporary rules restricted to the invoking UID and exact executable paths:
`/bin/true` for exec, and the dedicated helper for its selected native syscalls.
No package, audit service, sudo policy, permanent rule, or global backlog setting
is changed. Existing rules are retained.

The ordinary-user workload performs 45 execs across two sensor runs (including
a bounded 32-exec burst with four workers), plus four sets of six benign operations:
create, rename, missing-file open, loopback connect, same-UID `setresuid`, and unlink.
One additional exec occurs while the sensor is stopped to check the documented
absence of outage replay. There is no connection to an external host or change
to the user's identity. A 120-second outer timeout bounds the suite.

Validation covers actual JSONL evidence matched to the known child PIDs and
syscall results, complete-group flags, boot/session identity, argument/environment
sentinel exclusion, periodic/final health, clean shutdown, stable agent identity
and distinct sessions after restart, full-scan/SQLite-indexed queries, PID queries,
`explain` preserving the target evidence, and Japanese/English health and analysis.
It does not treat a numeric PID timeline as a verified process-lifetime identity.
The suite explicitly runs `index --input` before indexed queries: `query` can
reuse an existing index but never creates one implicitly. Indexed queries must
report `(indexed)`; a silent full-scan fallback is still a test failure.

Raw host audit records may also be received if existing rules are present. Data
stays in a mode-0700 directory owned by the validation user; do not publish these
files as fixtures. The sensor configuration is root-owned and its output lies
outside the workload's file operations. The helper deletes only the file it
created and renamed in each fresh workload directory.

On success or failure the administrator wrapper removes its exact temporary
rules and sensor capability and compares the original/final rule lists and auditd
owner PID. Inputs and evidence remain under the printed `/var/tmp/threatfalcon-e2e.*`
directory, with its parent owned by root and accessible to the user's primary group.
Root-only policy snapshots are retained there for troubleshooting. Terminal output
is also saved in `scripts/linux-validation/logs/` (or the staged suite directory).

The summary counts only the explicitly generated expected operations. Loader and
other legitimate native events can make the saved event count larger. A successful
bounded run and zero reported loss counters do not establish lossless collection,
complete policy coverage, sustained-load performance, or Linux threat detection.
If a check fails, inspect its saved evidence before changing the sensor or test.

## Resume saved-data checks without sudo

If capture completed and `events.jsonl` / `expected.json` remain, the readback
checks can run with the existing executable after the wrapper removes its capability:

```sh
python3 -I scripts/linux-validation/validate.py --verify-existing \
  --binary /var/tmp/threatfalcon-e2e.EXAMPLE/threatfalcon \
  --data /var/tmp/threatfalcon-e2e.EXAMPLE/data
```

Replace `EXAMPLE` with the printed run directory. This does not start a sensor,
modify audit policy, or require sudo. It rechecks saved native evidence, creates
or updates the optional SQLite sidecar, and writes CLI reports and `summary.json`
in a new `data/readback-*` directory. Original capture/ground-truth SHA-256 values
must remain unchanged; original failure logs are retained.

The live runner saves `capture.json` after its capture assertions and before CLI
checks. Older runs may lack this manifest; their readback summary says so. An
offline retry does not reproduce live timing or the original private-sentinel
test and must not be reported as a fresh full live-suite run.

Harness-only regression tests need neither Linux nor sudo:

```sh
python3 -I -B scripts/linux-validation/test_validate.py
```

## HTTPS check without sudo

```sh
python3 scripts/linux-validation/https.py --binary /absolute/path/to/threatfalcon --output-parent /private/writable/directory
```

This separate check disables every collector and transmits only startup/final
health to temporary HTTPS servers bound to `127.0.0.1`. It creates one-day test
certificates in a mode-0700 directory and uses process-local `SSL_CERT_FILE` and
`SSL_CERT_DIR` overrides. It verifies acceptance of the chosen CA, rejection of
an unrelated CA and an address mismatch, and replay of two queued health records
after trust is corrected. The OS trust store is not edited. Keys stay in the
private test directory and must not be committed; the aggregate summary contains
no keys. This does not validate every distro trust-store layout or exactly-once
delivery across arbitrary failures.
