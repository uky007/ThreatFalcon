# ThreatFalcon management server

`threatfalcon-server` receives telemetry from ThreatFalcon sensors (the
sensor's `[output] type = "http"` sink) and stores it per agent. This
directory contains everything needed to run it on AWS (Tokyo region,
`ap-northeast-1`) with continuous deployment from GitHub: every push to
`main` is tested, built and deployed to the server.

```
 Endpoint (Windows)                       AWS ap-northeast-1 - EC2, Ubuntu 24.04
 +-------------------+   HTTPS :443       +------------------------------------------+
 | threatfalcon.exe  | -----------------> | Caddy (Let's Encrypt)                    |
 | [output] http     |  Bearer tfs_...    |   POST /api/v1/events -> 127.0.0.1:8080  |
 | spool on failure  |                    | threatfalcon-server (sandboxed, no root) |
 +-------------------+                    |   /var/lib/threatfalcon-server/agents/*  |
                                          |   admin API 127.0.0.1:8081 (not exposed) |
 Workstation (optional)   HTTPS :8443     |   read API  127.0.0.1:8082               |
 curl + threatfalcon CLI ---------------> |   (8443 open to ReaderCidr only)         |
   Bearer tfr_...                         +------------------------------------------+
 git push main -> GitHub Actions: test, build -> S3 bundle -> SSM (fixed document)
               -> threatfalcon-server-deploy: verify, install, restart, health check
```

What the server does:

- Authenticates every agent with its own bearer token (only the token's
  SHA-256 is stored on the server).
- Stores events as `agents/<name>/events.jsonl` with the same rotation scheme
  as the sensor's file sink, so the investigation CLI (`threatfalcon query`,
  `hunt`, `score`, `tree`, `tail`, `alert`, ...) works unchanged on the server.
  The CLI binary is deployed alongside the server.
- Never loses what it acknowledged: a batch is acknowledged only after it is
  fsynced (including the directory entries of new files). The sensor treats
  any 2xx as delivery of the whole batch, so elements that fail validation
  are not dropped but kept in `agents/<name>/rejected.jsonl`.
- Never stores an event twice: events are deduplicated by their `id` against
  the last 200,000 ids of the agent. The window is rebuilt from the stored
  files when the server starts, so batches re-sent after a lost
  acknowledgement, a restart (deploys) or a crash in the middle of a write are
  not duplicated.
- Tracks liveness from successful ingests (an agent whose requests keep
  failing is `failing`, not `ok`) and the latest sensor health report
  (collector errors, dropped events, spooling) in a status API and Prometheus
  metrics.

## How deployment works

On every push to `main` (and on manual runs), `.github/workflows/deploy-server.yml`:

1. runs `cargo test --workspace`, builds `threatfalcon-server` and
   `threatfalcon` on Ubuntu 24.04, and packages them with
   `deploy/server/package-bundle.sh`;
2. in the `production` environment, assumes the deploy role through GitHub
   OIDC (no stored AWS keys), uploads the bundle to the deploy bucket and runs
   the stack's SSM document on the instance;
3. on the instance, `threatfalcon-server-deploy` downloads the bundle, checks
   its SHA-256 and contents, installs it as a new release, restarts the
   service and waits until the admin health endpoint reports the new commit.
   If that fails, the previous release is restored and the workflow fails.

Caddy holds incoming requests for up to 10 s while the service restarts, and
agents keep retrying any batch that still fails (newer batches wait in memory,
then in `spool_dir`), so deployments do not lose telemetry.

What CI is allowed to do, by design:

| CI can                                              | CI cannot                                        |
|-----------------------------------------------------|--------------------------------------------------|
| assume the deploy role, only from the `production` environment of this repository (OIDC `sub` condition; the environment only allows `main`) | assume it from forks, pull requests or other branches |
| upload objects under `releases/` in the deploy bucket | read or delete anything else in AWS              |
| run the one SSM document, on the one instance       | run arbitrary commands (`AWS-RunShellScript`)    |
| pass a bundle key and a SHA-256 (regex-validated)    | change the systemd unit, Caddy or server config  |
| install two binaries that run as the sandboxed `threatfalcon` user, without access to the instance metadata service | run its code as root                             |

Host-level files (systemd unit, Caddyfile, deploy script) change only when
you re-run `bootstrap.sh` on the server (see [Operations](#operations)).

The repository is public, so workflow logs are public too: the instance ID,
bucket, document name and role ARN are stored as environment secrets (masked
in logs) and the deploy output contains no agent data.

## Installation

You need:

- an AWS account and the AWS CLI with permissions for CloudFormation, IAM,
  EC2, S3 and SSM (and Route 53 if you let the stack create the DNS record);
- a domain name you control (agents connect to `https://<domain>`);
- the GitHub CLI (`gh`), logged in with admin rights on the repository;
- for shell access to the server: the
  [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)
  (there is no SSH; port 22 is closed).

### 1. Create the AWS resources

```bash
export AWS_REGION=ap-northeast-1

# Current Ubuntu 24.04 LTS AMI. Pass it explicitly: later stack updates keep
# it, so the instance is never replaced by accident.
AMI=$(aws ssm get-parameter \
  --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
  --query Parameter.Value --output text)

aws cloudformation deploy \
  --stack-name threatfalcon-server \
  --template-file deploy/aws/threatfalcon-server.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides DomainName=tf.example.com ImageId="$AMI"

aws cloudformation describe-stacks --stack-name threatfalcon-server \
  --query 'Stacks[0].Outputs' --output table
```

Optional parameters:

| Parameter | Default | Notes |
|-----------|---------|-------|
| `AcmeEmail` | (none) | Let's Encrypt account contact |
| `InstanceType` | `t3.small` | must be x86_64 |
| `VolumeSize` | `30` | GiB; telemetry lives on this volume |
| `SnapshotRetention` | `7` | daily snapshots of the volume to keep |
| `IngressCidr` | `0.0.0.0/0` | restrict 443 to your agents' egress IPs if they are fixed |
| `ReaderCidr` | (none) | the one address (e.g. `203.0.113.10/32`) allowed to reach the [read API](#7-read-api-from-your-workstation-optional) on 8443; empty keeps 8443 closed |
| `HostedZoneId` | (none) | Route 53 zone of `DomainName`; creates the A record |
| `VpcId`, `SubnetId` | default VPC | both or neither; the subnet must be public |
| `GitHubRepository` | `uky007/ThreatFalcon` | repository allowed to deploy |
| `GitHubOidcProviderArn` | (create one) | set this if the account already has the `token.actions.githubusercontent.com` provider, e.g. `arn:aws:iam::<account>:oidc-provider/token.actions.githubusercontent.com` |

The stack creates: the EC2 instance with an Elastic IP (IMDSv2 only,
encrypted gp3 volume), a security group that opens 443 (and 8443 to
`ReaderCidr` when it is set), a private and
encrypted S3 bucket for release bundles (expired after 30 days), the
instance role (SSM agent + read bundles), the GitHub OIDC provider and deploy
role, the deploy SSM document, and a Data Lifecycle Manager policy that
snapshots the volume daily (see [Backups and restore](#backups-and-restore)).

On first boot the instance clones this repository (`BootstrapRef`, default
`main`) and runs `deploy/server/bootstrap.sh`, which installs Caddy, creates
the `threatfalcon` user, the systemd unit, the deploy script and
`/etc/threatfalcon-server/server.toml`. Its log is
`/var/log/threatfalcon-bootstrap.log`.

### 2. Point DNS at the server

Create an `A` record for the domain with the `PublicIp` output (skip this if
you passed `HostedZoneId`). Caddy obtains the certificate by itself as soon as
the name resolves (TLS-ALPN-01 on port 443; port 80 stays closed).

### 3. Connect GitHub

```bash
deploy/aws/configure-github.sh threatfalcon-server
```

This creates the `production` environment (deployments only from `main`) and
stores `AWS_DEPLOY_ROLE_ARN`, `DEPLOY_BUCKET`, `DEPLOY_INSTANCE_ID` and
`DEPLOY_SSM_DOCUMENT` as environment secrets, plus `PUBLIC_HEALTH_URL` as a
variable for the post-deploy smoke test. It finally sets the repository
variable `SERVER_DEPLOY_ENABLED=true`; until then the workflow only tests and
builds (so pushes before the AWS setup do not fail), and setting it to
anything else pauses deployments. Optionally add required reviewers to
the environment in the repository settings if you want to approve each
deployment.

### 4. First deployment

Wait about five minutes after the stack is created (bootstrap and SSM agent
registration), then either merge to `main` or run:

```bash
gh workflow run deploy-server.yml
gh run watch
```

If it ran too early, the SSM step fails (the deploy script is not installed
yet, or the instance is not registered); just run it again.

### 5. Add agents

```bash
aws ssm start-session --target <InstanceId>          # shell on the server

sudo threatfalcon-server token add lab-ws01
sudo systemctl restart threatfalcon-server
```

`token add` prints the token once, together with the matching agent
configuration. Use one token per agent; the name (`[a-z0-9._-]`) is also the
agent's storage directory.

### 6. Configure the agent (Windows)

In `C:\ProgramData\ThreatFalcon\threatfalcon.toml`:

```toml
[output]
type = "http"
url = "https://tf.example.com/api/v1/events"
bearer_token = "tfs_..."
gzip = true
# Keep batches on disk while the server is unreachable (also covers deploys).
spool_dir = "spool"
```

```powershell
.\threatfalcon.exe --validate-config
.\threatfalcon.exe --install-service
sc.exe start ThreatFalcon
```

The file contains the token: restrict it to SYSTEM and Administrators
(`icacls C:\ProgramData\ThreatFalcon\threatfalcon.toml /inheritance:r /grant:r SYSTEM:F Administrators:F`).
Within a minute (one health interval) the agent shows up as `ok` in the status API.

### 7. Read API from your workstation (optional)

To investigate from your own machine instead of a Session Manager shell, the
server can serve agent status and stored events on port 8443. Access needs
both: the security group opens 8443 only to `ReaderCidr`, and every request
needs a reader token. Reader tokens are separate from agent tokens (neither
works in place of the other) and are created on the workstation, so only
their hash ever reaches the server.

1. On the workstation, create the token (kept as a curl header file) and
   print its hash:

   ```bash
   umask 077 && mkdir -p ~/.config/threatfalcon
   t="tfr_$(openssl rand -hex 32)"
   printf 'Authorization: Bearer %s\n' "$t" > ~/.config/threatfalcon/reader.header
   printf '%s' "$t" | sha256sum | cut -d' ' -f1; unset t
   ```

2. On the server, register the hash (this also enables `reader_listen`):

   ```bash
   sudo threatfalcon-server reader add laptop --token-sha256 <hash>
   sudo systemctl restart threatfalcon-server
   ```

3. Open 8443 to the workstation's address, by updating the stack (in
   CloudShell, other parameters keep their values):

   ```bash
   aws cloudformation deploy --stack-name threatfalcon-server \
     --template-file deploy/aws/threatfalcon-server.yaml \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides ReaderCidr=203.0.113.10/32
   ```

   When the address changes, run it again with the new one; an empty
   `ReaderCidr=` closes 8443 again. (Editing the security group by hand
   also works, but the next stack update reverts it.)

4. Servers installed before the read API existed also need the Caddy site
   for 8443: re-apply the host config (see [Operations](#operations)).

Then, from the workstation:

```bash
H=~/.config/threatfalcon/reader.header
U=https://tf.example.com:8443/api/v1
curl -sS -H @$H "$U/agents?format=text"
curl -sS --compressed -H @$H \
  "$U/agents/lab-ws01/events?from=2026-11-15T05:00:00Z&category=File" > events.jsonl
threatfalcon stats --input events.jsonl
```

See [Read API](#read-api-port-8443) for the parameters.

## Operations

All commands run on the server (`aws ssm start-session --target <InstanceId>`).

| Task | Command |
|------|---------|
| Agent status | `curl -s 'http://127.0.0.1:8081/api/v1/agents?format=text'` (JSON without `?format=text`) |
| Status from your PC | `aws ssm start-session --target <InstanceId> --document-name AWS-StartPortForwardingSession --parameters portNumber=8081,localPortNumber=8081`, then use `http://127.0.0.1:8081` locally |
| Running version | `curl -s http://127.0.0.1:8081/healthz` |
| Prometheus metrics | `curl -s http://127.0.0.1:8081/metrics` |
| Server logs | `journalctl -u threatfalcon-server -f` |
| TLS / proxy | `journalctl -u caddy`, access log `/var/log/caddy/threatfalcon-access.log` (tokens are redacted) |
| Investigate | `sudo -u threatfalcon threatfalcon hunt --rotated --input /var/lib/threatfalcon-server/agents/lab-ws01/events.jsonl` (also `query`, `stats`, `score`, `tree`, `ioc`, `explain`, `bundle`). `--rotated` includes the rotated files `events.jsonl.N` (older history); without it only the active file is read and a note says how many older files were left out |
| Follow live | `sudo -u threatfalcon threatfalcon tail --input /var/lib/threatfalcon-server/agents/lab-ws01/events.jsonl` |
| Revoke an agent | `sudo threatfalcon-server token remove lab-ws01 && sudo systemctl restart threatfalcon-server` (its data is kept) |
| Revoke a reader | `sudo threatfalcon-server reader remove laptop && sudo systemctl restart threatfalcon-server`; `reader list` shows the readers |
| Read API log | `/var/log/caddy/threatfalcon-reader-access.log`; exports are also logged by the server (`journalctl -u threatfalcon-server`, "events exported") |
| Rotate a token | `token remove` then `token add` with the same name |
| Releases on disk | `ls -lt /opt/threatfalcon-server/releases` (`current` is a symlink) |
| Manual rollback | `sudo ln -sfn /opt/threatfalcon-server/releases/<dir> /opt/threatfalcon-server/current && sudo systemctl restart threatfalcon-server`, or re-run an older successful run of the deploy workflow |
| Re-apply host config | `sudo git -C /opt/threatfalcon-server/src pull --ff-only && sudo /opt/threatfalcon-server/src/deploy/server/bootstrap.sh` (settings are remembered in `/etc/threatfalcon-server/deploy.env`) |

Run the CLI as the `threatfalcon` user (not root): the data is owned by it,
and the CLI is deployed by CI.

Agent states (`state` in the status API):

| State | Meaning |
|-------|---------|
| `ok` | data stored within `stale_after_secs` (300 s) and the latest request succeeded |
| `failing` | the agent is in contact, but its latest request failed (e.g. 507 while the disk is full) or nothing was stored for `stale_after_secs` |
| `stale` | no contact for `stale_after_secs` |
| `never_seen` | nothing received since the agent was added |

`last_seen` is the last stored batch, `last_contact` the last authenticated
request. Warnings are derived from the latest health event (collectors in
`Error`, dropped events, batches spooled on the agent, or a sensor that was
shut down: its last health event is the one it sends when it stops),
quarantined events and recent failed requests. Counters cover the current server process; after
a restart, `last_seen` comes from the events file until the agent reports
again.

Storage: each agent's file rotates at `rotation_size_mb` (100 MB), and at most
`max_rotated_files` (50) rotated files are kept per agent (the same applies
to `rejected.jsonl`). Free disk space is checked after retention had its say:
a rotation that is due happens first (and deletes the oldest file), and when
space is below `min_free_disk_mb` (1 GB) an agent that already holds its full
set of rotated files gives up its oldest one early. Only if that frees
nothing (the disk is filled by data still within retention) are batches
refused with HTTP 507; agents then keep them in their spool. Grow the volume
or lower `max_rotated_files` (applied on the next write).

The CLI warns when it skips lines it cannot read (events of a newer sensor
version, or damaged lines), so such events are never left out silently.

Quarantine: `agents/<name>/rejected.jsonl` holds one record per element that
failed validation: `{"received_at", "agent", "index", "reason", "element"}`,
where `element` is what the agent sent. They are typically caused by a sensor
newer than the server; after upgrading the server they can be re-sent with
the agent's token:

```bash
jq -c '.element' rejected.jsonl | jq -cs . |
  curl -fsS -H "Authorization: Bearer $AGENT_TOKEN" -H 'Content-Type: application/json' \
    --data-binary @- http://127.0.0.1:8080/api/v1/events
```

OS updates: Ubuntu's unattended-upgrades applies security updates; Caddy comes
from its official apt repository.

## Backups and restore

The instance volume is the only copy of the stored telemetry, so the stack
protects it:

- A Data Lifecycle Manager policy snapshots the volume every day at 18:00 UTC
  (03:00 JST) and keeps `SnapshotRetention` (7) snapshots. Snapshots are
  crash-consistent, which the server tolerates: on start it truncates an
  interrupted last line and rebuilds duplicate suppression from the files.
- The instance and its security group have `DeletionPolicy` and
  `UpdateReplacePolicy` `Retain`, and the volume is not deleted on
  termination. A stack update that replaces the instance (a new `ImageId`
  or subnet) keeps the old one, and deleting the stack leaves the instance,
  its volume and the snapshots in place.

Restore (manual; for example onto a replacement instance):

```bash
# Latest snapshot of the server volume
aws ec2 describe-snapshots --owner-ids self \
  --filters Name=tag:threatfalcon:backup,Values=threatfalcon-server \
  --query 'sort_by(Snapshots,&StartTime)[-1].[SnapshotId,StartTime]' --output text

# Create a volume from it in the instance's availability zone and attach it
aws ec2 create-volume --snapshot-id <snap-id> --availability-zone <az> --volume-type gp3
aws ec2 attach-volume --volume-id <vol-id> --instance-id <InstanceId> --device /dev/sdf

# On the server: copy the data back
sudo mkdir -p /mnt/restore && sudo mount -o ro /dev/nvme1n1p1 /mnt/restore
sudo systemctl stop threatfalcon-server
sudo rsync -a /mnt/restore/var/lib/threatfalcon-server/ /var/lib/threatfalcon-server/
sudo systemctl start threatfalcon-server
sudo umount /mnt/restore   # then detach and delete the temporary volume
```

Removing everything after `aws cloudformation delete-stack`: empty the deploy
bucket first (or the delete fails), then terminate the retained instance and
delete its volume, the retained security group and the snapshots you no longer
need.

## Server reference

### Configuration (`/etc/threatfalcon-server/server.toml`)

| Key | Default | Meaning |
|-----|---------|---------|
| `listen` | `127.0.0.1:8080` | ingest listener (plain HTTP behind Caddy) |
| `admin_listen` | `127.0.0.1:8081` | status API and metrics; must be loopback (unauthenticated) |
| `reader_listen` | off | read API (reader tokens); must be loopback, published by Caddy on 8443; set by the first `reader add` |
| `data_dir` | `/var/lib/threatfalcon-server` | storage root |
| `public_url` | - | only used in `token add` output |
| `limits.max_body_mb` | 16 | request body as received |
| `limits.max_decompressed_mb` | 32 | after gzip decoding |
| `limits.max_events_per_batch` | 10000 | |
| `limits.max_concurrent_requests` | 8 | bounds memory use |
| `limits.request_timeout_secs` | 30 | for receiving the body |
| `limits.min_free_disk_mb` | 1024 | below this, HTTP 507 (0 disables) |
| `storage.rotation_size_mb` | 100 | 0 disables rotation |
| `storage.max_rotated_files` | 50 | per agent, 0 keeps all |
| `storage.fsync` | true | fsync each batch before acknowledging |
| `status.stale_after_secs` | 300 | |
| `[[agents]]` `name`, `token_sha256` | - | managed by `threatfalcon-server token add/remove/list` |
| `[[readers]]` `name`, `token_sha256` | - | managed by `threatfalcon-server reader add/remove/list` |

Unknown keys are rejected. Check a config with
`threatfalcon-server check-config --config <path>`.

### Ingest API

`POST /api/v1/events` with `Authorization: Bearer <token>`, a JSON array of
ThreatFalcon events (`Content-Type: application/json`), optionally
`Content-Encoding: gzip`. This is what the sensor's HTTP sink sends.

Each element must have the `ThreatEvent` envelope (`id` and `agent_id` UUIDs,
RFC 3339 `timestamp`, `hostname`, `sensor_version`, `source`, `category`,
`severity`, and a `data` object with a `type`). Valid elements are stored
byte-for-byte (line breaks between JSON tokens become spaces); payload fields
are not interpreted, so newer sensors with new event types work without a
server update. Elements that fail the check are quarantined, not dropped.

| Status | Meaning | Sensor behaviour |
|--------|---------|------------------|
| 200 | durable; body `{"accepted": n, "duplicates": d, "quarantined": q, "errors": [...]}` (new events stored, already stored events skipped, invalid elements quarantined, first validation errors) | done |
| 400 | body is not a JSON array, or bad gzip | drops the batch and counts it (not retried) |
| 401 | missing or unknown token | retries with backoff |
| 413 | body, decoded payload or event count over the limits | drops the batch and counts it (not retried) |
| 415 | unsupported `Content-Type` / `Content-Encoding` | retries with backoff |
| 503 | too many concurrent requests (`Retry-After`) | retries with backoff |
| 507 | low disk space (`Retry-After`) | retries with backoff |
| 500 | storage error | retries with backoff |

While the sensor retries a batch, newer batches wait in its memory
(`queue_max_mb`) and then in its spool (`spool_dir`); collection is never
paused for delivery.

`GET /healthz` returns `ok` (used for the external smoke test; no version
information is exposed publicly).

### Admin API (loopback only)

- `GET /healthz`: status, version, revision, start time, configured agents
- `GET /api/v1/agents[?format=text]`: per-agent status
- `GET /metrics`: Prometheus text format: per agent `..._agent_up`,
  `..._agent_failing`, `..._agent_last_seen_timestamp_seconds`,
  `..._agent_last_contact_timestamp_seconds`, `..._agent_events_total`,
  `..._agent_duplicate_events_total`, `..._agent_quarantined_events_total`,
  `..._agent_failed_requests_total`; globally `..._auth_failures_total`,
  `..._server_errors_total`, `..._disk_available_bytes`, ... (all prefixed
  `threatfalcon_server_`)

### Read API (port 8443)

Behind Caddy on `https://<domain>:8443`, reachable only from `ReaderCidr`.
Every request except `/healthz` needs `Authorization: Bearer <reader token>`
(401 otherwise, before anything else in the request is looked at). Read only.

- `GET /healthz`: `ok` (to check that the port is reachable)
- `GET /api/v1/agents[?format=text]`: per-agent status, as on the admin API
- `GET /api/v1/agents/<agent>/events`: the agent's stored events as JSON
  lines (`application/x-ndjson`, gzip with `--compressed`), oldest first,
  rotated files included. Query parameters, all optional:

  | Parameter | Meaning |
  |-----------|---------|
  | `from`, `to` | inclusive bounds on the event `timestamp` (RFC 3339, e.g. `2026-11-15T05:00:00Z`) |
  | `category` | e.g. `File`, `Registry`, `Process` (case-insensitive) |
  | `min_severity` | `Info`, `Low`, `Medium`, `High` or `Critical`: that severity and above |
  | `detections` | `true`: only events with detection rule metadata (`rule`) |
  | `contains` | substring of the stored JSON line (as stored: `\` in paths is `\\`), up to 256 bytes |
  | `limit` | events to return, default 100000, at most 1000000; if exactly `limit` lines come back there may be more: continue with `from` set to the last timestamp |

  Unknown parameters and agents are refused (400, 404). At most two exports
  run at a time (503 with `Retry-After` beyond that).

  Reading the files is what an export costs, so files that cannot hold a
  match are not read. Rotated files never change: the first export that
  reads one in full records its summary (event time range, counts by
  category and severity, detections) in `.export-index.json` in the agent
  directory, and later exports skip it when the filters rule it out. Files
  without a summary, and the active file, can only be ruled out by a time
  range, by their write times (allowing 24 h of agent clock skew). The
  first filtered export after a lot of new data is therefore slower than
  the ones after it.

## Running without AWS

`bootstrap.sh` works on any Ubuntu 24.04 x86_64 host with a public DNS name
(without `--deploy-bucket`). Build and install a release manually:

```bash
cargo build --release --locked -p threatfalcon-server -p threatfalcon
sudo install -d /opt/threatfalcon-server/releases/manual/bin
sudo install -m 0755 target/release/threatfalcon-server target/release/threatfalcon \
  /opt/threatfalcon-server/releases/manual/bin/
sudo ln -sfn /opt/threatfalcon-server/releases/manual /opt/threatfalcon-server/current
sudo systemctl restart threatfalcon-server
```

Build on Ubuntu 24.04 (or older glibc) so the binaries run on the server.
Outside the stack there are no automatic snapshots: back up
`/var/lib/threatfalcon-server` yourself.

## Limitations

- Single instance, no high availability: the data lives on the instance's
  volume with daily snapshots, so up to a day of telemetry can be lost if the
  volume itself is lost. Restoring is manual (see above).
- No web UI and no built-in alerting yet: use the status API / metrics for
  liveness and the CLI on the server for investigation.
- A batch the server rejects as a whole with 400 or 413 is dropped by the
  sensor (and counted in its health event, shown as `sink dropped N events`).
  Invalid elements inside a batch do not cause this (they are quarantined);
  with the official sensor it only happens if the server limits are set below
  what the agents send: lower the agents' `batch_size` or raise the limits.
- Duplicate suppression covers the last 200,000 events per agent (about 12 MB
  of memory per agent). That covers the sensor's re-sends (a retried batch
  follows its original within a few batches), but a re-send of more than
  200,000 events at once (for example replaying a whole file) is stored again
  in full. Quarantined elements are not deduplicated.
