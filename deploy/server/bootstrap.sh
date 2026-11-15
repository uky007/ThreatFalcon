#!/usr/bin/env bash
# Host setup for the ThreatFalcon management server (idempotent).
#
# Target: Ubuntu 24.04 LTS on x86_64, run as root. The CloudFormation
# template runs it from user data; on any other host run it manually:
#
#   sudo deploy/server/bootstrap.sh --domain tf.example.com \
#       [--email ops@example.com] \
#       [--deploy-bucket <bucket> --region ap-northeast-1]
#
# Settings are saved to /etc/threatfalcon-server/deploy.env, so later runs
# (to apply changes to the files below) need no arguments.
#
# Manages: Caddy (TLS termination), the threatfalcon system user, the
# systemd unit, /usr/local/sbin/threatfalcon-server-deploy and the initial
# server.toml (never overwritten once it exists). It does not install the
# server binary; the first deployment from GitHub Actions does.
set -euo pipefail
shopt -u patsub_replacement 2>/dev/null || true

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR
readonly ETC=/etc/threatfalcon-server
readonly PREFIX=/opt/threatfalcon-server
readonly DEPLOY_ENV=$ETC/deploy.env
readonly SERVICE_USER=threatfalcon

log() { printf '[bootstrap] %s\n' "$*"; }
die() { printf '[bootstrap] ERROR: %s\n' "$*" >&2; exit 1; }
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-0}"; }
saved() { [[ -f $DEPLOY_ENV ]] && sed -n "s/^$1=//p" "$DEPLOY_ENV" | tail -n 1 || true; }

domain=$(saved DOMAIN)
email=$(saved ACME_EMAIL)
bucket=$(saved DEPLOY_BUCKET)
region=$(saved AWS_REGION)
while [[ $# -gt 0 ]]; do
    case $1 in
        --domain) domain=${2:-}; shift 2 ;;
        --email) email=${2:-}; shift 2 ;;
        --deploy-bucket) bucket=${2:-}; shift 2 ;;
        --region) region=${2:-}; shift 2 ;;
        -h | --help) usage 0 ;;
        *) printf 'unknown option: %s\n\n' "$1" >&2; usage 1 ;;
    esac
done

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
domain=${domain,,}
[[ $domain =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || die "--domain must be a fully qualified domain name"
[[ -z $email || $email =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "--email is not a valid address"
if [[ -n $bucket || -n $region ]]; then
    [[ $bucket =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] || die "--deploy-bucket is not a valid S3 bucket name"
    [[ $region =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]] || die "--region is not a valid AWS region"
fi
for f in Caddyfile.template server.toml.template threatfalcon-server.service threatfalcon-server-deploy; do
    [[ -f $SCRIPT_DIR/$f ]] || die "missing $SCRIPT_DIR/$f"
done

# shellcheck source=/dev/null
. /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 ]]; then
    log "WARNING: expected Ubuntu 24.04, found ${PRETTY_NAME:-unknown}; release binaries are built on Ubuntu 24.04"
fi
[[ $(uname -m) == x86_64 ]] || die "release binaries are built for x86_64 only"

export DEBIAN_FRONTEND=noninteractive

log "installing packages"
apt-get update -y -q
apt-get install -y -q --no-install-recommends ca-certificates curl gnupg jq tar util-linux

if [[ ! -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg ]]; then
    log "adding the Caddy apt repository"
    curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key |
        gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    chmod 0644 /usr/share/keyrings/caddy-stable-archive-keyring.gpg
fi
cat >/etc/apt/sources.list.d/caddy-stable.list <<'EOF'
deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main
EOF
chmod 0644 /etc/apt/sources.list.d/caddy-stable.list
apt-get update -y -q
apt-get install -y -q caddy

if [[ -n $bucket ]] && ! command -v aws >/dev/null && [[ ! -x /snap/bin/aws ]]; then
    log "installing the AWS CLI (snap)"
    snap install aws-cli --classic
fi

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "creating system user $SERVICE_USER"
    useradd --system --user-group --no-create-home \
        --home-dir /var/lib/threatfalcon-server --shell /usr/sbin/nologin "$SERVICE_USER"
fi

install -d -m 0750 -o root -g "$SERVICE_USER" "$ETC"
install -d -m 0755 -o root -g root "$PREFIX" "$PREFIX/releases"

{
    echo "# Written by bootstrap.sh. Read (not sourced) by bootstrap.sh and threatfalcon-server-deploy."
    echo "DOMAIN=$domain"
    echo "ACME_EMAIL=$email"
    echo "DEPLOY_BUCKET=$bucket"
    echo "AWS_REGION=$region"
    echo "HEALTH_URL=http://127.0.0.1:8081/healthz"
} >"$DEPLOY_ENV.tmp"
chmod 0600 "$DEPLOY_ENV.tmp"
mv -f "$DEPLOY_ENV.tmp" "$DEPLOY_ENV"

if [[ ! -f $ETC/server.toml ]]; then
    log "writing $ETC/server.toml"
    config=$(<"$SCRIPT_DIR/server.toml.template")
    printf '%s\n' "${config//__TFS_DOMAIN__/$domain}" >"$ETC/server.toml.tmp"
    chown root:"$SERVICE_USER" "$ETC/server.toml.tmp"
    chmod 0640 "$ETC/server.toml.tmp"
    mv -f "$ETC/server.toml.tmp" "$ETC/server.toml"
else
    log "keeping existing $ETC/server.toml"
fi

install -m 0755 -o root -g root "$SCRIPT_DIR/threatfalcon-server-deploy" /usr/local/sbin/threatfalcon-server-deploy
install -m 0644 -o root -g root "$SCRIPT_DIR/threatfalcon-server.service" /etc/systemd/system/threatfalcon-server.service
ln -sfn "$PREFIX/current/bin/threatfalcon-server" /usr/local/bin/threatfalcon-server
ln -sfn "$PREFIX/current/bin/threatfalcon" /usr/local/bin/threatfalcon
systemctl daemon-reload
systemctl enable threatfalcon-server.service >/dev/null
# Apply unit changes if a release is already running.
systemctl try-restart threatfalcon-server.service

log "configuring Caddy for $domain"
caddyfile=$(<"$SCRIPT_DIR/Caddyfile.template")
caddyfile=${caddyfile//__TFS_DOMAIN__/$domain}
if [[ -n $email ]]; then
    caddyfile=${caddyfile//__TFS_ACME_EMAIL__/email $email}
else
    caddyfile=${caddyfile//__TFS_ACME_EMAIL__/}
fi
printf '%s\n' "$caddyfile" >/etc/caddy/Caddyfile.new
chmod 0644 /etc/caddy/Caddyfile.new
# Validate as the caddy user: run as root, validation would create the access
# log file owned by root and the caddy service could no longer open it.
if ! out=$(runuser -u caddy -- caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile.new 2>&1); then
    printf '%s\n' "$out" >&2
    die "generated Caddyfile (/etc/caddy/Caddyfile.new) is invalid"
fi
if [[ -f /etc/caddy/Caddyfile && ! -f /etc/caddy/Caddyfile.dist ]]; then
    cp -p /etc/caddy/Caddyfile /etc/caddy/Caddyfile.dist
fi
mv -f /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile
systemctl enable caddy >/dev/null
systemctl reload-or-restart caddy

log "done"
cat <<EOF

Next steps
  1. Point DNS for $domain (A record) at this host's public IP. Caddy obtains
     the TLS certificate on its own once the name resolves (port 443 open).
  2. Deploy the server binary: push to main, or run the "Deploy management
     server" workflow in GitHub Actions.
  3. Add an agent:   sudo threatfalcon-server token add <name>
                     sudo systemctl restart threatfalcon-server
  4. Agent status:   curl -s 'http://127.0.0.1:8081/api/v1/agents?format=text'
EOF
