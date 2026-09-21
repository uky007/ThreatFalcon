#!/usr/bin/env bash
# Administrator entry point for a bounded, user-run live Audit validation suite.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 077
[[ $EUID == 0 && -n ${SUDO_USER:-} && $SUDO_USER != root ]] || {
    echo 'Use run.sh as the ordinary validation user.' >&2; exit 1;
}
[[ $# == 1 && $(uname -m) == x86_64 ]] || exit 1
suite=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary=$(readlink -f -- "$1")
[[ -f $binary && -x $binary && -x $suite/workload && -f $suite/validate.py ]] || exit 1
test_user=$SUDO_USER
test_uid=$(id -u "$test_user")
test_group=$(id -gn "$test_user")
[[ $test_uid != 0 ]] || exit 1
systemctl is-active --quiet auditd || { echo 'auditd must already be active.' >&2; exit 1; }

root_dir=$(mktemp -d /var/tmp/threatfalcon-e2e.XXXXXX)
echo "E2E artifacts: $root_dir/data"
echo "Validation user: $test_user (UID $test_uid)"
snapshot() {
    local source=$1 destination=$2 permissions=$3 expected actual
    expected=$(sha256sum -- "$source" | cut -d ' ' -f 1)
    install -o root -g "$test_group" -m "$permissions" -- "$source" "$destination"
    actual=$(sha256sum -- "$destination" | cut -d ' ' -f 1)
    [[ $actual == "$expected" ]] || { echo 'Input changed during protected copy.' >&2; exit 1; }
    printf '%s  %s\n' "$actual" "$destination"
}
snapshot "$binary" "$root_dir/threatfalcon" 750
snapshot "$suite/workload" "$root_dir/workload" 750
snapshot "$suite/validate.py" "$root_dir/validate.py" 640
install -d -o "$test_user" -g "$test_group" -m 700 "$root_dir/data"
printf '%s\n' \
 'hostname = "linux-e2e-validation"' \
 'state_path = "data/agent.state"' \
 'health_interval_secs = 1' \
 '[output]' 'type = "file"' 'path = "data/events.jsonl"' 'rotation_size_mb = 10' \
 '[collectors.linux_audit]' 'enabled = true' \
 '[collectors.macos]' 'enabled = false' \
 '[collectors.etw]' 'enabled = false' \
 '[collectors.sysmon]' 'enabled = false' \
 '[collectors.wfp_audit]' 'enabled = false' \
 '[collectors.evasion]' 'enabled = false' > "$root_dir/config.toml"
chown root:"$test_group" "$root_dir" "$root_dir/config.toml"
chmod 640 "$root_dir/config.toml"
cd "$root_dir"
auditctl -s > status-before.txt
auditctl -l > rules-before.txt
grep -q '^enabled 1$' status-before.txt || { echo 'Audit must be enabled and mutable.' >&2; exit 1; }
auditd_pid=$(awk '$1 == "pid" { print $2 }' status-before.txt)
[[ $auditd_pid =~ ^[1-9][0-9]*$ ]] || exit 1
key="tf_e2e_$$"
exec_rule=(-F arch=b64 -S execve -F "exe=$(readlink -f /bin/true)" -F "uid=$test_uid" -k "$key")
work_rule=(-F arch=b64 -S openat,renameat,unlinkat,connect,setresuid -F "exe=$root_dir/workload" -F "uid=$test_uid" -k "$key")
exec_added=0
work_added=0
cap_added=0
cleanup() {
    result=$?
    trap - EXIT INT TERM
    if (( work_added )); then
        auditctl -d always,exit "${work_rule[@]}" || result=1
    fi
    if (( exec_added )); then
        auditctl -d always,exit "${exec_rule[@]}" || result=1
    fi
    if (( cap_added )); then
        setcap -r "$root_dir/threatfalcon" || result=1
        [[ -z $(getcap "$root_dir/threatfalcon") ]] || result=1
    fi
    auditctl -l > rules-after.txt || result=1
    auditctl -s > status-after.txt || result=1
    cmp -s rules-before.txt rules-after.txt || { echo 'ERROR: Audit rules changed across this run.' >&2; result=1; }
    [[ $(awk '$1 == "pid" { print $2 }' status-after.txt) == "$auditd_pid" ]] || result=1
    systemctl is-active --quiet auditd || result=1
    chmod 750 "$root_dir" || result=1
    cat status-before.txt status-after.txt
    if (( result == 0 )); then
        echo 'PASS: capture/readback/restart suite; auditd PID unchanged; temporary rules and capability removed.'
    else
        echo "FAIL: inspect $root_dir/data and the retained root-only audit snapshots." >&2
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
auditctl -a always,exit "${exec_rule[@]}"
exec_added=1
auditctl -a always,exit "${work_rule[@]}"
work_added=1
setcap cap_audit_read=ep "$root_dir/threatfalcon"
cap_added=1
chmod 710 "$root_dir"
getcap "$root_dir/threatfalcon"
runuser -u "$test_user" -- timeout --signal=TERM --kill-after=5s 120s \
    python3 -I "$root_dir/validate.py" --binary "$root_dir/threatfalcon" \
    --workload "$root_dir/workload" --config "$root_dir/config.toml" \
    --data "$root_dir/data" --key "$key"
