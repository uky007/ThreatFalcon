#!/usr/bin/env bash
# Run on the Linux test host as its ordinary user; sudo prompts locally once.
set -euo pipefail
umask 077
suite=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary=${1:-"$suite/../source/target/debug/threatfalcon"}
[[ $# -le 1 && -x $binary ]] || { echo 'Usage: bash run.sh /path/to/threatfalcon' >&2; exit 1; }
[[ $(id -u) != 0 ]] || { echo 'Run as the ordinary validation user.' >&2; exit 1; }
cc -std=c11 -O2 -Wall -Wextra -Werror "$suite/workload.c" -o "$suite/workload"
bash -n "$suite/admin.sh"
python3 -I -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$suite/validate.py"
python3 -I -B "$suite/test_validate.py"
mkdir -p "$suite/logs"
log=$(mktemp "$suite/logs/e2e.XXXXXX.log")
echo "Log: $log"
echo 'Runs 69 controlled operations plus one between-runs exec, using two temporary Audit rules.'
echo 'Only the protected sensor receives CAP_AUDIT_READ; workloads run as your ordinary user.'
echo 'No package, service, sudo-policy, or persistent rule changes; private evidence is retained.'
sudo bash "$suite/admin.sh" "$binary" 2>&1 | tee "$log"
