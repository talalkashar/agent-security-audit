#!/usr/bin/env bash
# Scripted terminal session for the README demo (docs/assets/demo.svg).
#
# Record it headlessly from the repo root, with `asa` on PATH:
#   uvx termtosvg -c "bash scripts/record_demo.sh" -g 100x32 -D 2000 docs/assets/demo.svg < <(sleep 120)
#
# The `< <(sleep 120)` matters when there is no interactive terminal (CI,
# an agent): termtosvg stops recording as soon as its stdin hits EOF.
#
# It starts the practice lab (vulnerable mode) on a free local port, runs
# three commands with typing pauses, then stops the lab. Nothing leaves
# the machine except the lab traffic on 127.0.0.1.
set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"
command -v asa >/dev/null || { echo "asa is not on PATH (pip install . first)" >&2; exit 1; }

# Work in a scratch folder so the session shows short relative paths and
# report.html does not land in the repo.
work="$(mktemp -d)"
mkdir -p "$work/tests/fixtures"
cp -R "$repo/tests/fixtures/code_vuln" "$work/tests/fixtures/"
cd "$work" || exit 1
real="$(pwd -P)"

port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
asa lab --mode vulnerable --port "$port" >/dev/null 2>&1 &
lab=$!
cleanup() { kill "$lab" 2>/dev/null; wait "$lab" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT

# Wait for the lab to answer (max ~5 s).
for _ in $(seq 50); do
  python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$port/', timeout=1)" 2>/dev/null && break
  sleep 0.1
done
url="http://127.0.0.1:$port"

type_cmd() {
  printf '\033[1;32m$\033[0m '
  local text="$1" i
  for ((i = 0; i < ${#text}; i++)); do
    printf '%s' "${text:i:1}"
    sleep 0.03
  done
  sleep 0.4
  printf '\n'
}

# Run under a pty (script) so asa prints its terminal summary, and turn the
# scratch folder's absolute path back into the relative one that was typed.
run() {
  type_cmd "$*"
  script -q /dev/null "$@" | sed -e "s#$real/##g" -e "s#$real#.#g"
  sleep 2.5
}

clear
sleep 0.5
run asa "$url" --quiet
run asa scan "$url" --format html --out report.html --quiet
run asa code tests/fixtures/code_vuln --no-osv
type_cmd ""
sleep 1
