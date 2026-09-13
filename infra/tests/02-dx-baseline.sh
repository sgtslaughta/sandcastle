#!/usr/bin/env bash
# Phase 2 verify: a developer gets a working workspace, and the workspace
# namespace refuses every pod shape that would escape Kata.
#
# Runs inside the lab VM (make verify-dx), after 03-platform.sh and a template
# push. Admission checks use server-side dry-run so they exercise the real
# policy without creating pods, and each denial is paired with an allowed
# positive control: a namespace that rejects everything would otherwise pass.
set -uo pipefail

WS_NS=sandcastle-workspaces
WS=dx-test
CODER=${CODER:-$HOME/.local/bin/coder}
fail=0
pass() { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }

cleanup() {
  "$CODER" delete "$WS" --yes >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Sandcastle phase 2 verify: developer experience baseline"

# --- admission -------------------------------------------------------------
pod() { # name runtimeClass automount extra-spec-json
  cat <<JSON
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"$1","namespace":"$WS_NS"},
 "spec":{$([[ -n "$2" ]] && echo "\"runtimeClassName\":\"$2\",")
  $([[ -n "$3" ]] && echo "\"automountServiceAccountToken\":$3,")
  ${4:+$4,}
  "containers":[{"name":"c","image":"busybox:1.36"}]}}
JSON
}
admits() { pod "$@" | kubectl apply --dry-run=server -f - >/dev/null 2>&1; }

admits ok-kata kata-clh-runtime-rs false \
  && pass "compliant kata pod admitted (positive control)" \
  || bad "compliant kata pod rejected — policy blocks everything, other checks meaningless"
admits no-class "" false \
  && bad "pod without runtimeClassName admitted (would run on runc)" \
  || pass "pod without runtimeClassName denied"
admits runc-class runc false \
  && bad "runtimeClassName runc admitted" || pass "runtimeClassName runc denied"
admits token kata-clh-runtime-rs "" \
  && bad "pod with default service account token admitted" || pass "service account token automount denied"
admits hostpath kata-clh-runtime-rs false '"volumes":[{"name":"h","hostPath":{"path":"/"}}]' \
  && bad "hostPath volume admitted (bypasses the VM boundary)" || pass "hostPath volume denied"
admits hostnet kata-clh-runtime-rs false '"hostNetwork":true' \
  && bad "hostNetwork admitted" || pass "hostNetwork denied"

# --- workspace lifecycle ---------------------------------------------------
echo "  ..    creating workspace $WS (Kata boot + image pulls, several minutes)"
if ! "$CODER" create "$WS" --template base --use-parameter-defaults --yes >/tmp/dx-create.log 2>&1; then
  bad "coder create failed; see /tmp/dx-create.log"
  tail -20 /tmp/dx-create.log
  exit 1
fi
for _ in $(seq 60); do "$CODER" ssh "$WS" -- true >/dev/null 2>&1 && break; sleep 5; done
"$CODER" ssh "$WS" -- true >/dev/null 2>&1 && pass "workspace agent reachable over coder ssh" || { bad "workspace agent never connected"; exit 1; }

classes=$(kubectl -n "$WS_NS" get pods -o jsonpath='{range .items[*]}{.spec.runtimeClassName}{"\n"}{end}' | sort -u)
[[ "$classes" == "kata-clh-runtime-rs" ]] && pass "workspace pod runs on kata-clh-runtime-rs" || bad "workspace pod runtime classes: '$classes'"

# coder ssh joins its arguments into one remote shell command, like ssh; pass a
# single string so compound commands keep their quoting.
wsh() { "$CODER" ssh "$WS" -- "$1" >/tmp/dx-cmd.log 2>&1; }

# --- installs through the mirror -------------------------------------------
wsh 'sudo apt-get update && sudo apt-get install -y tree' \
  && pass "apt install" || { bad "apt install"; tail -5 /tmp/dx-cmd.log; }
wsh 'python3 -m venv /tmp/v && /tmp/v/bin/pip install six' \
  && pass "pip install" || { bad "pip install"; tail -5 /tmp/dx-cmd.log; }
wsh 'mkdir -p /tmp/n && cd /tmp/n && npm init -y >/dev/null && npm install left-pad' \
  && pass "npm install" || { bad "npm install"; tail -5 /tmp/dx-cmd.log; }

# Success alone would not show the mirror was used; the workspace could have
# fallen back to a public index. Nexus's request log is the proof.
nexus_log=$(kubectl -n sandcastle-mirror exec nexus-0 -- cat /nexus-data/log/request.log 2>/dev/null)
for repo in apt-ubuntu pypi-proxy npm-proxy; do
  grep -q "/repository/$repo/" <<<"$nexus_log" && pass "Nexus served $repo" || bad "no $repo requests in Nexus request log"
done

# --- container builds ------------------------------------------------------
# The agent can connect before the sidecar's daemon is up (containers start in
# order), so wait for the daemon rather than racing it.
docker_up=0
for _ in $(seq 24); do wsh 'docker version' && { docker_up=1; break; }; sleep 5; done
(( docker_up )) && pass "Docker daemon reachable from dev container" \
  || { bad "Docker daemon never answered"; tail -5 /tmp/dx-cmd.log; }

wsh 'mkdir -p /tmp/d && printf "FROM busybox:1.36\nRUN echo built\n" >/tmp/d/Dockerfile && docker build -t dx-test /tmp/d' \
  && pass "docker build in DinD sidecar" \
  || { bad "docker build failed (is /var/lib/docker the loop-mounted ext4? see images/dind)"; tail -8 /tmp/dx-cmd.log; }

# The API must have no TCP presence. Check the sidecar's own listening sockets
# rather than probing from another pod: a probe only proves "closed" if a
# daemon was listening, which the first version of this test got wrong when
# dockerd crash-looped on a 0.0.0.0:2375 bind it should never have attempted.
if (( docker_up )); then
  ws_pod=$(kubectl -n "$WS_NS" get pods -o name | head -1)
  listeners=$(kubectl -n "$WS_NS" exec "$ws_pod" -c dind -- netstat -ltn 2>/dev/null | awk 'NR>2 {print $4}' | tr '\n' ' ')
  grep -qE ':(2375|2376)( |$)' <<<"$listeners" \
    && bad "Docker API listening on TCP: $listeners" \
    || pass "Docker API has no TCP listener (sidecar listeners: ${listeners:-none})"
else
  bad "Docker API TCP check skipped: daemon not running, result would be meaningless"
fi

echo
(( fail )) && { echo "phase 2 FAILED"; exit 1; }
echo "phase 2 passed"
