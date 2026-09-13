#!/usr/bin/env bash
# Phase 4 verify: sandcastle-admin turns zones, requests and grants into
# enforced egress for exactly one workspace within seconds, revokes and
# expires them (closing open tunnels), fails closed without admin, keeps
# itself unreachable from workspaces, and audits every change.
#
# Runs inside the lab VM (make verify-admin) after 05-admin.sh with
# TEST_HOOKS=1, make egress-lock and a template push. Uses two workspaces.
set -uo pipefail

WS_NS=sandcastle-workspaces
A=adm-a; B=adm-b
CODER=${CODER:-$HOME/.local/bin/coder}
NODE_IP=$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')
ADMIN=http://$NODE_IP:30081
ZONE_NAME=restricted-$RANDOM
fail=0
pass() { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }

TOKEN=$(kubectl -n sandcastle-admin get secret admin-test-token -o jsonpath='{.data.token}' 2>/dev/null | base64 -d)
APP_PW=$(kubectl -n sandcastle-admin get secret admin-db -o jsonpath='{.data.app-password}' | base64 -d)
sql() { kubectl -n sandcastle-admin exec statefulset/admin-db -- psql -U postgres -d admin -tAc "$1" 2>&1; }
# api PATH key=value... : POST a form as the test hook; prints "CODE REDIRECT".
api() {
  local path=$1 args=(); shift
  for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  curl -s -o /tmp/adm-api.log -w '%{http_code} %{redirect_url}' -H "Authorization: Bearer $TOKEN" "${args[@]}" "$ADMIN$path"
}
wsh()  { timeout 300 "$CODER" ssh "$1" -- "$2" >/tmp/adm-cmd.log 2>&1; }
wout() { timeout 120 "$CODER" ssh "$1" -- "$2" 2>/dev/null; }
now_ms() { date +%s%3N; }
# reach WS HOST: exit 0 if HTTPS via the proxy succeeds.
reach() { wsh "$1" "curl -s -o /dev/null -m 10 https://$2"; }
# await WS HOST yes|no SECS: poll inside the workspace (no ssh per try);
# prints the workspace epoch ms when the state is first seen.
await() {
  local test='curl -s -o /dev/null -m 5 https://'"$2"
  [[ $3 == no ]] && test="! $test"
  wout "$1" "end=\$((\$(date +%s)+$4)); while [ \$(date +%s) -lt \$end ]; do if $test; then date +%s%3N; exit 0; fi; sleep 0.25; done; exit 1"
}
ws_id() { kubectl -n "$WS_NS" get pods -l "com.coder.workspace.name=$1" -o jsonpath='{.items[0].metadata.labels.com\.coder\.workspace\.id}'; }

cleanup() {
  kubectl -n sandcastle-admin scale deploy/sandcastle-admin --replicas=1 >/dev/null 2>&1
  [[ -n "${B_ID:-}" && -n "${DEF_ID:-}" ]] && api "/workspaces/$B_ID/zone" "zone=$DEF_ID" >/dev/null
  [[ -n "${ZONE_ID:-}" ]] && api "/zones/$ZONE_ID/delete" >/dev/null
  "$CODER" delete "$A" --yes >/dev/null 2>&1 || true
  "$CODER" delete "$B" --yes >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Sandcastle phase 4 verify: admin control plane"

# --- preflight -----------------------------------------------------------------
[[ -n "$TOKEN" ]] && pass "test hook token present" || { bad "admin-test-token missing: run 05-admin.sh with TEST_HOOKS=1"; exit 1; }
kubectl -n sandcastle-admin rollout status deploy/sandcastle-admin --timeout=2m >/dev/null && pass "sandcastle-admin ready" || { bad "sandcastle-admin not ready"; exit 1; }
kubectl -n sandcastle-egress rollout status deploy/envoy-egress --timeout=2m >/dev/null && pass "envoy ready (listeners from xDS)" || { bad "envoy not ready"; exit 1; }
kubectl -n sandcastle-egress logs deploy/envoy-egress --since=30m | grep -iE 'rejected|NACK' >/dev/null \
  && bad "envoy rejected xDS config" || pass "envoy accepted xDS config"
DEF_ID=$(sql "SELECT id FROM zones WHERE is_default")
[[ "$(sql "SELECT count(*) FROM rules WHERE zone_id='$DEF_ID' AND value='example.com'")" == 2 ]] \
  && pass "default zone seeded with example.com" || bad "default zone seed missing"

# --- workspaces ------------------------------------------------------------------
for w in "$A" "$B"; do kubectl -n "$WS_NS" wait --for=delete pod -l "com.coder.workspace.name=$w" --timeout=3m >/dev/null 2>&1; done
echo "  ..    creating workspaces $A and $B (several minutes)"
"$CODER" create "$A" --template base --use-parameter-defaults --yes >/tmp/adm-create-a.log 2>&1 &
"$CODER" create "$B" --template base --use-parameter-defaults --yes >/tmp/adm-create-b.log 2>&1 &
wait
wsh "$A" true && wsh "$B" true && pass "both workspaces reachable over coder ssh" || { bad "workspace creation failed; see /tmp/adm-create-*.log"; exit 1; }
A_ID=$(ws_id "$A"); B_ID=$(ws_id "$B")

# --- zones -----------------------------------------------------------------------
[[ -n "$(await "$A" example.com yes 30)" ]] && pass "A reaches example.com via default zone" || bad "A cannot reach example.com (default zone)"
read -r code _ <<<"$(api "/zones/$DEF_ID/clone" "name=$ZONE_NAME")"
ZONE_ID=$(sql "SELECT id FROM zones WHERE name='$ZONE_NAME'")
[[ "$code" == 303 && -n "$ZONE_ID" ]] && pass "zone cloned ($ZONE_NAME)" || bad "clone failed ($code): $(cat /tmp/adm-api.log)"
for rid in $(sql "SELECT id FROM rules WHERE zone_id='$ZONE_ID' AND value='example.com'"); do api "/rules/$rid/delete" back=/zones >/dev/null; done
read -r code _ <<<"$(api "/workspaces/$B_ID/zone" "zone=$ZONE_ID")"
[[ "$code" == 303 ]] && pass "B moved to $ZONE_NAME" || bad "move failed ($code)"
[[ -n "$(await "$B" example.com no 15)" ]] && pass "B denied example.com after zone move" || bad "B still reaches example.com"
reach "$A" example.com && pass "A unaffected by B's move" || bad "A lost example.com"

# --- request -> approve ------------------------------------------------------------
reach "$A" example.org && bad "A reaches example.org before any grant" || pass "A denied example.org before grant"
read -r code loc <<<"$(api /requests "ws=$A_ID" host=example.org port=443 "justification=phase 4 verify")"
REQ_ID=${loc##*filed=}
[[ "$code" == 303 && -n "$REQ_ID" ]] && pass "request filed" || bad "request failed ($code): $(cat /tmp/adm-api.log)"
await "$A" example.org yes 30 >/tmp/adm-await.log &
w=$!; sleep 2; t0=$(now_ms)
read -r code _ <<<"$(api "/requests/$REQ_ID/approve" ttl=168h)"
wait $w; t1=$(cat /tmp/adm-await.log)
if [[ "$code" == 303 && -n "$t1" ]] && (( t1 - t0 <= 5000 )); then pass "approval enforced for A in $((t1 - t0))ms"
else bad "approval not enforced within 5s (code $code, took $(( ${t1:-0} - t0 ))ms)"; fi
reach "$B" example.org && bad "B reaches example.org (grant leaked across workspaces)" || pass "grant applies to A only"

# --- revoke closes open tunnels ------------------------------------------------------
cat >/tmp/adm-tunnel.py <<'PY'
import os, socket, ssl, sys, time
host, port = os.environ["HTTPS_PROXY"].split("//")[-1].rstrip("/").rsplit(":", 1)
s = socket.create_connection((host, int(port)), timeout=10)
s.sendall(b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n")
if b" 200" not in s.recv(1024).split(b"\r\n")[0]:
    print("noconnect", flush=True); sys.exit(1)
t = ssl.create_default_context().wrap_socket(s, server_hostname="example.org")
print("open", flush=True)
try:
    while True:  # keep traffic flowing: the CDN closes idle keepalives (~15s)
        t.sendall(b"HEAD / HTTP/1.1\r\nHost: example.org\r\n\r\n")
        if not t.recv(4096):
            break
        time.sleep(2)
except Exception:
    pass
print("closed", int(time.time() * 1000), flush=True)
PY
wsh "$A" "echo $(base64 -w0 /tmp/adm-tunnel.py) | base64 -d > /tmp/tunnel.py"
timeout 90 "$CODER" ssh "$A" -- "python3 /tmp/tunnel.py" >/tmp/adm-tunnel.log 2>&1 &
tun=$!
for _ in $(seq 30); do grep '^open' /tmp/adm-tunnel.log >/dev/null && break; sleep 1; done
grep '^open' /tmp/adm-tunnel.log >/dev/null && pass "long-lived tunnel to example.org open" || bad "tunnel did not open: $(cat /tmp/adm-tunnel.log)"
GRANT_ID=$(sql "SELECT id FROM rules WHERE workspace_id='$A_ID' AND value='example.org'")
t0=$(now_ms)
read -r code _ <<<"$(api "/rules/$GRANT_ID/delete" back=/workspaces)"
t1=$(await "$A" example.org no 30)
[[ "$code" == 303 && -n "$t1" ]] && (( t1 - t0 <= 5000 )) && pass "revocation enforced for new connections in $((t1 - t0))ms" \
  || bad "revocation not enforced within 5s (code $code)"
wait $tun
closed=$(awk '/^closed/ {print $2}' /tmp/adm-tunnel.log)
[[ -n "$closed" ]] && (( closed - t0 <= 10000 )) && pass "open tunnel closed $((closed - t0))ms after revoke" \
  || bad "open tunnel survived revoke: $(tail -2 /tmp/adm-tunnel.log)"

# --- expiry ---------------------------------------------------------------------------
read -r code _ <<<"$(api "/workspaces/$A_ID/grants" kind=host value=example.net port=443 ttl=60s)"
[[ "$code" == 303 && -n "$(await "$A" example.net yes 30)" ]] && pass "60s grant to example.net works" || bad "short grant failed ($code)"
[[ -n "$(await "$A" example.net no 110)" ]] && pass "grant expired and was enforced" || bad "expired grant still works after 110s"
[[ "$(sql "SELECT count(*) FROM audit WHERE action='expire' AND detail->>'value'='example.net'")" -ge 1 ]] \
  && pass "expiry audited" || bad "expiry not audited"

# --- dns grant ------------------------------------------------------------------------
read -r code _ <<<"$(api "/workspaces/$A_ID/grants" kind=dns value=example.org ttl=1h)"
ok=0; for _ in $(seq 20); do wsh "$A" 'getent hosts example.org' && { ok=1; break; }; sleep 2; done
(( ok )) && pass "DNS grant: A resolves example.org" || bad "DNS grant not applied ($code)"
wsh "$B" 'getent hosts example.org' && bad "B resolves example.org (DNS grant leaked)" || pass "DNS grant applies to A only"

# --- admin unreachable from workspaces ------------------------------------------------------
for target in sandcastle-admin.sandcastle-admin.svc.cluster.local/18000 sandcastle-admin-ui.sandcastle-admin.svc.cluster.local/80 "$NODE_IP/30081"; do
  wsh "$A" "timeout 5 bash -c '</dev/tcp/$target'" && bad "workspace connected to admin at $target" || pass "workspace cannot reach admin at $target"
done

# --- denials recorded ----------------------------------------------------------------------
wsh "$A" 'curl -s -o /dev/null -m 5 https://github.com'
ok=0; for _ in $(seq 10); do [[ "$(sql "SELECT count(*) FROM denials WHERE workspace_id='$A_ID' AND host='github.com'")" -ge 1 ]] && { ok=1; break; }; sleep 1; done
(( ok )) && pass "denial recorded for A (github.com)" || bad "denial not recorded"

# --- audit -----------------------------------------------------------------------------------
for action in zone_clone rule_delete assign request approve grant expire; do
  [[ "$(sql "SELECT count(*) FROM audit WHERE action='$action'")" -ge 1 ]] && pass "audit has $action" || bad "audit missing $action"
done
out=$(kubectl -n sandcastle-admin exec statefulset/admin-db -- env PGPASSWORD="$APP_PW" psql -h 127.0.0.1 -U sandcastle_app -d admin -c "UPDATE audit SET actor='x'" 2>&1)
echo "$out" | grep 'permission denied' >/dev/null && pass "app role cannot rewrite audit" || bad "UPDATE audit as app role: $out"

# --- fail closed --------------------------------------------------------------------------------
kubectl -n sandcastle-admin scale deploy/sandcastle-admin --replicas=0 >/dev/null
kubectl -n sandcastle-admin wait --for=delete pod -l app=sandcastle-admin --timeout=2m >/dev/null 2>&1
reach "$A" example.com && pass "admin down: running Envoy keeps last snapshot" || bad "admin down broke existing access"
kubectl -n sandcastle-egress delete pod -l app=envoy-egress --wait=true >/dev/null
sleep 10
reach "$A" example.com && bad "fresh Envoy without admin allowed egress" || pass "fresh Envoy without admin fails closed"
kubectl -n sandcastle-admin scale deploy/sandcastle-admin --replicas=1 >/dev/null
kubectl -n sandcastle-egress rollout status deploy/envoy-egress --timeout=3m >/dev/null
[[ -n "$(await "$A" example.com yes 60)" ]] && pass "admin back: egress restored" || bad "egress not restored after admin returned"

echo
(( fail == 0 )) && echo "phase 4 passed" || { echo "phase 4 FAILED"; exit 1; }
