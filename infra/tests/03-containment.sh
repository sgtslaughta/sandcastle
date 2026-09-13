#!/usr/bin/env bash
# Phase 3 verify: a workspace reaches only Envoy, kube-dns, Nexus and coderd;
# every other path is dropped, and the drop is visible with workspace identity.
#
# Runs inside the lab VM (make verify-containment) after 04-containment.sh,
# make egress-lock and a template push. Positive controls run first and gate
# the blocked checks: "unreachable" proves nothing if the target was down or
# the workspace had no network at all (Phase 2: the first Docker API probe
# passed because dockerd was crash-looping).
set -uo pipefail

WS_NS=sandcastle-workspaces
WS=ct-test
CODER=${CODER:-$HOME/.local/bin/coder}
NEXUS=http://nexus.sandcastle-mirror.svc.cluster.local
NODE_IP=$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')
CODERD=${CODERD:-http://coder.coder.svc.cluster.local} # spike S5
FAST_MS=${FAST_MS:-3000}                               # spike S3
SNI_CHECK=${SNI_CHECK:-1}                              # spike S4
fail=0
pass() { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }
# Stream checks below use "grep PATTERN >/dev/null", never "grep -q": with
# pipefail, grep -q exits at the first match, the writer dies of SIGPIPE, and
# the pipeline reports failure for a match it found.
hub()  { kubectl -n kube-system exec ds/cilium -- hubble observe --namespace "$WS_NS" -o json "$@" 2>/dev/null; }

cleanup() {
  "$CODER" delete "$WS" --yes >/dev/null 2>&1 || true
  kubectl -n "$WS_NS" delete pod ct-peer --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

# coder ssh joins arguments into one remote command; pass one string.
# timeout: coder ssh waits forever for an agent that never connects.
wsh()  { timeout 300 "$CODER" ssh "$WS" -- "$1" >/tmp/ct-cmd.log 2>&1; }
wout() { timeout 60 "$CODER" ssh "$WS" -- "$1" 2>/dev/null; }
# blocked NAME CMD [MAX_MS]: CMD must fail, within MAX_MS (+3s coder ssh overhead).
blocked() {
  local s rc ms max=${3:-$FAST_MS}
  s=$(date +%s%N); wsh "$2"; rc=$?; ms=$(( ($(date +%s%N) - s) / 1000000 ))
  if (( rc == 0 )); then bad "$1 succeeded"; tail -3 /tmp/ct-cmd.log
  elif (( ms > max + 3000 )); then bad "$1 blocked but slow (${ms}ms)"
  else pass "$1 blocked (${ms}ms)"; fi
}

echo "Sandcastle phase 3 verify: containment core"

# --- host layer --------------------------------------------------------------
# Node traffic is not under workspace policy, so this is what a workspace
# packet looks like if Cilium failed open: only the host lock stops it.
curl -s -m 5 -o /dev/null https://example.com \
  && bad "VM primary IP reached the internet: host egress lock is off (make egress-lock)" \
  || pass "VM primary IP cannot reach the internet (host lock on)"

# --- workspace up (positive controls) ----------------------------------------
kubectl -n "$WS_NS" get cnp workspace-egress >/dev/null 2>&1 \
  && pass "workspace policy present" || { bad "CiliumNetworkPolicy workspace-egress missing"; exit 1; }

# A ct-test pod from an earlier run may still be terminating; its labels
# match the new workspace's and would hand later checks the wrong pod IP.
kubectl -n "$WS_NS" wait --for=delete pod -l "com.coder.workspace.name=$WS" --timeout=3m >/dev/null 2>&1
t_create=$SECONDS
echo "  ..    creating workspace $WS (several minutes)"
"$CODER" create "$WS" --template base --use-parameter-defaults --yes >/tmp/ct-create.log 2>&1 \
  || { bad "coder create failed; see /tmp/ct-create.log"; exit 1; }
for _ in $(seq 60); do timeout 10 "$CODER" ssh "$WS" -- true >/dev/null 2>&1 && break; sleep 5; done
wsh true && pass "coder ssh works (coderd L7 allowlist admits the agent)" \
  || { bad "agent never connected: coderd allowlist too tight? check hubble --protocol http"; exit 1; }
ws_ip=$(kubectl -n "$WS_NS" get pods -l "com.coder.workspace.name=$WS" -o jsonpath='{.items[0].status.podIP}')

for _ in $(seq 24); do wsh 'curl -fsS -m 3 http://127.0.0.1:13337/healthz' && break; sleep 5; done
wsh 'curl -fsS -m 3 http://127.0.0.1:13337/healthz' && pass "code-server healthy" || bad "code-server unhealthy"
wsh 'curl -fsS -m 20 -o /dev/null https://example.com' && pass "allowlisted HTTPS via proxy (example.com)" \
  || { bad "allowlisted host via proxy failed: denial checks would be meaningless"; tail -3 /tmp/ct-cmd.log; exit 1; }
wsh 'getent hosts nexus.sandcastle-mirror.svc.cluster.local' && pass "service DNS resolves" || bad "service DNS failed"
wsh 'sudo apt-get update >/dev/null && sudo apt-get install -y tree >/dev/null' && pass "apt via Nexus" || bad "apt via Nexus"
wsh 'python3 -m venv /tmp/v && /tmp/v/bin/pip install -q six' && pass "pip via Nexus" || bad "pip via Nexus"
wsh 'mkdir -p /tmp/n && cd /tmp/n && npm init -y >/dev/null && npm install -s left-pad' && pass "npm via Nexus" || bad "npm via Nexus"

docker_up=0
for _ in $(seq 24); do wsh 'docker version' && { docker_up=1; break; }; sleep 5; done
(( docker_up )) || bad "Docker daemon never answered"
wsh 'mkdir -p /tmp/d && printf "FROM busybox:1.36\nRUN echo built\n" >/tmp/d/Dockerfile && docker build -q -t ct-test /tmp/d' \
  && pass "docker build via Nexus registry mirror" || { bad "docker build failed"; tail -5 /tmp/ct-cmd.log; }
kubectl -n sandcastle-mirror exec nexus-0 -- grep -q '/v2/library/busybox' /nexus-data/log/request.log \
  && pass "Nexus docker-hub served busybox" || bad "no busybox pulls in Nexus request log"

kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: ct-peer, namespace: $WS_NS}
spec:
  runtimeClassName: kata-clh-runtime-rs
  automountServiceAccountToken: false
  containers:
    - {name: c, image: "sandcastle/base:0.2.0", imagePullPolicy: Never, command: ["python3", "-m", "http.server", "8000"]}
YAML
kubectl -n "$WS_NS" wait --for=condition=Ready pod/ct-peer --timeout=5m >/dev/null
peer_ip=$(kubectl -n "$WS_NS" get pod ct-peer -o jsonpath='{.status.podIP}')
# Ready means the container started, not that python is listening yet.
for _ in $(seq 30); do curl -fs -m 2 -o /dev/null "http://$peer_ip:8000/" && break; sleep 2; done
curl -fsS -m 5 -o /dev/null "http://$peer_ip:8000/" \
  && pass "peer pod listening (positive control from node)" || bad "peer pod unreachable from node: peer check meaningless"

# --- noise budget ------------------------------------------------------------
# Everything so far was allowed work (boot, ssh, installs, builds). The only
# drops it may cause are the Coder agent's embedded Tailscale port-mapping
# probes, which no setting disables in Coder 2.36.5 (CODER_BLOCK_DIRECT and
# TS_DISABLE_UPNP both tried): NAT-PMP/PCP and SSDP to the pod gateway, SSDP
# multicast, and UDP to 203.0.113.1:12345. Policy keeps them blocked; any
# other drop is unexplained, which is what must page. Phase 6 alert rules
# reuse these three signatures.
gw=$(ip -4 -o addr show cilium_host | awk '{split($4,a,"/"); print a[1]}')
ws_pod=$(kubectl -n "$WS_NS" get pods -l "com.coder.workspace.name=$WS" -o jsonpath='{.items[0].metadata.name}')
unexplained=$(kubectl -n kube-system exec ds/cilium -- hubble observe --since "$(( SECONDS - t_create ))s" \
    --pod "$WS_NS/$ws_pod" --verdict DROPPED -o json 2>/dev/null \
  | jq -r --arg gw "$gw" '.flow | {d: .IP.destination, u: (.l4.UDP.destination_port // 0), t: (.l4.TCP.destination_port // 0), q: (.l7.dns.query // ((.l7.http.method // "") + " " + (.l7.http.url // "")))}
      | select(((.u == 5351 and .d == $gw) or (.u == 1900 and (.d == $gw or .d == "239.255.255.250")) or (.u == 12345 and .d == "203.0.113.1")) | not)
      | "\(.d) udp:\(.u) tcp:\(.t) \(.q)"' | sort | uniq -c)
[[ -z "$unexplained" ]] && pass "allowed work caused no drops beyond the 3 known agent probe signatures" \
  || bad "unexplained drops during allowed work: $(tr -s ' \n' ' ' <<<"$unexplained")"

# --- blocked -----------------------------------------------------------------
blocked "direct egress to 1.1.1.1 ignoring proxy" "curl --noproxy '*' -s -m 20 -o /dev/null http://1.1.1.1"
# Service-translated destinations (ClusterIPs) get no ICMP deny response
# (spike S3): the drop is silent, so these wait for their own timeout.
blocked "kube API 10.43.0.1:443" "curl --noproxy '*' -sk -m 10 -o /dev/null https://10.43.0.1/" 12000
blocked "kubelet $NODE_IP:10250" "curl --noproxy '*' -sk -m 20 -o /dev/null https://$NODE_IP:10250/"
blocked "other workspace pod $peer_ip:8000" "curl --noproxy '*' -s -m 20 -o /dev/null http://$peer_ip:8000/"
blocked "coder Postgres coder-db:5432" "timeout 10 bash -c '</dev/tcp/coder-db.coder.svc.cluster.local/5432'" 12000

wsh 'getent hosts example.com' && bad "workspace resolved external name example.com (DNS exfil path)" \
  || pass "external DNS names refused"
wsh "curl -s -v -m 20 -o /dev/null https://github.com 2>&1 | grep -iq '^< x-sandcastle-denied'" \
  && pass "non-allowlisted HTTPS: 403 with x-sandcastle-denied" || bad "non-allowlisted HTTPS not denied with header"
code=$(wout "curl -s -m 20 -o /dev/null -w '%{http_code}' http://neverssl.com/")
[[ "$code" == 403 ]] && pass "non-allowlisted HTTP: 403" || bad "non-allowlisted HTTP returned '$code'"
if (( SNI_CHECK )); then
  wsh "curl -sk -m 20 -o /dev/null --connect-to github.com:443:example.com:443 https://github.com" \
    && bad "SNI github.com tunneled via CONNECT example.com (fronting)" || pass "SNI mismatch via allowlisted CONNECT refused"
fi

code=$(wout "curl --noproxy '*' -s -m 10 -o /dev/null -w '%{http_code}' $CODERD/api/v2/users")
[[ "$code" == 403 ]] && pass "coderd /api/v2/users refused (403)" || bad "coderd /api/v2/users returned '$code'"
code=$(wout "curl --noproxy '*' -s -m 10 -o /dev/null -w '%{http_code}' -X POST $CODERD/api/v2/users/login")
[[ "$code" == 403 ]] && pass "coderd login refused (403)" || bad "coderd login returned '$code'"
code=$(wout "curl --noproxy '*' -s -m 10 -o /dev/null -w '%{http_code}' -X PUT --data x $NEXUS:8081/repository/pypi-proxy/x")
[[ "$code" == 403 ]] && pass "Nexus PUT refused (403)" || bad "Nexus PUT returned '$code'"
code=$(wout "curl --noproxy '*' -s -m 10 -o /dev/null -w '%{http_code}' $NEXUS:8081/service/rest/v1/status")
[[ "$code" == 403 ]] && pass "Nexus REST API refused (403)" || bad "Nexus REST API returned '$code'"

if (( docker_up )); then
  wsh 'docker run --rm busybox:1.36 true' && pass "docker run works (positive control)" || bad "docker run failed"
  blocked "DinD --network host direct egress" "docker run --rm --network host busybox:1.36 wget -T 15 -q -O /dev/null http://1.1.1.1"
fi
wsh "awk '\$4 == \"00\"' /proc/net/if_inet6 | grep -q ." \
  && bad "workspace has a global IPv6 address" || pass "no global IPv6 address in workspace"

# --- seen --------------------------------------------------------------------
timeout 30 "$CODER" ssh "$WS" -- "curl --noproxy '*' -s -m 3 http://1.1.1.2" >/dev/null 2>&1
seen=0
for s in 1 2 3 4 5; do
  # Not hub(): hubble refuses --to-ip combined with --namespace.
  kubectl -n kube-system exec ds/cilium -- hubble observe --since 30s --verdict DROPPED --to-ip 1.1.1.2 -o json 2>/dev/null | grep "com.coder.workspace.name=$WS" >/dev/null && { seen=$s; break; }
  sleep 1
done
(( seen )) && pass "Hubble drop attributed to workspace $WS within ${seen}s" || bad "no attributed Hubble drop within 5s"
hub --since 15m --protocol http | grep '/api/v2/users' >/dev/null && pass "Hubble L7 denial for coderd /api/v2/users" || bad "no Hubble L7 event for /api/v2/users"
hub --since 15m --protocol dns | grep 'example.com' >/dev/null && pass "Hubble DNS event for example.com" || bad "no Hubble DNS event for example.com"
kubectl -n sandcastle-egress logs deploy/envoy-egress --since=20m | grep '"authority":"github.com:443"' | grep "\"src\":\"$ws_ip\"" >/dev/null \
  && pass "Envoy denial logged with source $ws_ip (workspace $WS)" || bad "no Envoy log line for github.com from $ws_ip"
if (( SNI_CHECK )); then
  kubectl -n sandcastle-egress logs deploy/envoy-egress --since=20m | grep '"stage":"sni"' | grep '"sni":"github.com"' | grep '"flags":"NR"' >/dev/null \
    && pass "Envoy logged SNI-mismatch refusal (sni github.com, NR)" || bad "SNI-mismatch refusal not logged by Envoy stage 2"
fi

echo
(( fail )) && { echo "phase 3 FAILED"; exit 1; }
echo "phase 3 passed (host side: sudo make verify-host-egress)"
