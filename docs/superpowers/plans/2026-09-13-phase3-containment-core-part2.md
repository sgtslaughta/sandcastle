# Phase 3 Containment Core Implementation Plan (part 2 of 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

Part 1 (header, Global Constraints, File Map, Tasks 0–4): `docs/superpowers/plans/2026-09-13-phase3-containment-core.md`. Its Global Constraints apply here unchanged. `VMSSH` and `VMSYNC` are defined there.

**Spike decisions used here** (from `docs/superpowers/specs/2026-09-13-phase3-spike-results.md`):
- **S1** egress gateway works with Kata, or falls back to a VM-wide allowlist.
- **S3** how a denied connection fails:
  - `icmp-fast`: fails immediately;
  - `icmp-needs-ingress-rule`: fails immediately only with an extra ingress rule;
  - `timeout-only`: hangs until timeout.
- **S4** whether Envoy checks SNI after CONNECT (two-stage) or only the CONNECT host.
- **S5**:
  - coder address: the pod on 8080, or the host NodePort 30080;
  - coder path regex list.
- **S6** DNS patterns.

---

### Task 5: Verify suite (written first, fails until Tasks 6–8 land)

**Files:**
- Create: `infra/tests/03-containment.sh`

**Interfaces:**
- Consumes (the names later tasks must create):
  - CNP `workspace-egress` in `sandcastle-workspaces`;
  - Deployment `envoy-egress` in `sandcastle-egress`, JSON access log keys `src`, `authority`, `code`;
  - Nexus `request.log`;
  - host log prefix `sandcastle-deny `.
- Env knobs set from spike decisions:
  - `CODERD`: `http://coder.coder.svc.cluster.local` for pod-8080, `http://<node-ip>:30080` for host-30080;
  - `FAST_MS`: 3000, or 20000 for timeout-only;
  - `SNI_CHECK`: 1, or 0 for authority-only.

- [ ] **Step 1: Write the script**

```bash
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
hub()  { kubectl -n kube-system exec ds/cilium -- hubble observe --namespace "$WS_NS" -o json "$@" 2>/dev/null; }

cleanup() {
  "$CODER" delete "$WS" --yes >/dev/null 2>&1 || true
  kubectl -n "$WS_NS" delete pod ct-peer --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

# coder ssh joins arguments into one remote command; pass one string.
wsh()  { "$CODER" ssh "$WS" -- "$1" >/tmp/ct-cmd.log 2>&1; }
wout() { "$CODER" ssh "$WS" -- "$1" 2>/dev/null; }
# blocked NAME CMD: CMD must fail, and fail fast (+3s coder ssh overhead).
blocked() {
  local s rc ms
  s=$(date +%s%N); wsh "$2"; rc=$?; ms=$(( ($(date +%s%N) - s) / 1000000 ))
  if (( rc == 0 )); then bad "$1 succeeded"; tail -3 /tmp/ct-cmd.log
  elif (( ms > FAST_MS + 3000 )); then bad "$1 blocked but slow (${ms}ms)"
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

echo "  ..    creating workspace $WS (several minutes)"
"$CODER" create "$WS" --template base --use-parameter-defaults --yes >/tmp/ct-create.log 2>&1 \
  || { bad "coder create failed; see /tmp/ct-create.log"; exit 1; }
for _ in $(seq 60); do "$CODER" ssh "$WS" -- true >/dev/null 2>&1 && break; sleep 5; done
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
curl -fsS -m 5 -o /dev/null "http://$peer_ip:8000/" \
  && pass "peer pod listening (positive control from node)" || bad "peer pod unreachable from node: peer check meaningless"

# --- blocked -----------------------------------------------------------------
blocked "direct egress to 1.1.1.1 ignoring proxy" "curl --noproxy '*' -s -m 20 -o /dev/null http://1.1.1.1"
blocked "kube API 10.43.0.1:443" "curl --noproxy '*' -sk -m 20 -o /dev/null https://10.43.0.1/"
blocked "kubelet $NODE_IP:10250" "curl --noproxy '*' -sk -m 20 -o /dev/null https://$NODE_IP:10250/"
blocked "other workspace pod $peer_ip:8000" "curl --noproxy '*' -s -m 20 -o /dev/null http://$peer_ip:8000/"
blocked "coder Postgres coder-db:5432" "timeout 20 bash -c '</dev/tcp/coder-db.coder.svc.cluster.local/5432'"

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
"$CODER" ssh "$WS" -- "curl --noproxy '*' -s -m 3 http://1.1.1.2" >/dev/null 2>&1
seen=0
for s in 1 2 3 4 5; do
  hub --since 30s --verdict DROPPED --to-ip 1.1.1.2 | grep -q "com.coder.workspace.name=$WS" && { seen=$s; break; }
  sleep 1
done
(( seen )) && pass "Hubble drop attributed to workspace $WS within ${seen}s" || bad "no attributed Hubble drop within 5s"
hub --since 15m --protocol http | grep -q '/api/v2/users' && pass "Hubble L7 denial for coderd /api/v2/users" || bad "no Hubble L7 event for /api/v2/users"
hub --since 15m --protocol dns | grep -q 'example.com' && pass "Hubble DNS event for example.com" || bad "no Hubble DNS event for example.com"
kubectl -n sandcastle-egress logs deploy/envoy-egress --since=20m | grep '"authority":"github.com:443"' | grep -q "\"src\":\"$ws_ip\"" \
  && pass "Envoy denial logged with source $ws_ip (workspace $WS)" || bad "no Envoy log line for github.com from $ws_ip"

echo
(( fail )) && { echo "phase 3 FAILED"; exit 1; }
echo "phase 3 passed (host side: sudo make verify-host-egress)"
```

- [ ] **Step 2: Syntax check**

Run: `bash -n infra/tests/03-containment.sh && wc -l infra/tests/03-containment.sh`
Expected: no errors, under 500 lines.

- [ ] **Step 3: Run it and watch it fail**

Run: `VMSYNC && VMSSH 'cd sandcastle && infra/tests/03-containment.sh'`
Expected: `FAIL  CiliumNetworkPolicy workspace-egress missing`, then exit 1. The host-layer line may also FAIL (lock off). That is the correct red state.

- [ ] **Step 4: Commit**

```bash
git add infra/tests/03-containment.sh
git commit -m "test(containment): add phase 3 containment verify suite"
```

---

### Task 6: Envoy egress gate

**Files:**
- Create: `platform/egress/envoy.yaml`

**Interfaces:**
- Produces:
  - Service `egress.sandcastle-egress:3128`;
  - pods labeled `app: envoy-egress`;
  - JSON access log keys `time`, `src`, `method`, `authority`, `code`, `flags`, `bytes_up`, `bytes_down`;
  - header `x-sandcastle-denied`.

- [ ] **Step 1: Write the manifest**

The `envoy.yaml` key in this ConfigMap is the exact file spike S4 validated. If S4 changed it, use the spike version.

```yaml
# Egress gate (Phase 3, static allowlist; Phase 4 replaces it with xDS from
# sandcastle-admin). Explicit proxy: workspaces set HTTP(S)_PROXY, and any
# other path is dropped by platform/policy/workspaces.yaml.
#
# HTTPS is two-stage. Stage 1 checks the CONNECT authority against the
# allowlist and terminates the tunnel into the internal listener sni_gate.
# Stage 2 reads the TLS SNI, requires it to be allowlisted too, and dials the
# SNI host, so an allowlisted CONNECT cannot carry a handshake for another
# host. Denials return 403 plus x-sandcastle-denied (browsers hide
# refused-CONNECT bodies; no TLS interception, DR-3.4). The source IP in the
# access log is the workspace identity (DR-3.5).
apiVersion: v1
kind: Namespace
metadata:
  name: sandcastle-egress
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: envoy-egress
  namespace: sandcastle-egress
data:
  envoy.yaml: |
    bootstrap_extensions:
      - name: envoy.bootstrap.internal_listener
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.bootstrap.internal_listener.v3.InternalListener
    admin:
      address: {socket_address: {address: 127.0.0.1, port_value: 9901}}
    static_resources:
      listeners:
        - name: proxy
          address: {socket_address: {address: 0.0.0.0, port_value: 3128}}
          filter_chains:
            - filters:
                - name: envoy.filters.network.http_connection_manager
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                    stat_prefix: egress
                    upgrade_configs: [{upgrade_type: CONNECT}]
                    access_log:
                      - name: envoy.access_loggers.stdout
                        typed_config:
                          "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
                          log_format:
                            json_format:
                              time: "%START_TIME%"
                              src: "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
                              method: "%REQ(:METHOD)%"
                              authority: "%REQ(:AUTHORITY)%"
                              code: "%RESPONSE_CODE%"
                              flags: "%RESPONSE_FLAGS%"
                              bytes_up: "%BYTES_RECEIVED%"
                              bytes_down: "%BYTES_SENT%"
                    http_filters:
                      - name: envoy.filters.http.dynamic_forward_proxy
                        typed_config:
                          "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
                          dns_cache_config: {name: dfp, dns_lookup_family: V4_ONLY}
                      - name: envoy.filters.http.router
                        typed_config:
                          "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                    route_config:
                      virtual_hosts:
                        - name: allow_https
                          domains: ["example.com:443"]
                          routes:
                            - match: {connect_matcher: {}}
                              route:
                                cluster: sni_gate
                                upgrade_configs: [{upgrade_type: CONNECT, connect_config: {}}]
                        - name: allow_http
                          domains: ["example.com", "example.com:80"]
                          routes:
                            - match: {prefix: "/"}
                              route: {cluster: dfp_http}
                        - name: deny
                          domains: ["*"]
                          response_headers_to_add:
                            - header:
                                key: x-sandcastle-denied
                                value: "host=%REQ(:AUTHORITY)%; source=%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
                          routes:
                            - match: {connect_matcher: {}}
                              direct_response: {status: 403}
                            - match: {prefix: "/"}
                              direct_response:
                                status: 403
                                body:
                                  inline_string: "sandcastle: egress to this host is not allowed for this workspace. Access requests arrive in Phase 4.\n"
        - name: sni_gate
          internal_listener: {}
          listener_filters:
            - name: envoy.filters.listener.tls_inspector
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
          filter_chains:
            - filter_chain_match: {server_names: ["example.com"]}
              filters:
                - name: envoy.filters.network.sni_dynamic_forward_proxy
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.network.sni_dynamic_forward_proxy.v3.FilterConfig
                    port_value: 443
                    dns_cache_config: {name: dfp, dns_lookup_family: V4_ONLY}
                - name: envoy.filters.network.tcp_proxy
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                    stat_prefix: sni
                    cluster: dfp_sni
      clusters:
        - name: sni_gate
          load_assignment:
            cluster_name: sni_gate
            endpoints:
              - lb_endpoints:
                  - endpoint:
                      address:
                        envoy_internal_address: {server_listener_name: sni_gate}
        - name: dfp_http
          lb_policy: CLUSTER_PROVIDED
          cluster_type:
            name: envoy.clusters.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
              dns_cache_config: {name: dfp, dns_lookup_family: V4_ONLY}
        - name: dfp_sni
          lb_policy: CLUSTER_PROVIDED
          cluster_type:
            name: envoy.clusters.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
              dns_cache_config: {name: dfp, dns_lookup_family: V4_ONLY}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: envoy-egress
  namespace: sandcastle-egress
spec:
  # ponytail: one replica on a one-node lab; DaemonSet or HPA once multi-node (DR-3.8).
  replicas: 1
  selector:
    matchLabels: {app: envoy-egress}
  template:
    metadata:
      labels: {app: envoy-egress}
      annotations:
        sandcastle.io/config-rev: "1" # bump to roll pods after a ConfigMap change
    spec:
      automountServiceAccountToken: false
      containers:
        - name: envoy
          image: envoyproxy/envoy:v1.39.1
          args: ["-c", "/etc/envoy/envoy.yaml", "--log-level", "warn"]
          ports:
            - containerPort: 3128
          readinessProbe:
            tcpSocket: {port: 3128}
            periodSeconds: 5
          securityContext:
            runAsNonRoot: true
            runAsUser: 101
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          resources:
            requests: {cpu: 100m, memory: 128Mi}
            limits: {memory: 512Mi}
          volumeMounts:
            - {name: config, mountPath: /etc/envoy, readOnly: true}
            - {name: tmp, mountPath: /tmp}
      volumes:
        - name: config
          configMap: {name: envoy-egress}
        - name: tmp
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: egress
  namespace: sandcastle-egress
spec:
  selector: {app: envoy-egress}
  ports:
    - {name: proxy, port: 3128, targetPort: 3128}
```

**S4 = authority-only fallback:** in `allow_https`, change `cluster: sni_gate` to `cluster: dfp_http`. Then delete the `sni_gate` listener and cluster. Rewrite the header comment's second paragraph to say SNI is not checked (residual widens, recorded in the spike results).

- [ ] **Step 2: Validate the config on the host**

Run: `mkdir -p /tmp/claude-envoy && python3 -c 'import yaml,sys; docs=list(yaml.safe_load_all(open("platform/egress/envoy.yaml"))); open("/tmp/claude-envoy/envoy.yaml","w").write([d for d in docs if d["kind"]=="ConfigMap"][0]["data"]["envoy.yaml"])' && docker run --rm -v /tmp/claude-envoy:/cfg:ro envoyproxy/envoy:v1.39.1 --mode validate -c /cfg/envoy.yaml`
Expected: `configuration '/cfg/envoy.yaml' OK`. (If python3 lacks yaml, extract the block with `sed` between `envoy.yaml: |` and `---`, removing 4 leading spaces.)

- [ ] **Step 3: Server-side dry run in the VM**

Run: `VMSYNC && VMSSH 'cd sandcastle && kubectl apply --dry-run=server -f platform/egress/envoy.yaml'`
Expected: 4 objects `(server dry run)`. The namespace dry-run may report `namespaces "sandcastle-egress" not found` for the namespaced objects; if so, apply the Namespace first with `kubectl apply -f - <<< "$(sed -n '1,/^---/p' ...)"`, or accept and move on, since Task 8 applies the whole file.

- [ ] **Step 4: Commit**

```bash
git add platform/egress/envoy.yaml
git commit -m "feat(egress): add envoy egress gate with connect and sni allowlist"
```

---

### Task 7: Cilium network policies and egress gateway

**Files:**
- Create: `platform/policy/workspaces.yaml`
- Create: `platform/policy/platform.yaml`
- Create: `platform/policy/egress-gateway.yaml`

**Interfaces:**
- Consumes: labels `app: envoy-egress` (Task 6), `app: nexus`, `app: coder-db`, `app.kubernetes.io/name: coder`, `k8s-app: kube-dns`; S3, S5 and S6.
- Produces: CNP `workspace-egress` (Task 5 checks for it by name).

- [ ] **Step 1: Write `platform/policy/workspaces.yaml`**

Replace the `dns:` list with the S6 patterns and the coder `http:` list with the S5 regexes. If S5 = `host-30080`, replace the whole coder egress entry with the commented alternative below it. If S3 = `icmp-needs-ingress-rule`, replace `ingress: [{}]` with the commented ICMP form.

```yaml
# Phase 3 core invariant (spec: 2026-09-13-phase3-containment-core-design.md):
# a workspace pod reaches exactly four destinations. endpointSelector {}
# covers every pod in the namespace, not only pods carrying Coder labels, so a
# pod created by a compromised coderd is locked down too (DR-3.1).
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: workspace-egress
  namespace: sandcastle-workspaces
spec:
  endpointSelector: {}
  # Default-deny ingress: nothing dials into a workspace; the Coder tunnel is
  # outbound from the agent.
  ingress:
    - {}
  # S3 icmp-needs-ingress-rule form:
  # ingress:
  #   - icmps:
  #       - fields: [{type: 3, family: IPv4}]
  egress:
    # DNS for in-cluster names only. External names are resolved by Envoy,
    # never by the workspace, which closes DNS-query exfil.
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: kube-system
            k8s:k8s-app: kube-dns
      toPorts:
        - ports:
            - {port: "53", protocol: UDP}
            - {port: "53", protocol: TCP}
          rules:
            dns:
              - matchPattern: "*.cluster.local"
              - matchPattern: "*.*.cluster.local"
              - matchPattern: "*.*.*.cluster.local"
              - matchPattern: "*.*.*.*.cluster.local"
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: sandcastle-egress
            app: envoy-egress
      toPorts:
        - ports: [{port: "3128", protocol: TCP}]
    # Nexus: package and registry reads only. Admin/REST API and uploads are
    # refused with 403 and logged by Hubble.
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: sandcastle-mirror
            app: nexus
      toPorts:
        - ports: [{port: "8081", protocol: TCP}]
          rules:
            http:
              - {method: GET, path: "/repository/.*"}
              - {method: HEAD, path: "/repository/.*"}
        - ports: [{port: "8082", protocol: TCP}]
          rules:
            http:
              - {method: GET, path: "/v2/.*"}
              - {method: HEAD, path: "/v2/.*"}
    # coderd: Coder agent API paths only, captured from real agent traffic in
    # spike S5. Everything else on this port (login, users, templates) is 403.
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: coder
            app.kubernetes.io/name: coder
      toPorts:
        - ports: [{port: "8080", protocol: TCP}]
          rules:
            http:
              - {method: GET, path: "/bin/coder-linux-amd64"}
              - {method: GET, path: "/api/v2/buildinfo"}
              - {path: "/api/v2/workspaceagents/me/.*"}
              - {path: "/derp.*"}
    # S5 host-30080 form (agent uses the NodePort access URL):
    # - toEntities: [host]
    #   toPorts:
    #     - ports: [{port: "30080", protocol: TCP}]
    #       rules:
    #         http: <same S5 list>
```

- [ ] **Step 2: Write `platform/policy/platform.yaml`**

```yaml
# Policies for the platform pods workspaces are allowed to reach. Each one
# limits who may call it and where it may go, so compromising Envoy, Nexus or
# coderd yields no more reach than the pod legitimately needs.
#
# "Public internet" is 0.0.0.0/0 minus private ranges: a DNS answer that
# points an allowlisted name at the lab network, GAME-01's LAN or an enclave
# must not become a route (DNS rebinding).
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: envoy-egress
  namespace: sandcastle-egress
spec:
  endpointSelector:
    matchLabels: {app: envoy-egress}
  ingress:
    - fromEndpoints:
        - matchLabels: {k8s:io.kubernetes.pod.namespace: sandcastle-workspaces}
      toPorts:
        - ports: [{port: "3128", protocol: TCP}]
  egress:
    - toEndpoints:
        - matchLabels: {k8s:io.kubernetes.pod.namespace: kube-system, k8s:k8s-app: kube-dns}
      toPorts:
        - ports: [{port: "53", protocol: UDP}, {port: "53", protocol: TCP}]
          rules:
            dns: [{matchPattern: "*"}]
    - toCIDRSet:
        - cidr: 0.0.0.0/0
          except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, 127.0.0.0/8]
      toPorts:
        - ports: [{port: "80", protocol: TCP}, {port: "443", protocol: TCP}]
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: nexus
  namespace: sandcastle-mirror
spec:
  endpointSelector:
    matchLabels: {app: nexus}
  # Workspaces only; kubelet probes and kubectl port-forward (configure.sh)
  # arrive from the host, which Cilium allows by default.
  ingress:
    - fromEndpoints:
        - matchLabels: {k8s:io.kubernetes.pod.namespace: sandcastle-workspaces}
      toPorts:
        - ports: [{port: "8081", protocol: TCP}, {port: "8082", protocol: TCP}]
  egress:
    - toEndpoints:
        - matchLabels: {k8s:io.kubernetes.pod.namespace: kube-system, k8s:k8s-app: kube-dns}
      toPorts:
        - ports: [{port: "53", protocol: UDP}, {port: "53", protocol: TCP}]
          rules:
            dns: [{matchPattern: "*"}]
    - toCIDRSet:
        - cidr: 0.0.0.0/0
          except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, 127.0.0.0/8]
      toPorts:
        - ports: [{port: "80", protocol: TCP}, {port: "443", protocol: TCP}]
---
# coderd egress only (ingress stays open: the UI is a NodePort). Postgres,
# the API server for the Terraform provisioner, its own access URL for DERP
# health checks, and public 443 for Terraform provider downloads.
# ponytail: public 443 is broad; a Nexus-backed provider mirror narrows it
# (production delta).
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: coderd-egress
  namespace: coder
spec:
  endpointSelector:
    matchLabels: {app.kubernetes.io/name: coder}
  egress:
    - toEndpoints:
        - matchLabels: {k8s:io.kubernetes.pod.namespace: kube-system, k8s:k8s-app: kube-dns}
      toPorts:
        - ports: [{port: "53", protocol: UDP}, {port: "53", protocol: TCP}]
          rules:
            dns: [{matchPattern: "*"}]
    - toEndpoints:
        - matchLabels: {app: coder-db}
      toPorts:
        - ports: [{port: "5432", protocol: TCP}]
    - toEntities: [kube-apiserver]
      toPorts:
        - ports: [{port: "6443", protocol: TCP}]
    - toEntities: [host]
      toPorts:
        - ports: [{port: "30080", protocol: TCP}]
    - toCIDRSet:
        - cidr: 0.0.0.0/0
          except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, 127.0.0.0/8]
      toPorts:
        - ports: [{port: "443", protocol: TCP}]
```

- [ ] **Step 3: Write `platform/policy/egress-gateway.yaml`**

Skip this file if S1 = `fallback-vm-allowlist`; record the skip in the spike results.

```yaml
# Second enforcement layer, cluster half (DR-3.2): the only pods allowed to
# reach the internet leave the VM from 192.168.130.10 on egress0. The host
# (infra/vm/01-host-egress-nft.sh) forwards only that source, so any other
# pod's traffic, including a workspace packet that slipped Cilium policy,
# exits the primary IP and is dropped and logged. If this policy breaks,
# Envoy/Nexus/coderd traffic also exits the primary IP and is dropped: it
# fails closed.
apiVersion: cilium.io/v2
kind: CiliumEgressGatewayPolicy
metadata:
  name: platform-egress
spec:
  selectors:
    - podSelector:
        matchLabels: {io.kubernetes.pod.namespace: sandcastle-egress, app: envoy-egress}
    - podSelector:
        matchLabels: {io.kubernetes.pod.namespace: sandcastle-mirror, app: nexus}
    - podSelector:
        matchLabels: {io.kubernetes.pod.namespace: coder, app.kubernetes.io/name: coder}
  destinationCIDRs: ["0.0.0.0/0"]
  # In-cluster and lab-network destinations never use the gateway.
  excludedCIDRs: ["10.42.0.0/16", "10.43.0.0/16", "192.168.122.0/24"]
  egressGateway:
    nodeSelector:
      matchLabels: {kubernetes.io/os: linux}
    egressIP: 192.168.130.10
```

- [ ] **Step 4: Server-side dry run**

Run: `VMSYNC && VMSSH 'cd sandcastle && kubectl apply --dry-run=server -f platform/policy/'`
Expected: `ciliumnetworkpolicy... created (server dry run)` for the workspace and coder policies, plus the egress gateway policy. The `sandcastle-egress` namespace may not exist yet (Task 8 creates it). Any **schema** error (unknown field) is a real failure: fix it against `kubectl explain cnp.spec.egress` before committing.

- [ ] **Step 5: Commit**

```bash
git add platform/policy/
git commit -m "feat(policy): add workspace four-destination policy, platform policies and egress gateway"
```

---

### Task 8: Bootstrap script, full run, suite green

**Files:**
- Create: `infra/bootstrap/04-containment.sh`

**Interfaces:**
- Consumes: everything from Tasks 0–7.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# Phase 3: containment core. Egress NIC, Cilium egress gateway, Coder
# block-direct and the Nexus docker proxy (via the Phase 1/2 scripts, which
# are re-runnable), the Envoy egress gate, then network policies.
#
# Runs inside the lab VM (make containment) with the host egress lock OFF:
# helm, image pulls and Nexus configuration need the primary IP. Run
# make egress-lock on the host afterwards. Re-runnable.
set -euo pipefail

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

step() { printf '\n==> %s\n' "$1"; }

step "egress NIC (egress0 192.168.130.10)"
sudo install -m 600 "$REPO_ROOT/infra/bootstrap/netplan-egress.yaml" /etc/netplan/60-sandcastle-egress.yaml
sudo netplan apply
ip -4 addr show egress0 2>/dev/null | grep -q 192.168.130.10 \
  || { echo "egress0 missing: run make vm-egress-net on the host" >&2; exit 1; }

step "cilium: egress gateway, bpf masquerade, icmp deny response"
"$REPO_ROOT/infra/bootstrap/01-k3s-cilium.sh"

step "platform: coder block-direct, nexus docker-hub proxy"
"$REPO_ROOT/infra/bootstrap/03-platform.sh"

step "egress gate"
kubectl apply -f "$REPO_ROOT/platform/egress/envoy.yaml"
kubectl -n sandcastle-egress rollout status deploy/envoy-egress --timeout=5m

step "network policies + egress gateway"
kubectl apply -f "$REPO_ROOT/platform/policy/"

step "done"
echo "next, on the host: make egress-lock && make template && make verify-containment"
```

Run: `bash -n infra/bootstrap/04-containment.sh`. Expected: no output.

- [ ] **Step 2: Run the bootstrap (lock is off)**

Run: `VMSYNC && VMSSH 'cd sandcastle && infra/bootstrap/04-containment.sh' 2>&1 | tail -30`
Expected: every step completes and prints `next, on the host: ...`. On failure, use superpowers:systematic-debugging, fix, re-run, and log the bug and its fix to open-brain (`log_context`, entry_type `bug`, 5 W's).

- [ ] **Step 3: [USER] Lock the host**

Hand to the owner: `sudo -u "$USER" make egress-lock`. Expected: `locked: VM 192.168.122.124 ...`.

- [ ] **Step 4: Run the verify suite**

Run: `VMSSH 'cd sandcastle && CODERD=<per S5> FAST_MS=<per S3> SNI_CHECK=<per S4> infra/tests/03-containment.sh'`
Expected: all `ok`, and `phase 3 passed`. For every FAIL: debug, fix the manifest or script, re-apply (`VMSYNC && VMSSH 'cd sandcastle && kubectl apply -f platform/policy/ -f platform/egress/envoy.yaml'`), and re-run. Never weaken an assertion to make it pass; if an assertion is wrong, say why in the commit message and the spike results.

- [ ] **Step 5: Hard-code the spike knobs as defaults**

Change the three `${VAR:-default}` defaults in `infra/tests/03-containment.sh` to the S3, S4 and S5 values that passed, so `make verify-containment` needs no env.

- [ ] **Step 6: Re-run Phase 1 and Phase 2 verify suites (regressions)**

Run: `VMSSH 'cd sandcastle && infra/tests/01-isolation-substrate.sh; infra/tests/02-dx-baseline.sh'`
Expected: `phase 1 passed`. Phase 2: `phase 2 passed`. If `docker build` in 02 fails because Phase 2's test predates the mirror, fix the test only if the cause is the test's assumption, and note it in the commit.

- [ ] **Step 7: [USER] Host-side verification**

Hand to the owner: `sudo -u "$USER" make verify-host-egress`. Expected: 4 `ok` lines.

- [ ] **Step 8: Commit**

```bash
git add infra/bootstrap/04-containment.sh infra/tests/03-containment.sh
git commit -m "feat(containment): add phase 3 bootstrap and pin verify defaults from spike"
```

---

### Task 9: Documentation, open-brain, release

**Files:**
- Modify: `README.md` (status line; Phase 3 run steps; layout rows for `platform/egress`, `platform/policy`)
- Modify: `docs/superpowers/specs/2026-09-13-phase3-containment-core-design.md` (Status → implemented; link to spike results; any fallback taken)
- Modify: `docs/superpowers/specs/2026-09-13-sandcastle-mvp-design.md` (phase list line 3 → "complete")

- [ ] **Step 1: README**

Set the status line to: `Phases 1–3 complete: isolation substrate, DX baseline, containment core (four-destination egress, Envoy gate, egress gateway + host nftables). Phase 4 (admin control plane) next.`
Add a "Phase 3" block to "Running the lab":
```
sudo -u "$USER" make vm-egress-net          # once
sudo -u "$USER" make egress-unlock          # bootstrap needs the primary IP
sudo -u "$USER" make containment
sudo -u "$USER" make image template
sudo -u "$USER" make egress-lock
sudo -u "$USER" make verify-containment
sudo -u "$USER" make verify-host-egress
```
Add a note: the host lock does not survive a reboot; `verify-containment` fails until `make egress-lock` runs again.

- [ ] **Step 2: Specs**

- Phase 3 spec: `Status: implemented (v0.3.0)`. Under Spike, add `Results: [spike results](2026-09-13-phase3-spike-results.md)`. For any fallback, edit the affected component row and add a dated "Revised" line naming the spike ID.
- MVP spec: in Implementation phases, append ` — complete (v0.3.0)` to item 3.

- [ ] **Step 3: Open-brain**

- `log_context` entry_type `milestone`, status `completed`, title `Phase 3 containment core complete (v0.3.0)`. Content in 5 W's form: Who, When (date plus commit), Where (files), What (verified checks, counted from the suite output), Why, and key findings.
- `log_context` entry_type `note`: residual risks accepted (copy the spec list).
- `end_session` for session `59881305-7b43-4968-90b2-5b41d2d03911` with a summary.

- [ ] **Step 4: Commit, tag, push**

```bash
git add README.md docs/
git commit -m "docs: mark phase 3 containment core complete"
git tag -a v0.3.0 -m "Phase 3: containment core"
git push && git push origin v0.3.0
```

- [ ] **Step 5: [USER] Snapshot**

Hand to the owner: `sudo -u "$USER" infra/vm/sandcastle-vm.sh snapshot phase3-done`.
