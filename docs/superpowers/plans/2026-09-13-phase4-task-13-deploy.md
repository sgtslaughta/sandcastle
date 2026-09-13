# Phase 4 Build — Task 13: Deploy — manifests, Envoy on xDS, bootstrap script

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Plan index, Global Constraints and File Map:** [2026-09-13-phase4-build.md](2026-09-13-phase4-build.md). The Global Constraints apply to this task.

### Task 13: Deploy — manifests, Envoy on xDS, bootstrap script

**Files:**
- Create: `platform/admin/admin.yaml` (namespace, admin-db, Deployment, Services)
- Create: `platform/admin/rbac.yaml`
- Create: `platform/policy/admin.yaml` (CNPs for admin and admin-db)
- Modify: `platform/policy/platform.yaml` (Envoy → admin :18000)
- Modify: `platform/egress/envoy.yaml` (bootstrap-only ConfigMap, drain args, config-rev 3)
- Modify: `platform/coder/values.yaml` (`CODER_EXPERIMENTS=oauth2`)
- Delete: `platform/policy/workspace-dns-allow.yaml`
- Create: `infra/bootstrap/05-admin.sh`
- Modify: `Makefile` (`admin-image`, `admin`, `verify-admin`; `policy` help text)

**Interfaces:**
- Consumes: image `sandcastle/admin:0.4.0` (Task 12); env contract (Task 12); Envoy node ID `sandcastle-egress` and cluster name `admin` (Task 5).
- Produces (used by Task 14):
  - Secret `sandcastle-admin/admin-test-token` key `token` (present when `TEST_HOOKS=1`, the lab default)
  - Secret `sandcastle-admin/admin-db` keys `owner-password`, `app-password`, `owner-dsn`, `app-dsn`
  - Postgres database `admin` in `statefulset/admin-db`
  - UI at `http://<node>:30081`

- [ ] **Step 1: Coder OAuth2 experiment** — `platform/coder/values.yaml`

Add to `coder.env`, after `CODER_BLOCK_DIRECT`:
```yaml
    # OAuth2 provider: sandcastle-admin logs users in through Coder
    # (Phase 4 DR-4.1; works on OSS 2.36.5 per spike S1).
    - name: CODER_EXPERIMENTS
      value: "oauth2"
```

- [ ] **Step 2: Envoy bootstrap-only** — `platform/egress/envoy.yaml`

Replace the header comment (lines 1–11) with:
```yaml
# Egress gate. Explicit proxy: workspaces set HTTP(S)_PROXY, and any other
# path is dropped by platform/policy/workspaces.yaml.
#
# All listeners, routes and clusters come from sandcastle-admin over ADS
# (Phase 4 DR-4.8): per-host virtual hosts allow only the pod IPs granted
# that host, and per-host SNI listeners bind TLS to the CONNECT host. With no
# admin, a freshly started Envoy has no listener and serves nothing (fail
# closed, DR-4.6); a running one keeps its last snapshot. Access logs go to
# stdout (Hubble/Phase 6) and to admin over ALS (denial queue).
```

Replace the whole `data.envoy.yaml` block of the ConfigMap with:
```yaml
  envoy.yaml: |
    node: {id: sandcastle-egress, cluster: sandcastle-egress}
    bootstrap_extensions:
      - name: envoy.bootstrap.internal_listener
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.bootstrap.internal_listener.v3.InternalListener
    admin:
      address: {socket_address: {address: 127.0.0.1, port_value: 9901}}
    dynamic_resources:
      ads_config:
        api_type: GRPC
        transport_api_version: V3
        grpc_services: [{envoy_grpc: {cluster_name: admin}}]
      lds_config: {ads: {}, resource_api_version: V3}
      cds_config: {ads: {}, resource_api_version: V3}
    static_resources:
      clusters:
        # ADS and ALS share this cluster. ponytail: plaintext in-cluster; only
        # this pod may reach admin :18000 (platform/policy/admin.yaml).
        - name: admin
          type: STRICT_DNS
          dns_lookup_family: V4_ONLY
          connect_timeout: 2s
          typed_extension_protocol_options:
            envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
              "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
              explicit_http_config: {http2_protocol_options: {}}
          load_assignment:
            cluster_name: admin
            endpoints:
              - lb_endpoints:
                  - endpoint:
                      address:
                        socket_address: {address: sandcastle-admin.sandcastle-admin.svc.cluster.local, port_value: 18000}
```

In the Deployment:
- Set `sandcastle.io/config-rev: "3"`.
- Replace the args line and its comment with:
```yaml
          # Access logs are the denial evidence; Envoy flushes them every 10s
          # by default, 1s keeps "seen within seconds" true. Drain 5s,
          # immediate: a revoked host's listener closes its open tunnels
          # within seconds (spike S3).
          args: ["-c", "/etc/envoy/envoy.yaml", "--log-level", "warn", "--file-flush-interval-msec", "1000",
                 "--drain-time-s", "5", "--drain-strategy", "immediate"]
```

- [ ] **Step 3: Admin manifests** — `platform/admin/admin.yaml`

```yaml
# sandcastle-admin (Phase 4 spec): its own Postgres (DR-4.7), the admin
# Deployment, ClusterIP :18000 for Envoy xDS + ALS, NodePort 30081 for the UI.
# Secrets are generated by infra/bootstrap/05-admin.sh, never committed.
# __CODER_URL__ and __PUBLIC_URL__ are substituted by that script.
apiVersion: v1
kind: Namespace
metadata:
  name: sandcastle-admin
---
apiVersion: v1
kind: Service
metadata:
  name: admin-db
  namespace: sandcastle-admin
spec:
  selector: {app: admin-db}
  ports:
    - {name: postgres, port: 5432, targetPort: 5432}
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: admin-db
  namespace: sandcastle-admin
spec:
  serviceName: admin-db
  replicas: 1
  selector:
    matchLabels: {app: admin-db}
  template:
    metadata:
      labels: {app: admin-db}
    spec:
      automountServiceAccountToken: false
      containers:
        - name: postgres
          image: postgres:17.6
          ports: [{containerPort: 5432}]
          env:
            - {name: POSTGRES_USER, value: postgres}
            - {name: POSTGRES_DB, value: admin}
            - name: POSTGRES_PASSWORD
              valueFrom: {secretKeyRef: {name: admin-db, key: owner-password}}
            - {name: PGDATA, value: /var/lib/postgresql/data/pgdata}
          volumeMounts:
            - {name: data, mountPath: /var/lib/postgresql/data}
          readinessProbe:
            exec: {command: ["pg_isready", "-U", "postgres"]}
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            requests: {cpu: 50m, memory: 128Mi}
            limits: {memory: 512Mi}
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: local-path
        resources:
          requests: {storage: 2Gi}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sandcastle-admin
  namespace: sandcastle-admin
spec:
  # ponytail: one replica; the rebuild loop and denial throttle assume a
  # single writer. HA needs leader election (multi-node).
  replicas: 1
  strategy: {type: Recreate}
  selector:
    matchLabels: {app: sandcastle-admin}
  template:
    metadata:
      labels: {app: sandcastle-admin}
    spec:
      serviceAccountName: sandcastle-admin
      containers:
        - name: admin
          image: sandcastle/admin:0.4.0
          imagePullPolicy: Never # imported by make admin-image
          ports:
            - {name: http, containerPort: 8080}
            - {name: xds, containerPort: 18000}
          env:
            - name: DB_OWNER_DSN
              valueFrom: {secretKeyRef: {name: admin-db, key: owner-dsn}}
            - name: DB_APP_DSN
              valueFrom: {secretKeyRef: {name: admin-db, key: app-dsn}}
            - name: DB_APP_PASSWORD
              valueFrom: {secretKeyRef: {name: admin-db, key: app-password}}
            - name: OAUTH_CLIENT_ID
              valueFrom: {secretKeyRef: {name: admin-oauth, key: client-id}}
            - name: OAUTH_CLIENT_SECRET
              valueFrom: {secretKeyRef: {name: admin-oauth, key: client-secret}}
            - name: SESSION_KEY
              valueFrom: {secretKeyRef: {name: admin-session, key: key}}
            # Test hook (lab only): absent secret disables it.
            - name: TEST_TOKEN
              valueFrom: {secretKeyRef: {name: admin-test-token, key: token, optional: true}}
            - {name: CODER_URL, value: "__CODER_URL__"}
            - {name: PUBLIC_URL, value: "__PUBLIC_URL__"}
            - {name: CODER_INTERNAL_URL, value: "http://coder.coder.svc.cluster.local"}
          readinessProbe:
            httpGet: {path: /healthz, port: http}
            periodSeconds: 5
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532 # distroless nonroot; numeric so kubelet can verify
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          resources:
            requests: {cpu: 50m, memory: 64Mi}
            limits: {memory: 256Mi}
---
apiVersion: v1
kind: Service
metadata:
  name: sandcastle-admin
  namespace: sandcastle-admin
spec:
  selector: {app: sandcastle-admin}
  ports:
    - {name: xds, port: 18000, targetPort: 18000}
---
apiVersion: v1
kind: Service
metadata:
  name: sandcastle-admin-ui
  namespace: sandcastle-admin
spec:
  type: NodePort
  selector: {app: sandcastle-admin}
  ports:
    - {name: http, port: 80, targetPort: 8080, nodePort: 30081}
```

- [ ] **Step 4: RBAC** — `platform/admin/rbac.yaml`

```yaml
# sandcastle-admin reads workspace pods (IP identity) and owns the DNS allow
# CiliumNetworkPolicies, in the workspace namespace only. No secrets, no
# other namespaces.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sandcastle-admin
  namespace: sandcastle-admin
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: sandcastle-admin
  namespace: sandcastle-workspaces
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list, watch]
  - apiGroups: [cilium.io]
    resources: [ciliumnetworkpolicies]
    verbs: [get, list, watch, create, update, delete]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sandcastle-admin
  namespace: sandcastle-workspaces
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: sandcastle-admin
subjects:
  - kind: ServiceAccount
    name: sandcastle-admin
    namespace: sandcastle-admin
```

- [ ] **Step 5: Policies** — `platform/policy/admin.yaml`, `platform/policy/platform.yaml`

`platform/policy/admin.yaml`:
```yaml
# sandcastle-admin decides all workspace egress, so it is the highest-value
# target. Workspaces cannot reach it (workspace-egress denies everything not
# listed), only Envoy may reach xDS/ALS, and the UI answers only clients
# from outside the cluster (lab network) and kubelet probes.
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: sandcastle-admin
  namespace: sandcastle-admin
spec:
  endpointSelector:
    matchLabels: {app: sandcastle-admin}
  ingress:
    - fromEndpoints:
        - matchLabels: {k8s:io.kubernetes.pod.namespace: sandcastle-egress, app: envoy-egress}
      toPorts:
        - ports: [{port: "18000", protocol: TCP}]
    - fromEntities: [world, host, remote-node]
      toPorts:
        - ports: [{port: "8080", protocol: TCP}]
  egress:
    - toEndpoints:
        - matchLabels: {k8s:io.kubernetes.pod.namespace: kube-system, k8s:k8s-app: kube-dns}
      toPorts:
        - ports: [{port: "53", protocol: UDP}, {port: "53", protocol: TCP}]
          rules:
            dns: [{matchPattern: "**.cluster.local"}]
    - toEndpoints:
        - matchLabels: {app: admin-db}
      toPorts:
        - ports: [{port: "5432", protocol: TCP}]
    # OAuth2 token exchange and users/me.
    - toEndpoints:
        - matchLabels: {k8s:io.kubernetes.pod.namespace: coder, app.kubernetes.io/name: coder}
      toPorts:
        - ports: [{port: "8080", protocol: TCP}]
    - toEntities: [kube-apiserver]
      toPorts:
        - ports: [{port: "6443", protocol: TCP}]
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: admin-db
  namespace: sandcastle-admin
spec:
  endpointSelector:
    matchLabels: {app: admin-db}
  ingress:
    - fromEndpoints:
        - matchLabels: {app: sandcastle-admin}
      toPorts:
        - ports: [{port: "5432", protocol: TCP}]
  egress:
    - {} # default deny: the database dials nothing
```

In `platform/policy/platform.yaml`, `envoy-egress` CNP, add to `egress:` after the DNS rule:
```yaml
    # xDS config and access logs from/to sandcastle-admin (Phase 4).
    - toEndpoints:
        - matchLabels: {k8s:io.kubernetes.pod.namespace: sandcastle-admin, app: sandcastle-admin}
      toPorts:
        - ports: [{port: "18000", protocol: TCP}]
```

Delete `platform/policy/workspace-dns-allow.yaml` (zones replace it; the seeded default zone has no DNS rules, the same as its placeholder).

- [ ] **Step 6: Bootstrap** — `infra/bootstrap/05-admin.sh`

```bash
#!/usr/bin/env bash
# Phase 4: sandcastle-admin. Coder OAuth2 experiment (via 03-platform.sh),
# admin secrets and OAuth2 app registration, policies, the admin Postgres and
# Deployment, then Envoy switched to xDS.
#
# Runs inside the lab VM (make admin) after make admin-image on the host,
# with the host egress lock OFF (helm in 03-platform.sh). Re-runnable:
# secrets and the OAuth2 app are created once. TEST_HOOKS=1 (default)
# creates the bearer token infra/tests/04-admin.sh uses; TEST_HOOKS=0
# removes it.
set -euo pipefail

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE_IP="${NODE_IP:-$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')}"
CODER="$HOME/.local/bin/coder"
CODER_URL="http://${NODE_IP}:30080"
PUBLIC_URL="http://${NODE_IP}:30081"
TEST_HOOKS="${TEST_HOOKS:-1}"
NS=sandcastle-admin

step() { printf '\n==> %s\n' "$1"; }
missing() { ! kubectl -n "$NS" get secret "$1" >/dev/null 2>&1; }
json() { python3 -c "import json,sys; print(json.load(sys.stdin)[\"$1\"])"; }

step "coder: oauth2 provider experiment"
"$REPO_ROOT/infra/bootstrap/03-platform.sh"
TOKEN=$("$CODER" tokens create --lifetime 1h --name "sandcastle-admin-bootstrap-$(date +%s)")
H=(-H "Coder-Session-Token: $TOKEN" -H 'Content-Type: application/json')
curl -fsS "${H[@]}" "$CODER_URL/api/v2/experiments" | grep oauth2 >/dev/null \
  || { echo "coder oauth2 experiment is not enabled" >&2; exit 1; }

step "namespace + secrets"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
# Secrets go through stdin, never argv, so they do not show in ps.
if missing admin-db; then
  owner_pw=$(openssl rand -hex 24); app_pw=$(openssl rand -hex 24)
  kubectl -n "$NS" create secret generic admin-db --from-env-file=/dev/stdin <<EOF
owner-password=$owner_pw
app-password=$app_pw
owner-dsn=postgres://postgres:$owner_pw@admin-db.$NS.svc.cluster.local:5432/admin?sslmode=disable
app-dsn=postgres://sandcastle_app:$app_pw@admin-db.$NS.svc.cluster.local:5432/admin?sslmode=disable
EOF
fi
if missing admin-session; then
  kubectl -n "$NS" create secret generic admin-session --from-env-file=/dev/stdin <<EOF
key=$(openssl rand -hex 32)
EOF
fi
if [[ "$TEST_HOOKS" == 1 ]]; then
  if missing admin-test-token; then
    kubectl -n "$NS" create secret generic admin-test-token --from-env-file=/dev/stdin <<EOF
token=$(openssl rand -hex 32)
EOF
  fi
else
  kubectl -n "$NS" delete secret admin-test-token --ignore-not-found
fi

step "coder oauth2 app"
if missing admin-oauth; then
  # A re-run after deleting this secret fails here while the app still
  # exists in Coder; delete the sandcastle-admin app in Coder first.
  app=$(curl -fsS "${H[@]}" -X POST "$CODER_URL/api/v2/oauth2-provider/apps" \
    -d "{\"name\":\"sandcastle-admin\",\"callback_url\":\"$PUBLIC_URL/callback\",\"icon\":\"\"}")
  app_id=$(json id <<<"$app")
  client_secret=$(curl -fsS "${H[@]}" -X POST "$CODER_URL/api/v2/oauth2-provider/apps/$app_id/secrets" | json client_secret_full)
  kubectl -n "$NS" create secret generic admin-oauth --from-env-file=/dev/stdin <<EOF
client-id=$app_id
client-secret=$client_secret
EOF
fi

step "policies"
kubectl apply -f "$REPO_ROOT/platform/policy/"
kubectl -n sandcastle-workspaces delete cnp workspace-dns-allow --ignore-not-found

step "admin postgres + deployment"
kubectl apply -f "$REPO_ROOT/platform/admin/rbac.yaml"
sed -e "s#__CODER_URL__#$CODER_URL#" -e "s#__PUBLIC_URL__#$PUBLIC_URL#" "$REPO_ROOT/platform/admin/admin.yaml" | kubectl apply -f -
kubectl -n "$NS" rollout status statefulset/admin-db --timeout=5m
kubectl -n "$NS" rollout restart deploy/sandcastle-admin # picks up a re-imported image with the same tag
kubectl -n "$NS" rollout status deploy/sandcastle-admin --timeout=5m

step "envoy: config from sandcastle-admin"
kubectl apply -f "$REPO_ROOT/platform/egress/envoy.yaml"
kubectl -n sandcastle-egress rollout status deploy/envoy-egress --timeout=5m

step "done"
echo "UI: $PUBLIC_URL  (log in with a Coder account; Coder owners are admins)"
echo "next, on the host: make egress-lock && make verify-admin"
```

- [ ] **Step 7: Makefile**

Change the `policy` help text to:
```make
policy:     ## re-apply static network policies (DNS allow rules now live in sandcastle-admin zones)
```
Append:
```make
# Phase 4
admin-image: ## build sandcastle-admin on the host and import it into the VM
	docker build -t sandcastle/admin:0.4.0 admin
	docker save sandcastle/admin:0.4.0 | $(VM) ssh 'sudo k3s ctr -n k8s.io images import -'

admin:      ## coder oauth2, admin postgres + deployment, envoy on xds (run egress-unlock first)
	@$(VM) snapshot pre-admin
	@$(VM) run infra/bootstrap/05-admin.sh

verify-admin: ## zones, requests, grants, revocation, expiry and fail-closed, end to end
	@$(VM) run infra/tests/04-admin.sh
```

- [ ] **Step 8: Static checks**

Run:
```bash
chmod +x infra/bootstrap/05-admin.sh
bash -n infra/bootstrap/05-admin.sh
for f in platform/admin/*.yaml platform/policy/admin.yaml platform/egress/envoy.yaml platform/policy/platform.yaml; do
  python3 -c 'import sys,yaml; list(yaml.safe_load_all(open(sys.argv[1])))' "$f" && echo "yaml ok $f"
done
python3 -c 'import yaml; c=[d for d in yaml.safe_load_all(open("platform/egress/envoy.yaml")) if d["kind"]=="ConfigMap"][0]; yaml.safe_load(c["data"]["envoy.yaml"]); print("bootstrap ok")'
```
Expected: no bash syntax errors; `yaml ok` for each file; `bootstrap ok`.

- [ ] **Step 9: Commit**

```bash
git add platform/admin platform/policy platform/egress/envoy.yaml platform/coder/values.yaml infra/bootstrap/05-admin.sh Makefile
git rm platform/policy/workspace-dns-allow.yaml
git commit -m "feat(admin): deploy sandcastle-admin and switch envoy to xds"
```

- [ ] **Step 10: Deploy (OWNER + executor)**

1. **OWNER** (host): `sudo -u "$USER" make egress-unlock`
2. Executor (host): `make admin-image`
3. **OWNER** (host): `sudo -u "$USER" make admin`. It snapshots `pre-admin` (libvirt), then runs `05-admin.sh`.
4. **OWNER** (host): `sudo -u "$USER" make egress-lock`

Executor then checks through `$P/vmssh`:
```bash
$P/vmssh 'kubectl -n sandcastle-admin get pods; kubectl -n sandcastle-egress get pods; kubectl -n sandcastle-egress logs deploy/envoy-egress --since=5m | grep -iE "rejected|NACK|error" | head -5; kubectl -n sandcastle-admin logs deploy/sandcastle-admin --since=5m | tail -5'
```
Expected: admin-db and sandcastle-admin `1/1 Running`; envoy-egress `1/1 Running` (ready means it received listeners over xDS); no rejected/NACK lines.
