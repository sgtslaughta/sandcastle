#!/usr/bin/env bash
# Phase 2: platform namespaces + workspace admission policy, Coder, and the
# Nexus mirror.
#
# Runs inside the lab VM (make platform), after 01-k3s-cilium.sh and
# 02-kata-gvisor.sh. Needs no sudo of its own; kubectl/helm access is already
# user-level from the earlier steps. Re-runnable.
set -euo pipefail

CODER_VERSION="${CODER_VERSION:-2.36.5}"
NODE_IP="${NODE_IP:-$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')}"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLATFORM_DIR="$REPO_ROOT/platform"

step() { printf '\n==> %s\n' "$1"; }

step "namespaces + workspace admission policy"
kubectl apply -f "$PLATFORM_DIR/namespaces.yaml"
kubectl apply -f "$PLATFORM_DIR/admission/workspace-policy.yaml"

step "coder-db credentials"
# Generated once and never rotated by re-runs: rotating would orphan the
# existing database, which has its own password baked into its data volume.
if kubectl -n coder get secret coder-db >/dev/null 2>&1; then
  echo "secret coder/coder-db already exists"
else
  DB_PW=$(openssl rand -base64 24 | tr -d '/+=')
  kubectl -n coder create secret generic coder-db --from-literal=password="$DB_PW"
  kubectl -n coder create secret generic coder-db-url \
    --from-literal=url="postgres://coder:${DB_PW}@coder-db.coder.svc.cluster.local:5432/coder?sslmode=disable"
fi

step "coder-db"
kubectl apply -f "$PLATFORM_DIR/coder/postgres.yaml"
kubectl -n coder rollout status statefulset/coder-db --timeout=5m

step "coder ${CODER_VERSION}"
helm repo add coder-v2 https://helm.coder.com/v2 >/dev/null
helm repo update coder-v2 >/dev/null
# values.yaml carries CODER_ACCESS_URL as the placeholder __CODER_ACCESS_URL__:
# the real value depends on NODE_IP, which is only known here at bootstrap
# time, and there is no yq on the box to patch a single env list entry
# cleanly, so the placeholder is substituted into a temp copy instead.
values_rendered=$(mktemp)
trap 'rm -f "$values_rendered"' EXIT
sed "s#__CODER_ACCESS_URL__#http://${NODE_IP}:30080#" "$PLATFORM_DIR/coder/values.yaml" > "$values_rendered"
helm upgrade --install coder coder-v2/coder --version "$CODER_VERSION" \
  -n coder -f "$values_rendered" \
  --wait --timeout 10m

step "workspace RBAC"
kubectl apply -f "$PLATFORM_DIR/coder/workspace-rbac.yaml"

step "nexus mirror"
kubectl apply -f "$PLATFORM_DIR/nexus/nexus.yaml"
kubectl -n sandcastle-mirror rollout status statefulset/nexus --timeout=15m

# A port-forward left by an interrupted run keeps 18081 bound to a pod that
# may no longer exist; the new one then fails to bind and configure.sh polls
# the dead tunnel until it times out.
pkill -f 'port-forward svc/nexus 18081:8081' 2>/dev/null || true
kubectl -n sandcastle-mirror port-forward svc/nexus 18081:8081 >/tmp/nexus-port-forward.log 2>&1 &
pf_pid=$!
trap 'kill "$pf_pid" 2>/dev/null || true; rm -f "$values_rendered"' EXIT
# Give the port-forward a moment to establish before configure.sh polls it.
sleep 3
"$PLATFORM_DIR/nexus/configure.sh"
kill "$pf_pid" 2>/dev/null || true

step "coder first user"
mkdir -p "$HOME/.local/bin"
curl -fsSLo "$HOME/.local/bin/coder" "http://${NODE_IP}:30080/bin/coder-linux-amd64"
chmod +x "$HOME/.local/bin/coder"
export PATH="$HOME/.local/bin:$PATH"

if kubectl -n coder get secret coder-admin >/dev/null 2>&1; then
  echo "Coder admin already provisioned. Retrieve the password with:"
  echo "  kubectl -n coder get secret coder-admin -o jsonpath='{.data.password}' | base64 -d"
else
  ADMIN_PW=$(openssl rand -base64 24 | tr -d '/+=')
  coder login "http://${NODE_IP}:30080" \
    --first-user-username admin \
    --first-user-email admin@sandcastle.local \
    --first-user-password "$ADMIN_PW" \
    --first-user-full-name "Sandcastle Admin" \
    --first-user-trial=false
  kubectl -n coder create secret generic coder-admin --from-literal=password="$ADMIN_PW"
  echo "Coder admin password: $ADMIN_PW (stored in secret coder/coder-admin)"
fi

step "done"
echo "Coder URL: http://${NODE_IP}:30080"
