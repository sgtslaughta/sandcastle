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
