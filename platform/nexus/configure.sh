#!/usr/bin/env bash
# Configures a freshly deployed Nexus: rotates the initial admin password,
# enables anonymous read (workspaces pull packages without credentials; there
# is nothing secret in a public-package proxy, and no per-workspace creds
# means none to steal), and creates the apt/PyPI/npm proxy repos.
#
# Runs inside the VM against a port-forwarded Nexus (the caller is expected to
# `kubectl -n sandcastle-mirror port-forward svc/nexus 18081:8081` first).
# Idempotent: safe to re-run.
#
# Payload shapes below are modeled on Nexus's documented repository-create API
# shape, not fetched live (the Sonatype docs page is not scriptable). Verify
# against the running server's own schema on first run: GET
# ${NEXUS_URL}/service/rest/swagger.json. Every curl uses --fail-with-body so
# a schema mismatch surfaces the server's error instead of a bare curl exit code.
set -euo pipefail

NEXUS_URL="${NEXUS_URL:-http://127.0.0.1:18081}"
NS=sandcastle-mirror

step() { printf '\n==> %s\n' "$1"; }

step "waiting for nexus (max 10m)"
for ((i = 0; i < 120; i++)); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$NEXUS_URL/service/rest/v1/status" || true)
  [[ "$code" == "200" ]] && break
  sleep 5
done
if [[ "$code" != "200" ]]; then
  echo "  FAIL  nexus never reported healthy at $NEXUS_URL/service/rest/v1/status"
  exit 1
fi

step "admin password"
if kubectl -n "$NS" get secret nexus-admin >/dev/null 2>&1; then
  ADMIN_PW=$(kubectl -n "$NS" get secret nexus-admin -o jsonpath='{.data.password}' | base64 -d)
else
  INITIAL_PW=$(kubectl -n "$NS" exec nexus-0 -- cat /nexus-data/admin.password)
  ADMIN_PW=$(openssl rand -base64 24 | tr -d '/+=')
  curl -fsS --fail-with-body -u "admin:$INITIAL_PW" \
    -X PUT -H 'Content-Type: text/plain' \
    --data "$ADMIN_PW" \
    "$NEXUS_URL/service/rest/v1/security/users/admin/change-password"
  kubectl -n "$NS" create secret generic nexus-admin --from-literal=password="$ADMIN_PW"
fi

step "community edition EULA"
# Since 3.77 Community Edition answers every repository request with 403 until
# its EULA is accepted; health and admin endpoints keep working, so a server
# that looks healthy still serves nothing. Acceptance was approved by the
# repository owner on 2026-09-13 (terms:
# https://links.sonatype.com/products/nxrm/ce-eula). The API requires the
# server's own disclaimer text echoed back with accepted=true.
eula=$(curl -fsS --fail-with-body -u "admin:$ADMIN_PW" "$NEXUS_URL/service/rest/v1/system/eula")
if grep -q '"accepted" *: *true' <<<"$eula"; then
  echo "  skip  EULA already accepted"
else
  python3 -c 'import json,sys; d=json.load(sys.stdin); d["accepted"]=True; print(json.dumps(d))' <<<"$eula" \
    | curl -fsS --fail-with-body -u "admin:$ADMIN_PW" -X POST -H 'Content-Type: application/json' \
        --data-binary @- "$NEXUS_URL/service/rest/v1/system/eula"
  echo "  ok    EULA accepted"
fi

step "anonymous read"
curl -fsS --fail-with-body -u "admin:$ADMIN_PW" \
  -X PUT -H 'Content-Type: application/json' \
  -d '{"enabled":true,"userId":"anonymous","realmName":"NexusAuthorizingRealm"}' \
  "$NEXUS_URL/service/rest/v1/security/anonymous"

create_repo() {
  local name="$1" endpoint="$2" payload="$3"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -u "admin:$ADMIN_PW" "$NEXUS_URL/service/rest/v1/repositories/$name")
  if [[ "$code" == "200" ]]; then
    echo "  skip  $name already exists"
    return
  fi
  curl -fsS --fail-with-body -u "admin:$ADMIN_PW" \
    -X POST -H 'Content-Type: application/json' \
    -d "$payload" \
    "$NEXUS_URL/service/rest/v1/repositories/$endpoint"
  echo "  ok    $name created"
}

step "apt-ubuntu proxy"
create_repo "apt-ubuntu" "apt/proxy" '{
  "name": "apt-ubuntu",
  "online": true,
  "storage": {"blobStoreName": "default", "strictContentTypeValidation": true},
  "proxy": {"remoteUrl": "http://archive.ubuntu.com/ubuntu/", "contentMaxAge": 1440, "metadataMaxAge": 1440},
  "negativeCache": {"enabled": true, "timeToLive": 1440},
  "httpClient": {"blocked": false, "autoBlock": true},
  "apt": {"distribution": "resolute", "flat": false}
}'

step "pypi-proxy"
create_repo "pypi-proxy" "pypi/proxy" '{
  "name": "pypi-proxy",
  "online": true,
  "storage": {"blobStoreName": "default", "strictContentTypeValidation": true},
  "proxy": {"remoteUrl": "https://pypi.org/", "contentMaxAge": 1440, "metadataMaxAge": 1440},
  "negativeCache": {"enabled": true, "timeToLive": 1440},
  "httpClient": {"blocked": false, "autoBlock": true}
}'

step "npm-proxy"
create_repo "npm-proxy" "npm/proxy" '{
  "name": "npm-proxy",
  "online": true,
  "storage": {"blobStoreName": "default", "strictContentTypeValidation": true},
  "proxy": {"remoteUrl": "https://registry.npmjs.org/", "contentMaxAge": 1440, "metadataMaxAge": 1440},
  "negativeCache": {"enabled": true, "timeToLive": 1440},
  "httpClient": {"blocked": false, "autoBlock": true}
}'

step "done"
echo "apt:  $NEXUS_URL/repository/apt-ubuntu/"
echo "pypi: $NEXUS_URL/repository/pypi-proxy/"
echo "npm:  $NEXUS_URL/repository/npm-proxy/"
