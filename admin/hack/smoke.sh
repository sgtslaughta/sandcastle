#!/usr/bin/env bash
# Real Envoy v1.39.1 against Build's output: allowed IP gets 200, other IP
# gets 403 with header and request link, and the denial reaches ALS.
# Throwaway containers on a private network; host needs docker + internet.
set -euo pipefail
cd "$(dirname "$0")/.."
NET=sc-smoke; CACHE="$HOME/.cache/sandcastle-go"; mkdir -p "$CACHE"
fail=0; ok() { echo "  ok    $1"; }; bad() { echo "  FAIL  $1"; fail=1; }
cleanup() { docker rm -f sc-smoke-admin sc-smoke-envoy sc-smoke-a sc-smoke-b >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker network create --subnet 172.31.0.0/24 $NET >/dev/null

docker run -d --name sc-smoke-admin --network $NET --ip 172.31.0.20 -u "$(id -u):$(id -g)" \
  -e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod -e ALLOW_IP=172.31.0.11 \
  -v "$CACHE:/cache" -v "$PWD:/src" -w /src golang:1.27 go run ./hack/smoke >/dev/null
for c in a:11 b:12; do
  docker run -d --name sc-smoke-${c%%:*} --network $NET --ip 172.31.0.${c##*:} alpine:3 sleep infinity >/dev/null
  docker exec sc-smoke-${c%%:*} apk add --no-cache curl >/dev/null
done
for _ in $(seq 60); do docker logs sc-smoke-admin 2>&1 | grep 'xds ready' >/dev/null && break; sleep 3; done
docker run -d --name sc-smoke-envoy --network $NET --ip 172.31.0.10 -v "$PWD/hack/smoke:/etc/envoy:ro" \
  envoyproxy/envoy:v1.39.1 -c /etc/envoy/bootstrap.yaml --drain-time-s 5 --drain-strategy immediate >/dev/null

px=http://172.31.0.10:3128
code=000
for _ in $(seq 30); do
  code=$(docker exec sc-smoke-a curl -s -o /dev/null -w '%{http_code}' -m 10 -x $px https://example.com || true)
  [[ "$code" == 200 ]] && break; sleep 2
done
[[ "$code" == 200 ]] && ok "allowed IP reaches example.com (200)" || bad "allowed IP got '$code'"

out=$(docker exec sc-smoke-b curl -si -m 10 -x $px http://example.com || true)
echo "$out" | grep -i '^x-sandcastle-denied: host=example.com; source=172.31.0.12' >/dev/null && ok "other IP denied with header" || bad "other IP: no denial header"
echo "$out" | grep 'Request access: http://admin.invalid/r?src=172.31.0.12&host=example.com' >/dev/null && ok "403 body carries request link" || bad "403 body missing request link"
code=$(docker exec sc-smoke-b curl -s -o /dev/null -w '%{http_code}' -m 10 -x $px https://example.com || true)
[[ "$code" == 000 || "$code" == 403 ]] && ok "other IP CONNECT refused" || bad "other IP CONNECT got '$code'"

sleep 2
docker logs sc-smoke-admin 2>&1 | grep 'DENIAL src=172.31.0.12 host=example.com' >/dev/null && ok "ALS delivered denial" || bad "ALS denial not received"
docker logs sc-smoke-envoy 2>&1 | grep -iE 'rejected|NACK' >/dev/null && bad "envoy rejected config: $(docker logs sc-smoke-envoy 2>&1 | grep -iE 'rejected|NACK' | head -2)" || ok "envoy accepted all xDS resources"

(( fail == 0 )) && echo "smoke passed" || { echo "smoke FAILED"; exit 1; }
