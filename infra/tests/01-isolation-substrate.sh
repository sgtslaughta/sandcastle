#!/usr/bin/env bash
# Phase 1 verify: the isolation substrate is real.
#
# The claim under test is not "a pod started" but "the workspace is running on a
# kernel that is not the host's". A Kata pod that silently fell back to runc
# would pass every liveness check and provide no isolation at all, so the kernel
# comparison below is the actual assertion.
set -uo pipefail

NS=sandcastle-verify
KUBECTL=${KUBECTL:-kubectl}
fail=0
pass() { printf '  ok    %s\n' "$1"; }
warn() { printf '  warn  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }

cleanup() { $KUBECTL delete ns "$NS" --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "Sandcastle phase 1 verify: isolation substrate"

$KUBECTL get nodes >/dev/null 2>&1 || { echo "  FAIL  cannot reach cluster"; exit 1; }
pass "cluster reachable"

# Cilium must be the CNI and must have replaced kube-proxy: the no-default-route
# policy in phase 3 is expressed as CiliumNetworkPolicy, and a surviving
# kube-proxy would leave service traffic outside Cilium's enforcement path.
if $KUBECTL -n kube-system get ds cilium >/dev/null 2>&1; then
  ready=$($KUBECTL -n kube-system get ds cilium -o jsonpath='{.status.numberReady}')
  want=$($KUBECTL -n kube-system get ds cilium -o jsonpath='{.status.desiredNumberScheduled}')
  [[ "$ready" == "$want" && "$ready" != "0" ]] && pass "cilium ready ($ready/$want)" || bad "cilium not ready ($ready/$want)"
else
  bad "cilium DaemonSet absent"
fi
$KUBECTL -n kube-system get ds kube-proxy >/dev/null 2>&1 && bad "kube-proxy still present — kubeProxyReplacement not in effect" || pass "no kube-proxy (replaced by cilium)"
$KUBECTL get crd ciliumnetworkpolicies.cilium.io >/dev/null 2>&1 && pass "CiliumNetworkPolicy CRD present" || bad "CiliumNetworkPolicy CRD absent"

for rc in kata-clh-runtime-rs gvisor; do
  $KUBECTL get runtimeclass "$rc" >/dev/null 2>&1 && pass "RuntimeClass $rc" || bad "RuntimeClass $rc absent"
done
# Any other RuntimeClass is an unreviewed way to run a pod outside Kata.
extra=$($KUBECTL get runtimeclass -o name 2>/dev/null | sed 's|.*/||' | grep -vxE 'kata-clh-runtime-rs|gvisor' | tr '\n' ' ')
[[ -z "$extra" ]] && pass "no unexpected RuntimeClasses" || bad "unexpected RuntimeClasses: $extra(k3s --disable=runtimes missing?)"

$KUBECTL create ns "$NS" >/dev/null 2>&1 || true

host_kernel=$(uname -r)
boot_pod() { # name runtimeclass
  $KUBECTL -n "$NS" run "$1" --restart=Never --image=busybox:1.36 \
    --overrides="{\"spec\":{\"runtimeClassName\":\"$2\"}}" \
    --command -- sh -c 'uname -r; sleep 10' >/dev/null 2>&1
  $KUBECTL -n "$NS" wait --for=condition=Ready "pod/$1" --timeout=180s >/dev/null 2>&1
}

if boot_pod kata-probe kata-clh-runtime-rs; then
  guest_kernel=$($KUBECTL -n "$NS" logs kata-probe 2>/dev/null | head -1)
  if [[ -n "$guest_kernel" && "$guest_kernel" != "$host_kernel" ]]; then
    pass "kata guest kernel $guest_kernel differs from host $host_kernel"
  else
    bad "kata pod reports kernel '$guest_kernel' — same as host, isolation is not real"
  fi
else
  bad "kata-clh-runtime-rs pod did not become ready"
fi

# gVisor is a sibling runtime class, not the workspace boundary. Here we only
# prove the shim is installed and sentry-backed; in-guest runsc inside Kata is a
# separate Phase 5 spike.
if boot_pod gvisor-probe gvisor; then
  dmesg_out=$($KUBECTL -n "$NS" exec gvisor-probe -- dmesg 2>/dev/null | head -3)
  grep -qi gvisor <<<"$dmesg_out" && pass "gvisor sentry confirmed" || warn "runsc pod ran but gVisor banner not seen"
else
  # A RuntimeClass that exists but cannot start pods is worse than none: it
  # looks available to anyone selecting it. Fail rather than warn.
  bad "gvisor pod did not become ready"
fi

echo
(( fail )) && { echo "phase 1 FAILED"; exit 1; }
echo "phase 1 passed"
