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
