#!/usr/bin/env bash
# Phase 1a: single-node k3s with Cilium as the only CNI and kube-proxy replaced.
#
# Why these choices: the containment model in phase 3 is expressed entirely as
# CiliumNetworkPolicy. k3s ships flannel plus a kube-router network-policy
# controller; both would fight Cilium and, worse, could enforce a *partial*
# policy that looks like it works. kube-proxy is replaced rather than kept so
# that service traffic cannot bypass Cilium's datapath.
#
# Runs inside the lab VM (make cluster), never on a workstation: a CNI that
# fails half-installed can take its host off the network. Needs sudo.
# Re-runnable: skips k3s install if the node is already up.
set -euo pipefail

K3S_VERSION="${K3S_VERSION:-v1.36.4+k3s1}"
CILIUM_VERSION="${CILIUM_VERSION:-1.20.1}"
NODE_IP="${NODE_IP:-$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')}"
API_PORT=6443

step() { printf '\n==> %s\n' "$1"; }

# --disable=runtimes stops k3s publishing RuntimeClasses (crun, nvidia, wasm
# shims, ...) for every runtime it knows of. Each is a way to schedule a pod
# outside Kata; the cluster should offer only the classes this repo installs.
step "k3s ${K3S_VERSION} (node IP ${NODE_IP})"
if systemctl is-active --quiet k3s; then
  echo "k3s already running: $(k3s --version | head -1)"
else
  curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$K3S_VERSION" \
    K3S_KUBECONFIG_MODE="644" \
    INSTALL_K3S_EXEC="server \
      --node-ip=${NODE_IP} \
      --flannel-backend=none \
      --disable-network-policy \
      --disable-kube-proxy \
      --disable=traefik \
      --disable=servicelb \
      --disable=runtimes" \
    sh -s -
fi

mkdir -p "$HOME/.kube" && install -m 600 /etc/rancher/k3s/k3s.yaml "$HOME/.kube/config"
export KUBECONFIG="$HOME/.kube/config"

# Without a CNI the node stays NotReady, which is expected at this point; wait
# only for the apiserver to answer.
step "waiting for apiserver"
until kubectl get --raw=/readyz >/dev/null 2>&1; do sleep 2; done
echo "apiserver ready"

step "cilium ${CILIUM_VERSION}"
helm repo add cilium https://helm.cilium.io/ >/dev/null
helm repo update cilium >/dev/null
helm upgrade --install cilium cilium/cilium --version "$CILIUM_VERSION" \
  --namespace kube-system \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost="$NODE_IP" \
  --set k8sServicePort="$API_PORT" \
  --set ipam.operator.clusterPoolIPv4PodCIDRList=10.42.0.0/16 \
  --set cni.exclusive=false \
  --set socketLB.hostNamespaceOnly=true \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --wait --timeout 10m

# The pod CIDR must match k3s's default (10.42.0.0/16); Cilium's own default
# cluster pool is 10.0.0.0/8, which disagrees with what k3s hands the node and
# claims routes for an entire private range any real network may be using.
#
# socketLB.hostNamespaceOnly is not a preference. Cilium's socket-level load
# balancing rewrites connections in the host netns; Kata pods run their own
# kernel behind a second netns, so socket LB must be confined to the host
# namespace or in-VM service traffic breaks in ways that look like random
# connection failures. Upstream documents this under network/kubernetes/kata.

step "waiting for node Ready"
kubectl wait --for=condition=Ready node --all --timeout=5m

step "done"
kubectl get nodes -o wide
echo
echo "Hubble UI: kubectl -n kube-system port-forward svc/hubble-ui 12000:80"
