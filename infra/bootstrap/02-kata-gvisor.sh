#!/usr/bin/env bash
# Phase 1b: Kata Containers (Cloud Hypervisor) as the workspace boundary, plus a
# gVisor runtime class alongside it.
#
# Kata 4.1.0 ships kata-deploy as a Helm chart with a k3s distribution preset,
# which is why this script does not hand-edit containerd config. Earlier
# kata-deploy releases wrote to k3s's generated config.toml, which k3s
# regenerates on every restart, and the resulting "no runtime for kata-clh is
# configured" failures are the subject of several open upstream issues. The
# chart's k8sDistribution=k3s path writes a drop-in k3s preserves instead. The
# verify step at the end exists because that history argues for checking rather
# than trusting.
#
# Needs sudo. Re-runnable.
set -euo pipefail

KATA_VERSION="${KATA_VERSION:-4.1.0}"
CHART_URL="https://github.com/kata-containers/kata-containers/releases/download/${KATA_VERSION}/kata-deploy-${KATA_VERSION}.tgz"
CACHE="${CACHE:-$HOME/.cache/sandcastle}"
CONTAINERD_SOCK=/run/k3s/containerd/containerd.sock

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
step() { printf '\n==> %s\n' "$1"; }

mkdir -p "$CACHE"

step "kata-deploy ${KATA_VERSION}"
chart="$CACHE/kata-deploy-${KATA_VERSION}.tgz"
[[ -f "$chart" ]] || curl -fsSLo "$chart" "$CHART_URL"

# Only the Cloud Hypervisor shim is installed. Each extra shim is another guest
# image, another config surface, and another runtime class an operator could
# select by mistake; the design commits to kata-clh.
helm upgrade --install kata-deploy "$chart" \
  --namespace kube-system \
  --set k8sDistribution=k3s \
  --set shims.disableAll=true \
  --set shims.clh.enabled=true \
  --wait --timeout 15m

step "waiting for node to report kata installed"
until [[ "$(kubectl get nodes -o jsonpath='{.items[0].metadata.labels.katacontainers\.io/kata-runtime}' 2>/dev/null)" == "true" ]]; do
  sleep 5
done
kubectl get runtimeclass

step "verifying containerd actually learned the kata-clh handler"
# This is the check the upstream k3s issues exist for: the DaemonSet can report
# success while containerd never picked up the runtime.
if sudo k3s crictl info 2>/dev/null | grep -q '"kata-clh"'; then
  echo "  ok    containerd knows kata-clh"
else
  echo "  FAIL  containerd does not list kata-clh."
  echo "        Inspect: sudo ls /var/lib/rancher/k3s/agent/etc/containerd/"
  echo "        and:     sudo k3s crictl info | grep -A5 runtimes"
  exit 1
fi

step "gVisor runtime class"
# gVisor is installed as a sibling runtime class, not nested inside Kata.
# Running runsc inside a Kata guest is not a documented or supported upstream
# configuration; see docs/superpowers/specs for the nesting decision.
if ! command -v runsc >/dev/null; then
  ARCH=$(uname -m)
  URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
  tmp=$(mktemp -d)
  (
    cd "$tmp"
    curl -fsSLO "${URL}/runsc" -O "${URL}/runsc.sha512" \
         -O "${URL}/containerd-shim-runsc-v1" -O "${URL}/containerd-shim-runsc-v1.sha512"
    sha512sum -c runsc.sha512 containerd-shim-runsc-v1.sha512
    chmod a+rx runsc containerd-shim-runsc-v1
    sudo mv runsc containerd-shim-runsc-v1 /usr/local/bin/
  )
  rm -rf "$tmp"
fi
runsc --version | head -1

# k3s regenerates config.toml on restart, so the runsc handler goes in a drop-in
# that survives. k3s merges every *.toml under containerd.d into its config.
sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/containerd.d
sudo tee /var/lib/rancher/k3s/agent/etc/containerd/containerd.d/runsc.toml >/dev/null <<'TOML'
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
TOML
sudo systemctl restart k3s
until kubectl get --raw=/readyz >/dev/null 2>&1; do sleep 2; done

kubectl apply -f - <<'YAML'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
YAML

step "done"
kubectl get runtimeclass
echo
echo "Next: infra/tests/01-isolation-substrate.sh"
