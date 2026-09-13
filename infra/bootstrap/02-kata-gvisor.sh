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

RUNTIME_CLASS=kata-clh-runtime-rs

# Only Cloud Hypervisor on the Rust runtime (runtime-rs) is installed. The Go
# runtime's clh shim is deprecated upstream since Kata 4.0. Each extra shim is
# another guest image, another config surface, and another runtime class an
# operator could select by mistake. defaultShim must name an enabled shim: the
# chart defaults it to qemu-runtime-rs, and kata-deploy exits at startup if
# that shim is not configured.
helm upgrade --install kata-deploy "$chart" \
  --namespace kube-system \
  --set k8sDistribution=k3s \
  --set shims.disableAll=true \
  --set shims.clh-runtime-rs.enabled=true \
  --set defaultShim.amd64=clh-runtime-rs \
  --wait --timeout 15m

step "waiting for node to report kata installed (max 10m)"
# helm --wait does not catch a crash-looping DaemonSet pod, so bound the wait
# and show the pod's own error instead of hanging.
for ((i = 0; i < 120; i++)); do
  [[ "$(kubectl get nodes -o jsonpath='{.items[0].metadata.labels.katacontainers\.io/kata-runtime}' 2>/dev/null)" == "true" ]] && break
  sleep 5
done
if (( i == 120 )); then
  echo "  FAIL  node never labeled kata-runtime=true. kata-deploy pod output:"
  kubectl -n kube-system logs -l name=kata-deploy --tail=20 2>&1 || true
  kubectl -n kube-system get pods -o wide | grep -i kata || true
  exit 1
fi
kubectl get runtimeclass

step "verifying containerd actually learned the $RUNTIME_CLASS handler"
# This is the check the upstream k3s issues exist for: the DaemonSet can report
# success while containerd never picked up the runtime.
if sudo k3s crictl info 2>/dev/null | grep -q "\"$RUNTIME_CLASS\""; then
  echo "  ok    containerd knows $RUNTIME_CLASS"
else
  echo "  FAIL  containerd does not list $RUNTIME_CLASS."
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
# that survives. k3s 1.36 generates a containerd v3 config whose only import is
# config-v3.toml.d/*.toml (the same directory kata-deploy writes to); files in
# the similarly named containerd.d are silently ignored. runtime_path is set
# explicitly, as kata-deploy does, rather than relying on containerd's PATH.
CONTAINERD_DIR=/var/lib/rancher/k3s/agent/etc/containerd
sudo rm -f "$CONTAINERD_DIR/containerd.d/runsc.toml"
sudo mkdir -p "$CONTAINERD_DIR/config-v3.toml.d"
sudo tee "$CONTAINERD_DIR/config-v3.toml.d/runsc.toml" >/dev/null <<'TOML'
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runsc]
runtime_type = "io.containerd.runsc.v1"
runtime_path = "/usr/local/bin/containerd-shim-runsc-v1"
TOML
sudo systemctl restart k3s
until kubectl get --raw=/readyz >/dev/null 2>&1; do sleep 2; done

if sudo k3s crictl info 2>/dev/null | grep -q '"runsc"'; then
  echo "  ok    containerd knows runsc"
else
  echo "  FAIL  containerd does not list runsc; check $CONTAINERD_DIR/config.toml imports"
  exit 1
fi

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
