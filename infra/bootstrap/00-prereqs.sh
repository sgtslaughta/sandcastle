#!/usr/bin/env bash
# Phase 0: install the host tools Sandcastle's bootstrap needs.
# Needs sudo. Installs nothing that is already present. Does not start k3s —
# that is 01-k3s-cilium.sh, so this stays safe to re-run.
set -euo pipefail

KUBECTL_VERSION="${KUBECTL_VERSION:-v1.31.4}"
TERRAFORM_VERSION="${TERRAFORM_VERSION:-1.10.3}"
ARCH=amd64
BIN=/usr/local/bin

have() { command -v "$1" >/dev/null; }
step() { printf '\n==> %s\n' "$1"; }

if have kubectl; then echo "kubectl present: $(kubectl version --client -o yaml | awk '/gitVersion/{print $2; exit}')"; else
  step "installing kubectl ${KUBECTL_VERSION}"
  curl -fsSLo /tmp/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl"
  curl -fsSLo /tmp/kubectl.sha256 "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl.sha256"
  echo "$(cat /tmp/kubectl.sha256)  /tmp/kubectl" | sha256sum -c -
  sudo install -m 0755 /tmp/kubectl "$BIN/kubectl"
fi

if have helm; then echo "helm present: $(helm version --short)"; else
  step "installing helm"
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

if have terraform; then echo "terraform present: $(terraform version -json | grep -o '"terraform_version":"[^"]*"')"; else
  step "installing terraform ${TERRAFORM_VERSION}"
  curl -fsSLo /tmp/tf.zip "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${ARCH}.zip"
  curl -fsSLo /tmp/tf.sums "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_SHA256SUMS"
  (cd /tmp && grep "linux_${ARCH}.zip" tf.sums | sed "s|terraform_${TERRAFORM_VERSION}_linux_${ARCH}.zip|tf.zip|" | sha256sum -c -)
  sudo unzip -oq /tmp/tf.zip -d "$BIN"
fi

# k3s installs kata and Cilium later; the installer script itself is pulled in
# 01-k3s-cilium.sh so the version pin lives next to the cluster config.
step "done"
"$(dirname "$0")/../tests/00-host-preflight.sh"
