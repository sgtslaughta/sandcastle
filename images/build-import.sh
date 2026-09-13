#!/usr/bin/env bash
# Build the workspace images and import them into the lab VM's k3s containerd.
# There is no registry yet, so images are imported directly into containerd's
# k8s.io namespace (the one kubelet reads) rather than pushed and pulled;
# workspace pods therefore use imagePullPolicy: Never. The Nexus OCI proxy
# replaces this path once it exists.
set -euo pipefail

VERSION="${VERSION:-0.1.0}"
IMAGES="${IMAGES:-base dind}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM_SCRIPT="$REPO_ROOT/infra/vm/sandcastle-vm.sh"

step() { printf '\n==> %s\n' "$1"; }

for name in $IMAGES; do
  image="sandcastle/$name:$VERSION"

  step "building $image"
  docker build -t "$image" "$REPO_ROOT/images/$name"

  step "importing $image into k3s containerd (namespace k8s.io)"
  docker save "$image" | "$VM_SCRIPT" ssh 'sudo k3s ctr -n k8s.io images import -'

  # containerd stores an untagged-registry name with an implied docker.io/
  # prefix, so accept either form. -F/-x avoids "." and "/" being read as
  # regex metacharacters.
  "$VM_SCRIPT" ssh "sudo k3s ctr -n k8s.io images ls -q | grep -Fxq -e '$image' -e 'docker.io/$image'"
  echo "$image imported"
done
