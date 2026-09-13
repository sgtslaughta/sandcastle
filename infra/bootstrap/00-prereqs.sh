#!/usr/bin/env bash
# Phase 0: install the tools Sandcastle's bootstrap needs inside the VM.
# Runs inside the VM. Needs sudo. Re-runnable.
#
# Only helm. kubectl comes from k3s, which links a client matching the server;
# a separately pinned kubectl both skews versions and stops k3s from creating
# that link. Terraform is not needed on the node: Coder runs its own.
set -euo pipefail

step() { printf '\n==> %s\n' "$1"; }

if command -v helm >/dev/null; then echo "helm present: $(helm version --short)"; else
  step "installing helm"
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

step "done"
"$(dirname "$0")/../tests/00-node-preflight.sh"
