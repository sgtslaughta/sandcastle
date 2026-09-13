#!/usr/bin/env bash
# Phase 0 verify: this VM (node) can run the Sandcastle reference implementation.
# Runs inside the VM. Read-only. No sudo. Exits non-zero on the first hard
# requirement that fails.
set -uo pipefail

fail=0
pass() { printf '  ok    %s\n' "$1"; }
warn() { printf '  warn  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }

echo "Sandcastle node preflight"

# Kata needs /dev/kvm inside the guest, which requires the VM to have been
# created with --cpu host-passthrough and the host to have nested virt enabled.
if [[ -c /dev/kvm ]]; then pass "/dev/kvm present"; else bad "/dev/kvm missing (VM needs --cpu host-passthrough and host nested virt)"; fi
if grep -qE '^flags.*\b(vmx|svm)\b' /proc/cpuinfo; then pass "CPU virtualization extensions"; else bad "no vmx/svm in guest /proc/cpuinfo"; fi

[[ -f /sys/fs/cgroup/cgroup.controllers ]] && pass "cgroup v2" || bad "cgroup v2 required"
[[ "$(systemctl is-system-running 2>/dev/null)" =~ ^(running|degraded)$ ]] && pass "systemd running" || bad "systemd required for k3s"

cpus=$(nproc)
mem=$(awk '/MemTotal/ {print int($2/1024/1024)}' /proc/meminfo)
(( cpus >= 8 )) && pass "${cpus} cpus" || bad "${cpus} cpus (8+ required)"
(( mem >= 16 )) && pass "${mem}GB RAM" || bad "${mem}GB RAM (16GB+ required)"

for t in kubectl helm; do
  command -v "$t" >/dev/null && pass "$t installed" || warn "$t missing"
done

echo
(( fail )) && { echo "preflight FAILED"; exit 1; }
echo "preflight passed"
