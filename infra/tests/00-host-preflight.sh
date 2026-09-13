#!/usr/bin/env bash
# Phase 0 verify: this host can run the Sandcastle reference implementation.
# Read-only. No sudo. Exits non-zero on the first hard requirement that fails.
set -uo pipefail

fail=0
pass() { printf '  ok    %s\n' "$1"; }
warn() { printf '  warn  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }

echo "Sandcastle host preflight"

# Kata with Cloud Hypervisor needs a real KVM device. The kata-runtime runs as
# root under k3s, so root access is the hard requirement; the invoking user
# needs it only for running a guest by hand while debugging.
if [[ -c /dev/kvm ]]; then pass "/dev/kvm present"; else bad "/dev/kvm missing"; fi
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  pass "/dev/kvm accessible to $USER"
else
  warn "/dev/kvm not accessible to $USER (k3s runs kata as root; for hand-run guests: sudo usermod -aG kvm $USER)"
fi
if grep -qE '^flags.*\b(vmx|svm)\b' /proc/cpuinfo; then pass "CPU virtualization extensions"; else bad "no vmx/svm in /proc/cpuinfo"; fi

# Nested virt matters only if the host is itself a VM; harmless to report.
nested=$(cat /sys/module/kvm_amd/parameters/nested /sys/module/kvm_intel/parameters/nested 2>/dev/null | head -1)
case "$nested" in
  1|Y|y) pass "nested virtualization enabled" ;;
  "")    warn "nested virtualization state unknown" ;;
  *)     warn "nested virtualization disabled ($nested)" ;;
esac

[[ -f /sys/fs/cgroup/cgroup.controllers ]] && pass "cgroup v2" || bad "cgroup v2 required"
[[ "$(systemctl is-system-running 2>/dev/null)" =~ ^(running|degraded)$ ]] && pass "systemd running" || bad "systemd required for k3s"

cpus=$(nproc)
mem=$(awk '/MemTotal/ {print int($2/1024/1024)}' /proc/meminfo)
(( cpus >= 8 )) && pass "${cpus} cpus" || warn "${cpus} cpus (8+ recommended)"
(( mem >= 24 )) && pass "${mem}GB RAM" || warn "${mem}GB RAM (24GB+ recommended)"
disk=$(df -BG --output=avail / | tail -1 | tr -dc 0-9)
(( disk >= 80 )) && pass "${disk}GB free on /" || warn "${disk}GB free on / (80GB+ recommended)"

for t in kubectl helm terraform k3s; do
  command -v "$t" >/dev/null && pass "$t installed" || warn "$t missing — run infra/bootstrap/00-prereqs.sh"
done

echo
(( fail )) && { echo "preflight FAILED"; exit 1; }
echo "preflight passed"
