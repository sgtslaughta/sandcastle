#!/usr/bin/env bash
# Phase 0 verify: this host can run the sandcastle lab VM.
# Read-only. No sudo. Exits non-zero on the first hard requirement that fails.
set -uo pipefail

fail=0
pass() { printf '  ok    %s\n' "$1"; }
warn() { printf '  warn  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=1; }

echo "Sandcastle host preflight"

if [[ -c /dev/kvm ]]; then pass "/dev/kvm present"; else bad "/dev/kvm missing"; fi
if grep -qE '^flags.*\b(vmx|svm)\b' /proc/cpuinfo; then pass "CPU virtualization extensions"; else bad "no vmx/svm in /proc/cpuinfo"; fi

# The VM runs Kata nested, so nested virt is a hard requirement now, not the
# best-effort check it was when the lab ran directly on the host.
nested=$(cat /sys/module/kvm_amd/parameters/nested /sys/module/kvm_intel/parameters/nested 2>/dev/null | head -1)
case "$nested" in
  1|Y|y) pass "nested virtualization enabled" ;;
  *)     bad "nested virtualization disabled or unknown ($nested) — enable kvm_amd/kvm_intel nested=1" ;;
esac

cpus=$(nproc)
mem=$(awk '/MemTotal/ {print int($2/1024/1024)}' /proc/meminfo)
(( cpus >= 12 )) && pass "${cpus} cpus" || bad "${cpus} cpus (12+ required, VM takes 10)"
(( mem >= 24 )) && pass "${mem}GB RAM" || bad "${mem}GB RAM (24GB+ required)"

libvirt_dir=/var/lib/libvirt
[[ -d "$libvirt_dir" ]] || libvirt_dir=/
disk=$(df -BG --output=avail "$libvirt_dir" | tail -1 | tr -dc 0-9)
(( disk >= 130 )) && pass "${disk}GB free on $libvirt_dir" || warn "${disk}GB free on $libvirt_dir (130GB+ recommended)"

for t in virsh virt-install qemu-img cloud-localds; do
  command -v "$t" >/dev/null && pass "$t installed" || warn "$t missing — run make vm-host"
done

id -nG | grep -qw libvirt && pass "$USER in libvirt group" || warn "$USER not in libvirt group — run make vm-host, then re-login"

virsh -c qemu:///system net-list --name 2>/dev/null | grep -qx default \
  && pass "libvirt default network active" \
  || warn "libvirt default network not active — run make vm-host"

for t in kubectl helm; do
  command -v "$t" >/dev/null && pass "$t installed" || warn "$t missing (optional, for driving the cluster from the host)"
done

echo
(( fail )) && { echo "preflight FAILED"; exit 1; }
echo "preflight passed"
