#!/usr/bin/env bash
# One-time host setup: installs libvirt/KVM so the lab can run inside a VM.
# This is the ONLY script that changes the host — everything after this runs
# inside the VM. The VM uses libvirt's NAT "default" network exclusively; this
# script never touches the physical NIC (enp38s0), never creates a bridge.
# Needs sudo.
set -euo pipefail

step() { printf '\n==> %s\n' "$1"; }

step "installing libvirt/KVM packages"
sudo apt-get install -y qemu-system-x86 qemu-utils libvirt-daemon-system virtinst cloud-image-utils

step "adding $USER to libvirt and kvm groups"
sudo usermod -aG libvirt,kvm "$USER"
echo "group membership changed — log out and back in before using virsh/virt-install as $USER (or prefix commands with: sudo -u \"$USER\")"

step "starting libvirt default NAT network"
sudo virsh -c qemu:///system net-start default || true
sudo virsh -c qemu:///system net-autostart default

step "creating image directory"
sudo install -d -o "$USER" -g libvirt -m 0775 /var/lib/libvirt/images/sandcastle

step "done"
"$(dirname "$0")/../tests/00-host-preflight.sh"
