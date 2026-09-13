#!/usr/bin/env bash
# Lifecycle for the sandcastle lab VM: create, ssh/sync/run, snapshot/revert,
# kubeconfig extraction, destroy. Everything after 00-host-libvirt.sh runs
# through this script so the lab never touches the host directly.
set -euo pipefail

VM_NAME="${VM_NAME:-sandcastle}"
VM_VCPUS="${VM_VCPUS:-10}"
VM_MEMORY_MB="${VM_MEMORY_MB:-20480}"
VM_DISK_GB="${VM_DISK_GB:-120}"
IMG_DIR="${IMG_DIR:-/var/lib/libvirt/images/sandcastle}"
IMG_URL="${IMG_URL:-https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img}"
SUMS_URL="${SUMS_URL:-https://cloud-images.ubuntu.com/releases/26.04/release/SHA256SUMS}"
SSH_PUBKEY="${SSH_PUBKEY:-$HOME/.ssh/id_gen_key.pub}"
SSH_KEY="${SSH_PUBKEY%.pub}"
VM_USER="${VM_USER:-dev}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Under sudo, $HOME becomes /root (wrong ssh key, wrong kubeconfig) and every
# file lands root-owned, breaking later runs as the user. qemu:///system access
# comes from libvirt group membership, not root.
if [[ $EUID -eq 0 ]]; then
  echo "do not run as root/sudo — run as your user (needs libvirt group; re-login after make vm-host)" >&2
  exit 1
fi

v() { virsh -c qemu:///system "$@"; }
ssh_opts() { printf '%s' "-i $SSH_KEY -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$IMG_DIR/known_hosts"; }

vm_ip() {
  v domifaddr "$VM_NAME" --source lease 2>/dev/null \
    | awk '/ipv4/ {split($4,a,"/"); print a[1]; exit}'
}

cmd_create() {
  # Group membership from make vm-host applies only to new login sessions;
  # check the libvirt socket before any download or disk work.
  v version >/dev/null 2>&1 || {
    echo "cannot reach qemu:///system — log out and back in after make vm-host, or run: sudo -u \"$USER\" make ..." >&2
    exit 1
  }
  if v dominfo "$VM_NAME" >/dev/null 2>&1; then
    echo "domain $VM_NAME already exists" >&2
    exit 1
  fi

  [[ -w "$IMG_DIR" ]] || { echo "$IMG_DIR not writable by $USER — run make vm-host, then re-login" >&2; exit 1; }
  [[ -r "$SSH_PUBKEY" ]] || { echo "ssh public key $SSH_PUBKEY not found — set SSH_PUBKEY" >&2; exit 1; }

  if [[ ! -f "$IMG_DIR/base.img" ]]; then
    echo "==> downloading base image"
    curl -fsSLo "$IMG_DIR/base.img.tmp" "$IMG_URL"
    mv "$IMG_DIR/base.img.tmp" "$IMG_DIR/base.img"
  fi

  echo "==> verifying base image checksum"
  local sums want got
  sums=$(curl -fsSL "$SUMS_URL")
  want=$(awk '/\*ubuntu-26\.04-server-cloudimg-amd64\.img$/ {print $1; exit}' <<<"$sums")
  if [[ -z "$want" ]]; then
    echo "checksum line for base image not found in $SUMS_URL" >&2
    exit 1
  fi
  got=$(sha256sum "$IMG_DIR/base.img" | awk '{print $1}')
  if [[ "$got" != "$want" ]]; then
    rm -f "$IMG_DIR/base.img"
    echo "checksum mismatch: got $got want $want (base.img deleted)" >&2
    exit 1
  fi

  echo "==> creating overlay disk"
  # No domain exists (checked above), so any overlay here is a leftover from a
  # failed create. Unlinking needs only directory write access, which also
  # clears root-owned leftovers from an accidental sudo run.
  rm -f "$IMG_DIR/$VM_NAME.qcow2" "$IMG_DIR/$VM_NAME-seed.iso"
  qemu-img create -f qcow2 -F qcow2 -b "$IMG_DIR/base.img" "$IMG_DIR/$VM_NAME.qcow2" "${VM_DISK_GB}G"

  echo "==> writing cloud-init seed"
  local seed_dir
  seed_dir=$(mktemp -d)

  local pubkey
  pubkey=$(cat "$SSH_PUBKEY")

  # NOPASSWD sudo is acceptable here: the VM is a disposable lab, not a
  # production host, and bootstrap must run unattended over ssh.
  cat >"$seed_dir/user-data" <<EOF
#cloud-config
hostname: $VM_NAME
users:
  - name: $VM_USER
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $pubkey
packages:
  - rsync
  - make
EOF

  cat >"$seed_dir/meta-data" <<EOF
instance-id: $VM_NAME
local-hostname: $VM_NAME
EOF

  cloud-localds "$IMG_DIR/$VM_NAME-seed.iso" "$seed_dir/user-data" "$seed_dir/meta-data"
  rm -rf "$seed_dir"

  echo "==> defining and starting VM"
  # host-passthrough exposes svm/vmx to the guest so Kata can run nested;
  # memballoon none keeps guest memory fixed so the lab cannot grow into the
  # host's streaming headroom; BIOS boot (no UEFI) is deliberate — libvirt
  # internal snapshots do not work with UEFI nvram.
  virt-install --connect qemu:///system \
    --name "$VM_NAME" \
    --vcpus "$VM_VCPUS" \
    --memory "$VM_MEMORY_MB" \
    --memballoon none \
    --cpu host-passthrough \
    --osinfo detect=on,require=off \
    --disk path="$IMG_DIR/$VM_NAME.qcow2",format=qcow2,bus=virtio \
    --disk path="$IMG_DIR/$VM_NAME-seed.iso",device=cdrom \
    --network network=default,model=virtio \
    --graphics none \
    --console pty,target_type=serial \
    --import --noautoconsole

  echo "==> waiting for IP"
  local waited=0 ip=""
  while (( waited < 180 )); do
    ip=$(vm_ip || true)
    [[ -n "$ip" ]] && break
    sleep 3
    waited=$((waited + 3))
  done
  if [[ -z "$ip" ]]; then
    echo "timed out waiting for VM IP" >&2
    exit 1
  fi

  echo "==> waiting for ssh + cloud-init"
  waited=0
  # shellcheck disable=SC2046
  until ssh $(ssh_opts) "$VM_USER@$ip" true 2>/dev/null; do
    (( waited >= 300 )) && { echo "timed out waiting for ssh" >&2; exit 1; }
    sleep 5
    waited=$((waited + 5))
  done
  # shellcheck disable=SC2046
  if ! ssh $(ssh_opts) "$VM_USER@$ip" 'sudo cloud-init status --wait'; then
    echo "cloud-init did not complete successfully" >&2
    exit 1
  fi

  # Eject the seed once cloud-init has consumed it. Internal snapshots require
  # every writable disk to be qcow2, and a raw ISO left attached is one less
  # thing to trust libvirt to skip.
  v change-media "$VM_NAME" "$IMG_DIR/$VM_NAME-seed.iso" --eject --live --config

  echo "$ip"
}

cmd_ip() {
  local ip
  ip=$(vm_ip)
  if [[ -z "$ip" ]]; then
    echo "no IP found for $VM_NAME" >&2
    exit 1
  fi
  echo "$ip"
}

cmd_ssh() {
  local ip
  ip=$(cmd_ip)
  # shellcheck disable=SC2046
  ssh $(ssh_opts) "$VM_USER@$ip" "$@"
}

cmd_sync() {
  local ip
  ip=$(cmd_ip)
  rsync -az --delete --exclude .git --exclude .remember \
    -e "ssh $(ssh_opts)" \
    "$REPO_ROOT/" "$VM_USER@$ip:sandcastle/"
}

cmd_run() {
  cmd_sync
  cmd_ssh "cd sandcastle && $*"
}

cmd_snapshot() {
  local name="$1"
  if v snapshot-info "$VM_NAME" "$name" >/dev/null 2>&1; then
    echo "snapshot $name exists, keeping original"
    return 0
  fi
  # Keeping the first snapshot preserves the clean pre-change state across
  # re-runs, rather than clobbering it with whatever state the VM is in now.
  v snapshot-create-as "$VM_NAME" "$name"
}

cmd_revert() {
  local name="$1"
  v snapshot-revert "$VM_NAME" "$name" --running
}

cmd_snapshots() {
  v snapshot-list "$VM_NAME"
}

cmd_kubeconfig() {
  local ip conf
  ip=$(cmd_ip)
  conf=$(cmd_ssh cat .kube/config)
  conf=${conf//127.0.0.1/$ip}

  if [[ -f "$HOME/.kube/config" ]] && ! grep -q sandcastle-vm "$HOME/.kube/config"; then
    cp "$HOME/.kube/config" "$HOME/.kube/config.bak.$(date +%s)"
  fi

  mkdir -p "$HOME/.kube"
  { echo "# sandcastle-vm"; printf '%s\n' "$conf"; } > "$HOME/.kube/config"
  chmod 600 "$HOME/.kube/config"
}

cmd_console() {
  v console "$VM_NAME"
}

cmd_destroy() {
  if [[ "${FORCE:-}" != "1" ]]; then
    read -r -p "type the VM name to confirm: " confirm
    [[ "$confirm" == "$VM_NAME" ]] || { echo "confirmation mismatch, aborting" >&2; exit 1; }
  fi
  v destroy "$VM_NAME" || true
  # base.img is not attached to the domain, so --remove-all-storage only
  # removes the overlay disk; the base image survives for reuse. The seed ISO
  # was ejected after first boot, so it is removed by hand.
  v undefine "$VM_NAME" --snapshots-metadata --remove-all-storage
  rm -f "$IMG_DIR/$VM_NAME-seed.iso"
}

usage() {
  cat <<EOF
usage: $(basename "$0") <command> [args]

commands:
  create              create and boot the VM
  ip                  print the VM's IPv4 address
  ssh [cmd...]        ssh into the VM, optionally running cmd
  sync                rsync the repo into the VM
  run <cmd...>        sync then run cmd in the VM
  snapshot NAME       create an internal snapshot (no-op if it exists)
  revert NAME         revert to an internal snapshot
  snapshots           list snapshots
  kubeconfig          copy the VM's kubeconfig to the host
  console             attach to the VM's serial console
  destroy             undefine the VM and its storage (not base.img)
EOF
}

main() {
  local sub="${1:-}"
  [[ -n "$sub" ]] && shift || true
  case "$sub" in
    create)     cmd_create "$@" ;;
    ip)         cmd_ip "$@" ;;
    ssh)        cmd_ssh "$@" ;;
    sync)       cmd_sync "$@" ;;
    run)        cmd_run "$@" ;;
    snapshot)   cmd_snapshot "$@" ;;
    revert)     cmd_revert "$@" ;;
    snapshots)  cmd_snapshots "$@" ;;
    kubeconfig) cmd_kubeconfig "$@" ;;
    console)    cmd_console "$@" ;;
    destroy)    cmd_destroy "$@" ;;
    *)          usage; exit 2 ;;
  esac
}

main "$@"
