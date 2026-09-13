#!/usr/bin/env bash
# Second enforcement layer, on the host: the lab VM may send traffic out only
# from its egress network (Cilium egress gateway IP), and only to 80/443.
# Anything from the VM's primary NIC leaving the host, or reaching host
# services other than libvirt's DHCP/DNS, is logged "sandcastle-deny" and
# dropped. That is what a workspace packet looks like if Cilium failed.
#
# Scope is deliberately narrow: our own table, input/forward hooks only, and
# every rule matches iifname virbr0 or virbr-sce. Host output traffic and
# other interfaces are never matched, so this cannot strand the host the way
# the first Cilium install did. Not persistent across host reboots
# (ponytail: re-run make egress-lock; verify-containment fails while unlocked).
#
# usage: sudo 01-host-egress-nft.sh lock <vm-primary-ip> | unlock | verify
set -euo pipefail

TABLE=sandcastle
LAB_BR=virbr0
EGRESS_BR=virbr-sce

[[ $EUID -eq 0 ]] || { echo "needs sudo" >&2; exit 1; }

lock() {
  local vm_ip="$1"
  [[ "$vm_ip" =~ ^192\.168\.122\.[0-9]+$ ]] || { echo "unexpected VM IP '$vm_ip'" >&2; exit 1; }
  ip link show "$EGRESS_BR" >/dev/null 2>&1 || { echo "$EGRESS_BR missing — run make vm-egress-net" >&2; exit 1; }
  # "table; delete table; table {...}" replaces the table atomically and
  # idempotently in one transaction.
  nft -f - <<EOF
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
  chain input {
    type filter hook input priority filter - 10; policy accept;
    iifname "$LAB_BR" ip saddr $vm_ip ct state established,related accept
    iifname "$LAB_BR" ip saddr $vm_ip udp dport { 53, 67 } accept
    iifname "$LAB_BR" ip saddr $vm_ip tcp dport 53 accept
    iifname "$EGRESS_BR" ct state established,related accept
    iifname { "$LAB_BR", "$EGRESS_BR" } limit rate 20/second burst 40 packets log prefix "sandcastle-deny " level warn
    iifname { "$LAB_BR", "$EGRESS_BR" } drop
  }
  chain forward {
    type filter hook forward priority filter - 10; policy accept;
    # Public destinations only: an allowlisted name resolving to the LAN or an
    # enclave range must not become a route (DNS rebinding).
    iifname "$EGRESS_BR" ip saddr 192.168.130.10 ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } tcp dport { 80, 443 } accept
    iifname { "$LAB_BR", "$EGRESS_BR" } limit rate 20/second burst 40 packets log prefix "sandcastle-deny " level warn
    iifname { "$LAB_BR", "$EGRESS_BR" } drop
  }
}
EOF
  echo "locked: VM $vm_ip may leave the host only via $EGRESS_BR (tcp 80/443)"
}

unlock() {
  nft delete table inet "$TABLE" 2>/dev/null && echo "unlocked" || echo "already unlocked"
}

verify() {
  local fail=0 hooks
  nft list table inet "$TABLE" >/dev/null 2>&1 && echo "  ok    table inet $TABLE present" || { echo "  FAIL  table inet $TABLE missing (unlocked)"; exit 1; }
  hooks=$(nft list table inet "$TABLE" | awk '/hook/ {print $4}' | sort -u | tr '\n' ' ')
  [[ "$hooks" == "forward input " ]] && echo "  ok    hooks: $hooks" || { echo "  FAIL  unexpected hooks: $hooks"; fail=1; }
  # Every rule line (not table/chain/type/brace) must match a lab bridge.
  # Never grep -q in these pipelines: under pipefail, grep -q exits at its
  # first match, the writer dies of SIGPIPE, and the pipeline reports failure,
  # which here would turn a found violation into "ok".
  if nft list table inet "$TABLE" | grep -vE '^\s*(table|chain|type|\}|$)' | grep -v iifname >/dev/null; then
    echo "  FAIL  a rule does not match on a lab bridge"; fail=1
  else
    echo "  ok    every rule is scoped to $LAB_BR/$EGRESS_BR"
  fi
  journalctl -k --since "-30 min" --no-pager | grep 'sandcastle-deny' >/dev/null \
    && echo "  ok    sandcastle-deny log lines in the last 30 min" \
    || { echo "  FAIL  no sandcastle-deny log lines in the last 30 min (run make verify-containment first)"; fail=1; }
  exit "$fail"
}

case "${1:-}" in
  lock)   lock "${2:?usage: lock <vm-primary-ip>}" ;;
  unlock) unlock ;;
  verify) verify ;;
  *)      echo "usage: $0 lock <vm-ip> | unlock | verify" >&2; exit 2 ;;
esac
