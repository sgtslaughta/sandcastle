# Sandcastle

Agent-containment developer platform for enterprises.

Developers get real workspaces — terminal, IDE, desktop, `apt install`,
`docker build`. A hostile or runaway AI agent with root inside one of those
workspaces reaches nothing it was not granted, and every attempt alerts within
seconds.

Design spec: [`docs/superpowers/specs/2026-09-13-sandcastle-mvp-design.md`](docs/superpowers/specs/2026-09-13-sandcastle-mvp-design.md)

## Core invariant

A workspace reaches exactly four destinations: the egress proxy, cluster DNS
(in-cluster names only), the artifact mirror (reads only), and coderd (the
Coder agent's own requests only). Everything else is dropped, so a tool that
ignores `HTTP_PROXY` fails instead of bypassing: bypass and failure are the
same event. Most denied connections fail in about 150 ms (Cilium ICMP deny
response); denied ClusterIP destinations time out silently. Enforced twice:
by Cilium policy, and by a host firewall that only forwards the dedicated
egress-gateway IP.

Any packet from a workspace toward an enclave CIDR is a page, not a log line.

## Layout

| Path | Contents |
|---|---|
| `infra/` | k3s bootstrap, Cilium, kata-deploy, host nftables, per-phase verify scripts |
| `infra/vm/` | libvirt/KVM lab VM lifecycle: create, ssh/sync/run, snapshot/revert |
| `platform/` | Coder, Nexus, Gitea, Ollama, Loki/Grafana, Falco manifests and values |
| `platform/egress/` | Envoy egress gate: CONNECT + SNI allowlist, 403 with `x-sandcastle-denied` |
| `platform/policy/` | Cilium policies (workspace four-destination rule, platform pods), egress gateway, `workspace-dns-allow.yaml` |
| `admin/` | `sandcastle-admin`: zones, egress request/approve, Envoy xDS, Cilium reconciler, htmx UI |
| `brokers/` | `cred-broker` (short-lived git tokens), `data-broker` (only path to enclave data) |
| `images/` | Workspace base and desktop images, honeytokens |
| `templates/` | Coder Terraform workspace templates |
| `redteam/` | Escape PoCs and prompt-injection evals; blocked and alerted asserted separately |

## Running the lab

The lab runs inside a KVM VM on a libvirt NAT network, so a cluster
networking failure (e.g. a bad Cilium policy) cannot take the host offline.

```
make preflight   # check the host can run the VM
make vm-host     # sudo, once — installs libvirt, then re-login
make vm          # create and boot the VM
make cluster     # k3s + cilium, inside the VM
make kata        # kata-clh-runtime-rs + gvisor runtime classes, inside the VM
make verify-substrate
make platform    # coder + nexus + admission, inside the VM
make image template
make verify-dx
```

Phase 3 (containment). The host egress lock blocks the VM's primary IP, and
bootstrap steps need that IP, so unlock around them:

```
make vm-egress-net     # once: libvirt egress network + second VM NIC
make egress-unlock     # sudo
make containment       # egress gateway, Envoy gate, network policies
make image template
make egress-lock       # sudo
make verify-containment
make verify-host-egress  # sudo
```

The lock does not survive a host reboot; `verify-containment` fails until
`make egress-lock` runs again. To let workspaces resolve an extra name (e.g. an
internal registry host), add it to `platform/policy/workspace-dns-allow.yaml`
and run `make policy`. Resolving a name never grants reaching it.

Run `make` targets as your user (`sudo -u "$USER" make ...` if the session
lacks the libvirt group). Rollback to a pre-phase snapshot: `make vm-snapshots`
to list, then `make vm-revert NAME=pre-containment` (or `pre-platform`,
`pre-kata`, `pre-cilium`).

## Status

Phases 1–3 complete (v0.3.0):
- **Substrate:** k3s + Cilium (kube-proxy replaced), Kata `kata-clh-runtime-rs`, gVisor.
- **DX baseline:** Coder workspaces on Kata with Docker builds; Nexus mirror for apt/PyPI/npm/Docker Hub; admission refuses non-Kata workspace pods.
- **Containment core:**
  - four-destination workspace policy with L7 rules on coderd and Nexus;
  - Envoy egress gate with CONNECT + SNI allowlist;
  - Cilium egress gateway plus host nftables as the independent second layer;
  - every denial visible in Hubble or Envoy logs with workspace identity;
  - a noise budget that fails on any unexplained drop during normal work.

Verified by `make verify-substrate`, `make verify-dx`, `make verify-containment` and `make verify-host-egress`.

Phase 4 (admin control plane: zones, request/approve, xDS) next.
