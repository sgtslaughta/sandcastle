# Sandcastle

Agent-containment developer platform for air-gapped enterprises.

Developers get real workspaces — terminal, IDE, desktop, `apt install`,
`docker build`. A hostile or runaway AI agent with root inside one of those
workspaces reaches nothing it was not granted, and every attempt alerts within
seconds.

Design spec: [`docs/superpowers/specs/2026-09-13-sandcastle-mvp-design.md`](docs/superpowers/specs/2026-09-13-sandcastle-mvp-design.md)

## Core invariant

A workspace's routing table has exactly three destinations: the egress proxy,
internal DNS, and the artifact mirror. Everything else is unreachable at L3, so
a tool that ignores `HTTP_PROXY` gets `EHOSTUNREACH` instead of a bypass —
bypass and failure become the same event. Enforced twice, by Cilium policy and
by a host firewall owned separately.

Any packet from a workspace toward an enclave CIDR is a page, not a log line.

## Layout

| Path | Contents |
|---|---|
| `infra/` | k3s bootstrap, Cilium, kata-deploy, host nftables, per-phase verify scripts |
| `infra/vm/` | libvirt/KVM lab VM lifecycle: create, ssh/sync/run, snapshot/revert |
| `platform/` | Coder, Nexus, Gitea, Ollama, Loki/Grafana, Falco manifests and values |
| `admin/` | `sandcastle-admin`: zones, egress request/approve, Envoy xDS, Cilium reconciler, htmx UI |
| `brokers/` | `cred-broker` (short-lived git tokens), `data-broker` (only path to enclave data) |
| `envoy/` | Egress gate config, self-service 403 page, rate limits |
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
```

Rollback to a pre-phase snapshot: `make vm-snapshots` to list, then
`make vm-revert NAME=pre-cilium` (or `pre-kata`).

## Status

Phase 1 (isolation substrate) — complete: k3s + Cilium (kube-proxy replaced), Kata `kata-clh-runtime-rs`, gVisor, verified by `make verify-substrate` in the lab VM. Phase 2 (developer experience baseline) next; see the spec for the phase plan.
