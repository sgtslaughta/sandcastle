# Sandcastle MVP — Design Spec

Date: 2026-09-13
Status: approved

## Problem

Enterprise runs AI coding agents (Claude Code, Codex, etc.) inside an air-gapped
network containing sensitive service enclaves. Developers need first-class
workspaces (terminal, IDE, desktop, container builds, package installs) while a
hostile or runaway agent — even with root in its workspace — must be unable to
reach anything it was not explicitly granted, with every attempt detected within
seconds.

Threat model, ranked:

1. **Supply-chain bridge** — agent-authored artifact flows through CI into an
   enclave. Highest probability path; process + promotion-gate control.
2. **Lateral movement** — workspace → enclave network access.
3. **Destructive runaway** — high-speed agent loops damaging shared services.
4. **Staged exfil** — data parked where a human/process later carries it out.

Out of scope for MVP: human clipboard exfil, freeze-and-snapshot forensics,
GPU passthrough, WebRTC streaming, multi-node scale-out, production airlock.

## Core invariant

The workspace routing table has exactly three destinations: egress proxy,
internal DNS, Nexus mirror. Everything else is unreachable at L3. A tool that
ignores `HTTP_PROXY` gets `EHOSTUNREACH` — bypass and failure are the same
event. Enforced twice by different mechanisms: Cilium `CiliumNetworkPolicy`
in-cluster and host nftables (production: VPC/VLAN rule owned by a different
team).

Any packet from a workspace toward an enclave CIDR is a page, never a log line.

## Architecture

Single KVM virtual machine on the developer's host, running k3s (flannel +
kube-proxy disabled), Cilium CNI, kata-deploy with Cloud Hypervisor
(`runtimeClassName: kata-clh-runtime-rs`). That is Cloud Hypervisor on Kata's
Rust runtime, the upstream default since 4.0; the Go runtime's `kata-clh` is
deprecated and receives no new features.

### Lab host boundary — added 2026-09-13

The first bootstrap ran directly on a workstation. Cilium's kube-proxy
replacement attaches eBPF at the node's NIC, and when its agent failed to come
up after the datapath was already in place, the host kept its IP and link but
answered nothing, re-blackholing itself on every reboot until k3s was disabled.

The lab therefore runs in a libvirt VM (Ubuntu 26.04, 10 vCPU, 20 GB fixed, no
balloon) on libvirt's NAT network. Every cluster-side failure mode — eBPF,
iptables, CNI config, routes — lives in the guest kernel, so the worst case is
an unreachable VM recovered through its serial console or a snapshot revert.
The host NIC is never bridged into the guest; a bridge would re-couple host
networking to the cluster's.

Rules that follow:

- Bootstrap steps that alter networking snapshot the VM first (`pre-cilium`,
  `pre-kata`) and keep the first snapshot of each name across re-runs.
- `infra/vm/00-host-libvirt.sh` is the only script that modifies the host.
- Substrate verification runs inside the VM. It compares the Kata pod's kernel
  with the kernel of the machine running the test; from the host, a runc
  fallback pod would report the VM's kernel and pass falsely.

Side effect worth keeping: host nftables on the libvirt network sit outside the
cluster's kernel entirely, making them a faithful stand-in for the production
"second enforcement layer owned by a different team".

Cost: Kata guests are now nested (L2) under the lab VM, so workspace boot and
memory overhead are higher than production bare metal. Production parity is
preserved with cloud instances that use nested virtualization.

### Second isolation layer — revised 2026-09-13

Planning assumed nested gVisor would be available as a per-template
`runtimeClassName` flag, on the reasoning that air-gapped patch latency makes a
single hypervisor boundary risky and that two layers rarely share a
vulnerability. The reasoning stands; the mechanism does not. Running `runsc`
inside a Kata guest is not a documented or supported upstream configuration —
Kata and gVisor are published as sibling runtimes selected per workload, and a
Kubernetes `RuntimeClass` selects exactly one of them.

Consequences for this design:

- `gvisor` is installed as a **sibling** RuntimeClass. It is not the boundary
  for sensitive workspaces — on this host it is strictly weaker than Kata — and
  exists to run the red-team suite's own tooling and as a documented fallback
  for hosts without nested virt.
- The genuine second layer inside a workspace is the **in-guest container
  runtime**. The workspace already runs a DinD sidecar in the Kata VM, so
  `runsc` installed inside the guest makes `docker run --runtime=runsc` the
  boundary for agent-executed and third-party code. That is a supported gVisor
  configuration, it sits exactly where untrusted code runs, and it does not
  depend on nesting a Kubernetes runtime class.
- Whether that in-guest `runsc` works under Cloud Hypervisor's guest kernel is
  unverified. It is a spike in Phase 5, not a dependency of any earlier phase.

### Platform namespace

| Component | Role |
|---|---|
| Coder OSS | Workspace lifecycle, templates, tunnel-only access (no inbound ports per workspace) |
| Nexus | Single mirror for apt/PyPI/npm/OCI; collapses allowlist to one hostname; stands in for the airlock ingest path |
| sandcastle-admin | Go + htmx + Postgres. Zone registry, per-workspace egress policy, request/approve queue, audit log. Pushes Envoy xDS (go-control-plane) and reconciles CiliumNetworkPolicy CRDs |
| Envoy egress gate | DaemonSet :3128. TLS-inspector reads SNI, matches per-workspace allowlist from xDS; deny → 403 page with denied hostname + prefilled request link. Per-workspace identity from source IP → Cilium identity. Rate limits via ratelimit service + Redis |
| Gitea | Internal SCM (air-gap stand-in for enterprise git) |
| Ollama | Mock inference cluster behind the same Envoy gate; per-workspace tokens, daily ceilings |
| cred-broker | Exchanges workspace Coder identity for 10-minute Gitea token scoped to template-declared repos; git credential helper in image calls it. No secrets in image or env |
| data-broker | Only path to enclave data: query endpoint with row limits, redaction, full audit, volume-anomaly alert (e.g. 10k-row pull through a 50-row endpoint) |
| Loki + Grafana | Log sink + dashboards + alert rules; workspace ID is the join key everywhere |
| Falco relay | Receives guest telemetry over a channel the workspace cannot tamper with |

### Workspace namespaces

- Templates: `base` (code-server) and `desktop` (linuxserver.io Webtop base,
  selkies **websocket-only** through the Coder tunnel, software rendering,
  enlarged /dev/shm). Both run on `kata-clh-runtime-rs`; untrusted code
  inside them runs under in-guest `runsc` (see Second isolation layer).
- DinD sidecar (`images/dind`) inside the same Kata VM — container dev DX
  contained by the VM boundary. Three Kata-specific findings from Phase 2
  shape it:
  - The Docker API is a unix socket on a **memory-medium** emptyDir, with no
    TCP listener. Upstream dind silently added `tcp://0.0.0.0:2375` next to a
    loopback flag; default emptyDirs are virtio-fs host shares on which a unix
    socket refuses connections, while memory emptyDirs are tmpfs in the guest.
  - `/var/lib/docker` is a sparse ext4 image loop-mounted from the volume.
    overlayfs rejects virtio-fs as an upper layer, and tmpfs would put every
    image layer in pod memory.
  - Test "unreachable" claims only after proving the service is up: the first
    Docker API probe passed because the daemon was crash-looping.
- Honeytokens baked into every image: fake `~/.aws/credentials`, fake `.env`,
  fake enclave DSN in `/etc/hosts`, honeytoken hostname. Any touch = near-zero
  false-positive alert.
- No Kubernetes service account token mounted; any API-server request alerts.
- Admission enforces the boundary: a `ValidatingAdmissionPolicy` rejects any
  pod in a workspace namespace whose `runtimeClassName` is not
  `kata-clh-runtime-rs`. Removing other RuntimeClasses (k3s
  `--disable=runtimes`) shrinks the menu, but a pod with no class at all still
  runs on runc; only admission closes that. Built in Phase 2 with the first
  workspace namespace.

### Enclave namespaces (2, mock)

Postgres each, zero route from workspaces, reachable only via data-broker.
Two of them to prove the zone→enclave grant model scales past one.

## Zone model

`Zone` = named policy bundle: { Cilium policy, Envoy allowlist baseline,
broker scopes (which enclave brokers reachable), template defaults }.
A workspace joins exactly one zone. Stored in admin Postgres, materialized as
CiliumNetworkPolicy CRDs + Envoy xDS. MVP ships 2 workspace zones + 2 enclaves.

## Admin flow

1. Agent/dev hits non-allowed host → Envoy 403 with denied hostname and
   prefilled request link.
2. Request lands in sandcastle-admin queue; admin approves/denies in htmx UI.
3. Approval applies to that workspace's policy within seconds (xDS push +
   Cilium reconcile). Direct admin toggles also available.
4. Every change audited (who, what, workspace, when).

## Runaway controls

- Envoy per-workspace limits: requests/min, bytes/hour, unique destinations/hour.
- Circuit breaker: hard threshold flips workspace Cilium policy to deny-all and
  posts to the workspace terminal: "Egress suspended — rate limit exceeded.
  Details: <link>".
- Per-workspace inference tokens with daily ceilings as independent backstop.

## Detection

Falco (eBPF in guest, trimmed ruleset): honeytoken/credential-path reads;
`unshare`/`setns`/`mount`/`keyctl`/module load; new listening sockets; writes
outside project tree; new git remotes; any k8s API touch. Enclave-CIDR packets
page at highest severity. Proxy logs are the primary (higher-signal) stream.
All to Loki with workspace ID as join key.

## Red team / acceptance (redteam/)

Scripted hostile agent, CI-runnable, asserting **blocked** and **alerted** as
separate pass criteria: metadata-SSRF analog, k8s API probe, enclave route
attempts, DNS exfil, tunneling tools, DinD abuse, honeytoken sweep.

Injection evals: plant payloads in Gitea repos/issues, run OSS agent
(Aider/OpenCode) on Ollama, measure (a) honeytoken touch rate, (b) enclave
route attempts, (c) commits that would have reached an enclave via CI.

## Success criteria

- Zero successful egress to non-granted destinations across the suite.
- Every escape PoC blocked AND alerted (separate assertions).
- 100% of workspace→enclave packets page.
- Honeytoken touch rate measured with a number under injection evals.
- Allow-request → applied median well under a minute.
- `apt install` / `pip install` / `docker build` / git clone / desktop all work
  inside a contained workspace.

## Implementation phases

0. Scaffold: repo, spec, prerequisites (kubectl/helm/terraform).
1. Isolation substrate: k3s + Cilium + kata-deploy/CLH + gVisor class.
2. DX baseline: Coder + `base` template + DinD + Nexus mirror.
3. Containment core: no-default-route ×2 + Envoy gate + 403 flow.
4. Admin control plane: zones, request/approve, xDS, Cilium reconciler, UI.
5. Brokers + enclaves + inference: data-broker, cred-broker, Ollama ceilings.
6. Detection + response: Falco, honeytokens, Loki/Grafana, ratelimit, breaker.
7. Desktop template: Webtop/selkies websocket under Kata.
8. Red team + eval suite; hardening loop on findings.

Each phase ends with a scripted verify step under `infra/tests/`.

## Risks

- Kata+Cilium+k3s interplay — proven first in Phase 1 before anything stacks.
  Root cause of the first Cilium agent failure is still undiagnosed; it is
  reproduced inside the VM, where failure costs a snapshot revert.
- Lab VM capped at 10 vCPU / 20 GB so the host keeps headroom — small Ollama
  model, warm pool of 1.
- Ubuntu 26.04 guest has less upstream test coverage with Kata 4.1 and Cilium
  1.20 than 24.04. If substrate issues trace to the guest OS, rebuild the VM
  on 24.04 rather than debugging the kernel.
- Selkies perf under software render — acceptable to document as slow.
- xDS integration — use envoyproxy/go-control-plane, never hand-rolled.

## Production deltas (documented, not built)

Kata node pool taints; VPC-level second enforcement; real airlock with
scanning/provenance/approval role; artifact promotion gate with out-of-sandbox
signing; CI on clean checkout outside workspaces; freeze-and-snapshot response;
inference cluster as its own enclave (separate tenancy, no shared prompt logs,
signed weights); offline CVE feed + monthly image rebuild cadence.
