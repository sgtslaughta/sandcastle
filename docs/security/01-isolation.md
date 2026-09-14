# Isolation controls

Scope: the boundary between a workspace pod (where a developer, or the agent
acting inside their session, runs with full local root) and the node kernel,
the Kubernetes control plane, and the platform pods. Seven controls, C-ISO-1
through C-ISO-7. See [`README.md`](../../README.md) for the system overview
and the four-destination network invariant, covered separately in
`02-network.md`.

---

### C-ISO-1 Kata microVM per workspace pod (Cloud Hypervisor)

**Threat mitigated.** A runaway or hostile agent has root inside its
workspace container. Without a hardware-virtualized boundary, root in a
container is one kernel exploit away from root on the node, every other
workspace, and the cluster network. A shared-kernel escape (namespace bug,
cgroup bug, unpatched CVE) is the single highest-value target for such an
agent.

**Control.** Every workspace pod runs under the `kata-clh-runtime-rs`
RuntimeClass: Kata Containers 4.1.0 with the Rust runtime (`runtime-rs`) and
the Cloud Hypervisor VMM. Each pod gets its own guest kernel, not the node's.
Installed by `infra/bootstrap/02-kata-gvisor.sh` (kata-deploy Helm chart,
`k8sDistribution=k3s`, only the `clh-runtime-rs` shim enabled — the deprecated
Go/`qemu` shims are explicitly disabled to shrink the config surface).
Requested by the workspace Terraform template (`templates/base/main.tf`,
`runtime_class_name = "kata-clh-runtime-rs"`) and independently required by
admission (C-ISO-3). Verified by `infra/tests/01-isolation-substrate.sh`,
which boots a probe pod and asserts the guest-reported kernel version differs
from the host's — the test explicitly rejects "pod started" as proof and
requires a differing kernel. Result: containment suite 35/35 including this
check.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| gVisor only (no Kata) | Lighter weight, faster cold start, smaller guest image | User-space kernel intercepts syscalls but shares the host kernel for what it does not emulate; weaker isolation for a workload the platform must assume is hostile | Low (already staged, see C-ISO-2) | Syscall emulation gaps are a known escape class (runsc CVEs) |
| Firecracker microVM | Purpose-built for one-VM-per-workload, minimal device model, strong isolation record | Kata's Cloud Hypervisor path is already integrated with the chosen stack; Firecracker needs its own containerd shim and lacks Kata's virtio-fs/DinD story used here | Medium-high (new shim, new guest image pipeline) | Re-doing device passthrough and volume-sharing work already solved for Cloud Hypervisor |
| Plain runc + seccomp/AppArmor | Cheapest, fastest, no VMM overhead | Shared kernel; a kernel 0-day or a missed seccomp rule is a straight container-to-host escape; profile maintenance is ongoing and easy to under-scope | Very low | Highest — this is exactly the risk the control inventory exists to close |
| Full VM per workspace (no Kubernetes) | Maximum isolation, mature ecosystem (libvirt/KVM) | Loses Kubernetes scheduling, Coder's Kubernetes provisioner, and the admission/RBAC layers built on pod semantics; heavier per-workspace footprint | High (re-architect provisioning, template, and identity model) | Operationally new stack for the whole platform, not just isolation |
| Sysbox (container runtime with system-container features) | Docker-in-Docker and systemd support without privileged mode, no VMM | Still shares the host kernel by design; the DinD problem is already solved here at lower risk with a Kata-isolated sidecar (C-ISO-5) | Low-medium | Same class of risk as runc: no kernel boundary |

**Why this control.** The threat model in
`docs/superpowers/specs/2026-09-13-sandcastle-mvp-design.md` treats the agent
inside a workspace as hostile with root by design, not as an edge case. A
VMM-backed guest kernel is the only option in this list that removes the
shared-kernel escape class entirely rather than narrowing it. Cloud
Hypervisor was chosen over Firecracker because it is the shim Kata 4.1.0
ships as current (the Go/qemu shims are deprecated upstream since Kata 4.0),
and it is what the DinD sidecar design (C-ISO-5) and the workspace admission
policy (C-ISO-3) are built around. The lab is a single KVM VM
(`infra/vm/`, C-ISO-7), so a second layer of nested virtualization (Kata's
guest VMs run inside the lab VM) is a deliberate, tested configuration, not
an afterthought.

**Residual risk.**
- Cloud Hypervisor / KVM itself has an attack surface (VMM escape); no VMM is
  proven un-escapable. See `05-gaps-and-monitoring.md` for monitoring of
  guest-boundary anomalies.
- `privileged: true` inside the guest (used by the DinD sidecar, C-ISO-5) is
  safe only as long as `kata-deploy` keeps `privileged_without_host_devices`
  set; a kata-deploy config regression would silently widen this.
- Nested virtualization inside the lab VM is a lab-only property; production
  deployment on bare metal changes the trust chain and needs re-verification
  (see `06-enterprise-scale.md`).

---

### C-ISO-2 gVisor sibling RuntimeClass

**Threat mitigated.** None directly for workspace pods today — this control
mitigates the risk of only ever having one isolation technology validated
and ready. If Kata/Cloud Hypervisor became unavailable (upstream regression,
hardware without nested-virt support, a class of guest-escape bugs), the
platform would have no fallback isolation boundary already integrated and
tested.

**Control.** `runsc` (gVisor) is installed as a second, independent
`RuntimeClass` named `gvisor`, alongside `kata-clh-runtime-rs`, by the same
script (`infra/bootstrap/02-kata-gvisor.sh`). It is explicitly *not* nested
inside Kata — the script's own comment states that running `runsc` inside a
Kata guest "is not a documented or supported upstream configuration."
Verified by `infra/tests/01-isolation-substrate.sh`, which boots a probe pod
under `gvisor` and checks for the gVisor sentry kernel banner, and further
asserts that **no RuntimeClass other than these two exists** on the cluster
(`k3s --disable=runtimes` plus an explicit allowlist check) — closing the gap
where a third, unreviewed RuntimeClass could quietly appear.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Do not install gVisor | One less moving part, smaller attack surface to maintain | No validated fallback if Kata becomes unusable on a given node/host | None | Single point of failure on isolation technology |
| gVisor as the primary/only boundary | Faster cold start than a full VM, lower memory overhead | Weaker isolation guarantee than a VMM (see C-ISO-1 comparison); this platform's threat model treats workspace root as fully hostile | Low | Accepts syscall-emulation-class escapes as the platform's baseline |
| Nest gVisor inside Kata guests | Defense in depth (VM boundary + syscall filtering) | Not a supported upstream combination per the bootstrap script's own finding; would be operating on unverified ground | Unknown/high (upstream support gap) | Running unsupported configurations in a security boundary |

**Why this control.** `workspace-policy.yaml` (C-ISO-3) currently requires
`kata-clh-runtime-rs` specifically for workspace pods, so gVisor is not in
the workspace request path today — it exists installed, labeled, and
verified so that a future decision (e.g., a workload class that needs faster
cold-start with a lower isolation bar, or a Kata regression) has a
ready-made, tested option rather than an unreviewed one improvised under
pressure. This matches the lab's single-node constraint: keeping the
`RuntimeClass` menu short and explicitly enumerated is cheap insurance
against silent expansion of the pod-to-runtime attack surface.

**Residual risk.**
- gVisor is provisioned but has no consumer in the current template or
  admission policy; it could bit-rot (untested against newer workload
  images) without a workspace class exercising it regularly.
- The isolation-substrate test only checks that `runsc` starts and reports a
  gVisor kernel banner — it does not run the full containment suite (C-SUP-7)
  against a gVisor-backed pod.

---

### C-ISO-3 ValidatingAdmissionPolicy on the workspace namespace

**Threat mitigated.** A compromised or misconfigured Coder deployment (or an
operator error) creates a workspace pod that omits `runtimeClassName` and
lands on plain `runc`, or requests `hostNetwork`/`hostPID`/`hostIPC`/a
`hostPath` mount, any of which would give the agent a direct path to the
node — bypassing the Kata boundary (C-ISO-1) entirely regardless of what the
template intends.

**Control.** A Kubernetes `ValidatingAdmissionPolicy` +
`ValidatingAdmissionPolicyBinding`
(`platform/admission/workspace-policy.yaml`), bound only to namespaces
labeled `sandcastle.io/zone-type: workspace`, with `failurePolicy: Fail`. It
rejects any pod CREATE/UPDATE unless: `runtimeClassName ==
"kata-clh-runtime-rs"` exactly (not merely "some Kata class" — gVisor is also
rejected here, see C-ISO-2), `automountServiceAccountToken == false`, and
`hostNetwork`/`hostPID`/`hostIPC` are false/unset, and no volume has
`hostPath`. The policy's own header comment states its purpose precisely:
removing other RuntimeClasses from the cluster "shrinks the menu, it does not
close the door" — a pod with no `runtimeClassName` at all still defaults to
`runc`; this policy is the door. Applied by
`infra/bootstrap/03-platform.sh`. The Terraform template also sets
`runtime_class_name` explicitly (`templates/base/main.tf`) so the template is
"correct by construction," with admission as the enforced backstop rather
than the only check.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Rely on the Terraform template alone (no admission policy) | Simpler, one less object to maintain | Any path that creates a pod directly (kubectl, a bug in Coder's provisioner, a future template) bypasses it entirely | None | Single point of failure; template correctness is not enforced |
| OPA Gatekeper / Kyverno instead of native VAP | Richer policy language, wider ecosystem, no CEL learning curve | Extra controller to deploy, watch, and patch; native VAP (GA since k8s 1.30) needs no extra component and the constraint set here is simple boolean logic that CEL expresses directly | Medium (new admission controller lifecycle) | New component in the admission path is itself a new failure/bypass surface |
| PodSecurityAdmission (baseline/restricted) standard | Built into Kubernetes, zero extra objects | Does not have an opinion on `runtimeClassName`, which is the control's core requirement; would need to be paired with something else anyway | Low, but insufficient alone | Leaves the primary gap (runc fallback) open |
| Mutating webhook that force-sets fields instead of rejecting | Self-healing instead of rejecting | Silently overriding a workload's declared intent hides misconfiguration instead of surfacing it; a bug in the webhook fails open unless carefully designed | Medium | Mutating admission is a broader blast radius if compromised than a pure validator |

**Why this control.** DR-3.x in
`docs/superpowers/specs/2026-09-13-phase3-containment-core-design.md`
establishes defense-in-depth as the platform's operating principle (see
DR-3.2's "second independent layer" reasoning for network egress, applied
here to runtime selection). Native `ValidatingAdmissionPolicy` was preferred
over a third-party admission controller because the rule set is small,
static, and expressible in CEL without adding a new controller to the
cluster's own trust boundary — fewer moving parts matters more in a
single-node lab than policy-language flexibility.

**Residual risk.**
- `failurePolicy: Fail` means an API-server or webhook-evaluation outage
  blocks workspace pod creation (fail closed) — availability risk, not a
  security gap; see `05-gaps-and-monitoring.md`.
- The policy governs pod *creation/update*; it does not re-validate an
  already-admitted pod if the admission plugin were later disabled cluster-wide.
- Binding is scoped by namespace label (`sandcastle.io/zone-type: workspace`)
  — mislabeling a namespace would silently exempt it from the policy.

---

### C-ISO-4 No Kubernetes credentials or API reach from workspaces

**Threat mitigated.** A workspace with a mounted service-account token, or
with Coder-side permission to touch other Kubernetes resources, could use
that credential to read secrets, list pods across namespaces, or escalate via
the Kubernetes API — sidestepping the Kata/network boundary by going through
a trusted control-plane path instead of the data plane.

**Control.** Three independent settings converge on the same outcome: (1)
`automountServiceAccountToken: false` is set in the Terraform template
(`templates/base/main.tf`) *and* required by the admission policy (C-ISO-3),
so no service-account token is ever mounted into a workspace pod; (2) Coder's
Helm values (`platform/coder/values.yaml`) set `workspacePerms: false`; (3)
the only RBAC touching the workspace namespace,
`platform/coder/workspace-rbac.yaml`, grants the `coder` ServiceAccount (in
the `coder` namespace, not the workspace's) a narrowly scoped Role — pods,
pod logs/exec, PVCs, deployments, events; no secrets, no ServiceAccounts, no
cluster-wide verbs — and that Role belongs to Coder's own control-plane
identity, never to a workspace pod. The workspace network policy also drops
any packet toward the Kubernetes API server (verified: `infra/tests/03-containment.sh`
blocks `10.43.0.1:443`, the ClusterIP for `kube-apiserver`).

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Mount a read-only, narrowly scoped token per workspace | Lets a workspace introspect its own pod state | Any token is a credential to steal; "read-only" RBAC still discloses more than the current zero-trust posture, and value to a legitimate developer is low (Coder already exposes `coder stat`) | Low-medium (per-workspace RBAC objects) | New credential class inside a hostile-by-default execution environment |
| Rely on network policy alone (skip automount / workspacePerms) | Fewer settings to configure | A token would still be readable from the filesystem even if network-blocked; defense-in-depth is lost, and a policy misconfiguration becomes a full compromise instead of a partial one | None | Removes a redundant, independent layer |
| Give workspaces their own dedicated low-privilege ServiceAccount instead of none | Slightly more "normal" Kubernetes pattern, easier per-workspace auditing via SA identity | Any non-empty RBAC surface for a hostile-by-design workload is strictly worse than none, for no functional gain the template currently needs | Medium | Broadens the API attack surface for no exercised feature |

**Why this control.** The MVP design treats "no route to the control plane"
as a first-class invariant, mirrored in the network invariant documented in
`README.md` (workspaces reach exactly four destinations, none of which is
the API server). Stacking the token-automount setting, the Coder permission
flag, and namespace-scoped RBAC means a single misconfiguration in any one
layer does not by itself grant API access — consistent with the multi-layer
approach used for network egress (C-NET-1/C-NET-11) and runtime selection
(C-ISO-1/C-ISO-3).

**Residual risk.**
- `workspacePerms: false` is a Coder-side setting; a Coder upgrade that
  changes its semantics needs to be re-verified against this control.
- RBAC review is manual today — no automated diff-on-change check that
  `workspace-rbac.yaml` still grants only the listed verbs/resources.

---

### C-ISO-5 Docker-in-Docker sidecar inside the same Kata VM, API on localhost only

**Threat mitigated.** Developers need `docker build`, which normally means
either mounting the host's Docker socket (full host compromise from any
workspace) or running a privileged sibling container reachable over the
network (lateral movement / unauthenticated Docker API exposure, a
well-known class of internet-scanned compromise).

**Control.** The `dind` container runs as a second container in the *same*
pod as the workspace (`templates/base/main.tf`), meaning it shares the same
Kata guest VM and guest kernel as the `dev` container — `privileged: true`
here reaches only the guest kernel, not the node, because `kata-deploy`
configures the shim with `privileged_without_host_devices`. The Docker API is
exposed only on a `unix:///run/dind/docker.sock` socket, on a `Memory`-medium
(tmpfs) `emptyDir` shared between the two containers — never TCP; the
template's own comment explains that `dockerd`'s default entrypoint would
otherwise bind `tcp://0.0.0.0:2375` (unauthenticated root API on every pod
interface) if invoked without an explicit `dockerd` argument list. Image
pulls go through the Nexus Docker Hub proxy (`--registry-mirror`, classic
image store to force mirror-or-fail rather than a Hub fallback) — see
`04-supply-chain-ops.md` C-SUP-1/C-SUP-2. Verified end-to-end by
`infra/tests/03-containment.sh` ("docker build via Nexus registry mirror",
"Nexus docker-hub served busybox").

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Mount host Docker socket | Simplest, no sidecar | Root-equivalent host access from any workspace — defeats every other isolation control | None | Total compromise of the isolation model |
| DinD as a separate pod, reached over the pod network | Slightly cleaner separation of container images | The Docker API must then be network-reachable (TCP), which is exactly the exposure this control avoids; also loses "same VM" guarantee, needs its own admission/network exceptions | Medium | Reintroduces network-exposed unauthenticated root API |
| Rootless Docker / Podman in the dev container (no sidecar) | No `privileged` container at all | Rootless storage drivers and networking have real compatibility gaps with existing developer workflows (build caches, some base images, bind mounts); would need re-validation for every workflow this platform supports | Medium-high | Functional regressions more than security regressions, but untested against this platform's build workloads |
| Sysbox-based system containers instead of privileged DinD | No `privileged` flag needed for nested Docker | Still shares the host/guest kernel via a different mechanism; does not remove the sidecar-vs-integrated-runtime trade-off, and is a new runtime component to validate | Medium | New, less-exercised runtime in the isolation-critical path |

**Why this control.** The Kata VM boundary (C-ISO-1) is what makes
`privileged: true` acceptable here at all — the template's comment is
explicit that this is safe *because* it is inside a Kata guest, not despite
it. Keeping the Docker API on a unix socket rather than TCP removes an entire
class of exposure regardless of network policy, which is the kind of
belt-and-suspenders reasoning DR-3.2 applies elsewhere. This was chosen over
rootless alternatives because it reuses infrastructure the lab had already
validated (Kata + Nexus mirror) rather than introducing an unvalidated
rootless storage stack under a Phase 3 deadline.

**Residual risk.**
- `privileged: true` is a strong flag; its safety is entirely contingent on
  `kata-deploy`'s `privileged_without_host_devices` setting remaining correct
  — a kata-deploy config drift would silently reintroduce host device access.
  See `05-gaps-and-monitoring.md`.
- The shared `emptyDir` volume for the docker backing store
  (`docker`, 25Gi, default medium) is a virtio-fs share into the guest, not
  memory-backed; only the socket volume needs (and gets) `Memory` medium.

---

### C-ISO-6 Hardened platform pods (non-root, read-only root fs, drop ALL caps, no token where unneeded)

**Threat mitigated.** A compromise of a platform component (Envoy egress
gate, sandcastle-admin) that runs with default container privileges could
escalate to root-in-container, write malware to its own filesystem for
persistence, or use an unneeded service-account token to reach the
Kubernetes API — turning one bug into a much larger foothold than the
component's actual job requires.

**Control.** Platform pods that terminate untrusted or internet-facing
traffic run with `runAsNonRoot: true`, a fixed numeric `runAsUser`,
`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, and
`capabilities: {drop: ["ALL"]}`. Confirmed in `platform/egress/envoy.yaml`
(`runAsUser: 101`, Envoy's own non-root UID) and `platform/admin/admin.yaml`
(the `sandcastle-admin` container, `runAsUser: 65532`, the conventional
distroless "nonroot" UID, chosen numerically so kubelet can verify it without
resolving `/etc/passwd`). `automountServiceAccountToken: false` is set
explicitly on pods that need no Kubernetes API access at all (Envoy, the
`admin-db` Postgres StatefulSet); the `sandcastle-admin` pod itself keeps its
token because its job requires the Kubernetes API (C-ADM-13 in
`03-admin-plane.md`) — "no token where unneeded" is applied selectively, not
uniformly.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Default Kubernetes pod security (no explicit securityContext) | Zero extra YAML | Root-in-container by default for most images; writable root filesystem gives an attacker a place to stage tools; full Linux capability set is rarely needed | None | Materially larger blast radius per compromised platform pod |
| PodSecurity `restricted` admission profile cluster-wide | Enforced automatically, no per-manifest duplication | Some platform images (Nexus StatefulSet needs `fsGroup`, various volume ownership needs) may not run unmodified under `restricted`; would need per-namespace exemptions anyway, converging back to explicit manifests for the components that matter most | Medium | A blanket profile can silently block legitimate workloads or, if exempted broadly, provide false assurance |
| Distroless/scratch images only, no hardening flags | Reduces in-image attack surface (no shell, no package manager) | Orthogonal to runtime hardening — a distroless image can still run as root with a writable filesystem and full capabilities if the pod spec does not say otherwise | Low-medium (image rebuild) | None added, but does not substitute for the pod-spec controls actually in place |

**Why this control.** These settings target exactly the platform pods that
sit on a trust boundary — Envoy terminates all workspace-originated egress
traffic, sandcastle-admin holds Kubernetes RBAC and DB credentials — so a
container escape or RCE in either is worth minimizing independently of the
Kata/network layers that protect workspaces themselves. Nexus and the
Postgres StatefulSets are less hardened in this specific set of flags
(Nexus needs `fsGroup` for its data volume) because they are not on the
same untrusted-input boundary; least-privilege effort was spent where the
threat model calls it out.

**Residual risk.**
- Not every platform pod has the full flag set (Nexus specifically has only
  `fsGroup`); a compromise there has a larger blast radius than Envoy or
  admin. See `05-gaps-and-monitoring.md`.
- `readOnlyRootFilesystem: true` does not prevent memory-resident attack
  persistence for the lifetime of the pod; it only removes filesystem
  persistence across restarts.

---

### C-ISO-7 Lab isolation: cluster inside a VM, never on the host

**Threat mitigated.** Standing up Cilium, Kata, and aggressive egress
policy directly on a shared or remote-managed host risks stranding that
host's own network access — Cilium's kube-proxy replacement and BPF-based
policy can conflict with a host's existing networking stack (observed in
this project: an earlier Cilium install on the host stranded it, per project
memory). Running the entire lab inside a disposable VM means a
misconfiguration is reversible and cannot take down the host it runs on.

**Control.** `infra/vm/00-host-libvirt.sh` is explicitly the *only* script
that touches the host, and only to install libvirt/KVM and start a NAT
`default` network — its own comment states it "never touches the physical
NIC ... never creates a bridge." Every subsequent bootstrap step
(`infra/bootstrap/*.sh`) runs inside the lab VM. `infra/vm/sandcastle-vm.sh`
manages the VM's lifecycle including internal snapshots
(`snapshot`/`revert`/`snapshots` subcommands) so risky steps can be rolled
back (also used by C-SUP-6). A second, independent host-level control,
`infra/vm/01-host-egress-nft.sh`, adds an nftables table scoped only to the
lab's virtual bridges (`virbr0`, `virbr-sce`) — the script's own comment notes
this scope is deliberately narrow ("this cannot strand the host the way the
first Cilium install did"). Verified by `infra/tests/00-host-preflight.sh`
and the `verify` subcommand of `01-host-egress-nft.sh`, which checks every
firewall rule matches only the lab bridge interfaces.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Run k3s/Cilium directly on the host | No virtualization overhead, simpler networking | Directly caused a prior host-network outage in this project (Cilium's kube-proxy replacement conflicting with host networking); no easy rollback of a broken CNI install | None (but already tried and rejected) | Host outage, no isolation between "lab experiment" and "the machine you're using" |
| Cloud VM / dedicated lab hardware instead of local KVM | No shared-host risk at all | Loses the air-gapped, fully local lab property the stack facts call out; adds cost and network dependency for a stage meant to validate the isolation model itself | Medium (infra to provision) | Different trust model to validate before this one is even proven |
| Container-based "cluster in Docker" (kind/k3d) on the host | Very fast to stand up, common CI pattern | Cannot host Kata guests (nested virtualization/VMM needs are awkward or unsupported inside another container runtime), which is the exact thing this lab exists to validate | N/A — not compatible with the isolation stack under test | Would not actually test Kata/Cloud Hypervisor at all |

**Why this control.** This decision predates and enables every other control
in this file: none of Kata, Cilium, or the admission policy can be
soundly evaluated if the evaluation itself is allowed to damage the host
running it. The project's own history (documented in the session's working
memory: "host is remote-streamed GAME-01; Cilium on host stranded it") is the
direct justification, not a hypothetical. `infra/vm/sandcastle-vm.sh`
snapshot/revert makes iteration cheap even when a step genuinely does break
something, since the blast radius is the disposable VM's disk image, not the
host.

**Residual risk.**
- Nested virtualization (Kata's guest VMs running inside the lab VM) is a
  lab-only property that does not carry over unchanged to bare-metal
  production; see `06-enterprise-scale.md` for the production delta.
- The host nftables lock (`01-host-egress-nft.sh`) is explicitly **not
  persistent across host reboots** per its own comment — an operator who
  reboots the host and forgets `make egress-lock` runs unlocked. The
  containment test suite fails while unlocked, which surfaces this, but only
  the next time the suite runs. See `05-gaps-and-monitoring.md`.
