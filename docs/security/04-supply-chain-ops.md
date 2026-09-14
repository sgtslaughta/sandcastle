# Supply-chain and operational controls

Scope: how packages, container images, and tools reach a workspace, and how
day-to-day platform operations (image builds, bootstrap, verification) avoid
becoming their own attack path. Eight controls, C-SUP-1 through C-SUP-8. See
[`README.md`](../../README.md) for the system overview; network enforcement
of these paths is covered in `02-network.md`, and workspace runtime isolation
in `01-isolation.md`.

---

### C-SUP-1 Nexus as the single package mirror (apt, PyPI, npm, Docker Hub proxy)

**Threat mitigated.** Without a mirror, a workspace's package managers
(`apt`, `pip`, `npm`) would need direct internet reach to a wide,
ever-changing set of upstream hosts — each one a potential exfiltration
channel and each one requiring its own egress allowlist entry. A compromised
or malicious package (typosquat, dependency-confusion, compromised
maintainer account) is also a standing supply-chain risk regardless of the
network path.

**Control.** Nexus Repository 3.96.1 CE (`platform/nexus/nexus.yaml`) runs
as a single StatefulSet exposing two ports: 8081 for the apt/PyPI/npm
proxy repositories, 8082 dedicated to the Docker Hub registry-mirror
connector (a mirror must be served at the root of its own `host:port`, so it
gets its own listener rather than a `/repository/` path).
`platform/nexus/configure.sh` provisions `apt-ubuntu` (proxying
`archive.ubuntu.com`), `pypi-proxy` (`pypi.org`), `npm-proxy`
(`registry.npmjs.org`), and `docker-hub` (`registry-1.docker.io`), each with
Nexus's negative-cache and auto-block settings enabled. The workspace image
(`images/base/mirror/etc/{npmrc,pip.conf,apt/sources.list.d/ubuntu.sources}`)
points every package manager at Nexus by default — copied into the image
*after* `apt-get install` of build tooling, so the image itself still builds
against public mirrors on the host, but every running workspace only knows
the in-cluster Nexus address. The workspace network policy admits Nexus as
one of the four reachable destinations (`02-network.md` C-NET-1), so this is
enforced at two layers: default configuration and network policy. Verified
by `infra/tests/03-containment.sh` ("apt via Nexus", "pip via Nexus", "npm
via Nexus", "docker build via Nexus registry mirror").

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Direct internet access per package manager, network-policy allowlisted per upstream host | No mirror to operate, always latest upstream content | Each upstream host (archive.ubuntu.com, pypi.org, npmjs.org, and their CDNs) is a separate, CDN-churning allowlist entry — brittle and a wider exfil surface; no offline/air-gapped operation | Low upfront, high ongoing (allowlist maintenance) | Larger, harder-to-audit egress surface; breaks the air-gap goal |
| Per-language mirrors (devpi for PyPI, Verdaccio for npm, apt-mirror for apt), no unified tool | Lighter-weight per component | Three+ services to run, patch, and monitor instead of one; three different admin models and auth systems | Medium-high (multiple services) | More components on the trust boundary, more upgrade/CVE surface overall |
| No mirror; vendor all dependencies into images at build time | Zero runtime network dependency for packages | Impractical for interactive development (arbitrary `apt install`/`pip install` during a session is a stated workflow); image rebuild required per dependency change | High (workflow change) | Loses the core "real workspace, real tools" product requirement |

**Why this control.** The MVP design's core invariant (`README.md`) is that
a workspace reaches exactly four destinations; collapsing every package
source into one hostname is what makes that invariant achievable without
constantly editing the egress allowlist as upstream CDNs change IPs. Nexus
CE was chosen because it is free, self-hosted, and covers all three package
ecosystems plus a Docker registry mirror in one component — fewer things to
patch and monitor in a single-operator lab.

**Residual risk.**
- Nexus itself becomes a single point of trust: a compromised Nexus instance
  could serve tampered packages to every workspace. See
  `05-gaps-and-monitoring.md`.
- `configure.sh`'s repository-create payloads are modeled on documented
  Nexus API shapes, not fetched live from the running server's own schema;
  the script's own comment flags this and recommends checking
  `swagger.json` on first run — a version drift in the Nexus REST API could
  silently produce a misconfigured repo.
- No package signature verification or vulnerability scanning is layered on
  top of the proxy today (`npm audit`/`fund` are explicitly disabled, see
  C-SUP-3) — the mirror controls *path*, not *content trust*.

---

### C-SUP-2 dockerd registry mirror + classic image store (no direct Docker Hub contact)

**Threat mitigated.** A workspace's Docker daemon pulling images directly
from Docker Hub bypasses the package-mirror control above entirely for
container images, and is a common route for malicious/typosquatted public
images.

**Control.** The DinD sidecar (`templates/base/main.tf`, container `dind`)
is started with `--registry-mirror=http://nexus.sandcastle-mirror.svc.cluster.local:8082`
and `--feature=containerd-snapshotter=false` (the classic image store). The
template's own comment explains why the feature flag matters: Docker 29's
default containerd-backed snapshotter treats the mirror and Docker Hub as one
host list and will contact Hub directly even when the mirror could serve the
pull — silently defeating the mirror and producing an unexplained policy
drop instead of a clean fetch. The classic store only falls back to Hub if
the mirror itself fails, which then surfaces as a real, actionable signal
under the network policy rather than a routine background contact. Verified
by `infra/tests/03-containment.sh` ("docker build via Nexus registry mirror",
"Nexus docker-hub served busybox" — checked by grepping Nexus's own request
log for pulls).

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| containerd-snapshotter default (Docker 29 default) | Newer default, image store shared with containerd proper | Confirmed in this codebase's own template comment to contact Docker Hub directly alongside the mirror, defeating the point of the mirror | None (it's the default) | Silent, hard-to-detect exfil/tamper path — this is the reason the control exists |
| Docker Hub allowed directly through the egress proxy (no mirror for images) | No registry-mirror flag to maintain | Reintroduces Docker Hub as a fifth destination, breaking the four-destination invariant; loses image caching benefits | Low | Widens the egress surface; each image pull is a fresh outbound path to audit |
| Self-hosted registry (Harbor, plain `registry:2`) instead of Nexus's Docker proxy | Purpose-built registry features (scanning, RBAC per repo) | Yet another component alongside Nexus, which already covers apt/pip/npm; duplicate operational burden for one more ecosystem | Medium | More components in the trust boundary |

**Why this control.** This is a direct, code-verified example of a
spec/implementation subtlety that would otherwise go unnoticed: the fix here
exists specifically because the *default* Docker behavior undermines the
Nexus mirror control (C-SUP-1) for images. Keeping images inside the same
Nexus instance as the other three package types was cheaper than running a
dedicated image registry, given the lab's single-operator constraint.

**Residual risk.**
- `--insecure-registry` is set for the Nexus docker-hub proxy (plain HTTP,
  in-cluster only); acceptable inside the cluster network but would need TLS
  if Nexus were ever reachable from outside the workspace network boundary.
- No image-content scanning at the mirror layer (see C-SUP-1's residual
  risk) — the mirror guarantees *path*, not that pulled images are free of
  known vulnerabilities.

---

### C-SUP-3 Tool telemetry off in images (npm audit/fund)

**Threat mitigated.** Tooling telemetry and "helpful" background calls
(`npm audit`, `npm fund`) contact external endpoints outside the declared
four-destination path, which would either be silently blocked (adding noise
that obscures real denial signals — see C-NET-13) or, if inadvertently
allowed, leak project/dependency metadata off the box.

**Control.** `images/base/mirror/etc/npmrc` sets `audit=false` and
`fund=false` globally for every workspace, with the file's own comment
explaining the underlying constraint precisely: `npm audit` POSTs the
dependency tree to the configured registry for advisory matching, Nexus CE
does not implement that audit endpoint, and workspace network policy refuses
writes to Nexus (C-NET-3, GET/HEAD-only) — so every `npm install` would
otherwise log a policy drop for a feature that cannot function here anyway.
Baked into the base image (`images/base/Dockerfile`, `COPY mirror/ /`).

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Leave npm defaults on, accept the resulting policy drops | No image change | Every `npm install` generates a drop that must be triaged as "known noise," directly undermining the alert-hygiene goal behind C-NET-13 | None | Alert fatigue; a real drop is easier to miss in the noise |
| Run a vulnerability-scanning proxy (e.g., point audit at a real advisory mirror) | Restores the intended npm-audit feature | No such service is deployed in this stack; would be new infrastructure and a new egress destination, contradicting the four-destination invariant unless routed through Nexus (which does not support it in CE) | Medium-high | New component and/or new allowed destination |
| Block only the specific audit/fund endpoints at the network layer, leave npm config default | Configuration stays "vanilla" | Functionally identical outcome to disabling it in config, but achieved by adding network-policy exceptions/denials instead of a one-line config change — more moving parts for the same result | Low-medium | No added risk, but strictly more complex than the chosen approach |

**Why this control.** This is a minimal, config-only fix scoped exactly to
the actual constraint (Nexus CE lacks the audit API, and policy would block
the write regardless). It keeps the "noise budget" described in
`docs/superpowers/specs/2026-09-13-phase3-containment-core-design.md`
narrow and enumerable (C-NET-13), which is what makes "any other drop is
unexplained, and must page" an operationally sane alerting rule.

**Residual risk.**
- Disabling `npm audit` means workspaces get no local dependency-vulnerability
  signal at all; this is a gap, not just a config choice — see
  `05-gaps-and-monitoring.md` for whether a scanning stage belongs elsewhere
  in the pipeline (e.g., at image build or Nexus policy level).
- Only npm's telemetry is addressed; other tools installed ad hoc inside a
  workspace (pip's own telemetry, language-specific package manager
  "phone-home" behavior) are not inventoried or suppressed by this control.

---

### C-SUP-4 Images built on host, imported to containerd, pinned versions, imagePullPolicy Never

**Threat mitigated.** A registry pull path (even an internal one) is a place
where an attacker who can influence DNS, MITM traffic, or compromise a
registry could substitute a malicious image at deploy time. Floating tags
(`latest`, unpinned base images) also make "what code is actually running"
unauditable and let an upstream image change silently change behavior on the
next pod restart.

**Control.** There is no image registry in the lab (`images/build-import.sh`'s
own comment: "The Nexus OCI proxy replaces this path once it exists").
Instead, `images/build-import.sh` builds `sandcastle/base` and
`sandcastle/dind` on the host with `docker build`, then `docker save`s the
image and pipes it directly into the lab VM's k3s containerd namespace
(`sudo k3s ctr -n k8s.io images import -`), verifying the import by name
afterward. Workspace and admin pods set `imagePullPolicy: Never`
(`templates/base/main.tf`, `platform/admin/admin.yaml`), so a pod can only
ever run the exact image bytes that were explicitly imported — there is no
pull path for a pod to substitute a different image at schedule time. Image
tags are pinned version strings (`sandcastle/base:0.2.0`,
`sandcastle/admin:0.4.0`), not `latest`. The same pattern is used for the
admin image (`make admin-image`, `Makefile`).

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Stand up an in-cluster registry (Nexus Docker-hosted repo or Harbor) now | Normal Kubernetes deployment pattern, works with `imagePullPolicy: IfNotPresent` and multi-node scheduling | Extra component to secure (registry auth, TLS) for a single-node lab that does not need pod rescheduling across nodes yet; deferred deliberately per the script's own comment | Medium | A registry with weak auth is itself a supply-chain target |
| Push to a public registry with content trust / image signing (Notary, cosign) | Strong provenance guarantees, standard in mature supply-chain security | Requires external connectivity or a private signing/verification service, at odds with the air-gapped lab; premature for a single-node lab | High | New key management surface to secure and back up |
| `imagePullPolicy: IfNotPresent` with locally built images | Slightly less rebuild-on-every-change friction | Reintroduces ambiguity about which image bytes are actually running if a stale local copy exists under the same tag; `Never` is stricter and matches "no registry" reality | None (policy choice) | Risk of running unintended cached image versions |

**Why this control.** This matches the lab's single-node, no-registry
reality rather than building registry infrastructure the current phase does
not need — consistent with the "production delta" framing used throughout
the specs (defer infrastructure that doesn't change what's being validated).
`imagePullPolicy: Never` plus pinned tags closes the "what's actually
running" question without needing signing infrastructure: the only way an
image reaches the cluster is the explicit, auditable import script.

**Residual risk.**
- `Never` + host-side `docker build` means image provenance depends entirely
  on the operator's own host being trustworthy at build time — there is no
  independent attestation step.
- Multi-node scaling (see `06-enterprise-scale.md`) cannot use this pattern
  as-is: every node would need the image imported locally, or a real
  registry becomes mandatory at that point.

---

### C-SUP-5 Admin-controlled workspace template (labels used as identity, proxy env, NO_PROXY, sidecar args)

**Threat mitigated.** If developers could freely edit their own workspace
Terraform template, they could remove the runtime class, add a hostPath
mount, disable the proxy environment variables, or otherwise dismantle every
other control in this document from inside the one place meant to configure
their own workspace.

**Control.** `templates/base/main.tf` is a single, admin-managed Terraform
template (pushed via `coder templates push`, not self-service). It sets
identity-bearing labels used elsewhere for enforcement — Coder's standard
`com.coder.workspace.id`/`com.coder.user.id` labels on both the PVC and the
Deployment, which Phase 4's admin plane reads via pod labels to resolve a
source IP to a workspace (DR-3.5, `05-admin.sh`/`admin/internal`). It hard-codes
`runtime_class_name = "kata-clh-runtime-rs"`, `automount_service_account_token
= false`, the proxy environment (`HTTP_PROXY`/`HTTPS_PROXY` pointing at the
Envoy egress gate, both upper- and lower-case since "curl reads only
`http_proxy` for plain HTTP, and tools disagree on which case they honor,"
per the template's own comment), and `NO_PROXY` scoped to `.cluster.local`
plus the Coder access-URL host (the one exception needed so the Coder agent
can reach coderd directly for its own tunnel, per DR-3.1). It also hard-codes
the `dind` sidecar's exact `dockerd` arguments (registry mirror, classic
store, unix socket only) — a developer cannot pass their own dockerd flags.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Let developers author or fork their own templates | More flexibility, faster iteration on workspace shape | Every one of the settings above is a control from this document; self-service templates would need their own admission-time enforcement to not be an opt-out button for the whole platform | High (would need template-level policy enforcement, largely redundant with C-ISO-3) | Direct bypass path for every template-level control |
| Template parameters exposed for the security-relevant fields (e.g., toggle DinD, toggle proxy) | Some self-service without full template access | Any exposed toggle for a security control is a toggle an agent or a careless developer could flip; the only currently exposed parameter is `home_disk_size`, a capacity setting with no security implication | Low per parameter, but erodes the model over time | Each added toggle is a new thing that must be re-reasoned about |
| Enforce these settings purely via admission policy, allow arbitrary templates | Templates become advisory, policy is authoritative | Admission already enforces the isolation-critical subset (C-ISO-3); it does not and reasonably cannot enforce proxy env vars, DinD args, or labels used for admin identity — those need the template to cooperate | Medium (would need a much larger CEL/webhook surface) | Either an enormous admission policy, or accepting these fields as template-trust-only |

**Why this control.** Admission (C-ISO-3) enforces the subset of settings
that Kubernetes itself can validate structurally (runtime class, host
namespaces, hostPath, token automount). The rest — proxy configuration, DinD
arguments, identity labels — are Terraform-level and only enforced by
restricting who can push a template at all. This mirrors the RBAC design
(C-ISO-4): Coder's own template-push permission is the actual boundary, so
keeping template authorship admin-only is treated as equivalent in
importance to the RBAC and admission controls it complements.

**Residual risk.**
- Nothing currently re-verifies at pod-admission time that a *running*
  workspace's environment variables still match the template's intent — a
  future template edit or a Coder bug could silently drop the proxy env vars
  without an admission-level check catching it.
- Identity labels (`com.coder.workspace.id`, etc.) are set by Coder's own
  provisioner, not independently re-derived; a bug in Coder's labeling is a
  single point of failure for admin identity resolution (see
  `03-admin-plane.md`, C-ADM-9).

---

### C-SUP-6 Bootstrap egress toggle (lock/unlock) + VM snapshots before risky changes

**Threat mitigated.** Bootstrap steps (installing k3s, Cilium, Kata,
pulling Helm charts and container images) inherently need broad internet
access from the lab VM's primary interface — the same interface the
containment model otherwise locks down. Running bootstrap under the full
host egress lock would fail; running the platform permanently unlocked would
leave the "isolated except via the egress gateway" invariant unverified and
unenforced during normal operation.

**Control.** `infra/vm/01-host-egress-nft.sh lock|unlock` toggles the host
nftables table described in C-ISO-7. The `Makefile` targets that perform
bootstrap (`cluster`, `kata`, `platform`, `containment`, `admin`) are
documented to require `egress-unlock` first, and
`infra/tests/03-containment.sh`'s own comment states plainly: "test fails
while unlocked" — the containment verify suite is itself the mechanism that
forces the lock back on before anyone can claim the lab is in its secure
state. Independently, `infra/vm/sandcastle-vm.sh snapshot` is called before
each risky bootstrap phase (`pre-cilium`, `pre-kata`, `pre-platform`,
`pre-containment`, `pre-admin` — see `Makefile`), so a bad step can be rolled
back with `vm-revert` rather than requiring a full lab rebuild. DR-3.7 in
`docs/superpowers/specs/2026-09-13-phase3-containment-core-design.md`
records this as a deliberate trade-off ("node image pulls and downloads use
the primary IP; a toggle is honest and small").

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Route node/Helm/image pulls through Nexus now, keep the lock always on | No toggle to forget; matches production posture more closely | Nexus does not yet proxy Helm charts or OS-level installer downloads (kata-deploy tarball, k3s installer, gVisor binaries); building that out was judged more scope than the current phase needs | Medium-high | None directly, but scope creep risk for the current phase |
| Always-on allowlist of the specific bootstrap-time registry/CDN IPs | No manual toggle step | These CDNs (GitHub Releases, Helm repos, Google Cloud Storage for gVisor) change IPs and ranges over time — a static allowlist would need constant upkeep and is itself a standing leak path even when not bootstrapping | Medium (ongoing maintenance) | A permanently-present allowlist is a permanently-present bypass surface |
| Perform bootstrap entirely outside the lab VM's normal network (separate bootstrap-only VM/image, promote afterward) | Cleanest separation of "install" vs "run" | Substantially more infrastructure (VM imaging pipeline) for the current single-operator, single-VM lab | High | New pipeline to build and validate |

**Why this control.** The DR-3.7 record is explicit that this is a
deliberate, documented compromise, not an oversight, weighed against the
cost of a bootstrap-time registry mirror. Making the test suite itself
enforce "locked" as a precondition for a passing containment result is what
keeps this from silently regressing into "usually unlocked" during active
development.

**Residual risk.**
- The lock is **not persistent across host reboots** (see C-ISO-7's residual
  risk) — an operator must remember `make egress-lock` after every host
  reboot; nothing pages on an unlocked-but-idle state, only on the next test
  run. See `05-gaps-and-monitoring.md`.
- The unlock window during bootstrap has no independent audit log of what
  the VM actually contacted while unlocked, beyond whatever the bootstrap
  scripts print.

---

### C-SUP-7 Verification suites as controls: every escape must be blocked AND visible (positive controls gate negatives)

**Threat mitigated.** A network or isolation control that silently fails
open is worse than one that was never built, because it creates false
confidence. Equally, a "blocked" result that only proves the target was
unreachable for an unrelated reason (target down, workspace has no network
at all) proves nothing about the control under test.

**Control.** Each phase has a paired verification script under
`infra/tests/` (`00-host-preflight.sh`, `00-node-preflight.sh`,
`01-isolation-substrate.sh`, `02-dx-baseline.sh`, `03-containment.sh`,
`04-admin.sh`) that is treated as part of the control, not an optional
afterthought. `03-containment.sh`'s own header states the principle
directly: "Positive controls run first and gate the blocked checks:
'unreachable' proves nothing if the target was down or the workspace had no
network at all" — citing a real prior incident in the same comment (a Phase 2
Docker API probe that "passed" only because dockerd was crash-looping). The
suite runs allowed operations first (coder ssh, code-server health, apt/pip/
npm/docker via Nexus) and only then asserts that disallowed paths are both
blocked and produce the expected signal (403 with `x-sandcastle-denied`,
ICMP-fast-fail timing, DNS refusal) — never a bare "the connection failed."
A further check asserts that all drops during the *allowed* workflow match
only three known, named agent-probe signatures (C-NET-13's "noise budget"),
so an unrecognized drop during otherwise-normal work fails the suite instead
of being silently accepted. Verified totals as of 2026-09-13: containment
suite 35/35, admin suite 39/39, Phase 1 regressions 9/9, Phase 2 regressions
18/18.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Manual, ad hoc verification per change | No test infrastructure to maintain | Not repeatable, easy to skip under time pressure, exactly the kind of gap that let the "dockerd crash-looping" false pass happen once already | Low upfront, high ongoing risk | Regressions ship unnoticed |
| "Negative-only" tests (assert denials, skip positive controls) | Fewer assertions, faster suite | Cannot distinguish "control is working" from "everything is broken"; this is the specific failure mode the header comment calls out from experience | Lower | False confidence in a broken environment |
| External red-team/pen-test cadence only, no in-repo automated suite | Independent perspective, less tempting to write tests that match implementation bugs | Runs far less often than every change; does not catch regressions between engagements; this project also maintains a separate `redteam/` directory for exactly that complementary purpose | High (external engagement cost) | Long windows between checks; not a substitute for continuous verification |

**Why this control.** This is the project's answer to "how do we know the
controls in this document actually hold" — every other control entry here
cites one of these suites as its verification evidence. The
positive-controls-first pattern exists because the project already
experienced the failure mode it prevents (the Phase 2 dockerd incident cited
in the script's own comment), making this a control with a documented,
concrete justification rather than a generic best practice.

**Residual risk.**
- Suites run against the single-node lab topology; they do not exercise
  multi-node scheduling, node failure, or the production AWS topology (see
  `06-enterprise-scale.md`) — passing here is not evidence for those
  environments.
- Coverage is only as good as the suite's authors anticipated; the "noise
  budget" of three named probe signatures is itself a maintained allowlist
  that could mask a fourth, newly introduced noisy behavior if not kept
  current.

---

### C-SUP-8 coderd public 443 for Terraform providers (accepted exposure; document as control + gap)

**Threat mitigated.** Coder's Terraform provisioner needs to download
Terraform provider binaries (the `coder/coder` and `hashicorp/kubernetes`
providers used by `templates/base/main.tf`) at template-push and
workspace-build time. Without any egress at all, provisioning would simply
fail; the question this control actually addresses is how narrowly that
necessary egress is scoped.

**Control.** `platform/policy/platform.yaml`'s `coderd-egress`
CiliumNetworkPolicy allows the `coder` namespace pods (`coderd` itself, which
runs the provisioner) DNS, its own Postgres, the Kubernetes API server
(`kube-apiserver` entity, :6443, for the Kubernetes provider), the node host
on :30080 (its own access URL, for DERP health checks), and — the control
under discussion — public `0.0.0.0/0` (minus private ranges) on **port 443
only**, with no path/SNI-level restriction the way Envoy's egress gate
applies to workspace traffic. The manifest's own comment is explicit that
this is a known compromise, not an oversight: *"public 443 is broad; a
Nexus-backed provider mirror narrows it (production delta)."* This is a
deliberately different (broader) exposure than the workspace-egress model in
`02-network.md`, scoped to the `coderd` control-plane component rather than
to workspaces.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Nexus-backed Terraform provider mirror (the noted production delta) | Collapses this to the same single-mirror model as C-SUP-1, full path visibility | Nexus CE does not natively proxy the Terraform Registry protocol the way it does apt/PyPI/npm/Docker; would need a proxy repository format Nexus supports or a separate provider-mirror tool (e.g., a filesystem mirror served over HTTP) | Medium | None beyond the added component's own maintenance |
| Vendor/pin provider binaries into the coderd image at build time, no runtime egress | Zero runtime network dependency for this path | Every provider version bump requires an image rebuild; brittle if templates ever add a new provider; still needs *some* trusted path to originally fetch the binaries | Medium | Stale binaries if the rebuild discipline lapses |
| SNI-restricted egress to just `releases.hashicorp.com` and the provider registry mirror hosts, instead of all of 443 | Materially narrower than "all of 0.0.0.0/0:443" | Terraform's provider installation protocol resolves to CDN-backed hosts that are not a small fixed list (registry.terraform.io redirects to per-provider mirror URLs); allowlist would need regular upkeep or break unpredictably | Medium (initial), ongoing (CDN churn) | Allowlist drift causes either breakage or silent over-permission if kept loose to compensate |

**Why this control.** This is `coderd`'s own control-plane requirement, not
a workspace capability — it does not touch the four-destination workspace
invariant at all, and `coderd` is not exposed to the untrusted agent
execution environment the way workspace egress is. The manifest documents
the trade-off explicitly rather than hiding it, which is why this entry
treats it as an accepted, tracked exposure: narrowing it (a Nexus-backed
provider mirror) is recorded as a known, not-yet-implemented production
delta rather than an unexamined gap.

**Residual risk.**
- This is the single broadest static egress allowance in the platform
  policy set — any compromise of `coderd` itself (not a workspace) has
  materially more reach than any other in-cluster component. See
  `05-gaps-and-monitoring.md`.
- No SNI or path filtering applies to this path the way Envoy applies it to
  workspace egress (C-NET-6/C-NET-7 in `02-network.md`), so traffic content
  on this path is not independently inspectable beyond TLS SNI at the CNI
  layer.
