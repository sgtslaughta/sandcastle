# Phase 3 — Containment Core — Design Spec

Date: 2026-09-13
Status: implemented (v0.3.0)
Parent: [MVP design](2026-09-13-sandcastle-mvp-design.md)

## Goal

A workspace with root reaches only the destinations it was granted, and a
bypass attempt is dropped by two independent mechanisms and visible within
seconds. Developer workflows from Phase 2 (`coder ssh`, code-server, apt, pip,
npm, `docker build`) keep working.

## Reachability invariant (revised)

A workspace pod reaches exactly four destinations:

| Destination | Port | Allowed traffic |
|---|---|---|
| Envoy egress gate (`sandcastle-egress`) | 3128 | HTTP forward / CONNECT |
| kube-dns | 53 | DNS queries for `*.cluster.local` only |
| Nexus (`sandcastle-mirror`) | 8081, 8082 | `GET`/`HEAD` on `/repository/*`; docker registry proxy |
| coderd (`coder`) | 8080 | Coder agent API paths only (captured, see Spike) |

Everything else is denied: kube API, node and kubelet, other workspaces,
Envoy admin, Hubble, all IPv6. The MVP spec listed three destinations; the
Coder agent must dial out to coderd for its tunnel, so the list is four.

## Architecture

```
workspace pod (Kata)                 sandcastle-egress ns            host GAME-01
 dev + dind ──HTTPS_PROXY──► Envoy :3128 ──egress GW IP──► virbr-egress ──► internet (allowlist)
   │  ├─ DNS ─► kube-dns (*.cluster.local only)
   │  ├─ GET/HEAD /repository/* ─► Nexus :8081 / docker :8082 ──egress GW IP──► upstream
   │  └─ agent paths ─► coderd :8080
   └─ anything else ─► Cilium DROP (+ICMP unreachable) + Hubble event
 VM primary IP ──► host nft: DROP + log "sandcastle-deny"
```

### Components

| Component | Location | Role |
|---|---|---|
| Envoy egress gate | `platform/egress/` | Deployment, 1 replica, static config (xDS in Phase 4). Stage 1: HTTP connection manager checks the CONNECT authority / HTTP host against the allowlist. Stage 2: the terminated CONNECT stream goes to an internal listener with `tls_inspector`; the SNI must also be allowlisted and the upstream is dialled by SNI. Denied → 403 with `x-sandcastle-denied` header (host, workspace IP); plain HTTP also gets a body page. |
| Workspace policy | `platform/policy/workspaces.yaml` | CiliumNetworkPolicy in `sandcastle-workspaces`, `endpointSelector: {}` (every pod, not Coder labels). Egress rules per the invariant table; L7 HTTP rules on coderd and Nexus; DNS `matchPattern` rules. No ingress. |
| Platform policies | `platform/policy/platform.yaml` | Envoy: ingress from workspaces :3128 only; egress DNS + public 80/443. Nexus: ingress :8081/8082 from workspaces; egress DNS + public 80/443. coderd (egress only): DNS, coder-db :5432, kube-apiserver :6443, host :30080 (DERP health), public 443 (Terraform providers). "Public" = 0.0.0.0/0 minus private ranges, so DNS rebinding to the LAN or an enclave is not a route. |
| Cilium config | `infra/bootstrap/04-containment.sh` | Helm upgrade: `egressGateway.enabled=true`, `bpf.masquerade=true`, policy deny response ICMP. Snapshot `pre-containment` first. |
| Egress gateway | `platform/policy/egress-gateway.yaml` | `CiliumEgressGatewayPolicy` selecting Envoy, Nexus and coderd pods; SNAT via the VM's second NIC. |
| Egress network | `infra/vm/sandcastle-vm.sh` | libvirt NAT network `sandcastle-egress` (192.168.130.0/24) and a second VM NIC. |
| Host layer | `infra/vm/01-host-egress-nft.sh` | nftables table `inet sandcastle`, input + forward hooks, every rule scoped to `virbr0`/`virbr-sce`. Lock: forward only egress IP → public 80/443; input only DHCP/DNS (plus established) from the VM; everything else from the VM logged `sandcastle-deny` and dropped. Unlock: delete the table. Not persistent across host reboot; the verify suite fails while unlocked. |
| Coder | `platform/coder/values.yaml` | `CODER_BLOCK_DIRECT=true`: DERP only, so denied STUN/UDP is not alert noise. |
| Base image | `images/base` | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY=.cluster.local,localhost,127.0.0.1`. |
| DinD image/template | `images/dind`, `templates/base` | `--registry-mirror` pointing at the Nexus docker-hub proxy (:8082). |
| Nexus | `platform/nexus/configure.sh`, `nexus.yaml` | Service port 8082 added. New `docker-hub` proxy repo with an HTTP connector on 8082, anonymous pull. |

### Failure modes

| Failure | Result |
|---|---|
| Egress gateway policy missing/broken | Envoy and Nexus traffic exits the primary IP; host drops it. Fails closed. |
| Envoy down | Proxy port refuses; direct paths still drop. Workspace access via coderd unaffected. |
| Cilium L7 proxy down | L7-policed flows are denied (Cilium fails closed). |
| Cilium policy absent | Workspace traffic leaving the VM uses the primary IP; host drops and logs it. In-cluster lateral paths are not covered by the host layer (see Residual risks). |
| Host lock left off | `03-containment.sh` fails. |

## Bootstrap egress toggle

Bootstrap steps (image pulls, helm charts, binaries) run from the VM primary
IP, which the host lock blocks. `make egress-unlock` before a bootstrap step,
`make egress-lock` after. The containment test fails while unlocked. Routing
node image pulls through a Nexus registry mirror would remove the toggle; it is
deferred.

## Threat analysis

Assume root in the workspace, including the ability to read `CODER_AGENT_TOKEN`.

| Path | Attack | Mitigation | Residual |
|---|---|---|---|
| coderd | Full API on the same port: login brute force, user enumeration, CVEs. coderd holds DB credentials and a Role that creates pods. | L7 allowlist of agent paths; other paths 403 + Hubble event; Coder API rate limit. | coderd CVEs on agent paths |
| coderd compromise | Create pods in the workspace namespace | Admission forces Kata, no hostPath/host namespaces; policy selects all pods in the namespace; coderd egress restricted | New pods get workspace-level access |
| Agent token | Misuse | Scoped to its own workspace; tailnet peers require coderd authorization | — |
| Agent logs/metadata | Staged exfil via the Coder UI and Postgres | Volume alert (Phase 6) | Low-bandwidth exfil |
| coderd DoS | Runaway agent loop | Coder rate limit; L7 request-rate alert | Shared-service degradation |
| Tailnet direct | STUN/UDP attempts | `CODER_BLOCK_DIRECT=true` | — |
| DNS | Data encoded in query names forwarded upstream | Only `*.cluster.local` resolvable; the proxy resolves external names | — |
| Nexus | Package-name exfil via upstream fetch; admin API; uploads | GET/HEAD `/repository/*` only; anonymous read | Lab-only: name-encoded upstream fetch (production Nexus has no internet upstream) |
| Envoy allowlist | Allowlisted hosts are exfil channels | Narrow allowlist | By definition |
| Domain fronting | CONNECT allowlisted host, different SNI | SNI must also be allowlisted; upstream dialled by SNI | Fronting via Host header on shared CDNs (no TLS interception) |
| Kube API, kubelet, Hubble, Envoy admin | Probing | Default deny; no SA token | — |
| DinD host networking, guest iptables | Bypass enforcement | Cilium enforces on the node side, outside the Kata guest kernel | — |
| IPv6, ICMP tunnels | Side channels | IPv6 off; default deny | — |
| Identity | Spoof another workspace's IP | Cilium BPF anti-spoofing; enforcement outside the guest | IP reuse after pod restart (closed in Phase 4 by pod-lifecycle grants) |

Residual risks accepted by the owner: CVEs in coderd, Nexus, Envoy and the
Cilium proxy (needs a patch cadence); low-bandwidth staged exfil; lab-only Nexus
upstream exfil; CDN fronting; in-cluster lateral paths enforced by Cilium only
until enclaves move out of the cluster in Phase 5.

## Spike (gates the build)

Results: [spike results](2026-09-13-phase3-spike-results.md). All six passed; no fallback taken.

Run in the VM after snapshot `pre-containment`. Throwaway; results logged to
open-brain and summarised here.

| # | Question | Pass | Fallback |
|---|---|---|---|
| 1 | Egress gateway with Kata pods | Selected Kata pod's source IP seen upstream is the egress-network IP | Host VM-wide allowlist (no source distinction) |
| 2 | Cilium L7 HTTP policy on Kata pods | Denied path returns 403 from Cilium proxy; allowed websocket upgrade (agent RPC, DERP) still works | Envoy fronts coderd and filters paths |
| 3 | Policy deny response ICMP | Direct connection fails in < 2 s | Test asserts failure within a timeout; docs drop the `EHOSTUNREACH` claim |
| 4 | Envoy two-stage CONNECT + SNI | Allowlisted host 200; mismatched SNI refused | Stage 1 authority check only; fronting residual widens |
| 5 | Coder agent paths | Path list captured from Hubble L7 during `coder ssh` + code-server use | — |

## Verification

`infra/tests/03-containment.sh` runs in the VM. Positive controls run first so
every "blocked" result is meaningful.

Must work:
- `coder ssh` and code-server healthcheck.
- `curl https://example.com` via proxy → 200.
- apt, pip, npm installs via Nexus; `docker build` FROM busybox via the Nexus docker proxy.
- Host lock is on.

Must be blocked:
- `curl --noproxy '*'` to 1.1.1.1 and example.com → fails fast.
- Proxied non-allowlisted host → 403 with `x-sandcastle-denied`.
- SNI mismatch through an allowlisted CONNECT → refused.
- DNS for `example.com` → refused; service names resolve.
- coderd `/api/v2/users` → 403; Nexus `PUT` → 403.
- kube API 10.43.0.1:443, node :10250, another workspace pod, Envoy admin :9901 → dropped.
- DinD `docker run --network host` direct curl → dropped.
- Any IPv6 address or route in the workspace → FAIL.
- VM node direct internet request (simulated leak) → dropped by host.

Must be seen:
- Hubble DROPPED flow with the workspace pod's labels within 5 s.
- Envoy access log line with source IP resolved to the workspace ID.
- Hubble L7 and DNS denial events.

`make verify-host-egress` runs on the host with sudo: the nft table exists, it
hooks only input/forward with every rule scoped to the lab bridges, and `sandcastle-deny` log lines appeared during the VM test.

## Implementation findings — 2026-09-13

Found by the verify suite after the spike. Each finding changed the build.

- **Agent download went through the gate.** The workspace image's
  `HTTP_PROXY` sent the Coder init script's binary download to Envoy, which
  denied it. The template adds the access URL host to `NO_PROXY`. The spike
  missed this because it ran image 0.1.0, which has no proxy env: spike with
  the image that ships.
- **DNS patterns.** A single `*` matches one label, and search-list expansions
  reach 7+ labels. The rule is now `**.cluster.local`.
- **Noise budget.** The Coder agent's embedded Tailscale emits port-mapping
  probes that no setting disables (Coder 2.36.5; `CODER_BLOCK_DIRECT` and
  `TS_DISABLE_UPNP` both tried): UDP 5351/1900 to the pod gateway, SSDP to
  239.255.255.250:1900, and UDP to 203.0.113.1:12345. Owner decision: keep
  them blocked and classify them as three exact signatures. The verify suite
  fails on any other drop during allowed work, and Phase 6 alert rules reuse
  the list.
- **Legitimate tools that leaked attempts:**
  - npm audit POSTs to Nexus: `audit=false`.
  - Docker 29's containerd image store contacted Docker Hub on every pull,
    even when the mirror served the pull: dind uses the classic store, which
    falls back to Hub only if the mirror fails. Allowing the DNS name first
    exposed the hidden connection attempts. Re-measure drops after allowing
    anything.
- **Permitting names** (owner requirement: closed networks use other registry
  hostnames): `platform/policy/workspace-dns-allow.yaml` plus `make policy`.
  Resolving never grants reaching. The file holds a `.invalid` placeholder,
  because an empty DNS rule list allows every name.
- **Envoy log latency.** The file flush defaults to 10 s; set to 1 s so
  denials are visible within seconds.
- **Silent drops.** ClusterIP destinations (kube API, coder-db) get no ICMP
  deny response and time out; Hubble still logs them.
- **Cilium upgrade deadlock** on a single node (two operator replicas):
  `operator.replicas=1`, with `maxUnavailable=1` so a rolling update can
  replace the only pod.

Result: `03-containment.sh` 35/35, plus Phase 1 9/9 and Phase 2 18/18
regressions, all under the host lock.

## Decision records

### DR-3.1 Workspace reaches coderd directly with an L7 path allowlist
- **Who:** owner (sgtslaughta), proposed by Claude.
- **When:** 2026-09-13, Phase 3 design.
- **Where:** workspace CiliumNetworkPolicy → `coder` namespace, :8080.
- **What:** direct L3 path limited by Cilium L7 HTTP rules to captured agent paths; Nexus gets GET/HEAD-only L7 rules; DNS limited to `*.cluster.local`; `CODER_BLOCK_DIRECT=true`.
- **Why:** the Coder agent needs coderd for its tunnel. The full coderd API on that port is the largest escape surface; path filtering shrinks it without making Envoy critical for workspace access.
- **Alternatives:** port-level only (full API exposed); through Envoy (same exposure, Envoy becomes a single point of failure for access).

### DR-3.2 Second layer: Cilium egress gateway + host nftables
- **Who:** owner, proposed by Claude.
- **When:** 2026-09-13.
- **Where:** VM second NIC, libvirt `sandcastle-egress` network, host `inet sandcastle` table.
- **What:** legitimate egress pods exit a dedicated IP; the host drops and logs everything else from the VM.
- **Why:** Cilium masquerades pod traffic to the VM IP, so the host cannot otherwise tell workspace traffic from Nexus/Envoy traffic. A separate IP makes the host layer independent and fail-closed.
- **Alternatives:** host VM-wide allowlist (Cilium failure exposes allowlisted IPs directly); in-VM nftables (same kernel, BPF bypasses netfilter); defer to Phase 5.

### DR-3.3 Mock enclaves move out of the cluster (Phase 5)
- **Who:** owner, proposed by Claude.
- **When:** 2026-09-13.
- **Where:** separate libvirt network guarded by host nftables.
- **What:** workspace → enclave becomes two-layer in the lab.
- **Why:** the host layer only sees traffic leaving the VM; in-cluster enclaves would stay Cilium-only. Matches production topology.
- **Alternatives:** keep in-cluster (cheaper, single layer).

### DR-3.4 No TLS interception
- **Who:** owner, proposed by Claude.
- **When:** 2026-09-13.
- **Where:** Envoy egress gate.
- **What:** CONNECT 403 with `x-sandcastle-denied`; SNI allowlisted too; CDN fronting documented as residual; interception may be added per zone later.
- **Why:** browsers discard refused-CONNECT bodies, but interception would put every secret in Envoy, make the CA key a crown jewel, and break pinned/bundled-CA tools and DinD builds.
- **Alternatives:** internal-CA interception.

### DR-3.5 Identity from pod source IP
- **Who:** owner, proposed by Claude.
- **When:** 2026-09-13.
- **Where:** Envoy access log (Phase 3), xDS grants (Phase 4).
- **What:** downstream source IP resolved to workspace ID via pod labels; Phase 4 keys grants by pod lifecycle.
- **Why:** unforgeable under Cilium anti-spoofing with enforcement outside the Kata guest; credentials would leak into build args and shell history.
- **Alternatives:** proxy credentials in URL.

### DR-3.6 Static allowlist: one test host
- **Who:** owner, proposed by Claude.
- **When:** 2026-09-13.
- **Where:** Envoy static config.
- **What:** `example.com` only; packages via Nexus.
- **Why:** closest to air-gapped production while still proving the allowed path.
- **Alternatives:** dev set (github, api.anthropic.com; each an exfil channel); empty (allowed path unprovable until Phase 4).

### DR-3.7 Bootstrap egress toggle
- **Who:** owner, proposed by Claude.
- **When:** 2026-09-13.
- **Where:** Makefile `egress-lock` / `egress-unlock`, host nft table.
- **What:** unlock for bootstrap steps, lock after; test fails while unlocked.
- **Why:** node image pulls and downloads use the primary IP; a toggle is honest and small.
- **Alternatives:** node pulls via Nexus registry mirror now (more scope); always-on registry IP allowlist (CDN churn, leak path).

### DR-3.8 Envoy as Deployment, not DaemonSet
- **Who:** Claude.
- **When:** 2026-09-13.
- **Where:** `platform/egress/`.
- **What:** one replica.
- **Why:** single-node lab; a DaemonSet adds nothing until multi-node.
- **Alternatives:** DaemonSet (MVP spec wording).

## Out of scope (later phases)

Admin UI, xDS, request/approve queue, `sandcastle denied` CLI (Phase 4);
out-of-cluster enclaves, brokers (Phase 5); Loki/Grafana alert routing, rate
limits, circuit breaker (Phase 6); node registry mirror; TLS interception.
