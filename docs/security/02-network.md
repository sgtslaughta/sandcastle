# Network containment (C-NET-1..13)

Scope: everything between a workspace pod's network namespace and the internet — Cilium policy, the Envoy egress gate, DNS, and the host nftables layer. Isolation of the pod itself (Kata/gVisor/admission) is `01-isolation.md`; the admin control plane that drives Envoy's config and authorizes hosts is `03-admin-plane.md`. See the [README](../../README.md) for the overall system.

Primary sources: `docs/superpowers/specs/2026-09-13-phase3-containment-core-design.md` (DR-3.1..3.8, threat analysis, spike results, implementation findings), `platform/policy/*.yaml`, `platform/egress/envoy.yaml`, `admin/internal/xds/build.go`, `infra/vm/01-host-egress-nft.sh`, `infra/bootstrap/01-k3s-cilium.sh`, `infra/bootstrap/04-containment.sh`, `infra/tests/03-containment.sh`.

Threat model default: attacker has root in a workspace pod (via a hostile agent or a compromised dev process) or has compromised a platform pod (Envoy, Nexus, coderd). Assume they can read files, run arbitrary code, and try any protocol on any interface reachable from the pod's netns.

## C-NET-1 Four-destination workspace CiliumNetworkPolicy

**Threat mitigated.** A workspace with root and no network policy could reach any pod, service, or external host: kube API, kubelet, other workspaces, the internet directly. That turns one compromised workspace into a pivot for the whole cluster and an unrestricted exfil channel.

**Control.** `platform/policy/workspaces.yaml`, a `CiliumNetworkPolicy` named `workspace-egress` in `sandcastle-workspaces` with `endpointSelector: {}` (every pod in the namespace, not just ones carrying Coder labels — a pod spawned by a compromised coderd is covered too) and `ingress: [{}]` (default-deny; the Coder tunnel is outbound only). Egress is limited to exactly four destinations: kube-dns (`**.cluster.local` only), the Envoy egress gate (`:3128`), Nexus (`:8081`/`:8082`, GET/HEAD only), and coderd (`:8080`, four captured agent paths). Verified by `infra/tests/03-containment.sh` (35/35 per the 2026-09-13 run) and spike S2.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| No network policy (do nothing) | Zero effort | Full lateral + internet reach from any workspace | None | Unbounded |
| Kubernetes `NetworkPolicy` (native) | No CNI-specific CRD | L3/L4 only, no L7 HTTP/DNS; still needs a Cilium-class CNI to enforce | Low, insufficient alone | Needs a second L7 mechanism anyway |
| Per-workspace policy (label-selected) | Slightly more targeted | Misses pods outside the expected label set (compromised coderd) | Low | Silent gap on label drift |

**Why this control.** DR-3.1: the Coder agent must reach coderd directly for its tunnel, so the reachability invariant is four destinations, not three as the MVP spec first assumed (`endpointSelector: {}` closes the case where a compromised coderd schedules an unlabeled pod). Matches the single-node lab's one CiliumNetworkPolicy per namespace model; no multi-tenant partitioning needed yet.

**Residual risk.**
- In-cluster lateral paths are Cilium-only until enclaves move out of the cluster (Phase 5, DR-3.3); see `05-gaps-and-monitoring.md`.
- A Cilium policy/CRD failure is a single point of failure here, mitigated by C-NET-11 (independent second layer).

## C-NET-2 coderd L7 path allowlist + CODER_BLOCK_DIRECT

**Threat mitigated.** coderd's full API — login, users, templates, workspace CRUD — runs on the same port the agent must dial for its tunnel. Unrestricted access from a compromised workspace gives an attacker credential brute force, user enumeration, and reach into coderd's own CVEs, and coderd holds DB credentials plus a Kubernetes Role that creates pods.

**Control.** `platform/policy/workspaces.yaml`, Cilium L7 HTTP rules on the coderd egress entry: exactly the four paths captured from Hubble during spike S5 (`GET /bin/coder-linux-amd64`, `GET /api/v2/workspaceagents/me/.*`, `GET /derp`, `GET /derp/latency-check`). Anything else, including `/api/v2/users` and `/api/v2/buildinfo`, gets a 403 from the Cilium L7 proxy. `platform/coder/values.yaml` sets `CODER_BLOCK_DIRECT=true` so the agent's embedded Tailscale never attempts direct/STUN connections — DERP relay only. Verified: spike S2/S5 (`/api/v2/buildinfo` 200 pre-restriction, `/api/v2/users` 403, `/derp` websocket 101) and `03-containment.sh`.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Port-level only (no L7) | Simple | Full coderd API reachable; largest escape surface on this path | None | High — auth/CVE surface fully exposed |
| Route everything through Envoy | Reuses Envoy's allowlist machinery | Envoy becomes a single point of failure for coderd access (SSH, code-server); same exposure since it still needs the same paths open | Medium | Availability coupling, no security gain |
| Full mTLS agent↔coderd | Strong mutual auth | Coder OSS 2.36.5 does not support this for the agent tunnel | High | Out of reach for this stack version |

**Why this control.** DR-3.1: direct L3 with an L7 path allowlist keeps workspace access to coderd off Envoy's critical path while shrinking the open surface to only what `coder ssh` and code-server need. Re-capture on any Coder upgrade — the path list is version-specific (2.36.5).

**Residual risk.**
- coderd CVEs on the four allowed paths are not mitigated here (patch cadence; see `05-gaps-and-monitoring.md`).
- A Coder upgrade that changes agent request paths needs manual re-capture; no automated diff exists yet.

## C-NET-3 Nexus L7 GET/HEAD-only rules

**Threat mitigated.** Nexus mirrors apt/PyPI/npm/Docker Hub for workspaces. Unrestricted access exposes its admin API and upload endpoints, and package names in requests are a name-encoded exfil channel even when read-only.

**Control.** `platform/policy/workspaces.yaml`: Cilium L7 HTTP rules limit the Nexus egress entry to `GET`/`HEAD` on `/repository/.*` (port 8081) and `/v2/.*` (port 8082, Docker registry proxy). `PUT` and any admin path get a 403. Verified by `03-containment.sh` (`Nexus PUT → 403`) and normal package installs (apt/pip/npm) passing.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Port-level only | Simple | Nexus admin UI/API and uploads reachable from any workspace | None | Credential/config exposure, tampering |
| Nexus-side RBAC (read-only role) | Defense at the app layer too | Doesn't cover a Nexus auth bypass CVE the way network blocking does | Low-medium | Not sufficient alone |
| Require authenticated pulls | Removes anonymous-read exfil path | Every workspace needs a credential to manage/rotate | Medium | Credential distribution is a new attack surface |

**Why this control.** Matches the reachability invariant in the Phase 3 design (`platform/policy/workspaces.yaml` header). Read-only L7 filtering is cheap and removes the highest-value abuse (uploads, admin) without touching Nexus's own auth model, which stays anonymous-read for the lab.

**Residual risk.**
- Lab-only: package-name exfil via upstream fetch is possible since lab Nexus proxies the real internet; production Nexus with no upstream closes this. See `05-gaps-and-monitoring.md`.
- Nexus CVEs on the allowed GET/HEAD surface are not mitigated here.

## C-NET-4 Workspace DNS limited to `**.cluster.local`

**Threat mitigated.** DNS queries are a classic covert channel: attacker encodes data in subdomain labels and the resolver forwards the whole name upstream regardless of whether the "answer" matters. Unrestricted DNS from a workspace is exfiltration that looks like ordinary traffic.

**Control.** `platform/policy/workspaces.yaml`: Cilium DNS `matchPattern: "**.cluster.local"` on the kube-dns egress entry. External names are resolved by Envoy on the workspace's behalf (via `dynamic_forward_proxy`), never by the workspace resolver. Verified: spike S6 confirmed `**.` (not a single `*`) is required — a single `*` matches one label, but the resolver's search-list expansion produces names 7+ labels deep (`egress.sandcastle-egress.svc.cluster.local`), and a naive pattern buried real denial alerts in noise. CoreDNS is authoritative for `cluster.local` and answers NXDOMAIN for expanded names locally, so they are never forwarded upstream.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| No DNS restriction | Simplest | Full DNS exfil channel to any resolver reachable | None | High |
| Allow external names, rely on proxy allowlist alone | Simpler policy | The query itself leaks data upstream before the proxy would refuse the connection | Low | Exfil succeeds even if the connection is blocked |
| Single `*` DNS pattern | Looks sufficient at a glance | Matches one label only; search-list expansion drops every legitimate lookup, burying real alerts (spike S6) | Low | Alert fatigue, missed real denials |

**Why this control.** Matches the phase3 threat analysis: "Data encoded in query names forwarded upstream → Only `*.cluster.local` resolvable; the proxy resolves external names." Closes the query-based channel entirely for workspaces; reachability of resolved names is separately gated by C-NET-1/C-NET-6.

**Residual risk.**
- None specific to workspace DNS; platform pods resolve external names themselves and are covered by C-NET-9 instead.

## C-NET-5 ICMP deny response (fail fast, bypass = failure)

**Threat mitigated.** A silent policy drop (packet vanishes, connection hangs until a client timeout) makes bypass attempts slow to detect during testing and gives an attacker a long window per probe. It also makes legitimate failures indistinguishable from policy drops without log correlation.

**Control.** `infra/bootstrap/01-k3s-cilium.sh` sets Cilium `policyDenyResponse=icmp` (marked experimental upstream) at helm install time. A denied egress packet gets an ICMP unreachable back immediately instead of being silently dropped. Verified by spike S3: direct connections to `1.1.1.1` and the node's `:10250` failed in ~150 ms, unchanged under default-deny ingress. **Exception found during the spike:** ClusterIP destinations (e.g. kube API `10.43.0.1:443`) get no ICMP response and time out (~16 s) because the ICMP response cannot be generated for a service-translated address; Hubble still logs the denial. The verify suite allows a timeout for that one case.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Default silent drop | Cilium default, no config needed | Bypass attempts and test failures both hang for the client's full timeout (seconds to minutes); slower detection | None | Slower operator/attacker feedback either way |
| TCP RST instead of ICMP | Faster feedback than silent drop | Not a Cilium `policyDenyResponse` option for L3/L4 default-deny at this version | N/A | N/A |
| Rely on Hubble events only, keep silent drop | No experimental flag | Detection depends on someone watching Hubble; a live probe (e.g. in CI) waits out the full timeout | None | Slower automated verification |

**Why this control.** Supports the phase3 goal: "a bypass attempt is dropped ... and visible within seconds." The spec's original "fails in under 2 s uniformly" claim is corrected here to exclude service-translated destinations, per spike S3.

**Residual risk.**
- `policyDenyResponse=icmp` is experimental upstream; behavior could change on a Cilium upgrade. See `05-gaps-and-monitoring.md`.
- ClusterIP-destination denials still take ~16 s to fail at the client.

## C-NET-6 Explicit Envoy egress proxy, two-stage CONNECT + SNI binding

**Threat mitigated.** Without an explicit forward proxy, "allow this hostname" has no enforcement point for HTTPS: a workspace could CONNECT to an allowed hostname's IP and then negotiate TLS to a completely different host (domain fronting), or bypass hostname filtering by IP literal.

**Control (as it runs today).** `platform/egress/envoy.yaml` deploys Envoy 1.39.1 in `sandcastle-egress` with **no static listeners, routes, or clusters for workspace traffic** — only `dynamic_resources.ads_config` pointing at `sandcastle-admin:18000` and a static `admin` cluster for ADS/ALS. `admin/internal/xds/build.go` (`Build`) renders the actual egress config from the grant set and pushes it over xDS (LDS/CDS/RDS) each time grants change (DR-4.8, Phase 4; supersedes the Phase 3 design's "static config" line). Per host:
- **Stage 1 (CONNECT/HTTP authority check).** The `proxy` listener (port 3128, identical across all builds) runs an HTTP connection manager with RDS-driven virtual hosts, one domain per granted `host:port`. Each vhost carries an `envoy.filters.http.rbac` `RBACPerRoute` override allowing the request only from the pod IPs granted that host (`direct_remote_ip`); the base RBAC filter denies by default, so an unmatched authority falls through to a catch-all `domains: ["*"]` vhost returning 403 with header `x-sandcastle-denied: host=...; source=...` and a body pointing at the access-request URL.
- **Stage 2 (SNI binding).** For port-443 hosts, stage 1 routes the CONNECT to a per-host internal cluster/listener pair (`sni_<hash>`). That listener runs `tls_inspector` + `filter_chain_match: {server_names: [host]}`, so a ClientHello whose SNI does not match the CONNECTed authority is refused before any bytes reach the internet — this stops CONNECT `example.com` / SNI `github.com` fronting. Matching traffic is dialed by SNI through `sni_dynamic_forward_proxy` into a `dynamic_forward_proxy` cluster (DNS resolved by Envoy, not the workspace).
- Denials are logged to stdout (Hubble/Phase 6) and via gRPC ALS to `sandcastle-admin` (C-ADM-12). Listener names hash `(host, sorted allowed IPs)`, so a change in who may reach a host renames the listener; Envoy drains the old one (5 s, immediate), closing already-open tunnels on revocation (C-ADM-7).

Verified: spike S1 (egress gateway path), S4 (two-stage CONNECT+SNI: allowed 200, denied host 403 with header, SNI mismatch refused, curl rc=35), and `03-containment.sh`. Stage-2 refusals initially produced no log line; a listener-level access log (`stage: sni`) was added and the suite asserts it (spike S4 finding).

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Transparent proxy / TPROXY | No client-side proxy config | Needs iptables/eBPF redirection fighting Kata's separate guest kernel and Cilium's datapath; SNI-only visibility, same fronting gap without stage-2 binding | High | New redirection layer to secure and debug |
| TLS-intercepting MITM proxy | Sees HTTPS payloads and hostnames; catches header-based fronting | Every workspace secret flows through Envoy in clear; interception CA key becomes a crown-jewel asset; breaks pinned/bundled-CA tools and `docker build` (DR-3.4) | High (CA mgmt, cert distribution, tool break-fix) | New single point of total compromise |
| Cilium FQDN policies alone | Removes Envoy as a component | Resolve via DNS snooping only; do not bind CONNECT authority to SNI, so fronting is not addressed; revocation needs Cilium policy churn instead of Envoy's fast listener drain | Medium | Fronting residual widens; slower revocation |
| Squid (or similar forward proxy) | Mature ACL syntax | No native per-pod-IP dynamic ACL from an external control plane comparable to xDS; needs a custom reload driver, likely slower than incremental xDS | Medium-high (build the control-plane integration from scratch) | Same fronting risk unless a second SNI-check layer is also built |
| Cloud NAT allowlist (FQDN egress firewall) | No in-cluster proxy component | Not available in this single-VM lab; typically L4/SNI-only visibility, coarser per-tenant granularity than per-pod-IP RBAC | N/A in lab; medium in cloud | Coarser identity binding than pod IP |

**Why this control.** DR-3.4 rules out interception; DR-4.8 chose per-host xDS vhosts with source-IP RBAC over a static allowlist once Phase 4 added an admin-driven grant model, making per-workspace, time-bounded grants (C-ADM-4/5) enforceable without touching Cilium policy per grant. The two-stage design closes the fronting gap a stage-1-only design leaves open (spike S4 fallback, not taken).

**Residual risk.**
- Domain fronting via the HTTP `Host` header on shared CDNs (one IP/SNI serving many hostnames) is not addressed. See `05-gaps-and-monitoring.md`.
- Envoy and its go-control-plane/xDS dependencies are CVE surface; a compromise here reaches every host any workspace is granted.

## C-NET-7 No TLS interception

**Threat mitigated.** N/A as a mitigation in itself — this is a deliberate non-control, documented because "why isn't there a MITM proxy filtering HTTPS payloads" is a reasonable question.

**Control.** Envoy terminates CONNECT for routing purposes only (stage 1) and never presents its own certificate for the tunneled TLS session; stage 2 binds by SNI without decrypting. `platform/egress/envoy.yaml` and `admin/internal/xds/build.go` contain no cert/key material for interception.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Internal-CA interception (per zone) | Payload-level visibility; catches Host-header fronting | Breaks pinned-cert tools and `docker build` fetches with bundled CAs; makes the CA key a crown jewel; puts every workspace secret through Envoy in clear | High | Single point of total compromise; tool breakage support burden |
| No interception (current) | No CA to protect; no tool breakage; secrets never transit Envoy in clear | Cannot see payload-level exfil in allowed hosts; Host-header fronting residual stays open | None (already the state) | Exfil via allowlisted hosts is undetectable at this layer by definition |

**Why this control.** DR-3.4: browsers discard bodies on a refused CONNECT so a 403 page is enough for stage 1, while interception would turn Envoy into a secrets-in-clear chokepoint and break pinned/bundled-CA tooling used for installs and image builds. Interception "per zone" is left open for a future zone that needs payload inspection badly enough to accept the trade-off.

**Residual risk.**
- Exfil inside an allowed, encrypted connection is invisible by design. See `05-gaps-and-monitoring.md`.
- CDN-hosted domain fronting via Host header remains open (shared with C-NET-6).

## C-NET-8 Workspace identity = pod source IP

**Threat mitigated.** If proxy authorization were based on a bearer credential instead of network identity, that credential would end up in `HTTPS_PROXY`/`HTTP_PROXY` env vars, build arguments, and shell history — readable by anything running in the workspace, and easy to exfiltrate or reuse from outside the pod.

**Control.** The Envoy RBAC per-route policy matches `direct_remote_ip` against the pod IPs granted a host (`admin/internal/xds/build.go: rbacPerRoute`), and the Envoy access log resolves the downstream source IP to a workspace ID for denial/audit purposes (C-ADM-12). Cilium's BPF-level anti-spoofing enforces this outside the Kata guest kernel, so a workspace cannot forge another pod's source IP at the network layer. Verified: spike S1 (source IP seen upstream is the pod's actual egress-network IP, confirmed via tcpdump) and the Phase 4 admin suite (39/39).

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Proxy auth token in URL/header | Standard proxy auth pattern; works with any generic proxy | Token lands in env vars, build logs, and shell history inside the workspace; any process in the pod can read and exfiltrate it | Low | Credential leak is close to certain given normal dev tool behavior |
| SPIFFE/mTLS workload identity | Cryptographic identity, portable beyond one node/network | Requires a SPIFFE/SPIRE deployment, workload attestation, and cert issuance/rotation machinery this stack does not have; the Kata guest would need its own client cert material, which reintroduces a leakable secret inside the pod | High | New PKI to build, operate, and rotate; still leakable if mishandled |
| Per-workspace proxy ports (one Envoy listener per pod) | Physically separates who talks to whom | Number of listeners scales with active workspace count; complicates the xDS build and the fixed proxy-port assumption baked into workspace `HTTPS_PROXY` config | Medium-high | Operational complexity grows with fleet size |

**Why this control.** DR-3.5: source IP is unforgeable under Cilium's anti-spoofing, with enforcement living outside the guest kernel, and puts no credential inside the workspace. Cheap on a single-node lab where Cilium already owns the datapath; it is the mechanism Phase 4's grant model (C-ADM-4..9) is built on.

**Residual risk.**
- IP reuse after a pod restart could hand a new workspace the old grants for a window; closed by C-ADM-9. See `05-gaps-and-monitoring.md`.
- Identity does not survive a NAT hop; holds only because Envoy sees the pod IP directly on the same cluster network.

## C-NET-9 Platform pod policies with private-range exclusion (DNS rebinding)

**Threat mitigated.** A platform pod (Envoy, Nexus, coderd) resolving an allowlisted external hostname could be handed a DNS answer pointing at the lab's private ranges, the host's LAN, or an enclave — DNS rebinding turning an allowed external name into an internal route the pod was never meant to reach.

**Control.** `platform/policy/platform.yaml`: each platform pod's egress `toCIDRSet` is `0.0.0.0/0` with `except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, 127.0.0.0/8]` — "public internet" is defined as everything outside the standard private/link-local/ loopback ranges, applied identically to the Envoy, Nexus, and coderd egress CiliumNetworkPolicies. Enforced independently again at the host nftables layer (C-NET-11) with the same exclusion list.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| No CIDR restriction on platform egress (do nothing) | Simplest | A rebound name lets Envoy/Nexus/coderd reach the lab LAN, cluster internals, or an enclave as if it were the internet | None | High — turns any allowed external hostname into an internal-network pivot |
| DNSSEC / DNS-response validation | Solves rebinding at the resolver, not the network | Not deployed by any upstream this stack resolves through; doesn't stop a legitimately-signed answer that simply points at a private IP (some rebinding attacks don't need to break DNSSEC) | Medium | Doesn't fully close the gap even if built |
| Per-hostname static IP pinning | Removes DNS trust from the loop entirely | Breaks any provider using rotating/CDN IPs (most of them); heavy operational burden to keep current | High | Frequent breakage requiring manual upkeep |

**Why this control.** Per `platform.yaml`'s header comment: "a DNS answer that points an allowlisted name at the lab network, GAME-01's LAN or an enclave range must not become a route." CIDR exclusion at the CNP layer is cheap and doubled by the host nftables layer for defense in depth.

**Residual risk.**
- Only IANA private/link-local/loopback ranges are excluded; rebinding to another sensitive public IP is not addressed here.

## C-NET-10 Cilium egress gateway: fixed egress IP for platform pods

**Threat mitigated.** Without a distinguishing signal, all pod traffic leaving the VM is masqueraded to the VM's one primary IP, so the host has no way to tell legitimate platform egress (Envoy, Nexus, coderd) from a workspace packet that slipped past Cilium policy — both would look identical at the host.

**Control.** `platform/policy/egress-gateway.yaml`, a `CiliumEgressGatewayPolicy` selecting exactly the Envoy, Nexus, and coderd pods, SNAT'd via the VM's second NIC to a fixed IP (`192.168.130.10`) on the `sandcastle-egress` libvirt network; in-cluster and lab-network CIDRs are excluded from the gateway. `infra/bootstrap/01-k3s-cilium.sh` enables `egressGateway.enabled=true` and `bpf.masquerade=true`, both required for the gateway to function. Verified by spike S1: tcpdump on the egress interface showed the Kata pod's traffic exiting from `192.168.130.10`, with nothing on the primary interface for that flow.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Host VM-wide allowlist (no source distinction) | No egress gateway component needed | A Cilium policy failure exposes the whole VM's allowlisted destinations directly, with no way to tell legitimate from bypassed traffic | Low | High — removes the entire benefit of a second independent layer |
| In-VM nftables marking traffic by source pod | Avoids a second NIC | Same kernel as the pods it's meant to constrain; a BPF datapath issue that lets traffic bypass Cilium also bypasses in-VM netfilter rules relying on the same identifiers | Medium | Not actually independent of the failure mode it's meant to catch |
| Defer to Phase 5 (do nothing yet) | Saves the NIC/network setup now | Leaves only one enforcement layer during Phase 3/4 | None | Single point of failure for the whole containment model in the interim |

**Why this control.** DR-3.2: Cilium masquerades pod traffic to the VM's primary IP by default, so a separate NIC/IP is the only way to make the host layer (C-NET-11) genuinely independent rather than trusting the datapath it backstops.

**Residual risk.**
- If the gateway policy breaks, Envoy/Nexus/coderd traffic falls back to the primary IP and the host drops it — fails closed, but also breaks legitimate egress; operators need to notice quickly.

## C-NET-11 Host nftables egress lock (second independent layer)

**Threat mitigated.** If Cilium policy is absent, misconfigured, or bypassed entirely (a datapath bug, an admission gap, a bad `kubectl apply`), a workspace pod's traffic would otherwise reach the internet unfiltered from the VM's primary interface with nothing to stop it.

**Control.** `infra/vm/01-host-egress-nft.sh`, table `inet sandcastle`, hooking only `input` and `forward` (never `output`), every rule matched on `iifname` to the lab bridges (`virbr0`, `virbr-sce`) only — deliberately narrow so a bad rule cannot strand the host itself. `forward` accepts only traffic from the egress gateway IP (`192.168.130.10`) to public 80/443 (same private-range exclusion as C-NET-9); everything else from either bridge is rate-limited, logged (`sandcastle-deny`), and dropped. Toggled via `make egress-lock`/`make egress-unlock` (needed during bootstrap, when helm and image pulls need the VM's primary IP — DR-3.7); not persistent across a host reboot. Verified by `make verify-host-egress`: table present, hooks are exactly `input`+`forward`, every rule is bridge-scoped, and `sandcastle-deny` log lines appear during the containment test run.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Rely on Cilium alone (do nothing at the host) | No host-level component to maintain | Single point of failure: any Cilium gap (policy missing, CRD not applied, datapath bug) has nothing behind it | None | High |
| Host-wide default-deny firewall (not scoped to lab bridges) | Simpler mental model ("deny everything, allow explicitly") | Risks stranding the host itself, especially one that is remote-streamed (this host is GAME-01, accessed remotely) — the exact failure this design explicitly avoids | Low to write, high to recover from a mistake | Host lockout |
| Cloud NAT / security-group egress allowlist (cloud equivalent) | Same purpose, managed service, survives host reboot | Not applicable in a single-VM lab; would be the natural home for this control in the AWS pathway (see `06-enterprise-scale.md`) | N/A in lab; low-medium in cloud | None significant in cloud form |

**Why this control.** DR-3.2, second half: independent of Cilium's own datapath, so a Cilium failure does not also defeat the backstop. Scoped narrowly to the lab bridges because an earlier, broader Cilium install had already stranded this same host once; the script's own comments record that lesson.

**Residual risk.**
- Not persistent across a host reboot; the containment test fails while unlocked, catching this before it's silent. See `05-gaps-and-monitoring.md`.
- Rate-limited logging (20/s, burst 40) could drop some deny-log lines; the verify script only checks at least one line exists, not a full count.

## C-NET-12 No IPv6 path

**Threat mitigated.** An IPv4-only policy set leaves IPv6 as an unfiltered side channel if it exists on the pod or node — traffic on the second stack would bypass every IPv4-focused rule above.

**Control.** k3s and Cilium are configured IPv4-only (`ipam.operator. clusterPoolIPv4PodCIDRList=10.42.0.0/16`, `dns_lookup_family: V4_ONLY` in the Envoy `dynamic_forward_proxy` clusters); no IPv6 pod CIDR, service CIDR, or route is configured anywhere in the stack. Verified by `infra/tests/03-containment.sh`: the suite fails if a workspace has any global IPv6 address or an IPv6 route.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Dual-stack with IPv6 policy mirrored | Future-proofs against IPv6-only upstreams | Doubles the policy surface to write and keep in sync (Cilium CNP, Envoy DNS family, host nftables) for no current benefit in an air-gapped/allowlisted lab | High | Higher chance of an IPv6 rule silently drifting from its IPv4 twin |
| Dual-stack with IPv6 unpoliced ("do nothing" on IPv6) | No extra work now | Direct bypass of the entire containment model documented above | None | Critical |

**Why this control.** Simplest correct choice for a single-node lab with no IPv6 upstream dependency: disabling IPv6 entirely removes an entire parallel policy surface rather than requiring it be built and kept in sync. The test suite enforces this as a hard fail condition rather than a soft check.

**Residual risk.**
- If a future dependency requires IPv6 (some upstream mirror, cloud provider requirement), this control has to be revisited as a design change, not a config tweak — see `06-enterprise-scale.md` for the AWS pathway note on this.

## C-NET-13 Noise budget: classified-and-blocked agent probe traffic

**Threat mitigated.** Not an attacker mitigation directly — this is an alert-hygiene control. Without it, benign background noise from legitimate tooling looks identical to a bypass attempt in the Hubble drop log, burying real signals and training operators to ignore denial events.

**Control.** The Coder agent's embedded Tailscale stack emits UDP port-mapping probes that no available setting disables (`CODER_BLOCK_DIRECT` and `TS_DISABLE_UPNP` were both tried against Coder 2.36.5 and neither stops them): NAT-PMP/PCP to the pod gateway (`:5351`), SSDP to the gateway and to `239.255.255.250:1900`, and a UDP probe to `203.0.113.1:12345`. Policy keeps all three blocked (they are not allowlisted); `infra/tests/ 03-containment.sh` classifies exactly these three signatures and asserts that no *other*, unexplained drop occurred during a run of otherwise-allowed work — turning "known, accepted noise" into an explicit, checked list rather than an implicit tolerance.

**Alternatives considered.**

| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Ignore the noise (do nothing) | No extra test logic | Every legitimate test run has unexplained drops, making "no drops beyond expectation" impossible to assert; real anomalies blend in | None | Reduced detection confidence over time |
| Suppress these three signatures at the Hubble/alert layer instead of asserting on them | Cleaner-looking logs | Silently discards a signal source without a test forcing someone to notice if the count or destinations change (e.g. a Coder upgrade adding a fourth probe) | Low | Silent drift if Coder's probe behavior changes |
| Patch/rebuild the Coder agent to disable Tailscale port-mapping | Removes the noise at the source | Coder OSS 2.36.5 exposes no such flag; would mean maintaining a fork | High | Fork maintenance burden for a cosmetic issue |

**Why this control.** Owner decision in the phase3 implementation findings: keep the three signatures blocked and classified, not allowlisted or ignored. Keeps the "no unexplained drops" assertion meaningful and gives Phase 6 alert rules a ready-made exact-match list.

**Residual risk.**
- The three signatures are pinned to Coder 2.36.5 behavior; an upgrade could change probe destinations, surfacing as new test failures (safe) or silently going stale if the format changes. See `05-gaps-and-monitoring.md`.

## Discrepancies found

- `workspaces.yaml`'s comments reference a separate DNS allow file (`platform/policy/workspace-dns-allow.yaml`, per the phase3 findings); it does not exist — the `**.cluster.local` pattern is inlined in `workspaces.yaml` instead.
- The phase3 spec describes Envoy as "static config (xDS in Phase 4)" with a one-host static allowlist (DR-3.6). The code (`envoy.yaml`, `admin/internal/xds/build.go`) has **no static allowlist**: the bootstrap carries only ADS/ALS wiring, and every host/route/cluster is pushed dynamically per grant. This doc follows the code (C-NET-6).
- The phase3 spec's ICMP-deny claim ("fails in under 2 s uniformly") is narrower than spike S3 found: ClusterIP destinations get no ICMP response and take ~16 s to time out (C-NET-5).

