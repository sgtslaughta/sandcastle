# Gaps and monitoring

Scope: what the controls in 01–04 do not cover at v0.4.0, how a hostile agent
would probe those gaps, which signals reveal the probing, and which of it is
checked by an automated test today. Controls are referenced by ID
(C-ISO-n, C-NET-n, C-ADM-n, C-SUP-n) and are described in their own files;
this file does not repeat them. Overview: [README](../../README.md) and
[docs/security/README.md](README.md).

Sources: the threat analyses, failure modes and "Out of scope" sections of the
[MVP](../superpowers/specs/2026-09-13-sandcastle-mvp-design.md),
[Phase 3](../superpowers/specs/2026-09-13-phase3-containment-core-design.md) and
[Phase 4](../superpowers/specs/2026-09-13-phase4-admin-control-plane-design.md)
specs (including the Phase 4 final code review, summarized in its
"Implementation findings"); `infra/tests/*.sh`;
`admin/internal/**`; `platform/**`.

Ratings are qualitative (low / med / high) for the lab as built and the
threat model in the MVP spec. They are not measured.

## 1. Known gaps

### 1.1 Resolved before v0.4.0

Findings from the Phase 4 final review that the v0.4.0 release is gated on.
They are listed so a reader of the review knows they are not open gaps.

| Review # | Area | Finding (one line) | Commit |
|---|---|---|---|
| 1 | `admin/internal/auth` | OAuth flow cookie could be replayed as a session cookie (same HMAC key, no name binding), giving an empty user with an empty CSRF token that matched; fix binds the cookie name into the MAC and rejects empty ID/CSRF. | `ac74876` |
| 2 | `admin/internal/auth` | Open redirect: `/login?next=/%09/evil.com` passed prefix checks and browsers turned it into `//evil.com`; fix parses the URL and rejects control characters, backslashes, scheme and host. | `ac74876` |
| 3 | `policy`, `xds` | An exact-host grant shadowed a same-port zone wildcard (Envoy prefers the exact vhost), cutting every other workspace off that host; fix merges wildcard IPs into matching exact keys. | `46bb834` |
| 4 | `platform/admin/admin.yaml` | Admin ran with the Postgres owner DSN, so code execution in admin could rewrite audit; fix runs migrations in an initContainer and gives the main container the app DSN only. | `2393f4e` |
| 5 | `admin/internal/web` | Request link parameter `ws=` overrode `src=`, letting an agent-crafted link target another workspace ID (bounded by the owner check); fix accepts `ws` only without `src` and shows the workspace ID. | `057d88f` |
| 6 | `admin/internal/cilium` | `Apply` stopped at the first error and skipped pruning, so revoked DNS grants could stay live; fix continues, collects errors, always prunes. | `58f2527` |
| 7 | `cmd/sandcastle-admin` | `ExpireGrants` in the main loop had no timeout; a hung database stalled all rebuilds; fix adds `context.WithTimeout`. | `222e655` |
| 10 | `store`, `xds` | Two SQL statements per 403 even when throttled, so a random-host flood produced steady DB write load; fix adds an in-memory 1 s skip and runs the cap DELETE only on insert. | `a0e1281` |
| 11 | `infra/bootstrap/05-admin.sh`, `infra/tests/04-admin.sh` | Test owner token on curl argv and never revoked, and `workspace-dns-allow` deleted before admin was up; fix removes the argv exposure and reorders. (The `TEST_HOOKS=1` default is not changed; see G-17.) | `2604add` |

Review item #12 (CNPs named by zone ID rather than name; `internal/als`
folded into `internal/xds`) is spec drift, not a security gap. Its third
point, plain HTTP to a 443-only host returning 404, is tracked as G-24.

### 1.2 Open gaps

L/I = likelihood / impact. "Phase n" refers to the MVP spec phase list;
"Prod" means a production delta that the lab will not build.

| ID | Gap | Affected controls | Attacker scenario | L/I | Current compensating control | Recommended fix | Target |
|---|---|---|---|---|---|---|---|
| G-1 | Host nftables lock is not persistent across a host reboot (`infra/vm/01-host-egress-nft.sh`). | C-NET-11, C-SUP-6 | Host reboots; the VM comes back with only Cilium between a workspace and the internet. A Cilium policy failure in that window is not caught by a second layer. | L: med / I: high | `03-containment.sh` first check fails while unlocked; `make verify-host-egress`; egress gateway still SNATs only Envoy/Nexus/coderd. | Install the table as a systemd unit or `nftables.service` include so it loads before libvirt networks start. | Phase 6 (lab); Prod: VPC firewall owned by another team |
| G-2 | coderd has egress to public 443 for Terraform provider downloads. | C-SUP-8, C-NET-9 | Code execution in coderd (CVE on an agent path, or a malicious template) gives an outbound HTTPS channel to any public host that bypasses Envoy logging. | L: low / I: high | coderd CNP limits ports; private ranges excluded (C-NET-9); egress gateway IP; L7 path allowlist (C-NET-2) shrinks the reachable API. | Nexus Terraform provider mirror (or `provider_installation` filesystem mirror) and remove the 443 rule. | Phase 5 |
| G-3 | Node image pulls, helm charts and binaries need `make egress-unlock`. | C-SUP-6, C-SUP-4, C-NET-11 | Operator forgets to relock, or a bootstrap step runs a long time; the VM primary IP has open internet while workspaces may be running. | L: med / I: med | Tests fail while unlocked; images use `imagePullPolicy: Never`; VM snapshots before risky steps. | Node registry mirror on Nexus (`registries.yaml`) and a vendored chart/binary cache; delete the toggle. | Phase 5 |
| G-4 | Single node and single replica for Envoy, admin, admin Postgres, coder-db and Nexus (`replicas: 1` in `platform/**`). | C-ADM-8, C-NET-6, C-ADM-10, C-SUP-1 | A runaway loop or a crash takes down egress, approvals, audit writes or packages for every workspace. Not a confidentiality break (fails closed) but an availability one that pressures operators to relax controls. | L: med / I: med | Fail-closed design (DR-4.6); running Envoy keeps its last snapshot; tested in `04-admin.sh`. | Multi-node: Envoy DaemonSet, admin leader election, CloudNativePG, Nexus HA or per-AZ mirror. See `07-enterprise-scale.md`. | Prod |
| G-5 | xDS and ALS between Envoy and admin are plaintext gRPC on :18000. | C-ADM-6, C-ADM-13, C-ADM-12 | A compromised pod that can reach :18000, or a node-level attacker, serves Envoy a permissive snapshot or reads the denial stream. | L: low / I: high | CNP `platform/policy/admin.yaml` admits :18000 only from the Envoy pod; single node, no wire between nodes. | mTLS with per-pod certificates (cert-manager or SPIFFE/SPIRE); pin the server identity in the Envoy bootstrap. | Prod (multi-node) |
| G-6 | Workspace identity is the pod source IP. | C-NET-8, C-ADM-9 | (a) A pod is deleted and its IP is reassigned to another workspace before the rebuild removes the grant (~1 s window). (b) If Cilium anti-spoofing were bypassed or disabled, a workspace could send from a granted IP. | L: low / I: med | Watcher uses Running pods with an IP only and rebuilds on every pod event; Cilium BPF anti-spoofing enforced outside the Kata guest. | Bind grants to Cilium security identity or SPIFFE ID (Envoy `principal` on a peer certificate or Cilium identity metadata). | Prod |
| G-7 | No TLS interception: Envoy sees only the CONNECT authority and SNI. | C-NET-7, C-NET-6 | Agent uses an allowed TLS session to send arbitrary data. On a shared CDN the inner HTTP `Host` header can name a different tenant than the SNI (domain fronting inside TLS). | L: med / I: high | SNI must match the allowed authority (C-NET-6); narrow allowlist; required expiry (C-ADM-5); 1 h tunnel cap (C-ADM-7). | Per-zone TLS inspection at an enterprise edge for selected categories (see 06); do not allowlist multi-tenant CDN front doors. | Prod / per zone |
| G-8 | Any allowlisted host is a full exfil channel (e.g. `github.com` gist, SaaS upload). | C-ADM-4, C-ADM-5, C-ADM-6 | Prompt-injected agent pushes source or secrets to an attacker-owned repo or account on an allowed SaaS. | L: high / I: high | Human-confirmed requests (C-ADM-2); expiry; `bytes_up` in the Envoy access log (no alert yet). | DLP/CASB tenant restrictions (06); per-workspace byte budgets (Phase 6); prefer internal mirrors to SaaS grants. | Phase 6 + external |
| G-9 | No rate limits, byte budgets or circuit breaker. | C-ADM-12, C-NET-2, C-NET-6 | Runaway agent hammers coderd agent paths, Nexus or an allowed host; denial floods load Postgres; a slow exfil runs unbounded. | L: high / I: med | ALS per-key throttle and 200-row cap (C-ADM-12); tunnel cap; Coder API rate limit. | Envoy local/global rate limit per source IP; Phase 6 breaker flips the workspace CNP to deny-all. | Phase 6 |
| G-10 | No runtime detection in the guest (Falco not deployed); honeytokens not built into images. | C-SUP-7, C-NET-13 | Agent reads credential paths, calls `unshare`/`mount`/`keyctl`, starts listeners, or adds git remotes without any alert. Only network attempts are visible. | L: high / I: med | Every network escape is visible in Hubble/Envoy/nft logs; noise budget classifies known probes. | Falco in guest with a relay the workspace cannot tamper with; honeytoken files and hostnames in `images/base`. | Phase 6 |
| G-11 | No brokers (cred-broker, data-broker); mock enclaves not built; any in-cluster lateral path is Cilium-only. | C-NET-1, C-NET-11 | Once enclaves exist in-cluster, a Cilium policy error exposes them with no second layer. Git credentials would otherwise end up in workspace env or images. | L: low today / I: high | Nothing sensitive exists in the cluster yet; DR-3.3 moves enclaves off-cluster. | Build Phase 5 as designed: off-cluster enclaves behind host nftables, short-lived broker tokens. | Phase 5 |
| G-12 | Kata guest kernel or Cloud Hypervisor escape. | C-ISO-1, C-ISO-3 | Agent with root in the guest exploits a guest kernel bug plus a CLH/virtio bug and runs on the node, where Cilium, Hubble and Envoy logs live. | L: low / I: high | Hardware virtualization boundary; admission forces Kata; no host mounts; lab VM as an outer boundary (C-ISO-7). | Patch cadence for Kata/CLH; in-guest `runsc` for untrusted code (Phase 5 spike); confidential VMs (06); node EDR. | Phase 5 spike + Prod |
| G-13 | DinD sidecar runs dockerd as root inside the Kata VM. | C-ISO-5 | Any container the agent starts can become root in the guest (`--privileged`, `--network host`). Network effect is contained; guest-level integrity is not. | L: high / I: low | Kata boundary; Cilium enforces outside the guest; `--network host` egress test in `03-containment.sh`. | In-guest `runsc` as default runtime for `docker run`; rootless dockerd where builds allow. | Phase 5 |
| G-14 | Admin login depends on Coder's OAuth2 provider, an experimental feature (`CODER_EXPERIMENTS=oauth2`). | C-ADM-1 | A Coder upgrade changes or breaks the flow; an experimental code path has an auth bug. | L: med / I: med | PKCE + state validated; role re-read from `/api/v2/users/me` at login; enforcement unaffected when login fails. | Corporate IdP via OIDC for both Coder and admin (06); re-run spike S1 on every Coder upgrade. | Prod |
| G-15 | Sessions are not revocable server-side; TTL 8 h (`auth.go` `sessionTTL`). Review #9. | C-ADM-11 | An admin demoted or disabled in Coder keeps admin rights in sandcastle-admin until the cookie expires. A stolen cookie works for 8 h. | L: low / I: high | HMAC-signed, HttpOnly, SameSite=Lax cookies; CSRF token; lab UI only on the lab network. | Server-side session table with revoke on logout and on role change; shorter TTL with re-check of `users/me`. | Phase 5 |
| G-16 | Audit identity is the Coder username, which is mutable. Review #8. | C-ADM-10 | A user renamed to `test-hook` or to a former admin's name makes audit rows ambiguous; `self_approved` compares names. | L: low / I: med | Append-only audit by DB grants; renames visible in Coder. | Store and compare the Coder user ID; show username as display text. | Phase 5 |
| G-17 | The test-hook bearer is created by default in the lab (`TEST_HOOKS=1` in `infra/bootstrap/05-admin.sh`). | C-ADM-14 | Anyone who reads secret `admin-test-token` (kubectl access, backup, node compromise) acts as an admin over HTTP. | L: low / I: high | Secret only in `sandcastle-admin` ns; admin RBAC has no secret read; constant-time compare. | Default `TEST_HOOKS=0`; tests create a short-lived token and delete it on exit. | v0.4.x |
| G-18 | Hubble flows, Envoy stdout logs and the admin DB live on the node; nothing is shipped off-box. Host nft log is rate-limited to 20/s. | C-SUP-7, C-NET-13, C-ADM-10 | Node compromise (after G-12) deletes or edits evidence. Hubble's ring buffer overwrites old flows under load. A flood past 20 packets/s loses nft log lines. | L: med / I: med | Append-only audit against the app role; nft journal is on the host, outside the VM. | Off-box shipping to WORM storage (Hubble exporter, Envoy ALS fan-out, audit export); Loki in Phase 6 and SIEM (06). | Phase 6 + external |
| G-19 | Kata guest clocks drift (~2 min observed; `infra/tests/04-admin.sh` `ws_offset`). | C-SUP-7 | Timestamps taken inside a workspace do not line up with node, Envoy and audit time; an investigator mis-orders events or misses correlation. | L: high / I: low | Enforcement and audit timestamps are taken on the node/DB, not in the guest; tests correct for offset. | Enable guest time sync (PTP/`chrony` via kvm-clock in the guest); record offset at workspace start. | Phase 6 |
| G-20 | Ubuntu 26.04 ships uutils coreutils; some flags differ from GNU (e.g. `date +%3N` ignored). | C-SUP-7 | A verify check silently computes the wrong value and passes. Not attacker-driven; a false-assurance risk. | L: med / I: med | Positive controls gate negative checks; known quirk worked around in `04-admin.sh`. | Prefer shell arithmetic / python over flag-dependent coreutils in tests; add self-tests for timing helpers. | v0.4.x |
| G-21 | Nexus proxies public upstreams and serves the same cached artifact to every workspace. | C-SUP-1, C-NET-3 | A poisoned or typosquatted PyPI/npm/Docker Hub package is fetched once and then served cluster-wide. In the lab, a package name can also encode data to upstream. | L: med / I: high | GET/HEAD-only L7 rules; anonymous read; no uploads from workspaces. | Package firewall / curation (06); pinned lockfiles; production Nexus fed only by an airlock. | Prod + external |
| G-22 | Agent-generated code reaching CI and enclaves (the MVP's top-ranked threat, supply-chain bridge). | none in-product yet | Agent commits a backdoor that passes review and is promoted into an enclave build. Network containment does not see this. | L: med / I: high | Out of sandbox today: human code review in the SCM. | CI on clean checkout outside workspaces; signed commits and provenance gates (Sigstore, SLSA); promotion gate (06). | Phase 5 + Prod |
| G-23 | Approvers can be socially engineered through request justification text. | C-ADM-2 | Agent writes a convincing reason into the 403 page context; the owner copies it; an approver grants a broad or wildcard host. | L: med / I: high | Filing requires the owner's browser session; required expiry; `self_approved` flag; strict name validation (C-ADM-4). The request form accepts any valid name, including `*.suffix`, so a wildcard request is possible. | Grant catalog and policy-as-code for common hosts; second approver for wildcards (06). | Phase 6 |
| G-24 | Plain HTTP to a host that is allowed only on 443 returns 404 and records no denial row (review #12). | C-ADM-12, C-NET-6 | Agent probes `http://allowed-host/` repeatedly; the attempts do not appear in the `denials` table or request queue. | L: med / I: low | Envoy stdout access log still has the line (code 404, source IP). | Add a deny route for port 80 on 443-only vhosts that returns 403 with the header. | v0.4.x |
| G-25 | Admin UI is plain HTTP on NodePort 30081; cookies lack `Secure` (`auth.go` ponytail comment). | C-ADM-11 | Anyone on the lab network path sniffs a session cookie or OAuth code. | L: low (lab) / I: high | NodePort reachable only on the lab network; no workspace route (C-ADM-2). | TLS termination in front of the UI; set `Secure`; HSTS. | Prod |
| G-26 | Coder agent paths remain a channel to coderd. | C-NET-2 | coderd CVE on `/api/v2/workspaceagents/me/*` or `/derp`; staged low-bandwidth exfil through agent logs and metadata. | L: low / I: med | Four GET patterns only (spike S5); `CODER_BLOCK_DIRECT`; agent token scoped to its workspace. | Patch cadence; volume alert on agent log size (Phase 6); re-capture paths on upgrade. | Phase 6 |
| G-27 | SNI listener names hash the whole IP set per host (`admin/internal/xds/build.go` `hashName`), so any workspace start or stop in a zone renames that zone's host listeners and drains every workspace's open tunnels to those hosts within 5 s. Found during documentation review; `04-admin.sh` does not cover concurrent pod churn. | C-ADM-6, C-ADM-7 | Not an access leak (fails closed). An agent that restarts its own workspace repeatedly resets other users' long-lived tunnels (git, streaming) to shared zone hosts: nuisance-level denial of service. | L: med / I: low (lab), high (500+ users) | Clients reconnect; 1 h cap already bounds tunnels. | Rename only when an IP is removed, and separate zone-rule listeners from grant listeners; or per-workspace filter chains (spike alternative C). See 07 section 5. | Before tier 500 |

## 2. Attack vectors to watch

A hostile agent's likely playbook, ordered from most to least likely. "Signal"
refers to rows in section 3.

| # | Vector | What the agent does | What stops it | Where it shows |
|---|---|---|---|---|
| 1 | Proxy-env bypass | `curl --noproxy '*'`, unset `HTTPS_PROXY`, raw sockets, other runtimes that ignore env. | C-NET-1 drop, C-NET-5 ICMP deny, C-NET-11 host drop | S-2 Hubble DROP |
| 2 | DNS tunneling | Encode data in query names; try TXT/NULL records; use a DoH endpoint. | C-NET-4 (only `**.cluster.local`), CoreDNS authoritative for the zone; DoH needs an allowed host | S-3 refused DNS |
| 3 | Allowlisted-host exfil | Push to an allowed SaaS (git push, gist, paste, issue comment). | Narrow allowlist, expiry (C-ADM-5); nothing detects content (G-7, G-8) | S-13 `bytes_up` spike |
| 4 | CONNECT / SNI games | CONNECT to an allowed host with a different SNI; no SNI; IP literal authority; `Host` fronting inside TLS. | C-NET-6 SNI binding, C-ADM-4 no IPs; fronting inside TLS is not stopped (G-7) | S-4 NR entries |
| 5 | Coder API abuse | Call coderd user, template or workspace APIs from the workspace; brute-force login. | C-NET-2 L7 allowlist (403) | S-2 L7 drop on coderd |
| 6 | Nexus write or abuse | `PUT`/`POST` to repositories, REST API, name-encoded upstream fetches, cache poisoning. | C-NET-3 GET/HEAD `/repository/*` only; name exfil not stopped in lab (G-21) | S-2 L7 drop on Nexus; Nexus request log |
| 7 | DinD and host networking | `docker run --privileged --network host`, guest iptables edits, new bridges. | Cilium enforces outside the guest (C-ISO-5, C-NET-1) | S-2 |
| 8 | Cluster and node probing | kube-apiserver, kubelet :10250, node ports, other workspaces, admin :30081/:18000, Envoy admin :9901. | C-ISO-4, C-NET-1, C-ADM-13 | S-2 (ClusterIPs drop silently) |
| 9 | Kata escape attempts | Kernel exploits, `/dev` probing, virtio fuzzing, module load. | C-ISO-1, C-ISO-3; no runtime detection (G-10, G-12) | Node kernel logs only; Falco in Phase 6 |
| 10 | Flooding denials to hide signal | Thousands of 403s to random hosts, or UDP spray, so real attempts get lost. | Denial throttle and 200-row cap (C-ADM-12); noise budget (C-NET-13) | S-1 unique-host rate; nft log rate limit (G-18) |
| 11 | Social engineering the approval queue | Plant justification text; ask the developer to request a broad host "to finish the task". | Human in the loop (C-ADM-2); expiry; self-approval flag | S-5, S-6, S-7 |
| 12 | IP reuse race | Churn pods to land on an IP that held a grant. Needs coderd pod creation or node access. | C-ADM-9 Running-only, rebuild on pod event | S-16 pod churn events |
| 13 | Timing around expiry and revocation | Open a tunnel just before expiry; reconnect in the drain window; use the 30 s expiry tick. | Listener rename closes tunnels within 5 s (C-ADM-7); expiry tick up to 30 s late | S-12 tunnel duration; audit `expire` vs last Envoy 200 |
| 14 | Long-lived tunnels | Keep one CONNECT busy for up to 1 h for bulk transfer. | 1 h cap (DR-4.10) | S-12, S-13 |

## 3. Monitoring signals

No alert routing exists until Phase 6 (Loki/Grafana). The queries below run
against what is on the node today, so they double as the Phase 6 rule list.
Thresholds are starting points to tune, not measured baselines.

Sources and where they live:
- Hubble: `kubectl -n kube-system exec ds/cilium -- hubble observe ...` (ring buffer in the agent; relay and UI enabled in `infra/bootstrap/01-k3s-cilium.sh`).
- Envoy stdout JSON: `kubectl -n sandcastle-egress logs deploy/envoy-egress`. Fields: `time, src, method, authority, code, flags, bytes_up, bytes_down`; stage-2 lines add `stage:"sni", sni`.
- ALS denials table and audit table: `psql` in `statefulset/admin-db`, database `admin`.
- Kubernetes events: `kubectl get events -A`.
- Coder audit: Coder's audit log (check licence tier; it may not be available in OSS 2.36.5).
- Host nft journal: `journalctl -k | grep sandcastle-deny` on the lab host.

| ID | Signal | Source | Query / detection logic | Suggested threshold | Response |
|---|---|---|---|---|---|
| S-1 | Many 403s to many unique hosts from one workspace | Envoy stdout; denials table | `jq -r 'select(.code=="403") \| [.src,.authority] \| @tsv' \| sort -u \| cut -f1 \| uniq -c`; SQL: `SELECT workspace_id, count(*) FROM denials WHERE first_seen > now() - interval '1 hour' GROUP BY 1` | > 20 unique hosts/h per workspace; any workspace at the 200-row cap | Page owner; review agent transcript; consider zone move to a restricted zone |
| S-2 | Hubble DROP from a workspace to kube-apiserver, kubelet, node IP, another workspace, `sandcastle-admin`, Envoy admin, coder-db | Hubble flows | `hubble observe --namespace sandcastle-workspaces --verdict DROPPED -o json`, then exclude the three noise signatures in `infra/tests/03-containment.sh` (UDP 5351/1900 to gateway, SSDP multicast, UDP 203.0.113.1:12345) | Any 1 | Page. Identify pod via labels; snapshot evidence; stop workspace if repeated |
| S-3 | DNS query refused for a non-cluster name | Hubble DNS | `hubble observe --namespace sandcastle-workspaces --protocol dns --verdict DROPPED` | > 10 distinct names/10 min per workspace, or any label > 40 chars / high entropy | Warn; if entropy-based match, page as DNS exfil attempt |
| S-4 | SNI mismatch refusals | Envoy stdout, stage 2 | `jq 'select(.stage=="sni" and .flags=="NR")'` | Any 1 (legitimate clients do not do this) | Page; record `sni` value; check if it is a CDN fronting attempt |
| S-5 | Self-approved grant | audit table | `SELECT * FROM audit WHERE action='approve' AND detail->>'self_approved'='true'`. Also `action='grant'` where the actor owns the workspace (direct grants are not flagged). | Any 1 | Second admin reviews within one business day |
| S-6 | Approval outside business hours | audit table | `SELECT * FROM audit WHERE action IN ('approve','grant','rule_add') AND extract(hour FROM at AT TIME ZONE 'site-tz') NOT BETWEEN 8 AND 18` | Any 1 | Review next business day; confirm with the approver out of band |
| S-7 | Grant or zone rule to a wildcard domain | audit table | `SELECT * FROM audit WHERE action IN ('approve','grant','rule_add') AND detail->>'value' LIKE '*.%'` | Any 1 | Review; zone wildcards are permanent and affect every member |
| S-8 | Reconcile errors | audit table; admin logs | `SELECT * FROM audit WHERE action='reconcile_error' AND at > now() - interval '15 min'`; `kubectl -n sandcastle-admin logs deploy/sandcastle-admin \| grep reconcile:` | Any 1; page if repeated for > 5 min | Check CNP apply errors; a stuck reconcile can leave revoked DNS grants live |
| S-9 | Envoy not Ready or xDS disconnected | Kubernetes; Envoy logs | `kubectl -n sandcastle-egress get deploy envoy-egress -o jsonpath='{.status.readyReplicas}'`; Envoy log lines matching `rejected\|NACK\|gRPC config stream closed` | readyReplicas < 1 for 1 min; any NACK | Page platform on-call; egress is failing closed |
| S-10 | Admin down | Kubernetes | `kubectl -n sandcastle-admin get deploy sandcastle-admin -o jsonpath='{.status.readyReplicas}'` = 0; events for scale changes | 0 for 2 min; any manual scale to 0 outside a change window | Page; running Envoy keeps last snapshot, so revocations and expiries are not applied |
| S-11 | `sandcastle-deny` lines from the VM primary IP | Host journal | `journalctl -k --since -5min \| grep 'sandcastle-deny' \| grep "SRC=<VM primary IP>"` | Any from the primary IP outside a bootstrap window | Page: something in the VM bypassed Cilium or the egress gateway |
| S-12 | Tunnel duration near 1 h | Envoy ALS / stdout | Stdout format has `time` (start) but no duration; add `%DURATION%` or read `time_to_last_downstream_tx_byte` from ALS. Flag CONNECT with duration > 50 min | > 3 per workspace/day | Review destination and `bytes_up` |
| S-13 | `bytes_up` spike on an allowlisted host | Envoy stdout | Sum `bytes_up` by `src, authority` per hour; compare to 7-day per-workspace baseline | > 50 MB/h or > 10x baseline | Page; treat as exfil until explained; revoke grant |
| S-14 | New zone created or default zone changed | audit table | `SELECT * FROM audit WHERE action IN ('zone_create','zone_clone','zone_default','zone_delete')` | Any 1 | Confirm against change record |
| S-15 | Requests with long or instruction-like justification | requests table | `SELECT * FROM requests WHERE length(justification) > 500 OR justification ~* '(ignore\|urgent\|approve\|admin)'` | Any 1 | Approver reads carefully; route to second approver |
| S-16 | Pod churn in the workspace namespace | Kubernetes events | Count `Killing`/`Scheduled` events per workspace label per 10 min | > 5 restarts/10 min | Investigate IP reuse attempt or crash loop |
| S-17 | coderd non-agent path attempts | Hubble L7 | `hubble observe --namespace sandcastle-workspaces --protocol http --verdict DROPPED` to `coder` ns | Any 1 | Page; agent is probing coderd API |
| S-18 | Coder role changes | Coder audit (if available) or periodic `GET /api/v2/users` diff | Any user gains `owner` or `user-admin` | Any 1 | Review; remember G-15: demotion does not end existing admin sessions |
| S-19 | Unexplained drops during normal work | Hubble | The noise-budget filter from `03-containment.sh`, run continuously | Any non-signature drop | Treat as S-2; if a new tool, classify and document |

## 4. Verification coverage map

What is exercised by an automated test at v0.4.0. "Partial" means the
mechanism is tested but not the whole attacker scenario.

Suites: `infra/tests/03-containment.sh` (VM, 35 checks),
`infra/tests/04-admin.sh` (VM, 39 checks), `admin/hack/smoke.sh`
(real Envoy v1.39.1 on Docker), Go unit tests in `admin/internal/**`.

### 4.1 Gaps

| Gap | Automated coverage | Test |
|---|---|---|
| G-1 host lock not persistent | Partial: detects lock off, does not test reboot | `03-containment.sh` host-layer check; `make verify-host-egress` |
| G-2 coderd 443 | None | — |
| G-3 egress unlock | Partial: tests fail while unlocked | `03-containment.sh` first check |
| G-4 single node SPOF | Partial: fail-closed with admin down and Envoy restarted | `04-admin.sh` fail-closed section |
| G-5 plaintext xDS | Partial: CNP admits only Envoy; workspace cannot reach :18000 | `04-admin.sh` admin-unreachable checks |
| G-6 source-IP identity | Partial: grant applies to one workspace only; Running-only filter | `04-admin.sh`; `watch` `TestPods`; `policy` `TestHostIPs` |
| G-7 no TLS interception | Partial: SNI mismatch refused and logged; fronting inside TLS not tested | `03-containment.sh` SNI checks; `xds` `TestHostsRenderRBACAndSNIBinding` |
| G-8 allowlisted exfil | None | — |
| G-9 rate limits | Partial: denial throttle and cap | `store` `TestDenialsThrottleAndCap` |
| G-10 runtime detection | None (not built) | — |
| G-11 brokers/enclaves | None (not built) | — |
| G-12 Kata escape | None (substrate only proves Kata kernel is separate) | `01-isolation-substrate.sh` |
| G-13 DinD root | Partial: `--network host` egress blocked | `03-containment.sh` |
| G-14 OAuth2 experiment | Partial: flow logic against an `httptest` fake coderd | `auth` `TestLoginFlowAdmin`, `TestCallbackRejectsWrongState` |
| G-15 session revocation | None | — |
| G-16 username identity | Partial: `self_approved` recorded | `store` `TestRequestFlow` |
| G-17 test hook default | Partial: `Require` handles bearer | `auth` `TestRequire` |
| G-18 on-node logs | Partial: audit append-only | `04-admin.sh` UPDATE refused; `store` `TestAuditIsAppendOnly` |
| G-19 clock skew | Worked around, not tested | `04-admin.sh` `ws_offset` |
| G-20 uutils quirks | None | — |
| G-21 Nexus bridge | Partial: PUT and REST API refused | `03-containment.sh` |
| G-22 code to CI | None | — |
| G-23 social engineering | None | — |
| G-24 HTTP 404 no denial | None | — |
| G-25 plain HTTP UI | None | — |
| G-26 coderd agent paths | Partial: non-agent paths and login refused | `03-containment.sh` |
| G-27 listener churn | None | — |

### 4.2 Attack vectors

| Vector (section 2) | Blocked asserted | Visible asserted | Test |
|---|---|---|---|
| 1 Proxy-env bypass | Yes (1.1.1.1, fast fail) | Yes (Hubble drop within 5 s) | `03-containment.sh` |
| 2 DNS tunneling | Yes (`example.com` refused) | Yes (Hubble DNS event) | `03-containment.sh`; DNS grant scope in `04-admin.sh` |
| 3 Allowlisted-host exfil | No | No | — |
| 4 CONNECT / SNI games | Yes (SNI mismatch) | Yes (NR log line) | `03-containment.sh`; `admin/hack/smoke.sh` |
| 5 Coder API abuse | Yes (`/api/v2/users`, login) | Yes (Hubble L7) | `03-containment.sh` |
| 6 Nexus write | Yes (PUT, REST API) | Partial (Hubble L7 not asserted for Nexus) | `03-containment.sh` |
| 7 DinD / host network | Yes | No explicit visibility check | `03-containment.sh` |
| 8 Cluster/node probing | Yes (kube API, kubelet, peer pod, coder-db, admin) | Partial (peer and kube API not asserted in Hubble) | `03-containment.sh`, `04-admin.sh` |
| 9 Kata escape | No | No | — |
| 10 Denial flooding | Partial (throttle/cap unit test) | Partial (denial row recorded) | `store` `TestDenialsThrottleAndCap`; `04-admin.sh` |
| 11 Approval social engineering | No | Partial (self-approval in audit) | `store` `TestRequestFlow` |
| 12 IP reuse race | Partial (Running-only filter) | No | `watch` `TestPods` |
| 13 Expiry/revocation timing | Yes (revoke < 5 s, tunnel closed, expiry enforced) | Yes (`expire` audited) | `04-admin.sh` |
| 14 Long-lived tunnels | Partial (cap present in rendered config) | No | `xds` `TestHostsRenderRBACAndSNIBinding` asserts `maxStreamDuration: 3600s`; the cap is not run end to end |

Rule for new tests (C-SUP-7): each new check asserts the positive control
first, then the block, then the signal.
