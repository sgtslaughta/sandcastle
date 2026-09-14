# External controls and roadmap

Scope: controls outside sandcastle that would raise security, in-product
enhancements planned for later phases, and ways to cut the approval workload
without losing the human-in-the-loop property. Gap IDs (G-n) and signal IDs
(S-n) refer to [05-gaps-and-monitoring.md](05-gaps-and-monitoring.md); control
IDs refer to 01–04. Overview: [README](../../README.md) and
[docs/security/README.md](README.md). AWS sizing and HA design are in
[07-enterprise-scale.md](07-enterprise-scale.md).

Cost and effort figures are **order-of-magnitude estimates, dated 2026-09**.
Effort is engineer-weeks for a team that already runs the lab. Licence cost is
a relative tier: `$` (open source or bundled), `$$` (per-user or per-node
commercial product), `$$$` (enterprise platform with a services contract).
Check current vendor pricing before budgeting.

## 1. External controls

Controls owned by other teams or products. Each closes or narrows gaps that
sandcastle cannot close on its own, usually because the gap is about content,
identity or evidence rather than reachability.

### 1.1 Corporate IdP with MFA via OIDC in front of Coder

- **What.** Coder and sandcastle-admin authenticate against the enterprise IdP (Okta, Entra ID, Keycloak, AWS IAM Identity Center) over OIDC with phishing-resistant MFA (FIDO2). Group claims map to Coder roles, so admin rights come from IdP groups.
- **Closes.** G-14 (removes reliance on the experimental OAuth2 provider for admin login if admin talks OIDC directly), G-15 partly (IdP session revocation and short token lifetimes), G-16 (stable subject IDs), G-25 partly (IdP flows require TLS).
- **Cost/effort.** 1–2 weeks. `$`–`$$` (existing IdP usually covers it).
- **Trade-offs.** The IdP becomes a dependency for login, not for enforcement (C-ADM-8 still holds). In an air-gapped VPC the IdP must be reachable inside the enclave network or federated through a broker. Group-to-role mapping becomes a new place to misconfigure admin rights; cover it in periodic access reviews (1.11).

### 1.2 SIEM with off-box log shipping

- **What.** Ship every evidence stream off the node within seconds: Hubble flow exporter (or Hubble Relay to a collector), a second Envoy ALS sink or a stdout collector (Fluent Bit / Vector), `audit` table export (logical replication or periodic dump) to S3 Object Lock in compliance mode (WORM), host `sandcastle-deny` journal via the host agent. Correlate in a SIEM (Splunk, Elastic, OpenSearch Security Analytics, Sentinel) with workspace ID as the join key.
- **Closes.** G-18 (tampering after node compromise; ring-buffer loss), G-19 partly (single time source at ingest), and turns section 3 of 05 into alerts rather than queries.
- **Cost/effort.** 3–6 weeks for pipelines and the S-1..S-19 rules. `$$`–`$$$` driven by ingest volume; Hubble flows dominate volume, so export DROPPED and L7 verdicts plus sampled FORWARDED.
- **Trade-offs.** Logs contain hostnames, source code paths in URLs and justification text; the SIEM becomes sensitive. Shipping adds an egress path from the platform namespace, which must itself be an allowlisted, internal-only destination. Ingest lag must stay under the "visible within seconds" claim for paging signals.

### 1.3 DLP / CASB for allowlisted SaaS

- **What.** For SaaS hosts that must be granted (GitHub, package registries with publish rights, AI APIs), route through a CASB or use tenant restrictions: only the corporate org or tenant is reachable, uploads are inspected for secrets and source markers, personal accounts are blocked.
- **Closes.** G-8 (allowlisted host as exfil channel) for the covered SaaS; G-7 partly (content visibility for those hosts).
- **Cost/effort.** 4–8 weeks including policy tuning. `$$$`.
- **Trade-offs.** Requires TLS inspection for inline modes (1.4) or API-mode integration with the SaaS. False positives block legitimate pushes. Does nothing for non-covered hosts, so the allowlist must stay narrow anyway.

### 1.4 TLS inspection at the enterprise edge for selected categories

- **What.** An upstream forward proxy or NGFW (downstream of Envoy's egress gateway IP) decrypts selected categories: file sharing, paste sites, generic cloud storage, personal webmail. Pinned or sensitive categories (banking, health, package registries with signature checks) are bypassed.
- **Closes.** G-7 (domain fronting inside TLS, content blindness) and G-8 for inspected categories.
- **Cost/effort.** 4–8 weeks, mostly CA distribution into images and exception handling. `$$`–`$$$`.
- **Trade-offs.** DR-3.4 declined interception inside sandcastle because it concentrates every secret in one component and breaks pinned tools and DinD builds. Doing it at the edge keeps Envoy simple but moves the same risks to the edge team: CA key is a crown jewel; images need the enterprise CA; bundled-CA tools (some language runtimes, `docker` pulls) fail. Scope it per zone, never globally.

### 1.5 EDR on nodes

- **What.** An endpoint agent on each Kubernetes node (not in workspaces): process lineage, kernel module load, unexpected binaries, writes to Kata, containerd and Cilium state, tamper protection that reports to an off-box console.
- **Closes.** G-12 detection after a guest escape, G-18 partly (tamper alerts), G-5 partly (unexpected processes talking to :18000).
- **Cost/effort.** 1–3 weeks to deploy and tune against Kata and Cilium eBPF noise. `$$` per node.
- **Trade-offs.** EDR agents run with full node privilege and are themselves an attack surface and a supply-chain dependency. eBPF-based EDR can conflict with Cilium programs; validate on a snapshot first (C-SUP-6). Does not see inside Kata guests.

### 1.6 Hardware roots of trust and confidential VMs

- **What.** TPM-backed measured boot and remote attestation for nodes; confidential computing (AMD SEV-SNP or Intel TDX) for Kata guests (Kata supports confidential containers with attestation via Trustee/KBS).
- **Closes.** G-12 narrows (host or hypervisor compromise cannot read guest memory), node integrity before workloads schedule.
- **Cost/effort.** 6–12 weeks; depends on instance families that expose SEV-SNP and nested virtualization. `$$` in instance premium.
- **Trade-offs.** Confidential VMs protect the guest from the host, which is the reverse of sandcastle's main threat (guest attacking host). The value is integrity attestation and protection of workspace secrets from a compromised node, not escape prevention. Availability of SEV-SNP with nested virt differs between AWS commercial and GovCloud regions; check before committing (see 07).

### 1.7 Network firewall with FQDN allowlists

- **What.** An independent L3/L7 firewall at the VPC edge (AWS Network Firewall with Suricata domain lists, or an NGFW) that permits only the egress gateway IP to the union of approved FQDNs, and drops everything else. Owned by a different team.
- **Closes.** G-1 and G-3 in production (the host nftables lock is replaced by an always-on, persistent control); G-2 partly (coderd 443 limited to the Terraform registry FQDNs); adds a third layer for G-6 and G-7 misconfigurations.
- **Cost/effort.** 2–4 weeks, plus a sync job from sandcastle zones to firewall domain lists. `$$`.
- **Trade-offs.** SNI-based FQDN matching has the same fronting limits as Envoy. Keeping the firewall list in sync with per-workspace grants is not practical; sync zone baselines and a coarse union only, and let Envoy do per-workspace decisions. Change lead time on the firewall slows zone updates.

### 1.8 Package firewall and curation

- **What.** Put a policy layer in front of Nexus upstreams: Sonatype Nexus Firewall/Repository Firewall, JFrog Artifactory with Xray/Curation, Socket, or deps.dev/OpenSSF Scorecard checks in a curation job. Quarantine new versions for a cool-off period, block known-malicious and typosquatted names, block install scripts from unknown publishers.
- **Closes.** G-21 (Nexus as supply-chain bridge) and the lab-only name-encoded upstream fetch (production Nexus is fed by an airlock only).
- **Cost/effort.** 2–6 weeks. `$` (Socket/deps.dev checks in a curation pipeline) to `$$$` (commercial repository firewall).
- **Trade-offs.** Cool-off periods delay urgent security fixes; needs an override path, which is itself an approval queue. Replacing Nexus CE with a commercial repository is a migration. Curation reduces but does not remove malicious packages that pass reputation checks.

### 1.9 Code review, signing and provenance gates in CI

- **What.** CI runs on a clean checkout outside workspaces; commits from agent-assisted workspaces are labeled; merges require human review; artifacts are built in hermetic CI, signed with Sigstore (cosign, keyless via the IdP), and carry SLSA provenance. Enclave deploy admits only signed artifacts with provenance from the trusted builder (policy controller, Kyverno or Connaisseur).
- **Closes.** G-22 (agent-generated code reaching enclaves), the MVP's top-ranked threat.
- **Cost/effort.** 4–10 weeks across CI, SCM and enclave admission. `$`–`$$`.
- **Trade-offs.** Review fatigue: agents produce large diffs, and reviewers approve what they do not read. Pair with diff-size limits and required tests. Keyless signing needs the IdP and a transparency log inside the air gap (self-hosted Rekor/Fulcio).

### 1.10 PAM / just-in-time approver elevation

- **What.** Admin rights are not standing. Approvers request elevation through a PAM tool (CyberArk, Teleport, Entra PIM, AWS IAM Identity Center temporary elevation) for a time window, with a reason, and the IdP group claim expires after it.
- **Closes.** G-15 impact (a stolen or stale admin session is only useful during elevation), G-23 partly (elevation reason is a second record), insider misuse.
- **Cost/effort.** 2–4 weeks. `$$`.
- **Trade-offs.** Adds friction to every approval, which pushes toward bulk or rushed approvals. Works best combined with section 3 so most requests never need an elevated human.

### 1.11 Periodic access reviews

- **What.** Quarterly (or monthly for high-risk zones) recertification: who holds Coder `owner`/`user-admin`, which zones have which permanent rules, which workspaces sit in non-default zones, top grants by count and by `bytes_up`.
- **Closes.** Drift in zone rules (zone rules never expire, DR-4.5), stale admin rights, G-16 ambiguity (reviewers confirm identities).
- **Cost/effort.** 1 week to build the report (SQL over `rules`, `assignments`, `audit`); a few hours per cycle per reviewer. `$`.
- **Trade-offs.** Rubber-stamping. Show the diff since last review, not the full list.

### 1.12 Red-team exercises

- **What.** External or internal red team with the MVP threat model as scope: hostile agent in a workspace, compromised platform pod, insider approver, poisoned package. Include prompt-injection campaigns against real agents and social engineering of the approval queue.
- **Closes.** Unknown gaps; validates G-7, G-8, G-12, G-23 assumptions and the monitoring rules in 05 section 3 (blocked **and** seen).
- **Cost/effort.** 2–4 weeks per exercise. `$$`–`$$$` if external.
- **Trade-offs.** Point-in-time. Feed findings into automated tests (C-SUP-7) so they stay covered; Phase 8 builds the scripted part in-product.

### 1.13 Summary

| Control | Gaps narrowed | Effort (wks) | Licence tier |
|---|---|---|---|
| IdP + MFA (OIDC) | G-14, G-15, G-16, G-25 | 1–2 | `$`–`$$` |
| SIEM + WORM shipping | G-18, G-19 | 3–6 | `$$`–`$$$` |
| DLP / CASB | G-8, G-7 | 4–8 | `$$$` |
| Edge TLS inspection | G-7, G-8 | 4–8 | `$$`–`$$$` |
| Node EDR | G-12, G-18, G-5 | 1–3 | `$$` |
| TPM / confidential VMs | G-12 | 6–12 | `$$` |
| VPC FQDN firewall | G-1, G-2, G-3 | 2–4 | `$$` |
| Package firewall | G-21 | 2–6 | `$`–`$$$` |
| CI signing / SLSA | G-22 | 4–10 | `$`–`$$` |
| PAM / JIT elevation | G-15, G-23 | 2–4 | `$$` |
| Access reviews | zone drift, G-16 | 1 | `$` |
| Red team | unknown gaps | 2–4 each | `$$`–`$$$` |

## 2. Future enhancements (in product)

### 2.1 Planned phases (MVP spec)

| Phase | Enhancement | Gaps closed | Notes |
|---|---|---|---|
| 5 | data-broker: only path to enclave data, row limits, redaction, audit, volume alert | G-11 | Enclaves off-cluster behind host nftables (DR-3.3) |
| 5 | cred-broker: 10-minute Gitea tokens scoped to template repos | G-11 | No git secrets in image or env |
| 5 | Mock enclaves on a separate host-guarded network | G-11 | Makes workspace to enclave two-layer |
| 5 | Ollama inference behind Envoy with per-workspace tokens and daily ceilings | G-9 partly | Independent runaway backstop |
| 5 | In-guest `runsc` spike for `docker run` | G-12, G-13 | Unverified under CLH guest kernel |
| 6 | Falco in guest with a tamper-resistant relay | G-10, G-12 detection | Trimmed ruleset from MVP spec "Detection" |
| 6 | Honeytokens in images (fake AWS credentials, `.env`, enclave DSN, hostname) | G-10 | Near-zero false-positive signal |
| 6 | Loki + Grafana with alert rules from 05 section 3 | G-18 partly | Workspace ID as join key; still on-node without 1.2 |
| 6 | Envoy per-workspace rate limits: requests/min, bytes/hour, unique destinations/hour | G-9, G-8 partly | Ratelimit service; Redis only if global limits are needed |
| 6 | Circuit breaker: flips the workspace CNP to deny-all and notifies the terminal | G-9 | Needs a clear human reset path and audit |
| 7 | Desktop template (Webtop, selkies websocket through the Coder tunnel) | — | New surface: clipboard and screen exfil stay out of scope |
| 8 | Scripted red team and injection evals; blocked and alerted as separate assertions | validates all | Includes honeytoken touch rate and CI-bridge commits |

### 2.2 Items surfaced in Phases 3–4

| Enhancement | Gaps closed | Effort (wks) | Notes |
|---|---|---|---|
| xDS/ALS mTLS with pinned server identity | G-5 | 1–2 | Required before multi-node |
| Workspace identity via SPIFFE or Cilium security identity instead of source IP | G-6 | 3–5 | Envoy principals on peer certificate, or Cilium identity metadata |
| Per-workspace rate limits on Envoy (local rate limit keyed by source IP) | G-9 | 1 | Earliest useful slice of Phase 6 |
| Persistent host lock (systemd unit or `nftables.service` include) | G-1 | < 1 | Lab only; production uses 1.7 |
| Nexus Terraform provider mirror; drop coderd public 443 | G-2 | 1 | Also re-check coderd CNP after removal |
| Node image mirror (k3s `registries.yaml` to Nexus) and vendored charts | G-3 | 1–2 | Removes `egress-unlock` from routine ops |
| CloudNativePG for admin and Coder Postgres | G-4 | 2–3 | Keep separate clusters (DR-4.7); see 07 |
| Admin leader election (one writer of xDS/CNPs, others serve UI) | G-4 | 1–2 | Snapshot cache must be consistent across replicas |
| User-ID-based audit and `self_approved` | G-16 | < 1 | Review #8 |
| Server-side session store with revocation on logout and role change | G-15 | 1 | Review #9; or shorten TTL and re-check `users/me` |
| UI error banner and exponential backoff for reconcile errors | S-8 | < 1 | Spec promised the banner; not built |
| Deny route for port 80 on 443-only vhosts | G-24 | < 1 | Review #12 point 3 |
| `TEST_HOOKS=0` default; short-lived test token | G-17 | < 1 | Review #11 remainder |
| TLS for the admin UI; `Secure` cookies | G-25 | < 1 | Behind an ingress with an internal CA |
| `%DURATION%` in the Envoy access log format | S-12 | < 1 | Makes tunnel-length signals queryable |
| Bulk grant templates without regex: named host sets applied to a workspace or zone | G-23 partly | 1–2 | Replaces many single-host approvals; see 3.1 |
| Guest time sync and offset recorded at workspace start | G-19 | < 1 | Forensic timeline accuracy |

## 3. Reducing admin burden

The per-request human approval (C-ADM-2) is the control most likely to erode:
if approvals are slow, users push for broad zone rules; if they are frequent,
approvers stop reading. Each mechanism below keeps an auditable decision
while removing routine reviews. None of them adds a workspace route to admin.

Cost column: order-of-magnitude engineer-weeks, dated 2026-09.

| # | Mechanism | Burden reduced | Security trade-off | Implementation cost |
|---|---|---|---|---|
| 3.1 | **Pre-approved grant catalogs per role or team.** Named, reviewed host sets (e.g. "python-dev: pypi mirror names, docs.python.org") that an owner can attach to their workspace without a queue entry, with the catalog's expiry. | Removes repeat approvals for the same hosts across many workspaces. | A catalog entry is a standing grant for anyone in the role; a bad entry spreads widely. Catalog changes need the same review as zone rules and appear in S-7/S-14. | 2–3 |
| 3.2 | **Auto-approve low-risk categories with policy-as-code** (OPA/Rego or CEL). Policy input: host, port, workspace zone, requester groups, request history. Output: approve with TTL, deny, or route to human. Every auto-decision audited with `actor=policy:<version>`. | Most requests never reach a person. | Policy bugs approve at machine speed. Mitigate with a deny-by-default policy, a max TTL for auto-approvals (1 d), no wildcards, unit tests on the policy, and S-1/S-13 on auto-approved hosts. | 3–4 |
| 3.3 | **Time-boxed self-service for known package registries.** Owners grant themselves 1 h access to a fixed list of registry hosts not yet mirrored in Nexus. | Unblocks installs outside business hours. | Registries are publish-capable exfil channels (G-8) and supply-chain inputs (G-21). Keep the list short, prefer adding the upstream to Nexus, and flag every use (S-5). | 1 |
| 3.4 | **Request deduplication and bundling across workspaces.** Group pending requests by host; approve once for the listed workspaces, or promote to a zone rule. | One decision instead of N. | Bundling hides per-workspace justification; show all justifications in the bundle. Promoting to a zone makes the grant permanent (DR-4.5), so require an explicit choice. | 1–2 |
| 3.5 | **Delegated approvers per zone or team.** A zone has approver groups (from IdP claims) who may decide requests for workspaces in that zone only. | Spreads load; approvers know the work. | More people hold approval rights; weaker separation of duties. Keep `self_approved` blocking (not just flagged) for delegated approvers, and restrict wildcards to central admins. | 2 |
| 3.6 | **ChatOps approval (Slack or Teams) with signed callbacks.** Request posts to a channel; approve/deny buttons call back to admin with a verified platform signature and the approver's mapped IdP identity. | Faster decisions without opening the UI. | Chat accounts become approval credentials; a compromised chat account approves grants. Require the approver's chat identity to map to an IdP user with admin rights, verify signatures and timestamps, and reject replayed callbacks. Admin needs an egress path to the chat platform (or an internal relay). | 2–3 |
| 3.7 | **Ticketing integration (Jira or ServiceNow).** Requests create tickets; justification and decisions live in the ticket; the grant references the ticket ID. | Uses an existing review trail and reporting; no duplicate records for auditors. | Ticket text is agent-influenced (G-23). Ticket systems are broader-access than admin; do not put hostnames of sensitive enclaves in them. | 2–3 |
| 3.8 | **Expiry reminders and one-click renew.** Notify the owner N hours before expiry; renew shows the grant's usage (`bytes_up`, request count) and requires a fresh justification. | Fewer re-requests from scratch; fewer surprise outages. | Renewal becomes habitual and grants become permanent in practice. Limit renewals (e.g. two) before a new review, and show usage so unused grants lapse. | 1 |
| 3.9 | **Zone-as-code in Git (GitOps) with PR review.** Zone rules and catalogs live in a repo; admin reconciles from the default branch; the UI shows zones read-only. Workspace grants stay in the UI. | Baseline changes get normal code review, history and rollback. | Git becomes a policy source; protect the branch, require reviewers, and sign commits (1.9). Two sources of truth (Git for zones, DB for grants) must be clearly separated. | 2–3 |
| 3.10 | **Analytics: top denied hosts to promote into zone baselines.** Weekly report from `denials` and `requests`: most-denied and most-approved hosts per zone, with approval rate. | Moves recurring hosts into reviewed baselines once, instead of per-request churn. | Popularity is not safety; an agent flood (S-1) can inflate counts. Count distinct workspaces and approved requests, not raw denials. | 1 |
| 3.11 | **Anomaly-based review queues.** Humans review only requests that differ from history: new host for the zone, wildcard, off-hours, high `bytes_up` on similar hosts, requester with recent S-1/S-4 signals. Others follow 3.1/3.2. | Human attention goes to the few risky requests. | Model or rule blind spots let unusual-but-quiet requests through. Keep a random sample (e.g. 5%) of auto-approved decisions in human review. | 3–5 |
| 3.12 | **Periodic recertification reports.** Scheduled report of standing zone rules, delegated approvers, catalog entries and long-lived renewals, with one-click revoke. | Turns 1.11 access reviews into a single page. | Same rubber-stamp risk as 1.11; show changes since last cycle. | 1 |

### 3.13 Suggested order

1. 3.8 and 3.10 first: cheap, reduce churn, and do not weaken any check.
2. 3.1 and 3.4 next, with catalog changes reviewed like zone rules.
3. 3.9 once there are more than a handful of zones.
4. 3.2, 3.5 and 3.11 only after Phase 6 signals (S-1, S-4, S-13) are alerting, so automated approvals have detection behind them.
5. 3.6 and 3.7 when the organisation already runs those tools inside the air gap.
