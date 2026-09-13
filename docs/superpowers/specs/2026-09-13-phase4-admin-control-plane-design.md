# Phase 4 — Admin Control Plane — Design Spec

Date: 2026-09-13
Status: approved (design); spikes pending
Parent: [MVP design](2026-09-13-sandcastle-mvp-design.md) · Builds on: [Phase 3](2026-09-13-phase3-containment-core-design.md)

## Goal

Egress policy stops being static YAML. An admin manages zones and grants in a
web UI; a developer turns a 403 into an access request; an approval is
enforced for exactly that workspace within 5 seconds; every change is
audited. The Phase 3 reachability invariant does not change: a workspace
still reaches exactly four destinations, and sandcastle-admin is not one.

## Scope

In:
- `sandcastle-admin`: one Go binary, htmx UI, own Postgres.
- Login through Coder's OAuth2 provider; Coder role decides admin rights.
- Zones: create, clone (with rules), edit, delete, set default, move workspaces.
- Rules of two kinds: proxy host (Envoy) and DNS name (Cilium).
- Workspace grants with required expiry.
- Request/approve queue fed by Envoy denials.
- Envoy configured entirely by xDS (go-control-plane) with per-workspace RBAC.
- CiliumNetworkPolicy reconciler for DNS rules (replaces `workspace-dns-allow.yaml`).
- Append-only audit log.

Out (later phases):
- Enclave/broker grants (Phase 5).
- Rate limits, circuit breaker, alerting (Phase 6).
- Owner-level grants, direct L3/CIDR grants, user-chosen zones.
- xDS mTLS and HA admin (multi-node).

## Decisions from brainstorming

| # | Question | Decision |
|---|---|---|
| 1 | Admin auth | Coder as IdP (OAuth2 provider); Coder `owner`/`user-admin` = sandcastle admin |
| 2 | Request path | Human-confirmed from denial log; workspace gets no route to admin |
| 3 | Grant scope | Workspace grants + zone rules; zones fully admin-managed (create, clone, attach) |
| 4 | Zone attach | New workspaces join the default zone; only admins move them |
| 5 | Rule types | Proxy hosts + DNS names; no L3 grants |
| 6 | Expiry | Required on workspace grants; approver picks 1h / 1d / 7d / 30d (default 7d) |
| 7 | Admin down | Envoy keeps last snapshot; a fresh Envoy with no admin fails closed |
| 8 | Database | Own Postgres StatefulSet in `sandcastle-admin` |
| 9 | Enforcement | xDS per-host virtual hosts with source-IP RBAC + per-host SNI internal listener |

## Architecture

```
 browser ──NodePort 30081──► sandcastle-admin (ns sandcastle-admin)
                              ├─ auth    : OAuth2 login via coderd (/oauth2/*)
                              ├─ store   : Postgres (own StatefulSet)
                              ├─ watch   : pod informer (ns sandcastle-workspaces) → {workspace_id, pod IP}
                              ├─ als     : Envoy access-log gRPC sink → denials
                              ├─ xds     : go-control-plane ADS :18000 ──────────► Envoy
                              ├─ cilium  : CNP reconciler ─────────────────────────► kube API
                              └─ web     : htmx handlers + templates
 workspace ──(four destinations, unchanged)──► Envoy :3128
```

State lives only in Postgres. Every change (UI action, pod event, expiry)
triggers a full rebuild: read rows + current pod IPs → build xDS snapshot and
desired CNPs → push/apply. No diffs, no in-memory policy state that can drift;
a restarted admin converges on its first rebuild.

### Components

| Package | Responsibility | Depends on |
|---|---|---|
| `cmd/sandcastle-admin` | wiring, flags, rebuild loop, expiry ticker (30 s) | all |
| `internal/auth` | OAuth2 code flow against coderd, session cookie, CSRF token, role check via `/api/v2/users/me` | coderd |
| `internal/store` | SQL migrations, queries | Postgres |
| `internal/policy` | pure: rows + pod IPs → effective allowlist per workspace | none |
| `internal/xds` | pure builder: effective allowlist → Envoy snapshot; ADS server | go-control-plane |
| `internal/als` | access-log gRPC service → denial upserts | store, watch |
| `internal/watch` | pod informer: Running pods with `com.coder.workspace.id` + pod IP | client-go |
| `internal/cilium` | pure render of desired CNPs + apply/prune owned objects | kube API |
| `internal/web` | htmx pages: queue, denials, zones, workspaces, audit, request form | store, auth |

Each file stays under 500 lines. `policy`, `xds` builder, and `cilium` render
are pure functions and carry the table tests.

### Data model

```sql
zones       (id uuid pk, name text unique, is_default bool, created_at)
            -- exactly one row with is_default = true (partial unique index)
rules       (id uuid pk, zone_id uuid null fk, workspace_id uuid null,
             kind text check (kind in ('host','dns')), value text, port int null,
             expires_at timestamptz null, created_by text, created_at)
            -- check: exactly one of zone_id / workspace_id set
            -- check: workspace_id set ⇒ expires_at not null
assignments (workspace_id uuid pk, zone_id uuid fk, assigned_by text, assigned_at)
            -- no row ⇒ default zone
requests    (id uuid pk, workspace_id uuid, host text, port int, justification text,
             requester text, status text check (status in ('pending','approved','denied')),
             decided_by text null, ttl interval null, created_at, decided_at null)
denials     (workspace_id uuid, host text, port int, count int, first_seen, last_seen,
             primary key (workspace_id, host, port))
audit       (id bigserial pk, at timestamptz, actor text, action text, detail jsonb)
```

The app's Postgres role has `INSERT, SELECT` on `audit` and no `UPDATE` or
`DELETE`; migrations run as a separate owner role.

Rule values:
- `host`: an exact FQDN or `*.suffix`, lowercase, validated with a strict
  regex. No IP literals, no bare `*`. Port is 443 or 80.
- `dns`: the same form. Cilium `matchName` for an exact name,
  `matchPattern: "*.suffix"` for a wildcard.

### Flows

**Denial → request**
1. Envoy denies a request and sends an access-log entry over gRPC.
2. Admin maps the source IP to a workspace via the pod watcher, then upserts
   `denials`. Rows are capped at 200 per workspace (oldest dropped) and
   updated at most once per second per key.
3. The 403 body carries `http://<node>:30081/r?ws=<id>&host=<host>&port=<p>`.
   The owner opens it in their own browser, outside the workspace, and logs in
   via Coder. The form is prefilled; they add a justification and submit.
4. Only the workspace owner, or an admin, may file for that workspace.

**Approve / deny**
1. The admin picks a TTL, which inserts a workspace `host` rule with
   `expires_at`. Denying only sets the request status.
2. Both are audited and trigger a rebuild. Target: enforced in under 5 s.
3. When the approver is also the requester, the audit entry records
   `self_approved: true`.

**Zones**
- Create, rename, clone (a deep copy of its rules under a new name), add or
  remove rules, set default, delete (refused while workspaces are assigned).
- Move a workspace. Each action is audited and triggers a rebuild.

**Expiry**
- A 30 s ticker deletes expired grants, writes an `expire` audit entry, and
  triggers a rebuild.

## Enforcement

### Envoy (xDS)

The bootstrap ConfigMap holds only the node ID, the ADS cluster
`sandcastle-admin.sandcastle-admin.svc:18000`, the ALS cluster (same target),
and the admin interface on 127.0.0.1. Admin serves everything else:

- **Effective allowlist:** for each workspace, its zone's host rules plus its
  unexpired grants. Inverted per host: `H → {pod IPs}`, using Running pods
  with a pod IP only.
- **Listener `proxy` :3128:** HTTP connection manager with filters
  `dynamic_forward_proxy`, `rbac` (default deny), `router`. Access logs go to
  stdout and to ALS.
- **Route config:** for each host H with a non-empty IP set:
  - vhost `H:443` (or `*.suffix:443`) carries `RBACPerRoute` ALLOW with
    principals `direct_remote_ip` = each IP/32. CONNECT routes to cluster
    `sni_<h>` → internal listener `sni_<h>`.
  - vhost `H`, `H:80` carries the same RBAC → `dfp_http`.
  - Catch-all vhost returns 403 + `x-sandcastle-denied`, with the request
    link in the body.
- **Internal listener `sni_<h>`:** `tls_inspector`, then a filter chain with
  `server_names: [H]` → `sni_dynamic_forward_proxy` → `dfp_sni`. The SNI is
  bound to the stage-1 host by construction, so workspace A cannot use its
  allowed CONNECT to carry an SNI that only workspace B may use.
- **Listener names:** `<h>` = short hash of (H, sorted IP set). Any change to
  who may reach H renames the listener; Envoy drains the old one, which closes
  already-open tunnels (Spike S3). Drain time is set short, 5 s.
- **Snapshot:** built with a monotonically increasing version. The ADS server
  uses the go-control-plane `SnapshotCache` keyed by Envoy node ID.

### Cilium (DNS rules)

- **Per zone:** `CiliumNetworkPolicy ws-dns-zone-<zone-name>` in ns `sandcastle-workspaces`.
  - Selector: `com.coder.workspace.id In [assigned ids]`.
  - Default zone: `Exists` AND `NotIn [all assigned ids]` (`Exists` alone when nothing is assigned). The `Exists` term keeps unlabeled pods out: `NotIn` by itself also matches pods without the label.
  - Egress to kube-dns :53 with `rules.dns` built from the zone's `dns` rules.
- **Per workspace with DNS grants:** `ws-dns-grant-<workspace-id>`, selecting
  that one ID.
- A zone with no DNS rules, or an `In` list that would be empty, emits no CNP.
  An empty DNS rule list would allow all names.
- **Ownership:** objects carry the label
  `app.kubernetes.io/managed-by=sandcastle-admin`. The reconciler
  creates/updates desired objects and deletes owned objects that are no
  longer desired. It never touches unlabeled CNPs.
- **Replaces** `platform/policy/workspace-dns-allow.yaml`, which is deleted
  and seeded into the default zone as data. `workspaces.yaml`
  (`**.cluster.local`) stays static.

Resolving a name still does not grant reaching it. L3 stays limited to the
four destinations.

### Reachability changes

| From → to | Port | New/changed |
|---|---|---|
| browser (lab net) → admin | NodePort 30081 | new |
| Envoy → admin | 18000 (ADS + ALS) | new; the only ingress to 18000 |
| admin → coderd | 8080 | new (OAuth2 token exchange, users/me) |
| admin → kube API | 6443 | new (pods list/watch and CNP CRUD in `sandcastle-workspaces`) |
| admin → admin-db | 5432 | new |
| Envoy static allowlist | — | removed |
| workspace → anything | — | **unchanged** |

The workspace CNP already denies the `sandcastle-admin` namespace, and a Phase
4 test asserts it.

## Failure modes

| Failure | Behavior |
|---|---|
| Admin down | Envoy keeps its last snapshot; existing grants work; approvals and denial recording wait |
| Envoy (re)starts while admin down | No listeners, so all proxied egress fails (fail closed); readiness stays false |
| Postgres down | UI returns errors; no rebuild; last snapshot stays |
| Pod deleted / IP reused | Watcher drops the IP on delete or non-Running; exposure window = rebuild latency (~1 s). Cilium blocks spoofing another endpoint's source IP |
| Revoke with an open tunnel | New CONNECTs denied on RDS push; open tunnels close when the renamed internal listener drains (≤ 5 s) |
| CNP apply fails | Rebuild retries with backoff; the error shows on the UI banner and in the audit log (`reconcile_error`) |
| Coder OAuth2 unavailable | No logins; enforcement unaffected |

## Threat analysis

| Vector | Mitigation |
|---|---|
| Agent reaches admin to self-approve | No route (workspace CNP); test asserts drop |
| Agent files requests | Filing needs the owner's Coder session in a browser outside the workspace |
| Agent floods denials to bury real ones | Dedup primary key, per-workspace cap, update throttling |
| Crafted host in the request link (injection, wildcard grab) | Strict FQDN / `*.suffix` regex, lowercase, no IPs, no bare `*`; htmx templates auto-escape |
| CSRF on approve | SameSite=Lax session cookie + per-session CSRF token on every POST |
| Admin compromise = all egress | Highest-value target: no workspace route; NodePort served only on the lab net; minimal k8s RBAC (no secrets, only `sandcastle-workspaces` pods + CNPs) |
| Audit tampering via the app | Database grants: app role cannot UPDATE/DELETE `audit` |
| Admin approving own request | Allowed, flagged `self_approved` |
| Stale IP → wrong workspace gets a grant | Rebuild on every pod event; only Running pods with a pod IP |
| Spoofed xDS server | ponytail: plaintext xDS in-cluster, with admin :18000 ingress limited to the Envoy pod by CNP. Add mTLS when multi-node |

## Spikes (gate before the build)

| # | Question | Pass |
|---|---|---|
| S1 | Coder OAuth2 provider works on OSS 2.36.5 (`--experiments oauth2`) | App registered, code flow returns a token, `/api/v2/users/me` works with it, roles visible |
| S2 | Per-vhost RBAC on CONNECT + per-host SNI internal listener (hand-written static config) | Allowed IP gets through; other IP gets 403; SNI mismatch refused |
| S3 | Renaming an internal listener closes an established tunnel | Open `openssl s_client` session dies within the drain time |
| S4 | CNP `In` / `NotIn` on `com.coder.workspace.id` works on Kata workspace pods | Name resolves only for the selected workspace |
| S5 | Envoy ALS reaches a gRPC sink | Stub receives an entry with source IP + authority + response code |

Results go to `2026-09-13-phase4-spike-results.md`. A failed spike returns to
design before any build work.

## Testing

**Go unit tests (`go test ./...`)**
- policy: effective allowlist, wildcard handling, expiry filtering.
- xds builder: snapshot contents, listener name hash changes when the IP set changes.
- cilium: CNP render, including default zone selectors and no empty `In` lists.
- validation: host regex.
- auth: role mapping.

**`infra/tests/04-admin.sh` (VM, host lock on)**
1. Admin healthy; Envoy ADS connected; seeded default zone contains `example.com`.
2. Two workspaces, A (default zone) and B (zone `restricted`, cloned from default with `example.com` removed).
3. B gets 403 for example.com, A gets 200 (zone move applied).
4. Request + approve `example.org` for A with the API test hook: A succeeds within 5 s, B still 403.
5. Revoke: A gets 403 within 5 s; an open tunnel closes.
6. Grant with a 1-minute TTL (test hook): expires, then 403.
7. DNS grant: the name resolves in A only.
8. Workspace → admin :30081 / :18000 blocked.
9. Admin scaled to 0: A's existing grant still works. Envoy restarted while admin is down: A gets 403.
10. Audit rows exist for each step; `UPDATE audit` as the app role is refused.
11. Denial from A appears in the `denials` table, attributed to A's workspace ID.

**Regression:** Phase 1 9/9, Phase 2 18/18, Phase 3 35/35. The Phase 3 suite
reads its allowlist from the seeded default zone.

**Test hook:** the API accepts bearer auth from a Kubernetes secret
`sandcastle-admin/test-token`, which exists only when the chart value
`testHooks=true`. The lab enables it; it is documented as off for production.

## Deliverables

- `admin/`: Go module, Dockerfile (distroless, non-root), migrations, templates.
- `platform/admin/`: namespace, Postgres, Deployment, Service (ClusterIP 18000
  + NodePort 30081), RBAC, CNPs for admin and admin-db.
- `platform/egress/envoy.yaml`: bootstrap-only ConfigMap.
- `platform/policy/platform.yaml`: Envoy → admin :18000.
- `platform/coder/values.yaml`: `CODER_EXPERIMENTS=oauth2`.
- `infra/bootstrap/05-admin.sh`: build/import the image, register the OAuth2
  app, apply, seed.
- Makefile: `admin`, `verify-admin`.
- `infra/tests/04-admin.sh`.
- README, MVP spec addenda, open-brain entries.
- Release `v0.4.0`.

## Decision records (5 W's)

### DR-4.1 Coder is the identity provider for admin
- **Who:** owner (sgtslaughta), proposed by Claude.
- **When:** 2026-09-13, Phase 4 design.
- **Where:** `internal/auth`, coderd `/oauth2/*`.
- **What:** admin logs users in through Coder's OAuth2 provider; Coder `owner`/`user-admin` maps to sandcastle admin; everyone else can only request.
- **Why:** one identity across workspace, request, and approval; the requester is directly the workspace owner; no extra IdP to run in an air-gapped lab.
- **Alternatives:** Dex/Keycloak (production-shaped, extra component); local accounts (identities not tied to Coder); admin-only with no requester login.

### DR-4.2 Requests are human-confirmed from the denial log
- **Who:** owner, proposed by Claude.
- **When:** 2026-09-13.
- **Where:** `internal/als`, `internal/web`, Envoy 403 body.
- **What:** Envoy denials become `denials` rows; the owner files a request in their own browser after logging in through Coder.
- **Why:** keeps admin off the workspace reachability list; a runaway agent can neither file nor spam requests; a human stands behind every justification.
- **Alternatives:** workspace POST endpoint as a fifth destination (agent can self-file); no request flow.

### DR-4.3 Grants attach to workspaces and zones; zones are admin-managed
- **Who:** owner (added: create, clone, and attach arbitrary zones).
- **When:** 2026-09-13.
- **Where:** `zones`, `rules`, `assignments` tables; UI zones page.
- **What:** effective allowlist = zone rules plus unexpired workspace grants; zones can be created, cloned with rules, edited, and set as default; new workspaces join the default zone and only admins move them.
- **Why:** stable identities (the workspace ID survives restarts; pod IPs do not); zones express shared baselines; admin-only placement prevents self-escalation through zone choice.
- **Alternatives:** workspace-only grants; owner-level grants (wider blast radius); template→zone or user-picked zones.

### DR-4.4 Rule kinds limited to proxy hosts and DNS names
- **Who:** owner, proposed by Claude.
- **When:** 2026-09-13.
- **Where:** `rules.kind`.
- **What:** `host` rules enforced by Envoy; `dns` rules enforced by per-zone CNPs; no direct L3/CIDR grants.
- **Why:** the four-destination invariant and Envoy logging stay intact; everything external is attributable.
- **Alternatives:** CIDR:port grants (widen the invariant, bypass logs); proxy-only (DNS stays static YAML).

### DR-4.5 Workspace grants require expiry
- **Who:** owner, proposed by Claude.
- **When:** 2026-09-13.
- **Where:** `rules.expires_at` check constraint; expiry ticker.
- **What:** the approver picks 1h/1d/7d/30d (default 7d); expired grants auto-revoke and are audited; zone rules are permanent.
- **Why:** stops forgotten grants accumulating; re-requesting is cheap.
- **Alternatives:** optional expiry; permanent until revoked.

### DR-4.6 Fail closed; keep the last snapshot
- **Who:** owner, proposed by Claude.
- **When:** 2026-09-13.
- **Where:** Envoy bootstrap (no static listeners).
- **What:** a running Envoy keeps its last xDS snapshot during an admin outage; a freshly started Envoy with no admin serves nothing.
- **Why:** nothing opens up on failure; running work is not disrupted by an admin restart; the baseline lives in one place.
- **Alternatives:** a static baseline in bootstrap (two sources of truth); ext_authz (instant total deny on outage).

### DR-4.7 Separate Postgres for admin
- **Who:** owner, proposed by Claude.
- **When:** 2026-09-13.
- **Where:** `platform/admin/postgres.yaml`.
- **What:** own StatefulSet and secret in `sandcastle-admin`.
- **Why:** coderd credential compromise does not expose policy/audit data, and vice versa; independent upgrades.
- **Alternatives:** an extra database on coder-db.

### DR-4.8 Enforcement via xDS per-host vhosts with source-IP RBAC
- **Who:** owner, proposed by Claude.
- **When:** 2026-09-13.
- **Where:** `internal/xds`.
- **What:** per-host virtual hosts with `RBACPerRoute` `direct_remote_ip` principals; per-host SNI internal listeners named by a hash of the host and its IP set.
- **Why:** per-workspace policy in one shared Envoy; the SNI is bound to the stage-1 host structurally; revocation closes open tunnels via listener replacement; the last snapshot survives an admin outage.
- **Alternatives:** ext_authz (outage = total deny, latency per request, stage-2 binding unsolved); per-zone ports (two mechanisms for zone vs grant).

### DR-4.9 Denials delivered by Envoy ALS, not log scraping
- **Who:** Claude, within the approved design.
- **When:** 2026-09-13.
- **Where:** `internal/als`; Envoy access log config.
- **What:** Envoy streams access logs over gRPC to admin on the xDS port; stdout logs stay for Hubble/Phase 6.
- **Why:** structured entries, no parsing, no `pods/log` RBAC into the egress namespace.
- **Alternatives:** client-go follow of Envoy pod logs.
