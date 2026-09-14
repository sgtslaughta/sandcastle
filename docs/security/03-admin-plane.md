# 03 — Admin control plane

Scope: `sandcastle-admin` (Go binary in `admin/`), its Postgres, its OAuth2 login through Coder, the xDS/ALS
channel to the egress Envoy, and the CiliumNetworkPolicy reconciler for DNS grants. Back to [README.md](../../README.md).
Design source: `docs/superpowers/specs/2026-09-13-phase4-admin-control-plane-design.md` (DR-4.1..4.11) and
`2026-09-13-phase4-spike-results.md`. Verified by `infra/tests/04-admin.sh`, 39/39, lab run 2026-09-13:
approve 605 ms, revoke 298 ms, open tunnel closed 7.2 s after revoke.

## C-ADM-1 Coder as identity provider (OAuth2 + PKCE, role → admin)

**Threat mitigated.** Without a real IdP, admin login needs its own account store or trusts an
unauthenticated caller. An insider or an attacker who reaches the NodePort could self-register as admin;
two identity systems means no single place to disable a departing user.

**Control.** `admin/internal/auth/auth.go` runs an OAuth2 authorization-code flow with PKCE (S256) against
coderd's `/oauth2/*` endpoints. On callback it exchanges the code, calls `coderd /api/v2/users/me`, and maps
Coder role `owner`/`user-admin` to `User.Admin = true`; everyone else can only file requests. Verified in
spike S1: app registration, PKCE flow, `users/me` all worked on Coder OSS 2.36.5 with `--experiments oauth2`.

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Dex / Keycloak | Standard OIDC, any downstream SSO | Extra component to run/patch air-gapped; second identity source to reconcile | order-of-magnitude days, 2026-09 | New attack surface (own admin UI, token store) |
| Corporate SSO (SAML/OIDC via Dex) | Matches enterprise IT policy | Needs a reachable IdP; not available air-gapped without a local relay | order-of-magnitude days, 2026-09 | Outage blocks admin login |
| Local accounts | No external dependency | Second password store; identity not tied to workspace owner | order-of-magnitude 1-2 days, 2026-09 | Credential stuffing, new reset flow |
| Admin-only login, no requester login | Simplest surface | Breaks the human-confirmed request flow (DR-4.2) | none (regression) | No audit trail linking requester to justification |

**Why this control.** One identity spans ownership, request filing, and approval (DR-4.1): the requester is
necessarily the Coder-authenticated workspace owner. No second IdP runs in the air-gapped lab. Ties to
DR-4.2 and DR-4.3, which assume a stable, Coder-backed actor identity.

**Residual risk.**
- Coder OAuth2 provider is an "experiment" flag on OSS 2.36.5; a later release could change it. See `docs/security/05-gaps-and-monitoring.md`.
- coderd compromise compromises admin login (shared trust root); DR-4.7's separate Postgres limits this to identity, not data.

## C-ADM-2 Human-confirmed access requests; workspaces have no route to admin

**Threat mitigated.** A runaway or hostile agent with root inside a workspace pod could, if it could reach
admin, file and potentially approve its own egress requests, defeating the approval model.

**Control.** Envoy's 403 carries a link (`http://<node>:30081/r?src=...&host=...`) a human opens in their
own browser outside the workspace. `admin/internal/web/handlers.go` `requestForm`/`fileRequest` require a
signed-in Coder session and `own(u, ws)` (admin or workspace owner). `requestForm` resolves the workspace
from `src=` (the pod IP Envoy saw) and only falls back to a caller-supplied `ws=` when `src=` is absent —
previously `ws=` took priority whenever present, so an agent-crafted authority in the 403 body could smuggle
a different workspace ID into the link (bounded by the `own()` check, but still surfaced the wrong workspace
in the form); fix wave #5, commit `057d88f`. The workspace CiliumNetworkPolicy
denies the `sandcastle-admin` namespace entirely; `infra/tests/04-admin.sh` asserts workspace → admin
:30081 and :18000 are both blocked.

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Workspace POST endpoint as a fifth destination | No human round-trip | Agent can self-file/spam/craft justification; breaks four-destination invariant | order-of-magnitude 1 day, 2026-09 | Direct path for a compromised agent to reach admin |
| No request flow (admin-initiated only) | Smallest surface | No self-service; admin must notice denials first | none | Slower response, more admin burden |

**Why this control.** Keeps admin off the four-destination reachability list (DR-4.2): a runaway agent can
neither file nor spam requests, and a human justification stands behind every approval. Matches threat-table
row "Agent reaches admin to self-approve."

**Residual risk.**
- The link's `src=` IP resolution depends on the pod watcher; a restarted pod invalidates old links (handled: 404, points to "My workspaces"). See `docs/security/05-gaps-and-monitoring.md`.

## C-ADM-3 Admin-managed zones, default zone, admin-only workspace moves

**Threat mitigated.** If owners could choose their own zone, an owner (or an agent with the owner's
session) could self-escalate egress by picking a permissive zone.

**Control.** `admin/internal/store/zones.go` implements zone create, rename, clone (deep copy of rules),
set-default, delete (refused while workspaces are assigned), and workspace assignment — all admin-only
routes in `admin/internal/web/web.go`. New workspaces default to the zone with `is_default = true`
(`policy.ZoneOf` falls back to it when no `assignments` row exists).

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Workspace-only grants (no zones) | Simpler model | No shared baseline; grant sprawl | order-of-magnitude 1 day saved | Harder audit |
| Owner-level grants | Convenient for multi-workspace users | Grant follows the person; wider blast radius | order-of-magnitude 1 day | Session theft reaches every workspace at once |
| User-chosen zones | Self-service | Self-escalation via zone choice | none | Defeats zone-based control |

**Why this control.** DR-4.3: stable identities (workspace ID, not pod IP or person) carry policy; zones
express shared baselines; admin-only placement prevents self-escalation. Fits the single-admin lab, where
one person reviews every move via `handlers.go` `audit`.

**Residual risk.**
- No workspace-facing UI shows current zone; owners rely on 403 messages. See `docs/security/05-gaps-and-monitoring.md`.

## C-ADM-4 Rule kinds limited to proxy host + DNS name; strict name validation

**Threat mitigated.** A CIDR or IP-literal grant would bypass Envoy's per-host logging and RBAC (an L3
grant reaches a network, not an audited host); a bare `*` or malformed pattern could open all egress.

**Control.** `admin/internal/policy/policy.go` `nameRE` requires an exact lowercase FQDN or `*.suffix` with
an alphabetic last label — no IP literals, no bare `*`. `ValidRule` restricts `host` rules to ports 80/443
and `dns` rules to port 0. `policy.Input.Effective` drops any row failing `ValidRule` before it reaches
Envoy or Cilium, so a bad database row is neutralized at read time.

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| CIDR:port grants | Covers non-HTTP protocols | Bypasses Envoy logging (DR-4.4); one mistake opens a whole segment | order-of-magnitude 2-3 days | Loses per-request attribution |
| Proxy-only (no DNS kind) | One enforcement point | DNS stays static YAML; no per-workspace DNS restriction | order-of-magnitude 1 day saved | Coarser DNS allowlisting |

**Why this control.** Preserves the four-destination invariant and keeps everything external attributable
to a logged, RBAC'd host (DR-4.4). Regex covered by table tests in `policy_test.go`.

**Residual risk.**
- Wildcard grants (`*.suffix`) are coarse: one approval opens every subdomain under that suffix. See `docs/security/05-gaps-and-monitoring.md`.

## C-ADM-5 Required expiry on workspace grants (1h/1d/7d/30d)

**Threat mitigated.** Permanent ad-hoc grants accumulate silently; a workspace that once needed
`pypi.org` for a week keeps that access forever, widening the blast radius of a later compromise.

**Control.** `rules` CHECK: `workspace_id IS NOT NULL ⇒ expires_at IS NOT NULL` (`001_init.sql`).
`admin/internal/web/web.go` `ttlFor` only accepts `1h/24h/168h/720h` from the UI (`60s` gated to the bearer
test hook). A 30-second ticker in `main.go` calls `st.ExpireGrants`, deleting expired rows, writing an
`expire` audit row, and triggering a rebuild. Zone rules carry no such constraint — they are permanent.

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Optional expiry | Flexible for long-lived needs | Defaults to "forever"; nobody revisits old grants | none | Grant sprawl |
| Permanent until revoked | No re-request friction | No cleanup mechanism | none | Same |

**Why this control.** DR-4.5: stops forgotten grants accumulating; re-requesting is cheap — the whole
denial-to-approval flow is under a second server-side per `infra/tests/04-admin.sh` (605 ms approve).

**Residual risk.**
- 30 days is still long for a one-off need; nothing nudges an admin toward a shorter TTL. See `docs/security/05-gaps-and-monitoring.md`.

## C-ADM-6 Per-host RBAC on source IP + per-host SNI listener, pushed over xDS

**Threat mitigated.** A shared egress proxy with one policy for all workspaces would let any workspace
reach anything another is allowed to reach. Without SNI binding, an allowed CONNECT could smuggle a
different SNI to reach a disallowed host.

**Control.** `admin/internal/xds/build.go` builds, per host, a virtual host carrying `RBACPerRoute` ALLOW
with `direct_remote_ip` principals set to exactly the pod IPs currently allowed that host (`rbacPerRoute`),
whose CONNECT route points at cluster `sni_<hash>` → internal listener `sni_<hash>` with
`filter_chain_match.server_names: [host]` (`sniListener`). The SNI the second-stage listener forwards is
fixed at build time to the stage-1 host, so a workspace cannot carry an allowed CONNECT to a disallowed
SNI. Because Envoy routes a request to the single most specific matching domain, an exact-host key used to
shadow a same-port zone wildcard entirely: a workspace-level grant on `api.github.com:443` produced an
exact vhost carrying only that grant's IPs, and Envoy preferred it over the zone's `*.github.com:443`
vhost, 403ing every other workspace the zone should still admit to `api.github.com` (a fail-closed outage,
not a leak, but a functional bug). `policy.HostIPs` now merges each `*.suffix` key's IPs into every other
key on the same port whose host the suffix covers — exact hosts and longer wildcards alike — before
`xds/build.go` renders vhosts, so the exact key inherits the wildcard's access too (fix wave #3, commit
`46bb834`; verified by `policy.TestHostIPsWildcardMerge` and `xds.TestExactVhostKeepsWildcardIPs`). Verified
in spike S2: allowed IP got 200, other IP 403, SNI mismatch refused (`no_filter_chain_match`).

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| ext_authz | Simple per-request model | Outage = total deny or fail-open depending on config; stage-2 SNI binding unsolved | order-of-magnitude 3-5 days | Outage denies all egress, or misconfig fails open |
| Per-zone proxy ports | Simple routing | Doesn't express per-workspace grants without one port per workspace | order-of-magnitude 3-5 days | Port exhaustion, harder NAT story |
| Per-workspace filter chains (spike C, tested) | Revokes correctly | Needs `validate_clusters: false`; a single-host revoke drains **all** that workspace's tunnels | tested, not built (~1 day if adopted) | Larger blast radius on revoke |

**Why this control.** DR-4.8: one shared Envoy expresses per-workspace policy; SNI bound structurally to
the stage-1 host; last snapshot survives an admin outage (pairs with C-ADM-8). Chosen over per-workspace
filter chains for its smaller revoke blast radius (spike results).

**Residual risk.**
- xDS channel is plaintext in-cluster (see C-ADM-13); mTLS deferred to multi-node. See `docs/security/05-gaps-and-monitoring.md`.

## C-ADM-7 Revocation closes open tunnels (listener rename + 5s drain) + 1h tunnel cap

**Threat mitigated.** Without active tunnel closure, a revoked or expired grant would only stop *new*
connections; an already-open CONNECT tunnel (a long download, an exfiltration channel) would keep flowing.

**Control.** Listener names are a short hash of `(host, sorted IP set)` (`xds.hashName`). Any IP-set change
renames the listener; Envoy drains the *old* one with `--drain-time-s 5 --drain-strategy immediate`
(`platform/egress/envoy.yaml`), closing its open tunnels. Every CONNECT route also sets
`max_stream_duration` to `tunnelMax` (1 hour, `main.go`) as a backstop (DR-4.10). Verified in spike S3
(tunnel EOF at swap + 6.0 s, other hosts' tunnels unaffected) and in `infra/tests/04-admin.sh`: open tunnel
to `example.org` closed 7.2 s after revoke in the most recent run.

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| 8-hour tunnel cap | Fewer reconnects for long jobs | Weaker exposure bound if listener-swap ever misses | trivial config change | Larger worst-case exposure window |
| No cap, rely on listener-swap alone | Simplest | No defense in depth if the swap mechanism regresses | none | Single point of failure for revocation |

**Why this control.** DR-4.8 (mechanism) + DR-4.10 (cap as defense in depth: "if listener-swap revocation
ever misses a tunnel, exposure is bounded"). Package/image pulls go through Nexus, unaffected by the cap.

**Residual risk.**
- Drain (5 s) plus in-flight completion means revocation is not instantaneous; the test suite tracks RBAC-level 403 latency and tunnel-close latency separately. See `docs/security/05-gaps-and-monitoring.md`.

## C-ADM-8 Fail closed without admin; running Envoy keeps last snapshot; Envoy pushed before Cilium

**Threat mitigated.** If admin's absence caused Envoy to fail open, an attacker could crash or DoS the
admin pod to remove all egress restriction. If a revocation's Cilium change applied before its Envoy
change, DNS could resolve a name whose L3 access was already being tightened, or vice versa.

**Control.** Envoy's bootstrap ConfigMap (`platform/egress/envoy.yaml`) has no static listeners, only the
ADS/ALS cluster. A running Envoy keeps the last `SnapshotCache` entry (`xds/server.go`,
`cache.NewSnapshotCache`) if admin disappears; a fresh Envoy with no snapshot serves nothing on `:3128`
(fail closed). `main.go` `apply()` pushes xDS before applying Cilium, so a revocation's L3 tightening never
waits on the kube API. `cilium.Apply` no longer stops at the first error: it collects a `fmt.Errorf` per
failed create/update/delete with `errors.Join`, but always lists and prunes managed policies regardless of
earlier failures, so one colliding or malformed object can no longer leave a revoked DNS grant's policy
live because pruning never ran (fix wave #6, commit `58f2527`; verified by a `cilium` test with a colliding
unmanaged name alongside another desired object: the error is returned, the other object is still created,
and the stale managed policy is still pruned). `infra/tests/04-admin.sh` scales admin to 0 and confirms A's
grant still works, then deletes the Envoy pod while admin is down and confirms the fresh Envoy 403s
everything.

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Static baseline in Envoy bootstrap | Some config even cold-started | Two sources of truth (YAML + Postgres); ambiguous precedence | order-of-magnitude 1 day | Config drift |
| ext_authz with fail-open on outage | Egress keeps working | Contradicts fail-closed model | order-of-magnitude 3-5 days | Availability attack becomes a policy bypass |

**Why this control.** DR-4.6: nothing opens up on failure; running work survives an admin restart; the
baseline lives in one place. Matches failure-mode rows "Admin down" and "Envoy (re)starts while admin down."

**Residual risk.**
- A cold-started Envoy during an admin outage denies *all* egress, even for workspaces with valid grants — a deliberate availability trade-off. See `docs/security/05-gaps-and-monitoring.md`.

## C-ADM-9 Terminating/non-running pods lose grants immediately (IP reuse)

**Threat mitigated.** Kubernetes reuses pod IPs. If a terminated workspace's IP stayed "allowed" in
Envoy's RBAC, a new pod (a different workspace, possibly attacker-controlled) receiving that IP would
inherit the old workspace's egress grants.

**Control.** `admin/internal/watch/pods.go` `Running()` only includes pods that are `PodRunning`, have a
`PodIP`, and have no `DeletionTimestamp`. The informer's add/update/delete handlers all call `onChange()`,
triggering a full rebuild (`main.go` debounces 200 ms then calls `apply()`). Every rebuild recomputes the
allowlist from scratch (`policy.HostIPs`), so a departed pod's IP drops out of every `RBACPerRoute` list.

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Diff-based incremental updates | Smaller xDS pushes | More state to get wrong; a missed delete leaves a stale IP allowed | order-of-magnitude 2-3 days | Drift, the exact bug class full-rebuild avoids |
| Time-based IP expiry, independent of pod state | Simpler informer | Fixed timer can be worse than ~1s rebuild latency | order-of-magnitude 1 day | Wider exposure window |

**Why this control.** Full-rebuild-on-every-change is the Phase 4 architectural choice ("no diffs, no
in-memory state that can drift"). Failure-mode table: exposure window = rebuild latency (~1 s); Cilium
blocks spoofing another endpoint's source IP as a second layer.

**Residual risk.**
- The ~1 s rebuild latency is a real, bounded exposure window between pod deletion and RBAC update. See `docs/security/05-gaps-and-monitoring.md`.

## C-ADM-10 Separate Postgres + append-only audit enforced by DB grants

**Threat mitigated.** If the app's database role could rewrite audit rows, a compromised admin process (or
an admin with DB access) could erase evidence of unauthorized approvals or grants.

**Control.** `001_init.sql` grants `sandcastle_app` `SELECT, INSERT` only on `audit`, no `UPDATE`/`DELETE`;
other tables get full CRUD. Migrations run as a separate owner role: `sandcastle-admin migrate`
(`cmd/sandcastle-admin/main.go`) applies schema migrations with `DB_OWNER_DSN` and `DB_APP_PASSWORD`, then
exits, and only runs as the `migrate` initContainer in `platform/admin/admin.yaml`; the long-running main
container's env carries only `DB_APP_DSN` — code execution in the main admin process can never hold the
owner credential (fix wave #4, commit `2393f4e`; checked on deploy: the pod spec's `migrate` container env
is `[DB_OWNER_DSN, DB_APP_PASSWORD]` and the `admin` container's is `[DB_APP_DSN, ...]`). `infra/tests/04-admin.sh`
execs `psql` as `sandcastle_app` and confirms `UPDATE audit ...` returns `permission denied`. Postgres runs
as its own StatefulSet in `sandcastle-admin` (DR-4.7), independent of coderd's database.

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| WORM / S3 Object Lock for audit | Immutable even against a compromised DB role | Needs S3-compatible storage (e.g. MinIO) in the air-gapped VPC; another component | order-of-magnitude 2-4 days, 2026-09 | New service; misconfig can silently drop writes |
| pgaudit extension | Captures every SQL statement | Noisier; same DB, same superuser trust boundary | order-of-magnitude 1 day, 2026-09 | Log volume |
| External SIEM ingestion | Centralized, tamper-evident | Needs a reachable SIEM; none exists air-gapped yet | order-of-magnitude 3-5 days, 2026-09 (excl. SIEM) | New network path is new attack surface if not scoped |
| Extra database on coder-db | One fewer StatefulSet | coderd compromise exposes admin data and vice versa (DR-4.7) | none saved | Cross-contamination of trust domains |

**Why this control.** DR-4.7 (independent blast radius) and the threat-table row "Audit tampering via the
app: database grants: app role cannot UPDATE/DELETE audit." Lab-scale answer; WORM or SIEM is the natural
next layer at 500/5000 users — see `docs/security/06-enterprise-scale.md`.

**Residual risk.**
- A Postgres superuser (not the app role) can still alter `audit`; this only constrains the app's own credential. See `docs/security/05-gaps-and-monitoring.md`.

## C-ADM-11 Web session security: HMAC cookies, CSRF, SameSite=Lax, CSP, no JS, owner-or-admin checks

**Threat mitigated.** Cookie tampering could forge an admin session; without CSRF, a hostile page could
submit approvals/grants using the owner's session; without a strict CSP and no client-side JS, an injected
script could exfiltrate the session cookie.

**Control.** `admin/internal/auth/auth.go` signs session/OAuth-flow cookies with HMAC-SHA256 over a
≥32-byte key (`getSigned` uses `hmac.Equal` for constant-time comparison), binding the cookie
*name* into the MAC (`mac(name+"|"+payload)`) so an `sc_oauth` flow cookie's value cannot be replayed as
an `sc_session` cookie; `User()` additionally rejects any session with an empty `ID` or empty `CSRF`, since
an all-zero-value session would otherwise pass an `""==""` CSRF check as a signed-in nobody (fix wave #1,
commit `ac74876`; verified by `auth.TestCookieConfusionAndEmptyCSRF`). Cookies set `HttpOnly` and
`SameSite=Lax`. `Login`'s `next` redirect target is validated by `localPath()`: `url.Parse` must succeed
with an empty scheme and host, the path must start with exactly one `/`, and no rune below `0x20`, `0x7f`,
or a backslash may appear raw or in the decoded path — anything else falls back to `/`, closing an open
redirect where `/login?next=/%09/evil.com` previously passed prefix checks and browsers turned the stripped
tab into `//evil.com` (fix wave #2, commit `ac74876`; verified by `auth.TestLoginNext`). Every non-GET
request under `Require` checks a per-session CSRF token from the form body against the cookie's `CSRF`
field with `subtle.ConstantTimeCompare` (bearer requests are exempt — browsers never attach a bearer
automatically). `web.go` `secure()` sets `Content-Security-Policy: default-src 'none'; style-src
'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`. Pages are server-rendered `html/template` with no JavaScript (DR-4.11,
auto-escaped). `own()` enforces owner-or-admin on request filing. Related: the request-form link
(`web/handlers.go` `requestForm`) only reads `ws=` when `src=` is absent, so an agent-crafted authority in
Envoy's 403 link cannot smuggle a different workspace ID past the `src=`-derived one — see C-ADM-2.

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Server-side session store | Instant server-side revocation | Extra store, extra round trip; current design already caps TTL at 8h | order-of-magnitude 1-2 days | New dependency or DB load |
| htmx for partial updates | Live queue updates | Needs vendoring (CDN unreachable air-gapped) for a flow that doesn't need it (DR-4.11) | order-of-magnitude 1 day | One more vendored dependency to patch |
| SameSite=Strict | Stronger CSRF baseline | Breaks the cross-site OAuth2 callback redirect from coderd | trivial | Login flow breaks |

**Why this control.** DR-4.11: an air-gapped browser cannot load htmx from a CDN, and no page needs partial
swaps. Signed cookies + CSRF + SameSite=Lax + CSP + no JS covers the standard web session threat surface.
Threat-table row: "CSRF on approve: SameSite=Lax cookie + per-session CSRF token on every POST."

**Residual risk.**
- Cookies lack `Secure` (lab UI is plain HTTP on a NodePort, per `ponytail` comment in `auth.go`); set once the UI sits behind TLS. See `docs/security/05-gaps-and-monitoring.md`.
- No server-side session revocation: a stolen signed cookie is valid until its 8-hour TTL expires.

## C-ADM-12 Denial ingest over Envoy ALS with per-key throttle and per-workspace cap

**Threat mitigated.** A hostile agent discovering 403 responses could flood denials for many hosts, either
to grow the `denials` table unbounded or to bury a real, actionable denial under noise.

**Control.** `xds/server.go` `StreamAccessLogs`/`denial()` classifies a denial purely by
`response_code == 403` on the `proxy` listener (spike S5: RBAC local-reply denials carry no response
flags, so flag-based classification would miss them). `cmd/sandcastle-admin/main.go` keeps an in-memory
`throttle` (mutex-guarded map keyed `workspace|host|port`) that skips a repeat within 1 s before it ever
reaches Postgres, so a retrying agent costs no DB round trip; above 10,000 tracked keys it prunes entries
older than a minute, and resets to just the current key if that still leaves more than 10,000 so a flood of
fresh keys never forces a full scan on every call. `store/requests.go` `RecordDenial` throttles again
independently (once per second per key, `ON CONFLICT ... WHERE denials.last_seen < now() - interval
'1 second'`, in case of a restart) and caps each workspace to its newest 200 rows — but now runs the cap
`DELETE ... OFFSET 200` only when a row was actually inserted (`RETURNING (xmax = 0)`), not on every
throttled update, so a flooding agent no longer costs two SQL statements per denial (fix wave #10, commit
`a0e1281`; verified by `cmd.TestDenialThrottle` and `store.TestDenialsThrottleAndCap`).

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Unthrottled, unbounded table | Simplest | Grows without bound under a flooding agent; noisy UI | none | Resource exhaustion, DoS on queue/mine pages |
| Rate limit at the Envoy layer | Stops the flood earlier | Out of scope for Phase 4 (spec: Phase 6) | deferred | none additional |
| Global (not per-workspace) cap | Simpler accounting | One noisy workspace starves another's visibility | trivial | Cross-workspace denial-of-visibility |

**Why this control.** Threat-table row: "Agent floods denials to bury real ones: dedup primary key,
per-workspace cap, update throttling." Per-workspace (not global) capping keeps one noisy workspace from
hiding another's signal.

**Residual risk.**
- 200 rows/workspace is a fixed, untuned cap; no metric currently alerts when a workspace is being throttled or dropped. See `docs/security/05-gaps-and-monitoring.md`.

## C-ADM-13 Admin least privilege: k8s Role scoped to workspace pods + CNPs; xDS limited to Envoy, UI to off-cluster

**Threat mitigated.** admin decides all workspace egress, "the highest-value target" (spec threat
analysis). Broad Kubernetes RBAC or network reachability would let a compromise of admin reach far more
than egress policy.

**Control.** `platform/admin/rbac.yaml`: a `Role` in `sandcastle-workspaces` limited to `get/list/watch` on
`pods` and CRUD on `ciliumnetworkpolicies` — no secrets, no other namespaces. `platform/policy/admin.yaml`
CNP: ingress to `:18000` (ADS+ALS) only from the `envoy-egress` pod; ingress to `:8080` (UI) only from
`world/host/remote-node` (off-cluster, never another pod); egress limited to kube-dns, `admin-db`, coderd
`:8080`, kube-apiserver `:6443`. `admin-db`'s CNP denies all egress and accepts ingress only from
`sandcastle-admin`.

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| ClusterRole, broader access | Simpler, future-proof | Violates least privilege; compromise reads pods cluster-wide | none saved | Wider blast radius |
| No CNP on :18000/:8080 ingress | Simpler manifest | Any in-cluster pod could reach xDS/ALS or the UI | none saved | Direct path to the highest-value target |

**Why this control.** Threat-table row: "Admin compromise = all egress: highest-value target: no workspace
route; NodePort served only on the lab network; minimal k8s RBAC." Defense in depth around the single
highest-value target in the system.

**Residual risk.**
- The xDS/ALS channel is plaintext gRPC in-cluster (`ponytail` note in `xds/server.go`: "add mTLS when multi-node"; threat row "Spoofed xDS server"). See `docs/security/05-gaps-and-monitoring.md`.

## C-ADM-14 Test-hook bearer gated by an optional secret (lab only)

**Threat mitigated.** Automated verification (`infra/tests/04-admin.sh`) needs to act as admin
non-interactively (scripted OAuth2 consent needs CSRF double-submit tokens a browser normally supplies, per
spike findings). Without a scoped, optional mechanism, tests need either real browser automation or a
permanent backdoor.

**Control.** `auth.go` `User()` accepts a `Bearer` token matching `Config.TestToken` (env `TEST_TOKEN`) and
maps it to a synthetic `testUser` (`Admin: true`, audited as `test-hook`) — only when `TestToken != ""`.
`infra/bootstrap/05-admin.sh` creates secret `admin-test-token` only when `TEST_HOOKS=1` (lab default);
`TEST_HOOKS=0` deletes it, and the Deployment sources `TEST_TOKEN` with `optional: true`. `main.go` logs a
`WARNING` at startup when the hook is enabled. Bearer requests are exempt from CSRF checking.

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| Full browser automation (scripted consent) | No backdoor at all | Needs CSRF double-submit scripting; brittle across Coder versions | order-of-magnitude 2-3 days | Test flakiness, not a security cost |
| Long-lived API key service account | Simpler than OAuth2 | Not scoped to "test only"; indistinguishable from a real credential if leaked | order-of-magnitude 1 day | Leaked key looks like a real admin credential |

**Why this control.** Test spec: "the API accepts bearer auth from a Kubernetes secret ... which exists
only when the chart value `testHooks=true` ... documented as off for production." Optional and absent by
default outside the lab bootstrap.

**Residual risk.**
- If `TEST_HOOKS=1` were left on outside the lab, the bearer grants full admin rights with no expiry beyond redeploying the secret. See `docs/security/05-gaps-and-monitoring.md`.

## C-ADM-15 Secret generation in-cluster, passed via stdin not argv; never committed

**Threat mitigated.** Secrets passed as command-line arguments are visible to any process on the host via
`ps` and to shell history; secrets checked into git are effectively permanent.

**Control.** `infra/bootstrap/05-admin.sh` generates DB passwords, the session HMAC key, and the test token
with `openssl rand -hex`, creating each Kubernetes secret via
`kubectl create secret generic ... --from-env-file=/dev/stdin <<EOF ... EOF` — never a `kubectl` argument.
The script states: "Secrets go through stdin, never argv, so they do not show in `ps`." No secret values or
`.env` files live in `platform/admin/admin.yaml`, which only references `secretKeyRef`s. The script's own
short-lived Coder bootstrap token (used to register the OAuth2 app and query the experiments API) previously
went to `curl` on argv, visible to any local `ps`, and was never revoked; it now goes through a `mktemp`,
`chmod 600` header file (`curl -H @"$hdr"`) and an `EXIT` trap that removes the file and runs
`coder tokens remove <name>` (warning, not failing, if removal fails) — fix wave #11, commit `2604add`,
checked on the VM: the header-file `curl` worked and the token returned 401 after removal.

**Alternatives considered.**
| Alternative | Pros | Cons / trade-offs | Cost to implement | Risk added |
|---|---|---|---|---|
| External secret manager (Vault, sealed-secrets) | Centralized rotation, encryption at rest | Another component to run/secure; overkill for a single-node lab | order-of-magnitude 2-4 days, 2026-09 | New service, new failure mode if unreachable |
| `kubectl create secret --from-literal` | Slightly shorter script | Value visible in shell history and briefly in `ps` on some kernels | trivial | Secret exposure via process listing/history |

**Why this control.** Operational hygiene matching the air-gapped, single-admin bootstrap model; called out
directly in the script's own comments and the deliverables list ("Secrets are generated by
infra/bootstrap/05-admin.sh, never committed").

**Residual risk.**
- Kubernetes Secrets are base64, not encrypted, unless etcd encryption at rest is configured; k3s default etcd encryption was not verified in this review. See `docs/security/05-gaps-and-monitoring.md`.

## Discrepancies found (code vs. spec)

- Spec's threat-table alternative ("per-workspace filter chains, tested not adopted") and the Enforcement
  section text agree with the shipped code (`xds/build.go` uses per-host vhosts) — no discrepancy.
- Spec's `rules.workspace_id`/`rules.zone_id` exclusivity check matches `001_init.sql` exactly
  (`CHECK ((zone_id IS NULL) <> (workspace_id IS NULL))`) — no discrepancy.
- No spec/code conflicts found for C-ADM-1 through C-ADM-15; the design doc's DR list and the shipped
  Go/YAML match on every control in this file.
