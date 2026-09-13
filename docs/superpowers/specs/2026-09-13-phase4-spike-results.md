# Phase 4 — Spike Results

Date: 2026-09-13
Spec: [Phase 4 design](2026-09-13-phase4-admin-control-plane-design.md)
Plans: [host spikes](../plans/2026-09-13-phase4-admin-control-plane.md) · [VM spikes](../plans/2026-09-13-phase4-spikes-vm.md)

S2, S3, and S5 ran on the host in throwaway Docker containers (Envoy v1.39.1,
file-based LDS/CDS/RDS, two clients on distinct IPs). S1 and S4 ran in the
lab VM. All spike files were scratchpad-only and are deleted.

| # | Question | Result | Evidence |
|---|---|---|---|
| S1 | Coder OAuth2 provider on OSS 2.36.5 | PASS | `CODER_EXPERIMENTS=oauth2` → `/api/v2/experiments` lists `oauth2`; app create returned an `id` (no license error); PKCE S256 authorize redirected to callback with `code` + `state`; token response has `access_token`; `users/me` with bearer → `admin`, roles include `owner` |
| S2 | Per-vhost RBAC + SNI binding | PASS | A→example.com 200 (HTTPS and HTTP); B→example.com 403 with `x-sandcastle-denied: host=example.com:443; source=172.30.0.12`; A→github.com 403 with header (deny vhost); `--connect-to` SNI mismatch fails; CONNECT example.com with SNI example.org → TLS EOF and `listener.envoy_internal_sni_com.no_filter_chain_match: 1` |
| S3 | Listener swap closes open tunnel | PASS | LDS+CDS+RDS rename `sni_com`→`sni_com2` with `--drain-time-s 5 --drain-strategy immediate`: com tunnel EOF at swap + 6.0 s; org tunnel still alive 20 s+ later; new com connection 200 through `sni_com2` |
| S4 | CNP In / Exists+NotIn on workspace-id label | PASS | Baseline REFUSED; `In [WSID]` → `getent hosts example.org` RESOLVED; `Exists` + `NotIn [WSID]` → REFUSED; bare key `com.coder.workspace.id` (no `k8s:` prefix) |
| S5 | Envoy ALS to gRPC sink | PASS | Stub received `src=172.30.0.12 authority=example.com:443 code=403` and `src=172.30.0.11 ... code=200`; RBAC denial has **no** response flags set |

## Findings that change Part 2

- **Denials are detected by response code, not flags.**
  - *Who:* host spike agent. *When:* 2026-09-13. *Where:* `internal/als`.
  - *What:* RBAC local-reply denials carry empty `response_flags` in ALS.
  - *Why it matters:* the ALS consumer must classify a denial as `response_code == 403` on the `proxy` listener, not by a flag.
- **The first S2/S3 "FAIL" verdicts were harness artifacts.**
  - *Who:* host spike agent, caught by the controller on review. *When:* 2026-09-13. *Where:* spike test commands.
  - *What:*
    - `openssl s_client -proxy` sends an HTTP/1.0 CONNECT with no Host header, which Envoy answers with `426`, so no tunnel opened at all.
    - The closure detector `(sleep 600) | openssl …; echo closed` could not fire before 600 s.
    - The example.com and example.org CDN close idle keepalives at ~15 s, which confounds tunnel-lifetime tests.
  - *Why it matters:* `infra/tests/04-admin.sh` must use HTTP/1.1 CONNECT clients (curl, or python `ssl` over a socket) and keep tunnels busy with periodic requests when measuring closure.
- **Revocation mechanism confirmed as designed (DR-4.8).**
  - *What:* the per-host internal listener named by hash(host, IP set) is replaced on any IP-set change, and Envoy closes that host's open tunnels within the drain time. Tunnels to other hosts survive.
  - *Where:* `internal/xds`; Envoy args must add `--drain-time-s 5 --drain-strategy immediate`.
- **Alternative tested, not adopted: per-workspace filter chains.**
  - *What:* `source_prefix_ranges` chains with an inline route per workspace also revoke correctly. They need `validate_clusters: false` on inline routes, and a change drains **all** of that workspace's tunnels, not just the revoked host.
  - *Why not adopted:* the per-host design (S2+S3) has a smaller blast radius and already passes.
- **Backstop available: route `max_stream_duration`.**
  - *What:* 20 s on the CONNECT route closed a busy tunnel at ~21 s.
  - *Status:* defense in depth only if the owner wants a hard cap on tunnel lifetime; not in the spec.
- **Scripted OAuth2 consent needs CSRF double-submit.**
  - *Who:* VM spike agent. *Where:* S1 script; test tooling only.
  - *What:* `POST /oauth2/authorize` requires the `csrf_token` cookie from the GET plus an `X-CSRF-Token` header. `GET /api/v2/experiments` needs a session token.
  - *Why it matters:* browsers get this from Coder's consent page, so `internal/auth` is unaffected. Automated tests use the admin test hook, not scripted consent.

## Config fixes made during spikes

- None for the planned configs: bootstrap, LDS, CDS, RDS, RBACPerRoute, `local_reply_config` mapper, and the `http_grpc` access log all loaded as written. The mapper header applied to both the RBAC local reply and the deny-vhost `direct_response`.
- Alternative C only: `validate_clusters: false` on inline `route_config`.
