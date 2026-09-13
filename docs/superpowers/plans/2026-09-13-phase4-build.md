# Phase 4 Build Plan — Index

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `sandcastle-admin`, which turns zones and grants into per-workspace Envoy xDS config and Cilium DNS policies, with a login-protected UI, request queue, and audit log.

**Architecture:** One Go binary under `admin/`. Pure packages (`policy`, `xds` builder, `cilium` render) carry the logic and the table tests. Thin I/O packages (`store`, `watch`, `auth`, `web`) wrap Postgres, the kube API, and coderd. `cmd/sandcastle-admin` rebuilds everything from the database on every change. One file per task, linked below; execute in order.

**Tech Stack:** Go 1.27 (in `golang:1.27` containers only), go-control-plane v0.14.0 + envoy module v1.39.0, grpc, protojson, client-go v0.37.0, pgx v5.11.0, golang.org/x/oauth2, Envoy v1.39.1, Cilium 1.20.1, Coder 2.36.5, Postgres 17.6.

**Spec:** `docs/superpowers/specs/2026-09-13-phase4-admin-control-plane-design.md` · spike evidence: `docs/superpowers/specs/2026-09-13-phase4-spike-results.md`

## Global Constraints

- Module path `github.com/sgtslaughta/sandcastle/admin`, directory `admin/`. Every Go file < 500 lines.
- No Go toolchain on the host or VM. Run Go with `make admin-test` / `make admin-go ARGS='...'` (Docker, `golang:1.27`, runs as your uid).
- Workspaces: namespace `sandcastle-workspaces`, pod label `com.coder.workspace.id` (bare key, spike S4), owner label `com.coder.user.id`, name label `com.coder.workspace.name`.
- Envoy node ID `sandcastle-egress`; RDS route name `egress`; bootstrap cluster for ADS + ALS is named `admin`.
- Rule values: exact FQDN or `*.suffix`, lowercase; host ports 443/80 only; DNS rules port 0.
- Denial detection: ALS entries with `response_code == 403` (spike S5: RBAC denials carry no flags).
- Tunnel cap: CONNECT route `max_stream_duration` 3600s (DR-4.10). Envoy args add `--drain-time-s 5 --drain-strategy immediate` (spike S3).
- Grant TTLs for humans: `1h`, `24h`, `168h` (default), `720h`. `60s` is allowed only for the test-hook bearer.
- Coder admin roles: `owner`, `user-admin`.
- UI: server-rendered `html/template`, POST-redirect-GET, no JavaScript (DR-4.11).
- Seed on first start: zone `default` (is_default) with host `example.com` on 443 and 80.
- Shell: under `set -o pipefail` use `grep ... >/dev/null`, never `grep -q`.
- Commits: conventional (`feat(admin): ...`, `test(admin): ...`) ending with the session's Co-Authored-By/Claude-Session trailer lines.
- Lab VM access for executors: `P=/tmp/claude-1000/-home-user-code-sandcastle/301b8128-c760-470f-8df4-cc65f4b3b771/scratchpad`, `$P/vmssh '<cmd>'` (stdin forwarded), `$P/vmsync` (rsync repo to `~/sandcastle`). No host sudo: steps marked **OWNER** are run by the owner.

## File Map

| File | Responsibility | Task |
|---|---|---|
| `Makefile` (modify) | `admin-go`, `admin-test`, later `admin-image`, `admin`, `verify-admin` | 4, 9, 13 |
| `admin/go.mod`, `admin/go.sum` | module | 4 |
| `admin/internal/policy/policy.go` + `_test.go` | validation, effective rules, host→IPs | 4 |
| `admin/internal/xds/build.go` + `_test.go` | allowlist → Envoy resources | 5 |
| `admin/internal/xds/server.go` + `_test.go` | ADS snapshot push, ALS denial sink | 6 |
| `admin/internal/cilium/cilium.go` + `_test.go` | CNP render, apply/prune | 7 |
| `admin/internal/watch/pods.go` + `_test.go` | workspace pod informer | 8 |
| `admin/internal/store/*.go`, `migrations/001_init.sql` | Postgres schema, queries, seed | 9 |
| `admin/internal/auth/auth.go` + `_test.go` | Coder OAuth2, session, CSRF, test hook | 10 |
| `admin/internal/web/*.go`, `templates/*.html` | pages and form handlers | 11 |
| `admin/cmd/sandcastle-admin/main.go`, `admin/Dockerfile` | wiring, rebuild loop | 12 |
| `platform/admin/*.yaml`, `platform/egress/envoy.yaml`, `platform/policy/platform.yaml`, `platform/coder/values.yaml`, `infra/bootstrap/05-admin.sh` | deploy | 13 |
| `infra/tests/04-admin.sh`, docs | verify + release | 14 |

## Tasks

Spikes (done): [host S2/S3/S5](2026-09-13-phase4-admin-control-plane.md), [VM S1/S4 + results](2026-09-13-phase4-spikes-vm.md). Tasks 0–3 are complete.

| # | Task |
|---|---|
| 4 | [Go module, Docker Go runner, `policy` package](2026-09-13-phase4-task-04-policy.md) |
| 5 | [xDS resource builder](2026-09-13-phase4-task-05-xds-build.md) |
| 6 | [xDS server, ALS denial sink, real-Envoy smoke test](2026-09-13-phase4-task-06-xds-server.md) |
| 7 | [Cilium DNS policy render + apply/prune](2026-09-13-phase4-task-07-cilium.md) |
| 8 | [Workspace pod watcher](2026-09-13-phase4-task-08-watch.md) |
| 9 | [Postgres store (schema, audit, zones, grants, requests, denials)](2026-09-13-phase4-task-09-store.md) |
| 10 | [Coder OAuth2 login, signed sessions, CSRF, test hook](2026-09-13-phase4-task-10-auth.md) |
| 11 | [Web UI and form handlers](2026-09-13-phase4-task-11-web.md) |
| 12 | [Main wiring, rebuild loop, image](2026-09-13-phase4-task-12-main.md) |
| 13 | [Deploy — manifests, Envoy on xDS, bootstrap script](2026-09-13-phase4-task-13-deploy.md) |
| 14 | [End-to-end verify, regressions, docs, release](2026-09-13-phase4-task-14-verify-release.md) |
