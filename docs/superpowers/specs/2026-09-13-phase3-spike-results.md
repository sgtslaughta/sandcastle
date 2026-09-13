# Phase 3 Spike Results

Date: 2026-09-13
Who: Claude (executor), owner (snapshot + libvirt network on GAME-01)
Where: lab VM 192.168.122.124 after snapshot `pre-containment`; S4 on host Docker
Why: gate the Phase 3 build on the mechanisms the [spec](2026-09-13-phase3-containment-core-design.md) assumes

No fallback was needed. Every row passed; S3 has one documented exception.

| ID | Question | Result | Evidence | Consequence for build |
|---|---|---|---|---|
| S1 | Egress gateway with Kata | **gateway-ok** | Cilium `Masquerading: BPF [ens2, egress0]` (egress0 auto-detected, no `devices` override). Kata pod `curl https://example.com` → 200; tcpdump on `egress0`: `IP 192.168.130.10.55720 > 104.20.23.154.443: Flags [S]`; nothing on `ens2` for that flow. | `egress-gateway.yaml` as planned. |
| S2 | L7 HTTP + DNS on Kata, incl. websocket | **l7-ok** | Kata pod: `/api/v2/buildinfo` 200, `/api/v2/users` 403, `/derp` websocket upgrade 101. Hubble: `dns-request proxy DROPPED (DNS Query example.com. A)`. | L7 rules on coderd and Nexus as planned. |
| S3 | ICMP deny response | **icmp-fast** (exception below) | `1.1.1.1` rc=7 in 151 ms; node `:10250` rc=7 in 146 ms; unchanged with default-deny ingress (`ingress: [{}]`): 144 ms / 137 ms. **Exception:** ClusterIP destinations (`10.43.0.1:443`, the kube API) get no ICMP response and time out (16 s); Hubble still logs `policy-verdict:none EGRESS DENIED`. | No ICMP ingress rule. Verify suite allows a timeout for the kube API check only. The spec's fail-fast claim holds for everything except service-translated destinations. |
| S4 | Envoy two-stage CONNECT + SNI | **two-stage-ok** | Allowed 200 (no deadlock); github.com CONNECT 403 with `x-sandcastle-denied: host=github.com:443; source=…`; plain HTTP 403; CONNECT example.com carrying SNI github.com refused (curl rc=35), `listener.envoy_internal_sni_gate.no_filter_chain_match: 1`. | Stage-2 refusals produced **no** log line: added a listener access log on the internal listener (`{"stage":"sni","sni":"github.com","flags":"NR"}`), and the suite asserts it. |
| S5 | Coder agent address + paths | **pod-8080** | The agent dials the NodePort access URL, but Cilium translates it before policy: Hubble peer `coder/coder-…:8080`. Requests (two live workspaces, including `coder ssh` and code-server): `GET /bin/coder-linux-amd64`, `GET /api/v2/workspaceagents/me/rpc?role=agent&version=2.10`, `GET /api/v2/workspaceagents/me/reinit?wait=true`, `GET /derp`, `GET /derp/latency-check`. `coder server --help`: `--block-direct-connections bool, $CODER_BLOCK_DIRECT`. | coderd rule is exactly those 4 GET patterns (`/api/v2/buildinfo` dropped: not used). Re-capture after any Coder upgrade. |
| S6 | DNS patterns | **explicit multi-label list** | With `*.cluster.local` … `*.*.*.*.cluster.local`: FQDN `nexus.sandcastle-mirror.svc.cluster.local` resolves; short name `coder.coder` resolves through the search list; `example.com` refused. Search-list expansions (`example.com.cluster.local`) are answered NXDOMAIN by CoreDNS, which is authoritative for `cluster.local` and never forwards them upstream. | Pattern list as planned. |

## Bug found during the spike

**Cilium upgrade deadlock on a single node.**
- **What:** enabling `egressGateway` restarted the agent, which waited forever for the CRD `ciliumegressgatewaypolicies.cilium.io`. Only the new operator registers that CRD, and both new operator pods were Pending.
- **Why:**
  - The chart defaults to `operator.replicas=2` with hostNetwork ports, so on one node the second pod had been Pending since Phase 1 (deployment `1/2`).
  - The rolling update (maxUnavailable rounds to 0) never removed the old operator pod.
- **Fix:** `operator.replicas=1` and `operator.updateStrategy.rollingUpdate.maxUnavailable=1` in `infra/bootstrap/01-k3s-cilium.sh`.
- **Where:** `infra/bootstrap/01-k3s-cilium.sh`, lab VM.
- **When:** 2026-09-13.
- **Who:** found and fixed by Claude.

## Observed, not acted on

- The owner's UI workspace `aquamarine-swordfish-6` was running during S5 and contributed its flows to the capture, confirming the path list against a real code-server session.
