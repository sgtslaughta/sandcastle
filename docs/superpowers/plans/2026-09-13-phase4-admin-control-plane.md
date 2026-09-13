# Phase 4 Admin Control Plane Implementation Plan — Part 1: Spikes

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the five risky mechanisms of the Phase 4 design (S1–S5) before writing any sandcastle-admin code.

**Architecture:** S2, S3, and S5 are pure Envoy behavior and run on the host
in throwaway Docker containers on a private bridge network, so the lab VM is
not disturbed. S1 (Coder OAuth2) and S4 (Cilium label selectors on Kata pods)
need the lab cluster and run inside the VM. All spike files live in the
session scratchpad and are never committed. Only the results doc is
committed.

**Tech Stack:** Envoy v1.39.1 (file-based LDS/CDS/RDS), golang:1.27 container, go-control-plane `envoy` module v1.39.0, Coder 2.36.5, Cilium 1.20.1.

**Spec:** `docs/superpowers/specs/2026-09-13-phase4-admin-control-plane-design.md`

**Part 2 (build tasks) is written after this gate passes.** The spike
outcomes decide the auth flow (PKCE or not), the RBAC/local-reply shape, and
the revocation mechanism, so writing that code first risks rewriting it.

## Global Constraints

- Envoy image: `envoyproxy/envoy:v1.39.1`. Go image: `golang:1.27`. Module: `github.com/envoyproxy/go-control-plane/envoy@v1.39.0`.
- Host has no Go toolchain and no cluster: Go runs only inside `golang:1.27` containers. Never run k3s/Cilium changes on the host.
- Lab VM access for executors: `P=/tmp/claude-1000/-home-user-code-sandcastle/301b8128-c760-470f-8df4-cc65f4b3b771/scratchpad`, then `$P/vmssh '<cmd>'`. The VM repo is `~/sandcastle`; the Coder CLI is `~/.local/bin/coder`; Coder URL `http://192.168.122.124:30080`.
- Workspaces run in namespace `sandcastle-workspaces`; pods carry label `com.coder.workspace.id`.
- In pipelines under `set -o pipefail`, use `grep ... >/dev/null`, never `grep -q`.
- Spike files are throwaway: scratchpad only, never committed.
- A failed spike stops the plan: record it in the results doc and return to design.

## Files

- Create (scratchpad, throwaway): `$P/p4spike/envoy/{bootstrap,lds,cds,rds}.yaml`, `$P/p4spike/als/main.go`, `$P/p4spike/s1.sh`, `$P/p4spike/cnp-in.yaml`, `$P/p4spike/cnp-notin.yaml`.
- Create (committed): `docs/superpowers/specs/2026-09-13-phase4-spike-results.md`.

---

### Task 0: Spikes S2, S3, S5 on the host (Envoy RBAC, SNI binding, tunnel drain, ALS)

**Interfaces:**
- Produces: the pass/fail rows S2, S3, S5 in the results doc, and the exact working Envoy snippets (RBACPerRoute, local_reply_config, http_grpc access log) that Part 2's xDS builder must reproduce.

- [ ] **Step 1: Create the Docker network and directories**

```bash
P=/tmp/claude-1000/-home-user-code-sandcastle/301b8128-c760-470f-8df4-cc65f4b3b771/scratchpad
D=$P/p4spike; mkdir -p $D/envoy $D/als
docker network create --subnet 172.30.0.0/24 p4spike
```
Expected: a network ID is printed. If the subnet collides, pick another /24 and replace `172.30.0.` everywhere below.

- [ ] **Step 2: Write the ALS stub (S5)** — `$D/als/main.go`

```go
package main

import (
	"log"
	"net"

	alsv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"google.golang.org/grpc"
)

type sink struct {
	alsv3.UnimplementedAccessLogServiceServer
}

func (sink) StreamAccessLogs(s alsv3.AccessLogService_StreamAccessLogsServer) error {
	for {
		m, err := s.Recv()
		if err != nil {
			return err
		}
		for _, e := range m.GetHttpLogs().GetLogEntry() {
			c := e.GetCommonProperties()
			log.Printf("ALS src=%s authority=%s code=%d flags=%v",
				c.GetDownstreamDirectRemoteAddress().GetSocketAddress().GetAddress(),
				e.GetRequest().GetAuthority(),
				e.GetResponse().GetResponseCode().GetValue(),
				c.GetResponseFlags())
		}
	}
}

func main() {
	l, err := net.Listen("tcp", ":18000")
	if err != nil {
		log.Fatal(err)
	}
	g := grpc.NewServer()
	alsv3.RegisterAccessLogServiceServer(g, sink{})
	log.Fatal(g.Serve(l))
}
```

Start it:
```bash
docker run -d --name p4-als --network p4spike --ip 172.30.0.20 -v $D/als:/src -w /src golang:1.27 \
  sh -c 'go mod init als && go get github.com/envoyproxy/go-control-plane/envoy@v1.39.0 google.golang.org/grpc && go mod tidy && go run .'
sleep 60; docker logs p4-als 2>&1 | tail -5
```
Expected: no compile errors. The process is left running; `docker ps` shows `p4-als` Up.

- [ ] **Step 3: Write the Envoy bootstrap** — `$D/envoy/bootstrap.yaml`

```yaml
node: {id: spike, cluster: spike}
bootstrap_extensions:
  - name: envoy.bootstrap.internal_listener
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.bootstrap.internal_listener.v3.InternalListener
admin:
  address: {socket_address: {address: 0.0.0.0, port_value: 9901}}
dynamic_resources:
  lds_config:
    resource_api_version: V3
    path_config_source: {path: /etc/envoy/lds.yaml, watched_directory: {path: /etc/envoy}}
  cds_config:
    resource_api_version: V3
    path_config_source: {path: /etc/envoy/cds.yaml, watched_directory: {path: /etc/envoy}}
static_resources:
  clusters:
    - name: als
      type: STATIC
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config: {http2_protocol_options: {}}
      load_assignment:
        cluster_name: als
        endpoints:
          - lb_endpoints:
              - endpoint: {address: {socket_address: {address: 172.30.0.20, port_value: 18000}}}
```

- [ ] **Step 4: Write CDS** — `$D/envoy/cds.yaml`

```yaml
resources:
  - "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
    name: sni_com
    load_assignment:
      cluster_name: sni_com
      endpoints: [{lb_endpoints: [{endpoint: {address: {envoy_internal_address: {server_listener_name: sni_com}}}}]}]
  - "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
    name: sni_org
    load_assignment:
      cluster_name: sni_org
      endpoints: [{lb_endpoints: [{endpoint: {address: {envoy_internal_address: {server_listener_name: sni_org}}}}]}]
  - "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
    name: dfp_http
    lb_policy: CLUSTER_PROVIDED
    cluster_type:
      name: envoy.clusters.dynamic_forward_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
        dns_cache_config: {name: dfp, dns_lookup_family: V4_ONLY}
  - "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
    name: dfp_sni
    lb_policy: CLUSTER_PROVIDED
    cluster_type:
      name: envoy.clusters.dynamic_forward_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
        dns_cache_config: {name: dfp, dns_lookup_family: V4_ONLY}
```

- [ ] **Step 5: Write LDS** — `$D/envoy/lds.yaml`

The proxy listener uses RDS from a file, so later route changes do not
replace the proxy listener. That keeps S3 measuring only the per-host
listener swap.

```yaml
resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: proxy
    address: {socket_address: {address: 0.0.0.0, port_value: 3128}}
    filter_chains:
      - filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              stat_prefix: egress
              upgrade_configs: [{upgrade_type: CONNECT}]
              rds:
                route_config_name: egress
                config_source:
                  resource_api_version: V3
                  path_config_source: {path: /etc/envoy/rds.yaml, watched_directory: {path: /etc/envoy}}
              access_log:
                - name: envoy.access_loggers.stdout
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
                - name: envoy.access_loggers.http_grpc
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.access_loggers.grpc.v3.HttpGrpcAccessLogConfig
                    common_config:
                      log_name: egress
                      transport_api_version: V3
                      grpc_service: {envoy_grpc: {cluster_name: als}}
              local_reply_config:
                mappers:
                  - filter:
                      status_code_filter:
                        comparison: {op: EQ, value: {default_value: 403, runtime_key: spike.deny}}
                    headers_to_add:
                      - header:
                          key: x-sandcastle-denied
                          value: "host=%REQ(:AUTHORITY)%; source=%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
                    body: {inline_string: "sandcastle: denied\n"}
              http_filters:
                - name: envoy.filters.http.rbac
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC
                    rules: {action: ALLOW, policies: {}}
                - name: envoy.filters.http.dynamic_forward_proxy
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
                    dns_cache_config: {name: dfp, dns_lookup_family: V4_ONLY}
                - name: envoy.filters.http.router
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: sni_com
    internal_listener: {}
    listener_filters:
      - name: envoy.filters.listener.tls_inspector
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
    filter_chains:
      - filter_chain_match: {server_names: ["example.com"]}
        filters:
          - name: envoy.filters.network.sni_dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.sni_dynamic_forward_proxy.v3.FilterConfig
              port_value: 443
              dns_cache_config: {name: dfp, dns_lookup_family: V4_ONLY}
          - name: envoy.filters.network.tcp_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
              stat_prefix: sni_com
              cluster: dfp_sni
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: sni_org
    internal_listener: {}
    listener_filters:
      - name: envoy.filters.listener.tls_inspector
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
    filter_chains:
      - filter_chain_match: {server_names: ["example.org"]}
        filters:
          - name: envoy.filters.network.sni_dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.sni_dynamic_forward_proxy.v3.FilterConfig
              port_value: 443
              dns_cache_config: {name: dfp, dns_lookup_family: V4_ONLY}
          - name: envoy.filters.network.tcp_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
              stat_prefix: sni_org
              cluster: dfp_sni
```

- [ ] **Step 6: Write RDS** — `$D/envoy/rds.yaml`

Client A = 172.30.0.11 (allowed both hosts). Client B = 172.30.0.12 (allowed nothing).

```yaml
resources:
  - "@type": type.googleapis.com/envoy.config.route.v3.RouteConfiguration
    name: egress
    virtual_hosts:
      - name: h_example_com
        domains: ["example.com:443"]
        typed_per_filter_config:
          envoy.filters.http.rbac:
            "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute
            rbac:
              rules:
                action: ALLOW
                policies:
                  ws:
                    permissions: [{any: true}]
                    principals: [{direct_remote_ip: {address_prefix: 172.30.0.11, prefix_len: 32}}]
        routes:
          - match: {connect_matcher: {}}
            route: {cluster: sni_com, upgrade_configs: [{upgrade_type: CONNECT, connect_config: {}}]}
      - name: h_example_org
        domains: ["example.org:443"]
        typed_per_filter_config:
          envoy.filters.http.rbac:
            "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute
            rbac:
              rules:
                action: ALLOW
                policies:
                  ws:
                    permissions: [{any: true}]
                    principals: [{direct_remote_ip: {address_prefix: 172.30.0.11, prefix_len: 32}}]
        routes:
          - match: {connect_matcher: {}}
            route: {cluster: sni_org, upgrade_configs: [{upgrade_type: CONNECT, connect_config: {}}]}
      - name: h_example_com_http
        domains: ["example.com", "example.com:80"]
        typed_per_filter_config:
          envoy.filters.http.rbac:
            "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute
            rbac:
              rules:
                action: ALLOW
                policies:
                  ws:
                    permissions: [{any: true}]
                    principals: [{direct_remote_ip: {address_prefix: 172.30.0.11, prefix_len: 32}}]
        routes:
          - match: {prefix: "/"}
            route: {cluster: dfp_http}
      - name: deny
        domains: ["*"]
        routes:
          - match: {connect_matcher: {}}
            direct_response: {status: 403}
          - match: {prefix: "/"}
            direct_response: {status: 403}
```

- [ ] **Step 7: Start Envoy and the two clients**

```bash
docker run -d --name p4-envoy --network p4spike --ip 172.30.0.10 -v $D/envoy:/etc/envoy \
  envoyproxy/envoy:v1.39.1 -c /etc/envoy/bootstrap.yaml --log-level info --drain-time-s 5 --drain-strategy immediate
for c in a:11 b:12; do
  docker run -d --name p4-${c%%:*} --network p4spike --ip 172.30.0.${c##*:} alpine:3 sleep infinity
  docker exec p4-${c%%:*} apk add --no-cache curl openssl >/dev/null
done
sleep 5; docker logs p4-envoy 2>&1 | grep -iE 'error|warn|rejected' | head
curl -s http://172.30.0.10:9901/listeners   # run from host; admin bound to 0.0.0.0 for the spike only
```
Expected: no `rejected` lines. The listener list shows `proxy`, `sni_com`, `sni_org`.
If a config is rejected, fix the named field (the error names it) and restart
`p4-envoy`. Record every fix in the results doc.

- [ ] **Step 8: S2 checks — RBAC per source IP, 403 shape, SNI binding**

```bash
px=http://172.30.0.10:3128
echo "A com:";  docker exec p4-a curl -s -o /dev/null -w '%{http_code}\n' -m 20 -x $px https://example.com
echo "A http:"; docker exec p4-a curl -s -o /dev/null -w '%{http_code}\n' -m 20 -x $px http://example.com
echo "B com:";  docker exec p4-b curl -sv -m 20 -x $px https://example.com 2>&1 | grep -iE '< HTTP|x-sandcastle-denied'
echo "B http:"; docker exec p4-b curl -si -m 20 -x $px http://example.com | grep -iE '^HTTP|x-sandcastle-denied|sandcastle:'
echo "A other host:"; docker exec p4-a curl -sv -m 20 -x $px https://github.com 2>&1 | grep -iE '< HTTP|x-sandcastle-denied'
echo "A SNI mismatch:"; docker exec p4-a curl -sk -m 20 -o /dev/null -w '%{http_code}\n' -x $px --connect-to github.com:443:example.com:443 https://github.com; echo "exit=$?"
echo "A cross-host SNI:"; docker exec p4-a sh -c "echo | openssl s_client -proxy 172.30.0.10:3128 -connect example.com:443 -servername example.org 2>&1 | grep -E 'CONNECTED|errno|handshake|Verify return'"
```
Pass criteria (all must hold):
- A com `200`; A http `200`.
- B com `403` **with** `x-sandcastle-denied` (RBAC local reply got the mapper header).
- B http `403` with the header and `sandcastle: denied` body.
- A other host `403` with the header (deny vhost direct_response got the mapper header).
- A SNI mismatch: curl fails (exit non-zero, code `000`).
- A cross-host SNI (CONNECT example.com, SNI example.org): handshake fails. This proves per-host binding, since example.org is allowed for A but only on its own vhost.

If the header is missing on the RBAC path or the direct_response path, record which one. Part 2 must then add the header another way: `response_headers_to_add` on the deny vhost for direct_response; for RBAC, a per-vhost route with direct_response instead of relying on the filter's local reply.

- [ ] **Step 9: S5 check — ALS entries**

```bash
docker logs p4-als 2>&1 | grep ALS | tail -8
```
Pass: lines exist for 172.30.0.12 with `authority=example.com:443 code=403` and for 172.30.0.11 with `code=200`. Record the `flags` value printed for the RBAC denial.

- [ ] **Step 10: S3 check — replacing the per-host listener closes open tunnels, and only those**

Open two long-lived tunnels from A, one per host:
```bash
for h in com org; do
  docker exec -d p4-a sh -c "(sleep 600) | openssl s_client -quiet -proxy 172.30.0.10:3128 -connect example.$h:443 -servername example.$h >/dev/null 2>&1; echo \"closed \$(date +%s)\" > /tmp/tunnel-$h"
done
sleep 5; docker exec p4-a sh -c 'ls /tmp/tunnel-* 2>/dev/null || echo "both open"'
```
Expected: `both open`.

Rename only the example.com listener/cluster: `sni_com` → `sni_com2`. Write
temp files, then `mv` each (atomic swap in the watched directory): LDS first,
then CDS, then RDS.
```bash
cd $D/envoy && date +%s > /tmp/p4-swap-at
for f in lds cds rds; do sed 's/\bsni_com\b/sni_com2/g' $f.yaml > .$f.tmp && mv .$f.tmp $f.yaml; sleep 1; done
sleep 12
docker exec p4-a sh -c 'for f in /tmp/tunnel-*; do echo "$f: $(cat $f)"; done 2>/dev/null; true'; echo "swap at $(cat /tmp/p4-swap-at)"
curl -s http://172.30.0.10:9901/listeners
docker exec p4-a curl -s -o /dev/null -w 'A com after swap: %{http_code}\n' -m 20 -x http://172.30.0.10:3128 https://example.com
```
Pass criteria:
- `/tmp/tunnel-com` exists with a close time ≤ swap + 10 s.
- `/tmp/tunnel-org` does not exist (untouched tunnel survives).
- The listener list shows `sni_com2`, not `sni_com`.
- A com after swap is `200` (new listener serves).

If the com tunnel stays open, check whether removing the **cluster**
`sni_com` without renaming the listener closes it: repeat with only the CDS
and RDS rename. Record which resource's removal closes the tunnel. Part 2's
naming hash goes on that resource.

- [ ] **Step 11: Clean up**

```bash
docker rm -f p4-envoy p4-als p4-a p4-b; docker network rm p4spike
```

---

Continue with [VM spikes S1, S4 and results](2026-09-13-phase4-spikes-vm.md).
