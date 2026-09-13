# Phase 4 Build — Task 6: xDS server, ALS denial sink, real-Envoy smoke test

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Plan index, Global Constraints and File Map:** [2026-09-13-phase4-build.md](2026-09-13-phase4-build.md). The Global Constraints apply to this task.

### Task 6: xDS server, ALS denial sink, real-Envoy smoke test

**Files:**
- Create: `admin/internal/xds/server.go`, `admin/internal/xds/server_test.go`
- Create: `admin/hack/smoke/main.go`, `admin/hack/smoke/bootstrap.yaml`, `admin/hack/smoke.sh`
- Modify: `Makefile` (add `admin-smoke`)

**Interfaces:**
- Consumes: `xds.Build`, `xds.Params`, `xds.NodeID` (Task 5); `policy.ValidName`, `policy.HostKey` (Task 4).
- Produces (used by Task 12):
  - `type Denial struct { SrcIP, Host string; Port int }`
  - `type Server struct { OnDenial func(Denial); ... }`
  - `func NewServer() *Server`
  - `func (s *Server) Push(ctx context.Context, res map[resource.Type][]types.Resource) error`
  - `func (s *Server) Register(ctx context.Context, g *grpc.Server)`

- [ ] **Step 1: Write the failing test** — `admin/internal/xds/server_test.go`

```go
package xds

import (
	"context"
	"net"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	accesslogdatav3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	alsv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
)

func entry(ip, authority string, code uint32) *accesslogdatav3.HTTPAccessLogEntry {
	return &accesslogdatav3.HTTPAccessLogEntry{
		CommonProperties: &accesslogdatav3.AccessLogCommon{
			DownstreamDirectRemoteAddress: &corev3.Address{Address: &corev3.Address_SocketAddress{
				SocketAddress: &corev3.SocketAddress{Address: ip}}},
		},
		Request:  &accesslogdatav3.HTTPRequestProperties{Authority: authority},
		Response: &accesslogdatav3.HTTPResponseProperties{ResponseCode: wrapperspb.UInt32(code)},
	}
}

func TestDenialFromEntry(t *testing.T) {
	for _, c := range []struct {
		e    *accesslogdatav3.HTTPAccessLogEntry
		want Denial
		ok   bool
	}{
		{entry("10.42.0.9", "Example.com:443", 403), Denial{"10.42.0.9", "example.com", 443}, true},
		{entry("10.42.0.9", "example.com", 403), Denial{"10.42.0.9", "example.com", 80}, true},
		{entry("10.42.0.9", "example.com:443", 200), Denial{}, false},
		{entry("10.42.0.9", "10.0.0.1:443", 403), Denial{}, false},
		{entry("", "example.com:443", 403), Denial{}, false},
	} {
		got, ok := denial(c.e)
		if ok != c.ok || got != c.want {
			t.Errorf("denial(%v) = %+v,%v want %+v,%v", c.e.GetRequest().GetAuthority(), got, ok, c.want, c.ok)
		}
	}
}

func TestADSServesPushedSnapshotAndALSReportsDenials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewServer()
	got := make(chan Denial, 1)
	s.OnDenial = func(d Denial) { got <- d }
	res, err := Build(Params{Hosts: map[policy.HostKey][]string{{Host: "example.com", Port: 443}: {"10.42.0.9"}},
		RequestURL: "http://admin.invalid/r", TunnelMax: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Push(ctx, res); err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	s.Register(ctx, g)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go g.Serve(l)
	defer g.Stop()

	conn, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ads, err := discoveryv3.NewAggregatedDiscoveryServiceClient(conn).StreamAggregatedResources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ads.Send(&discoveryv3.DiscoveryRequest{Node: &corev3.Node{Id: NodeID}, TypeUrl: resource.ClusterType}); err != nil {
		t.Fatal(err)
	}
	resp, err := ads.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetVersionInfo() != "1" || len(resp.GetResources()) != 3 {
		t.Fatalf("CDS version %q with %d resources, want 1 and 3 (dfp_http, dfp_sni, sni_*)", resp.GetVersionInfo(), len(resp.GetResources()))
	}

	als, err := alsv3.NewAccessLogServiceClient(conn).StreamAccessLogs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := als.Send(&alsv3.StreamAccessLogsMessage{
		Identifier: &alsv3.StreamAccessLogsMessage_Identifier{Node: &corev3.Node{Id: NodeID}, LogName: "egress"},
		LogEntries: &alsv3.StreamAccessLogsMessage_HttpLogs{HttpLogs: &alsv3.StreamAccessLogsMessage_HTTPAccessLogEntries{
			LogEntry: []*accesslogdatav3.HTTPAccessLogEntry{entry("10.42.0.7", "github.com:443", 403)},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-got:
		if d != (Denial{"10.42.0.7", "github.com", 443}) {
			t.Fatalf("denial = %+v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no denial reported")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `make admin-test`
Expected: FAIL, `undefined: NewServer` / `undefined: denial`.

- [ ] **Step 3: Implement** — `admin/internal/xds/server.go`

```go
package xds

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	accesslogdatav3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	alsv3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
)

// Denial is one refused request, as Envoy saw it.
type Denial struct {
	SrcIP, Host string
	Port        int
}

// Server holds the ADS snapshot for the egress Envoy and receives its access
// logs. ponytail: plaintext gRPC in-cluster; only the Envoy pod may reach it
// (CNP). Add mTLS when multi-node.
type Server struct {
	alsv3.UnimplementedAccessLogServiceServer
	OnDenial func(Denial)

	cache   cache.SnapshotCache
	version atomic.Uint64
}

func NewServer() *Server {
	return &Server{cache: cache.NewSnapshotCache(true, cache.IDHash{}, nil)}
}

// Push replaces the whole snapshot. Envoy keeps the last one it accepted if
// admin goes away (DR-4.6).
func (s *Server) Push(ctx context.Context, res map[resource.Type][]types.Resource) error {
	snap, err := cache.NewSnapshot(strconv.FormatUint(s.version.Add(1), 10), res)
	if err != nil {
		return err
	}
	if err := snap.Consistent(); err != nil {
		return err
	}
	return s.cache.SetSnapshot(ctx, NodeID, snap)
}

// Register adds the ADS and ALS services to g.
func (s *Server) Register(ctx context.Context, g *grpc.Server) {
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(g, server.NewServer(ctx, s.cache, server.CallbackFuncs{}))
	alsv3.RegisterAccessLogServiceServer(g, s)
}

func (s *Server) StreamAccessLogs(st alsv3.AccessLogService_StreamAccessLogsServer) error {
	for {
		msg, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, e := range msg.GetHttpLogs().GetLogEntry() {
			if d, ok := denial(e); ok && s.OnDenial != nil {
				s.OnDenial(d)
			}
		}
	}
}

// denial classifies by response code: RBAC local replies carry no response
// flags (spike S5).
func denial(e *accesslogdatav3.HTTPAccessLogEntry) (Denial, bool) {
	if e.GetResponse().GetResponseCode().GetValue() != 403 {
		return Denial{}, false
	}
	ip := e.GetCommonProperties().GetDownstreamDirectRemoteAddress().GetSocketAddress().GetAddress()
	host, port := strings.ToLower(e.GetRequest().GetAuthority()), 80
	if h, p, err := net.SplitHostPort(host); err == nil {
		if n, err := strconv.Atoi(p); err == nil {
			host, port = h, n
		}
	}
	if ip == "" || !policy.ValidName(host) {
		return Denial{}, false
	}
	return Denial{SrcIP: ip, Host: host, Port: port}, true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make admin-go ARGS='mod tidy' && make admin-test`
Expected: `ok` for `internal/policy` and `internal/xds`.

- [ ] **Step 5: Write the real-Envoy smoke harness**

`admin/hack/smoke/main.go`:
```go
// Command smoke serves one fixed snapshot to a real Envoy so `make
// admin-smoke` can prove Envoy v1.39.1 accepts what Build renders. Test-only.
package main

import (
	"context"
	"log"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
	"github.com/sgtslaughta/sandcastle/admin/internal/xds"
)

func main() {
	ctx := context.Background()
	s := xds.NewServer()
	s.OnDenial = func(d xds.Denial) { log.Printf("DENIAL src=%s host=%s port=%d", d.SrcIP, d.Host, d.Port) }
	res, err := xds.Build(xds.Params{
		Hosts:      map[policy.HostKey][]string{{Host: "example.com", Port: 443}: {os.Getenv("ALLOW_IP")}},
		RequestURL: "http://admin.invalid/r",
		TunnelMax:  time.Hour,
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := s.Push(ctx, res); err != nil {
		log.Fatal(err)
	}
	g := grpc.NewServer()
	s.Register(ctx, g)
	l, err := net.Listen("tcp", ":18000")
	if err != nil {
		log.Fatal(err)
	}
	log.Print("xds ready")
	log.Fatal(g.Serve(l))
}
```

`admin/hack/smoke/bootstrap.yaml` has the same shape as the production bootstrap (Task 13) but targets the smoke admin IP:
```yaml
node: {id: sandcastle-egress, cluster: sandcastle-egress}
bootstrap_extensions:
  - name: envoy.bootstrap.internal_listener
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.bootstrap.internal_listener.v3.InternalListener
admin:
  address: {socket_address: {address: 0.0.0.0, port_value: 9901}}
dynamic_resources:
  ads_config:
    api_type: GRPC
    transport_api_version: V3
    grpc_services: [{envoy_grpc: {cluster_name: admin}}]
  lds_config: {ads: {}, resource_api_version: V3}
  cds_config: {ads: {}, resource_api_version: V3}
static_resources:
  clusters:
    - name: admin
      type: STATIC
      connect_timeout: 2s
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config: {http2_protocol_options: {}}
      load_assignment:
        cluster_name: admin
        endpoints:
          - lb_endpoints:
              - endpoint: {address: {socket_address: {address: 172.31.0.20, port_value: 18000}}}
```

`admin/hack/smoke.sh`:
```bash
#!/usr/bin/env bash
# Real Envoy v1.39.1 against Build's output: allowed IP gets 200, other IP
# gets 403 with header and request link, and the denial reaches ALS.
# Throwaway containers on a private network; host needs docker + internet.
set -euo pipefail
cd "$(dirname "$0")/.."
NET=sc-smoke; CACHE="$HOME/.cache/sandcastle-go"; mkdir -p "$CACHE"
fail=0; ok() { echo "  ok    $1"; }; bad() { echo "  FAIL  $1"; fail=1; }
cleanup() { docker rm -f sc-smoke-admin sc-smoke-envoy sc-smoke-a sc-smoke-b >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker network create --subnet 172.31.0.0/24 $NET >/dev/null

docker run -d --name sc-smoke-admin --network $NET --ip 172.31.0.20 -u "$(id -u):$(id -g)" \
  -e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod -e ALLOW_IP=172.31.0.11 \
  -v "$CACHE:/cache" -v "$PWD:/src" -w /src golang:1.27 go run ./hack/smoke >/dev/null
for c in a:11 b:12; do
  docker run -d --name sc-smoke-${c%%:*} --network $NET --ip 172.31.0.${c##*:} alpine:3 sleep infinity >/dev/null
  docker exec sc-smoke-${c%%:*} apk add --no-cache curl >/dev/null
done
for _ in $(seq 60); do docker logs sc-smoke-admin 2>&1 | grep 'xds ready' >/dev/null && break; sleep 3; done
docker run -d --name sc-smoke-envoy --network $NET --ip 172.31.0.10 -v "$PWD/hack/smoke:/etc/envoy:ro" \
  envoyproxy/envoy:v1.39.1 -c /etc/envoy/bootstrap.yaml --drain-time-s 5 --drain-strategy immediate >/dev/null

px=http://172.31.0.10:3128
code=000
for _ in $(seq 30); do
  code=$(docker exec sc-smoke-a curl -s -o /dev/null -w '%{http_code}' -m 10 -x $px https://example.com || true)
  [[ "$code" == 200 ]] && break; sleep 2
done
[[ "$code" == 200 ]] && ok "allowed IP reaches example.com (200)" || bad "allowed IP got '$code'"

out=$(docker exec sc-smoke-b curl -si -m 10 -x $px http://example.com || true)
echo "$out" | grep -i '^x-sandcastle-denied: host=example.com; source=172.31.0.12' >/dev/null && ok "other IP denied with header" || bad "other IP: no denial header"
echo "$out" | grep 'Request access: http://admin.invalid/r?src=172.31.0.12&host=example.com' >/dev/null && ok "403 body carries request link" || bad "403 body missing request link"
code=$(docker exec sc-smoke-b curl -s -o /dev/null -w '%{http_code}' -m 10 -x $px https://example.com || true)
[[ "$code" == 000 || "$code" == 403 ]] && ok "other IP CONNECT refused" || bad "other IP CONNECT got '$code'"

sleep 2
docker logs sc-smoke-admin 2>&1 | grep 'DENIAL src=172.31.0.12 host=example.com' >/dev/null && ok "ALS delivered denial" || bad "ALS denial not received"
docker logs sc-smoke-envoy 2>&1 | grep -iE 'rejected|NACK' >/dev/null && bad "envoy rejected config: $(docker logs sc-smoke-envoy 2>&1 | grep -iE 'rejected|NACK' | head -2)" || ok "envoy accepted all xDS resources"

(( fail == 0 )) && echo "smoke passed" || { echo "smoke FAILED"; exit 1; }
```

Append to `Makefile`:
```make
admin-smoke: ## real envoy v1.39.1 accepts sandcastle-admin xds (docker)
	admin/hack/smoke.sh
```

- [ ] **Step 6: Run the smoke test**

Run: `chmod +x admin/hack/smoke.sh && make admin-smoke`
Expected: 6 `ok` lines, then `smoke passed`.
If Envoy rejects a resource, `docker logs sc-smoke-envoy` names the field.
Fix it in `build.go`, re-run `make admin-test` and `make admin-smoke`, and
record the fix in the report. (`curl -x` with `https://` sends an HTTP/1.1
CONNECT. Do not use `openssl s_client -proxy`: it sends HTTP/1.0 and gets
426, per spike results.)

- [ ] **Step 7: Commit**

```bash
git add admin/internal/xds/server.go admin/internal/xds/server_test.go admin/hack Makefile admin/go.mod admin/go.sum
git commit -m "feat(admin): serve xds snapshots and receive envoy denials"
```
