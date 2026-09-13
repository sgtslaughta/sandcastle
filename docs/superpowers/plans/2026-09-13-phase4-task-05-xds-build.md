# Phase 4 Build — Task 5: xDS resource builder

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Plan index, Global Constraints and File Map:** [2026-09-13-phase4-build.md](2026-09-13-phase4-build.md). The Global Constraints apply to this task.

### Task 5: xDS resource builder

**Files:**
- Create: `admin/internal/xds/build.go`, `admin/internal/xds/build_test.go`

**Interfaces:**
- Consumes: `policy.HostKey`.
- Produces (used by Tasks 6, 12):
  - `const NodeID = "sandcastle-egress"`, `const RouteName = "egress"`
  - `type Params struct { Hosts map[policy.HostKey][]string; RequestURL string; TunnelMax time.Duration }`
  - `func Build(p Params) (map[resource.Type][]types.Resource, error)`

Design notes for the implementer:
- Resources are written as Go maps mirroring the Envoy YAML proven in the spikes, then marshaled to JSON and decoded with `protojson` into typed protos. `json.Marshal` sorts map keys, so output is deterministic.
- The `proxy` listener must be **identical** in every build. If it changed, Envoy would replace it and drain every workspace's connections. Only routes, `sni_*` listeners, and `sni_*` clusters vary.
- `sni_<hash>` names hash (host, port, IP set). Any change to who may reach a host renames its listener, which closes that host's open tunnels (S3).

- [ ] **Step 1: Write the failing test** — `admin/internal/xds/build_test.go`

```go
package xds

import (
	"strings"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
)

func params(hosts map[policy.HostKey][]string) Params {
	return Params{Hosts: hosts, RequestURL: "http://192.168.122.124:30081/r", TunnelMax: time.Hour}
}

func listeners(t *testing.T, p Params) map[string]*listenerv3.Listener {
	t.Helper()
	res, err := Build(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.NewSnapshot("1", res); err != nil {
		t.Fatal(err)
	}
	out := map[string]*listenerv3.Listener{}
	for _, r := range res[resource.ListenerType] {
		l := r.(*listenerv3.Listener)
		out[l.GetName()] = l
	}
	return out
}

func routeJSON(t *testing.T, p Params) string {
	t.Helper()
	res, err := Build(p)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res[resource.RouteType]); n != 1 {
		t.Fatalf("want 1 route config, got %d", n)
	}
	b, _ := protojson.Marshal(res[resource.RouteType][0].(*routev3.RouteConfiguration))
	return string(b)
}

func TestEmptyIsDenyOnly(t *testing.T) {
	ls := listeners(t, params(nil))
	if len(ls) != 1 || ls["proxy"] == nil {
		t.Fatalf("want only proxy listener, got %v", ls)
	}
	rj := routeJSON(t, params(nil))
	if !strings.Contains(rj, `"name":"deny"`) || strings.Contains(rj, "h_") {
		t.Fatalf("route should hold only the deny vhost: %s", rj)
	}
}

func TestSnapshotConsistent(t *testing.T) {
	res, err := Build(params(map[policy.HostKey][]string{
		{Host: "example.com", Port: 443}: {"10.42.0.9"},
		{Host: "example.org", Port: 80}:  {"10.42.0.7"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := cache.NewSnapshot("1", res)
	if err != nil {
		t.Fatal(err)
	}
	if err := snap.Consistent(); err != nil {
		t.Fatalf("snapshot inconsistent: %v", err)
	}
}

func TestHostsRenderRBACAndSNIBinding(t *testing.T) {
	p := params(map[policy.HostKey][]string{
		{Host: "example.com", Port: 443}:   {"10.42.0.8", "10.42.0.9"},
		{Host: "*.example.org", Port: 80}: {"10.42.0.7"},
	})
	ls := listeners(t, p)
	var sni *listenerv3.Listener
	for name, l := range ls {
		if strings.HasPrefix(name, "sni_") {
			sni = l
		}
	}
	if len(ls) != 2 || sni == nil {
		t.Fatalf("want proxy + one sni listener (port 80 needs none), got %d", len(ls))
	}
	if got := sni.GetFilterChains()[0].GetFilterChainMatch().GetServerNames(); len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("sni listener server_names = %v", got)
	}
	rj := routeJSON(t, p)
	for _, want := range []string{
		`"example.com:443"`, `"*.example.org"`, `"*.example.org:80"`,
		`"addressPrefix":"10.42.0.8"`, `"addressPrefix":"10.42.0.9"`, `"addressPrefix":"10.42.0.7"`,
		`"maxStreamDuration":"3600s"`, `"cluster":"` + sni.GetName() + `"`,
	} {
		if !strings.Contains(rj, want) {
			t.Errorf("route JSON missing %s", want)
		}
	}
}

func TestProxyListenerStableAndNamesTrackIPs(t *testing.T) {
	a := listeners(t, params(map[policy.HostKey][]string{
		{Host: "example.com", Port: 443}: {"10.42.0.9"},
		{Host: "example.org", Port: 443}: {"10.42.0.9"},
	}))
	b := listeners(t, params(map[policy.HostKey][]string{
		{Host: "example.com", Port: 443}: {"10.42.0.9", "10.42.0.10"},
		{Host: "example.org", Port: 443}: {"10.42.0.9"},
	}))
	if !proto.Equal(a["proxy"], b["proxy"]) {
		t.Fatal("proxy listener changed between builds; Envoy would drain every connection")
	}
	same, changed := 0, 0
	for name := range a {
		if name == "proxy" {
			continue
		}
		if b[name] != nil {
			same++
		} else {
			changed++
		}
	}
	if same != 1 || changed != 1 {
		t.Fatalf("want example.org listener kept and example.com renamed, got same=%d changed=%d", same, changed)
	}
}

func TestDenyBodyCarriesRequestLink(t *testing.T) {
	b, _ := protojson.Marshal(listeners(t, params(nil))["proxy"])
	for _, want := range []string{"x-sandcastle-denied", "http://192.168.122.124:30081/r?src=%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%", `"logName":"egress"`, `"clusterName":"admin"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("proxy listener missing %s", want)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `make admin-go ARGS='get github.com/envoyproxy/go-control-plane@v0.14.0 github.com/envoyproxy/go-control-plane/envoy@v1.39.0 google.golang.org/protobuf' && make admin-test`
Expected: FAIL, `undefined: Build` / `undefined: Params`.

- [ ] **Step 3: Implement** — `admin/internal/xds/build.go`

```go
// Package xds builds and serves the Envoy egress configuration.
//
// Resources are written as maps that mirror the Envoy YAML proven in the
// Phase 4 spikes, then decoded with protojson into typed protos. The proxy
// listener is identical in every build, so pushes never drain it; only
// routes and per-host sni_* listeners and clusters change.
package xds

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	// typed_config messages, resolved by protojson from the global registry.
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
)

const (
	NodeID    = "sandcastle-egress" // Envoy bootstrap node.id
	RouteName = "egress"
)

// Params is the input for one snapshot.
type Params struct {
	Hosts      map[policy.HostKey][]string // host:port -> allowed pod IPs
	RequestURL string                      // e.g. http://192.168.122.124:30081/r; must not contain '%'
	TunnelMax  time.Duration               // CONNECT tunnel cap (DR-4.10)
}

type obj = map[string]any

// Build renders the full resource set for Params.
func Build(p Params) (map[resource.Type][]types.Resource, error) {
	if strings.Contains(p.RequestURL, "%") {
		return nil, fmt.Errorf("request URL must not contain %%")
	}
	keys := make([]policy.HostKey, 0, len(p.Hosts))
	for k := range p.Hosts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Host != keys[j].Host {
			return keys[i].Host < keys[j].Host
		}
		return keys[i].Port < keys[j].Port
	})

	listeners := []obj{proxyListener(p.RequestURL)}
	clusters := []obj{dfpCluster("dfp_http"), dfpCluster("dfp_sni")}
	var vhosts []obj
	for _, k := range keys {
		ips := p.Hosts[k]
		hash := hashName(k, ips)
		perRoute := obj{"envoy.filters.http.rbac": rbacPerRoute(ips)}
		if k.Port == 443 {
			sni := "sni_" + hash
			vhosts = append(vhosts, obj{
				"name": "h_" + hash, "domains": []string{k.Host + ":443"}, "typed_per_filter_config": perRoute,
				"routes": []obj{{
					"match": obj{"connect_matcher": obj{}},
					"route": obj{
						"cluster":             sni,
						"max_stream_duration": obj{"max_stream_duration": fmt.Sprintf("%ds", int(p.TunnelMax.Seconds()))},
						"upgrade_configs":     []obj{{"upgrade_type": "CONNECT", "connect_config": obj{}}},
					},
				}},
			})
			clusters = append(clusters, obj{
				"name": sni,
				"load_assignment": obj{"cluster_name": sni, "endpoints": []obj{{"lb_endpoints": []obj{{
					"endpoint": obj{"address": obj{"envoy_internal_address": obj{"server_listener_name": sni}}},
				}}}}},
			})
			listeners = append(listeners, sniListener(sni, k.Host))
			continue
		}
		vhosts = append(vhosts, obj{
			"name": "h_" + hash, "domains": []string{k.Host, k.Host + ":80"}, "typed_per_filter_config": perRoute,
			"routes": []obj{{"match": obj{"prefix": "/"}, "route": obj{"cluster": "dfp_http"}}},
		})
	}
	// No per-route RBAC override here: the base RBAC filter denies, and the
	// local reply mapper adds the header and request link.
	vhosts = append(vhosts, obj{"name": "deny", "domains": []string{"*"}, "routes": []obj{
		{"match": obj{"connect_matcher": obj{}}, "direct_response": obj{"status": 403}},
		{"match": obj{"prefix": "/"}, "direct_response": obj{"status": 403}},
	}})

	out := map[resource.Type][]types.Resource{}
	for _, l := range listeners {
		m := &listenerv3.Listener{}
		if err := decode(l, m); err != nil {
			return nil, fmt.Errorf("listener %v: %w", l["name"], err)
		}
		out[resource.ListenerType] = append(out[resource.ListenerType], m)
	}
	for _, c := range clusters {
		m := &clusterv3.Cluster{}
		if err := decode(c, m); err != nil {
			return nil, fmt.Errorf("cluster %v: %w", c["name"], err)
		}
		out[resource.ClusterType] = append(out[resource.ClusterType], m)
	}
	rc := &routev3.RouteConfiguration{}
	if err := decode(obj{"name": RouteName, "virtual_hosts": vhosts}, rc); err != nil {
		return nil, fmt.Errorf("route: %w", err)
	}
	out[resource.RouteType] = []types.Resource{rc}
	return out, nil
}

func decode(v obj, m proto.Message) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := protojson.Unmarshal(b, m); err != nil {
		return err
	}
	if val, ok := m.(interface{ ValidateAll() error }); ok {
		return val.ValidateAll()
	}
	return nil
}

func typed(t string, fields obj) obj {
	fields["@type"] = "type.googleapis.com/" + t
	return fields
}

func hashName(k policy.HostKey, ips []string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s", k.Host, k.Port, strings.Join(ips, ","))))
	return hex.EncodeToString(h[:5])
}

func dnsCache() obj { return obj{"name": "dfp", "dns_lookup_family": "V4_ONLY"} }

func rbacPerRoute(ips []string) obj {
	principals := make([]obj, len(ips))
	for i, ip := range ips {
		principals[i] = obj{"direct_remote_ip": obj{"address_prefix": ip, "prefix_len": 32}}
	}
	return typed("envoy.extensions.filters.http.rbac.v3.RBACPerRoute", obj{"rbac": obj{"rules": obj{
		"action":   "ALLOW",
		"policies": obj{"workspaces": obj{"permissions": []obj{{"any": true}}, "principals": principals}},
	}}})
}

func dfpCluster(name string) obj {
	return obj{"name": name, "lb_policy": "CLUSTER_PROVIDED", "cluster_type": obj{
		"name":         "envoy.clusters.dynamic_forward_proxy",
		"typed_config": typed("envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig", obj{"dns_cache_config": dnsCache()}),
	}}
}

func proxyListener(requestURL string) obj {
	body := "sandcastle: egress to %REQ(:AUTHORITY)% is not allowed for this workspace.\n" +
		"Request access: " + requestURL + "?src=%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%&host=%REQ(:AUTHORITY)%\n"
	hcm := typed("envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", obj{
		"stat_prefix":     "egress",
		"upgrade_configs": []obj{{"upgrade_type": "CONNECT"}},
		"rds":             obj{"route_config_name": RouteName, "config_source": obj{"ads": obj{}, "resource_api_version": "V3"}},
		"access_log": []obj{
			{"name": "envoy.access_loggers.stdout", "typed_config": typed("envoy.extensions.access_loggers.stream.v3.StdoutAccessLog", obj{
				"log_format": obj{"json_format": obj{
					"time": "%START_TIME%", "src": "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%", "method": "%REQ(:METHOD)%",
					"authority": "%REQ(:AUTHORITY)%", "code": "%RESPONSE_CODE%", "flags": "%RESPONSE_FLAGS%",
					"bytes_up": "%BYTES_RECEIVED%", "bytes_down": "%BYTES_SENT%",
				}},
			})},
			{"name": "envoy.access_loggers.http_grpc", "typed_config": typed("envoy.extensions.access_loggers.grpc.v3.HttpGrpcAccessLogConfig", obj{
				"common_config": obj{"log_name": "egress", "transport_api_version": "V3", "grpc_service": obj{"envoy_grpc": obj{"cluster_name": "admin"}}},
			})},
		},
		"local_reply_config": obj{"mappers": []obj{{
			"filter":               obj{"status_code_filter": obj{"comparison": obj{"op": "EQ", "value": obj{"default_value": 403, "runtime_key": "sandcastle.deny"}}}},
			"headers_to_add":       []obj{{"header": obj{"key": "x-sandcastle-denied", "value": "host=%REQ(:AUTHORITY)%; source=%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"}}},
			"body_format_override": obj{"text_format_source": obj{"inline_string": body}},
		}}},
		"http_filters": []obj{
			{"name": "envoy.filters.http.rbac", "typed_config": typed("envoy.extensions.filters.http.rbac.v3.RBAC", obj{"rules": obj{"action": "ALLOW"}})},
			{"name": "envoy.filters.http.dynamic_forward_proxy", "typed_config": typed("envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig", obj{"dns_cache_config": dnsCache()})},
			{"name": "envoy.filters.http.router", "typed_config": typed("envoy.extensions.filters.http.router.v3.Router", obj{})},
		},
	})
	return obj{
		"name":          "proxy",
		"address":       obj{"socket_address": obj{"address": "0.0.0.0", "port_value": 3128}},
		"filter_chains": []obj{{"filters": []obj{{"name": "envoy.filters.network.http_connection_manager", "typed_config": hcm}}}},
	}
}

// sniListener is stage 2: it accepts only a TLS handshake whose SNI is the
// host this listener was built for (spike S2), then dials that SNI.
func sniListener(name, host string) obj {
	return obj{
		"name":              name,
		"internal_listener": obj{},
		"listener_filters": []obj{{"name": "envoy.filters.listener.tls_inspector",
			"typed_config": typed("envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector", obj{})}},
		"filter_chains": []obj{{
			"filter_chain_match": obj{"server_names": []string{host}},
			"filters": []obj{
				{"name": "envoy.filters.network.sni_dynamic_forward_proxy", "typed_config": typed(
					"envoy.extensions.filters.network.sni_dynamic_forward_proxy.v3.FilterConfig", obj{"port_value": 443, "dns_cache_config": dnsCache()})},
				{"name": "envoy.filters.network.tcp_proxy", "typed_config": typed(
					"envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", obj{"stat_prefix": name, "cluster": "dfp_sni"})},
			},
		}},
		// Stage 2 refusals close before any HTTP response; flags NR marks them.
		"access_log": []obj{{"name": "envoy.access_loggers.stdout", "typed_config": typed(
			"envoy.extensions.access_loggers.stream.v3.StdoutAccessLog", obj{"log_format": obj{"json_format": obj{
				"time": "%START_TIME%", "stage": "sni", "sni": "%REQUESTED_SERVER_NAME%", "flags": "%RESPONSE_FLAGS%",
				"bytes_up": "%BYTES_RECEIVED%", "bytes_down": "%BYTES_SENT%",
			}}})}},
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make admin-go ARGS='mod tidy' && make admin-test`
Expected: `ok` for `internal/policy` and `internal/xds`.
If protojson rejects a field, the error names it. Fix the map key to the
proto field name (snake_case) and note the fix in the report. Do not change
what the config means.

- [ ] **Step 5: Commit**

```bash
git add admin/go.mod admin/go.sum admin/internal/xds
git commit -m "feat(admin): build per-workspace envoy xds resources"
```
