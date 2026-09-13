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
