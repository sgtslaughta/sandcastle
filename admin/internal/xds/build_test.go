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
		{Host: "example.com", Port: 443}:  {"10.42.0.8", "10.42.0.9"},
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

// Envoy picks the exact vhost over the wildcard one, so the exact vhost must
// also admit everyone the wildcard zone admits.
func TestExactVhostKeepsWildcardIPs(t *testing.T) {
	hosts := policy.HostIPs(policy.Input{
		DefaultZone: "z",
		ZoneRules:   map[string][]policy.Rule{"z": {{Kind: "host", Value: "*.github.com", Port: 443}}},
		Grants:      map[string][]policy.Rule{"ws-a": {{Kind: "host", Value: "api.github.com", Port: 443}}},
		Pods:        []policy.Workspace{{ID: "ws-a", IP: "10.42.0.1"}, {ID: "ws-b", IP: "10.42.0.2"}},
	})
	res, err := Build(params(hosts))
	if err != nil {
		t.Fatal(err)
	}
	for _, vh := range res[resource.RouteType][0].(*routev3.RouteConfiguration).GetVirtualHosts() {
		if len(vh.GetDomains()) == 1 && vh.GetDomains()[0] == "api.github.com:443" {
			b, _ := protojson.Marshal(vh)
			for _, ip := range []string{"10.42.0.1", "10.42.0.2"} {
				if !strings.Contains(string(b), `"addressPrefix":"`+ip+`"`) {
					t.Errorf("exact vhost RBAC missing %s: %s", ip, b)
				}
			}
			return
		}
	}
	t.Fatal("no api.github.com:443 vhost")
}
