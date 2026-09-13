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
