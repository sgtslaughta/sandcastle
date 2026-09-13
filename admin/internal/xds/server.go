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
