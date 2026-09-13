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
