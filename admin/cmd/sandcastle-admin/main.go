// Command sandcastle-admin serves the admin UI (:8080) and Envoy xDS + ALS
// (:18000). All policy state lives in Postgres; every change, pod event,
// expiry and a one-minute resync rebuild the full Envoy snapshot and the
// Cilium DNS policies from it.
//
// "sandcastle-admin migrate" applies schema migrations as the Postgres owner
// and exits; it runs as an initContainer so the long-running server never
// holds the owner DSN.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/sgtslaughta/sandcastle/admin/internal/auth"
	"github.com/sgtslaughta/sandcastle/admin/internal/cilium"
	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
	"github.com/sgtslaughta/sandcastle/admin/internal/store"
	"github.com/sgtslaughta/sandcastle/admin/internal/watch"
	"github.com/sgtslaughta/sandcastle/admin/internal/web"
	"github.com/sgtslaughta/sandcastle/admin/internal/xds"
)

const tunnelMax = time.Hour // DR-4.10

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	run := serve
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		run = migrate
	}
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func env(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s is required", k)
	}
	return v
}

func migrate(ctx context.Context) error {
	if err := store.Migrate(ctx, env("DB_OWNER_DSN"), env("DB_APP_PASSWORD")); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func serve(ctx context.Context) error {
	st, err := store.Open(ctx, env("DB_APP_DSN"))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if err := st.Seed(ctx); err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	key, err := hex.DecodeString(env("SESSION_KEY"))
	if err != nil {
		return fmt.Errorf("SESSION_KEY: %w", err)
	}
	publicURL := env("PUBLIC_URL")
	au, err := auth.New(auth.Config{
		CoderURL: env("CODER_URL"), CoderInternalURL: env("CODER_INTERNAL_URL"),
		ClientID: env("OAUTH_CLIENT_ID"), ClientSecret: env("OAUTH_CLIENT_SECRET"),
		CallbackURL: publicURL + "/callback", Key: key, TestToken: os.Getenv("TEST_TOKEN"),
	})
	if err != nil {
		return err
	}
	if os.Getenv("TEST_TOKEN") != "" {
		log.Print("WARNING: test hook enabled (TEST_TOKEN set); disable outside the lab")
	}

	kcfg, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	cs, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		return err
	}
	dyn, err := dynamic.NewForConfig(kcfg)
	if err != nil {
		return err
	}

	changed := make(chan struct{}, 1)
	notify := func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	pods, err := watch.Start(ctx, cs, notify)
	if err != nil {
		return err
	}

	xs := xds.NewServer()
	xs.OnDenial = func(d xds.Denial) {
		ws, ok := pods.ByIP(d.SrcIP)
		if !ok {
			return
		}
		if err := st.RecordDenial(ctx, ws.ID, d.Host, d.Port); err != nil {
			log.Printf("record denial: %v", err)
		}
	}
	g := grpc.NewServer()
	xs.Register(ctx, g)
	lis, err := net.Listen("tcp", ":18000")
	if err != nil {
		return err
	}
	go func() {
		if err := g.Serve(lis); err != nil {
			log.Printf("grpc: %v", err)
		}
	}()

	srv := &http.Server{Addr: ":8080", ReadHeaderTimeout: 10 * time.Second,
		Handler: (&web.Server{Store: st, Auth: au, Pods: pods, Changed: notify}).Routes()}
	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http: %v", err)
		}
	}()

	lastErr := ""
	reconcile := func() {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		err := apply(rctx, st, pods, xs, dyn, publicURL)
		msg := ""
		if err != nil {
			msg = err.Error()
			log.Printf("reconcile: %v", err)
			if msg != lastErr { // audit each distinct failure once, not every retry
				if aerr := st.AuditSystem(rctx, "reconcile_error", map[string]any{"error": msg}); aerr != nil {
					log.Printf("audit: %v", aerr)
				}
			}
		}
		lastErr = msg
	}

	notify()
	expiry, resync := time.NewTicker(30*time.Second), time.NewTicker(time.Minute)
	defer expiry.Stop()
	defer resync.Stop()
	for {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			srv.Shutdown(sctx)
			g.Stop()
			return nil
		case <-changed:
			time.Sleep(200 * time.Millisecond) // coalesce bursts of pod events
			select {
			case <-changed:
			default:
			}
			reconcile()
		case <-resync.C:
			reconcile()
		case <-expiry.C:
			ectx, cancel := context.WithTimeout(ctx, 30*time.Second) // a hung DB must not stall rebuilds
			n, err := st.ExpireGrants(ectx)
			cancel()
			if err != nil {
				log.Printf("expire: %v", err)
			} else if n > 0 {
				notify()
			}
		}
	}
}

// apply pushes Envoy first, then Cilium: a revocation must not wait on the
// kube API. If loading fails nothing is pushed and Envoy keeps its last
// snapshot (DR-4.6).
func apply(ctx context.Context, st *store.Store, pods *watch.Pods, xs *xds.Server, dyn dynamic.Interface, publicURL string) error {
	in, err := st.PolicyInput(ctx)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	in.Pods = pods.Running()
	res, err := xds.Build(xds.Params{Hosts: policy.HostIPs(in), RequestURL: publicURL + "/r", TunnelMax: tunnelMax})
	if err != nil {
		return fmt.Errorf("build xds: %w", err)
	}
	if err := xs.Push(ctx, res); err != nil {
		return fmt.Errorf("push xds: %w", err)
	}
	if err := cilium.Apply(ctx, dyn, cilium.Render(in)); err != nil {
		return fmt.Errorf("apply cilium: %w", err)
	}
	return nil
}
