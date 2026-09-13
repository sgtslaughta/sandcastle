package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
)

// newStore recreates database sc_test, migrates it and opens it as the app
// role. Needs ADMIN_TEST_DSN (owner, database postgres); `make admin-test`
// sets it.
func newStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("ADMIN_TEST_DSN")
	if dsn == "" {
		t.Skip("ADMIN_TEST_DSN not set")
	}
	ctx := context.Background()
	var conn *pgx.Conn
	var err error
	for i := 0; i < 30; i++ { // the postgres image restarts once during init
		if conn, err = pgx.Connect(ctx, dsn); err == nil {
			if err = conn.Ping(ctx); err == nil {
				break
			}
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"DROP DATABASE IF EXISTS sc_test WITH (FORCE)", "CREATE DATABASE sc_test"} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close(ctx)
	u, _ := url.Parse(dsn)
	u.Path = "/sc_test"
	if err := Migrate(ctx, u.String(), "apppw"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, u.String(), "apppw"); err != nil {
		t.Fatalf("migrate is not idempotent: %v", err)
	}
	u.User = url.UserPassword("sandcastle_app", "apppw")
	s, err := Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

const wsA, wsB = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"

func TestSeedAndPolicyInput(t *testing.T) {
	s, ctx := newStore(t), context.Background()
	if err := s.Seed(ctx); err != nil { // second seed is a no-op
		t.Fatal(err)
	}
	in, err := s.PolicyInput(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rules := in.ZoneRules[in.DefaultZone]
	if in.DefaultZone == "" || len(rules) != 2 || rules[0].Value != "example.com" {
		t.Fatalf("seed = %+v", in)
	}
}

func TestZoneLifecycle(t *testing.T) {
	s, ctx := newStore(t), context.Background()
	in, _ := s.PolicyInput(ctx)
	def := in.DefaultZone

	if _, err := s.CreateZone(ctx, "alice", "Bad Name"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad name: %v", err)
	}
	build, err := s.CreateZone(ctx, "alice", "build")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateZone(ctx, "alice", "build"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	if err := s.AddZoneRule(ctx, "alice", build, policy.Rule{Kind: "dns", Value: "*.docker.io"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddZoneRule(ctx, "alice", build, policy.Rule{Kind: "host", Value: "10.0.0.1", Port: 443}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid rule: %v", err)
	}
	clone, err := s.CloneZone(ctx, "alice", build, "build-2")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RenameZone(ctx, "alice", clone, "build-copy"); err != nil {
		t.Fatal(err)
	}
	if err := s.Assign(ctx, "alice", wsA, build); err != nil {
		t.Fatal(err)
	}
	in, _ = s.PolicyInput(ctx)
	if in.Assign[wsA] != build || len(in.ZoneRules[clone]) != 1 || in.ZoneRules[clone][0].Value != "*.docker.io" {
		t.Fatalf("after clone/assign: %+v", in)
	}
	if err := s.DeleteZone(ctx, "alice", build); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete assigned zone: %v", err)
	}
	if err := s.DeleteZone(ctx, "alice", def); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete default zone: %v", err)
	}
	if err := s.Assign(ctx, "alice", wsA, def); err != nil { // back to default removes the row
		t.Fatal(err)
	}
	if err := s.SetDefaultZone(ctx, "alice", clone); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteZone(ctx, "alice", build); err != nil {
		t.Fatal(err)
	}
	zones, err := s.Zones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 || !zones[0].Default || zones[0].Name != "build-copy" {
		t.Fatalf("zones = %+v", zones)
	}
	in, _ = s.PolicyInput(ctx)
	if _, ok := in.Assign[wsA]; ok || in.DefaultZone != clone {
		t.Fatalf("after moves: %+v", in)
	}
}

func TestGrantsExpire(t *testing.T) {
	s, ctx := newStore(t), context.Background()
	if err := s.Grant(ctx, "bob", wsA, policy.Rule{Kind: "host", Value: "pypi.org", Port: 443}, time.Second); err != nil {
		t.Fatal(err)
	}
	in, _ := s.PolicyInput(ctx)
	if len(in.Grants[wsA]) != 1 {
		t.Fatalf("grant missing: %+v", in.Grants)
	}
	time.Sleep(1200 * time.Millisecond)
	in, _ = s.PolicyInput(ctx)
	if len(in.Grants[wsA]) != 0 {
		t.Fatal("expired grant still effective")
	}
	if n, err := s.ExpireGrants(ctx); err != nil || n != 1 {
		t.Fatalf("ExpireGrants = %d, %v", n, err)
	}
	rows, _ := s.Audit(ctx, 10)
	if rows[0].Action != "expire" || !strings.Contains(rows[0].Detail, "pypi.org") {
		t.Fatalf("audit = %+v", rows[0])
	}
}

func TestRequestFlow(t *testing.T) {
	s, ctx := newStore(t), context.Background()
	id, err := s.FileRequest(ctx, "alice", wsA, "pypi.org", 443, "need packages")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := s.FileRequest(ctx, "alice", wsA, "pypi.org", 443, "again")
	if again != id {
		t.Fatal("duplicate pending request created")
	}
	if _, err := s.FileRequest(ctx, "alice", wsA, "*", 443, "x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid host: %v", err)
	}
	if err := s.Decide(ctx, "alice", id, true, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Decide(ctx, "alice", id, false, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("second decision: %v", err)
	}
	in, _ := s.PolicyInput(ctx)
	if len(in.Grants[wsA]) != 1 || in.Grants[wsA][0] != (policy.Rule{Kind: "host", Value: "pypi.org", Port: 443}) {
		t.Fatalf("grants = %+v", in.Grants)
	}
	reqs, _ := s.Requests(ctx, "approved", []string{wsA})
	if len(reqs) != 1 || reqs[0].DecidedBy != "alice" {
		t.Fatalf("requests = %+v", reqs)
	}
	rows, _ := s.Audit(ctx, 1)
	if rows[0].Action != "approve" || !strings.Contains(rows[0].Detail, `"self_approved": true`) {
		t.Fatalf("audit = %+v", rows[0])
	}
}

func TestDenialsThrottleAndCap(t *testing.T) {
	s, ctx := newStore(t), context.Background()
	for i := 0; i < 3; i++ {
		if err := s.RecordDenial(ctx, wsB, "github.com", 443); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := s.Denials(ctx, []string{wsB})
	if len(d) != 1 || d[0].Count != 1 {
		t.Fatalf("throttle: %+v", d)
	}
	for i := 0; i < 205; i++ {
		if err := s.RecordDenial(ctx, wsB, fmt.Sprintf("h%d.example.com", i), 443); err != nil {
			t.Fatal(err)
		}
	}
	if d, _ = s.Denials(ctx, []string{wsB}); len(d) != 200 {
		t.Fatalf("cap: %d rows", len(d))
	}
}

func TestAuditIsAppendOnly(t *testing.T) {
	s, ctx := newStore(t), context.Background()
	if _, err := s.pool.Exec(ctx, "UPDATE audit SET actor = 'mallory'"); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("UPDATE audit as app role: %v", err)
	}
	if _, err := s.pool.Exec(ctx, "DELETE FROM audit"); err == nil {
		t.Fatal("DELETE audit as app role succeeded")
	}
}
