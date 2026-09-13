# Phase 4 Build — Task 9: Postgres store (schema, audit, zones, grants, requests, denials)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Plan index, Global Constraints and File Map:** [2026-09-13-phase4-build.md](2026-09-13-phase4-build.md). The Global Constraints apply to this task.

### Task 9: Postgres store (schema, audit, zones, grants, requests, denials)

**Files:**
- Create: `admin/internal/store/migrations/001_init.sql`
- Create: `admin/internal/store/store.go` (migrate, open, seed, audit, policy input)
- Create: `admin/internal/store/zones.go` (zones, rules, assignments, grants, expiry)
- Create: `admin/internal/store/requests.go` (requests, denials)
- Create: `admin/internal/store/store_test.go`
- Modify: `Makefile` (`admin-test` starts a throwaway Postgres)

**Interfaces:**
- Consumes: `policy.Rule`, `policy.Input`, `policy.ValidRule`, `policy.ValidName` (Task 4).
- Produces (used by Tasks 11, 12):
  - `var ErrConflict, ErrInvalid, ErrNotFound error`
  - `func Migrate(ctx context.Context, ownerDSN, appPassword string) error`
  - `func Open(ctx context.Context, appDSN string) (*Store, error)`, `func (s *Store) Close()`
  - `func (s *Store) Seed(ctx) error`
  - `func (s *Store) PolicyInput(ctx) (policy.Input, error)` (Pods left empty)
  - `func (s *Store) AuditSystem(ctx, action string, detail map[string]any) error`
  - `func (s *Store) Audit(ctx, limit int) ([]AuditRow, error)`
  - `type RuleRow struct { ID, ZoneID, WorkspaceID, Kind, Value string; Port int; ExpiresAt *time.Time; CreatedBy string }`
  - `type Zone struct { ID, Name string; Default bool; Rules []RuleRow; Members []string }`
  - `Zones`, `CreateZone(ctx, actor, name) (string, error)`, `CloneZone(ctx, actor, srcID, name) (string, error)`, `RenameZone(ctx, actor, id, name) error`, `DeleteZone(ctx, actor, id) error`, `SetDefaultZone(ctx, actor, id) error`, `AddZoneRule(ctx, actor, zoneID string, r policy.Rule) error`, `DeleteRule(ctx, actor, ruleID string) error`, `Assign(ctx, actor, wsID, zoneID string) error`
  - `Grant(ctx, actor, wsID string, r policy.Rule, ttl time.Duration) error`, `Grants(ctx) ([]RuleRow, error)`, `ExpireGrants(ctx) (int, error)`
  - `type Request struct { ID, WorkspaceID, Host string; Port int; Justification, Requester, Status, DecidedBy string; CreatedAt time.Time }`
  - `FileRequest(ctx, actor, wsID, host string, port int, justification string) (string, error)`, `Requests(ctx, status string, wsIDs []string) ([]Request, error)`, `Decide(ctx, actor, id string, approve bool, ttl time.Duration) error`
  - `type Denial struct { WorkspaceID, Host string; Port, Count int; LastSeen time.Time }`
  - `RecordDenial(ctx, wsID, host string, port int) error`, `Denials(ctx, wsIDs []string) ([]Denial, error)`
  - `type AuditRow struct { At time.Time; Actor, Action, Detail string }`

Semantics:
- Assigning a workspace to the current default zone deletes its assignment row ("no row means default").
- `FileRequest` returns the existing ID when the same workspace/host/port is already pending.
- `RecordDenial` updates an existing row at most once per second, and keeps the newest 200 rows per workspace.
- All mutating calls write an audit row in the same transaction.
- The app role cannot UPDATE or DELETE `audit` (spec DR data model).

- [ ] **Step 1: Makefile — `admin-test` starts Postgres**

Replace the `admin-test` target from Task 4 with:
```make
admin-test: ## sandcastle-admin tests with a throwaway postgres (docker)
	@docker network create sc-admin-test >/dev/null 2>&1 || true
	@docker rm -f sc-admin-testdb >/dev/null 2>&1 || true
	@docker run -d --name sc-admin-testdb --network sc-admin-test -e POSTGRES_PASSWORD=test postgres:17.6 >/dev/null
	@$(GO_RUN) go test -p 1 ./...; s=$$?; docker rm -f sc-admin-testdb >/dev/null; exit $$s

# -p 1: store and web tests share one Postgres server and its roles.
admin-test: GO_DOCKER_ARGS = --network sc-admin-test -e ADMIN_TEST_DSN=postgres://postgres:test@sc-admin-testdb:5432/postgres?sslmode=disable
```

- [ ] **Step 2: Write the schema** — `admin/internal/store/migrations/001_init.sql`

```sql
-- sandcastle-admin schema (spec: 2026-09-13-phase4-admin-control-plane-design.md).
-- Runs as the database owner; the app connects as sandcastle_app.

CREATE TABLE zones (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,40}$'),
  is_default boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX zones_one_default ON zones (is_default) WHERE is_default;

CREATE TABLE rules (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  zone_id      uuid REFERENCES zones (id) ON DELETE CASCADE,
  workspace_id uuid,
  kind         text NOT NULL CHECK (kind IN ('host', 'dns')),
  value        text NOT NULL,
  port         int  NOT NULL CHECK ((kind = 'host' AND port IN (80, 443)) OR (kind = 'dns' AND port = 0)),
  expires_at   timestamptz,
  created_by   text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  CHECK ((zone_id IS NULL) <> (workspace_id IS NULL)),
  CHECK (workspace_id IS NULL OR expires_at IS NOT NULL)
);
CREATE UNIQUE INDEX rules_zone_uniq ON rules (zone_id, kind, value, port) WHERE zone_id IS NOT NULL;
CREATE INDEX rules_workspace ON rules (workspace_id) WHERE workspace_id IS NOT NULL;

CREATE TABLE assignments (
  workspace_id uuid PRIMARY KEY,
  zone_id      uuid NOT NULL REFERENCES zones (id),
  assigned_by  text NOT NULL,
  assigned_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE requests (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id  uuid NOT NULL,
  host          text NOT NULL,
  port          int  NOT NULL CHECK (port IN (80, 443)),
  justification text NOT NULL CHECK (length(justification) BETWEEN 1 AND 2000),
  requester     text NOT NULL,
  status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
  decided_by    text,
  ttl           interval,
  created_at    timestamptz NOT NULL DEFAULT now(),
  decided_at    timestamptz
);

CREATE TABLE denials (
  workspace_id uuid NOT NULL,
  host         text NOT NULL,
  port         int  NOT NULL,
  count        int  NOT NULL DEFAULT 1,
  first_seen   timestamptz NOT NULL DEFAULT now(),
  last_seen    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, host, port)
);

CREATE TABLE audit (
  id     bigserial PRIMARY KEY,
  at     timestamptz NOT NULL DEFAULT now(),
  actor  text NOT NULL,
  action text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'
);

DO $$ BEGIN
  CREATE ROLE sandcastle_app LOGIN;
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON zones, rules, assignments, requests, denials TO sandcastle_app;
-- Append-only: the app may read and add audit rows, never change them.
GRANT SELECT, INSERT ON audit TO sandcastle_app;
GRANT USAGE ON SEQUENCE audit_id_seq TO sandcastle_app;
```

- [ ] **Step 3: Write the failing test** — `admin/internal/store/store_test.go`

```go
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
```

- [ ] **Step 4: Run to verify it fails**

Run: `make admin-go ARGS='get github.com/jackc/pgx/v5@v5.11.0' && make admin-test`
Expected: FAIL, `undefined: Migrate` (and friends).

- [ ] **Step 5: Implement** — `admin/internal/store/store.go`

```go
// Package store is sandcastle-admin's Postgres: the only place policy state
// lives. Every mutation writes its audit row in the same transaction.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
)

//go:embed migrations/*.sql
var migrations embed.FS

var (
	ErrConflict = errors.New("conflict")
	ErrInvalid  = errors.New("invalid")
	ErrNotFound = errors.New("not found")
)

type Store struct {
	pool *pgxpool.Pool
}

type AuditRow struct {
	At            time.Time
	Actor, Action string
	Detail        string
}

// Migrate applies pending migrations as the owner and sets the app role's
// password from the deployment secret.
func Migrate(ctx context.Context, ownerDSN, appPassword string) error {
	conn, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY)`); err != nil {
		return err
	}
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, e := range entries {
		var done bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, e.Name()).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		sql, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil { // no args: simple protocol, multi-statement
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, e.Name())
			return err
		}); err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
	}
	// ALTER ROLE takes no bind parameters; quote as a SQL literal.
	_, err = conn.Exec(ctx, "ALTER ROLE sandcastle_app WITH LOGIN PASSWORD '"+strings.ReplaceAll(appPassword, "'", "''")+"'")
	return err
}

func Open(ctx context.Context, appDSN string) (*Store, error) {
	pool, err := pgxpool.New(ctx, appDSN)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Seed creates the default zone with the Phase 3 allowlist on first start.
func (s *Store) Seed(ctx context.Context) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM zones`).Scan(&n); err != nil || n > 0 {
			return err
		}
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO zones (name, is_default) VALUES ('default', true) RETURNING id::text`).Scan(&id); err != nil {
			return err
		}
		for _, port := range []int{443, 80} {
			if _, err := tx.Exec(ctx, `INSERT INTO rules (zone_id, kind, value, port, created_by) VALUES ($1, 'host', 'example.com', $2, 'bootstrap')`, id, port); err != nil {
				return err
			}
		}
		return audit(ctx, tx, "bootstrap", "seed", map[string]any{"zone": id, "hosts": []string{"example.com:443", "example.com:80"}})
	})
}

// PolicyInput loads zones, effective rules and assignments. Expired grants
// are excluded here, so they stop working before the expiry ticker deletes
// them.
func (s *Store) PolicyInput(ctx context.Context) (policy.Input, error) {
	in := policy.Input{ZoneRules: map[string][]policy.Rule{}, Assign: map[string]string{}, Grants: map[string][]policy.Rule{}}
	rows, err := s.pool.Query(ctx, `SELECT id::text, is_default FROM zones`)
	if err != nil {
		return in, err
	}
	for rows.Next() {
		var id string
		var def bool
		if err := rows.Scan(&id, &def); err != nil {
			return in, err
		}
		in.ZoneRules[id] = []policy.Rule{}
		if def {
			in.DefaultZone = id
		}
	}
	if err := rows.Err(); err != nil {
		return in, err
	}
	rows, err = s.pool.Query(ctx, `SELECT coalesce(zone_id::text, ''), coalesce(workspace_id::text, ''), kind, value, port
		FROM rules WHERE expires_at IS NULL OR expires_at > now() ORDER BY kind, value, port`)
	if err != nil {
		return in, err
	}
	for rows.Next() {
		var zone, ws string
		var r policy.Rule
		if err := rows.Scan(&zone, &ws, &r.Kind, &r.Value, &r.Port); err != nil {
			return in, err
		}
		if zone != "" {
			in.ZoneRules[zone] = append(in.ZoneRules[zone], r)
		} else {
			in.Grants[ws] = append(in.Grants[ws], r)
		}
	}
	if err := rows.Err(); err != nil {
		return in, err
	}
	rows, err = s.pool.Query(ctx, `SELECT workspace_id::text, zone_id::text FROM assignments`)
	if err != nil {
		return in, err
	}
	for rows.Next() {
		var ws, zone string
		if err := rows.Scan(&ws, &zone); err != nil {
			return in, err
		}
		in.Assign[ws] = zone
	}
	return in, rows.Err()
}

// AuditSystem records an event with no human actor (reconcile errors).
func (s *Store) AuditSystem(ctx context.Context, action string, detail map[string]any) error {
	return s.tx(ctx, func(tx pgx.Tx) error { return audit(ctx, tx, "system", action, detail) })
}

func (s *Store) Audit(ctx context.Context, limit int) ([]AuditRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT at, actor, action, detail::text FROM audit ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditRow, error) {
		var a AuditRow
		return a, r.Scan(&a.At, &a.Actor, &a.Action, &a.Detail)
	})
}

func (s *Store) tx(ctx context.Context, fn func(pgx.Tx) error) error {
	return mapErr(pgx.BeginFunc(ctx, s.pool, fn))
}

func audit(ctx context.Context, tx pgx.Tx, actor, action string, detail map[string]any) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit (actor, action, detail) VALUES ($1, $2, $3)`, actor, action, detail)
	return err
}

// mapErr turns constraint violations into ErrConflict/ErrInvalid so handlers
// can answer 409/400 without parsing driver errors.
func mapErr(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505", "23503": // unique, foreign key
			return fmt.Errorf("%w: %s", ErrConflict, pg.Message)
		case "23514", "22P02": // check, invalid text (e.g. uuid)
			return fmt.Errorf("%w: %s", ErrInvalid, pg.Message)
		}
	}
	return err
}
```

- [ ] **Step 6: Implement** — `admin/internal/store/zones.go`

```go
package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
)

type RuleRow struct {
	ID, ZoneID, WorkspaceID, Kind, Value string
	Port                                 int
	ExpiresAt                            *time.Time
	CreatedBy                            string
}

type Zone struct {
	ID, Name string
	Default  bool
	Rules    []RuleRow
	Members  []string // assigned workspace IDs (default-zone members are implicit)
}

func scanRule(r pgx.CollectableRow) (RuleRow, error) {
	var x RuleRow
	return x, r.Scan(&x.ID, &x.ZoneID, &x.WorkspaceID, &x.Kind, &x.Value, &x.Port, &x.ExpiresAt, &x.CreatedBy)
}

const ruleCols = `id::text, coalesce(zone_id::text, ''), coalesce(workspace_id::text, ''), kind, value, port, expires_at, created_by`

// Zones lists zones, default first, with rules and explicit members.
func (s *Store) Zones(ctx context.Context) ([]Zone, error) {
	rows, err := s.pool.Query(ctx, `SELECT z.id::text, z.name, z.is_default,
		coalesce(array_agg(a.workspace_id::text) FILTER (WHERE a.workspace_id IS NOT NULL), '{}')
		FROM zones z LEFT JOIN assignments a ON a.zone_id = z.id
		GROUP BY z.id ORDER BY z.is_default DESC, z.name`)
	if err != nil {
		return nil, err
	}
	zones, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Zone, error) {
		var z Zone
		return z, r.Scan(&z.ID, &z.Name, &z.Default, &z.Members)
	})
	if err != nil {
		return nil, err
	}
	rows, err = s.pool.Query(ctx, `SELECT `+ruleCols+` FROM rules WHERE zone_id IS NOT NULL ORDER BY kind, value, port`)
	if err != nil {
		return nil, err
	}
	rules, err := pgx.CollectRows(rows, scanRule)
	if err != nil {
		return nil, err
	}
	for i := range zones {
		for _, r := range rules {
			if r.ZoneID == zones[i].ID {
				zones[i].Rules = append(zones[i].Rules, r)
			}
		}
	}
	return zones, nil
}

func (s *Store) CreateZone(ctx context.Context, actor, name string) (id string, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO zones (name) VALUES ($1) RETURNING id::text`, name).Scan(&id); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "zone_create", map[string]any{"zone": id, "name": name})
	})
	return id, err
}

// CloneZone copies a zone's rules under a new name.
func (s *Store) CloneZone(ctx context.Context, actor, srcID, name string) (id string, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO zones (name) SELECT $1 WHERE EXISTS (SELECT 1 FROM zones WHERE id = $2) RETURNING id::text`, name, srcID).Scan(&id); err != nil {
			if err == pgx.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO rules (zone_id, kind, value, port, created_by)
			SELECT $1, kind, value, port, $2 FROM rules WHERE zone_id = $3`, id, actor, srcID); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "zone_clone", map[string]any{"zone": id, "from": srcID, "name": name})
	})
	return id, err
}

func (s *Store) RenameZone(ctx context.Context, actor, id, name string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if err := one(tx.Exec(ctx, `UPDATE zones SET name = $1 WHERE id = $2`, name, id)); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "zone_rename", map[string]any{"zone": id, "name": name})
	})
}

// DeleteZone refuses the default zone and zones with assigned workspaces.
func (s *Store) DeleteZone(ctx context.Context, actor, id string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var def, assigned bool
		if err := tx.QueryRow(ctx, `SELECT is_default, EXISTS (SELECT 1 FROM assignments WHERE zone_id = $1) FROM zones WHERE id = $1`, id).Scan(&def, &assigned); err != nil {
			if err == pgx.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		if def || assigned {
			return ErrConflict
		}
		if _, err := tx.Exec(ctx, `DELETE FROM zones WHERE id = $1`, id); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "zone_delete", map[string]any{"zone": id})
	})
}

func (s *Store) SetDefaultZone(ctx context.Context, actor, id string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE zones SET is_default = false WHERE is_default`); err != nil {
			return err
		}
		if err := one(tx.Exec(ctx, `UPDATE zones SET is_default = true WHERE id = $1`, id)); err != nil {
			return err
		}
		// Explicit rows pointing at the new default are now redundant.
		if _, err := tx.Exec(ctx, `DELETE FROM assignments WHERE zone_id = $1`, id); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "zone_default", map[string]any{"zone": id})
	})
}

func (s *Store) AddZoneRule(ctx context.Context, actor, zoneID string, r policy.Rule) error {
	if !policy.ValidRule(r) {
		return ErrInvalid
	}
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO rules (zone_id, kind, value, port, created_by) VALUES ($1, $2, $3, $4, $5)`,
			zoneID, r.Kind, r.Value, r.Port, actor); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "rule_add", map[string]any{"zone": zoneID, "kind": r.Kind, "value": r.Value, "port": r.Port})
	})
}

// DeleteRule removes a zone rule or revokes a workspace grant.
func (s *Store) DeleteRule(ctx context.Context, actor, ruleID string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var zone, ws, kind, value string
		var port int
		if err := tx.QueryRow(ctx, `DELETE FROM rules WHERE id = $1 RETURNING coalesce(zone_id::text, ''), coalesce(workspace_id::text, ''), kind, value, port`,
			ruleID).Scan(&zone, &ws, &kind, &value, &port); err != nil {
			if err == pgx.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		return audit(ctx, tx, actor, "rule_delete", map[string]any{"zone": zone, "workspace": ws, "kind": kind, "value": value, "port": port})
	})
}

// Assign moves a workspace to a zone; moving it to the default zone deletes
// the row, so it follows future default changes.
func (s *Store) Assign(ctx context.Context, actor, wsID, zoneID string) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var def bool
		if err := tx.QueryRow(ctx, `SELECT is_default FROM zones WHERE id = $1`, zoneID).Scan(&def); err != nil {
			if err == pgx.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		var err error
		if def {
			_, err = tx.Exec(ctx, `DELETE FROM assignments WHERE workspace_id = $1`, wsID)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO assignments (workspace_id, zone_id, assigned_by) VALUES ($1, $2, $3)
				ON CONFLICT (workspace_id) DO UPDATE SET zone_id = $2, assigned_by = $3, assigned_at = now()`, wsID, zoneID, actor)
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, actor, "assign", map[string]any{"workspace": wsID, "zone": zoneID})
	})
}

func (s *Store) Grant(ctx context.Context, actor, wsID string, r policy.Rule, ttl time.Duration) error {
	return s.tx(ctx, func(tx pgx.Tx) error { return grant(ctx, tx, actor, wsID, r, ttl, nil) })
}

func grant(ctx context.Context, tx pgx.Tx, actor, wsID string, r policy.Rule, ttl time.Duration, extra map[string]any) error {
	if !policy.ValidRule(r) || ttl <= 0 {
		return ErrInvalid
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rules (workspace_id, kind, value, port, expires_at, created_by)
		VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5), $6)`, wsID, r.Kind, r.Value, r.Port, ttl.Seconds(), actor); err != nil {
		return err
	}
	detail := map[string]any{"workspace": wsID, "kind": r.Kind, "value": r.Value, "port": r.Port, "ttl": ttl.String()}
	action := "grant"
	for k, v := range extra {
		detail[k] = v
		action = "approve"
	}
	return audit(ctx, tx, actor, action, detail)
}

// Grants lists unexpired workspace grants.
func (s *Store) Grants(ctx context.Context) ([]RuleRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+ruleCols+` FROM rules WHERE workspace_id IS NOT NULL AND expires_at > now() ORDER BY workspace_id, value`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanRule)
}

// ExpireGrants deletes expired grants and audits each one.
func (s *Store) ExpireGrants(ctx context.Context) (n int, err error) {
	err = s.tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `DELETE FROM rules WHERE workspace_id IS NOT NULL AND expires_at <= now()
			RETURNING `+ruleCols)
		if err != nil {
			return err
		}
		gone, err := pgx.CollectRows(rows, scanRule)
		if err != nil {
			return err
		}
		for _, r := range gone {
			if err := audit(ctx, tx, "system", "expire", map[string]any{"workspace": r.WorkspaceID, "kind": r.Kind, "value": r.Value, "port": r.Port}); err != nil {
				return err
			}
		}
		n = len(gone)
		return nil
	})
	return n, err
}

func one(tag interface{ RowsAffected() int64 }, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
```

Note: `one` receives `pgconn.CommandTag`, which has `RowsAffected()`. Go allows `one(tx.Exec(...))` because `Exec` returns exactly `(pgconn.CommandTag, error)`.

- [ ] **Step 7: Implement** — `admin/internal/store/requests.go`

```go
package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
)

type Request struct {
	ID, WorkspaceID, Host                          string
	Port                                           int
	Justification, Requester, Status, DecidedBy    string
	CreatedAt                                      time.Time
}

type Denial struct {
	WorkspaceID, Host string
	Port, Count       int
	LastSeen          time.Time
}

// FileRequest records a pending request, or returns the ID of an identical
// pending one.
func (s *Store) FileRequest(ctx context.Context, actor, wsID, host string, port int, justification string) (id string, err error) {
	if !policy.ValidRule(policy.Rule{Kind: "host", Value: host, Port: port}) {
		return "", ErrInvalid
	}
	err = s.tx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id::text FROM requests WHERE workspace_id = $1 AND host = $2 AND port = $3 AND status = 'pending'`,
			wsID, host, port).Scan(&id)
		if err != pgx.ErrNoRows {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO requests (workspace_id, host, port, justification, requester) VALUES ($1, $2, $3, $4, $5) RETURNING id::text`,
			wsID, host, port, justification, actor).Scan(&id); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "request", map[string]any{"request": id, "workspace": wsID, "host": host, "port": port})
	})
	return id, err
}

// Requests lists newest first. Empty status means all; nil wsIDs means all.
func (s *Store) Requests(ctx context.Context, status string, wsIDs []string) ([]Request, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text, workspace_id::text, host, port, justification, requester, status, coalesce(decided_by, ''), created_at
		FROM requests WHERE ($1 = '' OR status = $1) AND ($2::uuid[] IS NULL OR workspace_id = ANY($2))
		ORDER BY created_at DESC LIMIT 200`, status, wsIDs)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Request, error) {
		var q Request
		return q, r.Scan(&q.ID, &q.WorkspaceID, &q.Host, &q.Port, &q.Justification, &q.Requester, &q.Status, &q.DecidedBy, &q.CreatedAt)
	})
}

// Decide approves (inserting a workspace grant) or denies a pending request.
func (s *Store) Decide(ctx context.Context, actor, id string, approve bool, ttl time.Duration) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var ws, host, requester string
		var port int
		status := "denied"
		if approve {
			status = "approved"
		}
		err := tx.QueryRow(ctx, `UPDATE requests SET status = $1, decided_by = $2, decided_at = now(), ttl = CASE WHEN $3 THEN make_interval(secs => $4) END
			WHERE id = $5 AND status = 'pending' RETURNING workspace_id::text, host, port, requester`,
			status, actor, approve, ttl.Seconds(), id).Scan(&ws, &host, &port, &requester)
		if err == pgx.ErrNoRows {
			return ErrConflict // unknown or already decided
		}
		if err != nil {
			return err
		}
		extra := map[string]any{"request": id, "self_approved": actor == requester}
		if !approve {
			return audit(ctx, tx, actor, "deny", extra)
		}
		return grant(ctx, tx, actor, ws, policy.Rule{Kind: "host", Value: host, Port: port}, ttl, extra)
	})
}

// RecordDenial upserts a denial. Updates are throttled to once per second per
// key and each workspace keeps its newest 200 rows, so a flooding agent
// cannot grow the table or bury other workspaces' denials.
func (s *Store) RecordDenial(ctx context.Context, wsID, host string, port int) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO denials (workspace_id, host, port) VALUES ($1, $2, $3)
			ON CONFLICT (workspace_id, host, port) DO UPDATE SET count = denials.count + 1, last_seen = now()
			WHERE denials.last_seen < now() - interval '1 second'`, wsID, host, port); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM denials WHERE workspace_id = $1 AND (host, port) IN (
			SELECT host, port FROM denials WHERE workspace_id = $1 ORDER BY last_seen DESC, host OFFSET 200)`, wsID)
		return err
	})
}

func (s *Store) Denials(ctx context.Context, wsIDs []string) ([]Denial, error) {
	rows, err := s.pool.Query(ctx, `SELECT workspace_id::text, host, port, count, last_seen FROM denials
		WHERE ($1::uuid[] IS NULL OR workspace_id = ANY($1)) ORDER BY last_seen DESC LIMIT 200`, wsIDs)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Denial, error) {
		var d Denial
		return d, r.Scan(&d.WorkspaceID, &d.Host, &d.Port, &d.Count, &d.LastSeen)
	})
}
```

Denials are not audited: they are Envoy events, not policy changes, and auditing them would let an agent flood the audit log.

- [ ] **Step 8: Run tests to verify they pass**

Run: `make admin-go ARGS='mod tidy' && make admin-test`
Expected: `ok` for `internal/store` and every earlier package (not `skipped`: the Makefile sets `ADMIN_TEST_DSN`).
If `TestDenialsThrottleAndCap` flakes on the 200-row cap because many rows
share a `last_seen` timestamp, the `ORDER BY last_seen DESC, host` tiebreak
is required. Keep it.

- [ ] **Step 9: Commit**

```bash
git add Makefile admin/internal/store admin/go.mod admin/go.sum
git commit -m "feat(admin): add postgres store with append-only audit"
```
