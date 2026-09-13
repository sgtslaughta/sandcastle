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
