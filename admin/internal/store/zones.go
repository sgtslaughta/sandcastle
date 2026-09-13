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
