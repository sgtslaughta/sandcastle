package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
)

type Request struct {
	ID, WorkspaceID, Host                       string
	Port                                        int
	Justification, Requester, Status, DecidedBy string
	CreatedAt                                   time.Time
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
