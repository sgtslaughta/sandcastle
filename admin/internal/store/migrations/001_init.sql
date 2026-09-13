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
