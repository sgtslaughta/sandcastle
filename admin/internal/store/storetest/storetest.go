// Package storetest gives tests in other packages a migrated, seeded store
// on a fresh database. Needs ADMIN_TEST_DSN, set by `make admin-test`.
package storetest

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sgtslaughta/sandcastle/admin/internal/store"
)

func New(t *testing.T, db string) *store.Store {
	t.Helper()
	dsn := os.Getenv("ADMIN_TEST_DSN")
	if dsn == "" {
		t.Skip("ADMIN_TEST_DSN not set")
	}
	ctx := context.Background()
	var conn *pgx.Conn
	var err error
	for i := 0; i < 30; i++ {
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
	for _, q := range []string{"DROP DATABASE IF EXISTS " + db + " WITH (FORCE)", "CREATE DATABASE " + db} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close(ctx)
	u, _ := url.Parse(dsn)
	u.Path = "/" + db
	if err := store.Migrate(ctx, u.String(), "apppw"); err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("sandcastle_app", "apppw")
	s, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}
