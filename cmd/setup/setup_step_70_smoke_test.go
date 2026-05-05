package setup

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestSetupStep70_AppliesAgainstEmbeddedPostgres is the in-process smoke
// test for cavekit-software-statement.md R9 / cavekit-eventstore-
// framework-guard.md R3. It boots an embedded Postgres, applies the
// step-70 SQL (the application-managed projections.dcr_software_statement_jtis1
// table introduced by T-002), then asserts:
//
//  1. No panic from any framework-guard path during the migration apply.
//  2. The table has the kit-mandated PRIMARY KEY (instance_id, iss, jti).
//  3. The expires_at index exists (precondition for the janitor reaper
//     written in T-011 to be cheap).
//  4. The migration is idempotent — re-applying it is a no-op.
//
// Closest in-session approximation of T-021's Postgres-boot sub-case
// (a) fresh empty Postgres + (b) upgrade-simulation Postgres. Embedded
// Postgres takes ~5s to start; the test is gated by `-short` so it
// stays out of the fast inner loop. CI runs without `-short` and
// exercises this path on every PR.
func TestSetupStep70_AppliesAgainstEmbeddedPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("embedded postgres takes ~5s to boot; skipping in -short mode")
	}

	port := freeTCPPort(t)
	runtimePath, err := os.MkdirTemp("", "zitadel-setup-step-70-smoke-*")
	if err != nil {
		t.Fatalf("mktempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimePath) })

	embedded := embeddedpostgres.NewDatabase(
		embeddedpostgres.DefaultConfig().
			Version(embeddedpostgres.V17).
			Port(uint32(port)).
			RuntimePath(runtimePath),
	)
	if err := embedded.Start(); err != nil {
		t.Fatalf("embedded start: %v", err)
	}
	t.Cleanup(func() { _ = embedded.Stop() })

	// DefaultConfig user/pass/db are all "postgres".
	dsn := fmt.Sprintf("host=localhost port=%d user=postgres password=postgres dbname=postgres sslmode=disable", port)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	if _, err := db.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS projections"); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	// First apply — the step-70 SQL.
	if _, err := db.ExecContext(ctx, dcrSoftwareStatementJTIs); err != nil {
		t.Fatalf("apply step 70: %v", err)
	}

	// Idempotency — second apply is a no-op (IF NOT EXISTS clauses).
	if _, err := db.ExecContext(ctx, dcrSoftwareStatementJTIs); err != nil {
		t.Fatalf("re-apply step 70 must be a no-op: %v", err)
	}

	// Primary key shape. cavekit-software-statement.md R9: PRIMARY KEY
	// (instance_id, iss, jti). The structural unique-violation that
	// drives the replay-dedupe (T-030) only works if these exact three
	// columns are part of the PK in this exact order.
	rows, err := db.QueryContext(ctx, `
		SELECT a.attname
		FROM   pg_index i
		JOIN   pg_class c ON c.oid = i.indrelid
		JOIN   pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
		WHERE  c.relname = 'dcr_software_statement_jtis1'
		AND    i.indisprimary
		ORDER BY array_position(i.indkey, a.attnum)
	`)
	if err != nil {
		t.Fatalf("query pk: %v", err)
	}
	defer rows.Close()
	var pkCols []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatalf("scan pk col: %v", err)
		}
		pkCols = append(pkCols, col)
	}
	want := []string{"instance_id", "software_statement_iss", "software_statement_jti"}
	if len(pkCols) != len(want) {
		t.Fatalf("pk columns: got %v, want %v", pkCols, want)
	}
	for i, c := range want {
		if pkCols[i] != c {
			t.Fatalf("pk col[%d]: got %q, want %q (full got=%v want=%v)", i, pkCols[i], c, pkCols, want)
		}
	}

	// Index on expires_at. T-011's janitor reaper relies on this index
	// to keep `DELETE WHERE expires_at < now()` cheap on a populated
	// table.
	var hasExpiresIdx bool
	err = db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE schemaname = 'projections'
			AND   tablename = 'dcr_software_statement_jtis1'
			AND   indexname = 'dcr_software_statement_jtis1_expires_at_idx'
		)
	`).Scan(&hasExpiresIdx)
	if err != nil {
		t.Fatalf("query expires_at idx: %v", err)
	}
	if !hasExpiresIdx {
		t.Fatal("expires_at index missing — janitor reap would be O(table-size) instead of O(reaped-rows)")
	}
}

// freeTCPPort grabs an OS-assigned TCP port and immediately releases
// it. There is a race window between the close and the embedded
// Postgres bind; for a single-test single-process invocation this is
// good enough — the same trick is used in internal/database/postgres/embedded.go.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}
