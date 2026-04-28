package query

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/query/projection"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// SoftwareStatementJTIRecorded distinguishes a successful first-time
// insert from a duplicate-violation. Callers in T-030 use the
// duplicate-violation result to emit the `Replay` error envelope per
// cavekit-software-statement.md R9.
type SoftwareStatementJTIRecorded int

const (
	JTIInserted    SoftwareStatementJTIRecorded = 1
	JTIAlreadySeen SoftwareStatementJTIRecorded = 2
)

// pgUniqueViolationCode is Postgres SQLSTATE 23505. We pin it locally
// rather than depend on a SQLSTATE constant package because the
// project keeps DB-driver knowledge concentrated at the database/
// boundary.
const pgUniqueViolationCode = "23505"

// RecordSoftwareStatementJTI INSERTs a (instance_id, iss, jti, created_at,
// expires_at) tuple into projections.dcr_software_statement_jtis1.
// Returns JTIInserted on a fresh insert, JTIAlreadySeen on a structural
// unique-violation. Any other error propagates.
//
// cavekit-software-statement.md R9 requires this to be a structural
// unique-violation, NOT a SELECT-then-INSERT race. The PRIMARY KEY
// (instance_id, iss, jti) does the work — Postgres serializes the
// constraint check inside the INSERT transaction.
//
// `expiresAt` is the absolute timestamp after which the janitor may
// reap this row (kit: `software_statement.exp + JTIRetentionBuffer`).
// Caller computes that — this function does not extend or apply skew.
func (q *Queries) RecordSoftwareStatementJTI(
	ctx context.Context,
	iss, jti string,
	createdAt, expiresAt time.Time,
) (_ SoftwareStatementJTIRecorded, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	const stmt = `INSERT INTO projections.dcr_software_statement_jtis1
		(instance_id, software_statement_iss, software_statement_jti, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`

	_, err = q.client.DB.ExecContext(ctx, stmt,
		authz.GetInstance(ctx).InstanceID(), iss, jti, createdAt, expiresAt)
	if err == nil {
		return JTIInserted, nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolationCode {
		return JTIAlreadySeen, nil
	}
	return 0, zerrors.ThrowInternal(err, "QUERY-JTI01", "Errors.Internal")
}

// ReapExpiredSoftwareStatementJTIs DELETEs every row with
// `expires_at < now`. Returns the rows-affected count. Intended to be
// called from a janitor cron (matches the Phase 1 IAT exhausted-slot
// reap pattern). Cheap on an empty table; the index on `expires_at`
// guarantees this is O(reaped-rows) not O(table-size).
func (q *Queries) ReapExpiredSoftwareStatementJTIs(ctx context.Context, now time.Time) (rows int64, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	const stmt = `DELETE FROM projections.dcr_software_statement_jtis1
		WHERE expires_at < $1`
	res, execErr := q.client.DB.ExecContext(ctx, stmt, now)
	if execErr != nil {
		return 0, zerrors.ThrowInternal(execErr, "QUERY-JTI02", "Errors.Internal")
	}
	rows, err = res.RowsAffected()
	if err != nil {
		return 0, zerrors.ThrowInternal(err, "QUERY-JTI03", "Errors.Internal")
	}
	return rows, nil
}

// Compile-time link to the projection so dead-code linters keep the
// projection registration honest — if the projection name changes,
// callers of this query helper will fail to build.
var _ = projection.DCRSoftwareStatementJTITable
