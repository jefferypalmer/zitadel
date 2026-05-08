package query

import (
	"context"
	"database/sql"
	"errors"

	sq "github.com/Masterminds/squirrel"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// AppNameExistsInProject returns true when an application with name
// `appName` already exists under `projectID` in the current instance.
// Thin existence-only probe — no full *App hydration.
//
// The eventstore enforces a unique-constraint on
// (instance_id, project_id, app_name) at push time, returning
// SQLSTATE 23505 on collision; the projection mirrors that
// uniqueness. This helper lets callers detect a collision BEFORE the
// push so they can either pick a different name (auto-suffix) or
// return a clean RFC 7591 error envelope to the client. Without the
// pre-push probe the eventstore violation surfaces as a 500 in the
// register handler — see cavekit-dcr-bootstrap-validation.md R8.
func (q *Queries) AppNameExistsInProject(ctx context.Context, projectID, appName string) (exists bool, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	stmt, scan := prepareAppNameExistsQuery()
	eq := sq.Eq{
		AppColumnProjectID.identifier():  projectID,
		AppColumnName.identifier():       appName,
		AppColumnInstanceID.identifier(): authz.GetInstance(ctx).InstanceID(),
	}
	query, args, err := stmt.Where(eq).ToSql()
	if err != nil {
		return false, zerrors.ThrowInternal(err, "QUERY-appN0", "Errors.Query.SQLStatement")
	}

	err = q.client.QueryRowContext(ctx, func(row *sql.Row) error {
		exists, err = scan(row)
		return err
	}, query, args...)
	return exists, err
}

func prepareAppNameExistsQuery() (sq.SelectBuilder, func(*sql.Row) (bool, error)) {
	// SELECT 1 ... LIMIT 1 — cheaper than COUNT(*).
	return sq.Select("1").
			From(appsTable.identifier()).
			Limit(1).
			PlaceholderFormat(sq.Dollar),
		func(row *sql.Row) (bool, error) {
			var one int
			err := row.Scan(&one)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return false, nil
				}
				return false, zerrors.ThrowInternal(err, "QUERY-appN1", "Errors.Internal")
			}
			return true, nil
		}
}
