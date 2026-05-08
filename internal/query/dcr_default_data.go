package query

import (
	"context"
	"database/sql"
	"errors"

	sq "github.com/Masterminds/squirrel"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// DCRDefaultProjectInfo is the projection-side existence + state snapshot
// of a project referenced as `OIDC.DCR.DefaultProjectID`. The split
// between Exists and Active lets callers (boot validation in
// cmd/start/start.go and per-request defense in
// commands.RegisterClient) emit precise error messages distinguishing
// "configured ID does not exist" from "configured ID exists but is
// deactivated".
//
// See cavekit-dcr-bootstrap-validation.md R4 + R5.
type DCRDefaultProjectInfo struct {
	Exists        bool
	Active        bool
	ResourceOwner string
	State         domain.ProjectState
}

// DCRDefaultOrgInfo mirrors DCRDefaultProjectInfo for the
// `OIDC.DCR.DefaultOrgID` lookup against projections.orgs1.
//
// See cavekit-dcr-bootstrap-validation.md R4 + R5.
type DCRDefaultOrgInfo struct {
	Exists bool
	Active bool
	State  domain.OrgState
}

// DCRDefaultProjectByID is a thin existence-only lookup against
// projections.projects4 for the configured anonymous-DCR
// DefaultProjectID. It loads only the columns needed for the boot
// + per-request validation contract (id presence, state, resource
// owner) — no full *Project hydration.
//
// Returns DCRDefaultProjectInfo{Exists: false} (no error) when the row
// is absent. The caller decides whether absence is fatal — at boot it
// is, in-request it is. Other database errors propagate.
//
// Why this lives next to the consumer rather than as a method on Project:
// the bug pattern motivating this helper (cavekit-dcr-bootstrap-validation
// R4) is "configured DefaultProjectID points to a row that does not exist
// in the projection /authorize JOINs through." The helper must hit the
// SAME projection (projections.projects4) /authorize traverses, not the
// eventstore — otherwise an event-vs-projection lag could mask the bug
// the helper is meant to catch.
func (q *Queries) DCRDefaultProjectByID(ctx context.Context, id string) (info DCRDefaultProjectInfo, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	stmt, scan := prepareDCRDefaultProjectQuery()
	eq := sq.Eq{
		ProjectColumnID.identifier():         id,
		ProjectColumnInstanceID.identifier(): authz.GetInstance(ctx).InstanceID(),
	}
	query, args, err := stmt.Where(eq).ToSql()
	if err != nil {
		return DCRDefaultProjectInfo{}, zerrors.ThrowInternal(err, "QUERY-dcrPj0", "Errors.Query.SQLStatement")
	}

	err = q.client.QueryRowContext(ctx, func(row *sql.Row) error {
		info, err = scan(row)
		return err
	}, query, args...)
	return info, err
}

// DCRDefaultOrgByID is the org-side counterpart to
// [Queries.DCRDefaultProjectByID]. It hits projections.orgs1 directly
// (rather than the eventstore-backed OrgByID) because the bug it
// guards against is a missing-from-projection failure mode.
//
// Returns DCRDefaultOrgInfo{Exists: false} (no error) when the row is
// absent.
func (q *Queries) DCRDefaultOrgByID(ctx context.Context, id string) (info DCRDefaultOrgInfo, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	stmt, scan := prepareDCRDefaultOrgQuery()
	eq := sq.Eq{
		OrgColumnID.identifier():         id,
		OrgColumnInstanceID.identifier(): authz.GetInstance(ctx).InstanceID(),
	}
	query, args, err := stmt.Where(eq).ToSql()
	if err != nil {
		return DCRDefaultOrgInfo{}, zerrors.ThrowInternal(err, "QUERY-dcrOg0", "Errors.Query.SQLStatement")
	}

	err = q.client.QueryRowContext(ctx, func(row *sql.Row) error {
		info, err = scan(row)
		return err
	}, query, args...)
	return info, err
}

func prepareDCRDefaultProjectQuery() (sq.SelectBuilder, func(*sql.Row) (DCRDefaultProjectInfo, error)) {
	return sq.Select(
			ProjectColumnState.identifier(),
			ProjectColumnResourceOwner.identifier(),
		).
			From(projectsTable.identifier()).
			PlaceholderFormat(sq.Dollar),
		func(row *sql.Row) (DCRDefaultProjectInfo, error) {
			var (
				state         domain.ProjectState
				resourceOwner string
			)
			err := row.Scan(&state, &resourceOwner)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return DCRDefaultProjectInfo{Exists: false}, nil
				}
				return DCRDefaultProjectInfo{}, zerrors.ThrowInternal(err, "QUERY-dcrPj1", "Errors.Internal")
			}
			return DCRDefaultProjectInfo{
				Exists:        true,
				Active:        state == domain.ProjectStateActive,
				ResourceOwner: resourceOwner,
				State:         state,
			}, nil
		}
}

func prepareDCRDefaultOrgQuery() (sq.SelectBuilder, func(*sql.Row) (DCRDefaultOrgInfo, error)) {
	return sq.Select(
			OrgColumnState.identifier(),
		).
			From(orgsTable.identifier()).
			PlaceholderFormat(sq.Dollar),
		func(row *sql.Row) (DCRDefaultOrgInfo, error) {
			var state domain.OrgState
			err := row.Scan(&state)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return DCRDefaultOrgInfo{Exists: false}, nil
				}
				return DCRDefaultOrgInfo{}, zerrors.ThrowInternal(err, "QUERY-dcrOg1", "Errors.Internal")
			}
			return DCRDefaultOrgInfo{
				Exists: true,
				Active: state == domain.OrgStateActive,
				State:  state,
			}, nil
		}
}
