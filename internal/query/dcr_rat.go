package query

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"time"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// DCRRATLookup is the projected view of one DCR-registered application's
// Registration Access Token (RAT) verification surface
// (cavekit-manage-handler.md R2 / T-051). Carries everything the
// manage handlers need to verify a presented Bearer and route the
// resulting silent-rehash / rotated event to the correct project +
// app aggregate.
//
// Field names + json tags match the SQL column aliases one-to-one so
// the `row_to_json(...)` SELECT decodes via [database.QueryJSONObject].
type DCRRATLookup struct {
	AppID         string     `json:"app_id"`
	ProjectID     string     `json:"project_id"`
	ResourceOwner string     `json:"resource_owner"`
	TokenHash     string     `json:"token_hash"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

//go:embed dcr_rat_lookup_by_client_id.sql
var dcrRATLookupByClientIDQuery string

// DCRRATLookupByClientID fetches the RAT verification surface for one
// DCR-registered application, scoped to the caller's instance.
//
//   - Cross-instance lookups return zerrors.ThrowNotFound — the WHERE
//     clause filters by authz.GetInstance(ctx).InstanceID().
//   - Apps that were not created via DCR (no RAT hash on the row)
//     return ThrowNotFound — the column predicate
//     `registration_access_token_hash IS NOT NULL` excludes them so
//     the legacy projects-app surface stays opaque to the manage path.
//   - The caller (cavekit-manage-handler.md R2 / T-051 VerifyRAT) MUST
//     bridge ThrowNotFound to the same 401 invalid_token envelope
//     used for wrong-RAT failures so the missing-row branch does not
//     leak existence information about valid client_ids
//     (cavekit-manage-handler.md R3 / T-052 layers the dummy-Verify
//     anti-enumeration on top of this).
func (q *Queries) DCRRATLookupByClientID(ctx context.Context, clientID string) (lookup *DCRRATLookup, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	lookup, err = database.QueryJSONObject[DCRRATLookup](ctx, q.client, dcrRATLookupByClientIDQuery,
		authz.GetInstance(ctx).InstanceID(), clientID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, zerrors.ThrowNotFound(err, "QUERY-DCR01", "Errors.DCR.Client.NotFound")
	}
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "QUERY-DCR02", "Errors.Internal")
	}
	return lookup, nil
}
