package query

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"time"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/domain"
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

// DCRGetMetadata is the projected view of one DCR-registered
// application's full metadata surface for the RFC 7592 GET handler
// (cavekit-manage-handler.md R4 / T-053). Carries everything the
// response body needs that is NOT already on the dispatcher's
// resolved [dcr.ManageContext].
//
// Field types match the projection columns: enum int arrays for
// grant_types/response_types/auth_method_type/application_type
// (the dcr-side adapter converts these back to RFC 7591 wire strings
// via the [domain.RFC7591*Strings] helpers). DCRMeta is the raw
// JSONB blob stamped at registration time (T-041); the response
// writer unpacks it into the RFC 7591 §2 pass-through fields.
type DCRGetMetadata struct {
	AppID             string                                  `json:"app_id"`
	ClientName        string                                  `json:"client_name,omitempty"`
	ClientIDIssuedAt  time.Time                               `json:"client_id_issued_at"`
	RedirectURIs      database.TextArray[string]              `json:"redirect_uris"`
	GrantTypes        database.NumberArray[domain.OIDCGrantType]    `json:"grant_types"`
	ResponseTypes     database.NumberArray[domain.OIDCResponseType] `json:"response_types"`
	ApplicationType   *domain.OIDCApplicationType             `json:"application_type,omitempty"`
	AuthMethodType    *domain.OIDCAuthMethodType              `json:"auth_method_type,omitempty"`
	DCRMeta           json.RawMessage                         `json:"dcr_meta,omitempty"`
	// JwksInline (cavekit-inline-jwks.md R5 / T-022) carries the
	// canonical sorted-key bytes of the stored inline JWK Set when the
	// row holds one; nil otherwise.
	JwksInline json.RawMessage `json:"jwks_inline,omitempty"`
}

//go:embed dcr_metadata_by_client_id.sql
var dcrMetadataByClientIDQuery string

// DCRMetadataByClientID fetches the full DCR app metadata for the
// RFC 7592 GET handler (cavekit-manage-handler.md R4 / T-053).
//
//   - Cross-instance lookups return ThrowNotFound (instance_id WHERE).
//   - Non-DCR apps return ThrowNotFound (registration_access_token_hash
//     IS NOT NULL filter).
//   - Apps in non-active state return ThrowNotFound (apps7.state = 1).
//
// The caller (dcr.GetClient) bridges ThrowNotFound to a 500 — this
// query is invoked AFTER VerifyRAT succeeds, so a NotFound on this
// path indicates a race between RAT verify and metadata lookup
// (the projection had the RAT row but lost the app between the two
// queries; structurally impossible under normal projection lag).
func (q *Queries) DCRMetadataByClientID(ctx context.Context, clientID string) (meta *DCRGetMetadata, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	meta, err = database.QueryJSONObject[DCRGetMetadata](ctx, q.client, dcrMetadataByClientIDQuery,
		authz.GetInstance(ctx).InstanceID(), clientID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, zerrors.ThrowNotFound(err, "QUERY-DCR03", "Errors.DCR.Client.NotFound")
	}
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "QUERY-DCR04", "Errors.Internal")
	}
	return meta, nil
}
