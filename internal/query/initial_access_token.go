package query

import (
	"context"
	_ "embed"
	"errors"
	"time"

	"database/sql"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// InitialAccessToken is the projected view of one IAT row. Field
// names + json tags match the projection columns one-to-one so the
// `row_to_json(...)` SELECT on the SQL side decodes cleanly into this
// struct via [database.QueryJSONObject] (matches the OIDCClient pattern
// at internal/query/oidc_client.go).
//
// The consume command (cavekit-iat.md R2 / T-017) reads this row on
// every retry; the registration handler (cavekit-register-handler.md
// R3 / T-037) reads it via InitialAccessTokenByHash to verify a
// Bearer-presented IAT.
type InitialAccessToken struct {
	ID                         string                       `json:"id"`
	InstanceID                 string                       `json:"instance_id"`
	ResourceOwner              string                       `json:"resource_owner"`
	ProjectID                  string                       `json:"project_id"`
	TokenHash                  string                       `json:"token_hash"`
	ExpiresAt                  *time.Time                   `json:"expires_at,omitempty"`
	MaxUses                    int64                        `json:"max_uses"`
	UsesConsumed               int64                        `json:"uses_consumed"`
	ConsumedSlots              database.NumberArray[int16]  `json:"consumed_slots"`
	AllowedGrantTypes          database.TextArray[string]   `json:"allowed_grant_types"`
	AllowedRedirectURIPatterns database.TextArray[string]   `json:"allowed_redirect_uri_patterns"`
	Revoked                    bool                         `json:"revoked"`
	CreatedAt                  time.Time                    `json:"created_at"`
	ChangeDate                 time.Time                    `json:"change_date"`
	Sequence                   uint64                       `json:"sequence"`
}

//go:embed initial_access_token_by_id.sql
var initialAccessTokenByIDQuery string

//go:embed initial_access_token_by_hash.sql
var initialAccessTokenByHashQuery string

//go:embed initial_access_tokens_search.sql
var initialAccessTokensSearchQuery string

// InitialAccessTokenByID looks up an IAT by its ID, scoped to the
// caller's instance and (optionally) resource owner.
//
//   - Cross-instance lookups return sql.ErrNoRows (translated to
//     zerrors.ThrowNotFound) — the WHERE clause filters by
//     authz.GetInstance(ctx).InstanceID().
//   - Pass resourceOwner=="" to skip the org-level scope (admin paths);
//     pass a non-empty value to enforce cross-org isolation.
//   - The returned row reflects the latest projection state. The
//     consume command (T-017) calls Trigger before invoking this if
//     it needs a guaranteed-fresh read.
func (q *Queries) InitialAccessTokenByID(ctx context.Context, id, resourceOwner string) (iat *InitialAccessToken, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	iat, err = database.QueryJSONObject[InitialAccessToken](ctx, q.client, initialAccessTokenByIDQuery,
		authz.GetInstance(ctx).InstanceID(), id, resourceOwner,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, zerrors.ThrowNotFound(err, "QUERY-IAT01", "Errors.DCR.IAT.NotFound")
	}
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "QUERY-IAT02", "Errors.Internal")
	}
	return iat, nil
}

// SearchInitialAccessTokens lists IAT rows for the caller's instance
// optionally narrowed by projectID (empty = all projects). Plaintext
// is never available in the projection, so the result is structurally
// safe for the admin gRPC ListInitialAccessTokens RPC (T-023).
//
// Sorted newest-first by created_at. Pagination is not yet wired —
// the kit (R6) declares the proto carries a ListQuery for future
// pagination, but the current admin UI surface returns a single page.
func (q *Queries) SearchInitialAccessTokens(ctx context.Context, projectID string) (iats []*InitialAccessToken, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	list, err := database.QueryJSONObject[[]*InitialAccessToken](ctx, q.client, initialAccessTokensSearchQuery,
		authz.GetInstance(ctx).InstanceID(), projectID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "QUERY-IAT05", "Errors.Internal")
	}
	if list == nil {
		return nil, nil
	}
	return *list, nil
}

// InitialAccessTokenByHash looks up an IAT by its Passwap-encoded
// token hash, scoped to the caller's instance. Used by the
// registration handler's IAT verification path (cavekit-register-handler.md
// R3 / T-037): the handler hashes the presented plaintext token then
// calls this lookup. Cross-instance IATs return not-found.
//
// Note: the hash IS the encoded Passwap string, NOT a raw byte digest.
// Verification of a presented plaintext against this hash uses
// passwap.Hasher.Verify (see T-037 + T-051) — the lookup is just an
// indexed retrieval.
func (q *Queries) InitialAccessTokenByHash(ctx context.Context, tokenHash string) (iat *InitialAccessToken, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	iat, err = database.QueryJSONObject[InitialAccessToken](ctx, q.client, initialAccessTokenByHashQuery,
		authz.GetInstance(ctx).InstanceID(), tokenHash,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, zerrors.ThrowNotFound(err, "QUERY-IAT03", "Errors.DCR.IAT.NotFound")
	}
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "QUERY-IAT04", "Errors.Internal")
	}
	return iat, nil
}
