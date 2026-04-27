package dcr

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/zitadel/zitadel/internal/zerrors"
)

// ManageQueries is the projection-read seam the RFC 7592 manage path
// (cavekit-manage-handler.md R2 / T-051) needs from query.Queries.
// Defined as an interface so unit tests can stub it without spinning
// up the full DB harness, mirroring the [IATLookupQueries] pattern.
type ManageQueries interface {
	DCRRATLookupByClientID(ctx context.Context, clientID string) (*ManageRATRow, error)
}

// ManageRATRow mirrors the subset of [query.DCRRATLookup] the manage
// auth path consumes. Defined as a local alias-shaped struct so this
// package does not have to import the full query package — same
// layering pattern as [QueryIATRow] for the IAT auth path.
//
// TokenHash is the Passwap-encoded RAT hash. ExpiresAt is nil when no
// expiry is configured (RAT.Lifetime=0); otherwise the timestamp the
// RAT becomes invalid. AppID + ProjectID + ResourceOwner route the
// silent-rehash event to the correct project aggregate.
type ManageRATRow struct {
	AppID         string
	ProjectID     string
	ResourceOwner string
	TokenHash     string
	ExpiresAt     *time.Time
}

// RATVerifier is the verification + silent-rehash seam. The manage
// path calls Verify(stored, presented) and uses the (updatedHash,
// err) return shape of passwap.Swapper.Verify. When updatedHash != ""
// the configured Passwap algorithm rotated since the RAT was last
// stored and the manage handler MUST persist the new encoded form via
// [Rehasher.RehashRegistrationAccessToken].
type RATVerifier interface {
	Verify(encoded, presented string) (updated string, err error)
}

// Rehasher is the function-shaped seam for invoking
// `command.Commands.RehashRegistrationAccessToken` from inside the dcr
// package without a direct command-package import. Production wires
// this to a closure that calls the command method; tests stub it.
//
// The closure receives the project + org + app identifiers resolved
// via [ManageQueries.DCRRATLookupByClientID] so the rehashed event is
// pushed onto the correct aggregate. orgID is the project's resource
// owner — RFC 7592 RAT-only requests carry no user CtxData, so the
// manage path passes the org explicitly rather than reading it from
// the request ctx.
type Rehasher func(ctx context.Context, projectID, orgID, appID, newEncodedHash string) error

// ManageContext is the post-verification handle the GET/PUT/DELETE
// bodies (T-053/T-054/T-056) consume. Carries the {client_id, app_id,
// project_id, resource_owner} resolution + a flag indicating whether
// a silent rehash event was already pushed (so a downstream handler
// that pushes its own RAT.set/.rotated event can sequence accordingly).
type ManageContext struct {
	ClientID      string
	AppID         string
	ProjectID     string
	ResourceOwner string
	Rehashed      bool
}

// ManageDeps is the dependency surface the RFC 7592 manage handlers
// consume at startup, mirroring [RegistrationDeps] for the register
// path. Injected once via [NewHandler].
//
// Every field is required when DCR is configured for RAT-authenticated
// management. The legacy [Handler] keeps the bearer-presence-only gate
// for migration coverage; production traffic flows through [NewHandler]
// with the full deps set.
type ManageDeps struct {
	Queries     ManageQueries
	RATVerifier RATVerifier
	Rehasher    Rehasher
	// AntiEnumDummyHash is the precomputed dummy Passwap hash used by
	// the manage path when [ManageQueries.DCRRATLookupByClientID]
	// returns NotFound, so the unknown-client_id branch pays the same
	// Verify cost as the wrong-RAT branch (cavekit-manage-handler.md
	// R3 / T-052 layers this on top of the lookup-then-verify flow
	// the present task wires). Reusing the same dummy hash the IAT
	// auth path uses keeps the algorithm prefix consistent with the
	// configured passwap.Swapper.
	AntiEnumDummyHash string
}

// Validate enforces non-nil/non-empty deps at boot. Called by
// [NewHandler] (extended in T-051) so a misconfigured wiring fails
// fast rather than 5xxing for the lifetime of the process.
func (d ManageDeps) Validate() error {
	if d.Queries == nil {
		return errors.New("dcr: ManageDeps.Queries is required")
	}
	if d.RATVerifier == nil {
		return errors.New("dcr: ManageDeps.RATVerifier is required")
	}
	if d.Rehasher == nil {
		return errors.New("dcr: ManageDeps.Rehasher is required")
	}
	if d.AntiEnumDummyHash == "" {
		return errors.New("dcr: ManageDeps.AntiEnumDummyHash is required (build via BuildAntiEnumDummyHash)")
	}
	return nil
}

// VerifyRAT implements cavekit-manage-handler.md R2 (T-051):
//
//  1. Look up the client_id row via the projection (instance-scoped
//     by the SQL WHERE).
//  2. NotFound → dummy-Verify (timing equivalence with wrong-RAT) +
//     401 invalid_token. The dummy-Verify pre-pays the cost the
//     known-client-id wrong-RAT branch will pay; structural anti-
//     enumeration tests for the timing distinguishability live in
//     T-052 and T-058.
//  3. Verify presented Bearer against stored Passwap hash via the
//     configured Swapper's two-return form. Mismatch → 401.
//  4. updatedHash != "" → push the silent-rehash event via
//     [Rehasher]. Failure to persist the rehash is logged but does
//     NOT fail the verification — the operator gets the rotated
//     algorithm on the NEXT verify. (Same trade-off the OIDC
//     client-secret silent-rehash makes at
//     internal/api/oidc/client.go:256-258.)
//  5. Lifetime > 0 → check expiry against ExpiresAt. Expired → 401.
//
// All 401 paths return *ClampError (Code=invalid_token); the manage
// dispatcher writes the WWW-Authenticate header on top via
// [writeAuthError] (already present from the register path / N-5).
func VerifyRAT(
	ctx context.Context,
	deps ManageDeps,
	clientID, presented string,
) (*ManageContext, error) {
	row, err := deps.Queries.DCRRATLookupByClientID(ctx, clientID)
	if err != nil {
		// Pay the Verify cost so unknown-client_id and wrong-RAT
		// timings match (R3 / T-052 layers this dummy-Verify into a
		// cross-handler structural test).
		_, _ = deps.RATVerifier.Verify(deps.AntiEnumDummyHash, presented)
		return nil, &ClampError{
			Status:      http.StatusUnauthorized,
			Code:        ErrCodeInvalidToken,
			Description: MissingOrInvalidAccessTokenDescription,
			Wrapped:     zerrors.ThrowInvalidArgument(err, "DCR-Mn001", "Errors.DCR.Client.NotFound"),
		}
	}

	updatedHash, vErr := deps.RATVerifier.Verify(row.TokenHash, presented)
	if vErr != nil {
		return nil, &ClampError{
			Status:      http.StatusUnauthorized,
			Code:        ErrCodeInvalidToken,
			Description: MissingOrInvalidAccessTokenDescription,
			Wrapped:     zerrors.ThrowInvalidArgument(vErr, "DCR-Mn002", "Errors.DCR.RAT.Invalid"),
		}
	}

	rehashed := false
	if updatedHash != "" {
		// Silent rehash. Best-effort push — failure does not invalidate
		// the verification (the operator gets the rotated form on the
		// next verify). The error is intentionally swallowed; production
		// wiring may attach a span/log inside the closure.
		if rehErr := deps.Rehasher(ctx, row.ProjectID, row.ResourceOwner, row.AppID, updatedHash); rehErr == nil {
			rehashed = true
		}
	}

	if row.ExpiresAt != nil && !row.ExpiresAt.IsZero() && time.Now().After(*row.ExpiresAt) {
		return nil, &ClampError{
			Status:      http.StatusUnauthorized,
			Code:        ErrCodeInvalidToken,
			Description: MissingOrInvalidAccessTokenDescription,
			Wrapped:     zerrors.ThrowInvalidArgument(nil, "DCR-Mn003", "Errors.DCR.RAT.Expired"),
		}
	}

	return &ManageContext{
		ClientID:      clientID,
		AppID:         row.AppID,
		ProjectID:     row.ProjectID,
		ResourceOwner: row.ResourceOwner,
		Rehashed:      rehashed,
	}, nil
}

// manageVerifyDispatch wraps a manage stub (T-053/T-054/T-056) with
// the bearer-presence + RAT-verify + 401 envelope chain. Called from
// [NewHandler] when ManageDeps is configured. The legacy [Handler]
// keeps the simpler [manageBearerGate] (T-050) for migration coverage.
//
// On success, falls through to the supplied stub. The future GET/PUT/
// DELETE bodies will read the resolved [ManageContext] from the
// request ctx via [contextWithManage] / [ManageFromContext] once those
// tasks land; for now the stubs ignore the resolution and emit 501.
func manageVerifyDispatch(deps ManageDeps, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mode, bearer := ClassifyAuthMode(r)
		if mode != AuthModeIAT {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			WriteError(w, http.StatusUnauthorized, ErrCodeInvalidToken,
				MissingOrInvalidAccessTokenDescription)
			return
		}

		clientID := mux.Vars(r)["client_id"]
		mctx, err := VerifyRAT(r.Context(), deps, clientID, bearer)
		if err != nil {
			writeAuthError(r.Context(), w, err)
			return
		}

		next(w, r.WithContext(contextWithManage(r.Context(), mctx)))
	}
}

// manageContextKey scopes the resolved ManageContext on the request
// ctx. Unexported so callers cannot stash arbitrary values under our
// key (and so the contract stays one-way: manageVerifyDispatch sets,
// the future GET/PUT/DELETE bodies read).
type manageContextKey struct{}

// contextWithManage returns a child context carrying the resolved
// ManageContext. The future T-053/T-054/T-056 handler bodies retrieve
// it via [ManageFromContext].
func contextWithManage(ctx context.Context, mctx *ManageContext) context.Context {
	return context.WithValue(ctx, manageContextKey{}, mctx)
}

// ManageFromContext extracts the ManageContext set by
// [manageVerifyDispatch]. Returns nil when called from a request that
// did not flow through the manage dispatch — the future handler bodies
// MUST handle that case as a programmer error (panic / 500), since a
// correctly-mounted handler will always have the value present.
func ManageFromContext(ctx context.Context) *ManageContext {
	mctx, _ := ctx.Value(manageContextKey{}).(*ManageContext)
	return mctx
}
