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
//
// DCRMetadataByClientID was added in T-053 — the GET handler reads the
// full metadata row AFTER the dispatcher's VerifyRAT proves the
// caller is authorised. NotFound on this path is unexpected (the
// VerifyRAT lookup just succeeded) and returns 500.
type ManageQueries interface {
	DCRRATLookupByClientID(ctx context.Context, clientID string) (*ManageRATRow, error)
	DCRMetadataByClientID(ctx context.Context, clientID string) (*ManageMetaRow, error)
}

// ManageMetaRow mirrors the subset of [query.DCRGetMetadata] the GET
// handler consumes. Same alias-shaped layering pattern as
// [ManageRATRow] / [QueryIATRow] — the dcr package does not import
// the full query package, so the wiring layer translates field-by-
// field.
//
// DCRMeta is the raw JSONB blob stamped at registration time
// (T-041). The GET writer unpacks it into the RFC 7591 §2 pass-
// through fields on the response body.
type ManageMetaRow struct {
	AppID            string
	ClientName       string
	ClientIDIssuedAt time.Time
	RedirectURIs     []string
	GrantTypes       []string
	ResponseTypes    []string
	ApplicationType  string
	AuthMethodType   string
	DCRMeta          []byte
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

	// ClientSecretExpiresIn echoes config.OIDC.DCR.ClientSecretExpiresIn
	// so the GET / PUT manage responses (T-053 / T-055) can compute
	// `client_secret_expires_at` per RFC 7591 §3.2.1. Zero = "no expiry"
	// MUST-emit sentinel — same convention as the register response
	// writer's [clientSecretExpiresAtFor]. The projection does not
	// store a per-secret expires_at column; the field is derived from
	// the issued-at + this lifetime at response build time.
	ClientSecretExpiresIn time.Duration

	// Update is the function-shaped seam for invoking
	// `command.Commands.UpdateRegisteredClient` (cavekit-manage-handler.md
	// R5 / T-054). Production wiring (cmd/start/start.go) bridges
	// dcr.UpdateRequest → command.UpdateRegisteredClientInput and the
	// result back; tests stub it directly.
	//
	// Optional — when nil, the PUT route falls back to the 501 stub so
	// deployments mid-rollout still emit a uniform error envelope while
	// the wiring is staged. Production MUST set every field.
	Update UpdateFn

	// Config drives the PUT-side re-clamp (R5 AC1). Same DCRConfigSubset
	// the POST register path uses (T-034) — passing the same operator
	// allow-lists keeps PUT and POST symmetrical, which is the whole
	// point of `validate.go` being a single source of truth.
	Config DCRConfigSubset

	// SupportedSigAlgs feeds the R4 `id_token_signed_response_alg`
	// validation that re-runs on PUT (R5 AC1: every R4 clamp re-runs).
	// Sourced from the OIDC server's `supportedSigningAlgs()` at startup
	// — same value the register dispatcher passes to ValidateAndClampMetadata.
	SupportedSigAlgs []string

	// SoftwareStatementEnabled gates the R4 unapproved_software_statement
	// rejection on PUT (R5 AC1). Sourced from
	// `config.OIDC.DCR.SoftwareStatement.Enabled`. Must match the value
	// the register dispatcher uses so a software_statement that was
	// rejected at POST stays rejected at PUT.
	SoftwareStatementEnabled bool

	// MaxBodyBytes caps the PUT request body. Mirrors RegistrationDeps
	// — keeps the per-request cap consistent across the DCR surface.
	// Zero falls back to DefaultMaxBodyBytes inside Decode.
	MaxBodyBytes int64
}

// UpdateFn is the function-shaped seam for invoking the PUT-side
// command (cavekit-manage-handler.md R5 / T-054). Returns a *ClampError
// on validation failure (mapped to 400 by the dispatcher); any other
// error type is treated as 500.
type UpdateFn func(ctx context.Context, req *UpdateRequest) (*UpdateResult, error)

// UpdateRequest is the dcr-internal shape passed to the closure.
// Mirrors the subset of `command.UpdateRegisteredClientInput` fields
// the dispatcher controls.
type UpdateRequest struct {
	ProjectID string
	OrgID     string
	AppID     string
	Clamped   *RFC7591Metadata
}

// UpdateResult is the dcr-internal shape returned by the closure.
// Mirrors the subset of `command.UpdateRegisteredClientResult` the
// PUT response writer (T-055) will echo. ClientSecret is empty unless
// this PUT minted a fresh secret via the auth-method `none → secret_*`
// transition (R5 AC3).
type UpdateResult struct {
	ClientID     string
	ClientSecret string
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
	// Update is optional — when nil, PUT falls back to the 501 stub. When
	// set, the re-clamp surface (Config) MUST also be set; otherwise the
	// PUT pipeline would have no allow-lists to enforce R5 AC1 against.
	if d.Update != nil && d.Config == nil {
		return errors.New("dcr: ManageDeps.Config is required when Update is set (PUT re-clamp uses the same DCRConfigSubset as POST register)")
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
