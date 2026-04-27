package dcr

import (
	"context"
	"net/http"
	"strings"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// RegistrationContext carries the resolved {instance, org, project, iat}
// identifiers + the IAT row ID (or empty-string sentinel for anonymous
// mode) for a single DCR register request. Produced by [Authenticate];
// consumed by T-040 RegisterClient command for ApplicationDynamicallyRegisteredEvent
// audit field population (cavekit-register-handler.md R6).
//
// Per cavekit-register-handler.md R3 AC: "the audit event records
// iat_id=\"\" (sentinel for anonymous)". The empty string is preserved
// verbatim into the audit event payload so downstream consumers can
// distinguish anonymous registrations from IAT-issued ones structurally.
type RegistrationContext struct {
	InstanceID string
	OrgID      string
	ProjectID  string
	IATID      string // empty string sentinel for anonymous mode
}

// AnonymousConfig is the slice of [DCRConfig] needed to resolve an
// anonymous registration request (cavekit-register-handler.md R3 AC4 +
// AC5). Defined as an interface so tests can stub it without pulling
// in the full Server config tree.
type AnonymousConfig interface {
	RequireInitialAccessToken() bool
	DefaultOrgID() string
	DefaultProjectID() string
}

// AuthMode classifies a single register request as IAT-presented vs
// anonymous (no Authorization header). The split is intentionally
// structural rather than config-driven so the handler can short-circuit
// missing-header responses for IAT-required deployments without parsing
// the body.
type AuthMode int

const (
	AuthModeAnonymous AuthMode = iota
	AuthModeIAT
)

// ClassifyAuthMode inspects the request's Authorization header and
// returns AuthModeIAT iff a Bearer token is presented. Empty / absent /
// non-Bearer headers map to AuthModeAnonymous; the caller decides what
// to do with that based on the deployment's [AnonymousConfig.RequireInitialAccessToken]
// setting.
//
// Spec reference: cavekit-register-handler.md R3 — "two authentication
// modes coexist: anonymous (default) and IAT-required. Per-request
// behavior is determined by the presence of a Bearer header."
func ClassifyAuthMode(r *http.Request) (AuthMode, string) {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h == "" {
		return AuthModeAnonymous, ""
	}
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		// Non-Bearer Authorization headers (Basic, Digest, custom) are
		// out-of-scope for DCR: RFC 7591 §2 only defines IAT delivery
		// via Bearer. Treat them as anonymous so the
		// RequireInitialAccessToken=true path still rejects them with the
		// expected 401 + WWW-Authenticate header.
		return AuthModeAnonymous, ""
	}
	tok := strings.TrimSpace(h[len("bearer "):])
	return AuthModeIAT, tok
}

// ResolveAnonymous produces a [RegistrationContext] for anonymous mode
// per cavekit-register-handler.md R3 AC4-AC5 (T-038):
//
//   - instance_id is derived from the request via authz.GetInstance(ctx)
//     (which itself sources from the request host through the API
//     server's instance interceptor — single source of truth across all
//     handlers, no DCR-specific host parsing).
//   - org_id and project_id come from DCR.DefaultOrgID / DefaultProjectID.
//   - iat_id is the empty-string sentinel ("" — the audit event records
//     this verbatim per the kit AC).
//
// Returns a 401 invalid_token RFC 7591 [ClampError] if the deployment
// requires an IAT (cavekit-config.md R4 / T-009 — refusing startup with
// empty defaults in anonymous mode is the upstream guard; this function
// is the runtime defence-in-depth for the case where config hot-reload
// or a misconfigured override left the defaults empty mid-run).
//
// Returns *ClampError (Code=invalid_token) when the request is
// anonymous but the deployment requires an IAT — the handler maps that
// to HTTP 401 with WWW-Authenticate: Bearer per R3 AC1.
//
// Returns a separate *ClampError (Code=feature_disabled) when
// anonymous mode is enabled but the resolved defaults are empty —
// defensive runtime guard since T-009 normally catches this at startup.
func ResolveAnonymous(ctx context.Context, cfg AnonymousConfig) (*RegistrationContext, error) {
	if cfg.RequireInitialAccessToken() {
		return nil, &ClampError{
			Code:        ErrCodeInvalidToken,
			Description: "this deployment requires an Initial Access Token; present one in the Authorization: Bearer header",
			Wrapped:     zerrors.ThrowInvalidArgument(nil, "DCR-Au001", "Errors.DCR.IAT.MissingBearer"),
		}
	}

	orgID := strings.TrimSpace(cfg.DefaultOrgID())
	projectID := strings.TrimSpace(cfg.DefaultProjectID())
	if orgID == "" || projectID == "" {
		// T-009 guards this at startup. If we reach here at runtime, the
		// deployment is in a half-configured state — fail closed rather
		// than register clients without org/project attribution.
		return nil, &ClampError{
			Code:        ErrCodeFeatureDisabled,
			Description: "anonymous DCR requires DCR.DefaultOrgID and DCR.DefaultProjectID; both are empty in this instance",
			Wrapped:     zerrors.ThrowPreconditionFailed(nil, "DCR-Au002", "Errors.DCR.AnonymousDefaultsMissing"),
		}
	}

	return &RegistrationContext{
		InstanceID: authz.GetInstance(ctx).InstanceID(),
		OrgID:      orgID,
		ProjectID:  projectID,
		IATID:      "", // sentinel — kit R3 AC5
	}, nil
}

// IATLookupQueries is the projection-read seam the IAT auth path
// needs from query.Queries. Defined as an interface so unit tests can
// stub it without spinning up the full DB harness.
type IATLookupQueries interface {
	InitialAccessTokenByID(ctx context.Context, id, resourceOwner string) (*QueryIATRow, error)
}

// QueryIATRow mirrors the subset of [query.InitialAccessToken] the
// auth path consumes. Defined as a local alias-shaped struct so this
// package does not have to import the full query package (avoids the
// import cycle between dcr → query and query → dcr that would arise
// once T-040 lands).
//
// Fields kept aligned with the order in
// `internal/query/initial_access_token.go::InitialAccessToken` so a
// type-converter is a 1:1 field copy.
type QueryIATRow struct {
	ID            string
	InstanceID    string
	ResourceOwner string
	ProjectID     string
	TokenHash     string
}

// IATVerifier is the verification + consume seam. The auth path calls
// VerifyIATPlaintext on a successful byID lookup, then ConsumeOneSlot
// to atomically reserve a slot via the eventstore UniqueConstraint.
type IATVerifier interface {
	VerifyIATPlaintext(presented, encodedHash string) error
}

// PlaintextParser is the single-method seam the auth path uses to
// extract the IAT row PK from a presented Bearer string. Stubbed to
// command.ParseIATPlaintext at the start.go wiring site.
type PlaintextParser func(presented string) (id, random string, ok bool)

// (dummyPassWapHash literal removed 2026-04-27 / F-101 — see
// cavekit-iat.md R4 amendment. The dummy hash now travels through
// [RegistrationDeps.AntiEnumDummyHash], built by [BuildAntiEnumDummyHash]
// at startup so its algorithm prefix matches the configured
// `passwap.Swapper`. A hardcoded `$argon2id$` literal vs a bcrypt-
// configured swapper returned `passwap.ErrNoVerifier` in microseconds
// while the wrong-random branch ran real bcrypt-verify in milliseconds,
// inverting the anti-enumeration oracle.)

// ResolveIAT implements cavekit-register-handler.md R3 AC2-AC3, AC6
// (T-037 — the post-DE-001 implementation). Steps:
//
//  1. Parse the Bearer plaintext via the supplied parser into
//     (id, random). Malformed input → dummy-Verify + 401.
//  2. Look up the IAT row by id (instance-scoped via authz ctx).
//     Not-found / cross-instance → dummy-Verify + 401.
//  3. Verify the presented plaintext against the row's stored
//     Passwap hash. Mismatch → 401 (no dummy-Verify needed; we
//     already paid the Verify cost).
//  4. Return the [RegistrationContext] with InstanceID/OrgID/
//     ProjectID resolved from the IAT row's claims and IATID set
//     to the row's PK. Caller (T-040 RegisterClient) is responsible
//     for the slot-consume push via Commands.ConsumeInitialAccessToken.
//
// The function does NOT consume the slot — it stops at verification.
// The split lets T-040 bundle slot-consume into the same eventstore
// transaction as the application-creation events for atomicity.
//
// `antiEnumDummyHash` MUST be the value built by [BuildAntiEnumDummyHash]
// at startup (cavekit-iat.md R4 amendment 2026-04-27 / F-101).
// Passing a static literal will reintroduce the inverted timing
// oracle.
func ResolveIAT(
	ctx context.Context,
	queries IATLookupQueries,
	verifier IATVerifier,
	parse PlaintextParser,
	presented string,
	antiEnumDummyHash string,
) (*RegistrationContext, error) {
	id, _, ok := parse(presented)
	if !ok {
		// Bad shape. Anti-enum: still pay one Verify so timing matches
		// the wrong-random case.
		_ = verifier.VerifyIATPlaintext(presented, antiEnumDummyHash)
		return nil, &ClampError{
			Code:        ErrCodeInvalidToken,
			Description: "Authorization Bearer is not a recognised IAT plaintext",
			Wrapped:     zerrors.ThrowInvalidArgument(nil, "DCR-Au003", "Errors.DCR.IAT.InvalidToken"),
		}
	}

	row, err := queries.InitialAccessTokenByID(ctx, id, "")
	if err != nil {
		// Not-found / cross-instance / DB error — uniform Verify-then-401
		// to suppress the unknown-ID-vs-wrong-random timing oracle.
		_ = verifier.VerifyIATPlaintext(presented, antiEnumDummyHash)
		return nil, &ClampError{
			Code:        ErrCodeInvalidToken,
			Description: "the presented Initial Access Token is not valid for this instance",
			Wrapped:     zerrors.ThrowInvalidArgument(err, "DCR-Au004", "Errors.DCR.IAT.InvalidToken"),
		}
	}

	// Defensive: the byID query already filters by instance_id in the
	// WHERE clause, but a misconfigured authz interceptor that left the
	// ctx instance empty would surface a row from any instance. Verify
	// the binding here so the auth boundary is explicit.
	if row.InstanceID != authz.GetInstance(ctx).InstanceID() {
		_ = verifier.VerifyIATPlaintext(presented, antiEnumDummyHash)
		return nil, &ClampError{
			Code:        ErrCodeInvalidToken,
			Description: "the presented Initial Access Token is not valid for this instance",
			Wrapped:     zerrors.ThrowInvalidArgument(nil, "DCR-Au005", "Errors.DCR.IAT.InvalidToken"),
		}
	}

	if err := verifier.VerifyIATPlaintext(presented, row.TokenHash); err != nil {
		// Wrong random — Verify already paid the timing cost.
		return nil, &ClampError{
			Code:        ErrCodeInvalidToken,
			Description: "the presented Initial Access Token is not valid for this instance",
			Wrapped:     zerrors.ThrowInvalidArgument(err, "DCR-Au006", "Errors.DCR.IAT.InvalidToken"),
		}
	}

	return &RegistrationContext{
		InstanceID: row.InstanceID,
		OrgID:      row.ResourceOwner,
		ProjectID:  row.ProjectID,
		IATID:      row.ID,
	}, nil
}
