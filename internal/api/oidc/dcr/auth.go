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

// IATAuthNotImplemented is the error returned by [ResolveIAT] until
// T-037 lands. Surfaced as 401 invalid_token to keep the handler's
// response shape stable for early integration probes.
//
// T-037 implementation requires either:
//
//  1. A deterministic lookup index for IATs (HMAC-of-plaintext column
//     on the projection) so InitialAccessTokenByHash works as the
//     existing SQL implies, or
//  2. Embedding the IAT ID into the plaintext format
//     (`zdiat_<id>.<random>`) so the handler can extract the ID from
//     the Bearer and look up by ID, or
//  3. An "all IATs in instance" query + per-row Verify — O(n) per
//     request but works without schema changes.
//
// The current T-021 plaintext (`zdiat_<48-byte-random>`, no embedded
// ID) plus the T-019 projection schema (Passwap-encoded `token_hash`,
// non-deterministic) cannot satisfy InitialAccessTokenByHash without
// one of the three above. /ck:revise should pick an option before
// T-037 implementation lands.
var IATAuthNotImplemented = &ClampError{
	Code:        ErrCodeInvalidToken,
	Description: "IAT-mode DCR is not yet implemented; T-037 awaits a /ck:revise pass on the IAT lookup design",
	Wrapped:     zerrors.ThrowUnimplemented(nil, "DCR-Au003", "Errors.DCR.IAT.LookupNotImplemented"),
}
