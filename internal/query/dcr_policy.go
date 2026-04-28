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

// DCRPolicyScope identifies which tier supplied a particular field of
// a merged effective policy. cavekit-org-dcr-policy.md R3 requires the
// merged result to surface this so observability spans (T-040) can
// emit `dcr.policy.scope = org|instance|static-config` per-attribute
// without re-deriving from the configured value.
type DCRPolicyScope int

const (
	DCRPolicyScopeUnknown DCRPolicyScope = iota
	DCRPolicyScopeOrg
	DCRPolicyScopeInstance
	DCRPolicyScopeStaticConfig
)

func (s DCRPolicyScope) String() string {
	switch s {
	case DCRPolicyScopeOrg:
		return "org"
	case DCRPolicyScopeInstance:
		return "instance"
	case DCRPolicyScopeStaticConfig:
		return "static-config"
	default:
		return "unknown"
	}
}

// DCRPolicy is the merged effective DCR policy for an
// (instance, org) pair. AllowedAudiences and
// RegistrationAccessTokenLifetime carry the resolved values; the
// matching *Scope field reports which tier supplied them.
//
// AllowedAudiences nil means "no allow-list configured at any tier" —
// per RFC 8707 §2 semantics that means UNRESTRICTED. An empty slice
// (length 0) means "explicitly empty allow-list" — which the static-
// config tier never emits (the YAML default `AllowedAudiences: []` is
// the unrestricted sentinel; the merge maps that to nil here so
// downstream callers don't need to distinguish).
type DCRPolicy struct {
	AllowedAudiences      []string
	AllowedAudiencesScope DCRPolicyScope

	RegistrationAccessTokenLifetime      time.Duration
	RegistrationAccessTokenLifetimeScope DCRPolicyScope
}

// DCRPolicyStaticDefaults carries the static-config bottom-tier values
// from `cavekit-config.md` R1 — `OIDC.DCR.AllowedAudiences` and
// `OIDC.DCR.RegistrationAccessToken.Lifetime`. Threaded through here
// because the query package does not import the OIDC config types
// (the import graph stays one-way: cmd/start.go → query, never the
// reverse).
type DCRPolicyStaticDefaults struct {
	AllowedAudiences                []string
	RegistrationAccessTokenLifetime time.Duration
}

//go:embed dcr_policy_by_org.sql
var dcrPolicyByOrgQuery string

// DCRPolicyByOrg returns the merged effective DCR policy for the
// caller's instance and the supplied org. cavekit-org-dcr-policy.md R3
// merge precedence: org override → instance default → staticDefaults.
// Each field's Scope marks which tier won.
//
// `orgID` empty is a programmer error (the caller should resolve the
// org from IAT claims or anonymous-mode DefaultOrgID before calling
// this); we still return a valid policy synthesised from the instance
// default + static-config in that case rather than erroring, so the
// Phase-1-equivalent code path stays compatible.
//
// Errors propagate sql.ErrNoRows as zerrors.NotFound only when both
// rows are absent AND staticDefaults is the zero value — the normal
// "neither row exists, but static config carries values" case is NOT
// an error. cavekit-org-dcr-policy.md R3: "synthesizes static-config-
// default when neither row exists".
func (q *Queries) DCRPolicyByOrg(
	ctx context.Context,
	orgID string,
	staticDefaults DCRPolicyStaticDefaults,
) (_ *DCRPolicy, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	instanceID := authz.GetInstance(ctx).InstanceID()

	var (
		orgAudiences           database.TextArray[string]
		orgLifetimeNS          sql.NullInt64
		instanceAudiences      database.TextArray[string]
		instanceLifetimeNS     sql.NullInt64
		orgAudiencesValid      bool
		instanceAudiencesValid bool
	)

	// pgx's TextArray scanner normalises NULL to an empty slice, which
	// we'd misread as "explicitly empty". Workaround: scan into a
	// pointer so NULL → nil pointer (distinct from zero-length slice).
	row := q.client.DB.QueryRowContext(ctx, dcrPolicyByOrgQuery, instanceID, orgID)
	var orgAudiencesPtr, instanceAudiencesPtr *database.TextArray[string]
	if err = row.Scan(
		&orgAudiencesPtr,
		&orgLifetimeNS,
		&instanceAudiencesPtr,
		&instanceLifetimeNS,
	); err != nil {
		// The query always returns exactly one row (the CTE expression
		// projects NULLs when neither row exists). sql.ErrNoRows here
		// would indicate a connection-level error, not a missing row.
		if errors.Is(err, sql.ErrNoRows) {
			return synthesiseFromStaticDefaults(staticDefaults), nil
		}
		return nil, zerrors.ThrowInternal(err, "QUERY-DcRP1", "Errors.Internal")
	}
	if orgAudiencesPtr != nil {
		orgAudiences = *orgAudiencesPtr
		orgAudiencesValid = true
	}
	if instanceAudiencesPtr != nil {
		instanceAudiences = *instanceAudiencesPtr
		instanceAudiencesValid = true
	}

	out := &DCRPolicy{}

	// AllowedAudiences merge: prefer org override, fall back to
	// instance default, finally to static-config. NULL at the org tier
	// (= "inherit") falls through.
	switch {
	case orgAudiencesValid:
		out.AllowedAudiences = []string(orgAudiences)
		out.AllowedAudiencesScope = DCRPolicyScopeOrg
	case instanceAudiencesValid:
		out.AllowedAudiences = []string(instanceAudiences)
		out.AllowedAudiencesScope = DCRPolicyScopeInstance
	default:
		out.AllowedAudiences = staticDefaults.AllowedAudiences
		out.AllowedAudiencesScope = DCRPolicyScopeStaticConfig
	}

	// Lifetime merge: same precedence. Stored as int64 nanoseconds for
	// projection-tool portability (T-010).
	switch {
	case orgLifetimeNS.Valid:
		out.RegistrationAccessTokenLifetime = time.Duration(orgLifetimeNS.Int64)
		out.RegistrationAccessTokenLifetimeScope = DCRPolicyScopeOrg
	case instanceLifetimeNS.Valid:
		out.RegistrationAccessTokenLifetime = time.Duration(instanceLifetimeNS.Int64)
		out.RegistrationAccessTokenLifetimeScope = DCRPolicyScopeInstance
	default:
		out.RegistrationAccessTokenLifetime = staticDefaults.RegistrationAccessTokenLifetime
		out.RegistrationAccessTokenLifetimeScope = DCRPolicyScopeStaticConfig
	}

	return out, nil
}

func synthesiseFromStaticDefaults(s DCRPolicyStaticDefaults) *DCRPolicy {
	return &DCRPolicy{
		AllowedAudiences:                     s.AllowedAudiences,
		AllowedAudiencesScope:                DCRPolicyScopeStaticConfig,
		RegistrationAccessTokenLifetime:      s.RegistrationAccessTokenLifetime,
		RegistrationAccessTokenLifetimeScope: DCRPolicyScopeStaticConfig,
	}
}
