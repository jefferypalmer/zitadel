package command

import (
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/policy"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// DCRStaticDefaults carries the static-config bottom-tier values
// (`OIDC.DCR.AllowedAudiences` + `OIDC.DCR.RegistrationAccessToken.Lifetime`)
// from cavekit-config.md R1. Threaded into the org-policy commands so
// the validation can compute the EFFECTIVE instance default at command
// time without the command package needing to import the OIDC config
// types.
type DCRStaticDefaults struct {
	AllowedAudiences                []string
	RegistrationAccessTokenLifetime time.Duration
}

// PolicyDCRWriteModel is the shared write model behind the org and
// instance DCR-policy aggregates. Fields are pointer types so the
// Reduce path can disambiguate "explicitly set to empty" (allow-list
// is empty, lifetime is 0s) from "absent — inherit upper tier"
// (cavekit-org-dcr-policy.md R1 NULL semantics).
type PolicyDCRWriteModel struct {
	eventstore.WriteModel

	AllowedAudiences                *[]string
	RegistrationAccessTokenLifetime *time.Duration
	State                           domain.PolicyState
}

func (wm *PolicyDCRWriteModel) Reduce() error {
	for _, event := range wm.Events {
		switch e := event.(type) {
		case *policy.DCRPolicyAddedEvent:
			if e.AllowedAudiences != nil {
				v := append([]string(nil), (*e.AllowedAudiences)...)
				wm.AllowedAudiences = &v
			}
			if e.RegistrationAccessTokenLifetime != nil {
				v := *e.RegistrationAccessTokenLifetime
				wm.RegistrationAccessTokenLifetime = &v
			}
			wm.State = domain.PolicyStateActive
		case *policy.DCRPolicyChangedEvent:
			if e.AllowedAudiences != nil {
				v := append([]string(nil), (*e.AllowedAudiences)...)
				wm.AllowedAudiences = &v
			}
			if e.RegistrationAccessTokenLifetime != nil {
				v := *e.RegistrationAccessTokenLifetime
				wm.RegistrationAccessTokenLifetime = &v
			}
		case *policy.DCRPolicyRemovedEvent:
			wm.State = domain.PolicyStateRemoved
			wm.AllowedAudiences = nil
			wm.RegistrationAccessTokenLifetime = nil
		}
	}
	return wm.WriteModel.Reduce()
}

// equalAudiences reports whether two pointer-to-slice values represent
// the same allow-list. nil and empty slices are NOT equal — nil means
// "inherit", empty means "explicitly unrestricted at this tier".
func equalAudiences(a, b *[]string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if len(*a) != len(*b) {
		return false
	}
	for i := range *a {
		if (*a)[i] != (*b)[i] {
			return false
		}
	}
	return true
}

func equalLifetime(a, b *time.Duration) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// effectiveInstanceAllowedAudiences returns the merged allow-list at the
// instance tier — the instance row if set, else the static-config tier.
// Used by the org-tier subset check (T-018) to know what "the parent's
// allow-list" actually is at command time. Returns (list, scope) where
// scope is "instance" or "static-config" — note org tier is irrelevant
// here; we never need the org's own merged value to validate an org
// override.
func effectiveInstanceAllowedAudiences(
	instance *PolicyDCRWriteModel,
	defaults DCRStaticDefaults,
) (list []string, fromStatic bool) {
	if instance != nil && instance.State.Exists() && instance.AllowedAudiences != nil {
		return *instance.AllowedAudiences, false
	}
	return defaults.AllowedAudiences, true
}

// effectiveInstanceLifetime: same idea, for the lifetime tier.
func effectiveInstanceLifetime(
	instance *PolicyDCRWriteModel,
	defaults DCRStaticDefaults,
) (lifetime time.Duration, fromStatic bool) {
	if instance != nil && instance.State.Exists() && instance.RegistrationAccessTokenLifetime != nil {
		return *instance.RegistrationAccessTokenLifetime, false
	}
	return defaults.RegistrationAccessTokenLifetime, true
}

// validateOrgAllowedAudiencesSubset enforces cavekit-org-dcr-policy.md
// R4 / T-018 set-narrowing: every URI in `org` must be syntactically
// valid (RFC 8707 §2 — absolute URI, no fragment) AND, when the
// instance tier has a non-empty allow-list, must be present in it.
// Empty/nil at the org tier (= "inherit") passes by definition.
//
// Empty instance allow-list (`UNRESTRICTED` per RFC 8707 §2 inverted-
// allow-list semantics) means any syntactically-valid URI passes —
// the kit explicitly carves this out. cavekit-org-dcr-policy.md R4:
// "Empty instance allow-list → org allow-list any valid URI list
// (subset vacuously satisfied)".
//
// On failure returns INVALID_ARGUMENT with i18n key
// `Errors.DCR.OrgPolicy.InvalidAudienceSubset`. The error_description
// names the FIRST violating URI (kit explicit "only the first") so
// large org allow-lists do not flood the error envelope.
func validateOrgAllowedAudiencesSubset(orgAudiences, instanceAudiences []string) error {
	for _, raw := range orgAudiences {
		if err := validateRFC8707ResourceSyntax(raw); err != nil {
			return zerrors.ThrowInvalidArgument(err, "DCRPL-ASub1",
				"Errors.DCR.OrgPolicy.InvalidAudienceSubset")
		}
		if len(instanceAudiences) == 0 {
			continue // unrestricted at instance tier
		}
		if !slices.Contains(instanceAudiences, raw) {
			return zerrors.ThrowInvalidArgument(
				fmt.Errorf("URI %q is not in the instance allow-list", raw),
				"DCRPL-ASub2", "Errors.DCR.OrgPolicy.InvalidAudienceSubset")
		}
	}
	return nil
}

// validateOrgLifetimeCap enforces cavekit-org-dcr-policy.md R5 / T-019
// cap-narrowing:
//   - negative durations are refused (matches the cavekit-config.md R1
//     ClientSecretExpiresIn refusal — a negative lifetime would
//     advertise expired-on-issue tokens).
//   - 0s at the org tier is permitted iff the instance default is also
//     0s (zero = "no expiry"; otherwise an org cannot weaken the
//     instance cap).
//   - any positive value must be ≤ instance default (when the instance
//     default is itself positive); when the instance default is 0s
//     ("no expiry") the org may set any positive value.
//
// Returns INVALID_ARGUMENT keyed
// `Errors.DCR.OrgPolicy.InvalidLifetimeCap` on violation.
func validateOrgLifetimeCap(orgLifetime, instanceLifetime time.Duration) error {
	if orgLifetime < 0 {
		return zerrors.ThrowInvalidArgument(
			fmt.Errorf("RegistrationAccessTokenLifetime %s is negative", orgLifetime),
			"DCRPL-LCap1", "Errors.DCR.OrgPolicy.InvalidLifetimeCap")
	}
	switch {
	case instanceLifetime == 0:
		// Instance allows "no expiry"; any positive (or zero) org
		// value is acceptable — zero matches, positive narrows.
		return nil
	case orgLifetime == 0:
		// Instance is positive (finite cap), org wants no-expiry —
		// that would WEAKEN the instance cap. Refuse.
		return zerrors.ThrowInvalidArgument(
			fmt.Errorf("0s (no expiry) requested but instance default is %s", instanceLifetime),
			"DCRPL-LCap2", "Errors.DCR.OrgPolicy.InvalidLifetimeCap")
	case orgLifetime > instanceLifetime:
		return zerrors.ThrowInvalidArgument(
			fmt.Errorf("RegistrationAccessTokenLifetime %s exceeds instance cap %s",
				orgLifetime, instanceLifetime),
			"DCRPL-LCap3", "Errors.DCR.OrgPolicy.InvalidLifetimeCap")
	}
	return nil
}

// validateRFC8707ResourceSyntax mirrors
// internal/api/oidc/rfc8707_validate.go::validateResourceSyntax — kept
// in sync deliberately (kit R4: "uses Phase 1 RFC 8707 URI parser — no
// divergence"). The oidc package imports command, so the parser cannot
// flow back into command without a cycle; this is the inlined parity
// copy. If you change one side, change the other.
func validateRFC8707ResourceSyntax(raw string) error {
	if raw == "" {
		return fmt.Errorf("URI is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("URI %q is not a valid URI: %w", raw, err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("URI %q must be an absolute URI per RFC 8707 §2", raw)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("URI %q must not include a fragment per RFC 8707 §2", raw)
	}
	return nil
}

// Suppress unused-domain-import lint when the helpers above don't yet
// reference domain.* (they do indirectly via PolicyDCRWriteModel.State).
var _ = domain.PolicyStateActive
