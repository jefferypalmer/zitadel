package command

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/zitadel/logging"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/api/oidc/dcr"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// policy_dcr_observability.go owns the structured emission for
// org/instance DCR-policy command outcomes per cavekit-org-dcr-policy.md
// R7 / T-037 / T-038 / T-039.
//
// Three signals fire from each command path:
//
//   - INFO audit log (T-037) on success — payload restricted to
//     instance_id, resource_owner, allowed_audiences_count (int),
//     registration_access_token_lifetime, scope. The list of audience
//     URIs is NEVER logged: org allow-lists may name internal-only
//     resources whose existence is itself sensitive.
//
//   - WARN audit log (T-038) on R4/R5 validation failure — payload
//     restricted to instance_id, resource_owner, error_key, and
//     first_violating_value. The submitted list itself is never logged.
//
//   - Counter `zitadel.dcr.org_policy_changes_total` (T-039) on every
//     command exit (success or failure) with labels org_id, scope, result.

// extractI18nKey returns the i18n key carried on a zerror chain or ""
// when the error doesn't carry one. The audit log + metric report this
// key — never the localised description (locale-dependent, breaks log
// indexing).
func extractI18nKey(err error) string {
	var zerr *zerrors.ZitadelError
	if errors.As(err, &zerr) {
		return zerr.Message
	}
	return ""
}

// emitDCRPolicyAccepted fires the success-path INFO log + counter.
// `allowedAudiences == nil` reports as `count=-1` to distinguish from
// explicit empty (`count=0` = "explicitly unrestricted at this tier")
// — important for audit consumers that need to tell "inherit" apart
// from "wide-open at this tier".
func (c *Commands) emitDCRPolicyAccepted(
	ctx context.Context,
	scope, resourceOwner string,
	allowedAudiences *[]string,
	lifetime *time.Duration,
) {
	instanceID := authz.GetInstance(ctx).InstanceID()
	count := -1
	if allowedAudiences != nil {
		count = len(*allowedAudiences)
	}
	lifetimeStr := "(inherit)"
	if lifetime != nil {
		lifetimeStr = lifetime.String()
	}
	logging.WithFields(
		"instance_id", instanceID,
		"resource_owner", resourceOwner,
		"allowed_audiences_count", count,
		"registration_access_token_lifetime", lifetimeStr,
		"scope", scope,
	).Info("dcr policy command accepted")
	dcr.RecordOrgPolicyChange(ctx, resourceOwnerForMetric(scope, resourceOwner),
		scope, dcr.MetricPolicyResultAccepted)
}

// emitDCRPolicyRejected fires the failure-path WARN log + counter.
// `firstViolatingValue` is the offending input (first invalid URI for
// allow-list validation, or the rejected duration for lifetime
// validation); empty string when the rejection is for some other
// reason. Never logs the full submitted list.
func (c *Commands) emitDCRPolicyRejected(
	ctx context.Context,
	scope, resourceOwner string,
	err error,
	firstViolatingValue string,
) {
	instanceID := authz.GetInstance(ctx).InstanceID()
	logging.WithFields(
		"instance_id", instanceID,
		"resource_owner", resourceOwner,
		"error_key", extractI18nKey(err),
		"first_violating_value", firstViolatingValue,
	).Warn("dcr policy command rejected")
	dcr.RecordOrgPolicyChange(ctx, resourceOwnerForMetric(scope, resourceOwner),
		scope, dcr.MetricPolicyResultRejected)
}

// resourceOwnerForMetric collapses the `org_id` label for the
// instance-tier counter to the literal "instance" string. This bounds
// label cardinality on the instance-tier emission (every instance
// produces exactly one bucket) while keeping the org-tier metric
// per-org as the kit requires.
func resourceOwnerForMetric(scope, resourceOwner string) string {
	if scope == dcr.MetricScopeInstance {
		return "instance"
	}
	return resourceOwner
}

// firstSubsetViolation mirrors validateOrgAllowedAudiencesSubset's
// loop but returns only the first offending URI (or "" when the list
// is valid). Used by the rejected-emit path so audit consumers see
// the same first-violator the error_description names — without the
// emit code having to re-implement the violation rules.
func firstSubsetViolation(orgAudiences, instanceAudiences []string) string {
	for _, raw := range orgAudiences {
		if validateRFC8707ResourceSyntax(raw) != nil {
			return raw
		}
		if len(instanceAudiences) == 0 {
			continue
		}
		if !slices.Contains(instanceAudiences, raw) {
			return raw
		}
	}
	return ""
}
