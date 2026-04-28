package command

import (
	"context"
	"time"

	"github.com/zitadel/zitadel/internal/api/oidc/dcr"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/org"
	"github.com/zitadel/zitadel/internal/repository/policy"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// SetOrgDCRPolicy creates an org-scope DCR policy override
// (cavekit-org-dcr-policy.md R1 / T-011 + R4/R5 validation T-018/T-019).
//
// `allowedAudiences == nil` and `registrationAccessTokenLifetime == nil`
// each encode "inherit upper tier" — both NULL means the org row holds no
// override at all but is still present (so audit trail records the create).
//
// Non-nil org values are validated against the EFFECTIVE instance default
// (instance row when present, static-config defaults otherwise) at
// command time:
//   - allowedAudiences: subset check vs instance allow-list (R4).
//   - registrationAccessTokenLifetime: ≤ instance cap (R5).
func (c *Commands) SetOrgDCRPolicy(
	ctx context.Context,
	orgID string,
	allowedAudiences *[]string,
	registrationAccessTokenLifetime *time.Duration,
	staticDefaults DCRStaticDefaults,
) (_ *domain.ObjectDetails, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if orgID == "" {
		return nil, zerrors.ThrowInvalidArgument(nil, "ORGD-DcR01", "Errors.ResourceOwnerMissing")
	}

	wm, err := c.orgDCRPolicyWriteModel(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if wm.State == domain.PolicyStateActive {
		return nil, zerrors.ThrowAlreadyExists(nil, "ORGD-DcR02", "Errors.Org.DCRPolicy.AlreadyExists")
	}
	if firstViolation, vErr := c.validateOrgDCRPolicyAgainstInstance(ctx, allowedAudiences, registrationAccessTokenLifetime, staticDefaults); vErr != nil {
		c.emitDCRPolicyRejected(ctx, dcr.MetricScopeOrg, orgID, vErr, firstViolation)
		return nil, vErr
	}
	orgAgg := org.NewAggregate(orgID)
	pushedEvents, err := c.eventstore.Push(ctx,
		org.NewOrgDCRPolicyAddedEvent(ctx, &orgAgg.Aggregate, allowedAudiences, registrationAccessTokenLifetime),
	)
	if err != nil {
		return nil, err
	}
	c.emitDCRPolicyAccepted(ctx, dcr.MetricScopeOrg, orgID, allowedAudiences, registrationAccessTokenLifetime)
	return pushedEventsToObjectDetails(pushedEvents), nil
}

// UpdateOrgDCRPolicy mutates an existing org-scope DCR policy. nil
// arguments mean "no change for this field" (NOT "set to inherit") —
// to clear an override use ResetOrgDCRPolicy.
//
// Validation runs identically to Set — non-nil values are subset/cap-
// narrowed against the effective instance default. Tightened-instance
// edge case (kit R4/R5): when the instance has narrowed since the org
// last set its override, this Update will refuse to push any value
// that no longer fits — historical events stay unchanged on the
// aggregate; only future updates are gated.
func (c *Commands) UpdateOrgDCRPolicy(
	ctx context.Context,
	orgID string,
	allowedAudiences *[]string,
	registrationAccessTokenLifetime *time.Duration,
	staticDefaults DCRStaticDefaults,
) (_ *domain.ObjectDetails, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if orgID == "" {
		return nil, zerrors.ThrowInvalidArgument(nil, "ORGD-DcR03", "Errors.ResourceOwnerMissing")
	}

	wm, err := c.orgDCRPolicyWriteModel(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if !wm.State.Exists() {
		return nil, zerrors.ThrowNotFound(nil, "ORGD-DcR04", "Errors.Org.DCRPolicy.NotFound")
	}
	if firstViolation, vErr := c.validateOrgDCRPolicyAgainstInstance(ctx, allowedAudiences, registrationAccessTokenLifetime, staticDefaults); vErr != nil {
		c.emitDCRPolicyRejected(ctx, dcr.MetricScopeOrg, orgID, vErr, firstViolation)
		return nil, vErr
	}

	changes := buildDCRPolicyChanges(&wm.PolicyDCRWriteModel,
		allowedAudiences, registrationAccessTokenLifetime)
	if len(changes) == 0 {
		return nil, zerrors.ThrowPreconditionFailed(nil, "ORGD-DcR05", "Errors.NoChangesFound")
	}

	orgAgg := org.NewAggregate(orgID)
	changedEvent, err := org.NewOrgDCRPolicyChangedEvent(ctx, &orgAgg.Aggregate, changes)
	if err != nil {
		return nil, err
	}
	pushedEvents, err := c.eventstore.Push(ctx, changedEvent)
	if err != nil {
		return nil, err
	}
	c.emitDCRPolicyAccepted(ctx, dcr.MetricScopeOrg, orgID, allowedAudiences, registrationAccessTokenLifetime)
	return pushedEventsToObjectDetails(pushedEvents), nil
}

// validateOrgDCRPolicyAgainstInstance runs the R4 (subset) + R5 (cap)
// gates against the effective instance default. nil args bypass their
// respective gate (= "inherit"); non-nil args are validated.
//
// On rejection returns (firstViolatingValue, error). The first return
// value is the offending input — first invalid/unauthorized URI for
// the subset path, the lifetime string for the cap path — so
// emitDCRPolicyRejected can name it without re-running validation.
// Empty on success.
func (c *Commands) validateOrgDCRPolicyAgainstInstance(
	ctx context.Context,
	allowedAudiences *[]string,
	registrationAccessTokenLifetime *time.Duration,
	staticDefaults DCRStaticDefaults,
) (string, error) {
	// Skip the round-trip when both args are nil — caller is just
	// recording an "inherit everything" override.
	if allowedAudiences == nil && registrationAccessTokenLifetime == nil {
		return "", nil
	}
	instanceWM, err := c.instanceDCRPolicyWriteModel(ctx)
	if err != nil {
		return "", err
	}
	if allowedAudiences != nil {
		effectiveAudiences, _ := effectiveInstanceAllowedAudiences(&instanceWM.PolicyDCRWriteModel, staticDefaults)
		if err := validateOrgAllowedAudiencesSubset(*allowedAudiences, effectiveAudiences); err != nil {
			return firstSubsetViolation(*allowedAudiences, effectiveAudiences), err
		}
	}
	if registrationAccessTokenLifetime != nil {
		effectiveLifetime, _ := effectiveInstanceLifetime(&instanceWM.PolicyDCRWriteModel, staticDefaults)
		if err := validateOrgLifetimeCap(*registrationAccessTokenLifetime, effectiveLifetime); err != nil {
			return registrationAccessTokenLifetime.String(), err
		}
	}
	return "", nil
}

// ResetOrgDCRPolicy removes the org-scope override so the effective
// policy falls back to the instance default (or static-config when no
// instance default exists).
func (c *Commands) ResetOrgDCRPolicy(
	ctx context.Context,
	orgID string,
) (_ *domain.ObjectDetails, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if orgID == "" {
		return nil, zerrors.ThrowInvalidArgument(nil, "ORGD-DcR06", "Errors.ResourceOwnerMissing")
	}

	wm, err := c.orgDCRPolicyWriteModel(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if !wm.State.Exists() {
		return nil, zerrors.ThrowNotFound(nil, "ORGD-DcR07", "Errors.Org.DCRPolicy.NotFound")
	}

	orgAgg := org.NewAggregate(orgID)
	pushedEvents, err := c.eventstore.Push(ctx,
		org.NewOrgDCRPolicyRemovedEvent(ctx, &orgAgg.Aggregate),
	)
	if err != nil {
		return nil, err
	}
	// Reset/Remove logs as accepted with nil audience + nil lifetime
	// — both `count=-1` ("inherit") and `lifetime=(inherit)` make the
	// reset distinguishable from a Set with no overrides.
	c.emitDCRPolicyAccepted(ctx, dcr.MetricScopeOrg, orgID, nil, nil)
	return pushedEventsToObjectDetails(pushedEvents), nil
}

// RemoveOrgDCRPolicy is an alias of ResetOrgDCRPolicy. Kept under both
// names because the gRPC surface (T-023 / R6) names the operation
// "Reset" while the kit R1 enumerates "Remove" — the wire event is the
// same `org.policy.dcr.removed` either way.
func (c *Commands) RemoveOrgDCRPolicy(ctx context.Context, orgID string) (*domain.ObjectDetails, error) {
	return c.ResetOrgDCRPolicy(ctx, orgID)
}

func (c *Commands) orgDCRPolicyWriteModel(ctx context.Context, orgID string) (_ *OrgDCRPolicyWriteModel, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	wm := newOrgDCRPolicyWriteModel(orgID)
	if err = c.eventstore.FilterToQueryReducer(ctx, wm); err != nil {
		return nil, err
	}
	return wm, nil
}

// buildDCRPolicyChanges converts the desired (allowedAudiences,
// lifetime) pair into a []policy.DCRPolicyChanges, only including the
// fields that actually differ from the current write model. Returns an
// empty slice when both inputs are nil OR all values match the current
// state (the caller turns that into a NoChangesFound error).
func buildDCRPolicyChanges(
	current *PolicyDCRWriteModel,
	allowedAudiences *[]string,
	lifetime *time.Duration,
) []policy.DCRPolicyChanges {
	changes := make([]policy.DCRPolicyChanges, 0, 2)
	if allowedAudiences != nil && !equalAudiences(allowedAudiences, current.AllowedAudiences) {
		v := append([]string(nil), (*allowedAudiences)...)
		changes = append(changes, policy.ChangeAllowedAudiences(&v))
	}
	if lifetime != nil && !equalLifetime(lifetime, current.RegistrationAccessTokenLifetime) {
		v := *lifetime
		changes = append(changes, policy.ChangeRegistrationAccessTokenLifetime(&v))
	}
	return changes
}

// OrgDCRPolicyWriteModel hydrates an org-scope DCR policy. It rebuilds
// the org-aggregate's `org.policy.dcr.*` event sequence so callers can
// detect prior override existence + tier-state.
type OrgDCRPolicyWriteModel struct {
	PolicyDCRWriteModel
}

func newOrgDCRPolicyWriteModel(orgID string) *OrgDCRPolicyWriteModel {
	return &OrgDCRPolicyWriteModel{
		PolicyDCRWriteModel{
			WriteModel: eventstore.WriteModel{
				AggregateID:   orgID,
				ResourceOwner: orgID,
			},
		},
	}
}

func (wm *OrgDCRPolicyWriteModel) AppendEvents(events ...eventstore.Event) {
	for _, event := range events {
		switch e := event.(type) {
		case *org.OrgDCRPolicyAddedEvent:
			wm.PolicyDCRWriteModel.AppendEvents(&e.DCRPolicyAddedEvent)
		case *org.OrgDCRPolicyChangedEvent:
			wm.PolicyDCRWriteModel.AppendEvents(&e.DCRPolicyChangedEvent)
		case *org.OrgDCRPolicyRemovedEvent:
			wm.PolicyDCRWriteModel.AppendEvents(&e.DCRPolicyRemovedEvent)
		}
	}
}

func (wm *OrgDCRPolicyWriteModel) Reduce() error {
	return wm.PolicyDCRWriteModel.Reduce()
}

func (wm *OrgDCRPolicyWriteModel) Query() *eventstore.SearchQueryBuilder {
	return eventstore.NewSearchQueryBuilder(eventstore.ColumnsEvent).
		ResourceOwner(wm.ResourceOwner).
		AddQuery().
		AggregateTypes(org.AggregateType).
		AggregateIDs(wm.PolicyDCRWriteModel.AggregateID).
		EventTypes(
			org.OrgDCRPolicyAddedEventType,
			org.OrgDCRPolicyChangedEventType,
			org.OrgDCRPolicyRemovedEventType,
		).
		Builder()
}
