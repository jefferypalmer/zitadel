package command

import (
	"context"
	"time"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/instance"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// SetInstanceDCRPolicy creates the instance-default DCR policy
// (cavekit-org-dcr-policy.md R1 / T-012). Per-org overrides resolve
// against this row via cavekit-org-dcr-policy.md R3 (T-017).
func (c *Commands) SetInstanceDCRPolicy(
	ctx context.Context,
	allowedAudiences *[]string,
	registrationAccessTokenLifetime *time.Duration,
) (_ *domain.ObjectDetails, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	wm, err := c.instanceDCRPolicyWriteModel(ctx)
	if err != nil {
		return nil, err
	}
	if wm.State == domain.PolicyStateActive {
		return nil, zerrors.ThrowAlreadyExists(nil, "INST-DcR01", "Errors.Instance.DCRPolicy.AlreadyExists")
	}
	instanceAgg := instance.NewAggregate(authz.GetInstance(ctx).InstanceID())
	pushedEvents, err := c.eventstore.Push(ctx,
		instance.NewInstanceDCRPolicyAddedEvent(ctx, &instanceAgg.Aggregate, allowedAudiences, registrationAccessTokenLifetime),
	)
	if err != nil {
		return nil, err
	}
	return pushedEventsToObjectDetails(pushedEvents), nil
}

// UpdateInstanceDCRPolicy mutates the instance-default DCR policy.
// `nil` arguments mean "no change for this field". The instance default
// has no Reset/Remove — narrowing the allow-list or lifetime tier is
// the operator's mechanism for reverting. cavekit-org-dcr-policy.md R5
// requires the cap check to use the EFFECTIVE instance default at
// command time; child orgs whose override is now out-of-bounds must be
// brought back into bounds before their next update.
func (c *Commands) UpdateInstanceDCRPolicy(
	ctx context.Context,
	allowedAudiences *[]string,
	registrationAccessTokenLifetime *time.Duration,
) (_ *domain.ObjectDetails, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	wm, err := c.instanceDCRPolicyWriteModel(ctx)
	if err != nil {
		return nil, err
	}
	if !wm.State.Exists() {
		return nil, zerrors.ThrowNotFound(nil, "INST-DcR02", "Errors.Instance.DCRPolicy.NotFound")
	}

	changes := buildDCRPolicyChanges(&wm.PolicyDCRWriteModel,
		allowedAudiences, registrationAccessTokenLifetime)
	if len(changes) == 0 {
		return nil, zerrors.ThrowPreconditionFailed(nil, "INST-DcR03", "Errors.NoChangesFound")
	}

	instanceAgg := instance.NewAggregate(authz.GetInstance(ctx).InstanceID())
	changedEvent, err := instance.NewInstanceDCRPolicyChangedEvent(ctx, &instanceAgg.Aggregate, changes)
	if err != nil {
		return nil, err
	}
	pushedEvents, err := c.eventstore.Push(ctx, changedEvent)
	if err != nil {
		return nil, err
	}
	return pushedEventsToObjectDetails(pushedEvents), nil
}

func (c *Commands) instanceDCRPolicyWriteModel(ctx context.Context) (_ *InstanceDCRPolicyWriteModel, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	wm := newInstanceDCRPolicyWriteModel(ctx)
	if err = c.eventstore.FilterToQueryReducer(ctx, wm); err != nil {
		return nil, err
	}
	return wm, nil
}

// InstanceDCRPolicyWriteModel hydrates the instance-default DCR policy
// from the instance-aggregate `instance.policy.dcr.*` event sequence.
type InstanceDCRPolicyWriteModel struct {
	PolicyDCRWriteModel
}

func newInstanceDCRPolicyWriteModel(ctx context.Context) *InstanceDCRPolicyWriteModel {
	id := authz.GetInstance(ctx).InstanceID()
	return &InstanceDCRPolicyWriteModel{
		PolicyDCRWriteModel{
			WriteModel: eventstore.WriteModel{
				AggregateID:   id,
				ResourceOwner: id,
			},
		},
	}
}

func (wm *InstanceDCRPolicyWriteModel) AppendEvents(events ...eventstore.Event) {
	for _, event := range events {
		switch e := event.(type) {
		case *instance.InstanceDCRPolicyAddedEvent:
			wm.PolicyDCRWriteModel.AppendEvents(&e.DCRPolicyAddedEvent)
		case *instance.InstanceDCRPolicyChangedEvent:
			wm.PolicyDCRWriteModel.AppendEvents(&e.DCRPolicyChangedEvent)
		}
	}
}

func (wm *InstanceDCRPolicyWriteModel) Reduce() error {
	return wm.PolicyDCRWriteModel.Reduce()
}

func (wm *InstanceDCRPolicyWriteModel) Query() *eventstore.SearchQueryBuilder {
	return eventstore.NewSearchQueryBuilder(eventstore.ColumnsEvent).
		ResourceOwner(wm.ResourceOwner).
		AddQuery().
		AggregateTypes(instance.AggregateType).
		AggregateIDs(wm.PolicyDCRWriteModel.AggregateID).
		EventTypes(
			instance.InstanceDCRPolicyAddedEventType,
			instance.InstanceDCRPolicyChangedEventType,
		).
		Builder()
}
