package instance

import (
	"context"
	"time"

	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/policy"
)

var (
	InstanceDCRPolicyAddedEventType   = instanceEventTypePrefix + policy.DCRPolicyAddedEventType
	InstanceDCRPolicyChangedEventType = instanceEventTypePrefix + policy.DCRPolicyChangedEventType
)

type InstanceDCRPolicyAddedEvent struct {
	policy.DCRPolicyAddedEvent
}

func NewInstanceDCRPolicyAddedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	allowedAudiences *[]string,
	registrationAccessTokenLifetime *time.Duration,
) *InstanceDCRPolicyAddedEvent {
	return &InstanceDCRPolicyAddedEvent{
		DCRPolicyAddedEvent: *policy.NewDCRPolicyAddedEvent(
			eventstore.NewBaseEventForPush(
				ctx,
				aggregate,
				InstanceDCRPolicyAddedEventType),
			allowedAudiences,
			registrationAccessTokenLifetime,
		),
	}
}

func InstanceDCRPolicyAddedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e, err := policy.DCRPolicyAddedEventMapper(event)
	if err != nil {
		return nil, err
	}
	return &InstanceDCRPolicyAddedEvent{DCRPolicyAddedEvent: *e.(*policy.DCRPolicyAddedEvent)}, nil
}

type InstanceDCRPolicyChangedEvent struct {
	policy.DCRPolicyChangedEvent
}

func NewInstanceDCRPolicyChangedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	changes []policy.DCRPolicyChanges,
) (*InstanceDCRPolicyChangedEvent, error) {
	changedEvent, err := policy.NewDCRPolicyChangedEvent(
		eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			InstanceDCRPolicyChangedEventType),
		changes,
	)
	if err != nil {
		return nil, err
	}
	return &InstanceDCRPolicyChangedEvent{DCRPolicyChangedEvent: *changedEvent}, nil
}

func InstanceDCRPolicyChangedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e, err := policy.DCRPolicyChangedEventMapper(event)
	if err != nil {
		return nil, err
	}
	return &InstanceDCRPolicyChangedEvent{DCRPolicyChangedEvent: *e.(*policy.DCRPolicyChangedEvent)}, nil
}
