package org

import (
	"context"
	"time"

	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/policy"
)

var (
	OrgDCRPolicyAddedEventType   = orgEventTypePrefix + policy.DCRPolicyAddedEventType
	OrgDCRPolicyChangedEventType = orgEventTypePrefix + policy.DCRPolicyChangedEventType
	OrgDCRPolicyRemovedEventType = orgEventTypePrefix + policy.DCRPolicyRemovedEventType
)

type OrgDCRPolicyAddedEvent struct {
	policy.DCRPolicyAddedEvent
}

func NewOrgDCRPolicyAddedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	allowedAudiences *[]string,
	registrationAccessTokenLifetime *time.Duration,
) *OrgDCRPolicyAddedEvent {
	return &OrgDCRPolicyAddedEvent{
		DCRPolicyAddedEvent: *policy.NewDCRPolicyAddedEvent(
			eventstore.NewBaseEventForPush(
				ctx,
				aggregate,
				OrgDCRPolicyAddedEventType),
			allowedAudiences,
			registrationAccessTokenLifetime,
		),
	}
}

func OrgDCRPolicyAddedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e, err := policy.DCRPolicyAddedEventMapper(event)
	if err != nil {
		return nil, err
	}
	return &OrgDCRPolicyAddedEvent{DCRPolicyAddedEvent: *e.(*policy.DCRPolicyAddedEvent)}, nil
}

type OrgDCRPolicyChangedEvent struct {
	policy.DCRPolicyChangedEvent
}

func NewOrgDCRPolicyChangedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	changes []policy.DCRPolicyChanges,
) (*OrgDCRPolicyChangedEvent, error) {
	changedEvent, err := policy.NewDCRPolicyChangedEvent(
		eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			OrgDCRPolicyChangedEventType),
		changes,
	)
	if err != nil {
		return nil, err
	}
	return &OrgDCRPolicyChangedEvent{DCRPolicyChangedEvent: *changedEvent}, nil
}

func OrgDCRPolicyChangedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e, err := policy.DCRPolicyChangedEventMapper(event)
	if err != nil {
		return nil, err
	}
	return &OrgDCRPolicyChangedEvent{DCRPolicyChangedEvent: *e.(*policy.DCRPolicyChangedEvent)}, nil
}

type OrgDCRPolicyRemovedEvent struct {
	policy.DCRPolicyRemovedEvent
}

func NewOrgDCRPolicyRemovedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
) *OrgDCRPolicyRemovedEvent {
	return &OrgDCRPolicyRemovedEvent{
		DCRPolicyRemovedEvent: *policy.NewDCRPolicyRemovedEvent(
			eventstore.NewBaseEventForPush(
				ctx,
				aggregate,
				OrgDCRPolicyRemovedEventType),
		),
	}
}

func OrgDCRPolicyRemovedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e, err := policy.DCRPolicyRemovedEventMapper(event)
	if err != nil {
		return nil, err
	}
	return &OrgDCRPolicyRemovedEvent{DCRPolicyRemovedEvent: *e.(*policy.DCRPolicyRemovedEvent)}, nil
}
