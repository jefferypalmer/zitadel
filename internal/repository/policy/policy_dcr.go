package policy

import (
	"time"

	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/zerrors"
)

const (
	DCRPolicyAddedEventType   = "policy.dcr.added"
	DCRPolicyChangedEventType = "policy.dcr.changed"
	DCRPolicyRemovedEventType = "policy.dcr.removed"
)

type DCRPolicyAddedEvent struct {
	eventstore.BaseEvent `json:"-"`

	AllowedAudiences               *[]string      `json:"allowed_audiences,omitempty"`
	RegistrationAccessTokenLifetime *time.Duration `json:"registration_access_token_lifetime,omitempty"`
}

func (e *DCRPolicyAddedEvent) Payload() interface{} {
	return e
}

func (e *DCRPolicyAddedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewDCRPolicyAddedEvent(
	base *eventstore.BaseEvent,
	allowedAudiences *[]string,
	registrationAccessTokenLifetime *time.Duration,
) *DCRPolicyAddedEvent {
	return &DCRPolicyAddedEvent{
		BaseEvent:                       *base,
		AllowedAudiences:                allowedAudiences,
		RegistrationAccessTokenLifetime: registrationAccessTokenLifetime,
	}
}

func DCRPolicyAddedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &DCRPolicyAddedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}

	if err := event.Unmarshal(e); err != nil {
		return nil, zerrors.ThrowInternal(err, "POLIC-DcRA1", "unable to unmarshal dcr policy")
	}

	return e, nil
}

type DCRPolicyChangedEvent struct {
	eventstore.BaseEvent `json:"-"`

	AllowedAudiences               *[]string      `json:"allowed_audiences,omitempty"`
	RegistrationAccessTokenLifetime *time.Duration `json:"registration_access_token_lifetime,omitempty"`
}

func (e *DCRPolicyChangedEvent) Payload() interface{} {
	return e
}

func (e *DCRPolicyChangedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

type DCRPolicyChanges func(*DCRPolicyChangedEvent)

func NewDCRPolicyChangedEvent(
	base *eventstore.BaseEvent,
	changes []DCRPolicyChanges,
) (*DCRPolicyChangedEvent, error) {
	if len(changes) == 0 {
		return nil, zerrors.ThrowPreconditionFailed(nil, "POLIC-DcRC1", "Errors.NoChangesFound")
	}
	changeEvent := &DCRPolicyChangedEvent{
		BaseEvent: *base,
	}
	for _, change := range changes {
		change(changeEvent)
	}
	return changeEvent, nil
}

func ChangeAllowedAudiences(allowedAudiences *[]string) func(*DCRPolicyChangedEvent) {
	return func(e *DCRPolicyChangedEvent) {
		e.AllowedAudiences = allowedAudiences
	}
}

func ChangeRegistrationAccessTokenLifetime(lifetime *time.Duration) func(*DCRPolicyChangedEvent) {
	return func(e *DCRPolicyChangedEvent) {
		e.RegistrationAccessTokenLifetime = lifetime
	}
}

func DCRPolicyChangedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &DCRPolicyChangedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}

	if err := event.Unmarshal(e); err != nil {
		return nil, zerrors.ThrowInternal(err, "POLIC-DcRC2", "unable to unmarshal dcr policy")
	}

	return e, nil
}

type DCRPolicyRemovedEvent struct {
	eventstore.BaseEvent `json:"-"`
}

func (e *DCRPolicyRemovedEvent) Payload() interface{} {
	return nil
}

func (e *DCRPolicyRemovedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewDCRPolicyRemovedEvent(base *eventstore.BaseEvent) *DCRPolicyRemovedEvent {
	return &DCRPolicyRemovedEvent{
		BaseEvent: *base,
	}
}

func DCRPolicyRemovedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	return &DCRPolicyRemovedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}, nil
}
