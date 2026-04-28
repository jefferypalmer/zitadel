package project

import (
	"context"

	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// Inline JWKS events (cavekit-inline-jwks.md R3 / T-016). Three wire
// types separate the operator audit story:
//
//   - `oidc_config.jwks.inline.set`     — initial transition from no
//     stored JWKS (or from `jwks_uri`) to inline `jwks`.
//   - `oidc_config.jwks.inline.changed` — change of an already-stored
//     inline JWK Set (key rotation via RFC 7592 PUT).
//   - `oidc_config.jwks.inline.removed` — clear stored inline `jwks`
//     (PUT with neither field, or PUT switching to `jwks_uri`).
//
// Storage-time mutual-exclusion (kit R3 last bullet): when the reducer
// applies `.set`, it MUST clear any prior `jwks_uri` value in the same
// transaction. Phase 1 has no `jwks_uri` projection column yet, so the
// current reducer only writes `jwks_inline` — when the `jwks_uri`
// column lands the reducer must extend its UPDATE statement to NULL it
// out for `.set` and to NULL `jwks_inline` for any future `jwks_uri.set`
// counterpart event.
const (
	ApplicationOIDCConfigJwksInlineSetType     = applicationEventTypePrefix + "oidc_config.jwks.inline.set"
	ApplicationOIDCConfigJwksInlineChangedType = applicationEventTypePrefix + "oidc_config.jwks.inline.changed"
	ApplicationOIDCConfigJwksInlineRemovedType = applicationEventTypePrefix + "oidc_config.jwks.inline.removed"
)

// ApplicationOIDCConfigJwksInlineSetEvent records the initial / mutual-
// exclusion-clearing set of an inline JWK Set. JwksInline carries the
// canonical sorted-key bytes returned by jwks_inline.Validate (T-007).
type ApplicationOIDCConfigJwksInlineSetEvent struct {
	eventstore.BaseEvent `json:"-"`

	AppID       string `json:"appId"`
	JwksInline  []byte `json:"jwksInline,omitempty"`
}

func (e *ApplicationOIDCConfigJwksInlineSetEvent) Payload() interface{} {
	return e
}

func (e *ApplicationOIDCConfigJwksInlineSetEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewApplicationOIDCConfigJwksInlineSetEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	appID string,
	jwksInline []byte,
) *ApplicationOIDCConfigJwksInlineSetEvent {
	return &ApplicationOIDCConfigJwksInlineSetEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			ApplicationOIDCConfigJwksInlineSetType,
		),
		AppID:      appID,
		JwksInline: jwksInline,
	}
}

func ApplicationOIDCConfigJwksInlineSetEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &ApplicationOIDCConfigJwksInlineSetEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	if err := event.Unmarshal(e); err != nil {
		return nil, zerrors.ThrowInternal(err, "OIDCC-Jw0S1", "unable to unmarshal jwks inline set event")
	}
	return e, nil
}

// ApplicationOIDCConfigJwksInlineChangedEvent records key rotation
// where the row already stored an inline JWK Set. Distinct from `.set`
// so audit logs separate "first set" from "subsequent change".
type ApplicationOIDCConfigJwksInlineChangedEvent struct {
	eventstore.BaseEvent `json:"-"`

	AppID      string `json:"appId"`
	JwksInline []byte `json:"jwksInline,omitempty"`
}

func (e *ApplicationOIDCConfigJwksInlineChangedEvent) Payload() interface{} {
	return e
}

func (e *ApplicationOIDCConfigJwksInlineChangedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewApplicationOIDCConfigJwksInlineChangedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	appID string,
	jwksInline []byte,
) *ApplicationOIDCConfigJwksInlineChangedEvent {
	return &ApplicationOIDCConfigJwksInlineChangedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			ApplicationOIDCConfigJwksInlineChangedType,
		),
		AppID:      appID,
		JwksInline: jwksInline,
	}
}

func ApplicationOIDCConfigJwksInlineChangedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &ApplicationOIDCConfigJwksInlineChangedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	if err := event.Unmarshal(e); err != nil {
		return nil, zerrors.ThrowInternal(err, "OIDCC-Jw0C1", "unable to unmarshal jwks inline changed event")
	}
	return e, nil
}

// ApplicationOIDCConfigJwksInlineRemovedEvent records clearing the
// stored inline JWK Set (PUT with neither field, or PUT switching to
// `jwks_uri` — the reducer NULLs the `jwks_inline` column).
type ApplicationOIDCConfigJwksInlineRemovedEvent struct {
	eventstore.BaseEvent `json:"-"`

	AppID string `json:"appId"`
}

func (e *ApplicationOIDCConfigJwksInlineRemovedEvent) Payload() interface{} {
	return e
}

func (e *ApplicationOIDCConfigJwksInlineRemovedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewApplicationOIDCConfigJwksInlineRemovedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	appID string,
) *ApplicationOIDCConfigJwksInlineRemovedEvent {
	return &ApplicationOIDCConfigJwksInlineRemovedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			ApplicationOIDCConfigJwksInlineRemovedType,
		),
		AppID: appID,
	}
}

func ApplicationOIDCConfigJwksInlineRemovedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &ApplicationOIDCConfigJwksInlineRemovedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	if err := event.Unmarshal(e); err != nil {
		return nil, zerrors.ThrowInternal(err, "OIDCC-Jw0R1", "unable to unmarshal jwks inline removed event")
	}
	return e, nil
}
