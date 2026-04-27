package project

import (
	"context"
	"time"

	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// Dynamic Client Registration audit + RAT events. Cavekit
// register-handler.md R6 specifies these are emitted by RegisterClient
// (T-040) AFTER the existing ApplicationAddedEvent + OIDCConfigAddedEvent.
// Both events live on the project aggregate alongside the rest of the
// application-config events; reuse OIDCApplicationWriteModel — no new
// write model.
const (
	ApplicationDynamicallyRegisteredType         = applicationEventTypePrefix + "dynamically_registered"
	ApplicationRegistrationAccessTokenSetType    = applicationEventTypePrefix + "registration_access_token.set"
)

// ApplicationDynamicallyRegisteredEvent records the audit context
// captured at /oidc/v1/register time: which IAT was consumed (if any),
// software_statement provenance (Phase 2), the registration method
// (anonymous vs IAT), the un-clamped client_name the caller originally
// sent (for support / fraud review), the SHA-256 of the remote IP
// (NEVER plaintext IP — privacy), and the User-Agent string.
type ApplicationDynamicallyRegisteredEvent struct {
	eventstore.BaseEvent `json:"-"`

	AppID                string         `json:"appId"`
	InitialAccessTokenID string         `json:"initialAccessTokenId,omitempty"`
	SoftwareStatementJTI string         `json:"softwareStatementJti,omitempty"`
	RegistrationMethod   string         `json:"registrationMethod"`
	ClientNameUnclamped  string         `json:"clientNameUnclamped,omitempty"`
	RemoteAddrSHA256     string         `json:"remoteAddrSha256,omitempty"`
	UserAgent            string         `json:"userAgent,omitempty"`
	// DCRMeta carries the RFC 7591 §2 pass-through fields (contacts,
	// logo_uri, client_uri, policy_uri, tos_uri, software_id,
	// software_version, default_max_age, require_auth_time,
	// default_acr_values, initiate_login_uri, scope) per
	// cavekit-register-handler.md R6 AC. Stored here on the audit
	// event so the projection (T-041) can write it to the apps7
	// dcr_meta JSONB column without altering the existing
	// OIDCConfigAddedEvent payload — additive (json:omitempty), older
	// events unmarshal with DCRMeta=nil.
	DCRMeta map[string]any `json:"dcrMeta,omitempty"`
}

func (e *ApplicationDynamicallyRegisteredEvent) Payload() interface{} {
	return e
}

func (e *ApplicationDynamicallyRegisteredEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewApplicationDynamicallyRegisteredEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	appID string,
	initialAccessTokenID string,
	softwareStatementJTI string,
	registrationMethod string,
	clientNameUnclamped string,
	remoteAddrSHA256 string,
	userAgent string,
	dcrMeta map[string]any,
) *ApplicationDynamicallyRegisteredEvent {
	return &ApplicationDynamicallyRegisteredEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			ApplicationDynamicallyRegisteredType,
		),
		AppID:                appID,
		InitialAccessTokenID: initialAccessTokenID,
		SoftwareStatementJTI: softwareStatementJTI,
		RegistrationMethod:   registrationMethod,
		ClientNameUnclamped:  clientNameUnclamped,
		RemoteAddrSHA256:     remoteAddrSHA256,
		UserAgent:            userAgent,
		DCRMeta:              dcrMeta,
	}
}

func ApplicationDynamicallyRegisteredEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &ApplicationDynamicallyRegisteredEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	if err := event.Unmarshal(e); err != nil {
		return nil, zerrors.ThrowInternal(err, "DCR-d8K3a", "unable to unmarshal application dynamically registered")
	}
	return e, nil
}

// ApplicationRegistrationAccessTokenSetEvent stores the Passwap-encoded
// RAT hash for an application. Carries ExpiresAt (zero-valued time.Time
// means no expiry — RFC 7591 §3.2.1 sentinel `client_secret_expires_at=0`
// has the same convention for RATs by extension since the RAT lifetime is
// orthogonal to the secret lifetime). Plaintext NEVER touches the event
// stream.
type ApplicationRegistrationAccessTokenSetEvent struct {
	eventstore.BaseEvent `json:"-"`

	AppID       string    `json:"appId"`
	HashedToken string    `json:"hashedToken"`
	ExpiresAt   time.Time `json:"expiresAt,omitempty"`
}

func (e *ApplicationRegistrationAccessTokenSetEvent) Payload() interface{} {
	return e
}

func (e *ApplicationRegistrationAccessTokenSetEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewApplicationRegistrationAccessTokenSetEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	appID string,
	hashedToken string,
	expiresAt time.Time,
) *ApplicationRegistrationAccessTokenSetEvent {
	return &ApplicationRegistrationAccessTokenSetEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			ApplicationRegistrationAccessTokenSetType,
		),
		AppID:       appID,
		HashedToken: hashedToken,
		ExpiresAt:   expiresAt,
	}
}

func ApplicationRegistrationAccessTokenSetEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &ApplicationRegistrationAccessTokenSetEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	if err := event.Unmarshal(e); err != nil {
		return nil, zerrors.ThrowInternal(err, "DCR-r4Tp1", "unable to unmarshal application registration access token set")
	}
	return e, nil
}
