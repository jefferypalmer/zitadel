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
	ApplicationDynamicallyRegisteredType            = applicationEventTypePrefix + "dynamically_registered"
	ApplicationRegistrationAccessTokenSetType       = applicationEventTypePrefix + "registration_access_token.set"
	// ApplicationRegistrationAccessTokenRehashedType records a silent
	// re-hash of the RAT after the configured Passwap algorithm rotated
	// (cavekit-manage-handler.md R2). Distinct from the `.set` event so
	// audit logs can distinguish "operator rotated the algorithm" from
	// "operator issued the RAT initially" or "operator PUT a new RAT
	// (T-055 .rotated)". Plaintext is unchanged; the projection updates
	// the stored Passwap-encoded hash only.
	ApplicationRegistrationAccessTokenRehashedType = applicationEventTypePrefix + "registration_access_token.rehashed"
	// ApplicationRegistrationAccessTokenRotatedType records a RFC 7592
	// PUT-side rotation of the RAT (cavekit-manage-handler.md R5 /
	// T-055). Distinct wire-type from `.set` and `.rehashed` so audit
	// logs separate the three operator actions:
	//   - `.set`       → operator created the RAT at registration time
	//   - `.rehashed`  → operator rotated the Passwap algorithm; the
	//                    plaintext is unchanged.
	//   - `.rotated`   → operator (or the caller) issued a NEW plaintext
	//                    RAT via successful PUT; the previous plaintext
	//                    is immediately invalid.
	// The projection reducer for this event updates BOTH the hash column
	// AND the expires_at column so a PUT can extend / shrink the RAT
	// lifetime atomically with the rotation.
	ApplicationRegistrationAccessTokenRotatedType = applicationEventTypePrefix + "registration_access_token.rotated"
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

// ApplicationRegistrationAccessTokenRehashedEvent records a silent
// re-hash of an existing RAT (cavekit-manage-handler.md R2). Emitted
// when the manage handler verifies a presented RAT and Passwap returns
// a non-empty `updatedHash` (algorithm rotated since the RAT was last
// stored). The plaintext remains unchanged; the operator action is
// invisible to the client. Same shape as
// [ApplicationRegistrationAccessTokenSetEvent] minus ExpiresAt — a
// silent rehash MUST NOT alter the RAT lifetime.
type ApplicationRegistrationAccessTokenRehashedEvent struct {
	eventstore.BaseEvent `json:"-"`

	AppID       string `json:"appId"`
	HashedToken string `json:"hashedToken"`
}

func (e *ApplicationRegistrationAccessTokenRehashedEvent) Payload() interface{} {
	return e
}

func (e *ApplicationRegistrationAccessTokenRehashedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewApplicationRegistrationAccessTokenRehashedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	appID string,
	hashedToken string,
) *ApplicationRegistrationAccessTokenRehashedEvent {
	return &ApplicationRegistrationAccessTokenRehashedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			ApplicationRegistrationAccessTokenRehashedType,
		),
		AppID:       appID,
		HashedToken: hashedToken,
	}
}

func ApplicationRegistrationAccessTokenRehashedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &ApplicationRegistrationAccessTokenRehashedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	if err := event.Unmarshal(e); err != nil {
		return nil, zerrors.ThrowInternal(err, "DCR-r4Tp2", "unable to unmarshal application registration access token rehashed")
	}
	return e, nil
}

// ApplicationRegistrationAccessTokenRotatedEvent records a RFC 7592
// PUT-side RAT rotation (cavekit-manage-handler.md R5 / T-055). Carries
// the new Passwap-encoded hash AND the new expires_at — same shape as
// [ApplicationRegistrationAccessTokenSetEvent] but a distinct
// wire-type so audit consumers can distinguish "first issuance" from
// "post-update rotation". Plaintext NEVER touches the event stream;
// the new plaintext is returned to the caller in the PUT response body
// exactly once.
//
// Old-RAT invalidation falls out of the projection reducer overwriting
// the stored hash column — the next VerifyRAT against the presented old
// plaintext fails on the Passwap.Verify step (no extra revocation
// event needed).
type ApplicationRegistrationAccessTokenRotatedEvent struct {
	eventstore.BaseEvent `json:"-"`

	AppID       string    `json:"appId"`
	HashedToken string    `json:"hashedToken"`
	ExpiresAt   time.Time `json:"expiresAt,omitempty"`
}

func (e *ApplicationRegistrationAccessTokenRotatedEvent) Payload() interface{} {
	return e
}

func (e *ApplicationRegistrationAccessTokenRotatedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func NewApplicationRegistrationAccessTokenRotatedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	appID string,
	hashedToken string,
	expiresAt time.Time,
) *ApplicationRegistrationAccessTokenRotatedEvent {
	return &ApplicationRegistrationAccessTokenRotatedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			ApplicationRegistrationAccessTokenRotatedType,
		),
		AppID:       appID,
		HashedToken: hashedToken,
		ExpiresAt:   expiresAt,
	}
}

func ApplicationRegistrationAccessTokenRotatedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &ApplicationRegistrationAccessTokenRotatedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	if err := event.Unmarshal(e); err != nil {
		return nil, zerrors.ThrowInternal(err, "DCR-r4Tp3", "unable to unmarshal application registration access token rotated")
	}
	return e, nil
}
