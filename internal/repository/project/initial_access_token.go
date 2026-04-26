package project

import (
	"context"
	"fmt"
	"time"

	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// IAT (Initial Access Token) events scoped to the `project` aggregate.
//
// Why the project aggregate (and not a new top-level aggregate) — IATs
// are issued for a specific project's DCR usage, share the project's
// resource owner / instance, and the eventstore's per-aggregate
// sequence lock gives us free serialization for IAT operations on a
// given project (see cavekit-iat.md R7 — pinned in handler godoc by
// T-025).
//
// Wire-types are fixed by the cavekit and cannot change without an
// event-replay migration:
//
//	project.initial_access_token.added
//	project.initial_access_token.consumed
//	project.initial_access_token.revoked
//
// The Consumed event carries a per-slot `UniqueConstraint` of the form
// `iat_uses:<iat_id>:<use_index>` so the eventstore commit refuses
// double-consumption of the same slot. This is the authoritative
// race-safety primitive for cavekit-iat.md R2 — projection-level
// SELECT FOR UPDATE is NOT used.

const (
	initialAccessTokenEventTypePrefix = projectEventTypePrefix + "initial_access_token."

	InitialAccessTokenAddedType     = initialAccessTokenEventTypePrefix + "added"
	InitialAccessTokenConsumedType  = initialAccessTokenEventTypePrefix + "consumed"
	InitialAccessTokenRevokedType   = initialAccessTokenEventTypePrefix + "revoked"

	// IATSlotUniqueType is the eventstore unique-constraint table key
	// for per-use-slot constraints. The unique field is built as
	// `iat_uses:<iat_id>:<use_index>` so each IAT's slots live in a
	// disjoint namespace.
	IATSlotUniqueType = "iat_uses"

	// IATSlotErrMessage is the translation key returned when an
	// IATSlotUniqueType constraint collides — i.e., a parallel
	// consumer beat us to the same use_index.
	IATSlotErrMessage = "Errors.DCR.IAT.SlotAlreadyConsumed"
)

// InitialAccessTokenAddedEvent is emitted when an admin issues a new
// IAT via the admin gRPC RPC (T-022).
type InitialAccessTokenAddedEvent struct {
	eventstore.BaseEvent `json:"-"`

	// ID is the IAT identifier (NOT the plaintext token, which is
	// returned only at issue time). Stored on the projection row PK.
	ID string `json:"id"`
	// Hash is the Passwap-encoded hash of the plaintext token. Plaintext
	// is never persisted (cavekit-iat.md R5).
	Hash string `json:"hash"`
	// MaxUses caps consumption. 0 = unlimited (no UniqueConstraint per
	// slot; the Consumed event still emits for audit). Finite values
	// drive the per-slot UniqueConstraint enforcement.
	MaxUses int `json:"max_uses"`
	// ExpiresAt bounds the IAT's lifetime; nil = no expiry override
	// (admin RPC default lifetime applies — cavekit-config.md R1
	// InitialAccessToken.DefaultLifetime=24h).
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// ProjectID is denormalized onto the event so projection reducers
	// can build the (instance_id, project_id) index without a second
	// lookup.
	ProjectID                  string   `json:"project_id"`
	AllowedGrantTypes          []string `json:"allowed_grant_types,omitempty"`
	AllowedRedirectURIPatterns []string `json:"allowed_redirect_uri_patterns,omitempty"`
	Description                string   `json:"description,omitempty"`
}

func (e *InitialAccessTokenAddedEvent) Payload() interface{} { return e }

func (e *InitialAccessTokenAddedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

// SetBaseEvent is required by the eventstore.Command interface for
// generic event mappers.
func (e *InitialAccessTokenAddedEvent) SetBaseEvent(b *eventstore.BaseEvent) {
	e.BaseEvent = *b
}

func NewInitialAccessTokenAddedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	id, hash, projectID, description string,
	maxUses int,
	expiresAt *time.Time,
	allowedGrantTypes []string,
	allowedRedirectURIPatterns []string,
) *InitialAccessTokenAddedEvent {
	return &InitialAccessTokenAddedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			InitialAccessTokenAddedType,
		),
		ID:                         id,
		Hash:                       hash,
		MaxUses:                    maxUses,
		ExpiresAt:                  expiresAt,
		ProjectID:                  projectID,
		AllowedGrantTypes:          allowedGrantTypes,
		AllowedRedirectURIPatterns: allowedRedirectURIPatterns,
		Description:                description,
	}
}

func InitialAccessTokenAddedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &InitialAccessTokenAddedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	if err := event.Unmarshal(e); err != nil {
		return nil, zerrors.ThrowInternal(err, "PROJE-DCRi1", "unable to unmarshal initial_access_token.added")
	}
	return e, nil
}

// InitialAccessTokenConsumedEvent records consumption of one IAT use
// slot. For finite MaxUses, the per-slot UniqueConstraint provides
// the eventstore-level race guarantee.
type InitialAccessTokenConsumedEvent struct {
	eventstore.BaseEvent `json:"-"`

	// ID identifies the IAT (matches InitialAccessTokenAddedEvent.ID).
	ID string `json:"id"`
	// UseIndex is the 0-based slot being consumed. Each (ID, UseIndex)
	// pair is unique-per-instance via the IATSlotUniqueType constraint
	// when finite (constraints emitted only when finite=true).
	UseIndex int `json:"use_index"`
	// finite is set transiently by the constructor — when true, the
	// event declares a UniqueConstraint; when false (MaxUses=0), no
	// constraint is emitted and the consume always succeeds. The
	// flag is NOT serialized (it is reconstructed from MaxUses on
	// the live IAT row by the consume command, T-017).
	finite bool `json:"-"`
}

func (e *InitialAccessTokenConsumedEvent) Payload() interface{} { return e }

func (e *InitialAccessTokenConsumedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	if !e.finite {
		// MaxUses=0 (unlimited): duplicate-slot collisions are benign,
		// so no constraint is declared.
		return nil
	}
	return []*eventstore.UniqueConstraint{
		eventstore.NewAddEventUniqueConstraint(
			IATSlotUniqueType,
			fmt.Sprintf("%s:%d", e.ID, e.UseIndex),
			IATSlotErrMessage,
		),
	}
}

func (e *InitialAccessTokenConsumedEvent) SetBaseEvent(b *eventstore.BaseEvent) {
	e.BaseEvent = *b
}

// NewInitialAccessTokenConsumedEvent emits a consume event. `finite`
// SHOULD be true when MaxUses>0 — the consume command at T-017 reads
// MaxUses from the projection and passes it through. When false
// (MaxUses=0), no UniqueConstraint is declared.
func NewInitialAccessTokenConsumedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	id string,
	useIndex int,
	finite bool,
) *InitialAccessTokenConsumedEvent {
	return &InitialAccessTokenConsumedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			InitialAccessTokenConsumedType,
		),
		ID:       id,
		UseIndex: useIndex,
		finite:   finite,
	}
}

func InitialAccessTokenConsumedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &InitialAccessTokenConsumedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	if err := event.Unmarshal(e); err != nil {
		return nil, zerrors.ThrowInternal(err, "PROJE-DCRi2", "unable to unmarshal initial_access_token.consumed")
	}
	return e, nil
}

// InitialAccessTokenRevokedEvent marks an IAT as revoked; subsequent
// consumes from any source MUST refuse pre-push (T-017). Carries no
// UniqueConstraint — revocation is idempotent at the projection.
type InitialAccessTokenRevokedEvent struct {
	eventstore.BaseEvent `json:"-"`

	ID string `json:"id"`
}

func (e *InitialAccessTokenRevokedEvent) Payload() interface{} { return e }

func (e *InitialAccessTokenRevokedEvent) UniqueConstraints() []*eventstore.UniqueConstraint {
	return nil
}

func (e *InitialAccessTokenRevokedEvent) SetBaseEvent(b *eventstore.BaseEvent) {
	e.BaseEvent = *b
}

func NewInitialAccessTokenRevokedEvent(
	ctx context.Context,
	aggregate *eventstore.Aggregate,
	id string,
) *InitialAccessTokenRevokedEvent {
	return &InitialAccessTokenRevokedEvent{
		BaseEvent: *eventstore.NewBaseEventForPush(
			ctx,
			aggregate,
			InitialAccessTokenRevokedType,
		),
		ID: id,
	}
}

func InitialAccessTokenRevokedEventMapper(event eventstore.Event) (eventstore.Event, error) {
	e := &InitialAccessTokenRevokedEvent{
		BaseEvent: *eventstore.BaseEventFromRepo(event),
	}
	if err := event.Unmarshal(e); err != nil {
		return nil, zerrors.ThrowInternal(err, "PROJE-DCRi3", "unable to unmarshal initial_access_token.revoked")
	}
	return e, nil
}
