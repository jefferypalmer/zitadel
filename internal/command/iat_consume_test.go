package command

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/project"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// iatAgg builds the project aggregate the consume command produces:
// project.NewAggregate(projectID, instanceID) defaults ResourceOwner
// to instanceID, but ConsumeInitialAccessToken overrides it with the
// IATSnapshot's ResourceOwner. Test fixtures must do the same so the
// expected event matches what reaches the eventstore.
func iatAgg(projectID, instanceID, ro string) *eventstore.Aggregate {
	a := project.NewAggregate(projectID, instanceID).Aggregate
	a.ResourceOwner = ro
	return &a
}

// TestConsumeInitialAccessToken_HappyPath pins R2 AC: a non-revoked,
// non-expired, non-exhausted IAT consume succeeds with slot==UsesConsumed
// and pushes a Consumed event with finite=true (since MaxUses>0).
func TestConsumeInitialAccessToken_HappyPath(t *testing.T) {
	ctx := context.Background()
	consumed := project.NewInitialAccessTokenConsumedEvent(
		ctx,
		iatAgg("proj-1", "instance-1", "ro-1"),
		"iat-1", 1, true,
	)
	c := &Commands{
		eventstore: eventstoreExpect(t,
			expectPush(consumed),
		),
	}

	lookups := 0
	lookup := func(ctx context.Context) (*IATSnapshot, error) {
		lookups++
		return &IATSnapshot{
			ID: "iat-1", ProjectID: "proj-1", InstanceID: "instance-1", ResourceOwner: "ro-1",
			MaxUses: 3, UsesConsumed: 1, Revoked: false,
		}, nil
	}
	slot, err := c.ConsumeInitialAccessToken(ctx, lookup)
	require.NoError(t, err)
	assert.Equal(t, 1, slot)
	assert.Equal(t, 1, lookups, "happy path should re-fetch projection exactly once")
}

// TestConsumeInitialAccessToken_Revoked pins R2 AC2: revoked IAT fails
// before pushing.
func TestConsumeInitialAccessToken_Revoked(t *testing.T) {
	c := &Commands{eventstore: eventstoreExpect(t)}
	_, err := c.ConsumeInitialAccessToken(context.Background(), func(context.Context) (*IATSnapshot, error) {
		return &IATSnapshot{ID: "iat-1", Revoked: true}, nil
	})
	require.Error(t, err)
	assert.True(t, zerrors.IsErrorInvalidArgument(err))
	assert.Contains(t, err.Error(), "Errors.DCR.IAT.Revoked")
}

// TestConsumeInitialAccessToken_Expired pins R2 AC2.
func TestConsumeInitialAccessToken_Expired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	c := &Commands{eventstore: eventstoreExpect(t)}
	_, err := c.ConsumeInitialAccessToken(context.Background(), func(context.Context) (*IATSnapshot, error) {
		return &IATSnapshot{ID: "iat-1", ProjectID: "proj-1", InstanceID: "instance-1", MaxUses: 3, ExpiresAt: &past}, nil
	})
	require.Error(t, err)
	assert.True(t, zerrors.IsErrorInvalidArgument(err))
	assert.Contains(t, err.Error(), "Errors.DCR.IAT.Expired")
}

// TestConsumeInitialAccessToken_Exhausted_PrePush pins R2 AC: when the
// projection reports all N slots consumed, consume fails before push
// with the same Exhausted error the post-3-retry path uses.
func TestConsumeInitialAccessToken_Exhausted_PrePush(t *testing.T) {
	c := &Commands{eventstore: eventstoreExpect(t)}
	_, err := c.ConsumeInitialAccessToken(context.Background(), func(context.Context) (*IATSnapshot, error) {
		return &IATSnapshot{ID: "iat-1", ProjectID: "proj-1", InstanceID: "instance-1", MaxUses: 3, UsesConsumed: 3}, nil
	})
	require.Error(t, err)
	assert.True(t, zerrors.IsErrorInvalidArgument(err))
	assert.Contains(t, err.Error(), "Errors.DCR.IAT.Exhausted")
}

// TestConsumeInitialAccessToken_Unlimited pins R2 AC6: max_uses=0 means
// finite=false → no UniqueConstraint on the consume event → push is
// guaranteed to succeed regardless of UsesConsumed value.
func TestConsumeInitialAccessToken_Unlimited(t *testing.T) {
	ctx := context.Background()
	// MaxUses=0, UsesConsumed=42 — for a finite IAT this would be
	// exhausted, but unlimited IATs ignore the cap.
	consumed := project.NewInitialAccessTokenConsumedEvent(
		ctx,
		iatAgg("proj-1", "instance-1", "ro-1"),
		"iat-1", 42, false,
	)
	c := &Commands{eventstore: eventstoreExpect(t, expectPush(consumed))}
	slot, err := c.ConsumeInitialAccessToken(ctx, func(context.Context) (*IATSnapshot, error) {
		return &IATSnapshot{
			ID: "iat-1", ProjectID: "proj-1", InstanceID: "instance-1", ResourceOwner: "ro-1",
			MaxUses: 0, UsesConsumed: 42,
		}, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 42, slot)
}

// TestConsumeInitialAccessToken_RetriesAfterAlreadyExists pins R2 AC4:
// on AlreadyExists from the eventstore, the command re-fetches the
// projection and retries with the updated slot index. After 3 total
// AlreadyExists collisions in a row, fail with Exhausted.
func TestConsumeInitialAccessToken_RetriesAfterAlreadyExists(t *testing.T) {
	ctx := context.Background()
	// Simulate three concurrent winners: every push collides; the
	// projection moves forward by 1 between each retry.
	pushes := []eventstore.Command{
		project.NewInitialAccessTokenConsumedEvent(ctx, iatAgg("proj-1", "instance-1", "ro-1"), "iat-1", 0, true),
		project.NewInitialAccessTokenConsumedEvent(ctx, iatAgg("proj-1", "instance-1", "ro-1"), "iat-1", 1, true),
		project.NewInitialAccessTokenConsumedEvent(ctx, iatAgg("proj-1", "instance-1", "ro-1"), "iat-1", 2, true),
	}
	collide := zerrors.ThrowAlreadyExists(nil, "EVENT-IATslot", "Errors.DCR.IAT.SlotAlreadyConsumed")
	c := &Commands{eventstore: eventstoreExpect(t,
		expectPushFailed(collide, pushes[0]),
		expectPushFailed(collide, pushes[1]),
		expectPushFailed(collide, pushes[2]),
	)}

	lookups := 0
	lookup := func(context.Context) (*IATSnapshot, error) {
		// Each retry sees one more slot consumed by the parallel winner.
		s := &IATSnapshot{
			ID: "iat-1", ProjectID: "proj-1", InstanceID: "instance-1", ResourceOwner: "ro-1",
			MaxUses: 100, UsesConsumed: lookups, Revoked: false,
		}
		lookups++
		return s, nil
	}

	_, err := c.ConsumeInitialAccessToken(ctx, lookup)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Errors.DCR.IAT.Exhausted")
	assert.Equal(t, IATConsumeMaxAttempts, lookups,
		"projection re-fetch must occur on every retry — kit R2 AC1")
}

// TestConsumeInitialAccessToken_Recovers_OnSecondAttempt pins R2 AC4:
// 1st push collides, 2nd lookup observes the racing winner, 2nd push
// for the next free slot succeeds.
func TestConsumeInitialAccessToken_Recovers_OnSecondAttempt(t *testing.T) {
	ctx := context.Background()
	collidedPush := project.NewInitialAccessTokenConsumedEvent(ctx, iatAgg("proj-1", "instance-1", "ro-1"), "iat-1", 0, true)
	successPush := project.NewInitialAccessTokenConsumedEvent(ctx, iatAgg("proj-1", "instance-1", "ro-1"), "iat-1", 1, true)
	collide := zerrors.ThrowAlreadyExists(nil, "EVENT-IATslot", "Errors.DCR.IAT.SlotAlreadyConsumed")
	c := &Commands{eventstore: eventstoreExpect(t,
		expectPushFailed(collide, collidedPush),
		expectPush(successPush),
	)}
	lookups := 0
	lookup := func(context.Context) (*IATSnapshot, error) {
		s := &IATSnapshot{
			ID: "iat-1", ProjectID: "proj-1", InstanceID: "instance-1", ResourceOwner: "ro-1",
			MaxUses: 5, UsesConsumed: lookups, Revoked: false,
		}
		lookups++
		return s, nil
	}
	slot, err := c.ConsumeInitialAccessToken(ctx, lookup)
	require.NoError(t, err)
	assert.Equal(t, 1, slot)
	assert.Equal(t, 2, lookups)
}

// TestConsumeInitialAccessToken_NonAlreadyExistsErrorBubblesUp pins
// the contract that only AlreadyExists triggers retry — every other
// push error is fatal to the first attempt.
func TestConsumeInitialAccessToken_NonAlreadyExistsErrorBubblesUp(t *testing.T) {
	ctx := context.Background()
	push := project.NewInitialAccessTokenConsumedEvent(ctx, iatAgg("proj-1", "instance-1", "ro-1"), "iat-1", 0, true)
	internalErr := errors.New("eventstore down")
	c := &Commands{eventstore: eventstoreExpect(t,
		expectPushFailed(internalErr, push),
	)}
	lookups := 0
	_, err := c.ConsumeInitialAccessToken(ctx, func(context.Context) (*IATSnapshot, error) {
		lookups++
		return &IATSnapshot{ID: "iat-1", ProjectID: "proj-1", InstanceID: "instance-1", ResourceOwner: "ro-1", MaxUses: 5}, nil
	})
	require.Error(t, err)
	assert.Equal(t, 1, lookups, "non-AlreadyExists error must NOT trigger retry")
}

// TestConsumeInitialAccessToken_LookupErrorBubbles pins that lookup
// failures (e.g., projection-store down) propagate as-is.
func TestConsumeInitialAccessToken_LookupErrorBubbles(t *testing.T) {
	c := &Commands{eventstore: eventstoreExpect(t)}
	want := errors.New("projection unreachable")
	_, err := c.ConsumeInitialAccessToken(context.Background(), func(context.Context) (*IATSnapshot, error) {
		return nil, want
	})
	require.ErrorIs(t, err, want)
}
