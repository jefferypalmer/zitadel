package project

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/eventstore"
)

// TestInitialAccessTokenAddedEvent_WireType pins the wire-type string;
// changing this would break event replay (cavekit-iat.md R1).
func TestInitialAccessTokenAddedEvent_WireType(t *testing.T) {
	assert.EqualValues(t, "project.initial_access_token.added", InitialAccessTokenAddedType)
	assert.EqualValues(t, "project.initial_access_token.consumed", InitialAccessTokenConsumedType)
	assert.EqualValues(t, "project.initial_access_token.revoked", InitialAccessTokenRevokedType)
}

func TestInitialAccessTokenAddedEvent_Payload(t *testing.T) {
	expires := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	agg := projectAggregate(t)
	ev := NewInitialAccessTokenAddedEvent(
		context.Background(), agg,
		"iat-1", "$passwap$encoded$hash", "project-1", "ci",
		3, &expires,
		[]string{"authorization_code"},
		[]string{"https://app/cb"},
	)

	assert.EqualValues(t, InitialAccessTokenAddedType, ev.EventType)

	payload, err := json.Marshal(ev.Payload())
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(payload, &raw))

	assert.Equal(t, "iat-1", raw["id"])
	assert.Equal(t, "$passwap$encoded$hash", raw["hash"])
	assert.EqualValues(t, 3, raw["max_uses"].(float64))
	assert.Equal(t, "project-1", raw["project_id"])
	assert.Equal(t, "ci", raw["description"])
	assert.NotNil(t, raw["expires_at"])
	assert.Nil(t, ev.UniqueConstraints(),
		"Added event must declare no unique constraint — only Consumed does")
}

func TestInitialAccessTokenAddedEvent_OptionalFieldsOmitempty(t *testing.T) {
	agg := projectAggregate(t)
	ev := NewInitialAccessTokenAddedEvent(
		context.Background(), agg,
		"iat-2", "$passwap$encoded", "project-2", "",
		1, nil, nil, nil,
	)
	payload, err := json.Marshal(ev.Payload())
	require.NoError(t, err)
	body := string(payload)
	assert.NotContains(t, body, `"expires_at"`)
	assert.NotContains(t, body, `"allowed_grant_types"`)
	assert.NotContains(t, body, `"allowed_redirect_uri_patterns"`)
	assert.NotContains(t, body, `"description"`)
}

// TestInitialAccessTokenConsumedEvent_UniqueConstraint covers
// cavekit-iat.md R1's per-slot constraint requirement.
func TestInitialAccessTokenConsumedEvent_UniqueConstraint(t *testing.T) {
	tests := []struct {
		name    string
		finite  bool
		wantLen int
	}{
		{name: "finite — declares iat_uses constraint", finite: true, wantLen: 1},
		{name: "unlimited (max_uses=0) — declares no constraint", finite: false, wantLen: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agg := projectAggregate(t)
			ev := NewInitialAccessTokenConsumedEvent(context.Background(), agg, "iat-x", 2, tt.finite)
			c := ev.UniqueConstraints()
			require.Len(t, c, tt.wantLen)
			if tt.finite {
				assert.Equal(t, IATSlotUniqueType, c[0].UniqueType)
				assert.Equal(t, fmt.Sprintf("iat-x:2"), c[0].UniqueField)
				assert.Equal(t, IATSlotErrMessage, c[0].ErrorMessage)
				assert.Equal(t, eventstore.UniqueConstraintAdd, c[0].Action)
			}
		})
	}
}

func TestInitialAccessTokenConsumedEvent_Payload(t *testing.T) {
	agg := projectAggregate(t)
	ev := NewInitialAccessTokenConsumedEvent(context.Background(), agg, "iat-y", 5, true)
	assert.EqualValues(t, InitialAccessTokenConsumedType, ev.EventType)

	payload, err := json.Marshal(ev.Payload())
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(payload, &raw))
	assert.Equal(t, "iat-y", raw["id"])
	assert.EqualValues(t, 5, raw["use_index"].(float64))
	// `finite` is intentionally NOT serialized (it is reconstructed
	// from the projection at read time by T-017).
	assert.NotContains(t, string(payload), "finite")
}

func TestInitialAccessTokenRevokedEvent_NoUniqueConstraint(t *testing.T) {
	agg := projectAggregate(t)
	ev := NewInitialAccessTokenRevokedEvent(context.Background(), agg, "iat-z")
	assert.EqualValues(t, InitialAccessTokenRevokedType, ev.EventType)
	assert.Nil(t, ev.UniqueConstraints(),
		"Revoked event MUST NOT declare a constraint (revocation is idempotent at the projection)")

	payload, err := json.Marshal(ev.Payload())
	require.NoError(t, err)
	assert.Contains(t, string(payload), `"id":"iat-z"`)
}

// Different IATs MUST produce non-colliding constraints (the unique
// field includes the IAT id).
func TestInitialAccessTokenConsumedEvent_DifferentIATsDifferentSlots(t *testing.T) {
	agg := projectAggregate(t)
	a := NewInitialAccessTokenConsumedEvent(context.Background(), agg, "iat-A", 0, true)
	b := NewInitialAccessTokenConsumedEvent(context.Background(), agg, "iat-B", 0, true)
	ac := a.UniqueConstraints()[0]
	bc := b.UniqueConstraints()[0]
	assert.Equal(t, ac.UniqueType, bc.UniqueType)
	assert.NotEqual(t, ac.UniqueField, bc.UniqueField,
		"distinct IAT ids must produce distinct unique fields")
}

func projectAggregate(t *testing.T) *eventstore.Aggregate {
	t.Helper()
	a := NewAggregate("agg-1", "instance-1")
	return &a.Aggregate
}
