package authrequest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zitadel/zitadel/internal/domain"
)

// TestAddedEvent_Resources_OmitemptyAndRoundTrip pins the additive Resources
// field semantics for T-014b:
//
//   - When Resources is nil/empty, the JSON payload omits the key
//     entirely (no `"resources":null` to confuse downstream readers).
//   - When Resources is set via WithResources, the slice round-trips
//     cleanly through marshal+unmarshal — guaranteeing both old events
//     (no field) and new events (field present) deserialize correctly
//     once this code ships.
func TestAddedEvent_Resources_OmitemptyAndRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		resources []string
		wantKey   bool
	}{
		{name: "nil — key absent", resources: nil, wantKey: false},
		{name: "empty — key absent", resources: []string{}, wantKey: false},
		{name: "single", resources: []string{"https://api.example.com"}, wantKey: true},
		{
			name:      "multiple — order preserved",
			resources: []string{"https://api.example.com", "https://mcp.example.com"},
			wantKey:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agg := &NewAggregate("V2_id", "instanceID").Aggregate
			ev := NewAddedEvent(context.Background(), agg,
				"login-client", "client", "https://app/cb", "state", "nonce",
				nil, nil, domain.OIDCResponseTypeCode, domain.OIDCResponseModeUnspecified, nil, nil, nil, nil, nil, nil, false,
				"https://issuer", "org",
			).WithResources(tt.resources)

			payload, err := json.Marshal(ev.Payload())
			assert.NoError(t, err)
			gotKey := contains(payload, `"resources":`)
			assert.Equal(t, tt.wantKey, gotKey, "key presence mismatch; payload=%s", string(payload))

			// Round-trip via direct unmarshal (the eventstore mapper
			// requires a live BaseEvent we can't synthesize cheaply
			// here; the field-level guarantee is the same).
			var got AddedEvent
			assert.NoError(t, json.Unmarshal(payload, &got))
			if len(tt.resources) == 0 {
				assert.Nil(t, got.Resources)
			} else {
				assert.Equal(t, tt.resources, got.Resources)
			}
		})
	}
}

// TestAddedEvent_Resources_OldEventBackCompat: a JSON payload written
// before the Resources field existed must unmarshal cleanly with
// Resources=nil. Asserts the additive-event guarantee for T-014b
// directly against the struct (the live eventstore mapper depends on
// runtime BaseEvent state we can't synthesize in a unit test).
func TestAddedEvent_Resources_OldEventBackCompat(t *testing.T) {
	// response_type is omitted because OIDCResponseType is an enumer-generated
	// integer with a custom UnmarshalJSON; we only care about the additive
	// Resources guarantee here.
	oldPayload := []byte(`{"login_client":"x","client_id":"c","redirect_uri":"u","scope":["s"],"audience":["a"]}`)
	var ev AddedEvent
	assert.NoError(t, json.Unmarshal(oldPayload, &ev))
	assert.Nil(t, ev.Resources)
	assert.Equal(t, "c", ev.ClientID)
	assert.Equal(t, "x", ev.LoginClient)
	assert.Equal(t, []string{"s"}, ev.Scope)
}

func contains(b []byte, sub string) bool {
	for i := 0; i+len(sub) <= len(b); i++ {
		if string(b[i:i+len(sub)]) == sub {
			return true
		}
	}
	return false
}

