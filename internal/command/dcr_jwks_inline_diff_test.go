package command

import (
	"context"
	"testing"

	"github.com/zitadel/zitadel/internal/eventstore"
	project_repo "github.com/zitadel/zitadel/internal/repository/project"
)

// cavekit-inline-jwks.md R4 / T-021: PUT-side diff emits exactly the
// right event for the (current, requested) tuple.
func TestBuildJwksInlineDiffEvent(t *testing.T) {
	agg := &eventstore.Aggregate{
		ID:            "proj1",
		Type:          project_repo.AggregateType,
		ResourceOwner: "org1",
		Version:       project_repo.AggregateVersion,
	}
	someBytes := []byte(`{"keys":[{"kid":"k1","kty":"EC","crv":"P-256","x":"a","y":"b"}]}`)
	otherBytes := []byte(`{"keys":[{"kid":"k2","kty":"EC","crv":"P-256","x":"c","y":"d"}]}`)

	tests := []struct {
		name      string
		current   []byte
		requested []byte
		wantEvent eventstore.EventType // "" = nil
	}{
		{name: "both nil → no event", wantEvent: ""},
		{name: "nil → bytes → set", requested: someBytes, wantEvent: project_repo.ApplicationOIDCConfigJwksInlineSetType},
		{name: "bytes → bytes (same) → no event", current: someBytes, requested: someBytes},
		{name: "bytes → bytes (different) → changed", current: someBytes, requested: otherBytes,
			wantEvent: project_repo.ApplicationOIDCConfigJwksInlineChangedType},
		{name: "bytes → nil → removed", current: someBytes,
			wantEvent: project_repo.ApplicationOIDCConfigJwksInlineRemovedType},
		{name: "empty slice treated as nil (no event)", current: []byte{}, requested: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildJwksInlineDiffEvent(context.Background(), agg, "app1", tc.current, tc.requested)
			if tc.wantEvent == "" {
				if got != nil {
					t.Fatalf("expected nil event, got %T", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected event %q, got nil", tc.wantEvent)
			}
			if got.Type() != tc.wantEvent {
				t.Errorf("event type = %s, want %s", got.Type(), tc.wantEvent)
			}
		})
	}
}
