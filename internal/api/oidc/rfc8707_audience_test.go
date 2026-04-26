package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMergeResourcesIntoAudience covers cavekit-rfc8707-resource.md R4 /
// T-027: resources merge into the audience slice used to compute
// OIDCSession.Audience and ultimately the issued access-token `aud`
// claim. Acceptance criteria pinned here:
//
//   - AC5: when no resource parameter is supplied, behavior is unchanged
//     from today's scope-derived audience (fast-path no-op).
//   - AC1: resources are appended to the audience slice.
//   - implicit: dedupe to avoid duplicate `aud` entries when a resource
//     is already in the project-derived audience.
func TestMergeResourcesIntoAudience(t *testing.T) {
	tests := []struct {
		name      string
		audience  []string
		resources []string
		want      []string
	}{
		{
			name:      "AC5: nil resources is no-op (audience unchanged)",
			audience:  []string{"project-1", "app-1"},
			resources: nil,
			want:      []string{"project-1", "app-1"},
		},
		{
			name:      "AC5: empty resources is no-op",
			audience:  []string{"project-1", "app-1"},
			resources: []string{},
			want:      []string{"project-1", "app-1"},
		},
		{
			name:      "AC1: single resource appended",
			audience:  []string{"project-1"},
			resources: []string{"https://api.example.com"},
			want:      []string{"project-1", "https://api.example.com"},
		},
		{
			name:      "AC1: multiple resources appended in order",
			audience:  []string{"project-1"},
			resources: []string{"https://api.example.com", "https://mcp.example.com"},
			want:      []string{"project-1", "https://api.example.com", "https://mcp.example.com"},
		},
		{
			name:      "dedupe: resource already in audience is not duplicated",
			audience:  []string{"project-1", "https://api.example.com"},
			resources: []string{"https://api.example.com"},
			want:      []string{"project-1", "https://api.example.com"},
		},
		{
			name:      "dedupe: multi-resource with one duplicate",
			audience:  []string{"https://api.example.com"},
			resources: []string{"https://api.example.com", "https://mcp.example.com"},
			want:      []string{"https://api.example.com", "https://mcp.example.com"},
		},
		{
			name:      "dedupe: resource list contains internal duplicates",
			audience:  []string{"project-1"},
			resources: []string{"https://api.example.com", "https://api.example.com"},
			want:      []string{"project-1", "https://api.example.com"},
		},
		{
			name:      "empty audience seed",
			audience:  nil,
			resources: []string{"https://api.example.com"},
			want:      []string{"https://api.example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeResourcesIntoAudience(tt.audience, tt.resources)
			assert.Equal(t, tt.want, got)
		})
	}
}
