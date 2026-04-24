package oidc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel/internal/domain"
)

// TestCreateAuthRequestToBusiness_ResourcesFromSidecar pins the RFC 8707
// sidecar wire-through: the `resource` slice attached to ctx via
// AuthorizeResourceSidecar / WithAuthorizeResources must land on
// domain.AuthRequest.Resources. T-014 only covers the V1 login path
// (the only path that flows through CreateAuthRequestToBusiness);
// the V2 login path (createAuthRequestLoginClient → command.AuthRequest)
// is tracked separately — see impl-rfc8707-resource.md.
func TestCreateAuthRequestToBusiness_ResourcesFromSidecar(t *testing.T) {
	tests := []struct {
		name      string
		ctxSeed   []string
		wantSlice []string
	}{
		{
			name:      "no resource on ctx → nil on domain",
			ctxSeed:   nil,
			wantSlice: nil,
		},
		{
			name:      "single resource",
			ctxSeed:   []string{"https://api.example.com"},
			wantSlice: []string{"https://api.example.com"},
		},
		{
			name:      "multiple resources — order preserved",
			ctxSeed:   []string{"https://api.example.com", "https://mcp.example.com"},
			wantSlice: []string{"https://api.example.com", "https://mcp.example.com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithAuthorizeResources(context.Background(), tt.ctxSeed)
			req := &oidc.AuthRequest{ClientID: "c", RedirectURI: "http://x/cb"}
			got := CreateAuthRequestToBusiness(ctx, req, "agent", "user", nil)
			assert.Equal(t, tt.wantSlice, got.Resources)
		})
	}
}

func TestResponseModeToBusiness(t *testing.T) {
	type args struct {
		responseMode oidc.ResponseMode
	}
	tests := []struct {
		name string
		args args
		want domain.OIDCResponseMode
	}{
		{
			name: "empty",
			args: args{""},
			want: domain.OIDCResponseModeUnspecified,
		},
		{
			name: "invalid",
			args: args{"foo"},
			want: domain.OIDCResponseModeUnspecified,
		},
		{
			name: "query",
			args: args{oidc.ResponseModeQuery},
			want: domain.OIDCResponseModeQuery,
		},
		{
			name: "fragment",
			args: args{oidc.ResponseModeFragment},
			want: domain.OIDCResponseModeFragment,
		},
		{
			name: "post_form",
			args: args{oidc.ResponseModeFormPost},
			want: domain.OIDCResponseModeFormPost,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResponseModeToBusiness(tt.args.responseMode)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResponseModeToOIDC(t *testing.T) {
	type args struct {
		responseMode domain.OIDCResponseMode
	}
	tests := []struct {
		name string
		args args
		want oidc.ResponseMode
	}{
		{
			name: "unspecified",
			args: args{domain.OIDCResponseModeUnspecified},
			want: "",
		},
		{
			name: "invalid",
			args: args{99},
			want: "",
		},
		{
			name: "query",
			args: args{domain.OIDCResponseModeQuery},
			want: oidc.ResponseModeQuery,
		},
		{
			name: "fragment",
			args: args{domain.OIDCResponseModeFragment},
			want: oidc.ResponseModeFragment,
		},
		{
			name: "form_post",
			args: args{domain.OIDCResponseModeFormPost},
			want: oidc.ResponseModeFormPost,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResponseModeToOIDC(tt.args.responseMode)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPromptToBusiness(t *testing.T) {
	type args struct {
		oidcPrompt []string
	}
	tests := []struct {
		name string
		args args
		want []domain.Prompt
	}{
		{
			name: "unspecified",
			args: args{nil},
			want: []domain.Prompt{},
		},
		{
			name: "invalid",
			args: args{[]string{"non_existing_prompt"}},
			want: []domain.Prompt{},
		},
		{
			name: "prompt_none",
			args: args{[]string{oidc.PromptNone}},
			want: []domain.Prompt{domain.PromptNone},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PromptToBusiness(tt.args.oidcPrompt)
			assert.Equal(t, tt.want, got)
		})
	}
}
