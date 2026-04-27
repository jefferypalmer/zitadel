package oidc

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAudienceFromTokenResources_R5 pins the additive-merge semantics
// for /token grants that build their audience from scratch
// (client_credentials, jwt_profile, token_exchange — refresh + auth_code
// use narrowAudienceByTokenResources instead per RFC 8707 §2.2).
func TestAudienceFromTokenResources_R5(t *testing.T) {
	cases := []struct {
		name      string
		base      []string
		resources []string
		want      []string
	}{
		{
			name: "no resources — base unchanged",
			base: []string{"orig-aud"},
			want: []string{"orig-aud"},
		},
		{
			name: "nil base + nil resources — nil out",
		},
		{
			name:      "single resource appends",
			base:      []string{"orig-aud"},
			resources: []string{"https://api.example.com"},
			want:      []string{"orig-aud", "https://api.example.com"},
		},
		{
			name:      "dedupe — already in base",
			base:      []string{"https://api.example.com"},
			resources: []string{"https://api.example.com"},
			want:      []string{"https://api.example.com"},
		},
		{
			name:      "multiple — preserves order, no dupes",
			base:      []string{"a"},
			resources: []string{"b", "c", "b"},
			want:      []string{"a", "b", "c"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithAuthorizeResources(context.Background(), tc.resources)
			got := audienceFromTokenResources(ctx, tc.base)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestNarrowAudienceByTokenResources_RFC8707_2_2 pins the refresh-token
// narrowing rule: a /token-supplied resource MUST be a subset of the
// stored audience. Broaden attempts are silently dropped.
func TestNarrowAudienceByTokenResources_RFC8707_2_2(t *testing.T) {
	cases := []struct {
		name             string
		original         []string
		requested        []string
		want             []string
		wantNarrowingRan bool
	}{
		{
			name:     "no requested resources — original unchanged",
			original: []string{"a", "b", "c"},
			want:     []string{"a", "b", "c"},
		},
		{
			name:      "requested subset — narrow to subset",
			original:  []string{"a", "b", "c"},
			requested: []string{"a", "c"},
			want:      []string{"a", "c"},
		},
		{
			name:      "request includes a value NOT in original — broaden dropped",
			original:  []string{"a", "b"},
			requested: []string{"a", "evil"},
			want:      []string{"a"},
		},
		{
			name:      "all requested values outside original — preserve original (empty intersection guard)",
			original:  []string{"a", "b"},
			requested: []string{"evil1", "evil2"},
			want:      []string{"a", "b"},
		},
		{
			name:      "exact match — preserved",
			original:  []string{"a", "b"},
			requested: []string{"a", "b"},
			want:      []string{"a", "b"},
		},
		{
			name:      "request order preserved on narrow",
			original:  []string{"a", "b", "c"},
			requested: []string{"c", "a"},
			want:      []string{"c", "a"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithAuthorizeResources(context.Background(), tc.requested)
			got := narrowAudienceByTokenResources(ctx, tc.original)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestNarrowAudienceByTokenResources_NoCtxValue pins the safe
// no-resource fast-path — handler call sites pass arbitrary contexts
// (including ones where the sidecar middleware did not run, e.g. in
// unit tests). MUST NOT panic.
func TestNarrowAudienceByTokenResources_NoCtxValue(t *testing.T) {
	got := narrowAudienceByTokenResources(context.Background(), []string{"a"})
	assert.Equal(t, []string{"a"}, got)
}

// TestF203_V2RefreshPathWiredToNarrow pins the cavekit-rfc8707-resource.md
// R5 amendment 2026-04-27 / F-203 — the v2 refresh-token path
// (Server.RefreshToken via ExchangeOIDCSessionRefreshAndAccessToken)
// MUST narrow the issued access token's audience using
// `narrowAudienceByTokenResources` before building the response.
//
// Without grpc / eventstore harness here we pin the contract by static
// inspection: we read token_refresh.go and assert the v2 branch line
// references `narrowAudienceByTokenResources`. Pre-fix, only the v1
// branch (refreshTokenV1, line ~59) did the narrowing — the primary
// v2 RefreshToken silently broadcast the original session audience.
func TestF203_V2RefreshPathWiredToNarrow(t *testing.T) {
	src, err := os.ReadFile("token_refresh.go")
	require.NoError(t, err)

	// V2 path is the body of `func (s *Server) RefreshToken(...)`.
	// Cut from "func (s *Server) RefreshToken" to "func refreshTokenV1"
	// (the V1 helper). The narrowing call MUST appear in that range.
	contents := string(src)
	v2Start := strings.Index(contents, "func (s *Server) RefreshToken(")
	require.NotEqual(t, -1, v2Start, "v2 RefreshToken not found")
	v1Start := strings.Index(contents, "func (s *Server) refreshTokenV1(")
	require.NotEqual(t, -1, v1Start, "refreshTokenV1 not found")
	v2Body := contents[v2Start:v1Start]

	assert.Contains(t, v2Body, "narrowAudienceByTokenResources",
		"F-203: v2 RefreshToken MUST call narrowAudienceByTokenResources before issuing the access token. Pre-fix only v1 was wired; the primary v2 path silently broadcast the original session audience.")
}
