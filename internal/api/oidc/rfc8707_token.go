package oidc

import (
	"context"
	"slices"
)

// audienceFromTokenResources merges the RFC 8707 `resource` values
// captured by the OIDC HTTP middleware (NewAuthorizeResourceSidecar in
// op.go) into the audience slice for /token grant handlers that build
// their audience from scratch (client_credentials, jwt_profile).
//
// Validation already happened at the middleware: by the time
// ResourcesFromContext returns a non-empty slice, every value passed
// ValidateResources against AllowedAudiences. The handler's job is
// purely propagation — merge into the audience claim that ends up on
// the issued access token (cavekit-rfc8707-resource.md R5).
//
// For handlers that re-issue from a stored audience (token_code,
// token_device): T-027 already merged resources at the /authorize
// time-of-write, so the stored audience already includes them. This
// helper covers the /token-time-of-issue case for the grants that
// have no /authorize step.
func audienceFromTokenResources(ctx context.Context, base []string) []string {
	resources := ResourcesFromContext(ctx)
	if len(resources) == 0 {
		return base
	}
	return mergeResourcesIntoAudience(base, resources)
}

// narrowAudienceByTokenResources implements the refresh-token narrowing
// rule from RFC 8707 §2.2: a refreshed access token's audience MUST be
// a subset of the original. When a refresh request supplies `resource`,
// the issued token's audience MUST be the intersection of:
//   - the original (refresh-token-stored) audience
//   - the requested `resource` set
//
// If the requested set contains values NOT in the original audience,
// those are dropped (broadening is forbidden). If after narrowing the
// audience is empty, returns the ORIGINAL audience unchanged — the
// kit and RFC 8707 §2.2 are silent on the empty-intersection case;
// preserving the original is the conservative choice that avoids
// minting an audience-less token while still rejecting broaden attempts.
//
// Empty `resources` (no resource on the refresh request) → original
// audience unchanged. This is the default path; pre-T-045 callers see
// the same behavior they had before.
func narrowAudienceByTokenResources(ctx context.Context, originalAudience []string) []string {
	resources := ResourcesFromContext(ctx)
	if len(resources) == 0 {
		return originalAudience
	}
	narrowed := make([]string, 0, len(resources))
	for _, r := range resources {
		if slices.Contains(originalAudience, r) {
			narrowed = append(narrowed, r)
		}
	}
	if len(narrowed) == 0 {
		return originalAudience
	}
	return narrowed
}
