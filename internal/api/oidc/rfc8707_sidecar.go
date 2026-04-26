package oidc

import (
	"context"
	"net/http"
)

// RFC 8707 `resource` sidecar.
//
// The pinned `github.com/zitadel/oidc/v3@v3.47.5` `AuthRequest` struct
// has no `Resource` field (grep evidence: context/impl/m5-authrequest-resource-decision-t005.md).
// Until the upstream PR
// (/home/jeff/oidc branch `feat/authrequest-resource-rfc8707`) merges
// and Zitadel bumps the dep past that SHA, we bridge the library
// boundary with a context-scoped slice extracted by a tiny HTTP
// middleware that runs before the library parses the request.
//
// `TokenExchangeRequest.Resource` already exists upstream, so
// /token/token-exchange can keep reading `r.Data.Resource` directly —
// this sidecar is about /authorize (and the /token flows that use the
// same converter path).
//
// When the upstream PR lands and the dep bumps, the sidecar becomes
// dead code and this file + its uses in auth_request_converter.go /
// op.go middleware chain can be deleted in one commit. See
// cavekit-rfc8707-resource.md R7 for the decision rationale.

type dcrResourceCtxKey struct{}

// WithAuthorizeResources attaches the /authorize `resource` slice to
// ctx. Called by the sidecar middleware; also exported so tests can
// seed it directly.
func WithAuthorizeResources(ctx context.Context, resources []string) context.Context {
	if len(resources) == 0 {
		return ctx
	}
	return context.WithValue(ctx, dcrResourceCtxKey{}, resources)
}

// ResourcesFromContext returns the `resource` slice attached by the
// sidecar middleware (or nil if none). Safe to call when DCR is
// disabled — returns nil.
func ResourcesFromContext(ctx context.Context) []string {
	v, _ := ctx.Value(dcrResourceCtxKey{}).([]string)
	return v
}

// NewAuthorizeResourceSidecar returns an HTTP middleware that extracts
// the RFC 8707 `resource` form/query values, validates them against the
// configured AllowedAudiences allow-list (cavekit-rfc8707-resource.md
// R3 / T-026), and stashes the slice on the request context. Install in
// the OIDC HTTP middleware chain (see NewServer in op.go). No-op when
// the request carries no `resource` parameter, so installing it
// unconditionally is safe.
//
// Validation behavior:
//   - len(allowed)==0 → only URI-syntax check is enforced.
//   - non-empty allow-list → each value must match.
//   - on first invalid value the request short-circuits with the
//     `invalid_target` 400 envelope (cavekit R6 / T-028) and downstream
//     handlers are NOT called.
//
// Thread-safety: each request is handled in its own goroutine and each
// gets its own context chain, so there is no shared state to protect.
func NewAuthorizeResourceSidecar(allowed []string) func(http.Handler) http.Handler {
	// Defensive copy so config rotation can't mutate the closure's view.
	allowedCopy := append([]string(nil), allowed...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ParseForm merges URL query + POST body. Idempotent: safe
			// to call here even though the library will also call it
			// later.
			if err := r.ParseForm(); err == nil {
				if values := r.Form["resource"]; len(values) > 0 {
					if vErr := ValidateResources(values, allowedCopy); vErr != nil {
						writeInvalidTargetError(w, vErr.Error())
						return
					}
					r = r.WithContext(WithAuthorizeResources(r.Context(), values))
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
