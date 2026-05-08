package oidc

import (
	"context"
	"sync"

	"github.com/zitadel/logging"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/query"
)

// lastSeenThrottle is the process-local throttle for the OIDC client
// last-seen-at update path. Initialized lazily on first use; subsequent
// calls observe the same instance via sync.Once.
//
// Process-local is fine because the worst case across replicas is a few
// duplicate UPDATEs per minute, which is exactly what the per-row
// idempotent UPDATE absorbs. cavekit-dcr-bootstrap-validation.md R12.
var (
	lastSeenThrottleOnce sync.Once
	lastSeenThrottle     *query.LastSeenThrottle
)

func getLastSeenThrottle() *query.LastSeenThrottle {
	lastSeenThrottleOnce.Do(func() {
		lastSeenThrottle = query.NewLastSeenThrottle(query.DefaultLastSeenThrottleInterval)
	})
	return lastSeenThrottle
}

// touchClientLastSeen records that the given OIDC client (resolved via
// query.OIDCClient.AppID) just had a successful chokepoint hit (a token
// endpoint authentication, an /authorize request, etc.). Writes are
// gated through the package-local throttle so a busy client (e.g. a CLI
// hitting /introspect on every command) doesn't write once per request.
//
// The call is synchronous because the UPDATE is a single-row, indexed,
// idempotent move — but errors are logged and swallowed: the auth flow
// MUST NOT fail because last-seen tracking failed.
//
// No-op on empty appID, empty instance_id, or nil queries handle.
func touchClientLastSeen(ctx context.Context, q *query.Queries, appID string) {
	if q == nil || appID == "" {
		return
	}
	instanceID := authz.GetInstance(ctx).InstanceID()
	if instanceID == "" {
		return
	}
	if !getLastSeenThrottle().ShouldWrite(instanceID, appID) {
		return
	}
	if err := q.TouchOIDCAppLastSeen(ctx, appID); err != nil {
		logging.OnError(err).Debug("dcr last_seen_at update failed (cavekit-dcr-bootstrap-validation R12)")
	}
}
