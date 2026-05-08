package query

import (
	"context"
	"sync"
	"time"

	sq "github.com/Masterminds/squirrel"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/query/projection"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// DefaultLastSeenThrottleInterval bounds projection-table churn from the
// last-seen-at update path. Every chokepoint that calls
// [Queries.TouchOIDCAppLastSeen] gates first through this interval per
// (instance_id, app_id) so a busy client (e.g. a CLI that hits
// /introspect on every command) doesn't write once per request.
//
// One minute matches the granularity needed for the DCR client janitor
// (cavekit-dcr-bootstrap-validation.md R12), which reaps clients whose
// last activity is older than a multi-day retention window. Sub-minute
// resolution would cost write amplification with no observable
// reap-query benefit.
const DefaultLastSeenThrottleInterval = time.Minute

// LastSeenThrottle deduplicates last-seen-at writes within a configured
// window. Process-local; not shared across replicas — that's fine
// because the worst case is a few duplicate UPDATEs per minute across
// the fleet, which is exactly what the per-row idempotent UPDATE absorbs.
//
// Memory shape: one entry per (instance_id, app_id) with a last-write
// timestamp. Sweep is opportunistic — entries older than 16× the
// configured window are eligible for replacement on the next
// ShouldWrite call (no separate goroutine).
type LastSeenThrottle struct {
	interval time.Duration
	now      func() time.Time

	mu      sync.Mutex
	entries map[lastSeenKey]time.Time
}

type lastSeenKey struct {
	instanceID string
	appID      string
}

// NewLastSeenThrottle constructs a throttle with the given window. A
// non-positive interval falls back to [DefaultLastSeenThrottleInterval].
func NewLastSeenThrottle(interval time.Duration) *LastSeenThrottle {
	if interval <= 0 {
		interval = DefaultLastSeenThrottleInterval
	}
	return &LastSeenThrottle{
		interval: interval,
		now:      time.Now,
		entries:  make(map[lastSeenKey]time.Time),
	}
}

// ShouldWrite returns true and records `now` when no write has been
// observed for (instanceID, appID) within the configured window. False
// means a recent write is on file — the caller skips the database
// round-trip. Both arms are safe to ignore: missing a write costs at
// most `interval` of staleness on `last_seen_at`; an unwanted write
// is cheap (idempotent UPDATE).
func (t *LastSeenThrottle) ShouldWrite(instanceID, appID string) bool {
	if t == nil || instanceID == "" || appID == "" {
		return false
	}
	key := lastSeenKey{instanceID: instanceID, appID: appID}
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()
	last, present := t.entries[key]
	if present && now.Sub(last) < t.interval {
		return false
	}
	t.entries[key] = now

	// Cheap opportunistic sweep — bounded by the size of the map at the
	// time of the call, no goroutine. Removes entries that haven't been
	// touched in 16× the interval.
	if len(t.entries) > 1024 {
		threshold := now.Add(-16 * t.interval)
		for k, v := range t.entries {
			if v.Before(threshold) {
				delete(t.entries, k)
			}
		}
	}
	return true
}

// TouchOIDCAppLastSeen updates projections.apps7_oidc_configs.last_seen_at
// for the given DCR-registered (or any OIDC) app to NOW(). Idempotent:
// re-running with the same arguments has no observable effect beyond
// the timestamp move. No-op when the (instance_id, app_id) row does
// not exist (the UPDATE simply matches zero rows).
//
// Callers MUST gate through a [LastSeenThrottle] first. The throttle is
// process-local and bounds projection-table churn; this function is the
// raw write that lands when the throttle says yes.
//
// cavekit-dcr-bootstrap-validation.md R12.
func (q *Queries) TouchOIDCAppLastSeen(ctx context.Context, appID string) (err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if appID == "" {
		return nil
	}
	instanceID := authz.GetInstance(ctx).InstanceID()
	if instanceID == "" {
		return nil
	}

	stmt, args, err := sq.Update(projection.AppOIDCTable).
		Set(projection.AppOIDCConfigColumnLastSeenAt, sq.Expr("NOW()")).
		Where(sq.Eq{
			projection.AppOIDCConfigColumnAppID:      appID,
			projection.AppOIDCConfigColumnInstanceID: instanceID,
		}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		return zerrors.ThrowInternal(err, "QUERY-lstS0", "Errors.Query.SQLStatement")
	}
	if _, err := q.client.ExecContext(ctx, stmt, args...); err != nil {
		return zerrors.ThrowInternal(err, "QUERY-lstS1", "Errors.Internal")
	}
	return nil
}
