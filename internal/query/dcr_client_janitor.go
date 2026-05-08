package query

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zitadel/logging"

	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// InactiveDCRClient is a candidate row identified by [ListInactiveDCRClients].
// Carries the four identifiers `commands.DeleteRegisteredClient` needs.
//
// cavekit-dcr-bootstrap-validation.md R12.
type InactiveDCRClient struct {
	InstanceID string
	ProjectID  string
	OrgID      string
	AppID      string
	ClientID   string
}

// ListInactiveDCRClients returns up to `batchLimit` DCR-registered apps
// whose last activity is older than `maxIdle`. "DCR-registered" is
// canonically defined as `apps7_oidc_configs.registration_access_token_hash
// IS NOT NULL` (the same predicate the projection's
// `IsDynamicallyRegistered` field uses).
//
// Candidate semantics:
//
//   - last_seen_at < (now - maxIdle): row's last successful client use
//     is older than the retention window.
//   - last_seen_at IS NULL AND creation_date < (now - maxIdle): row was
//     created before T-106 shipped (so never got a last_seen_at write)
//     OR has never had a successful client use. We treat that as "stale"
//     only when the row's own creation is also past the threshold —
//     otherwise a freshly-registered client that hasn't yet been used
//     would be reaped.
//
// Returns at most `batchLimit` rows so a janitor tick that finds
// thousands of stale clients can break the work into pieces and
// respect its per-tick deadline.
func (q *Queries) ListInactiveDCRClients(ctx context.Context, maxIdle time.Duration, batchLimit int) (out []InactiveDCRClient, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if maxIdle <= 0 || batchLimit <= 0 {
		return nil, nil
	}

	const stmt = `
SELECT a.instance_id, a.project_id, p.resource_owner, a.id, c.client_id
FROM projections.apps7 a
JOIN projections.apps7_oidc_configs c
  ON a.instance_id = c.instance_id
 AND a.id = c.app_id
JOIN projections.projects4 p
  ON a.instance_id = p.instance_id
 AND a.project_id = p.id
WHERE c.registration_access_token_hash IS NOT NULL
  AND (
    c.last_seen_at < $1
    OR (c.last_seen_at IS NULL AND a.creation_date < $1)
  )
LIMIT $2
`
	threshold := time.Now().UTC().Add(-maxIdle)
	err = q.client.QueryContext(ctx, func(rows *sql.Rows) error {
		for rows.Next() {
			var row InactiveDCRClient
			if scanErr := rows.Scan(&row.InstanceID, &row.ProjectID, &row.OrgID, &row.AppID, &row.ClientID); scanErr != nil {
				return scanErr
			}
			out = append(out, row)
		}
		return rows.Err()
	}, stmt, threshold, batchLimit)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, zerrors.ThrowInternal(err, "QUERY-DCRJ1", "Errors.Internal")
	}
	return out, nil
}

// DCRClientJanitorDeleteFn is the function-shaped seam that performs
// the RFC 7592 DELETE for a single inactive client. Production wires
// this to `commands.DeleteRegisteredClient` so the same event-sourcing
// + session-revocation + projection-chain path the manage-handler
// DELETE uses fires on each reap. Keeping this as a closure preserves
// the one-way query → command import boundary.
type DCRClientJanitorDeleteFn func(ctx context.Context, c InactiveDCRClient) error

// RunDCRClientJanitor mirrors [Queries.RunSoftwareStatementJTIJanitor]
// for the DCR client retention janitor (cavekit-dcr-bootstrap-
// validation.md R12). Periodically lists inactive DCR-registered apps
// and deletes them via `deleteFn`. Per-tick deadline is `interval/2`
// so a hung DELETE cannot block subsequent ticks.
//
// The recorder seam (same shape as the JTI janitor's
// [JanitorTickRecorder]) emits OTel
// `zitadel.dcr.client_janitor_reaped_total` + `..._duration_seconds`
// per tick. Pass nil to skip emission. `batchLimit` caps the
// per-tick reap count (recommend 100 — enough to make progress on a
// large pile without hogging the eventstore for any single tick).
//
// `interval <= 0` or `maxIdle <= 0` returns immediately — disables
// the loop. Production wiring derives both from
// `OIDC.DCR.ClientRetention.{Interval, MaxIdleDuration}`.
func (q *Queries) RunDCRClientJanitor(
	ctx context.Context,
	interval time.Duration,
	maxIdle time.Duration,
	batchLimit int,
	deleteFn DCRClientJanitorDeleteFn,
	recorder JanitorTickRecorder,
) {
	if interval <= 0 || maxIdle <= 0 || batchLimit <= 0 || deleteFn == nil {
		return
	}
	tickTimeout := interval / 2
	if tickTimeout <= 0 {
		tickTimeout = interval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			started := time.Now()
			tickCtx, cancel := context.WithTimeout(ctx, tickTimeout)
			reaped, errored := runOneClientJanitorTick(tickCtx, q, maxIdle, batchLimit, deleteFn)
			cancel()
			duration := time.Since(started)
			result := "ok"
			if errored {
				result = "error"
			}
			if recorder != nil {
				recorder(ctx, result, duration)
			}
			if reaped > 0 {
				logging.WithFields("reaped", reaped, "duration_ms", duration.Milliseconds()).
					Info("dcr: client janitor reaped inactive clients (cavekit-dcr-bootstrap-validation R12)")
			}
		}
	}
}

// runOneClientJanitorTick lists candidates and deletes them one by one.
// Extracted from the loop so it's testable in isolation. Returns the
// number of clients successfully reaped + whether any error occurred
// during the tick (list error or per-row delete error). A per-row
// delete error does NOT stop the tick — the next row still gets a
// chance.
func runOneClientJanitorTick(
	ctx context.Context,
	q *Queries,
	maxIdle time.Duration,
	batchLimit int,
	deleteFn DCRClientJanitorDeleteFn,
) (reaped int, errored bool) {
	candidates, err := q.ListInactiveDCRClients(ctx, maxIdle, batchLimit)
	if err != nil {
		logging.OnError(err).Warn("dcr: client janitor list failed; will retry next tick")
		return 0, true
	}
	for _, c := range candidates {
		if delErr := deleteFn(ctx, c); delErr != nil {
			logging.OnError(delErr).
				WithField("client_id", c.ClientID).
				Warn("dcr: client janitor delete failed; continuing to next candidate")
			errored = true
			continue
		}
		reaped++
	}
	return reaped, errored
}
