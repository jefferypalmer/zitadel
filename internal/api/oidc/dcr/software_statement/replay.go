package software_statement

// replay.go implements cavekit-software-statement.md R9 — JTI replay
// dedupe. Sits between Verify (R5) and the registration handler
// (T-031): every successfully-verified software_statement gets a JTI
// row inserted; a duplicate triggers the Replay envelope.
//
// The kit's "structural unique-violation" requirement — duplicate
// INSERT raises a database constraint violation, not a SELECT-then-
// INSERT race — is satisfied by the projection-side primary key on
// (instance_id, iss, jti) that T-014 declared. This file wires the
// integration: it owns the retention computation (`exp +
// JTIRetentionBuffer`) and the fail-closed branch (any DB error →
// reject the software_statement with InvalidSignature).

import (
	"context"
	"time"
)

// JTIRecorderResult mirrors query.SoftwareStatementJTIRecorded so this
// package doesn't import internal/query. The recorder closure caller
// translates between the two.
type JTIRecorderResult int

const (
	JTIRecorderInserted    JTIRecorderResult = 1
	JTIRecorderAlreadySeen JTIRecorderResult = 2
)

// JTIRecorder is the function-shaped seam for invoking the eventstore-
// boundary INSERT. Production wires this to a closure that calls
// Queries.RecordSoftwareStatementJTI. Tests stub it.
//
// `expiresAt` is the absolute timestamp the row may be reaped at —
// computed by RecordReplay below as `parsed.Body.Exp + retentionBuffer`.
//
// On failure, the recorder MAY return any non-nil error; RecordReplay
// translates it to the fail-closed InvalidSignature envelope per kit
// R9 ("DB unreachable → fail-closed").
type JTIRecorder func(ctx context.Context, iss, jti string, createdAt, expiresAt time.Time) (JTIRecorderResult, error)

// RecordReplay runs the R9 dedupe insert. Caller has already run R5
// (Verify) so `parsed.Body.Exp` and `parsed.Body.Jti` are guaranteed
// non-nil / non-empty. Returns:
//
//   - nil → first sighting; caller proceeds with registration.
//   - *ParseError keyed ReplayKey → duplicate sighting; caller emits
//     the Replay envelope and DOES NOT push any registration event.
//   - *ParseError keyed InvalidSignatureKey → DB unreachable, fail-
//     closed. Kit R9 explicit: "any software_statement rejected with
//     Errors.DCR.SoftwareStatement.InvalidSignature".
//
// `now` is threaded so tests can pin createdAt without time.Sleep.
// `retentionBuffer` mirrors `OIDC.DCR.SoftwareStatement.JTIRetentionBuffer`
// (default 24h).
func RecordReplay(
	ctx context.Context,
	parsed *Parsed,
	recorder JTIRecorder,
	now time.Time,
	retentionBuffer time.Duration,
) *ParseError {
	if parsed == nil {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: parser returned nil before replay record",
			I18nKey:     InvalidSignatureKey,
		}
	}
	if parsed.Body.Jti == "" || parsed.Body.Exp == nil {
		// Verify guarantees these are present, but defending the
		// invariant here avoids a NPE if the caller plumbs a parse-
		// only path into RecordReplay by mistake.
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: missing jti / exp before replay record",
			I18nKey:     InvalidStructureKey,
		}
	}
	exp := time.Unix(*parsed.Body.Exp, 0)
	expiresAt := exp.Add(retentionBuffer)

	result, err := recorder(ctx, parsed.Body.Iss, parsed.Body.Jti, now, expiresAt)
	if err != nil {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: replay store unavailable — fail-closed",
			I18nKey:     InvalidSignatureKey,
			Wrapped:     err,
		}
	}
	if result == JTIRecorderAlreadySeen {
		return &ParseError{
			Code:        "invalid_software_statement",
			Description: "software_statement: jti has already been used",
			I18nKey:     ReplayKey,
		}
	}
	return nil
}
