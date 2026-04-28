package projection

import (
	"context"

	old_handler "github.com/zitadel/zitadel/internal/eventstore/handler"
	"github.com/zitadel/zitadel/internal/eventstore/handler/v2"
)

// dcr_software_statement_jtis projection
// (cavekit-software-statement.md R9 / T-014).
//
// This projection is structurally unusual: there are no events driving
// it. Rows are written directly from the verifier (T-030) on every
// successful `software_statement` verification, and a janitor reaps
// rows past `expires_at`. The projection framework still runs `Init`
// to create the table; `Reducers()` returns an empty slice so the
// handler's Trigger pipeline is a no-op.
//
// The table mirrors the Phase 1 IAT slot-dedupe pattern: the
// uniqueness contract lives at the database level (a unique index on
// `(instance_id, software_statement_iss, software_statement_jti)`).
// A duplicate INSERT raises a structural unique-violation, NOT a
// SELECT-then-INSERT race — kit R9 explicitly mandates this.
const (
	DCRSoftwareStatementJTITable = "projections.dcr_software_statement_jtis1"

	DCRSoftwareStatementJTIInstanceIDCol = "instance_id"
	DCRSoftwareStatementJTIIssCol        = "software_statement_iss"
	DCRSoftwareStatementJTIJtiCol        = "software_statement_jti"
	DCRSoftwareStatementJTICreatedAtCol  = "created_at"
	DCRSoftwareStatementJTIExpiresAtCol  = "expires_at"
)

type dcrSoftwareStatementJTIProjection struct{}

func newDCRSoftwareStatementJTIProjection(ctx context.Context, config handler.Config) *handler.Handler {
	return handler.NewHandler(ctx, &config, new(dcrSoftwareStatementJTIProjection))
}

func (*dcrSoftwareStatementJTIProjection) Name() string {
	return DCRSoftwareStatementJTITable
}

func (*dcrSoftwareStatementJTIProjection) Init() *old_handler.Check {
	return handler.NewTableCheck(
		handler.NewTable([]*handler.InitColumn{
			handler.NewColumn(DCRSoftwareStatementJTIInstanceIDCol, handler.ColumnTypeText),
			handler.NewColumn(DCRSoftwareStatementJTIIssCol, handler.ColumnTypeText),
			handler.NewColumn(DCRSoftwareStatementJTIJtiCol, handler.ColumnTypeText),
			handler.NewColumn(DCRSoftwareStatementJTICreatedAtCol, handler.ColumnTypeTimestamp),
			handler.NewColumn(DCRSoftwareStatementJTIExpiresAtCol, handler.ColumnTypeTimestamp),
		},
			// Composite PK = the unique constraint that enforces dedupe.
			// (instance_id, iss, jti) together is unique within the
			// retention window; the janitor reaps past `expires_at` so
			// the same (iss, jti) can be re-seen *after* the original
			// JWT expires (which is fine — replay protection only needs
			// to cover the lifetime of the JWT).
			handler.NewPrimaryKey(
				DCRSoftwareStatementJTIInstanceIDCol,
				DCRSoftwareStatementJTIIssCol,
				DCRSoftwareStatementJTIJtiCol,
			),
			// Index on expires_at supports the janitor's
			// `DELETE WHERE expires_at < NOW()` reap.
			handler.WithIndex(handler.NewIndex("dcr_software_statement_jtis_expires_at",
				[]string{DCRSoftwareStatementJTIExpiresAtCol})),
		),
	)
}

// Reducers returns no event reducers — this projection is populated
// directly by the verifier (T-030) via INSERT, not driven by an event
// stream. The framework calls Reducers() during projection setup; an
// empty slice is the documented "no events" response.
func (*dcrSoftwareStatementJTIProjection) Reducers() []handler.AggregateReducer {
	return nil
}
