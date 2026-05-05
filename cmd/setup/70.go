package setup

import (
	"context"
	_ "embed"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/eventstore"
)

var (
	//go:embed 70.sql
	dcrSoftwareStatementJTIs string
)

// DCRSoftwareStatementJTIs creates projections.dcr_software_statement_jtis1.
// The table is application-managed (the verifier writes rows directly via
// query.RecordSoftwareStatementJTI; a janitor reaps rows past expires_at)
// — it is NOT a projection-framework table. See cavekit-software-statement.md
// R9 / R12 and cavekit-eventstore-framework-guard.md R1.
type DCRSoftwareStatementJTIs struct {
	dbClient *database.DB
}

func (mig *DCRSoftwareStatementJTIs) Execute(ctx context.Context, _ eventstore.Event) error {
	_, err := mig.dbClient.ExecContext(ctx, dcrSoftwareStatementJTIs)
	return err
}

func (mig *DCRSoftwareStatementJTIs) String() string {
	return "70_dcr_software_statement_jtis"
}
