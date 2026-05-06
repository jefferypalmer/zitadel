package setup

import (
	"context"
	_ "embed"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/eventstore"
)

var (
	//go:embed 71.sql
	dcrAppOIDCBackfill string
)

// DCRAppOIDCBackfill backfills the four DCR columns on
// projections.apps7_oidc_configs that the Phase-1/2 inline-jwks +
// registration-access-token + dcr_meta work added to the projection's
// Init() but never to a numbered setup step. Without this migration,
// upgrading DBs hit `column c.jwks_inline does not exist` on
// /oauth/v2/authorize. cavekit-register-handler.md R6 / cavekit-inline-jwks.md
// (Phase 1/2 backfill).
type DCRAppOIDCBackfill struct {
	dbClient *database.DB
}

func (mig *DCRAppOIDCBackfill) Execute(ctx context.Context, _ eventstore.Event) error {
	_, err := mig.dbClient.ExecContext(ctx, dcrAppOIDCBackfill)
	return err
}

func (mig *DCRAppOIDCBackfill) String() string {
	return "71_dcr_app_oidc_backfill"
}
