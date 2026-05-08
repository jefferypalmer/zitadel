package setup

import (
	"context"
	_ "embed"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/eventstore"
)

var (
	//go:embed 73.sql
	dcrAppOIDCLastSeenAt string
)

// DCRAppOIDCLastSeenAt adds the projections.apps7_oidc_configs.last_seen_at
// column on upgrading databases. The DCR client janitor
// (cavekit-dcr-bootstrap-validation.md R12) reaps DCR-registered apps
// whose last_seen_at is older than the configured retention window;
// without this column the reap query fails on upgraded DBs even though
// fresh DBs got the column via the projection's Init().
type DCRAppOIDCLastSeenAt struct {
	dbClient *database.DB
}

func (mig *DCRAppOIDCLastSeenAt) Execute(ctx context.Context, _ eventstore.Event) error {
	_, err := mig.dbClient.ExecContext(ctx, dcrAppOIDCLastSeenAt)
	return err
}

func (mig *DCRAppOIDCLastSeenAt) String() string {
	return "73_dcr_app_oidc_last_seen_at"
}
