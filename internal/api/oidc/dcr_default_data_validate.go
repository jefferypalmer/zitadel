package oidc

import (
	"context"
	"fmt"

	"github.com/zitadel/zitadel/internal/query"
)

// ValidateDCRDefaultDataAtBoot enforces cavekit-dcr-bootstrap-validation.md
// R4. It runs at startup (cmd/start/start.go) ONLY when DCR is enabled
// in anonymous mode (`DCR.Enabled=true`, `DCR.RequireInitialAccessToken=
// false`) — the configured `DefaultProjectID` and `DefaultOrgID` MUST
// resolve to existing, ACTIVE rows in projections.projects4 and
// projections.orgs1, AND the project's resource_owner MUST equal the
// configured DefaultOrgID. A mismatch or absence is a fatal config
// error: starting up otherwise admits anonymous registrations that
// quietly emit ApplicationAddedEvents with dangling foreign keys, then
// fail at /authorize hours later (the failure mode the v5.0.0-dcr.7
// hotfix would have prevented at boot).
//
// The function is a no-op when the precondition (anonymous-mode + DCR
// enabled) is not met; the caller can therefore invoke it
// unconditionally as long as it has a queries handle.
func ValidateDCRDefaultDataAtBoot(ctx context.Context, queries *query.Queries, cfg *DCRConfig) error {
	if cfg == nil || !cfg.Enabled || cfg.RequireInitialAccessToken {
		return nil
	}
	if queries == nil {
		// Defensive: caller bug — ValidateDCRConfig would already have
		// rejected an anonymous-mode config without DefaultProjectID/
		// DefaultOrgID, so reaching here without a queries handle is a
		// programming error, not a config error. Fail fast.
		return fmt.Errorf("dcr boot validation: queries handle required when DCR is in anonymous mode")
	}
	if cfg.DefaultProjectID == "" || cfg.DefaultOrgID == "" {
		// ValidateDCRConfig (in dcr_config.go) emits the precise
		// "missing keys" error for this state; nothing more to add.
		return nil
	}

	projectInfo, err := queries.DCRDefaultProjectByID(ctx, cfg.DefaultProjectID)
	if err != nil {
		return fmt.Errorf("dcr boot validation: lookup OIDC.DCR.DefaultProjectID=%q: %w", cfg.DefaultProjectID, err)
	}
	if !projectInfo.Exists {
		return fmt.Errorf(
			"dcr: OIDC.DCR.DefaultProjectID=%q does not exist in projections.projects4 — "+
				"anonymous DCR mode requires a real project ID. Create the project first or set a different ID.",
			cfg.DefaultProjectID,
		)
	}
	if !projectInfo.Active {
		return fmt.Errorf(
			"dcr: OIDC.DCR.DefaultProjectID=%q is in projection state %d (NOT ACTIVE) — "+
				"anonymous DCR mode requires an ACTIVE project. Reactivate the project or set a different ID.",
			cfg.DefaultProjectID, projectInfo.State,
		)
	}

	orgInfo, err := queries.DCRDefaultOrgByID(ctx, cfg.DefaultOrgID)
	if err != nil {
		return fmt.Errorf("dcr boot validation: lookup OIDC.DCR.DefaultOrgID=%q: %w", cfg.DefaultOrgID, err)
	}
	if !orgInfo.Exists {
		return fmt.Errorf(
			"dcr: OIDC.DCR.DefaultOrgID=%q does not exist in projections.orgs1 — "+
				"anonymous DCR mode requires a real org ID. Create the org first or set a different ID.",
			cfg.DefaultOrgID,
		)
	}
	if !orgInfo.Active {
		return fmt.Errorf(
			"dcr: OIDC.DCR.DefaultOrgID=%q is in projection state %d (NOT ACTIVE) — "+
				"anonymous DCR mode requires an ACTIVE org. Reactivate the org or set a different ID.",
			cfg.DefaultOrgID, orgInfo.State,
		)
	}

	if projectInfo.ResourceOwner != cfg.DefaultOrgID {
		return fmt.Errorf(
			"dcr: OIDC.DCR.DefaultProjectID=%q.resource_owner=%q does not match OIDC.DCR.DefaultOrgID=%q — "+
				"the configured project must belong to the configured org. Either fix DefaultOrgID to match "+
				"the project's actual owner (%q), or change DefaultProjectID to a project under the configured org.",
			cfg.DefaultProjectID, projectInfo.ResourceOwner, cfg.DefaultOrgID, projectInfo.ResourceOwner,
		)
	}
	return nil
}
