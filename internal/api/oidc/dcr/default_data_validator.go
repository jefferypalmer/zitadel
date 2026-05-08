package dcr

import "context"

// DefaultDataValidator is the function-shaped seam the dispatcher uses
// at request time to re-check that the configured anonymous-DCR
// DefaultProjectID + DefaultOrgID still resolve to existing, ACTIVE
// rows in projections.projects4 / projections.orgs1, AND that the
// project's resource_owner equals the configured org. Production wires
// this to a closure over Queries.DCRDefaultProjectByID +
// DCRDefaultOrgByID; tests stub it directly (no Queries import here).
//
// Returns a non-nil *ClampError on any check failure. Returning nil
// means the configured defaults are still valid for this request.
//
// cavekit-dcr-bootstrap-validation.md R5.
//
// The boot-time check (R4 / cmd/start/start.go) is the primary line of
// defense; this in-request validator catches the race where an
// operator deletes the default project/org mid-run. Without it, the
// command-layer eventstore push would emit ApplicationAddedEvent with
// a dangling FK and /authorize would later fail with the same
// "Errors.App.NotFound" the v5.0.0-dcr.7 hotfix repaired.
type DefaultDataValidator func(ctx context.Context, projectID, orgID string) *ClampError

// NewDefaultDataValidator builds the production validator from the two
// existence-probe seams. Each takes (ctx, id) and returns a tristate:
// (exists, active, resourceOwner) for the project, (exists, active)
// for the org. The caller (production wiring in cmd/start/start.go)
// closes over queries.DCRDefaultProjectByID / DCRDefaultOrgByID and
// adapts the typed return values into these primitive shapes — this
// keeps the dcr package free of any internal/query import.
//
// Each closure may return a non-nil error to indicate a transient DB
// failure; the validator collapses that to a 503 server_error so the
// caller can retry, NOT a 400 invalid_client_metadata (the request
// itself is fine).
func NewDefaultDataValidator(
	probeProject func(ctx context.Context, projectID string) (exists, active bool, resourceOwner string, err error),
	probeOrg func(ctx context.Context, orgID string) (exists, active bool, err error),
) DefaultDataValidator {
	return func(ctx context.Context, projectID, orgID string) *ClampError {
		exists, active, ownerOfProject, err := probeProject(ctx, projectID)
		if err != nil {
			return &ClampError{
				Status:      503,
				Code:        ErrCodeServerError,
				Description: "transient failure verifying default project; retry",
				Wrapped:     err,
			}
		}
		if !exists {
			return &ClampError{
				Status:      503,
				Code:        ErrCodeDefaultProjectNotFound,
				Description: "default project not configured",
			}
		}
		if !active {
			return &ClampError{
				Status:      503,
				Code:        ErrCodeDefaultProjectNotFound,
				Description: "default project is not active",
			}
		}

		oExists, oActive, err := probeOrg(ctx, orgID)
		if err != nil {
			return &ClampError{
				Status:      503,
				Code:        ErrCodeServerError,
				Description: "transient failure verifying default org; retry",
				Wrapped:     err,
			}
		}
		if !oExists {
			return &ClampError{
				Status:      503,
				Code:        ErrCodeDefaultProjectNotFound,
				Description: "default org not configured",
			}
		}
		if !oActive {
			return &ClampError{
				Status:      503,
				Code:        ErrCodeDefaultProjectNotFound,
				Description: "default org is not active",
			}
		}
		if ownerOfProject != orgID {
			return &ClampError{
				Status:      503,
				Code:        ErrCodeDefaultProjectNotFound,
				Description: "default project is not owned by the configured org",
			}
		}
		return nil
	}
}
