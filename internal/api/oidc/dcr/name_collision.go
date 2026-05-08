package dcr

import (
	"context"
	"fmt"
	"strconv"
)

// AppNameTakenFn is the function-shaped seam that probes whether a
// (project_id, app_name) pair is already taken in the apps projection.
// Production wires it to a closure over Queries.AppNameExistsInProject;
// tests stub it directly (no Queries import here).
//
// Returns (true, nil) when the name is taken, (false, nil) when it is
// not. A non-nil error is treated as "skip the policy" by
// applyClientNameCollisionPolicy — the bug R8 fixes is "duplicate
// client_name → 500"; refusing the registration because the projection
// probe failed would re-introduce the same UX regression in a different
// shape.
type AppNameTakenFn func(ctx context.Context, projectID, appName string) (bool, error)

// Collision policy values for [RegistrationDeps.OnNameCollision].
//
//   - CollisionPolicyOff (zero value): the policy is disabled. The
//     registration goes through with whatever name the clamp produced;
//     duplicate-name eventstore violations would surface as 5xx as they
//     did pre-R8. Production MUST set CollisionPolicySuffix or
//     CollisionPolicyReject.
//
//   - CollisionPolicySuffix: on collision, auto-append `-N` where N is
//     the smallest integer >= 2 that yields a non-colliding name. This
//     is the MCP-friendly default — Claude Code / VS Code MCP clients
//     re-register on every startup, so transparent suffixing is what
//     users actually want. cavekit-dcr-bootstrap-validation.md R8.
//
//   - CollisionPolicyReject: on collision, return a 400
//     invalid_client_metadata error to the client. Useful for operators
//     who want stable client_name -> client_id round-trips and accept
//     the cost of explicit rejection.
const (
	CollisionPolicyOff     = ""
	CollisionPolicySuffix  = "suffix"
	CollisionPolicyReject  = "reject"
	collisionSuffixMaxAttempts = 1000
)

// applyClientNameCollisionPolicy enforces
// cavekit-dcr-bootstrap-validation.md R8 between the metadata clamp and
// the RegisterClient command call.
//
// Behavior:
//
//  1. If the policy is off (CollisionPolicyOff) or no probe is wired,
//     return nil — caller continues unchanged.
//  2. If clientName is empty (the RFC 7591 §3.1 default-synthesis path
//     in RegisterClient produces a clientID-suffixed name that is
//     unique by construction), return nil.
//  3. Probe (projectID, clientName) once. No collision → return nil.
//  4. CollisionPolicyReject: return *ClampError 400
//     invalid_client_metadata describing the duplicate name.
//  5. CollisionPolicySuffix: probe `<base>-2`, `<base>-3`, … until a
//     non-colliding name is found, capped at collisionSuffixMaxAttempts.
//     Mutates `meta.ClientName` to the resolved suffix on success. Cap
//     exhausted → *ClampError 500 server_error (operator's projection
//     is in an unexpectedly populated state for this name family).
//
// Probe failures (taken-fn returns a non-nil error) collapse to "skip
// the policy" — see AppNameTakenFn for the rationale. The unique-
// constraint at the eventstore push level is a defense-in-depth backstop
// for that case; the worst-case outcome is the pre-R8 5xx, not data
// corruption.
func applyClientNameCollisionPolicy(
	ctx context.Context,
	policy string,
	taken AppNameTakenFn,
	projectID string,
	meta *RFC7591Metadata,
) *ClampError {
	if meta == nil {
		return nil
	}
	if policy == CollisionPolicyOff || taken == nil {
		return nil
	}
	base := meta.ClientName
	if base == "" {
		// RegisterClient synthesizes "Dynamically Registered Client
		// <clientID[:8]>" for empty names — that's clientID-derived and
		// thus collision-free by construction.
		return nil
	}

	// Initial probe on the requested name.
	collides, err := taken(ctx, projectID, base)
	if err != nil {
		return nil // probe failure: skip policy (constraint is the backstop)
	}
	if !collides {
		return nil
	}

	switch policy {
	case CollisionPolicyReject:
		return &ClampError{
			Status: 400,
			Code:   ErrCodeInvalidClientMetadata,
			Description: fmt.Sprintf(
				"client_name %q is already in use under this project; supply a different name",
				base,
			),
		}
	case CollisionPolicySuffix:
		for n := 2; n <= collisionSuffixMaxAttempts; n++ {
			candidate := base + "-" + strconv.Itoa(n)
			collides, err := taken(ctx, projectID, candidate)
			if err != nil {
				return nil // mid-loop probe failure: fall through to backstop
			}
			if !collides {
				meta.ClientName = candidate
				return nil
			}
		}
		return &ClampError{
			Status:      500,
			Code:        ErrCodeServerError,
			Description: "client_name suffix-resolution exhausted: too many existing collisions for this name family",
		}
	default:
		// Unknown policy value (config typo). Treat as off rather than
		// fail-closed — the register endpoint must remain available.
		return nil
	}
}
