package dcr

// software_statement_override.go bridges the JWT-derived override map
// (cavekit-software-statement.md R6 / T-028) onto an *RFC7591Metadata
// so the post-merge value can flow through the Phase 1 R4 clamp
// pipeline a second time. Kept here (rather than in
// software_statement/) because the merge target is the dcr-package
// metadata struct and putting it on the subpackage would invert the
// import direction.

import (
	"encoding/json"
	"fmt"
)

// mergeOverrideClaims returns a copy of `body` with the `mergedExtra`
// override claims (JWT-supplied) applied for each mapped RFC 7591
// §2.3 field. Claims absent from `mergedExtra` leave the body value
// untouched. JSON decode errors propagate — a malformed JWT-supplied
// claim turns into invalid_client_metadata at the caller site rather
// than a silent miscompose.
//
// The set of fields handled here mirrors `software_statement.MappedClaims`
// — if you add to that table, mirror the override here. The unit test
// in software_statement/override_test.go enforces the parity.
func mergeOverrideClaims(body *RFC7591Metadata, mergedExtra map[string]json.RawMessage) (*RFC7591Metadata, error) {
	if body == nil {
		return nil, fmt.Errorf("nil body")
	}
	out := *body // shallow copy; slice / pointer fields reassigned below.

	for claim, raw := range mergedExtra {
		switch claim {
		case "client_name":
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("software_statement.client_name: %w", err)
			}
			out.ClientName = v
		case "client_uri":
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("software_statement.client_uri: %w", err)
			}
			out.ClientURI = v
		case "logo_uri":
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("software_statement.logo_uri: %w", err)
			}
			out.LogoURI = v
		case "policy_uri":
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("software_statement.policy_uri: %w", err)
			}
			out.PolicyURI = v
		case "tos_uri":
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("software_statement.tos_uri: %w", err)
			}
			out.TosURI = v
		case "software_id":
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("software_statement.software_id: %w", err)
			}
			out.SoftwareID = v
		case "software_version":
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("software_statement.software_version: %w", err)
			}
			out.SoftwareVersion = v
		case "scope":
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("software_statement.scope: %w", err)
			}
			out.Scope = v
		case "redirect_uris":
			var v []string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("software_statement.redirect_uris: %w", err)
			}
			out.RedirectURIs = v
		case "grant_types":
			var v []string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("software_statement.grant_types: %w", err)
			}
			out.GrantTypes = v
		case "response_types":
			var v []string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("software_statement.response_types: %w", err)
			}
			out.ResponseTypes = v
		}
	}
	return &out, nil
}
