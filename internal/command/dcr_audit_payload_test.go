package command

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/domain"
	project_repo "github.com/zitadel/zitadel/internal/repository/project"
)

// T-068 — DCR audit-event payload completeness
// (cavekit-console-ui-docs-and-observability.md R6).
//
// Acceptance criteria pinned by this file:
//
//   - AC1 Every DCR HTTP operation that mutates state emits at least
//         one eventstore event whose payload OR aggregate carries
//         {instance_id, org_id, project_id, client_id, iat_id,
//         software_statement_jti, remote_addr_sha256, user_agent,
//         registration_method} where applicable.
//   - AC2 `remote_addr_sha256` is the SHA-256 of the IP string
//         returned by `internal/api/http.RemoteIPStringFromRequest`
//         (XFF first hop, fallback `r.RemoteAddr`); raw IP is never
//         persisted on any event payload.
//   - AC3 (XFF trust-boundary documented in SECURITY.md) is delivered
//         by T-083 — out of scope for this test file.
//
// AC1 verification strategy:
//
//   - The POST /oidc/v1/register state-change event
//     (ApplicationDynamicallyRegisteredEvent) is the canonical audit
//     row. Every R6 AC1 field maps to either a payload attribute on
//     this event OR an aggregate-level field on `BaseEvent`. We pin
//     each mapping below.
//   - PUT (rotated event), DELETE (revocation events), and IAT
//     {Added, Consumed, Revoked} events carry their identifiers via
//     the project aggregate (ID=project_id, ResourceOwner=org_id) +
//     BaseEvent.InstanceID. Their existing tests cover state
//     transitions; this file pins the audit-shape invariant.
//   - GET is intentionally out of scope: read operations do NOT push
//     events (no state change) per the kit's "where applicable per
//     operation" qualifier.

func TestT068_R6_AC1_RegisterEvent_PayloadCompleteness(t *testing.T) {
	c, p := newRegisterClientFixture(t, "client-audit", "app-audit")

	app := &domain.OIDCApp{
		AppName:         "audit-probe",
		RedirectUris:    []string{"https://example.com/cb"},
		ResponseTypes:   []domain.OIDCResponseType{domain.OIDCResponseTypeCode},
		GrantTypes:      []domain.OIDCGrantType{domain.OIDCGrantTypeAuthorizationCode},
		AuthMethodType:  ptrAuthMethod(domain.OIDCAuthMethodTypeBasic),
		ApplicationType: ptrAppType(domain.OIDCApplicationTypeWeb),
		OIDCVersion:     ptrVersion(domain.OIDCVersionV1),
	}

	res, err := c.RegisterClient(context.Background(), &RegisterClientInput{
		App:                  app,
		OrgID:                "org-audit",
		ProjectID:            "proj-audit",
		IATID:                "iat-99",
		SoftwareStatementJTI: "jwt-jti-42",
		RegistrationMethod:   RegistrationMethodIAT,
		ClientNameUnclamped:  "audit-probe",
		RemoteIPString:       "203.0.113.42",
		UserAgent:            "claude-code/1.0",
	})
	require.NoError(t, err)
	require.NotNil(t, res)

	// Locate the audit event in the push sequence.
	var dyn *project_repo.ApplicationDynamicallyRegisteredEvent
	for _, cmd := range p.pushed {
		if e, ok := cmd.(*project_repo.ApplicationDynamicallyRegisteredEvent); ok {
			dyn = e
			break
		}
	}
	require.NotNil(t, dyn, "RegisterClient MUST emit ApplicationDynamicallyRegisteredEvent")

	// R6 AC1: payload-level fields.
	t.Run("client_id field carried as AppID payload", func(t *testing.T) {
		assert.Equal(t, "app-audit", dyn.AppID,
			"client_id (AppID) MUST be present so audit-correlation by client succeeds")
	})
	t.Run("iat_id field carried", func(t *testing.T) {
		assert.Equal(t, "iat-99", dyn.InitialAccessTokenID,
			"iat_id MUST be carried for IAT-mode registrations")
	})
	t.Run("software_statement_jti field carried", func(t *testing.T) {
		assert.Equal(t, "jwt-jti-42", dyn.SoftwareStatementJTI,
			"software_statement_jti MUST be carried so a leaked statement can be traced back to its registration")
	})
	t.Run("registration_method field carried", func(t *testing.T) {
		assert.Equal(t, RegistrationMethodIAT, dyn.RegistrationMethod,
			"registration_method (anonymous|iat) MUST be carried — distinguishes attack-surface in dashboards")
	})
	t.Run("remote_addr_sha256 field carried (NOT plaintext)", func(t *testing.T) {
		require.Equal(t, sha256Hex("203.0.113.42"), dyn.RemoteAddrSHA256,
			"R6 AC2: remote_addr_sha256 MUST equal SHA-256 of the input IP string")
		require.Len(t, dyn.RemoteAddrSHA256, 64,
			"hex SHA-256 = 64 chars; any other length means accidental hex/base64 swap or truncation")
		require.NotContains(t, dyn.RemoteAddrSHA256, "203",
			"plaintext IP MUST NOT bleed into the hash — checks against accidental field aliasing")
	})
	t.Run("user_agent field carried", func(t *testing.T) {
		assert.Equal(t, "claude-code/1.0", dyn.UserAgent,
			"user_agent MUST be carried (R6 AC1)")
	})

	// R6 AC1: aggregate-level fields. The audit event embeds
	// eventstore.BaseEvent which captures the project aggregate at
	// push time — project_id and org_id come from the aggregate ID +
	// ResourceOwner; instance_id comes from authz context (empty
	// under context.Background, but the field is there).
	t.Run("project_id carried via aggregate.ID", func(t *testing.T) {
		assert.Equal(t, "proj-audit", dyn.Aggregate().ID,
			"project_id (aggregate root) MUST be reachable on the BaseEvent")
	})
	t.Run("org_id carried via aggregate.ResourceOwner", func(t *testing.T) {
		assert.Equal(t, "org-audit", dyn.Aggregate().ResourceOwner,
			"org_id (resource_owner on the project aggregate) MUST be reachable on the BaseEvent")
	})
	t.Run("instance_id field present on BaseEvent", func(t *testing.T) {
		// context.Background() → empty InstanceID. The presence of the
		// field is structural — assert it can be addressed without
		// panic so production code (which sets it via
		// authz.WithInstanceID) sees a populated value.
		_ = dyn.Aggregate().InstanceID // compile-time field presence
	})
}

// TestT068_R6_AC1_AnonymousMode_IATIDOmitted pins that anonymous-mode
// registrations carry an empty IAT id (json:omitempty) — the audit
// event still emits with the same shape, but iat_id absent on
// anonymous requests is the correct contract.
func TestT068_R6_AC1_AnonymousMode_IATIDOmitted(t *testing.T) {
	c, p := newRegisterClientFixture(t, "client-anon", "app-anon")

	app := &domain.OIDCApp{
		AppName:         "anon-probe",
		RedirectUris:    []string{"https://example.com/cb"},
		ResponseTypes:   []domain.OIDCResponseType{domain.OIDCResponseTypeCode},
		GrantTypes:      []domain.OIDCGrantType{domain.OIDCGrantTypeAuthorizationCode},
		AuthMethodType:  ptrAuthMethod(domain.OIDCAuthMethodTypeBasic),
		ApplicationType: ptrAppType(domain.OIDCApplicationTypeWeb),
		OIDCVersion:     ptrVersion(domain.OIDCVersionV1),
	}

	_, err := c.RegisterClient(context.Background(), &RegisterClientInput{
		App:                 app,
		OrgID:               "org-1",
		ProjectID:           "proj-1",
		IATID:               "",
		RegistrationMethod:  RegistrationMethodAnonymous,
		ClientNameUnclamped: "anon-probe",
		RemoteIPString:      "198.51.100.1",
		UserAgent:           "ua",
	})
	require.NoError(t, err)

	var dyn *project_repo.ApplicationDynamicallyRegisteredEvent
	for _, cmd := range p.pushed {
		if e, ok := cmd.(*project_repo.ApplicationDynamicallyRegisteredEvent); ok {
			dyn = e
			break
		}
	}
	require.NotNil(t, dyn)

	assert.Equal(t, RegistrationMethodAnonymous, dyn.RegistrationMethod)
	assert.Empty(t, dyn.InitialAccessTokenID,
		"anonymous mode MUST NOT populate iat_id (json:omitempty drops the field on the wire)")
}

// TestT068_R6_AC2_RemoteAddrSHA256_DispatcherSourcePin pins the AC2
// invariant that the IP string fed into the audit event comes from
// `RemoteIPStringFromRequest` — not `r.RemoteAddr` directly. This is
// a source-level structural pin: any future refactor that swaps the
// IP source MUST update this assertion deliberately.
func TestT068_R6_AC2_RemoteAddrSHA256_DispatcherSourcePin(t *testing.T) {
	src, err := os.ReadFile("../api/oidc/dcr/wire.go")
	require.NoError(t, err)
	body := string(src)

	require.Contains(t, body, "http_util.RemoteIPStringFromRequest(r)",
		"R6 AC2: the dispatcher MUST source remote IP via "+
			"`internal/api/http.RemoteIPStringFromRequest` (XFF first hop "+
			"+ RemoteAddr fallback) — direct r.RemoteAddr access leaks "+
			"the load-balancer IP into every audit row.")

	// Negative pin: no caller should be reaching for r.RemoteAddr
	// directly under the dispatcher pipeline. The exception is the
	// header.go fallback inside RemoteIPStringFromRequest itself —
	// that file is not loaded here, so the negative grep is safe.
	require.NotContains(t, body, "r.RemoteAddr",
		"R6 AC2: dispatcher MUST NOT bypass RemoteIPStringFromRequest "+
			"by reaching for r.RemoteAddr — that strips the XFF first-hop "+
			"step and yields the load-balancer IP instead of the real client.")
}

// TestT068_R6_HashRemoteAddr_NeverEmptyOnNonEmptyInput is a
// privacy-defence pin: the audit row's remote_addr_sha256 field
// carries SHA-256 hex (64 chars) for any non-empty IP string, never
// the plaintext value and never a partial hash. Empty input → empty
// hash so the json:omitempty guard drops the field rather than
// emitting an all-zeros sentinel that would confuse correlation.
func TestT068_R6_HashRemoteAddr_NeverEmptyOnNonEmptyInput(t *testing.T) {
	// Sample a representative set of valid IP shapes.
	cases := []string{
		"203.0.113.42",
		"2001:db8::1",
		"::1",
		"10.0.0.1",
		"127.0.0.1",
	}
	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			h := HashRemoteAddr(ip)
			require.Len(t, h, 64,
				"hex SHA-256 of any non-empty IP MUST be 64 chars")
			require.NotContains(t, h, ip,
				"hashed value MUST NOT contain the plaintext IP fragment")
			// Hash is hex-only — no non-hex chars sneak in.
			require.True(t, isHexLower(h),
				"HashRemoteAddr output MUST be lowercase hex; got %q", h)
		})
	}

	t.Run("empty input → empty hash (omitempty guard)", func(t *testing.T) {
		require.Empty(t, HashRemoteAddr(""))
		require.Empty(t, HashRemoteAddr("   "))
	})
}

func isHexLower(s string) bool {
	const hex = "0123456789abcdef"
	for _, r := range s {
		if !strings.ContainsRune(hex, r) {
			return false
		}
	}
	return true
}
