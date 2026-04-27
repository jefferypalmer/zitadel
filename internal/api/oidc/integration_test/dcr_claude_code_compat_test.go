//go:build integration

package oidc_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/integration"
	admin_pb "github.com/zitadel/zitadel/pkg/grpc/admin"
	oidc_pb "github.com/zitadel/zitadel/pkg/grpc/oidc/v2"
)

// claudeCodeRedirectURI is the loopback URI Claude Code uses today
// for the native PKCE flow. RFC 7591 §2 + cavekit-register-handler.md
// R5 explicitly accept loopback HTTP for application_type=native.
const claudeCodeRedirectURI = "http://localhost:54212/callback"

// claudeCodeRegisterBody is the literal JSON Claude Code MCP sends
// when it discovers a DCR-capable IdP. cavekit-register-handler.md R9
// pins this exact shape: a regression that breaks Claude Code's
// out-of-the-box experience MUST fail this test.
//
// Fields:
//   - application_type=native + token_endpoint_auth_method=none →
//     public client; PKCE S256 mandatory (T-036 R5).
//   - grant_types includes refresh_token + scope contains
//     `offline_access` so the issued tokens carry a refresh token.
//   - redirect_uris is loopback HTTP (RFC 8252 §7.3 + R5 native AC).
const claudeCodeRegisterBody = `{
  "client_name": "Claude Code MCP",
  "redirect_uris": ["http://localhost:54212/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "application_type": "native",
  "scope": "openid profile email offline_access"
}`

// TestServer_DCR_ClaudeCodeCompat covers cavekit-register-handler.md R9
// end-to-end against a running zitadel instance:
//
//	AC1: POST literal Claude Code body returns 201 + correct shape
//	     (no client_secret, RAT present, registration_client_uri
//	     absolute under the issuer, client_id minted).
//	AC2: PKCE S256 authorization_code follow-up against the registered
//	     client issues tokens successfully.
//
// Because the integration fixture (apps/api/test-integration-api.yaml,
// T-048) sets `RequireInitialAccessToken: true`, the test first creates
// an IAT for a fresh project and POSTs register WITH the IAT in the
// Authorization header. R9's "literal Claude Code body" is the request
// payload — IAT delivery is orthogonal (per kit R3, the IAT travels
// in the Authorization header, not the body).
//
// The PKCE follow-up reuses the existing test scaffolding:
// `createAuthRequest` (which already sets PKCE S256 via
// `oidc.NewSHACodeChallenge(integration.CodeVerifier)`) +
// `exchangeTokens` (which calls `rp.WithCodeVerifier(integration.CodeVerifier)`).
// Both helpers were originally written for static-config public
// clients but operate purely on the clientID, so a DCR-registered
// client with the same shape (auth_method=none, native, PKCE-only)
// is a structural match.
func TestServer_DCR_ClaudeCodeCompat(t *testing.T) {
	// 1. Fresh project for this test — keeps the registered Claude
	//    Code client isolated from other integration suites.
	project := Instance.CreateProject(CTX, t, "", integration.ProjectName(), false, false)
	require.NotEmpty(t, project.GetId())

	// 2. IAT scoped to the new project (admin gRPC requires IAM auth).
	iatResp, err := Instance.Client.Admin.CreateInitialAccessToken(CTXIAM,
		&admin_pb.CreateInitialAccessTokenRequest{
			ProjectId:   project.GetId(),
			MaxUses:     1,
			Description: "T-057 Claude Code compat integration test",
		})
	require.NoError(t, err)
	require.NotEmpty(t, iatResp.GetToken(),
		"R9 prerequisite: integration fixture has RequireInitialAccessToken=true; need IAT to register")

	// 3. POST literal Claude Code body to /oidc/v1/register.
	registerURL := Instance.OIDCIssuer() + "/oidc/v1/register"
	req, err := http.NewRequest(http.MethodPost, registerURL,
		strings.NewReader(claudeCodeRegisterBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+iatResp.GetToken())

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// R9 AC1: 201 status.
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"register MUST return 201 for the literal Claude Code payload — body: %s", string(bodyBytes))
	assert.Equal(t, "application/json;charset=UTF-8", resp.Header.Get("Content-Type"))

	var reg map[string]any
	require.NoError(t, json.Unmarshal(bodyBytes, &reg))

	// R9 AC1: no client_secret in body (token_endpoint_auth_method=none).
	_, hasSecret := reg["client_secret"]
	assert.False(t, hasSecret,
		"R9 AC1: Claude Code is auth_method=none → response MUST NOT carry client_secret")

	// R9 AC1: RAT present.
	rat, _ := reg["registration_access_token"].(string)
	assert.NotEmpty(t, rat, "R9 AC1: registration_access_token MUST be present in 201 body")
	assert.True(t, strings.HasPrefix(rat, "zdrat_"),
		"R9 AC1: RAT plaintext MUST carry the zdrat_ prefix")

	// R9 AC1: registration_client_uri absolute under issuer.
	rcuri, _ := reg["registration_client_uri"].(string)
	assert.True(t, strings.HasPrefix(rcuri, Instance.OIDCIssuer()),
		"R9 AC1: registration_client_uri MUST be absolute and under the OIDC issuer (was: %s)", rcuri)
	assert.Contains(t, rcuri, "/oidc/v1/register/",
		"R9 AC1: registration_client_uri MUST point at the RFC 7592 manage path")

	// client_id is needed for the PKCE follow-up.
	clientID, _ := reg["client_id"].(string)
	require.NotEmpty(t, clientID, "R9 AC1: client_id MUST be returned")

	// 4. R9 AC2: PKCE S256 authorization_code follow-up.
	//
	// `createAuthRequest` already wires PKCE S256 via
	// `integration.CodeVerifier`; `exchangeTokens` already supplies
	// the matching verifier on /token. Both helpers operate on the
	// clientID, so they work uniformly for static and DCR-registered
	// public clients with auth_method=none.
	authRequestID := createAuthRequest(t, Instance, clientID, claudeCodeRedirectURI,
		"openid", "profile", "email", "offline_access")

	sessionID, sessionToken, _, _ := Instance.CreateVerifiedWebAuthNSession(t, CTXLOGIN, User.GetUserId())
	linkResp, err := Instance.Client.OIDCv2.CreateCallback(CTXLOGIN,
		&oidc_pb.CreateCallbackRequest{
			AuthRequestId: authRequestID,
			CallbackKind: &oidc_pb.CreateCallbackRequest_Session{
				Session: &oidc_pb.Session{
					SessionId:    sessionID,
					SessionToken: sessionToken,
				},
			},
		})
	require.NoError(t, err)

	code := assertCodeResponse(t, linkResp.GetCallbackUrl())
	tokens, err := exchangeTokens(t, Instance, clientID, code, claudeCodeRedirectURI)
	require.NoError(t, err, "R9 AC2: PKCE S256 token exchange MUST succeed for the DCR-registered Claude Code client")

	assert.NotEmpty(t, tokens.AccessToken,
		"R9 AC2: access_token MUST be issued")
	assert.NotEmpty(t, tokens.IDToken,
		"R9 AC2: id_token MUST be issued (openid scope was requested)")
	assert.NotEmpty(t, tokens.RefreshToken,
		"R9 AC2: refresh_token MUST be issued (offline_access scope + refresh_token grant_type registered)")
}
