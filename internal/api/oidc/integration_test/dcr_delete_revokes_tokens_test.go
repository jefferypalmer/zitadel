//go:build integration

package oidc_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/integration"
	admin_pb "github.com/zitadel/zitadel/pkg/grpc/admin"
	oidc_pb "github.com/zitadel/zitadel/pkg/grpc/oidc/v2"
)

// dcrDeleteRevokesBody is the registration payload used by this test —
// shaped like the Claude Code MCP body (T-057) but isolated so a
// regression in the DELETE path can't be confused with a regression in
// the registration path. auth_method=none + native + offline_access
// gives us both an access and a refresh token after exchange.
const dcrDeleteRevokesBody = `{
  "client_name": "DCR DELETE Revoke Test",
  "redirect_uris": ["http://localhost:54213/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "application_type": "native",
  "scope": "openid profile offline_access"
}`

const dcrDeleteRevokesRedirectURI = "http://localhost:54213/callback"

// TestServer_DCR_DELETE_RevokesIssuedTokens covers cavekit-manage-handler.md
// R6 (T-056) end-to-end against a running zitadel instance:
//
//	AC1: DELETE returns 204 No Content.
//	AC3: After DELETE, the access token issued before deletion is
//	     rejected by /oidc/v1/userinfo, and the refresh token is
//	     rejected by /oauth/v2/token.
//
// The flow:
//  1. Mint an IAT for a fresh project.
//  2. POST literal body to /oidc/v1/register → 201 + RAT.
//  3. Run a PKCE S256 authorization_code flow → access + refresh.
//  4. Probe userinfo with the access token → 200 (sanity).
//  5. DELETE /oidc/v1/register/{client_id} with the RAT → 204.
//  6. Probe userinfo with the access token → 401 (revoked).
//  7. Refresh-token grant against /oauth/v2/token → 4xx (revoked).
//
// Steps 4 and 7 are the structural pins that wouldn't pass before
// path-(a) `RevokeApplicationTokens` shipped. The pre-DELETE userinfo
// probe (step 4) anchors the test against transient
// network/projection-lag issues that would otherwise produce a
// confusing pass-at-step-6.
func TestServer_DCR_DELETE_RevokesIssuedTokens(t *testing.T) {
	// 1. Fresh project + IAT.
	project := Instance.CreateProject(CTX, t, "", integration.ProjectName(), false, false)
	require.NotEmpty(t, project.GetId())

	iatResp, err := Instance.Client.Admin.CreateInitialAccessToken(CTXIAM,
		&admin_pb.CreateInitialAccessTokenRequest{
			ProjectId:   project.GetId(),
			MaxUses:     1,
			Description: "T-056 DCR DELETE revoke integration test",
		})
	require.NoError(t, err)

	// 2. POST register.
	registerURL := Instance.OIDCIssuer() + "/oidc/v1/register"
	regReq, err := http.NewRequest(http.MethodPost, registerURL,
		strings.NewReader(dcrDeleteRevokesBody))
	require.NoError(t, err)
	regReq.Header.Set("Content-Type", "application/json")
	regReq.Header.Set("Authorization", "Bearer "+iatResp.GetToken())

	regResp, err := http.DefaultClient.Do(regReq)
	require.NoError(t, err)
	defer regResp.Body.Close()
	regBody, err := io.ReadAll(regResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, regResp.StatusCode,
		"register MUST return 201 — body: %s", string(regBody))

	var reg map[string]any
	require.NoError(t, json.Unmarshal(regBody, &reg))
	clientID, _ := reg["client_id"].(string)
	rat, _ := reg["registration_access_token"].(string)
	rcuri, _ := reg["registration_client_uri"].(string)
	require.NotEmpty(t, clientID)
	require.NotEmpty(t, rat)
	require.NotEmpty(t, rcuri)

	// 3. Authorization code + PKCE → tokens.
	authRequestID := createAuthRequest(t, Instance, clientID, dcrDeleteRevokesRedirectURI,
		"openid", "profile", "offline_access")

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
	tokens, err := exchangeTokens(t, Instance, clientID, code, dcrDeleteRevokesRedirectURI)
	require.NoError(t, err, "token exchange MUST succeed for the registered client")
	require.NotEmpty(t, tokens.AccessToken, "access_token MUST be issued")
	require.NotEmpty(t, tokens.RefreshToken, "refresh_token MUST be issued (offline_access scope)")

	// 4. Pre-DELETE sanity: access token is valid.
	userinfoURL := Instance.OIDCIssuer() + "/oidc/v1/userinfo"
	uReq, err := http.NewRequest(http.MethodGet, userinfoURL, nil)
	require.NoError(t, err)
	uReq.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	uResp, err := http.DefaultClient.Do(uReq)
	require.NoError(t, err)
	uResp.Body.Close()
	require.Equal(t, http.StatusOK, uResp.StatusCode,
		"pre-DELETE userinfo MUST be 200 with the freshly-issued access token (sanity check)")

	// 5. DELETE with the RAT → 204.
	delReq, err := http.NewRequest(http.MethodDelete, rcuri, nil)
	require.NoError(t, err)
	delReq.Header.Set("Authorization", "Bearer "+rat)
	delResp, err := http.DefaultClient.Do(delReq)
	require.NoError(t, err)
	delBody, _ := io.ReadAll(delResp.Body)
	delResp.Body.Close()
	require.Equal(t, http.StatusNoContent, delResp.StatusCode,
		"R6 AC1: DELETE MUST return 204 — body: %s", string(delBody))
	assert.Empty(t, delBody, "R6 AC1: 204 body MUST be empty")

	// 6. Post-DELETE: access token is rejected.
	//
	// The OIDCSession revocation events flow through the projection
	// asynchronously. Real production introspection / userinfo paths
	// hit the projection, so a tight test could race the projection
	// lag. The cavekit-iat.md R7 retry pattern applies here too:
	// retry up to a small number of times before failing.
	require.Eventually(t, func() bool {
		req, _ := http.NewRequest(http.MethodGet, userinfoURL, nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		resp, derr := http.DefaultClient.Do(req)
		if derr != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusUnauthorized
	}, 10*time.Second, 200*time.Millisecond,
		"R6 AC3: access token MUST be rejected by /oidc/v1/userinfo after DELETE")

	// 7. Post-DELETE: refresh token is rejected.
	tokenURL := Instance.OIDCIssuer() + "/oauth/v2/token"
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", tokens.RefreshToken)
	form.Set("client_id", clientID)
	form.Set("scope", "openid profile offline_access")
	require.Eventually(t, func() bool {
		req, _ := http.NewRequest(http.MethodPost, tokenURL,
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, derr := http.DefaultClient.Do(req)
		if derr != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode >= 400 && resp.StatusCode < 500
	}, 10*time.Second, 200*time.Millisecond,
		"R6 AC3: refresh_token grant MUST be rejected by /oauth/v2/token after DELETE")
}
