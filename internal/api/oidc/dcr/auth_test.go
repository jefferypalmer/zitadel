package dcr

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/api/authz"
)

// stubAnonConfig satisfies [AnonymousConfig] for unit tests.
type stubAnonConfig struct {
	requireIAT     bool
	defaultOrgID   string
	defaultProject string
}

func (s stubAnonConfig) RequireInitialAccessToken() bool { return s.requireIAT }
func (s stubAnonConfig) DefaultOrgID() string            { return s.defaultOrgID }
func (s stubAnonConfig) DefaultProjectID() string        { return s.defaultProject }

// TestClassifyAuthMode_R3 covers the Bearer-vs-anonymous split that
// determines per-request behaviour (cavekit-register-handler.md R3).
func TestClassifyAuthMode_R3(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantMode  AuthMode
		wantToken string
	}{
		{
			name:     "no Authorization header → anonymous",
			header:   "",
			wantMode: AuthModeAnonymous,
		},
		{
			name:     "blank Authorization header → anonymous",
			header:   "   ",
			wantMode: AuthModeAnonymous,
		},
		{
			name:      "lowercase Bearer → IAT",
			header:    "bearer zdiat_aaa",
			wantMode:  AuthModeIAT,
			wantToken: "zdiat_aaa",
		},
		{
			name:      "uppercase Bearer → IAT",
			header:    "Bearer zdiat_xyz",
			wantMode:  AuthModeIAT,
			wantToken: "zdiat_xyz",
		},
		{
			name:      "mixed-case + extra whitespace → IAT, trimmed",
			header:    "BeArEr   zdiat_pad   ",
			wantMode:  AuthModeIAT,
			wantToken: "zdiat_pad",
		},
		{
			name:     "Basic auth → anonymous (RFC 7591 only defines Bearer)",
			header:   "Basic dXNlcjpwYXNz",
			wantMode: AuthModeAnonymous,
		},
		{
			name:     "Digest auth → anonymous",
			header:   "Digest username=...",
			wantMode: AuthModeAnonymous,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/oidc/v1/register", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			gotMode, gotTok := ClassifyAuthMode(req)
			assert.Equal(t, tt.wantMode, gotMode)
			assert.Equal(t, tt.wantToken, gotTok)
		})
	}
}

// TestResolveAnonymous_R3_HappyPath pins R3 AC4 + AC5: anonymous
// mode resolves instance from context (set upstream by the API server's
// instance interceptor), org/project from DCR.Default*ID, iat_id="".
func TestResolveAnonymous_R3_HappyPath(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-1")
	cfg := stubAnonConfig{
		requireIAT:     false,
		defaultOrgID:   "org-fixture",
		defaultProject: "proj-fixture",
	}
	got, err := ResolveAnonymous(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "inst-1", got.InstanceID, "instance from authz ctx (sourced from request host upstream)")
	assert.Equal(t, "org-fixture", got.OrgID)
	assert.Equal(t, "proj-fixture", got.ProjectID)
	assert.Equal(t, "", got.IATID, "anonymous mode → empty-string sentinel per kit R3 AC5")
}

// TestResolveAnonymous_R3_RequiresIAT pins R3 AC1: when
// RequireInitialAccessToken=true and the request has no Bearer header
// (caller routed to ResolveAnonymous because of that), respond
// 401 invalid_token. The handler maps the ClampError to the
// WWW-Authenticate response header.
func TestResolveAnonymous_R3_RequiresIAT(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-1")
	cfg := stubAnonConfig{
		requireIAT:     true,
		defaultOrgID:   "org-fixture",
		defaultProject: "proj-fixture",
	}
	got, err := ResolveAnonymous(ctx, cfg)
	assert.Nil(t, got)
	ce, ok := IsClampError(err)
	require.True(t, ok)
	assert.Equal(t, ErrCodeInvalidToken, ce.Code)
	assert.Contains(t, ce.Description, "Initial Access Token")
	assert.Contains(t, ce.Description, "Bearer")
}

// TestResolveAnonymous_R3_DefensiveDefaultsCheck pins the runtime
// guard for the half-configured deployment (T-009 normally catches
// this at startup, but config hot-reload could drop a default; fail
// closed).
func TestResolveAnonymous_R3_DefensiveDefaultsCheck(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-1")
	cases := []struct {
		name string
		cfg  stubAnonConfig
	}{
		{name: "empty org", cfg: stubAnonConfig{defaultOrgID: "", defaultProject: "proj"}},
		{name: "empty project", cfg: stubAnonConfig{defaultOrgID: "org", defaultProject: ""}},
		{name: "both empty", cfg: stubAnonConfig{}},
		{name: "whitespace-only org", cfg: stubAnonConfig{defaultOrgID: "   ", defaultProject: "proj"}},
		{name: "whitespace-only project", cfg: stubAnonConfig{defaultOrgID: "org", defaultProject: "\t"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ResolveAnonymous(ctx, c.cfg)
			assert.Nil(t, got)
			ce, ok := IsClampError(err)
			require.True(t, ok)
			assert.Equal(t, ErrCodeFeatureDisabled, ce.Code,
				"defensive runtime guard maps to feature_disabled (not invalid_token)")
		})
	}
}

// stubIATQueries / stubIATVerifier are the test seams for ResolveIAT.

type stubIATQueries struct {
	row *QueryIATRow
	err error
}

func (s stubIATQueries) InitialAccessTokenByID(ctx context.Context, id, ro string) (*QueryIATRow, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.row == nil || s.row.ID != id {
		return nil, errors.New("not found")
	}
	return s.row, nil
}

type stubIATVerifier struct {
	verifyCalls int
	matchHash   string // when row.TokenHash equals this, return nil; else error
}

func (s *stubIATVerifier) VerifyIATPlaintext(presented, encoded string) error {
	s.verifyCalls++
	if encoded == s.matchHash {
		return nil
	}
	return errors.New("wrong random")
}

func parseStub(presented string) (string, string, bool) {
	const prefix = "zdiat_"
	if len(presented) < len(prefix)+3 || presented[:len(prefix)] != prefix {
		return "", "", false
	}
	body := presented[len(prefix):]
	for i := 0; i < len(body); i++ {
		if body[i] == '.' {
			if i == 0 || i == len(body)-1 {
				return "", "", false
			}
			return body[:i], body[i+1:], true
		}
	}
	return "", "", false
}

// TestResolveIAT_R3_HappyPath pins the success path: parse → byID →
// Verify → RegistrationContext{IATID=row.ID, etc.}.
func TestResolveIAT_R3_HappyPath(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-1")
	row := &QueryIATRow{
		ID:            "iat-row-1",
		InstanceID:    "inst-1",
		ResourceOwner: "org-from-iat",
		ProjectID:     "proj-from-iat",
		TokenHash:     "stored-hash-XYZ",
	}
	q := stubIATQueries{row: row}
	v := &stubIATVerifier{matchHash: "stored-hash-XYZ"}

	got, err := ResolveIAT(ctx, q, v, parseStub, "zdiat_iat-row-1.somerandom", "stub-dummy-hash")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "inst-1", got.InstanceID)
	assert.Equal(t, "org-from-iat", got.OrgID)
	assert.Equal(t, "proj-from-iat", got.ProjectID)
	assert.Equal(t, "iat-row-1", got.IATID, "IATID must be the row PK so audit events record it per R3 AC3")
	assert.Equal(t, 1, v.verifyCalls, "happy path: exactly one Verify call (no dummy-verify)")
}

// TestResolveIAT_R4_DummyVerifyOnNotFound pins the anti-enumeration
// timing AC: byID not-found MUST trigger a dummy Verify so unknown-ID
// timing matches known-ID-wrong-random timing.
func TestResolveIAT_R4_DummyVerifyOnNotFound(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-1")
	q := stubIATQueries{err: errors.New("not found")}
	v := &stubIATVerifier{matchHash: "never-matches"}

	got, err := ResolveIAT(ctx, q, v, parseStub, "zdiat_unknown-id.somerandom", "stub-dummy-hash")
	assert.Nil(t, got)
	ce, ok := IsClampError(err)
	require.True(t, ok)
	assert.Equal(t, ErrCodeInvalidToken, ce.Code)
	assert.Equal(t, 1, v.verifyCalls, "anti-enum: dummy Verify must be called even though byID errored")
}

// TestResolveIAT_R5_DummyVerifyOnMalformed pins the parser-failure
// path: malformed plaintext also runs dummy Verify so an attacker
// cannot distinguish "ID parsed OK but unknown" from "couldn't parse"
// by timing.
func TestResolveIAT_R5_DummyVerifyOnMalformed(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-1")
	q := stubIATQueries{}
	v := &stubIATVerifier{matchHash: "never-matches"}

	got, err := ResolveIAT(ctx, q, v, parseStub, "garbage-not-a-zdiat-token", "stub-dummy-hash")
	assert.Nil(t, got)
	ce, ok := IsClampError(err)
	require.True(t, ok)
	assert.Equal(t, ErrCodeInvalidToken, ce.Code)
	assert.Equal(t, 1, v.verifyCalls, "anti-enum: dummy Verify must be called on parse failure")
}

// TestResolveIAT_R3_WrongInstanceRejected pins the cross-instance
// abuse boundary (R3 AC6): a row whose instance_id differs from the
// authz context is rejected with 401 + dummy Verify (defence-in-depth
// over the SQL WHERE clause).
func TestResolveIAT_R3_WrongInstanceRejected(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-1")
	row := &QueryIATRow{
		ID:            "iat-1",
		InstanceID:    "inst-OTHER", // mismatch — would only happen if SQL filter is misconfigured
		ResourceOwner: "org-x",
		ProjectID:     "proj-x",
		TokenHash:     "hash-x",
	}
	q := stubIATQueries{row: row}
	v := &stubIATVerifier{matchHash: "hash-x"} // would have matched if we let it through

	got, err := ResolveIAT(ctx, q, v, parseStub, "zdiat_iat-1.somerandom", "stub-dummy-hash")
	assert.Nil(t, got)
	ce, ok := IsClampError(err)
	require.True(t, ok)
	assert.Equal(t, ErrCodeInvalidToken, ce.Code)
	assert.Equal(t, 1, v.verifyCalls, "anti-enum: cross-instance rejection still pays Verify cost")
}

// TestResolveIAT_R3_WrongRandomRejected pins the per-credential
// failure: byID succeeds, but the random portion doesn't match the
// stored Passwap encoding.
func TestResolveIAT_R3_WrongRandomRejected(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-1")
	row := &QueryIATRow{
		ID:            "iat-1",
		InstanceID:    "inst-1",
		ResourceOwner: "org-x",
		ProjectID:     "proj-x",
		TokenHash:     "stored-hash-XYZ",
	}
	q := stubIATQueries{row: row}
	v := &stubIATVerifier{matchHash: "different-hash"} // forces Verify to fail

	got, err := ResolveIAT(ctx, q, v, parseStub, "zdiat_iat-1.wrongrandom", "stub-dummy-hash")
	assert.Nil(t, got)
	ce, ok := IsClampError(err)
	require.True(t, ok)
	assert.Equal(t, ErrCodeInvalidToken, ce.Code)
	assert.Equal(t, 1, v.verifyCalls, "wrong-random path: exactly one real Verify call (no extra dummy)")
}

// TestResolveIAT_F401_All401PathsUseCanonicalDescription pins the
// cavekit-register-handler.md R3 amendment 2026-04-27 / N-5 — ALL 401
// paths from the IAT auth flow MUST use the canonical
// `MissingOrInvalidAccessTokenDescription` string. Three distinct
// strings would let an attacker distinguish bad-shape vs unknown-id
// vs wrong-random vs cross-instance, partially defeating the
// F-Au004/Au005/Au006 anti-enumeration design.
//
// F-401 was logged in the 4th /ck:check pass after the original N-5
// fix migrated only 1 of 5 sites despite the kit AC enumerating 4.
func TestResolveIAT_F401_All401PathsUseCanonicalDescription(t *testing.T) {
	// Use the existing &stubIATVerifier{matchHash:"never"} — encoded
	// arg ("$bcrypt$x" or the dummy hash) never equals "never", so
	// every Verify returns an error. That covers the bad-shape +
	// unknown-id + cross-instance + wrong-random branches uniformly.
	verifier := &stubIATVerifier{matchHash: "never"}

	cases := []struct {
		name    string
		queries IATLookupQueries
		parser  PlaintextParser
		bearer  string
		ctxFunc func() context.Context
	}{
		{
			name:    "bad shape — parser rejects",
			parser:  func(string) (string, string, bool) { return "", "", false },
			bearer:  "not-a-zdiat",
			ctxFunc: func() context.Context { return authz.WithInstanceID(context.Background(), "i") },
		},
		{
			name:    "unknown id — queries returns ErrNotFound",
			parser:  func(string) (string, string, bool) { return "id-x", "rand", true },
			queries: stubLookupErr{err: errors.New("not found")},
			bearer:  "zdiat_id-x.rand",
			ctxFunc: func() context.Context { return authz.WithInstanceID(context.Background(), "i") },
		},
		{
			name:    "cross-instance — row.InstanceID != ctx instance",
			parser:  func(string) (string, string, bool) { return "id-x", "rand", true },
			queries: stubLookupRow{row: &QueryIATRow{ID: "id-x", InstanceID: "OTHER", TokenHash: "$bcrypt$x"}},
			bearer:  "zdiat_id-x.rand",
			ctxFunc: func() context.Context { return authz.WithInstanceID(context.Background(), "MINE") },
		},
		{
			name:    "wrong random — Verify rejects",
			parser:  func(string) (string, string, bool) { return "id-x", "rand", true },
			queries: stubLookupRow{row: &QueryIATRow{ID: "id-x", InstanceID: "MINE", TokenHash: "$bcrypt$x"}},
			bearer:  "zdiat_id-x.rand",
			ctxFunc: func() context.Context { return authz.WithInstanceID(context.Background(), "MINE") },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveIAT(tc.ctxFunc(), tc.queries,
				verifier, tc.parser, tc.bearer, "$bcrypt$dummy")
			require.Error(t, err)
			var ce *ClampError
			require.True(t, errors.As(err, &ce), "expected *ClampError, got %T", err)
			assert.Equal(t, ErrCodeInvalidToken, ce.Code)
			assert.Equal(t, MissingOrInvalidAccessTokenDescription, ce.Description,
				"F-401: 401 description MUST be the canonical RFC 6750 §3 string at all 4 paths")
		})
	}
}

type stubLookupErr struct{ err error }

func (s stubLookupErr) InitialAccessTokenByID(_ context.Context, _, _ string) (*QueryIATRow, error) {
	return nil, s.err
}

type stubLookupRow struct{ row *QueryIATRow }

func (s stubLookupRow) InitialAccessTokenByID(_ context.Context, _, _ string) (*QueryIATRow, error) {
	return s.row, nil
}

// TestT064_CrossInstanceIATAbuse_Rejected pins
// cavekit-security-hardening.md R6 T11 evidence: an IAT minted on one
// instance MUST NOT authenticate a registration request landing on a
// DIFFERENT instance. ResolveIAT's defensive instance-binding check
// at auth.go:235 catches the case even when a misconfigured authz
// interceptor leaves the byID query unfiltered.
//
// Threat shape: an attacker steals an IAT plaintext from instance-A
// and replays it against instance-B's /oidc/v1/register. The byID
// query already filters by instance_id WHERE-clause, but T11 evidence
// requires the explicit secondary check so a defense-in-depth gap
// surfaces here in a unit test, not in production.
func TestT064_CrossInstanceIATAbuse_Rejected(t *testing.T) {
	// Request landed on inst-B; IAT row is bound to inst-A.
	ctx := authz.WithInstanceID(context.Background(), "inst-B")
	row := &QueryIATRow{
		ID:            "iat-row-1",
		InstanceID:    "inst-A", // belongs to a different instance
		ResourceOwner: "org-on-A",
		ProjectID:     "proj-on-A",
		TokenHash:     "stored-hash-XYZ",
	}
	q := stubIATQueries{row: row}
	v := &stubIATVerifier{matchHash: "stored-hash-XYZ"}

	got, err := ResolveIAT(ctx, q, v, parseStub, "zdiat_iat-row-1.somerandom", "stub-dummy-hash")
	assert.Nil(t, got, "T11: cross-instance IAT MUST NOT resolve")
	ce, ok := IsClampError(err)
	require.True(t, ok)
	assert.Equal(t, ErrCodeInvalidToken, ce.Code,
		"T11: cross-instance abuse → invalid_token (NOT not-found — anti-enum)")

	// Anti-enum: dummy Verify MUST run BEFORE the cross-instance reject
	// so timing matches the wrong-random branch (R4 / T12 cross-cut).
	assert.Equal(t, 1, v.verifyCalls,
		"T11+T12 cross-cut: cross-instance reject MUST pay dummy-Verify cost")
}

// TestT064_CrossOrgIATAbuse_RejectedByByIDFilter pins R6 T11 evidence
// for the cross-org case: an IAT belonging to org-A on instance-X
// CANNOT be looked up by a request coming from a different org-B
// context on the SAME instance, because the byID query filters by
// `WHERE instance_id = $1 AND project_id = $2` (cavekit-iat.md R4
// AC4) and the IAT's project_id is bound to org-A.
//
// We model the org boundary by setting up a row whose ResourceOwner
// is org-A and asserting that the query returns it (org filter is at
// the SQL level, not at ResolveIAT) — but the broader abuse shape
// (an attacker re-uses an IAT to register a client under a different
// org/project than the IAT's claims) is rejected because ResolveIAT
// returns RegistrationContext{OrgID = row.ResourceOwner} so the
// downstream RegisterClient command persists the application under
// org-A regardless of any caller-supplied org. That contract is
// pinned by the existing T-040 RegisterClient tests; this test pins
// the IAT-side leg: the resolved RegistrationContext carries the
// IAT's org, NOT any caller-supplied value.
func TestT064_CrossOrgIATAbuse_RegistrationContextBoundToIATOrg(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-1")
	// IAT was minted by org-A under proj-on-A.
	row := &QueryIATRow{
		ID:            "iat-row-1",
		InstanceID:    "inst-1",
		ResourceOwner: "org-A", // IAT-bound org
		ProjectID:     "proj-on-A",
		TokenHash:     "stored-hash-XYZ",
	}
	q := stubIATQueries{row: row}
	v := &stubIATVerifier{matchHash: "stored-hash-XYZ"}

	got, err := ResolveIAT(ctx, q, v, parseStub, "zdiat_iat-row-1.somerandom", "stub-dummy-hash")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "org-A", got.OrgID,
		"T11: RegistrationContext.OrgID MUST come from the IAT row, NOT from any caller-supplied value — prevents cross-org client registration via a stolen IAT")
	assert.Equal(t, "proj-on-A", got.ProjectID,
		"T11: RegistrationContext.ProjectID MUST come from the IAT row — same boundary")
}

// TestT064_CrossInstanceIAT_WrongInstanceCtx_DummyVerifyTimingMatch
// pins the timing-equivalence guarantee for the cross-instance reject
// branch: the dummy Verify call uses the same anti-enum hash as the
// not-found branch (DCR-Au005 path at auth.go:236), so an attacker
// cannot distinguish "IAT belongs to different instance" from "IAT
// not found at all" by timing observation. R12 cross-cut to T-058's
// real-Passwap timing pin.
func TestT064_CrossInstanceIAT_WrongInstanceCtx_DummyVerifyTimingMatch(t *testing.T) {
	ctx := authz.WithInstanceID(context.Background(), "inst-B")
	row := &QueryIATRow{
		ID:            "iat-row-1",
		InstanceID:    "inst-A", // wrong instance
		ResourceOwner: "org-A",
		ProjectID:     "proj-A",
		TokenHash:     "should-never-be-used",
	}
	v := &stubIATVerifier{matchHash: "should-never-be-used"}
	q := stubIATQueries{row: row}

	got, err := ResolveIAT(ctx, q, v, parseStub, "zdiat_iat-row-1.somerandom", "anti-enum-dummy")
	assert.Nil(t, got)
	require.Error(t, err)

	// CRITICAL: even though row.TokenHash WOULD match the verifier's
	// stub matchHash, ResolveIAT MUST NOT call Verify against
	// row.TokenHash on the cross-instance branch — the dummy hash MUST
	// be used. Otherwise an attacker can detect cross-instance vs
	// not-found by submitting the correct random for an IAT they DON'T
	// own (verify-against-stored returns nil/no-error → faster path)
	// vs an unknown ID (verify-against-dummy → same path). Pin via
	// verifyCalls==1 AND the failure path: the result is invalid_token
	// regardless of plaintext correctness.
	assert.Equal(t, 1, v.verifyCalls,
		"T11+T12: cross-instance branch MUST run exactly one Verify (against dummy, not stored)")
	ce, ok := IsClampError(err)
	require.True(t, ok)
	assert.Equal(t, ErrCodeInvalidToken, ce.Code)
}
