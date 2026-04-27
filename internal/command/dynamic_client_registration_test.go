package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/passwap"
	"github.com/zitadel/passwap/bcrypt"

	"github.com/zitadel/zitadel/internal/crypto"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	new_db "github.com/zitadel/zitadel/backend/v3/storage/database"
	"github.com/zitadel/zitadel/internal/id"
	id_mock "github.com/zitadel/zitadel/internal/id/mock"
	project_repo "github.com/zitadel/zitadel/internal/repository/project"
)

// ───────────────────────────────────────────────────────────────────────
// HashRemoteAddr
// ───────────────────────────────────────────────────────────────────────

func TestHashRemoteAddr(t *testing.T) {
	t.Run("empty input returns empty", func(t *testing.T) {
		assert.Equal(t, "", HashRemoteAddr(""))
		assert.Equal(t, "", HashRemoteAddr("   "))
	})

	t.Run("ipv4 deterministic", func(t *testing.T) {
		got := HashRemoteAddr("203.0.113.42")
		want := sha256Hex("203.0.113.42")
		assert.Equal(t, want, got)
		assert.Equal(t, got, HashRemoteAddr("203.0.113.42"))
	})

	t.Run("ipv6 deterministic", func(t *testing.T) {
		got := HashRemoteAddr("2001:db8::1")
		want := sha256Hex("2001:db8::1")
		assert.Equal(t, want, got)
	})

	t.Run("trims whitespace before hashing", func(t *testing.T) {
		// Stability contract: callers pass the raw RemoteIPStringFromRequest
		// result, but a stray surrounding whitespace must not change the
		// hash domain — TrimSpace runs first.
		assert.Equal(t,
			HashRemoteAddr("203.0.113.42"),
			HashRemoteAddr("  203.0.113.42  "),
		)
	})

	t.Run("never returns plaintext IP", func(t *testing.T) {
		got := HashRemoteAddr("203.0.113.42")
		require.NotContains(t, got, "203")
		require.NotContains(t, got, "113")
		require.Len(t, got, 64) // hex SHA-256
	})
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ───────────────────────────────────────────────────────────────────────
// generateRATPlaintext / IsRATPlaintext
// ───────────────────────────────────────────────────────────────────────

func TestGenerateRATPlaintext(t *testing.T) {
	plain, err := generateRATPlaintext()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(plain, ratPlaintextPrefix), "wanted zdrat_ prefix, got %q", plain)
	assert.True(t, IsRATPlaintext(plain))

	// 48 random bytes → 64 base64url chars (no padding).
	rest := strings.TrimPrefix(plain, ratPlaintextPrefix)
	assert.Equal(t, 64, len(rest))
}

func TestGenerateRATPlaintext_DistinctPerCall(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 50; i++ {
		p, err := generateRATPlaintext()
		require.NoError(t, err)
		_, dup := seen[p]
		require.False(t, dup, "RAT collision after %d calls", i)
		seen[p] = struct{}{}
	}
}

func TestIsRATPlaintext(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"happy path", "zdrat_aGVsbG8td29ybGQ", true},
		{"missing prefix", "zdiat_aGVsbG8td29ybGQ", false},
		{"prefix only", "zdrat_", false},
		{"non-base64url body", "zdrat_!!!not-b64!!!", false},
		{"empty", "", false},
		{"random non-rat", "Bearer xyz", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsRATPlaintext(tc.in))
		})
	}
}

// ───────────────────────────────────────────────────────────────────────
// RegisterClient — end-to-end against fake pusher
// ───────────────────────────────────────────────────────────────────────

// fakeRegisterPusher records every event passed to Push so the test can
// assert event order, types, and payloads (cavekit-register-handler.md
// R6 requires a specific 4-event sequence).
type fakeRegisterPusher struct {
	mu     sync.Mutex
	pushed []eventstore.Command
}

func (p *fakeRegisterPusher) Health(context.Context) error { return nil }

func (p *fakeRegisterPusher) Push(_ context.Context, _ new_db.QueryExecutor, cmds ...eventstore.Command) ([]eventstore.Event, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pushed = append(p.pushed, cmds...)
	return nil, nil
}

func newRegisterClientFixture(t *testing.T, ids ...string) (*Commands, *fakeRegisterPusher) {
	t.Helper()
	hasher := &crypto.Hasher{
		Swapper: passwap.NewSwapper(bcrypt.New(bcrypt.MinCost)),
	}
	p := &fakeRegisterPusher{}
	es := eventstore.NewEventstore(&eventstore.Config{Pusher: p})

	// Default ids: appID, clientID. Override via variadic for ordered
	// consumption matching SetNewClientID + idGenerator.Next() calls.
	if len(ids) == 0 {
		ids = []string{"client-1", "app-1"}
	}
	gen := id_mock.NewIDGeneratorExpectIDs(t, ids...)

	c := &Commands{
		eventstore:      es,
		idGenerator:     gen,
		secretHasher:    hasher,
		newHashedSecret: mockHashedSecret("hashed-client-secret"),
	}
	return c, p
}

func TestRegisterClient_HappyPath_AnonymousMode_NoSecret(t *testing.T) {
	// SetNewClientID consumes 1 ID, then we consume another for AppID.
	c, p := newRegisterClientFixture(t, "client-x", "app-x")

	app := &domain.OIDCApp{
		AppName:         "claude-code",
		RedirectUris:    []string{"http://localhost:54212/callback"},
		ResponseTypes:   []domain.OIDCResponseType{domain.OIDCResponseTypeCode},
		GrantTypes:      []domain.OIDCGrantType{domain.OIDCGrantTypeAuthorizationCode, domain.OIDCGrantTypeRefreshToken},
		AuthMethodType:  ptrAuthMethod(domain.OIDCAuthMethodTypeNone),
		ApplicationType: ptrAppType(domain.OIDCApplicationTypeNative),
		OIDCVersion:     ptrVersion(domain.OIDCVersionV1),
	}

	res, err := c.RegisterClient(context.Background(), &RegisterClientInput{
		App:                 app,
		OrgID:               "org-1",
		ProjectID:           "proj-1",
		IATID:               "",
		RegistrationMethod:  RegistrationMethodAnonymous,
		ClientNameUnclamped: "claude-code",
		RemoteIPString:      "203.0.113.42",
		UserAgent:           "claude-code/1.0",
	})

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "client-x", res.ClientID)
	assert.Equal(t, "", res.ClientSecret, "auth_method=none MUST omit client_secret per RFC 7591")
	assert.True(t, IsRATPlaintext(res.RATPlaintext))
	assert.True(t, res.RATExpiresAt.IsZero(), "RATLifetime=0 MUST yield zero ExpiresAt (sentinel for no expiry)")
	assert.False(t, res.ClientIDIssuedAt.IsZero())

	// Event order is the R6 contract.
	require.Len(t, p.pushed, 4)
	_, ok := p.pushed[0].(*project_repo.ApplicationAddedEvent)
	assert.True(t, ok, "expected ApplicationAddedEvent at [0], got %T", p.pushed[0])
	_, ok = p.pushed[1].(*project_repo.OIDCConfigAddedEvent)
	assert.True(t, ok, "expected OIDCConfigAddedEvent at [1], got %T", p.pushed[1])
	dyn, ok := p.pushed[2].(*project_repo.ApplicationDynamicallyRegisteredEvent)
	require.True(t, ok, "expected ApplicationDynamicallyRegisteredEvent at [2], got %T", p.pushed[2])
	rat, ok := p.pushed[3].(*project_repo.ApplicationRegistrationAccessTokenSetEvent)
	require.True(t, ok, "expected ApplicationRegistrationAccessTokenSetEvent at [3], got %T", p.pushed[3])

	// Audit-event payload contract (R6 AC).
	assert.Equal(t, RegistrationMethodAnonymous, dyn.RegistrationMethod)
	assert.Equal(t, "", dyn.InitialAccessTokenID, "anonymous mode MUST emit empty IAT id")
	assert.Equal(t, "claude-code", dyn.ClientNameUnclamped)
	assert.Equal(t, "claude-code/1.0", dyn.UserAgent)
	assert.Equal(t, sha256Hex("203.0.113.42"), dyn.RemoteAddrSHA256, "remote IP MUST be SHA-256 hashed; never plaintext")
	assert.NotContains(t, dyn.RemoteAddrSHA256, "203")

	// RAT event contract: encoded hash never plaintext, ExpiresAt zero.
	assert.NotEqual(t, res.RATPlaintext, rat.HashedToken)
	assert.True(t, strings.HasPrefix(rat.HashedToken, "$"), "expected Passwap-encoded hash, got %q", rat.HashedToken)
	assert.True(t, rat.ExpiresAt.IsZero())
}

func TestRegisterClient_BasicAuth_EmitsClientSecret(t *testing.T) {
	c, p := newRegisterClientFixture(t, "client-y", "app-y")

	app := &domain.OIDCApp{
		AppName:         "web-app",
		RedirectUris:    []string{"https://example.com/cb"},
		ResponseTypes:   []domain.OIDCResponseType{domain.OIDCResponseTypeCode},
		GrantTypes:      []domain.OIDCGrantType{domain.OIDCGrantTypeAuthorizationCode},
		AuthMethodType:  ptrAuthMethod(domain.OIDCAuthMethodTypeBasic),
		ApplicationType: ptrAppType(domain.OIDCApplicationTypeWeb),
		OIDCVersion:     ptrVersion(domain.OIDCVersionV1),
	}

	res, err := c.RegisterClient(context.Background(), &RegisterClientInput{
		App:                 app,
		OrgID:               "org-1",
		ProjectID:           "proj-1",
		IATID:               "iat-99",
		RegistrationMethod:  RegistrationMethodIAT,
		ClientNameUnclamped: "web-app",
		RemoteIPString:      "198.51.100.7",
		UserAgent:           "curl/8",
	})

	require.NoError(t, err)
	assert.Equal(t, "hashed-client-secret", res.ClientSecret,
		"client_secret_basic MUST surface the plaintext secret (mocked) once")

	dyn := p.pushed[2].(*project_repo.ApplicationDynamicallyRegisteredEvent)
	assert.Equal(t, RegistrationMethodIAT, dyn.RegistrationMethod)
	assert.Equal(t, "iat-99", dyn.InitialAccessTokenID, "IAT mode MUST audit the consumed IAT id")
}

func TestRegisterClient_RejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		in   *RegisterClientInput
	}{
		{"nil", nil},
		{"nil app", &RegisterClientInput{ProjectID: "p", OrgID: "o", RegistrationMethod: RegistrationMethodAnonymous}},
		{"missing project", &RegisterClientInput{App: &domain.OIDCApp{AppName: "x"}, OrgID: "o", RegistrationMethod: RegistrationMethodAnonymous}},
		{"missing org", &RegisterClientInput{App: &domain.OIDCApp{AppName: "x"}, ProjectID: "p", RegistrationMethod: RegistrationMethodAnonymous}},
		{"missing app name", &RegisterClientInput{App: &domain.OIDCApp{}, ProjectID: "p", OrgID: "o", RegistrationMethod: RegistrationMethodAnonymous}},
		{"unknown registration method", &RegisterClientInput{App: &domain.OIDCApp{AppName: "x"}, ProjectID: "p", OrgID: "o", RegistrationMethod: "bogus"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Commands{
				idGenerator:  noopIDGen{},
				secretHasher: &crypto.Hasher{Swapper: passwap.NewSwapper(bcrypt.New(bcrypt.MinCost))},
			}
			_, err := c.RegisterClient(context.Background(), tc.in)
			assert.Error(t, err)
		})
	}
}

func TestRegisterClient_RATLifetime_StampsExpiry(t *testing.T) {
	c, p := newRegisterClientFixture(t, "client-z", "app-z")

	app := &domain.OIDCApp{
		AppName:         "x",
		RedirectUris:    []string{"https://example.com/cb"},
		ResponseTypes:   []domain.OIDCResponseType{domain.OIDCResponseTypeCode},
		GrantTypes:      []domain.OIDCGrantType{domain.OIDCGrantTypeAuthorizationCode},
		AuthMethodType:  ptrAuthMethod(domain.OIDCAuthMethodTypeNone),
		ApplicationType: ptrAppType(domain.OIDCApplicationTypeWeb),
		OIDCVersion:     ptrVersion(domain.OIDCVersionV1),
	}

	res, err := c.RegisterClient(context.Background(), &RegisterClientInput{
		App:                 app,
		OrgID:               "org-1",
		ProjectID:           "proj-1",
		RegistrationMethod:  RegistrationMethodAnonymous,
		ClientNameUnclamped: "x",
		RemoteIPString:      "203.0.113.1",
		RATLifetime:         60_000_000_000, // 60s
	})
	require.NoError(t, err)
	assert.False(t, res.RATExpiresAt.IsZero())

	rat := p.pushed[3].(*project_repo.ApplicationRegistrationAccessTokenSetEvent)
	assert.False(t, rat.ExpiresAt.IsZero())
}

// ───────────────────────────────────────────────────────────────────────
// helpers
// ───────────────────────────────────────────────────────────────────────

func ptrAuthMethod(v domain.OIDCAuthMethodType) *domain.OIDCAuthMethodType { return &v }
func ptrAppType(v domain.OIDCApplicationType) *domain.OIDCApplicationType  { return &v }
func ptrVersion(v domain.OIDCVersion) *domain.OIDCVersion                  { return &v }

// noopIDGen never gets called — it satisfies id.Generator for input
// validation tests that fail before any ID is generated.
type noopIDGen struct{}

var _ id.Generator = noopIDGen{}

func (noopIDGen) Next() (string, error) { return "", errors.New("noop") }
func (noopIDGen) NextID() (uint64, error) {
	return 0, errors.New("noop")
}
