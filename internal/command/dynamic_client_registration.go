package command

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/muhlemmer/gu"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	project_repo "github.com/zitadel/zitadel/internal/repository/project"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// RAT plaintext format: `zdrat_` + base64url(48 random bytes).
// Distinct from `zdiat_` (IAT) so the cavekit-security-hardening.md R3
// log-redaction regex `zd(iat|rat)_[^\s"',]+` can target both. 48 random
// bytes = 384 bits — well above any realistic search-space attack budget.
const (
	ratPlaintextPrefix     = "zdrat_"
	ratPlaintextRandomSize = 48
)

// RegistrationMethod values for the audit event.
const (
	RegistrationMethodAnonymous = "anonymous"
	RegistrationMethodIAT       = "iat"
)

// RegisterClientInput carries everything the DCR registration handler
// extracts from the inbound request: the clamped OIDCApp (from T-039
// OIDCAppFromRFC7591Metadata), the org/project the application is being
// created under, the IAT id consumed (empty for anonymous mode), the
// RFC 7591 pass-through metadata for the dcr_meta JSONB column, and the
// audit context (un-clamped client_name + remote IP string + UA).
//
// The remote IP is hashed inside RegisterClient — callers MUST pass the
// pre-hash plaintext from `internal/api/http.RemoteIPStringFromRequest`
// per cavekit-register-handler.md R6 AC `remote_addr_sha256`.
type RegisterClientInput struct {
	App                  *domain.OIDCApp
	OrgID                string
	ProjectID            string
	IATID                string
	DCRMeta              map[string]any
	SoftwareStatementJTI string
	RegistrationMethod   string
	ClientNameUnclamped  string
	RemoteIPString       string
	UserAgent            string
	RATLifetime          time.Duration
	// ClientSecretLifetime caps the issued client_secret per
	// cavekit-register-handler.md R7. Zero = "no expiry" sentinel
	// (RFC 7591 §3.2.1). Production wiring threads
	// `OIDC.DCR.ClientSecretExpiresIn` into this slot.
	ClientSecretLifetime time.Duration
}

// RegisterClientResult is the post-commit projection of the data the
// DCR HTTP handler must echo to the client per RFC 7591 §3.2.1
// (cavekit-register-handler.md R7).
type RegisterClientResult struct {
	ClientID         string
	ClientSecret     string
	// ClientSecretExpiresIn echoes the input lifetime so the dispatcher
	// can compute `client_secret_expires_at` per R7. Zero = no expiry.
	ClientSecretExpiresIn time.Duration
	RATPlaintext     string
	RATExpiresAt     time.Time
	ClientIDIssuedAt time.Time
	// PersistedAppName is the AppName actually stored on the
	// ApplicationAddedEvent — the synthesised
	// `Dynamically Registered Client <clientID[:8]>` form when the
	// caller passed empty AppName, otherwise the caller's value
	// unchanged. The DCR HTTP dispatcher reflects this back into the
	// 201 response body's client_name (cavekit-register-handler.md R7).
	PersistedAppName string
}

// RegisterClient implements the cavekit-register-handler.md R6 contract.
//
// It pushes — in this exact order, on the project aggregate — the four
// events: ApplicationAddedEvent (existing), OIDCConfigAddedEvent (existing),
// ApplicationDynamicallyRegisteredEvent (new — T-040), and
// ApplicationRegistrationAccessTokenSetEvent (new — T-040). Reuses the
// existing OIDCApplicationWriteModel; no new write model.
//
// Concurrent registrations under the same project serialize on the
// project aggregate's eventstore lock — same characteristic as the IAT
// consume path (cavekit-iat.md R7 / T-025).
//
// Caller responsibilities:
//   - The OIDCApp argument MUST already have been clamped by
//     `dcr.ValidateAndClampMetadata` (T-034) and mapped via
//     `domain.OIDCAppFromRFC7591Metadata` (T-039). RegisterClient does
//     no further validation of OIDC vocabulary.
//   - For IAT mode, the caller MUST have already verified the IAT and
//     consumed a slot via `Commands.ConsumeInitialAccessToken`. Passing
//     a non-empty `IATID` is purely audit metadata — RegisterClient does
//     not re-consume.
//   - `RemoteIPString` MUST come from `http.RemoteIPStringFromRequest`
//     (XFF first hop or RemoteAddr fallback). RegisterClient SHA-256s
//     it before persisting; plaintext IP NEVER touches the eventstore.
func (c *Commands) RegisterClient(ctx context.Context, in *RegisterClientInput) (_ *RegisterClientResult, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if in == nil || in.App == nil {
		return nil, zerrors.ThrowInvalidArgument(nil, "DCR-RC001", "Errors.Invalid.Argument")
	}
	if strings.TrimSpace(in.ProjectID) == "" || strings.TrimSpace(in.OrgID) == "" {
		return nil, zerrors.ThrowInvalidArgument(nil, "DCR-RC002", "Errors.Invalid.Argument")
	}
	if in.RegistrationMethod != RegistrationMethodAnonymous && in.RegistrationMethod != RegistrationMethodIAT {
		return nil, zerrors.ThrowInvalidArgument(nil, "DCR-RC003", "Errors.Invalid.Argument")
	}
	if strings.TrimSpace(in.App.AppName) == "" {
		return nil, zerrors.ThrowInvalidArgument(nil, "DCR-RC004", "Errors.Invalid.Argument")
	}

	// Bind the OIDCApp to the project aggregate and stamp issued-at.
	// We deliberately do NOT run FilterToQueryReducer against an
	// OIDCApplicationWriteModel here: the appID is freshly minted by
	// idGenerator below (snowflake — collision-free by construction),
	// so the duplicate-app check the AddOIDCApplicationWithID path
	// performs is moot for DCR. Project existence is the caller's
	// contract (anonymous mode validates DefaultProjectID at startup
	// per cavekit-config.md R4 / T-009; IAT mode binds via the IAT
	// row's project_id per cavekit-iat.md R3 / T-037).
	in.App.AggregateID = in.ProjectID
	now := time.Now().UTC()

	if err := domain.SetNewClientID(in.App, c.idGenerator); err != nil {
		return nil, err
	}
	in.App.AppID, err = c.idGenerator.Next()
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "DCR-RC005", "Errors.Internal")
	}

	// cavekit-register-handler.md R2 AC: empty/missing client_name is
	// replaced with `Dynamically Registered Client <clientID[:8]>`.
	// Done HERE (not at the dispatcher) because the synthesis needs the
	// post-mint clientID, and persisting a placeholder then updating
	// would require an extra event push. Keeping it inside RegisterClient
	// means the synthesis happens atomically with ApplicationAddedEvent.
	if strings.TrimSpace(in.App.AppName) == "" {
		idSuffix := in.App.ClientID
		if len(idSuffix) > 8 {
			idSuffix = idSuffix[:8]
		}
		in.App.AppName = "Dynamically Registered Client " + idSuffix
	}

	plainSecret, err := domain.SetNewClientSecretIfNeeded(in.App, func() (string, string, error) {
		return c.newHashedSecret(ctx, c.eventstore.Filter) //nolint:staticcheck
	})
	if err != nil {
		return nil, err
	}

	ratPlain, err := generateRATPlaintext()
	if err != nil {
		return nil, err
	}
	ratEncoded, err := c.secretHasher.Hash(ratPlain)
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "DCR-RC006", "Errors.Internal")
	}
	var ratExpiresAt time.Time
	if in.RATLifetime > 0 {
		ratExpiresAt = now.Add(in.RATLifetime)
	}

	projectAgg := project_repo.NewAggregate(in.ProjectID, in.OrgID).Aggregate

	cmds := []eventstore.Command{
		project_repo.NewApplicationAddedEvent(ctx, &projectAgg, in.App.AppID, in.App.AppName),
		project_repo.NewOIDCConfigAddedEvent(ctx,
			&projectAgg,
			gu.Value(in.App.OIDCVersion),
			in.App.AppID,
			in.App.ClientID,
			in.App.EncodedHash,
			trimStringSliceWhiteSpaces(in.App.RedirectUris),
			in.App.ResponseTypes,
			in.App.GrantTypes,
			gu.Value(in.App.ApplicationType),
			gu.Value(in.App.AuthMethodType),
			trimStringSliceWhiteSpaces(in.App.PostLogoutRedirectUris),
			gu.Value(in.App.DevMode),
			gu.Value(in.App.AccessTokenType),
			gu.Value(in.App.AccessTokenRoleAssertion),
			gu.Value(in.App.IDTokenRoleAssertion),
			gu.Value(in.App.IDTokenUserinfoAssertion),
			gu.Value(in.App.ClockSkew),
			trimStringSliceWhiteSpaces(in.App.AdditionalOrigins),
			gu.Value(in.App.SkipNativeAppSuccessPage),
			strings.TrimSpace(gu.Value(in.App.BackChannelLogoutURI)),
			gu.Value(in.App.LoginVersion),
			strings.TrimSpace(gu.Value(in.App.LoginBaseURI)),
		),
		project_repo.NewApplicationDynamicallyRegisteredEvent(ctx,
			&projectAgg,
			in.App.AppID,
			in.IATID,
			in.SoftwareStatementJTI,
			in.RegistrationMethod,
			in.ClientNameUnclamped,
			HashRemoteAddr(in.RemoteIPString),
			in.UserAgent,
			in.DCRMeta,
		),
		project_repo.NewApplicationRegistrationAccessTokenSetEvent(ctx,
			&projectAgg,
			in.App.AppID,
			ratEncoded,
			ratExpiresAt,
		),
	}

	if _, err := c.eventstore.Push(ctx, cmds...); err != nil {
		return nil, err
	}

	return &RegisterClientResult{
		ClientID:              in.App.ClientID,
		ClientSecret:          plainSecret,
		ClientSecretExpiresIn: in.ClientSecretLifetime,
		RATPlaintext:          ratPlain,
		RATExpiresAt:          ratExpiresAt,
		ClientIDIssuedAt:      now,
		PersistedAppName:      in.App.AppName,
	}, nil
}

// HashRemoteAddr returns the lowercase hex SHA-256 of the input string.
// Empty input returns empty string so the audit field stays absent in
// the event payload (json:omitempty) when the handler could not extract
// an IP. The hash domain-separates a remote_addr from any other field —
// downstream tooling that wants to correlate registrations from the
// same IP can recompute the SHA-256 without touching plaintext.
//
// Per cavekit-register-handler.md R6 the input MUST be the
// `RemoteIPStringFromRequest` result (XFF first hop or RemoteAddr
// fallback) — not a parsed net.IP, not a normalized form. Stability of
// the hash is contingent on stability of that string.
func HashRemoteAddr(remoteIPString string) string {
	s := strings.TrimSpace(remoteIPString)
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// generateRATPlaintext returns a fresh `zdrat_<48-byte-b64url>` token.
// Crypto-random source is `crypto/rand`; failure to read is propagated
// as an internal error (the caller cannot recover from RNG failure).
func generateRATPlaintext() (string, error) {
	buf := make([]byte, ratPlaintextRandomSize)
	if _, err := rand.Read(buf); err != nil {
		return "", zerrors.ThrowInternal(err, "DCR-RAT01", "Errors.Internal")
	}
	return ratPlaintextPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// IsRATPlaintext is the cheap structural check the handler can use
// before invoking secretHasher.Verify (which is comparatively expensive
// because Passwap intentionally tarpits). A bearer that doesn't carry
// the `zdrat_` prefix can be rejected with the same anti-enumeration
// dummy-Verify path the IAT lookup uses (cavekit-iat.md R4).
func IsRATPlaintext(s string) bool {
	if !strings.HasPrefix(s, ratPlaintextPrefix) {
		return false
	}
	rest := s[len(ratPlaintextPrefix):]
	if rest == "" {
		return false
	}
	// base64.RawURLEncoding alphabet check.
	_, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil
}

// _ pulls in authz to anchor the import for follow-up tasks (T-053
// GET handler reads instance from context). Keeping it here avoids a
// churn diff once T-053 lands.
var _ = authz.GetInstance
