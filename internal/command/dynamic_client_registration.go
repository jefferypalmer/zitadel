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
	"github.com/zitadel/zitadel/internal/repository/oidcsession"
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

// RehashRegistrationAccessToken pushes a single
// ApplicationRegistrationAccessTokenRehashedEvent on the project
// aggregate (cavekit-manage-handler.md R2 / T-051). Called by the dcr
// manage-handler verify path when Passwap's two-return Verify reports
// a non-empty `updatedHash` — the configured hash algorithm rotated
// since the RAT was last stored, and the new encoded form must be
// persisted so the next verification doesn't re-encode unnecessarily.
//
// The plaintext RAT is unchanged and the operation is invisible to the
// client. Lifetime is intentionally untouched (the projection reducer
// for the rehashed event omits the expires_at column).
//
// projectID, orgID, and appID MUST be the values the manage handler
// resolved via [query.Queries.DCRRATLookupByClientID] — silent rehash
// MUST route to the same aggregate the original RAT lives on. orgID
// is the project's resource owner; the manage handler does NOT use
// authz.GetCtxData here because RFC 7592 RAT-only requests have no
// user CtxData (the Bearer is the RAT, not a user session token).
func (c *Commands) RehashRegistrationAccessToken(ctx context.Context, projectID, orgID, appID, newEncodedHash string) error {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.End() }()

	if projectID == "" || orgID == "" || appID == "" || newEncodedHash == "" {
		return zerrors.ThrowInvalidArgument(nil, "DCR-RAT02", "Errors.Internal")
	}
	projectAgg := project_repo.NewAggregate(projectID, orgID).Aggregate
	_, err := c.eventstore.Push(ctx,
		project_repo.NewApplicationRegistrationAccessTokenRehashedEvent(ctx,
			&projectAgg,
			appID,
			newEncodedHash,
		),
	)
	return err
}

// UpdateRegisteredClientInput is the seam between the dcr PUT handler
// (cavekit-manage-handler.md R5 / T-054) and the command layer. The
// caller MUST have already passed the new metadata through
// `dcr.ValidateAndClampMetadata` (R4 rules, T-034) so the App argument
// here is the clamped form. UpdateRegisteredClient does no further
// vocabulary validation.
//
// ProjectID + OrgID + AppID route the change events to the correct
// aggregate — RFC 7592 RAT-only requests have no user CtxData, so the
// caller passes the resolved triple explicitly (same pattern as
// [Commands.RehashRegistrationAccessToken]).
//
// The auth-method transition matrix lives in this command (not the
// handler) so the secret-mint / secret-clear event push is atomic with
// the OIDCConfigChangedEvent push:
//
//   - old `none` + new `client_secret_basic`/`client_secret_post`
//     → mint a new secret, push OIDCConfigSecretChangedEvent.
//   - old `client_secret_*` + new `none`
//     → push OIDCConfigSecretChangedEvent with empty hash to clear the
//     stored column.
//   - old `none` + new `private_key_jwt`
//     → no secret event (auth uses jwks_uri; clamp already ensured a
//     valid jwks_uri is present).
//   - any other transition → no secret event.
//
// `client_secret_jwt` is rejected at the clamp layer (R5 AC), so this
// command never sees that value.
type UpdateRegisteredClientInput struct {
	ProjectID string
	OrgID     string
	AppID     string
	App       *domain.OIDCApp
	// RATLifetime caps the rotated RAT (cavekit-manage-handler.md R5 /
	// T-055). Mirrors `RegisterClientInput.RATLifetime`. Zero =
	// "no expiry" — the rotated event carries a zero-value ExpiresAt
	// and the projection reducer leaves the existing column untouched
	// (so a previously-finite RAT cannot be silently extended by a
	// rotation that fails to specify a lifetime).
	RATLifetime time.Duration
}

// UpdateRegisteredClientResult mirrors the subset of the persisted state
// the dcr PUT handler echoes to the client. ClientSecret is non-empty
// only when this PUT minted a new secret (auth-method transition
// `none → client_secret_*`); for all other transitions the field stays
// empty so the response writer can json:omitempty it per RFC 7592 §2.
type UpdateRegisteredClientResult struct {
	ClientID        string
	ClientSecret    string
	AuthMethodType  domain.OIDCAuthMethodType
	GrantTypes      []domain.OIDCGrantType
	ResponseTypes   []domain.OIDCResponseType
	ApplicationType domain.OIDCApplicationType
	RedirectURIs    []string
	ClientName      string
	ChangedAt       time.Time

	// RATPlaintext is the rotated RAT (cavekit-manage-handler.md R5 AC7
	// / T-055). Returned exactly once — the caller MUST surface it in
	// the 200 response body and treat the previous RAT as invalid from
	// this moment forward.
	RATPlaintext string
	// RATExpiresAt is the rotated RAT's expiry (zero = no expiry).
	// Mirrors RegisterClientResult.RATExpiresAt.
	RATExpiresAt time.Time
}

// UpdateRegisteredClient implements cavekit-manage-handler.md R5
// (T-054): full-replacement PUT against an existing dynamically-
// registered client. Re-clamp + auth-method transitions are atomic
// against the project aggregate.
//
// RAT rotation (R5 AC7-9) is OUT OF SCOPE for T-054 and lives in T-055
// — this command does not touch the RAT events. Layered separately so
// a malformed PUT body cannot rotate the RAT.
//
// Returns ThrowNotFound when the AppID is unknown / removed (the dcr
// handler maps that to 401 + WWW-Authenticate to avoid leaking the
// existence-vs-state distinction; mapping happens in the dispatcher).
func (c *Commands) UpdateRegisteredClient(ctx context.Context, in *UpdateRegisteredClientInput) (_ *UpdateRegisteredClientResult, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if in == nil || in.App == nil {
		return nil, zerrors.ThrowInvalidArgument(nil, "DCR-UC001", "Errors.Invalid.Argument")
	}
	if strings.TrimSpace(in.ProjectID) == "" || strings.TrimSpace(in.OrgID) == "" || strings.TrimSpace(in.AppID) == "" {
		return nil, zerrors.ThrowInvalidArgument(nil, "DCR-UC002", "Errors.Invalid.Argument")
	}

	existing, err := c.getOIDCAppWriteModel(ctx, in.ProjectID, in.AppID, in.OrgID)
	if err != nil {
		return nil, err
	}
	if existing.State == domain.AppStateUnspecified || existing.State == domain.AppStateRemoved {
		return nil, zerrors.ThrowNotFound(nil, "DCR-UC003", "Errors.Project.App.NotExisting")
	}
	if !existing.IsOIDC() {
		return nil, zerrors.ThrowInvalidArgument(nil, "DCR-UC004", "Errors.Project.App.IsNotOIDC")
	}

	app := in.App
	app.AggregateID = in.ProjectID
	app.AppID = in.AppID

	projectAgg := ProjectAggregateFromWriteModel(&existing.WriteModel)

	var backChannelLogout, loginBaseURI *string
	if app.BackChannelLogoutURI != nil {
		backChannelLogout = gu.Ptr(strings.TrimSpace(*app.BackChannelLogoutURI))
	}
	if app.LoginBaseURI != nil {
		loginBaseURI = gu.Ptr(strings.TrimSpace(*app.LoginBaseURI))
	}

	changedEvent, hasChanges, err := existing.NewChangedEvent(
		ctx,
		projectAgg,
		app.AppID,
		trimStringSliceWhiteSpaces(app.RedirectUris),
		trimStringSliceWhiteSpaces(app.PostLogoutRedirectUris),
		app.ResponseTypes,
		app.GrantTypes,
		app.ApplicationType,
		app.AuthMethodType,
		app.OIDCVersion,
		app.AccessTokenType,
		app.DevMode,
		app.AccessTokenRoleAssertion,
		app.IDTokenRoleAssertion,
		app.IDTokenUserinfoAssertion,
		app.ClockSkew,
		trimStringSliceWhiteSpaces(app.AdditionalOrigins),
		app.SkipNativeAppSuccessPage,
		backChannelLogout,
		app.LoginVersion,
		loginBaseURI,
	)
	if err != nil {
		return nil, err
	}

	// Auth-method transition decision. The new app's AuthMethodType is a
	// pointer (domain.OIDCApp); clamp guarantees it's set when shaped via
	// `domain.OIDCAppFromRFC7591Metadata`.
	oldAuth := existing.AuthMethodType
	var newAuth domain.OIDCAuthMethodType
	if app.AuthMethodType != nil {
		newAuth = *app.AuthMethodType
	} else {
		newAuth = oldAuth // no transition expressed → keep existing
	}

	cmds := make([]eventstore.Command, 0, 3)
	if hasChanges && changedEvent != nil {
		cmds = append(cmds, changedEvent)
	}

	var plainSecret string
	switch {
	case oldAuth == domain.OIDCAuthMethodTypeNone &&
		(newAuth == domain.OIDCAuthMethodTypeBasic || newAuth == domain.OIDCAuthMethodTypePost):
		// none → client_secret_*: mint a new secret atomically with the
		// changed event. Same path RegisterClient uses for first-time
		// secret issuance.
		encoded, plain, hashErr := c.newHashedSecret(ctx, c.eventstore.Filter) //nolint:staticcheck
		if hashErr != nil {
			return nil, hashErr
		}
		plainSecret = plain
		cmds = append(cmds, project_repo.NewOIDCConfigSecretChangedEvent(ctx, projectAgg, app.AppID, encoded))
	case (oldAuth == domain.OIDCAuthMethodTypeBasic || oldAuth == domain.OIDCAuthMethodTypePost) &&
		newAuth == domain.OIDCAuthMethodTypeNone:
		// client_secret_* → none: clear the stored hash. The projection
		// reducer writes the (empty) HashedSecret into the column —
		// `crypto.SecretOrEncodedHash("", "")` yields nil, which the
		// app-lookup path treats as "no secret stored".
		cmds = append(cmds, project_repo.NewOIDCConfigSecretChangedEvent(ctx, projectAgg, app.AppID, ""))
	}

	// RAT rotation (cavekit-manage-handler.md R5 AC7-9 / T-055). Every
	// successful PUT mints a fresh RAT and pushes the rotated event
	// atomically with any config / secret events. Old-RAT invalidation
	// happens implicitly because the projection reducer overwrites the
	// stored hash column — the next VerifyRAT against the previous
	// plaintext fails on Passwap.Verify.
	ratPlain, err := generateRATPlaintext()
	if err != nil {
		return nil, err
	}
	ratEncoded, err := c.secretHasher.Hash(ratPlain)
	if err != nil {
		return nil, zerrors.ThrowInternal(err, "DCR-UC005", "Errors.Internal")
	}
	now := time.Now().UTC()
	var ratExpiresAt time.Time
	if in.RATLifetime > 0 {
		ratExpiresAt = now.Add(in.RATLifetime)
	}
	cmds = append(cmds, project_repo.NewApplicationRegistrationAccessTokenRotatedEvent(ctx,
		projectAgg,
		app.AppID,
		ratEncoded,
		ratExpiresAt,
	))

	pushedEvents, pErr := c.eventstore.Push(ctx, cmds...)
	if pErr != nil {
		return nil, pErr
	}
	if appendErr := AppendAndReduce(existing, pushedEvents...); appendErr != nil {
		return nil, appendErr
	}

	return &UpdateRegisteredClientResult{
		ClientID:        existing.ClientID,
		ClientSecret:    plainSecret,
		AuthMethodType:  existing.AuthMethodType,
		GrantTypes:      existing.GrantTypes,
		ResponseTypes:   existing.ResponseTypes,
		ApplicationType: existing.ApplicationType,
		RedirectURIs:    existing.RedirectUris,
		ClientName:      existing.AppName,
		ChangedAt:       now,
		RATPlaintext:    ratPlain,
		RATExpiresAt:    ratExpiresAt,
	}, nil
}

// applicationTokenRevocations enumerates active OIDC sessions whose
// AddedEvent.ClientID matches the target client_id, tracking which
// sessions still have outstanding access / refresh tokens. Used by
// [Commands.RevokeApplicationTokens] (cavekit-manage-handler.md R6 /
// T-056) to decide which revocation events to push.
//
// Layout note: the OIDC session aggregate has no projection today
// (T-007 M4 worker report), so this write model walks the eventstore
// directly. It implements [eventstore.QueryReducer] so the same
// FilterToQueryReducer helper used everywhere else can drive it.
//
// Reduce is a streaming reducer — `Sessions` is keyed by aggregate ID
// and updated in-place as events arrive. After Reduce, [revocations]
// returns the sessions that still need a revocation event.
type applicationTokenRevocations struct {
	eventstore.WriteModel

	InstanceID string
	ClientID   string

	// Sessions is keyed by oidc_session aggregate ID. A session enters
	// the map on AddedEvent (only when ClientID matches the target);
	// access / refresh state flips on the per-token events.
	Sessions map[string]*revocationSessionState
}

type revocationSessionState struct {
	AggregateID    string
	ResourceOwner  string
	HasAccessToken bool
	HasRefreshToken bool
}

func newApplicationTokenRevocations(instanceID, clientID string) *applicationTokenRevocations {
	return &applicationTokenRevocations{
		WriteModel: eventstore.WriteModel{InstanceID: instanceID},
		InstanceID: instanceID,
		ClientID:   clientID,
		Sessions:   make(map[string]*revocationSessionState),
	}
}

// Query returns the eventstore search query — every oidc_session
// AddedEvent for the target instance, plus the per-token events the
// reducer needs to track active state. EventData filtering at the
// AddedEvent level lets the database narrow before any reduction
// runs (cuts the transferred row count by orders of magnitude on
// busy instances).
func (wm *applicationTokenRevocations) Query() *eventstore.SearchQueryBuilder {
	builder := eventstore.NewSearchQueryBuilder(eventstore.ColumnsEvent)
	if wm.InstanceID != "" {
		builder.InstanceID(wm.InstanceID)
	}
	// Branch 1: AddedEvents narrowed by EventData{clientID}. This is the
	// expensive filter (warning on `EventData`); narrow first so the
	// follow-up branch only inflates by event-count not row count.
	builder.AddQuery().
		AggregateTypes(oidcsession.AggregateType).
		EventTypes(oidcsession.AddedType).
		EventData(map[string]interface{}{"clientID": wm.ClientID}).
		Builder()
	// Branch 2: per-token events for ANY session aggregate. Reduce
	// drops them on the floor when their aggregate ID isn't in the
	// known-clientID set — the cost is one map lookup per event.
	builder.AddQuery().
		AggregateTypes(oidcsession.AggregateType).
		EventTypes(
			oidcsession.AccessTokenAddedType,
			oidcsession.AccessTokenRevokedType,
			oidcsession.RefreshTokenAddedType,
			oidcsession.RefreshTokenRenewedType,
			oidcsession.RefreshTokenRevokedType,
		).
		Builder()
	return builder
}

// Reduce is the streaming reducer. AddedEvent enters the per-aggregate
// state when ClientID matches. The per-token events flip the active
// flags only when the aggregate ID is already in the map (any other
// session is unrelated to our client).
func (wm *applicationTokenRevocations) Reduce() error {
	for _, e := range wm.Events {
		switch ev := e.(type) {
		case *oidcsession.AddedEvent:
			if ev.ClientID != wm.ClientID {
				continue
			}
			id := ev.Aggregate().ID
			if _, exists := wm.Sessions[id]; !exists {
				wm.Sessions[id] = &revocationSessionState{
					AggregateID:   id,
					ResourceOwner: ev.Aggregate().ResourceOwner,
				}
			}
		case *oidcsession.AccessTokenAddedEvent:
			if s, ok := wm.Sessions[ev.Aggregate().ID]; ok {
				s.HasAccessToken = true
			}
		case *oidcsession.AccessTokenRevokedEvent:
			if s, ok := wm.Sessions[ev.Aggregate().ID]; ok {
				s.HasAccessToken = false
			}
		case *oidcsession.RefreshTokenAddedEvent, *oidcsession.RefreshTokenRenewedEvent:
			if s, ok := wm.Sessions[ev.Aggregate().ID]; ok {
				s.HasRefreshToken = true
			}
		case *oidcsession.RefreshTokenRevokedEvent:
			if s, ok := wm.Sessions[ev.Aggregate().ID]; ok {
				s.HasRefreshToken = false
				// RefreshTokenRevoked also invalidates the access token
				// per the existing session model contract; mirror it
				// here so the revocation pass doesn't double-emit a
				// stale access-token revocation.
				s.HasAccessToken = false
			}
		}
	}
	wm.Events = nil
	return nil
}

// AppendEvents satisfies the QueryReducer requirement.
func (wm *applicationTokenRevocations) AppendEvents(events ...eventstore.Event) {
	wm.WriteModel.AppendEvents(events...)
}

// revocations returns the sessions that still need a revocation event.
// A session contributes at most one access-token revocation and one
// refresh-token revocation; both are pushed in the same eventstore
// transaction so the projection sees them atomically.
func (wm *applicationTokenRevocations) revocations() []*revocationSessionState {
	out := make([]*revocationSessionState, 0, len(wm.Sessions))
	for _, s := range wm.Sessions {
		if s.HasAccessToken || s.HasRefreshToken {
			out = append(out, s)
		}
	}
	return out
}

// RevokeApplicationTokens emits revocation events for every active
// access / refresh token owned by sessions whose AddedEvent.ClientID
// matches the target client (cavekit-manage-handler.md R6 / T-056
// path-(a) per the M4 worker decision). Returns the count of sessions
// touched so the DCR DELETE handler can audit-log it.
//
// Volume note (kit residual risk): on a busy instance with thousands
// of active sessions per client, this writes thousands of events in a
// single Push. Phase 1 accepts the cost; Phase 2 may batch in chunks
// or async-defer.
//
// The aggregate boundary: revocation events live on the per-session
// `oidc_session` aggregates (not on the project aggregate). One Push
// is multi-aggregate — supported by the eventstore.
func (c *Commands) RevokeApplicationTokens(ctx context.Context, clientID string) (count int, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if strings.TrimSpace(clientID) == "" {
		return 0, zerrors.ThrowInvalidArgument(nil, "DCR-RA001", "Errors.Invalid.Argument")
	}
	instanceID := authz.GetInstance(ctx).InstanceID()

	wm := newApplicationTokenRevocations(instanceID, clientID)
	if err := c.eventstore.FilterToQueryReducer(ctx, wm); err != nil {
		return 0, zerrors.ThrowInternal(err, "DCR-RA002", "Errors.Internal")
	}

	candidates := wm.revocations()
	if len(candidates) == 0 {
		return 0, nil
	}

	cmds := make([]eventstore.Command, 0, len(candidates)*2)
	for _, s := range candidates {
		agg := &oidcsession.NewAggregate(s.AggregateID, s.ResourceOwner).Aggregate
		// Refresh-token revocation is the strict superset (it implicitly
		// invalidates the access-token in the session model). Push it
		// alone when both flags were set; push access-token revocation
		// by itself otherwise. Cuts the event count in half for the
		// common case (sessions with both an access and a refresh
		// token, which is most of them).
		if s.HasRefreshToken {
			cmds = append(cmds, oidcsession.NewRefreshTokenRevokedEvent(ctx, agg))
			continue
		}
		if s.HasAccessToken {
			cmds = append(cmds, oidcsession.NewAccessTokenRevokedEvent(ctx, agg))
		}
	}

	if len(cmds) == 0 {
		return 0, nil
	}
	if _, err := c.eventstore.Push(ctx, cmds...); err != nil {
		return 0, err
	}
	return len(candidates), nil
}

// DeleteRegisteredClient implements cavekit-manage-handler.md R6
// (T-056) — RFC 7592 DELETE. Sequence:
//   1. RevokeApplicationTokens — emit revocation events for every
//      outstanding access / refresh token belonging to the client.
//   2. ApplicationRemovedEvent — push on the project aggregate.
//
// The two pushes are NOT a single transaction (different aggregate
// types). Order: revocations first, then removal — if step 2 fails
// after step 1 succeeds we end up with revoked tokens on a still-
// existing app, which is strictly safer than the inverse (app removed
// but tokens still introspect as active until they expire).
//
// Bypasses the [Commands.RemoveApplication] permission check because
// RFC 7592 RAT-only requests carry no user CtxData — the RAT is the
// authorization (verified upstream by [dcr.VerifyRAT] / T-051).
func (c *Commands) DeleteRegisteredClient(ctx context.Context, projectID, orgID, appID, clientID string) (revokedSessions int, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(orgID) == "" || strings.TrimSpace(appID) == "" {
		return 0, zerrors.ThrowInvalidArgument(nil, "DCR-DC001", "Errors.Invalid.Argument")
	}

	revokedSessions, err = c.RevokeApplicationTokens(ctx, clientID)
	if err != nil {
		return 0, err
	}

	existing, err := c.getOIDCAppWriteModel(ctx, projectID, appID, orgID)
	if err != nil {
		return revokedSessions, err
	}
	if existing.State == domain.AppStateUnspecified || existing.State == domain.AppStateRemoved {
		return revokedSessions, zerrors.ThrowNotFound(nil, "DCR-DC002", "Errors.Project.App.NotExisting")
	}
	projectAgg := ProjectAggregateFromWriteModel(&existing.WriteModel)
	if _, err := c.eventstore.Push(ctx,
		project_repo.NewApplicationRemovedEvent(ctx, projectAgg, appID, existing.AppName, ""),
	); err != nil {
		return revokedSessions, err
	}
	return revokedSessions, nil
}

