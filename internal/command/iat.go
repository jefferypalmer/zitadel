package command

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/repository/project"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// IATPlaintextPrefix is the literal prefix attached to every IAT
// plaintext token (cavekit-iat.md R5 / T-021). The chosen string is
// disjoint from every other Zitadel token prefix verified by M1 grep
// at T-021 implementation:
//
//	at_       — access token
//	rt_       — refresh token
//	sess_     — session token
//	zdiat_    — initial access token (this kit, no collision)
//
// The prefix doubles as the wire-format discriminator for any future
// token-prefix unification work; for now nothing depends on parsing it
// out — it is purely a human/admin readability marker.
const IATPlaintextPrefix = "zdiat_"

// iatRandomBytes is the count of cryptographically-random bytes encoded
// into the plaintext after the prefix. Per cavekit-iat.md R5: "decoded
// random portion is 48 bytes". 48 bytes → 64 base64url chars (no
// padding) → entropy of 384 bits, well above 128-bit collision floor.
const iatRandomBytes = 48

// iatIDSeparator is the literal byte that delimits the IAT row ID
// from the random portion in the plaintext (cavekit-iat.md R5
// amendment 2026-04-26). The parser splits on the FIRST occurrence
// only, so additional `.` characters in the random suffix do not
// confuse the split.
const iatIDSeparator = "."

// iatIDAlphabet bounds the characters allowed in the `<id>` portion
// of the plaintext to the URL-safe set Sonyflake produces. Stricter
// than RFC 7591 needs but defensive against ID-shape weirdness
// reaching the SQL layer (parameterized queries already protect; this
// is belt + suspenders).
func iatIDAlphabetOK(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_', r == '-':
			continue
		default:
			return false
		}
	}
	return true
}

// GenerateIATPlaintextForID produces a fresh IAT plaintext token in
// the form `zdiat_<id>.<random>` per cavekit-iat.md R5 (amended
// 2026-04-26 / DE-001). `<id>` is the IAT row's primary-key ID — the
// caller MUST allocate it before calling this function so the
// returned plaintext, the persisted hash, and the projection row all
// reference the same ID. `<random>` is base64url(48 random bytes) =
// 384 bits of crypto/rand entropy.
//
// The plaintext is the ONLY representation that can later be
// presented as the Bearer token; the caller MUST hash the entire
// returned string (not just the random portion) before persistence
// and MUST surface plaintext exactly once at issue time.
//
// Returns an error if the id violates the iatIDAlphabet contract —
// programmer error, caught at test-time.
func GenerateIATPlaintextForID(id string) (string, error) {
	if !iatIDAlphabetOK(id) {
		return "", zerrors.ThrowInternal(nil, "COMMA-IAT01b",
			"IAT id must be non-empty URL-safe alphanumerics + `_-`; got "+id)
	}
	buf := make([]byte, iatRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", zerrors.ThrowInternal(err, "COMMA-IAT01", "Errors.Internal")
	}
	return IATPlaintextPrefix + id + iatIDSeparator + base64.RawURLEncoding.EncodeToString(buf), nil
}

// IsIATPlaintext reports whether s carries the IAT plaintext prefix.
// Cheap structural check used by the registration handler (T-037)
// before invoking the slow Passwap verify path on a presented Bearer.
func IsIATPlaintext(s string) bool {
	return strings.HasPrefix(s, IATPlaintextPrefix)
}

// ParseIATPlaintext parses a presented Bearer IAT plaintext into its
// (id, random) parts per cavekit-iat.md R5. Returns ok=false on:
//   - missing or wrong prefix (case-sensitive)
//   - missing `.` separator
//   - empty `<id>` portion
//   - empty `<random>` portion
//   - `<id>` characters outside [A-Za-z0-9_-]
//
// The split uses strings.Cut on the FIRST `.` so an attacker who
// places extra `.` characters in the random portion cannot smuggle
// values into the id portion or vice versa.
//
// The returned (id, random) values are ONLY suitable for lookup
// (id) and verification-substrate (random) — the caller MUST still
// run VerifyIATPlaintext against the full original presented string
// to authenticate.
func ParseIATPlaintext(presented string) (id, random string, ok bool) {
	if !strings.HasPrefix(presented, IATPlaintextPrefix) {
		return "", "", false
	}
	body := presented[len(IATPlaintextPrefix):]
	idPart, randomPart, found := strings.Cut(body, iatIDSeparator)
	if !found {
		return "", "", false
	}
	if randomPart == "" {
		return "", "", false
	}
	if !iatIDAlphabetOK(idPart) {
		return "", "", false
	}
	return idPart, randomPart, true
}

// CreateInitialAccessToken issues a new IAT under the given project.
// Steps (cavekit-iat.md R5 + R1):
//
//  1. Generate plaintext via GenerateIATPlaintext.
//  2. Hash the plaintext via the secret hasher (Passwap-encoded).
//     ONLY the hash is persisted — plaintext is returned to the caller
//     once and never written back.
//  3. Push InitialAccessTokenAddedEvent on the project aggregate
//     carrying the hash + metadata.
//
// Returned plaintext MUST be surfaced to the admin caller exactly
// once and treated as a credential. Subsequent ListInitialAccessToken
// responses cannot reproduce it (the projection stores only the hash).
//
// Concurrent consumption of IATs from the same project is serialized
// by eventstore aggregate locking; use multiple projects for
// parallelism (cavekit-iat.md R7 — pinned in T-025).
func (c *Commands) CreateInitialAccessToken(
	ctx context.Context,
	projectID, resourceOwner, description string,
	maxUses int,
	lifetime time.Duration,
	allowedGrantTypes []string,
	allowedRedirectURIPatterns []string,
) (plaintext, iatID string, err error) {
	if strings.TrimSpace(projectID) == "" {
		return "", "", zerrors.ThrowInvalidArgument(nil, "COMMA-IAT02", "Errors.Project.IDMissing")
	}
	if maxUses < 0 {
		return "", "", zerrors.ThrowInvalidArgument(nil, "COMMA-IAT03", "Errors.DCR.IAT.MaxUsesNegative")
	}

	// Verify project exists + resolve resource owner. checkProjectExists
	// returns the resourceOwner of the project so callers can pass empty
	// and get the canonical RO back.
	ro, err := c.checkProjectExists(ctx, projectID, resourceOwner)
	if err != nil {
		return "", "", err
	}

	// Allocate IAT row ID FIRST so it can be embedded in the plaintext
	// (cavekit-iat.md R5 amendment 2026-04-26 / DE-001). The plaintext
	// shape `zdiat_<id>.<random>` lets the registration handler
	// resolve the row by ID without needing a deterministic hash index.
	iatID, err = c.idGenerator.Next()
	if err != nil {
		return "", "", err
	}

	plaintext, err = GenerateIATPlaintextForID(iatID)
	if err != nil {
		return "", "", err
	}
	hash, err := c.secretHasher.Hash(plaintext)
	if err != nil {
		return "", "", zerrors.ThrowInternal(err, "COMMA-IAT04", "Errors.Internal")
	}

	var expiresAt *time.Time
	if lifetime > 0 {
		t := time.Now().Add(lifetime)
		expiresAt = &t
	}

	agg := project.NewAggregate(projectID, authz.GetInstance(ctx).InstanceID()).Aggregate
	agg.ResourceOwner = ro
	_, err = c.eventstore.Push(ctx, project.NewInitialAccessTokenAddedEvent(
		ctx,
		&agg,
		iatID,
		hash,
		projectID,
		description,
		maxUses,
		expiresAt,
		allowedGrantTypes,
		allowedRedirectURIPatterns,
	))
	if err != nil {
		return "", "", err
	}
	return plaintext, iatID, nil
}

// IATSnapshot is the projection state of an IAT at the moment the
// consume command read it. Each retry loop iteration calls the
// IATLookup closure to get a fresh snapshot before picking the next
// slot — that's how revocation / expiry committed between retries are
// observed (cavekit-iat.md R2 AC1, AC2).
type IATSnapshot struct {
	ID            string
	ProjectID     string
	InstanceID    string
	ResourceOwner string
	MaxUses       int
	UsesConsumed  int
	Revoked       bool
	ExpiresAt     *time.Time
}

// IATLookup is the projection-read seam — the consume command calls it
// on every retry. Concrete callers (the registration handler at T-037)
// wrap query.Queries.InitialAccessTokenByID to satisfy this signature.
// The lookup MUST return the latest projected state, not a cached snapshot.
type IATLookup func(ctx context.Context) (*IATSnapshot, error)

// IATConsumeMaxAttempts caps the retry loop in ConsumeInitialAccessToken
// per cavekit-iat.md R2 AC4 ("retries up to 3 total attempts").
const IATConsumeMaxAttempts = 3

// ConsumeInitialAccessToken consumes one slot of the IAT identified by
// the lookup closure. Race safety:
//
//   - The eventstore-level UniqueConstraint per (iat_id, use_index)
//     declared by InitialAccessTokenConsumedEvent (T-011, finite=true)
//     guarantees that two parallel consumers cannot both succeed for
//     the same slot. The loser receives zerrors.ThrowAlreadyExists
//     and we re-fetch the projection then retry with the next slot.
//   - For max_uses=0 (unlimited), no UniqueConstraint is declared and
//     the consume always succeeds; the slot index still increments
//     for audit linkage but contention is benign.
//
// Returned (slot, nil) on success — slot is the use_index that was
// reserved (== usesConsumed at the moment of push). On failure returns
// a typed error the registration handler maps to HTTP 401 with
// `error_description: "initial access token exhausted"` (R2 AC5).
//
// Concurrent consumption of IATs from the same project is serialized
// by eventstore aggregate locking; use multiple projects for
// parallelism (R7 — pinned in T-025 godoc).
func (c *Commands) ConsumeInitialAccessToken(ctx context.Context, lookup IATLookup) (slot int, err error) {
	for attempt := 1; attempt <= IATConsumeMaxAttempts; attempt++ {
		snap, lookupErr := lookup(ctx)
		if lookupErr != nil {
			return -1, lookupErr
		}
		if snap.Revoked {
			return -1, zerrors.ThrowInvalidArgument(nil, "COMMA-IAT07", "Errors.DCR.IAT.Revoked")
		}
		if snap.ExpiresAt != nil && !snap.ExpiresAt.After(time.Now()) {
			return -1, zerrors.ThrowInvalidArgument(nil, "COMMA-IAT08", "Errors.DCR.IAT.Expired")
		}
		finite := snap.MaxUses > 0
		if finite && snap.UsesConsumed >= snap.MaxUses {
			return -1, zerrors.ThrowInvalidArgument(nil, "COMMA-IAT09", "Errors.DCR.IAT.Exhausted")
		}

		slot = snap.UsesConsumed
		agg := project.NewAggregate(snap.ProjectID, snap.InstanceID).Aggregate
		agg.ResourceOwner = snap.ResourceOwner
		_, pushErr := c.eventstore.Push(ctx, project.NewInitialAccessTokenConsumedEvent(
			ctx, &agg, snap.ID, slot, finite,
		))
		if pushErr == nil {
			return slot, nil
		}
		if !zerrors.IsErrorAlreadyExists(pushErr) {
			return -1, pushErr
		}
		// Slot reserved by a concurrent consumer between our read and
		// push. Re-fetch the projection on the next loop iteration so a
		// freshly-committed revoke / expire / max-uses-bump is observed.
	}
	return -1, zerrors.ThrowInvalidArgument(nil, "COMMA-IAT10", "Errors.DCR.IAT.Exhausted")
}

// RevokeInitialAccessToken pushes the project.initial_access_token.revoked
// event for the given IAT. Idempotent at the projection (the reducer
// re-sets revoked=TRUE) but not at the eventstore — repeated revokes
// add audit trail entries.
func (c *Commands) RevokeInitialAccessToken(ctx context.Context, iatID, projectID, resourceOwner string) error {
	if strings.TrimSpace(iatID) == "" {
		return zerrors.ThrowInvalidArgument(nil, "COMMA-IAT11", "Errors.DCR.IAT.IDMissing")
	}
	ro, err := c.checkProjectExists(ctx, projectID, resourceOwner)
	if err != nil {
		return err
	}
	agg := project.NewAggregate(projectID, authz.GetInstance(ctx).InstanceID()).Aggregate
	agg.ResourceOwner = ro
	_, err = c.eventstore.Push(ctx, project.NewInitialAccessTokenRevokedEvent(ctx, &agg, iatID))
	return err
}

// VerifyIATPlaintext checks a presented Bearer plaintext against an
// IAT's stored hash via the secret hasher. Returns nil on success;
// returns a typed not-found-equivalent error on mismatch so the
// registration handler can map to HTTP 401 invalid_token without
// distinguishing "wrong token" from "no such IAT" (anti-enumeration).
//
// T-051 (RFC 7592 RAT verification) introduces the rehash-on-success
// pattern via the two-return Hasher.Verify; T-021 ships the simple
// match-only variant — the registration handler call site at T-037
// can switch to two-return without rebuilding the signature.
func (c *Commands) VerifyIATPlaintext(presented, encodedHash string) error {
	if presented == "" || encodedHash == "" {
		return zerrors.ThrowInvalidArgument(nil, "COMMA-IAT05", "Errors.DCR.IAT.InvalidToken")
	}
	// Verify returns (updated, error). The updated string is the
	// rehashed encoding when the hasher params changed; the registration
	// handler at T-037 will swap to a two-return form to emit the silent
	// rehash event (cavekit-manage-handler.md R2 / T-051). For T-021's
	// purposes we only care about match success.
	if _, err := c.secretHasher.Verify(encodedHash, presented); err != nil {
		// Don't leak whether the IAT row exists vs the hash mismatched
		// — both map to the same 401 at the handler.
		return zerrors.ThrowInvalidArgument(err, "COMMA-IAT06", "Errors.DCR.IAT.InvalidToken")
	}
	return nil
}
