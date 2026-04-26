---
created: "2026-04-26T22:00:00Z"
last_edited: "2026-04-26T22:00:00Z"
---
# Dead Ends — DCR Build Site

Build site: context/plans/build-site.md

Document approaches that were tried, why they don't work, and what the
forward path is. Future iterations re-read this file before picking
tasks so we don't relitigate decisions.

## DE-001 — T-037 cannot use InitialAccessTokenByHash as currently shipped

**Symptom:** During T-038 implementation (iter 14, 2026-04-26), tracing the
T-037 IAT-mode auth flow revealed a fundamental mismatch between the
plaintext format (T-021), the projection schema (T-019), and the lookup
helper (T-020).

**Mechanism:**
- T-021 plaintext format is `zdiat_` + base64url(48 random bytes). No
  embedded IAT ID, no embedded deterministic hash.
- T-019 projection stores `token_hash` as the Passwap-encoded form
  (non-deterministic — different salt every Hash() call).
- T-020 query helper `InitialAccessTokenByHash(ctx, tokenHash)` does
  `WHERE token_hash = $2` — assumes the caller can derive the lookup
  key from the presented Bearer.

You cannot derive the Passwap encoding from a presented plaintext (by
design — that's why Passwap is a hash function). So the kit's described
flow ("the handler hashes the presented plaintext token then calls this
lookup") cannot work with the T-021 plaintext + T-019 hash combination.

**Forward path — three options for /ck:revise to pick from:**

1. **Embed IAT ID in plaintext.** Change T-021 to
   `zdiat_<id>.<48-random-bytes-b64url>`. Handler extracts ID, calls
   `InitialAccessTokenByID`, then `VerifyIATPlaintext` against the
   stored Passwap hash. Schema unchanged. Plaintext gets longer.

2. **Add a deterministic lookup-only column.** New `token_lookup`
   column on `projections.initial_access_tokens` storing
   HMAC-SHA256(plaintext, server-secret). Handler computes the HMAC of
   the presented plaintext to look up the row, then verifies via
   Passwap. Requires a migration + a new server secret.

3. **List + verify.** Add an instance-scoped IAT search query
   (`SearchInitialAccessTokensByInstance`) and have the handler
   iterate every active IAT in the instance, calling
   `VerifyIATPlaintext` until one matches. O(N) per request where N is
   IATs-per-instance. Acceptable for small N (admin-issued, finite);
   becomes a timing oracle for large N.

**Recommendation:** Option 1. Smallest scope, no migration, no new
server secret, no scaling concern. Cost is a one-time format change
that hasn't shipped to any user yet (T-021 just landed mid-build).

**Status:** T-037 implementation **PARTIAL**. The handler's auth
dispatcher (T-038, iter 14) returns `IATAuthNotImplemented` for the
Bearer branch with a deliberate 401 invalid_token + descriptive error
message naming T-037. `/ck:revise` should pick an option above before
T-037 actually wires the IAT path.

**Test coverage:** `TestIATAuthNotImplemented_T037` pins the placeholder
so a future contributor cannot silently flip the toggle without
touching the test (and therefore seeing this dead-end note).
