---
created: "2026-04-28T00:00:00Z"
last_edited: "2026-04-28T00:00:00Z"
complexity: unknown
---

# Cavekit: Inline `jwks` (RFC 7591 §2.1.1 / RFC 7592 §2.2)

## Scope
Defines the production-grade handling of an inline `jwks` JSON object on `POST /oidc/v1/register` (RFC 7591 §2.1.1) and on `PUT /oidc/v1/register/{client_id}` (RFC 7592 §2.2). Phase 1 supports `jwks_uri` only; this kit adds `jwks` (a JWK Set value embedded directly in the request body) as a peer alternative. When stored, inline `jwks` is AUTHORITATIVE for `private_key_jwt` client authentication at the token endpoint — Zitadel does NOT fall back to a `jwks_uri` fetch when both are configured (RFC 7591 §2.1.1 says `jwks` and `jwks_uri` are mutually exclusive at storage). Mutual exclusion is enforced at the handler boundary: presence of both fields in the same request is `invalid_client_metadata`.

## Source
- Phase 2 design (Approach A) — user-approved.
- Phase 1 carve-outs: `cavekit-config.md` Out of Scope ("Inline `jwks` (vs `jwks_uri`)"); `cavekit-register-handler.md` Out of Scope ("Inline `jwks` (Phase 2)"); `cavekit-manage-handler.md` Out of Scope ("Inline `jwks` updates (Phase 2)").
- Brownfield reference: column-naming conventions inspected at `internal/query/projection/app.go` for the new OIDC-config column.
- Spec references: RFC 7591 §2.1.1 (`jwks` vs `jwks_uri`), RFC 7517 §5 (JWK Set), RFC 7518 (JWA), RFC 7592 §2.2 (PUT update).

## Requirements

### R1: Decode and mutual exclusion
**Description:** The request decoder accepts a `jwks` field as a JWK Set per RFC 7517 §5 (`{"keys": [<JWK>...]}`). Presence of both `jwks` and `jwks_uri` in the same request is `invalid_client_metadata` per RFC 7591 §2.1.1. An empty `keys` array is rejected — a degenerate empty key set provides no authentication capability.

**Acceptance Criteria:**
- [ ] A request body containing both `jwks` and `jwks_uri` returns 400 `invalid_client_metadata` with i18n key `Errors.DCR.Jwks.MutuallyExclusive`.
- [ ] A request body containing `jwks` whose value is not an object with a `keys` array returns 400 `invalid_client_metadata` with i18n key `Errors.DCR.Jwks.InvalidStructure`.
- [ ] A request body containing `jwks` whose `keys` array is empty (`{"keys": []}`) returns 400 `invalid_client_metadata` with i18n key `Errors.DCR.Jwks.EmptyKeySet`.
- [ ] A request body containing `jwks` whose `keys` value is not a JSON array returns the same `Errors.DCR.Jwks.InvalidStructure`.
- [ ] A request body with neither `jwks` nor `jwks_uri` is unchanged from Phase 1 behavior — the handler accepts (or rejects) per the auth-method rules in `cavekit-register-handler.md` R5.
- [ ] The decode step occurs after the body-cap and Content-Type checks of `cavekit-register-handler.md` R2 (decoder errors do not leak around request-size limits).

**Dependencies:** `cavekit-register-handler.md` R2, R5.

### R2: JWK validation
**Description:** Each member of the `keys` array MUST satisfy structural and algorithmic constraints. Per-set caps bound CPU and memory on adversarial input. Private-key material is structurally rejected.

**Acceptance Criteria:**
- [ ] Each JWK MUST carry a non-empty `kid` claim; absence returns 400 `invalid_client_metadata` with i18n key `Errors.DCR.Jwks.InvalidStructure`.
- [ ] `kid` values MUST be unique within the JWK Set; a duplicate `kid` returns 400 with i18n key `Errors.DCR.Jwks.DuplicateKid`.
- [ ] Each JWK's `kty` MUST be in `{RSA, EC, OKP}`; other values return 400 with `Errors.DCR.Jwks.InvalidStructure`.
- [ ] Each JWK's `alg`, when present, MUST be in `{RS256, RS384, RS512, ES256, ES384, ES512, EdDSA}`; other values return 400 with i18n key `Errors.DCR.Jwks.UnsupportedAlgorithm`.
- [ ] Any JWK carrying ANY of the private-key fields `d`, `p`, `q`, `dp`, `dq`, `qi` returns 400 with i18n key `Errors.DCR.Jwks.PrivateKeyMaterial` and `error_description: "private key material in jwks"`. The check covers all six fields independently — a JWK with only `d` set is rejected.
- [ ] The `keys` array contains at most 10 entries; an 11th entry returns 400 with i18n key `Errors.DCR.Jwks.TooManyKeys`.
- [ ] The serialized `jwks` JSON value (after re-serialization with sorted keys for deterministic measurement) MUST be ≤ 16 KiB; a larger value returns 400 with i18n key `Errors.DCR.Jwks.TooLarge`.
- [ ] When a JWK carries a `use` field, its value MUST be `sig` or absent; `use=enc` is silently dropped (encryption-use keys are not consumed by Zitadel today — Phase 2 does NOT implement client-encryption flows).

**Dependencies:** R1.

### R3: Storage
**Description:** Inline `jwks` is persisted as JSON on a new column on the OIDC-config row. The projection is updated to surface the column. Mutations to the column emit eventstore events so the audit log records the source of authentication material.

**Acceptance Criteria:**
- [ ] A new column is added to the OIDC-config row alongside the existing `jwks_uri` column. The column name follows the prevailing naming conventions inspected at `internal/query/projection/app.go` — drafter does not pin a specific name (implementation chooses to match the existing `jwks_uri_*` neighbor's style).
- [ ] The column type is JSONB (Postgres) so the stored content is queryable as structured data and not opaque text.
- [ ] The column is nullable; rows that use `jwks_uri` (or have neither) leave it NULL.
- [ ] The OIDC-config projection's reducer for the new R3 events writes / clears the column atomically with the rest of the OIDC config.
- [ ] A new event `project.application.oidc_config.jwks.inline.set` is emitted on initial set; payload carries the JWK Set as JSON.
- [ ] A new event `project.application.oidc_config.jwks.inline.changed` is emitted on subsequent updates that replace the stored value.
- [ ] A new event `project.application.oidc_config.jwks.inline.removed` is emitted when a PUT transitions the row away from inline `jwks` (e.g., back to `jwks_uri` or to neither).
- [ ] Setting `jwks` via POST or PUT MUST clear any previously stored `jwks_uri` on the same row in a single transaction (mutual exclusion preserved at storage).
- [ ] Setting `jwks_uri` via PUT MUST clear any previously stored inline `jwks` on the same row in a single transaction (the inverse direction).

**Dependencies:** R1, R2.

### R4: RFC 7592 PUT update
**Description:** PUT on the management endpoint accepts `jwks` subject to R1 + R2. PUT can atomically transition between `jwks` and `jwks_uri` in either direction. Each transition is recorded as an event so the audit log captures the source change.

**Acceptance Criteria:**
- [ ] PUT with a request body containing `jwks` is decoded and validated per R1 + R2 — the same rules as POST register.
- [ ] PUT with `jwks` set on a row that previously stored `jwks_uri` clears the stored `jwks_uri`, persists the new inline JWK Set, and emits both `jwks_uri.removed` and `jwks.inline.set` events (or, equivalently, the existing `OIDCConfigChangedEvent` covers the cleared `jwks_uri` while a new `jwks.inline.set` event covers the new column — implementation choice; either pattern satisfies this AC provided the audit trail captures both transitions).
- [ ] PUT with `jwks_uri` set on a row that previously stored inline `jwks` clears the inline column, persists the new `jwks_uri`, and emits the inverse pair of events.
- [ ] PUT with neither `jwks` nor `jwks_uri` on a row that previously stored one of them clears the stored value (PUT is a full replacement per `cavekit-manage-handler.md` R5).
- [ ] PUT-time clamps from `cavekit-manage-handler.md` R5 still run — auth-method transitions interact with R6's authoritativeness rules.
- [ ] A PUT carrying both `jwks` and `jwks_uri` is rejected per R1 — same envelope as POST register.

**Dependencies:** R1, R2, R3; `cavekit-manage-handler.md` R5.

### R5: GET read-back
**Description:** RFC 7592 GET on a client with stored inline `jwks` echoes the stored JWK Set verbatim. GET on a client with `jwks_uri` echoes the URI. Both fields are never present simultaneously in a single response.

**Acceptance Criteria:**
- [ ] When a row stores inline `jwks`, GET response body includes the `jwks` field with the JSON value byte-equal (modulo key order normalization) to the stored column.
- [ ] When a row stores `jwks_uri`, GET response body includes the `jwks_uri` field and OMITS the `jwks` field entirely (key absent from JSON, never `null`).
- [ ] When a row stores neither, GET response body OMITS both fields (key absent from JSON, never `null`).
- [ ] At no point does a GET response body contain both `jwks` and `jwks_uri`.
- [ ] An integration test asserts each of the three storage states produces the documented response shape.

**Dependencies:** R3; `cavekit-manage-handler.md` R4.

### R6: Token-endpoint authoritativeness for `private_key_jwt`
**Description:** When a registered client's stored OIDC config has inline `jwks`, the `/oauth/v2/token` endpoint's `private_key_jwt` client-authentication path MUST verify the client-asserted JWT against the stored inline JWK Set. Inline `jwks` is AUTHORITATIVE — the token endpoint MUST NOT fall back to `jwks_uri` fetching when inline is set (the fields are stored as mutually exclusive per R3, so the fallback is unreachable in practice; this AC pins the behavior so that a future regression cannot reintroduce a parallel `jwks_uri` lookup).

**Acceptance Criteria:**
- [ ] `private_key_jwt` token-endpoint authentication selects the verification key from the stored inline `jwks` column when that column is non-NULL.
- [ ] Key selection within the stored JWK Set follows the same `kid`-match contract used in `cavekit-software-statement.md` R5 — exact-string match on the asserted JWT header `kid` against `keys[].kid`.
- [ ] When the asserted JWT's `kid` does not match any stored key, the token endpoint returns the SAME error envelope today's `jwks_uri` path returns on key mismatch — no DCR-specific divergence.
- [ ] When the stored row has only `jwks_uri` (no inline `jwks`), the existing Phase 1 `jwks_uri`-fetch path is unchanged.
- [ ] When the stored row has neither `jwks` nor `jwks_uri` and the client is configured for `private_key_jwt`, behavior matches today's "no signing material configured" path.
- [ ] An integration test asserts that a client with inline `jwks` can authenticate at `/oauth/v2/token` via `private_key_jwt`, and that key rotation via RFC 7592 PUT (replacing the inline `jwks`) invalidates the previous key on the next token request.

**Dependencies:** R3, R5.

### R7: i18n and observability
**Description:** Error keys introduced here are translated for every locale shipped under `internal/api/ui/login/static/i18n/`. A new OTel attribute communicates the per-request authentication-material source.

**Acceptance Criteria:**
- [ ] Keys `Errors.DCR.Jwks.MutuallyExclusive`, `InvalidStructure`, `PrivateKeyMaterial`, `TooManyKeys`, `TooLarge`, `UnsupportedAlgorithm`, `DuplicateKid`, and `EmptyKeySet` are present in all 22 yaml locale files under `internal/api/ui/login/static/i18n/`.
- [ ] `internal/i18n/dcr_keys_test.go` is extended; absence in any locale fails the test.
- [ ] OTel spans `oidc.dcr.register` (per `cavekit-console-ui-docs-and-observability.md` R7), `oidc.dcr.update` (PUT path), and the existing token-endpoint span are extended with attribute `dcr.jwks.source` whose value is `inline | uri | none`.
- [ ] The attribute value `inline` is set when the verified-against material was the stored inline JWK Set; `uri` when it was a `jwks_uri` fetch result; `none` when no signing material was configured.
- [ ] Span attributes NEVER carry the JWK Set content itself.

**Dependencies:** R3, R6; `cavekit-console-ui-docs-and-observability.md` R3, R7.

## Out of Scope
- JWK rotation events scoped narrower than R3's set/changed/removed (clients rotate keys via RFC 7592 PUT — a dedicated rotate endpoint is not in scope).
- Per-client `/jwks` endpoint exposure (Zitadel does NOT publish per-client JWK Sets; the inline JWK Set is consumed only by the token endpoint).
- Encryption-key handling (`use=enc` is silently dropped; Zitadel does not perform JWE-encrypted client communications today).
- Inline `jwks` editor UI in console — clients self-manage via RFC 7592 PUT (see `cavekit-console-phase2.md` Out of Scope).
- Per-key revocation list (revoke-by-`kid`) — clients revoke a key by issuing a PUT with the JWK omitted.
- `jwks` validation against the `token_endpoint_auth_method` (the auth-method clamp lives in `cavekit-register-handler.md` R5; this kit assumes the request reached jwks-validation only because auth-method was already accepted).

## Cross-References
- See `cavekit-register-handler.md` R2, R4, R5: request decode, clamp surface, auth-method-driven jwks requirement (R1 mutual exclusion enforced alongside R5 `private_key_jwt` accepts either `jwks_uri` or now `jwks`).
- See `cavekit-manage-handler.md` R4, R5: GET shape and PUT full-replacement contract honored by R5 / R4.
- See `cavekit-software-statement.md` R5: `kid`-match algorithm reused at the token endpoint per R6.
- See `cavekit-console-ui-docs-and-observability.md` R3, R7: i18n fallback contract, OTel span attribute registration.
- See `cavekit-console-phase2.md` R7: full 22-locale rollout for these error keys.

## Changelog
- 2026-04-28: Initial Phase 2 draft.
