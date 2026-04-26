package query

import (
	"database/sql"
	"database/sql/driver"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// TestQueries_InitialAccessTokenByID covers cavekit-iat.md R4: lookup
// returns the projected row scoped to the caller's instance + (when
// requested) resource owner. Cross-instance lookups translate to
// not-found.
func TestQueries_InitialAccessTokenByID(t *testing.T) {
	expQuery := regexp.QuoteMeta(initialAccessTokenByIDQuery)
	cols := []string{"row_to_json"}
	expiry := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	createdAt := time.Date(2026, 4, 26, 10, 0, 0, 0, time.UTC)
	row := `{
		"id": "iat-1",
		"instance_id": "instanceID",
		"resource_owner": "ro-1",
		"project_id": "proj-1",
		"token_hash": "$argon2id$v=19$...",
		"expires_at": "2030-01-02T03:04:05Z",
		"max_uses": 3,
		"uses_consumed": 1,
		"consumed_slots": [0],
		"allowed_grant_types": ["authorization_code"],
		"allowed_redirect_uri_patterns": ["https://*.example.com/cb"],
		"revoked": false,
		"created_at": "2026-04-26T10:00:00Z",
		"change_date": "2026-04-26T10:00:00Z",
		"sequence": 7
	}`

	tests := []struct {
		name          string
		resourceOwner string
		mock          sqlExpectation
		want          *InitialAccessToken
		wantErr       error
	}{
		{
			name:          "not found → ThrowNotFound",
			resourceOwner: "",
			mock:          mockQueryErr(expQuery, sql.ErrNoRows, "instanceID", "iat-1", ""),
			wantErr:       zerrors.ThrowNotFound(sql.ErrNoRows, "QUERY-IAT01", "Errors.DCR.IAT.NotFound"),
		},
		{
			name:          "internal error → ThrowInternal",
			resourceOwner: "",
			mock:          mockQueryErr(expQuery, sql.ErrConnDone, "instanceID", "iat-1", ""),
			wantErr:       zerrors.ThrowInternal(sql.ErrConnDone, "QUERY-IAT02", "Errors.Internal"),
		},
		{
			name:          "happy path: empty resourceOwner skips org scope",
			resourceOwner: "",
			mock:          mockQuery(expQuery, cols, []driver.Value{row}, "instanceID", "iat-1", ""),
			want: &InitialAccessToken{
				ID:                         "iat-1",
				InstanceID:                 "instanceID",
				ResourceOwner:              "ro-1",
				ProjectID:                  "proj-1",
				TokenHash:                  "$argon2id$v=19$...",
				ExpiresAt:                  &expiry,
				MaxUses:                    3,
				UsesConsumed:               1,
				ConsumedSlots:              database.NumberArray[int16]{0},
				AllowedGrantTypes:          database.TextArray[string]{"authorization_code"},
				AllowedRedirectURIPatterns: database.TextArray[string]{"https://*.example.com/cb"},
				Revoked:                    false,
				CreatedAt:                  createdAt,
				ChangeDate:                 createdAt,
				Sequence:                   7,
			},
		},
		{
			name:          "happy path: resourceOwner enforces org scope (passed as $3)",
			resourceOwner: "ro-1",
			mock:          mockQuery(expQuery, cols, []driver.Value{row}, "instanceID", "iat-1", "ro-1"),
			want: &InitialAccessToken{
				ID:                         "iat-1",
				InstanceID:                 "instanceID",
				ResourceOwner:              "ro-1",
				ProjectID:                  "proj-1",
				TokenHash:                  "$argon2id$v=19$...",
				ExpiresAt:                  &expiry,
				MaxUses:                    3,
				UsesConsumed:               1,
				ConsumedSlots:              database.NumberArray[int16]{0},
				AllowedGrantTypes:          database.TextArray[string]{"authorization_code"},
				AllowedRedirectURIPatterns: database.TextArray[string]{"https://*.example.com/cb"},
				Revoked:                    false,
				CreatedAt:                  createdAt,
				ChangeDate:                 createdAt,
				Sequence:                   7,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			execMock(t, tt.mock, func(db *sql.DB) {
				q := &Queries{client: &database.DB{DB: db}}
				ctx := authz.NewMockContext("instanceID", "orgID", "loginClient")
				got, err := q.InitialAccessTokenByID(ctx, "iat-1", tt.resourceOwner)
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			})
		})
	}
}

// TestQueries_InitialAccessTokenByHash covers cavekit-iat.md R4 lookup
// path used by the registration handler (T-037). Cross-instance
// hashes return not-found via the WHERE clause.
func TestQueries_InitialAccessTokenByHash(t *testing.T) {
	expQuery := regexp.QuoteMeta(initialAccessTokenByHashQuery)
	cols := []string{"row_to_json"}
	hash := "$argon2id$v=19$...specifichash"
	row := `{
		"id": "iat-2",
		"instance_id": "instanceID",
		"resource_owner": "ro-1",
		"project_id": "proj-1",
		"token_hash": "` + hash + `",
		"max_uses": 0,
		"uses_consumed": 0,
		"consumed_slots": [],
		"revoked": false,
		"created_at": "2026-04-26T10:00:00Z",
		"change_date": "2026-04-26T10:00:00Z",
		"sequence": 1
	}`

	tests := []struct {
		name    string
		mock    sqlExpectation
		want    *InitialAccessToken
		wantErr error
	}{
		{
			name:    "not found → ThrowNotFound",
			mock:    mockQueryErr(expQuery, sql.ErrNoRows, "instanceID", hash),
			wantErr: zerrors.ThrowNotFound(sql.ErrNoRows, "QUERY-IAT03", "Errors.DCR.IAT.NotFound"),
		},
		{
			name: "happy path: nullable expires_at left empty (max_uses=0 unlimited IAT)",
			mock: mockQuery(expQuery, cols, []driver.Value{row}, "instanceID", hash),
			want: &InitialAccessToken{
				ID:            "iat-2",
				InstanceID:    "instanceID",
				ResourceOwner: "ro-1",
				ProjectID:     "proj-1",
				TokenHash:     hash,
				ExpiresAt:     nil,
				MaxUses:       0,
				UsesConsumed:  0,
				ConsumedSlots: database.NumberArray[int16]{},
				Revoked:       false,
				CreatedAt:     time.Date(2026, 4, 26, 10, 0, 0, 0, time.UTC),
				ChangeDate:    time.Date(2026, 4, 26, 10, 0, 0, 0, time.UTC),
				Sequence:      1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			execMock(t, tt.mock, func(db *sql.DB) {
				q := &Queries{client: &database.DB{DB: db}}
				ctx := authz.NewMockContext("instanceID", "orgID", "loginClient")
				got, err := q.InitialAccessTokenByHash(ctx, hash)
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			})
		})
	}
}
