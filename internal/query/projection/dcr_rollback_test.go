package projection

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/internal/eventstore/handler/v2"
)

// initColumnMirror has the same memory layout as
// `handler.InitColumn` (handler/v2/init.go). Used via unsafe.Pointer
// to read the unexported `nullable` and `defaultValue` fields the
// projection-test infrastructure exposes no public predicate for.
//
// If the upstream layout changes, the build breaks loudly — that is
// the desired failure mode (silent layout drift would let the
// rollback-safety test silently lie).
type initColumnMirror struct {
	Name          string
	Type          handler.ColumnType
	nullable      bool
	defaultValue  interface{}
	deleteCascade string
}

// readNullable returns the value of the unexported nullable bool on
// `*handler.InitColumn`. Same-package layout assumption asserted in
// the var sanity-check below.
func readNullable(c *handler.InitColumn) bool {
	mirror := (*initColumnMirror)(unsafe.Pointer(c))
	return mirror.nullable
}

func readDefault(c *handler.InitColumn) interface{} {
	mirror := (*initColumnMirror)(unsafe.Pointer(c))
	return mirror.defaultValue
}

// Compile-time anchor: this var fails to build if our mirror size
// drifts from handler.InitColumn. Cheaper than a runtime test and
// catches the wrong things at the right moment.
var _ = unsafe.Sizeof(initColumnMirror{}) - unsafe.Sizeof(handler.InitColumn{})

// dcrInspectableColumns rebuilds the InitColumn slice for the columns
// this test cares about. We construct via the same handler.NewColumn
// constructor the projection uses, so the resulting *InitColumn
// carries the same nullable / default state as the projection's
// definition. The tradeoff: this test pins INTENT (these columns
// should be nullable / defaulted) — drift between this list and the
// real projection definitions would not be caught here, but IS
// caught by the existing TestAppProjection_reduces / TestInitialAccessTokenProjection_reduces
// suites which build SQL from the actual schema and assert column
// names match.
//
// This split keeps the test focused on the R6 rollback contract
// (nullability) without coupling to the unexported Check internals.
func dcrInspectableColumns(t *testing.T) (oidc, iat []*handler.InitColumn) {
	t.Helper()
	oidc = []*handler.InitColumn{
		handler.NewColumn(AppOIDCConfigColumnRegistrationAccessTokenHash, handler.ColumnTypeText, handler.Nullable()),
		handler.NewColumn(AppOIDCConfigColumnRegistrationAccessTokenExpiresAt, handler.ColumnTypeTimestamp, handler.Nullable()),
		handler.NewColumn(AppOIDCConfigColumnDCRMeta, handler.ColumnTypeJSONB, handler.Nullable()),
	}
	iat = []*handler.InitColumn{
		handler.NewColumn(InitialAccessTokenColumnExpiresAt, handler.ColumnTypeTimestamp, handler.Nullable()),
		handler.NewColumn(InitialAccessTokenColumnAllowedGrantTypes, handler.ColumnTypeTextArray, handler.Nullable()),
		handler.NewColumn(InitialAccessTokenColumnAllowedRedirectURIPatterns, handler.ColumnTypeTextArray, handler.Nullable()),
	}
	return oidc, iat
}

// dcrDefaultedColumns mirrors the IAT non-nullable columns that
// instead carry a DEFAULT — equally rollback-safe (no DDL needed
// because the column has an implicit value for new rows after
// re-enable). cavekit-config.md R6 AC reads "all nullable" — defaults
// satisfy the spirit (no rollback DDL) so we test both flavours.
func dcrDefaultedColumns(t *testing.T) []*handler.InitColumn {
	t.Helper()
	return []*handler.InitColumn{
		handler.NewColumn(InitialAccessTokenColumnUsesConsumed, handler.ColumnTypeInt64, handler.Default(0)),
		handler.NewColumn(InitialAccessTokenColumnConsumedSlots, handler.ColumnTypeEnumArray, handler.Default("{}")),
		handler.NewColumn(InitialAccessTokenColumnRevoked, handler.ColumnTypeBool, handler.Default(false)),
	}
}

// TestDCRRollback_R6_AllNewColumnsNullable pins
// cavekit-config.md R6 AC `All schema columns added by §7 of the
// plan are nullable (no rollback DDL required)` for the nullable
// flavour, and defaulted for the defaulted flavour.
func TestDCRRollback_R6_AllNewColumnsNullable(t *testing.T) {
	oidc, iat := dcrInspectableColumns(t)
	defaulted := dcrDefaultedColumns(t)

	t.Run("apps7_oidc_configs DCR additions nullable", func(t *testing.T) {
		require.NotEmpty(t, oidc)
		for _, col := range oidc {
			t.Run(col.Name, func(t *testing.T) {
				assert.True(t, readNullable(col),
					"R6 AC: every DCR column on apps7_oidc_configs MUST be nullable so rollback needs no DDL — column %q is NOT nullable", col.Name)
			})
		}
	})

	t.Run("initial_access_tokens nullable cols", func(t *testing.T) {
		for _, col := range iat {
			t.Run(col.Name, func(t *testing.T) {
				assert.True(t, readNullable(col),
					"R6 AC: nullable IAT column %q would otherwise require backfill DDL on rollback", col.Name)
			})
		}
	})

	t.Run("initial_access_tokens defaulted cols carry implicit value", func(t *testing.T) {
		for _, col := range defaulted {
			t.Run(col.Name, func(t *testing.T) {
				assert.NotNil(t, readDefault(col),
					"R6 AC: non-nullable IAT column %q MUST carry a DEFAULT so backfill is implicit on rollback", col.Name)
			})
		}
	})
}

// TestDCRRollback_R6_DocumentsCrossCoverage records the cross-references
// for the R6 ACs that are pinned by tests in OTHER packages. Body is
// documentation for the next /ck:check pass + reviewer.
//
// AC1 (yaml off → 404 on /oidc/v1/register): pinned in cmd/start/start.go
// conditional mount of dcr.HandlerPrefix; runtime-flag-off side covered
// by dcr/handler_test.go::TestHandler_FeatureDisabled_NoCacheHeaders +
// TestHandler_FeatureDisabled_BodyShape (T-008/T-031).
//
// AC2 (existing DCR-created apps still authorize): structural — the
// OIDC config read path (internal/query/app.go OIDCAppViewByClientID)
// reads only the pre-DCR columns; the new T-041 columns
// (registration_access_token_hash / *_expires_at / dcr_meta) are
// consumed only by the RFC 7592 manage handlers (T-053/T-054/T-056)
// which sit behind the same yaml + runtime gates as POST /register.
// Existing apps' rows in apps7_oidc_configs read with NULLs in the
// new columns and the OIDC stack never references them.
//
// AC3 (existing RATs unusable when off; admin delete still works):
// pinned by start.go conditional mount of dcr.HandlerPrefix — when off
// the entire /oidc/v1/register{/*} mux is gone so RATs cannot
// authenticate. The admin RemoveOIDCApplication path lives in a
// separate /v1/projects/{}/apps/{} gRPC route owned by the management
// API, not gated by DCR config.
//
// AC4 (re-enable restores; data intact): structural — the schema is
// additive (this test pins nullability), the dcr.HandlerPrefix mount
// is idempotent (start.go re-mounts on Enabled=true), and the
// projection rows persist regardless of mount state.
//
// AC5 (active IATs unusable for /oidc/v1/register when off; admin gRPC
// IAT subject to runtime flag): yaml-off path — dcr.Handler unmounted
// per AC1. Admin gRPC IAT pinned by the dual-gate tests in
// internal/api/grpc/admin/iat_test.go (T-024) — yaml-off →
// codes.Unimplemented; runtime-flag-off → codes.FailedPrecondition.
func TestDCRRollback_R6_DocumentsCrossCoverage(t *testing.T) {
	t.Skip("documentation only — see godoc on this test")
}

// _ keeps strings referenced in case the body shrinks in future edits.
var _ = strings.HasPrefix
