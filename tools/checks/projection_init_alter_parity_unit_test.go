package checks

import (
	"testing"
)

func TestExtractInitColumns_LiteralAndSymbol(t *testing.T) {
	diff := `+	handler.NewColumn("last_seen_at", handler.ColumnTypeTimestamp, handler.Nullable()),
+	handler.NewColumn(AppOIDCConfigColumnLastSeenAt, handler.ColumnTypeTimestamp, handler.Nullable()),
-	handler.NewColumn("removed_col", handler.ColumnTypeText),
 	handler.NewColumn("context_col", handler.ColumnTypeText),
+	handler.NewColumn(UnresolvedConst, handler.ColumnTypeText),`

	constMap := map[string]string{"AppOIDCConfigColumnLastSeenAt": "last_seen_at"}

	got := extractInitColumns(diff, constMap)

	wantSet := map[string]bool{"last_seen_at": true}
	if len(got) != len(wantSet) {
		t.Errorf("expected %d columns, got %d (%v)", len(wantSet), len(got), got)
	}
	if _, ok := got["last_seen_at"]; !ok {
		t.Errorf("missing last_seen_at in %v", got)
	}
	if _, ok := got["removed_col"]; ok {
		t.Errorf("unexpected removed_col captured (regex must skip `-` lines)")
	}
	if _, ok := got["context_col"]; ok {
		t.Errorf("unexpected context_col captured (regex must skip context lines)")
	}
}

func TestExtractAlterColumns(t *testing.T) {
	diff := `+ALTER TABLE IF EXISTS projections.apps7_oidc_configs ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
+alter table foo add column if not exists Mixed_Case_Col TEXT;
-ALTER TABLE bar ADD COLUMN IF NOT EXISTS removed_alter TEXT;
 ALTER TABLE baz ADD COLUMN IF NOT EXISTS context_alter TEXT;
+-- comment line, not a column add
+ALTER TABLE silly ADD COLUMN no_if_not_exists TEXT;`

	got := extractAlterColumns(diff)

	if _, ok := got["last_seen_at"]; !ok {
		t.Errorf("expected last_seen_at, got %v", got)
	}
	if _, ok := got["mixed_case_col"]; !ok {
		t.Errorf("expected mixed_case_col (case-insensitive), got %v", got)
	}
	if _, ok := got["removed_alter"]; ok {
		t.Errorf("unexpected removed_alter (regex must skip `-` lines)")
	}
	if _, ok := got["context_alter"]; ok {
		t.Errorf("unexpected context_alter (regex must skip context lines)")
	}
	if _, ok := got["no_if_not_exists"]; ok {
		t.Errorf("regex must require IF NOT EXISTS clause, got %v", got)
	}
}

func TestParityCompare(t *testing.T) {
	initCols := map[string]struct{}{"a": {}, "b": {}, "c": {}}
	alterCols := map[string]struct{}{"a": {}, "c": {}}
	missing := []string{}
	for col := range initCols {
		if _, ok := alterCols[col]; !ok {
			missing = append(missing, col)
		}
	}
	if len(missing) != 1 || missing[0] != "b" {
		t.Errorf("expected only `b` missing, got %v", missing)
	}
}
