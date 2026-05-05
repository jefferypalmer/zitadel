package start

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoEmptyReducers_FrameworkGuardBackStop is the back-stop verification
// for cavekit-eventstore-framework-guard.md R3. The runtime guard at
// internal/eventstore/handler/v2/handler.go::NewHandler (T-009) panics
// at construction time on the degenerate (empty Reducers + nil
// TriggerWithoutEvents + non-Global) combination. This static walk
// asserts that no projection currently registered in cmd/setup or
// cmd/start would trip the guard at startup — equivalent to the kit's
//
//	`grep -rn 'func.*Reducers().*\[\]handler.AggregateReducer' \
//	    internal/admin/repository/eventsourcing/handler/ \
//	    internal/auth/repository/eventsourcing/handler/ \
//	    internal/notification/handlers/ \
//	    internal/query/projection/ | \
//	  xargs grep -l 'return nil$\|return \[\]handler.AggregateReducer{}$'`
//
// returning empty after T-001 has been applied.
//
// The full boot-smoke (cases (a) fresh Postgres + (b) upgrade
// simulation Postgres) requires the //go:build integration harness in
// cmd/setup/integration_test/. This test runs unconditionally on every
// `go test ./cmd/start/...` so the regression is caught at PR review,
// not waiting for the integration job. A duplicate of T-003
// (internal/query/projection/no_empty_reducers_test.go) intentionally —
// the kit calls for the assertion to live alongside the boot-smoke
// sub-cases.
func TestNoEmptyReducers_FrameworkGuardBackStop(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	subdirs := []string{
		"internal/query/projection",
		"internal/admin/repository/eventsourcing/handler",
		"internal/auth/repository/eventsourcing/handler",
		"internal/notification/handlers",
	}

	scanned := 0
	for _, sub := range subdirs {
		dir := filepath.Join(repoRoot, sub)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Logf("skip absent dir %s", dir)
			continue
		}
		scanned++
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			scanFileForEmptyReducers(t, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if scanned == 0 {
		t.Fatal("no projection directories were scanned — paths likely wrong")
	}
}

func scanFileForEmptyReducers(t *testing.T, path string) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != "Reducers" || fn.Recv == nil {
			continue
		}
		if fn.Body == nil || len(fn.Body.List) != 1 {
			continue
		}
		ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			continue
		}
		switch v := ret.Results[0].(type) {
		case *ast.Ident:
			if v.Name == "nil" {
				t.Errorf("%s: Reducers() returns nil — would trip framework guard at NewHandler (cavekit-eventstore-framework-guard.md R1)",
					path)
			}
		case *ast.CompositeLit:
			at, ok := v.Type.(*ast.ArrayType)
			if !ok || len(v.Elts) != 0 {
				continue
			}
			sel, ok := at.Elt.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "AggregateReducer" {
				continue
			}
			t.Errorf("%s: Reducers() returns []handler.AggregateReducer{} — same as nil for the framework guard",
				path)
		}
	}
}
