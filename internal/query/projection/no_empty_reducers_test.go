package projection_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoEmptyReducers asserts that no projection in the configured
// projection / handler directories has a Reducers() method that returns
// nil or []handler.AggregateReducer{}. Such a projection registered with
// the v2 handler framework triggers the prefill loop to scan the entire
// eventstore as no-op statements — see cavekit-software-statement.md
// R12 and cavekit-eventstore-framework-guard.md R1 for full context.
//
// This is the static (parse-time) counterpart to the framework guard
// in internal/eventstore/handler/v2/handler.go::NewHandler, which
// panics at construction time. Catching the pattern at test time gives
// a fast-fail signal during PR review without booting the whole stack.
func TestNoEmptyReducers(t *testing.T) {
	roots := []string{
		filepath.Join("..", ".."),
	}
	subdirs := []string{
		"query/projection",
		"admin/repository/eventsourcing/handler",
		"auth/repository/eventsourcing/handler",
		"notification/handlers",
	}

	var scanned []string
	for _, root := range roots {
		for _, sub := range subdirs {
			dir := filepath.Join(root, sub)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				t.Logf("skip absent dir %s", dir)
				continue
			}
			scanned = append(scanned, dir)
			walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return nil
				}
				checkFile(t, path)
				return nil
			})
			if walkErr != nil {
				t.Fatalf("walk %s: %v", dir, walkErr)
			}
		}
	}
	if len(scanned) == 0 {
		t.Fatal("no projection directories were scanned — paths likely wrong")
	}
}

func checkFile(t *testing.T, path string) {
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
				t.Errorf("%s: %s.Reducers() returns nil — refusing to register a projection with no event reducers; see cavekit-eventstore-framework-guard.md R1",
					relPath(path), receiverName(fn))
			}
		case *ast.CompositeLit:
			if isEmptyAggregateReducerSlice(v) {
				t.Errorf("%s: %s.Reducers() returns []handler.AggregateReducer{} — same as nil for the framework; see cavekit-eventstore-framework-guard.md R1",
					relPath(path), receiverName(fn))
			}
		}
	}
}

func isEmptyAggregateReducerSlice(c *ast.CompositeLit) bool {
	if len(c.Elts) != 0 {
		return false
	}
	at, ok := c.Type.(*ast.ArrayType)
	if !ok {
		return false
	}
	sel, ok := at.Elt.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel != nil && sel.Sel.Name == "AggregateReducer"
}

func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return "<unknown>"
	}
	switch t := fn.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return "*" + id.Name
		}
	case *ast.Ident:
		return t.Name
	}
	return "<unknown>"
}

func relPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(wd, abs)
	if err != nil {
		return p
	}
	return rel
}
