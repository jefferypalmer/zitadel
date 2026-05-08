package oidc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestNoNewIssuerFromContextCallsites pins the issuer-source invariant
// from cavekit-dcr-bootstrap-validation.md R3.
//
// Rule: any handler that builds an issuer-derived URL and mounts OUTSIDE
// the OIDC server's middleware chain (anything reached via
// apis.RegisterHandlerOnPrefix without op.NewIssuerInterceptor) MUST
// source the issuer from internal/api/oidc.ContextToIssuer, not
// op.IssuerFromContext. The latter only sees the context value
// populated by NewIssuerInterceptor and silently returns "" outside
// that chain — every issuer-derived URL then degrades to a relative
// path.
//
// This test enforces the rule by pinning the set of files that
// currently contain op.IssuerFromContext callsites. Adding a new file
// to the allowlist forces a doctrine review: the contributor must
// either move the work to ContextToIssuer (preferred) or document a
// justification in this list.
//
// Test files are excluded — fixtures legitimately use op.ContextWithIssuer
// + op.IssuerFromContext to populate the OIDC-server-mux context value.
func TestNoNewIssuerFromContextCallsites(t *testing.T) {
	// Allowlist: files where op.IssuerFromContext is intentionally used,
	// either because they run INSIDE the OIDC mux (where the context value
	// is populated) or because they are the documented fallback after the
	// ContextToIssuer attempt.
	//
	// Paths are relative to the package directory ("." == this dir).
	allowed := map[string]string{
		// In-mux usage: these handlers run behind op.NewIssuerInterceptor
		// so the context value is populated. ContextToIssuer would also
		// work, but the existing code is correct and not load-bearing for
		// the bug R3 fixed.
		"access_token.go":      "in-mux: access-token verification",
		"client.go":            "in-mux: client.JWT-profile verifier",
		"introspect.go":        "in-mux: token introspection",
		"op.go":                "in-mux: ID-token-hint + access-token verifiers configured at server build",
		"token.go":             "in-mux: token endpoint",
		"token_exchange.go":    "in-mux: token-exchange endpoint",
		"token_jwt_profile.go": "in-mux: jwt-profile grant",

		// Fallback after ContextToIssuer (R3 hotfix shape):
		"server.go": "out-of-mux fallback: ContextToIssuer first, op.IssuerFromContext as test-fixture fallback (cavekit-dcr-bootstrap-validation.md R3)",
	}

	// Sub-package allowlist (relative to this dir):
	allowedSubpkg := map[string]string{
		"dcr/response.go": "out-of-mux fallback: ContextToIssuer first, op.IssuerFromContext as test-fixture fallback (cavekit-dcr-bootstrap-validation.md R3)",
	}

	type hit struct {
		relPath string
		line    int
	}
	var hits []hit
	root := "."
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Limit walk depth to package + dcr subpackage; skip large unrelated subtrees.
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		// Normalize path separators for matching on all OSes.
		rel = filepath.ToSlash(rel)

		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", rel, perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if pkg.Name == "op" && sel.Sel != nil && sel.Sel.Name == "IssuerFromContext" {
				pos := fset.Position(call.Pos())
				hits = append(hits, hit{relPath: rel, line: pos.Line})
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk: %v", walkErr)
	}

	seen := map[string]bool{}
	var unauthorized []string
	for _, h := range hits {
		if _, ok := allowed[h.relPath]; ok {
			seen[h.relPath] = true
			continue
		}
		if _, ok := allowedSubpkg[h.relPath]; ok {
			seen[h.relPath] = true
			continue
		}
		unauthorized = append(unauthorized, h.relPath+":"+itoa(h.line))
	}
	if len(unauthorized) > 0 {
		sort.Strings(unauthorized)
		t.Errorf("new callsite(s) of op.IssuerFromContext detected outside the allowlist:\n  %s\n\n"+
			"Out-of-mux handlers MUST source the issuer from ContextToIssuer (which reads "+
			"http_utils.DomainContext(ctx).Origin()), not op.IssuerFromContext. See "+
			"context/kits/cavekit-dcr-bootstrap-validation.md R3 and CONTRIBUTING.md "+
			"\"DCR & well-known endpoint invariants\".\n\n"+
			"If this callsite is genuinely in-mux (runs behind op.NewIssuerInterceptor) or "+
			"is a documented fallback after a ContextToIssuer attempt, add it to the allowlist "+
			"in this test with a one-line justification.",
			strings.Join(unauthorized, "\n  "))
	}

	// Stale-allowlist hygiene: every entry in `allowed`/`allowedSubpkg`
	// must be observed by at least one hit. Otherwise the allowlist has
	// dead weight (e.g. file deleted but allowlist not pruned).
	for path := range allowed {
		if !seen[path] {
			t.Errorf("allowlist entry %q has no matching callsite — please remove the stale entry", path)
		}
	}
	for path := range allowedSubpkg {
		if !seen[path] {
			t.Errorf("allowlist entry %q has no matching callsite — please remove the stale entry", path)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
