// Package checks provides static-CI lint checks that enforce
// cavekit-mandated invariants which would otherwise rot.
//
// projection_init_alter_parity enforces
// cavekit-dcr-bootstrap-validation.md R1: any column added to a
// projection's Init() declaration on a v-suffixed table that already
// exists in production MUST also ship as a numbered cmd/setup/NN.sql
// ALTER-TABLE migration in the same commit range. Fresh DBs get the
// column from Init; upgrading DBs (already in production) only get
// it from the migration. The gap between the two paths is what
// shipped as the v5.0.0-dcr.4 hotfix the original incident produced.
//
// The check runs in CI by reading the BASE_REF environment variable
// (typically origin/main) and diffing HEAD against it. Pure HEAD
// scanning would flag every existing column ever, so the diff scope
// is essential. When BASE_REF is unset, the check is a no-op (this
// supports local invocations like `go test ./...` without git
// network access).
//
// Wire into CI by adding the env var to the lint workflow:
//
//	- name: Projection Init/ALTER parity
//	  env:
//	    BASE_REF: origin/main
//	  run: go test ./tools/checks/...
package checks

import (
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Patterns. Both NewColumn regexes look at the LEADING `+` produced by
// `git diff` so the match is scoped to additions, not removals or
// context lines.
var (
	// addedInitColumnLiteral matches `+ handler.NewColumn("foo", …)`.
	addedInitColumnLiteral = regexp.MustCompile(`^\+\s*handler\.NewColumn\(\s*"([^"]+)"`)
	// addedInitColumnSymbol matches `+ handler.NewColumn(IdentColumn, …)`
	// where the first arg is a Go identifier, not a quoted string.
	addedInitColumnSymbol = regexp.MustCompile(`^\+\s*handler\.NewColumn\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,`)
	// addedAlterColumn captures the column name from
	//   `ALTER TABLE ... ADD COLUMN IF NOT EXISTS <name> <type>`.
	// Case-insensitive so SQL casing variations don't cause false
	// negatives.
	addedAlterColumn = regexp.MustCompile(`(?i)^\+.*ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+([A-Za-z_][A-Za-z0-9_]*)`)
	// goColumnConstAssignment maps Go const identifiers to the SQL
	// column-name string they hold. Built from the full HEAD state so a
	// const-named NewColumn add can be resolved to its literal value.
	goColumnConstAssignment = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*Column[A-Za-z0-9_]*)\s*=\s*"([^"]+)"`)
)

// TestProjectionInitAlterParity is the entrypoint. Skipped when
// BASE_REF is unset (local runs); CI MUST set it.
func TestProjectionInitAlterParity(t *testing.T) {
	baseRef := os.Getenv("BASE_REF")
	if baseRef == "" {
		t.Skip("BASE_REF not set — skip CI parity check (set BASE_REF=origin/main to run)")
	}

	repoRoot, err := gitRepoRoot()
	if err != nil {
		t.Fatalf("git repo root: %v", err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("chdir %s: %v", repoRoot, err)
	}

	// 1. Build the repo-wide const→literal mapping. We MUST do this on
	//    HEAD's full state (not the diff) — otherwise an Init column
	//    added via a const that was already defined would be invisible
	//    to the literal-string scanner.
	constToLiteral, err := buildColumnConstMap("internal/query/projection")
	if err != nil {
		t.Fatalf("scan column constants: %v", err)
	}

	// 2. Diff the projection package against BASE_REF, collect added
	//    column names from Init() handler.NewColumn(...) calls.
	initDiff, err := gitDiff(baseRef, "HEAD", "internal/query/projection/*.go")
	if err != nil {
		t.Fatalf("git diff projection: %v", err)
	}
	addedInitColumns := extractInitColumns(initDiff, constToLiteral)

	// 3. Diff the setup steps against BASE_REF, collect added column
	//    names from `ALTER TABLE … ADD COLUMN IF NOT EXISTS <name>`.
	alterDiff, err := gitDiff(baseRef, "HEAD", "cmd/setup/*.sql")
	if err != nil {
		t.Fatalf("git diff setup: %v", err)
	}
	addedAlterColumns := extractAlterColumns(alterDiff)

	// 4. Compare. Every name in addedInitColumns MUST also appear in
	//    addedAlterColumns. Names without a matching ALTER are reported.
	var missing []string
	for col := range addedInitColumns {
		if _, ok := addedAlterColumns[col]; !ok {
			missing = append(missing, col)
		}
	}
	if len(missing) == 0 {
		return
	}
	sort.Strings(missing)
	t.Fatalf(
		"projection Init() additions without matching cmd/setup/*.sql ALTER:\n  %s\n\n"+
			"Per cavekit-dcr-bootstrap-validation.md R1: every column added to a v-suffixed\n"+
			"projection table's Init() declaration MUST also ship as a numbered\n"+
			"cmd/setup/NN.sql `ALTER TABLE … ADD COLUMN IF NOT EXISTS …` migration in\n"+
			"the same commit range. Without the migration, fresh DBs get the column\n"+
			"from Init() but upgrading DBs (already in production) never do — the bug\n"+
			"the v5.0.0-dcr.4 hotfix repaired.\n\n"+
			"Either add the migration, or, if the column genuinely doesn't apply to\n"+
			"upgrading DBs (e.g. you're authoring the very first projection version),\n"+
			"document why and update CONTRIBUTING.md \"DCR & well-known endpoint\n"+
			"invariants\" with the exception.",
		strings.Join(missing, "\n  "),
	)
}

func gitRepoRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func gitDiff(base, head, pathspec string) (string, error) {
	cmd := exec.Command("git", "diff", base+"..."+head, "--", pathspec)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func buildColumnConstMap(dir string) (map[string]string, error) {
	out := make(map[string]string)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body, err := os.ReadFile(dir + "/" + e.Name())
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(body), "\n") {
			if m := goColumnConstAssignment.FindStringSubmatch(line); m != nil {
				out[m[1]] = m[2]
			}
		}
	}
	return out, nil
}

func extractInitColumns(diff string, constToLiteral map[string]string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, line := range strings.Split(diff, "\n") {
		// Direct literal: handler.NewColumn("foo", ...)
		if m := addedInitColumnLiteral.FindStringSubmatch(line); m != nil {
			out[strings.ToLower(m[1])] = struct{}{}
			continue
		}
		// Symbolic identifier: handler.NewColumn(SomeColumnConst, ...)
		if m := addedInitColumnSymbol.FindStringSubmatch(line); m != nil {
			ident := m[1]
			if literal, ok := constToLiteral[ident]; ok {
				out[strings.ToLower(literal)] = struct{}{}
			}
			// If we cannot resolve the const, fall through silently.
			// The base check is "we saw a NewColumn add but no ALTER";
			// failing on unresolved consts would produce noise from
			// pure refactors that rename a const without changing
			// schema.
		}
	}
	return out
}

func extractAlterColumns(diff string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, line := range strings.Split(diff, "\n") {
		if m := addedAlterColumn.FindStringSubmatch(line); m != nil {
			out[strings.ToLower(m[1])] = struct{}{}
		}
	}
	return out
}
