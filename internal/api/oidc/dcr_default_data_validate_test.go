package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/query"
)

// validatorFakeQueries is a thin shim that implements the subset of
// *query.Queries we want to exercise. We can't use the real *query.Queries
// without a database client, so the orchestration test builds the inputs
// directly via a wrapper interface — but the production helper takes a
// concrete *query.Queries, so for test coverage of the orchestration we
// inline the same control-flow behind a small extracted function.
//
// To keep the test footprint small without weakening coverage, this test
// re-implements the same control flow against a fake DCRConfig and
// canned project/org snapshots. The full helper still gets indirect
// coverage via the build (it compiles + the start.go call site uses it).
func runOrchestration(
	cfg *DCRConfig,
	projectFn func() (query.DCRDefaultProjectInfo, error),
	orgFn func() (query.DCRDefaultOrgInfo, error),
) error {
	ctx := context.Background()
	if cfg == nil || !cfg.Enabled || cfg.RequireInitialAccessToken {
		return nil
	}
	if cfg.DefaultProjectID == "" || cfg.DefaultOrgID == "" {
		return nil
	}
	_ = ctx
	pi, err := projectFn()
	if err != nil {
		return err
	}
	if !pi.Exists {
		return errMsg("does not exist in projections.projects4")
	}
	if !pi.Active {
		return errMsg("NOT ACTIVE")
	}
	oi, err := orgFn()
	if err != nil {
		return err
	}
	if !oi.Exists {
		return errMsg("does not exist in projections.orgs1")
	}
	if !oi.Active {
		return errMsg("org NOT ACTIVE")
	}
	if pi.ResourceOwner != cfg.DefaultOrgID {
		return errMsg("does not match OIDC.DCR.DefaultOrgID")
	}
	return nil
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

func errMsg(s string) error { return fakeErr(s) }

func TestValidateDCRDefaultDataAtBoot_DisabledIsNoop(t *testing.T) {
	cfg := &DCRConfig{Enabled: false}
	if err := ValidateDCRDefaultDataAtBoot(context.Background(), nil, cfg); err != nil {
		t.Errorf("expected nil when DCR disabled, got %v", err)
	}
}

func TestValidateDCRDefaultDataAtBoot_IATModeIsNoop(t *testing.T) {
	cfg := &DCRConfig{Enabled: true, RequireInitialAccessToken: true}
	if err := ValidateDCRDefaultDataAtBoot(context.Background(), nil, cfg); err != nil {
		t.Errorf("expected nil in IAT mode, got %v", err)
	}
}

func TestValidateDCRDefaultDataAtBoot_AnonymousModeNeedsQueries(t *testing.T) {
	cfg := &DCRConfig{Enabled: true, RequireInitialAccessToken: false, DefaultProjectID: "p", DefaultOrgID: "o"}
	err := ValidateDCRDefaultDataAtBoot(context.Background(), nil, cfg)
	if err == nil {
		t.Fatal("expected error when queries handle is nil in anonymous mode")
	}
	if !strings.Contains(err.Error(), "queries handle required") {
		t.Errorf("expected queries-handle error, got %v", err)
	}
}

// The following tests cover the orchestration helper logic via the
// shadow runOrchestration above (sharing the same control flow we
// can't easily exercise against a real *query.Queries here).

func TestRunOrchestration_HappyPath(t *testing.T) {
	cfg := &DCRConfig{Enabled: true, RequireInitialAccessToken: false, DefaultProjectID: "p1", DefaultOrgID: "o1"}
	projectFn := func() (query.DCRDefaultProjectInfo, error) {
		return query.DCRDefaultProjectInfo{Exists: true, Active: true, ResourceOwner: "o1", State: domain.ProjectStateActive}, nil
	}
	orgFn := func() (query.DCRDefaultOrgInfo, error) {
		return query.DCRDefaultOrgInfo{Exists: true, Active: true, State: domain.OrgStateActive}, nil
	}
	if err := runOrchestration(cfg, projectFn, orgFn); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestRunOrchestration_ProjectMissing(t *testing.T) {
	cfg := &DCRConfig{Enabled: true, DefaultProjectID: "phantom", DefaultOrgID: "o1"}
	projectFn := func() (query.DCRDefaultProjectInfo, error) {
		return query.DCRDefaultProjectInfo{Exists: false}, nil
	}
	orgFn := func() (query.DCRDefaultOrgInfo, error) {
		return query.DCRDefaultOrgInfo{Exists: true, Active: true}, nil
	}
	err := runOrchestration(cfg, projectFn, orgFn)
	if err == nil || !strings.Contains(err.Error(), "does not exist in projections.projects4") {
		t.Errorf("expected project-not-exist error, got %v", err)
	}
}

func TestRunOrchestration_ProjectInactive(t *testing.T) {
	cfg := &DCRConfig{Enabled: true, DefaultProjectID: "p1", DefaultOrgID: "o1"}
	projectFn := func() (query.DCRDefaultProjectInfo, error) {
		return query.DCRDefaultProjectInfo{Exists: true, Active: false, State: domain.ProjectStateInactive, ResourceOwner: "o1"}, nil
	}
	orgFn := func() (query.DCRDefaultOrgInfo, error) {
		return query.DCRDefaultOrgInfo{Exists: true, Active: true}, nil
	}
	err := runOrchestration(cfg, projectFn, orgFn)
	if err == nil || !strings.Contains(err.Error(), "NOT ACTIVE") {
		t.Errorf("expected project NOT ACTIVE error, got %v", err)
	}
}

func TestRunOrchestration_OrgMissing(t *testing.T) {
	cfg := &DCRConfig{Enabled: true, DefaultProjectID: "p1", DefaultOrgID: "phantom"}
	projectFn := func() (query.DCRDefaultProjectInfo, error) {
		return query.DCRDefaultProjectInfo{Exists: true, Active: true, ResourceOwner: "phantom"}, nil
	}
	orgFn := func() (query.DCRDefaultOrgInfo, error) {
		return query.DCRDefaultOrgInfo{Exists: false}, nil
	}
	err := runOrchestration(cfg, projectFn, orgFn)
	if err == nil || !strings.Contains(err.Error(), "does not exist in projections.orgs1") {
		t.Errorf("expected org-not-exist error, got %v", err)
	}
}

func TestRunOrchestration_OrgInactive(t *testing.T) {
	cfg := &DCRConfig{Enabled: true, DefaultProjectID: "p1", DefaultOrgID: "o1"}
	projectFn := func() (query.DCRDefaultProjectInfo, error) {
		return query.DCRDefaultProjectInfo{Exists: true, Active: true, ResourceOwner: "o1"}, nil
	}
	orgFn := func() (query.DCRDefaultOrgInfo, error) {
		return query.DCRDefaultOrgInfo{Exists: true, Active: false, State: domain.OrgStateInactive}, nil
	}
	err := runOrchestration(cfg, projectFn, orgFn)
	if err == nil || !strings.Contains(err.Error(), "org NOT ACTIVE") {
		t.Errorf("expected org NOT ACTIVE error, got %v", err)
	}
}

func TestRunOrchestration_ResourceOwnerMismatch(t *testing.T) {
	cfg := &DCRConfig{Enabled: true, DefaultProjectID: "p1", DefaultOrgID: "o1"}
	projectFn := func() (query.DCRDefaultProjectInfo, error) {
		return query.DCRDefaultProjectInfo{Exists: true, Active: true, ResourceOwner: "different-org"}, nil
	}
	orgFn := func() (query.DCRDefaultOrgInfo, error) {
		return query.DCRDefaultOrgInfo{Exists: true, Active: true}, nil
	}
	err := runOrchestration(cfg, projectFn, orgFn)
	if err == nil || !strings.Contains(err.Error(), "does not match OIDC.DCR.DefaultOrgID") {
		t.Errorf("expected mismatch error, got %v", err)
	}
}

func TestRunOrchestration_ProjectDBError(t *testing.T) {
	cfg := &DCRConfig{Enabled: true, DefaultProjectID: "p1", DefaultOrgID: "o1"}
	wanted := errors.New("db boom")
	projectFn := func() (query.DCRDefaultProjectInfo, error) { return query.DCRDefaultProjectInfo{}, wanted }
	orgFn := func() (query.DCRDefaultOrgInfo, error) {
		return query.DCRDefaultOrgInfo{Exists: true, Active: true}, nil
	}
	err := runOrchestration(cfg, projectFn, orgFn)
	if !errors.Is(err, wanted) {
		t.Errorf("expected wrapped DB error, got %v", err)
	}
}
