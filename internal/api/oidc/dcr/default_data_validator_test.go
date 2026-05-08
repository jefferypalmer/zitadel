package dcr

import (
	"context"
	"errors"
	"testing"
)

func TestNewDefaultDataValidator_HappyPath(t *testing.T) {
	v := NewDefaultDataValidator(
		func(ctx context.Context, id string) (bool, bool, string, error) {
			return true, true, "org-1", nil
		},
		func(ctx context.Context, id string) (bool, bool, error) {
			return true, true, nil
		},
	)
	if got := v(context.Background(), "p1", "org-1"); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestNewDefaultDataValidator_ProjectMissing(t *testing.T) {
	v := NewDefaultDataValidator(
		func(ctx context.Context, id string) (bool, bool, string, error) {
			return false, false, "", nil
		},
		func(ctx context.Context, id string) (bool, bool, error) {
			return true, true, nil
		},
	)
	got := v(context.Background(), "p1", "org-1")
	if got == nil || got.Code != ErrCodeDefaultProjectNotFound || got.HTTPStatus() != 503 {
		t.Errorf("expected 503 default_project_not_found, got %+v", got)
	}
}

func TestNewDefaultDataValidator_ProjectInactive(t *testing.T) {
	v := NewDefaultDataValidator(
		func(ctx context.Context, id string) (bool, bool, string, error) {
			return true, false, "org-1", nil
		},
		func(ctx context.Context, id string) (bool, bool, error) {
			return true, true, nil
		},
	)
	got := v(context.Background(), "p1", "org-1")
	if got == nil || got.Code != ErrCodeDefaultProjectNotFound {
		t.Errorf("expected default_project_not_found for inactive, got %+v", got)
	}
}

func TestNewDefaultDataValidator_OrgMissing(t *testing.T) {
	v := NewDefaultDataValidator(
		func(ctx context.Context, id string) (bool, bool, string, error) {
			return true, true, "org-1", nil
		},
		func(ctx context.Context, id string) (bool, bool, error) {
			return false, false, nil
		},
	)
	got := v(context.Background(), "p1", "org-1")
	if got == nil || got.Code != ErrCodeDefaultProjectNotFound {
		t.Errorf("expected default_project_not_found for missing org, got %+v", got)
	}
}

func TestNewDefaultDataValidator_OrgInactive(t *testing.T) {
	v := NewDefaultDataValidator(
		func(ctx context.Context, id string) (bool, bool, string, error) {
			return true, true, "org-1", nil
		},
		func(ctx context.Context, id string) (bool, bool, error) {
			return true, false, nil
		},
	)
	got := v(context.Background(), "p1", "org-1")
	if got == nil || got.Code != ErrCodeDefaultProjectNotFound {
		t.Errorf("expected default_project_not_found for inactive org, got %+v", got)
	}
}

func TestNewDefaultDataValidator_ResourceOwnerMismatch(t *testing.T) {
	v := NewDefaultDataValidator(
		func(ctx context.Context, id string) (bool, bool, string, error) {
			return true, true, "different-org", nil
		},
		func(ctx context.Context, id string) (bool, bool, error) {
			return true, true, nil
		},
	)
	got := v(context.Background(), "p1", "org-1")
	if got == nil || got.Code != ErrCodeDefaultProjectNotFound {
		t.Errorf("expected default_project_not_found for owner mismatch, got %+v", got)
	}
}

func TestNewDefaultDataValidator_ProjectProbeError(t *testing.T) {
	v := NewDefaultDataValidator(
		func(ctx context.Context, id string) (bool, bool, string, error) {
			return false, false, "", errors.New("db boom")
		},
		func(ctx context.Context, id string) (bool, bool, error) {
			return true, true, nil
		},
	)
	got := v(context.Background(), "p1", "org-1")
	if got == nil || got.Code != ErrCodeServerError || got.HTTPStatus() != 503 {
		t.Errorf("expected 503 server_error on probe failure, got %+v", got)
	}
	if got.Wrapped == nil {
		t.Errorf("expected Wrapped error to carry probe failure")
	}
}

func TestNewDefaultDataValidator_OrgProbeError(t *testing.T) {
	v := NewDefaultDataValidator(
		func(ctx context.Context, id string) (bool, bool, string, error) {
			return true, true, "org-1", nil
		},
		func(ctx context.Context, id string) (bool, bool, error) {
			return false, false, errors.New("db hiccup")
		},
	)
	got := v(context.Background(), "p1", "org-1")
	if got == nil || got.Code != ErrCodeServerError {
		t.Errorf("expected 503 server_error on org probe failure, got %+v", got)
	}
}
