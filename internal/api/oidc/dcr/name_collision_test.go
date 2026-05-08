package dcr

import (
	"context"
	"errors"
	"testing"
)

// fakeAppNameTaken builds an AppNameTakenFn from a static set of taken
// names for the given project. Optional `errFor` returns an error for a
// matching name to exercise the "probe failure → skip policy" branch.
func fakeAppNameTaken(taken map[string]bool, errFor map[string]error) AppNameTakenFn {
	return func(ctx context.Context, projectID, appName string) (bool, error) {
		if errFor != nil {
			if e, ok := errFor[appName]; ok {
				return false, e
			}
		}
		return taken[appName], nil
	}
}

func TestApplyClientNameCollisionPolicy_PolicyOff(t *testing.T) {
	meta := &RFC7591Metadata{ClientName: "smoke"}
	taken := fakeAppNameTaken(map[string]bool{"smoke": true}, nil)
	if err := applyClientNameCollisionPolicy(context.Background(), CollisionPolicyOff, taken, "p1", meta); err != nil {
		t.Fatalf("expected nil error when policy off, got %+v", err)
	}
	if meta.ClientName != "smoke" {
		t.Errorf("expected ClientName unchanged when policy off, got %q", meta.ClientName)
	}
}

func TestApplyClientNameCollisionPolicy_NoTakenFn(t *testing.T) {
	meta := &RFC7591Metadata{ClientName: "smoke"}
	if err := applyClientNameCollisionPolicy(context.Background(), CollisionPolicySuffix, nil, "p1", meta); err != nil {
		t.Fatalf("expected nil error when probe fn missing, got %+v", err)
	}
	if meta.ClientName != "smoke" {
		t.Errorf("expected ClientName unchanged when probe fn missing, got %q", meta.ClientName)
	}
}

func TestApplyClientNameCollisionPolicy_EmptyName(t *testing.T) {
	meta := &RFC7591Metadata{ClientName: ""}
	taken := fakeAppNameTaken(nil, nil)
	if err := applyClientNameCollisionPolicy(context.Background(), CollisionPolicySuffix, taken, "p1", meta); err != nil {
		t.Fatalf("expected nil error for empty name, got %+v", err)
	}
	if meta.ClientName != "" {
		t.Errorf("expected ClientName unchanged when empty, got %q", meta.ClientName)
	}
}

func TestApplyClientNameCollisionPolicy_NilMeta(t *testing.T) {
	taken := fakeAppNameTaken(nil, nil)
	if err := applyClientNameCollisionPolicy(context.Background(), CollisionPolicySuffix, taken, "p1", nil); err != nil {
		t.Fatalf("expected nil error for nil meta, got %+v", err)
	}
}

func TestApplyClientNameCollisionPolicy_NoCollision(t *testing.T) {
	meta := &RFC7591Metadata{ClientName: "fresh"}
	taken := fakeAppNameTaken(map[string]bool{"already-taken": true}, nil)
	if err := applyClientNameCollisionPolicy(context.Background(), CollisionPolicySuffix, taken, "p1", meta); err != nil {
		t.Fatalf("expected nil error when no collision, got %+v", err)
	}
	if meta.ClientName != "fresh" {
		t.Errorf("expected ClientName unchanged when no collision, got %q", meta.ClientName)
	}
}

func TestApplyClientNameCollisionPolicy_SuffixFirstAttempt(t *testing.T) {
	meta := &RFC7591Metadata{ClientName: "smoke"}
	taken := fakeAppNameTaken(map[string]bool{"smoke": true}, nil)
	if err := applyClientNameCollisionPolicy(context.Background(), CollisionPolicySuffix, taken, "p1", meta); err != nil {
		t.Fatalf("unexpected error: %+v", err)
	}
	if meta.ClientName != "smoke-2" {
		t.Errorf("expected suffix smoke-2, got %q", meta.ClientName)
	}
}

func TestApplyClientNameCollisionPolicy_SuffixSkipMultiple(t *testing.T) {
	meta := &RFC7591Metadata{ClientName: "smoke"}
	taken := fakeAppNameTaken(map[string]bool{
		"smoke":   true,
		"smoke-2": true,
		"smoke-3": true,
		"smoke-4": true,
	}, nil)
	if err := applyClientNameCollisionPolicy(context.Background(), CollisionPolicySuffix, taken, "p1", meta); err != nil {
		t.Fatalf("unexpected error: %+v", err)
	}
	if meta.ClientName != "smoke-5" {
		t.Errorf("expected suffix smoke-5, got %q", meta.ClientName)
	}
}

func TestApplyClientNameCollisionPolicy_SuffixCapExhausted(t *testing.T) {
	meta := &RFC7591Metadata{ClientName: "saturated"}
	allTaken := map[string]bool{"saturated": true}
	for n := 2; n <= collisionSuffixMaxAttempts; n++ {
		allTaken["saturated-"+itoaN(n)] = true
	}
	taken := fakeAppNameTaken(allTaken, nil)
	got := applyClientNameCollisionPolicy(context.Background(), CollisionPolicySuffix, taken, "p1", meta)
	if got == nil {
		t.Fatal("expected ClampError when suffix cap exhausted, got nil")
	}
	if got.Code != ErrCodeServerError || got.HTTPStatus() != 500 {
		t.Errorf("expected 500 server_error, got status=%d code=%q", got.HTTPStatus(), got.Code)
	}
	// On exhaustion the meta is left unchanged so the dispatcher's error
	// path doesn't observe a partial mutation.
	if meta.ClientName != "saturated" {
		t.Errorf("expected ClientName unchanged on cap exhausted, got %q", meta.ClientName)
	}
}

func TestApplyClientNameCollisionPolicy_RejectMode(t *testing.T) {
	meta := &RFC7591Metadata{ClientName: "smoke"}
	taken := fakeAppNameTaken(map[string]bool{"smoke": true}, nil)
	got := applyClientNameCollisionPolicy(context.Background(), CollisionPolicyReject, taken, "p1", meta)
	if got == nil {
		t.Fatal("expected ClampError in reject mode on collision, got nil")
	}
	if got.Code != ErrCodeInvalidClientMetadata || got.HTTPStatus() != 400 {
		t.Errorf("expected 400 invalid_client_metadata, got status=%d code=%q", got.HTTPStatus(), got.Code)
	}
	if meta.ClientName != "smoke" {
		t.Errorf("expected ClientName unchanged in reject mode, got %q", meta.ClientName)
	}
}

func TestApplyClientNameCollisionPolicy_ProbeError(t *testing.T) {
	meta := &RFC7591Metadata{ClientName: "smoke"}
	taken := fakeAppNameTaken(nil, map[string]error{"smoke": errors.New("db down")})
	if err := applyClientNameCollisionPolicy(context.Background(), CollisionPolicySuffix, taken, "p1", meta); err != nil {
		t.Fatalf("expected nil (probe failure → skip policy), got %+v", err)
	}
	if meta.ClientName != "smoke" {
		t.Errorf("expected ClientName unchanged on probe error, got %q", meta.ClientName)
	}
}

func TestApplyClientNameCollisionPolicy_MidLoopProbeError(t *testing.T) {
	meta := &RFC7591Metadata{ClientName: "smoke"}
	taken := fakeAppNameTaken(
		map[string]bool{"smoke": true, "smoke-2": true},
		map[string]error{"smoke-3": errors.New("db hiccup")},
	)
	if err := applyClientNameCollisionPolicy(context.Background(), CollisionPolicySuffix, taken, "p1", meta); err != nil {
		t.Fatalf("expected nil (mid-loop probe failure → skip), got %+v", err)
	}
	if meta.ClientName != "smoke" {
		t.Errorf("expected ClientName unchanged when mid-loop probe fails, got %q", meta.ClientName)
	}
}

func TestApplyClientNameCollisionPolicy_UnknownPolicyTreatedAsOff(t *testing.T) {
	meta := &RFC7591Metadata{ClientName: "smoke"}
	taken := fakeAppNameTaken(map[string]bool{"smoke": true}, nil)
	if err := applyClientNameCollisionPolicy(context.Background(), "garbage-config-typo", taken, "p1", meta); err != nil {
		t.Fatalf("expected nil for unknown policy (fail-open), got %+v", err)
	}
	if meta.ClientName != "smoke" {
		t.Errorf("expected ClientName unchanged on unknown policy, got %q", meta.ClientName)
	}
}

func itoaN(n int) string {
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
