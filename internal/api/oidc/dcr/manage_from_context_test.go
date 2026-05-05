package dcr

import (
	"context"
	"strings"
	"testing"
)

// cavekit-manage-handler.md R8 (T-007). ManageFromContext panics when
// called without manageVerifyDispatch in the chain. Production paths
// never trip the panic — the dispatcher monopoly guarantees the value
// is set. cavekit-manage-handler.md R9 (T-025) wraps the DCR router in
// middleware.RecoverHandler so a router regression that mounts a
// handler outside the dispatch chain still emits the RFC 7591 JSON
// envelope from dcrWriteRecoverError (not the text/plain fallback).
func TestManageFromContext_PanicOnMissing(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on bare context, got nil")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic value, got %T: %v", r, r)
		}
		if !strings.Contains(msg, "programmer error") {
			t.Fatalf("panic message missing 'programmer error' marker: %q", msg)
		}
	}()
	_ = ManageFromContext(context.Background())
}

func TestManageFromContext_HappyPath(t *testing.T) {
	want := &ManageContext{ClientID: "c1", AppID: "a1", ProjectID: "p1", ResourceOwner: "o1"}
	ctx := contextWithManage(context.Background(), want)
	got := ManageFromContext(ctx)
	if got != want {
		t.Fatalf("ManageFromContext: got %+v, want %+v", got, want)
	}
}
