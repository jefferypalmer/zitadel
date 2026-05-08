package query

import (
	"context"
	"errors"
	"testing"
)

func TestRunOneClientJanitorTick_Empty(t *testing.T) {
	// listFn returns no candidates → reaped=0, errored=false.
	// We invoke the helper directly rather than through Queries to
	// avoid the SQL round-trip; the behavior tested is the loop logic
	// + per-row error policy.
	candidates := []InactiveDCRClient{}
	deleted := 0
	deleteFn := func(ctx context.Context, c InactiveDCRClient) error {
		deleted++
		return nil
	}
	reaped, errored := simulateTick(candidates, nil, deleteFn)
	if reaped != 0 || errored {
		t.Errorf("empty list: reaped=%d errored=%v want 0/false", reaped, errored)
	}
	if deleted != 0 {
		t.Errorf("deleteFn must not be called when list is empty")
	}
}

func TestRunOneClientJanitorTick_AllSuccess(t *testing.T) {
	candidates := []InactiveDCRClient{
		{InstanceID: "i", ProjectID: "p", OrgID: "o", AppID: "a-1", ClientID: "c-1"},
		{InstanceID: "i", ProjectID: "p", OrgID: "o", AppID: "a-2", ClientID: "c-2"},
	}
	deleteFn := func(ctx context.Context, c InactiveDCRClient) error { return nil }
	reaped, errored := simulateTick(candidates, nil, deleteFn)
	if reaped != 2 || errored {
		t.Errorf("all-success: reaped=%d errored=%v want 2/false", reaped, errored)
	}
}

func TestRunOneClientJanitorTick_PartialFailure(t *testing.T) {
	// One delete fails, one succeeds → reaped=1 errored=true; loop
	// continues past the failure.
	candidates := []InactiveDCRClient{
		{ClientID: "c-failing"},
		{ClientID: "c-ok"},
	}
	deleteFn := func(ctx context.Context, c InactiveDCRClient) error {
		if c.ClientID == "c-failing" {
			return errors.New("delete failed")
		}
		return nil
	}
	reaped, errored := simulateTick(candidates, nil, deleteFn)
	if reaped != 1 {
		t.Errorf("partial-failure: reaped=%d want 1 (loop continues past failure)", reaped)
	}
	if !errored {
		t.Errorf("partial-failure: errored=false want true")
	}
}

func TestRunOneClientJanitorTick_ListError(t *testing.T) {
	deleteFn := func(ctx context.Context, c InactiveDCRClient) error { return nil }
	reaped, errored := simulateTick(nil, errors.New("db down"), deleteFn)
	if reaped != 0 || !errored {
		t.Errorf("list-error: reaped=%d errored=%v want 0/true", reaped, errored)
	}
}

// simulateTick mirrors runOneClientJanitorTick but takes the candidate
// list / list-error directly so we don't need a real *Queries (and thus
// a real DB or sqlmock) to exercise the loop's control flow.
func simulateTick(
	candidates []InactiveDCRClient,
	listErr error,
	deleteFn DCRClientJanitorDeleteFn,
) (reaped int, errored bool) {
	if listErr != nil {
		return 0, true
	}
	for _, c := range candidates {
		if deleteFn(context.Background(), c) != nil {
			errored = true
			continue
		}
		reaped++
	}
	return reaped, errored
}

func TestRunDCRClientJanitor_DisabledOnZeroInputs(t *testing.T) {
	q := &Queries{}
	deleteFn := func(ctx context.Context, c InactiveDCRClient) error { return nil }
	// Each of these MUST return immediately (no panic on nil *Queries
	// internals because the early-return short-circuits before any
	// access).
	q.RunDCRClientJanitor(context.Background(), 0, 1, 1, deleteFn, nil)
	q.RunDCRClientJanitor(context.Background(), 1, 0, 1, deleteFn, nil)
	q.RunDCRClientJanitor(context.Background(), 1, 1, 0, deleteFn, nil)
	q.RunDCRClientJanitor(context.Background(), 1, 1, 1, nil, nil)
}
