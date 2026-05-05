package query

import (
	"context"
	"testing"
	"time"
)

// cavekit-software-statement.md R9 (T-011). The janitor goroutine MUST
// exit within ~one tick of ctx.Done() — kit acceptance asserts a 100ms
// upper bound. We pin the interval well above 100ms so the deadline is
// load-bearing on the ctx.Done() select arm and not on a stray tick.
func TestRunSoftwareStatementJTIJanitor_ExitsOnContextCancel(t *testing.T) {
	q := &Queries{} // unused on the cancellation arm — the reaper isn't invoked
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		q.RunSoftwareStatementJTIJanitor(ctx, time.Hour, nil)
		close(done)
	}()
	cancel()
	select {
	case <-done:
		// pass
	case <-time.After(100 * time.Millisecond):
		t.Fatal("janitor did not exit within 100ms of ctx.Done()")
	}
}

// Non-positive interval disables the janitor (returns immediately).
// Pinned because cmd/start/start.go gates on Enabled — Interval=0 is a
// belt-and-suspenders no-op even if the gate is bypassed.
func TestRunSoftwareStatementJTIJanitor_DisabledOnZeroInterval(t *testing.T) {
	q := &Queries{}
	done := make(chan struct{})
	go func() {
		q.RunSoftwareStatementJTIJanitor(context.Background(), 0, nil)
		close(done)
	}()
	select {
	case <-done:
		// pass
	case <-time.After(100 * time.Millisecond):
		t.Fatal("janitor with zero interval should return immediately")
	}
}
