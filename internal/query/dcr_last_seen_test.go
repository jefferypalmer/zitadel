package query

import (
	"sync"
	"testing"
	"time"
)

func TestLastSeenThrottle_ShouldWrite(t *testing.T) {
	throttle := NewLastSeenThrottle(time.Minute)
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	throttle.now = func() time.Time { return now }

	if !throttle.ShouldWrite("inst-1", "app-1") {
		t.Fatal("first call must allow write")
	}
	if throttle.ShouldWrite("inst-1", "app-1") {
		t.Fatal("immediate second call must throttle")
	}

	// Advance just under window — still throttled.
	throttle.now = func() time.Time { return now.Add(59 * time.Second) }
	if throttle.ShouldWrite("inst-1", "app-1") {
		t.Fatal("call within window must throttle")
	}

	// Advance past window.
	throttle.now = func() time.Time { return now.Add(61 * time.Second) }
	if !throttle.ShouldWrite("inst-1", "app-1") {
		t.Fatal("call outside window must allow write")
	}
}

func TestLastSeenThrottle_DistinctKeys(t *testing.T) {
	throttle := NewLastSeenThrottle(time.Minute)
	if !throttle.ShouldWrite("inst-1", "app-1") {
		t.Fatal("inst-1/app-1 first call should pass")
	}
	if !throttle.ShouldWrite("inst-1", "app-2") {
		t.Fatal("inst-1/app-2 must not be throttled by inst-1/app-1")
	}
	if !throttle.ShouldWrite("inst-2", "app-1") {
		t.Fatal("inst-2/app-1 must not be throttled by inst-1/app-1")
	}
	if throttle.ShouldWrite("inst-1", "app-1") {
		t.Fatal("inst-1/app-1 must remain throttled after distinct-key writes")
	}
}

func TestLastSeenThrottle_EmptyKeys(t *testing.T) {
	throttle := NewLastSeenThrottle(time.Minute)
	if throttle.ShouldWrite("", "app-1") {
		t.Fatal("empty instanceID must short-circuit to false")
	}
	if throttle.ShouldWrite("inst-1", "") {
		t.Fatal("empty appID must short-circuit to false")
	}
}

func TestLastSeenThrottle_NilReceiver(t *testing.T) {
	var throttle *LastSeenThrottle
	if throttle.ShouldWrite("inst-1", "app-1") {
		t.Fatal("nil throttle must return false (no-op)")
	}
}

func TestLastSeenThrottle_DefaultInterval(t *testing.T) {
	throttle := NewLastSeenThrottle(0)
	if throttle.interval != DefaultLastSeenThrottleInterval {
		t.Errorf("expected default interval %v, got %v", DefaultLastSeenThrottleInterval, throttle.interval)
	}
	throttle = NewLastSeenThrottle(-1 * time.Second)
	if throttle.interval != DefaultLastSeenThrottleInterval {
		t.Errorf("expected default interval for negative input, got %v", throttle.interval)
	}
}

func TestLastSeenThrottle_ConcurrentSafe(t *testing.T) {
	// Smoke test: race detector run (-race) catches mutex misuse.
	throttle := NewLastSeenThrottle(time.Minute)
	var wg sync.WaitGroup
	wg.Add(50)
	for i := 0; i < 50; i++ {
		go func() {
			defer wg.Done()
			throttle.ShouldWrite("inst-1", "app-1")
			throttle.ShouldWrite("inst-1", "app-2")
		}()
	}
	wg.Wait()
}
