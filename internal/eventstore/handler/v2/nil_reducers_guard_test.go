package handler

import (
	"strings"
	"testing"

	"github.com/zitadel/zitadel/internal/eventstore"
)

// cavekit-eventstore-framework-guard.md R1 / R2 (T-009 / T-010).
//
// Truth-table: NewHandler must panic when a projection has empty
// Reducers AND no TriggerWithoutEvents callback AND does not implement
// GlobalProjection. The other three combinations must construct
// without panic. FieldHandler is unaffected — it constructs Handler{}
// via struct literal (field_handler.go:43-58), bypassing this guard
// by design.

// guardProjection is the minimal Projection used by these cases.
type guardProjection struct {
	name     string
	reducers []AggregateReducer
}

func (p *guardProjection) Name() string                  { return p.name }
func (p *guardProjection) Reducers() []AggregateReducer  { return p.reducers }

// guardGlobalProjection adds the GlobalProjection marker (FilterGlobalEvents)
// so case 4 exercises the global-projection escape hatch.
type guardGlobalProjection struct{ guardProjection }

func (p *guardGlobalProjection) FilterGlobalEvents() {}

func TestNewHandler_GuardCase1_PanicOnEmptyReducers(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on empty Reducers + nil TriggerWithoutEvents + non-Global, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic value, got %T: %v", r, r)
		}
		if !strings.Contains(msg, "refusing to construct") {
			t.Fatalf("panic message missing 'refusing to construct' substring: %q", msg)
		}
		if !strings.Contains(msg, "the_offender") {
			t.Fatalf("panic message must include the projection name; got %q", msg)
		}
	}()

	p := &guardProjection{name: "the_offender", reducers: nil}
	_ = NewHandler(t.Context(), &Config{}, p)
}

func TestNewHandler_GuardCase2_PassWithNonEmptyReducers(t *testing.T) {
	p := &guardProjection{
		name: "good_with_events",
		reducers: []AggregateReducer{{
			Aggregate: eventstore.AggregateType("test"),
			EventReducers: []EventReducer{{
				Event: eventstore.EventType("test.created"),
			}},
		}},
	}
	h := NewHandler(t.Context(), &Config{}, p)
	if h == nil {
		t.Fatal("NewHandler returned nil for valid projection")
	}
	if got, want := len(h.eventTypes), 1; got != want {
		t.Fatalf("eventTypes length: got %d, want %d", got, want)
	}
}

func TestNewHandler_GuardCase3_PassWithTriggerWithoutEvents(t *testing.T) {
	p := &guardProjection{name: "good_scheduled", reducers: nil}
	cfg := &Config{
		TriggerWithoutEvents: func(e eventstore.Event) (*Statement, error) {
			return nil, nil
		},
	}
	h := NewHandler(t.Context(), cfg, p)
	if h == nil {
		t.Fatal("NewHandler returned nil for projection with TriggerWithoutEvents")
	}
	if h.triggerWithoutEvents == nil {
		t.Fatal("expected triggerWithoutEvents to be stored on the handler")
	}
}

func TestNewHandler_GuardCase4_PassWithGlobalProjection(t *testing.T) {
	p := &guardGlobalProjection{guardProjection: guardProjection{name: "good_global", reducers: nil}}
	h := NewHandler(t.Context(), &Config{}, p)
	if h == nil {
		t.Fatal("NewHandler returned nil for GlobalProjection")
	}
	if !h.queryGlobal {
		t.Fatal("queryGlobal must be true when projection implements GlobalProjection")
	}
}

// cavekit-eventstore-framework-guard.md R1.1 (T-028). 5th truth-table
// case: a projection that returns a non-empty []AggregateReducer slice
// where every entry has nil/empty EventReducers must still trip the
// guard. Pre-R1.1 the guard only fired on `len(aggregates) == 0`,
// missing this degenerate-non-empty shape — the prefill loop would
// scan the eventstore as no-op statements just as in the empty case.
func TestNewHandler_GuardCase5_PanicOnDegenerateNonEmptyReducers(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on degenerate non-empty Reducers (entries with empty EventReducers), got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic value, got %T: %v", r, r)
		}
		if !strings.Contains(msg, "refusing to construct") {
			t.Fatalf("panic message missing 'refusing to construct' substring: %q", msg)
		}
	}()

	p := &guardProjection{
		name: "degenerate_non_empty",
		reducers: []AggregateReducer{
			{Aggregate: eventstore.AggregateType("x"), EventReducers: nil},
			{Aggregate: eventstore.AggregateType("y"), EventReducers: []EventReducer{}},
		},
	}
	_ = NewHandler(t.Context(), &Config{}, p)
}
