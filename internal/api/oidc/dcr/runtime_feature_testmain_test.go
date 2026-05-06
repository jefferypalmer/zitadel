package dcr

import (
	"os"
	"testing"
)

// TestMain flips DefaultRuntimeFlag to false for the duration of every
// test in this package. v5.0.0-dcr.5 hotfix: production defaults the
// runtime flag to true (because the proto/projection wire-up was never
// finished), but the kit's R3 dual-gate behavior — runtime flag off →
// gate fires — is still part of the contract once the wire-up lands.
// The strict semantics are exercised here so the legacy contract has a
// permanent test surface; tests that need the production-default
// behavior can flip the var locally with `t.Cleanup`.
func TestMain(m *testing.M) {
	prev := DefaultRuntimeFlag
	DefaultRuntimeFlag = false
	code := m.Run()
	DefaultRuntimeFlag = prev
	os.Exit(code)
}
