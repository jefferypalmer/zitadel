package admin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/api/oidc/dcr"
	"github.com/zitadel/zitadel/internal/feature"
	"github.com/zitadel/zitadel/pkg/grpc/admin"
)

// TestIAT_RuntimeFeatureGate covers cavekit-iat.md R6 dual-gate AC for
// the runtime half: yaml=ON, runtime flag=OFF → FAILED_PRECONDITION
// with Errors.DCR.FeatureDisabled across all three IAT admin RPCs.
//
// The tests use a Server with nil command/query because the gate runs
// BEFORE either is touched — that's the contract. If a future refactor
// moves the gate after a command call, these tests will panic loudly
// on the nil deref and force the regression to be caught.
func TestIAT_RuntimeFeatureGate(t *testing.T) {
	// v5.0.0-dcr.5 hotfix: dcr.DefaultRuntimeFlag now defaults to true
	// (see internal/api/oidc/dcr/runtime_feature.go). Override to false
	// here so the legacy "runtime flag off → FAILED_PRECONDITION"
	// contract still has a test seam.
	prevDefault := dcr.DefaultRuntimeFlag
	dcr.DefaultRuntimeFlag = false
	t.Cleanup(func() { dcr.DefaultRuntimeFlag = prevDefault })

	s := &Server{dcrYAMLEnabled: true}
	ctx := authz.WithFeatures(context.Background(), feature.Features{DynamicClientRegistration: false})

	t.Run("CreateInitialAccessToken", func(t *testing.T) {
		_, err := s.CreateInitialAccessToken(ctx, &admin.CreateInitialAccessTokenRequest{ProjectId: "p"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok, "must be a gRPC status error, got %T: %v", err, err)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Equal(t, "Errors.DCR.FeatureDisabled", st.Message())
	})

	t.Run("ListInitialAccessTokens", func(t *testing.T) {
		_, err := s.ListInitialAccessTokens(ctx, &admin.ListInitialAccessTokensRequest{})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok, "must be a gRPC status error, got %T: %v", err, err)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Equal(t, "Errors.DCR.FeatureDisabled", st.Message())
	})

	t.Run("RevokeInitialAccessToken", func(t *testing.T) {
		_, err := s.RevokeInitialAccessToken(ctx, &admin.RevokeInitialAccessTokenRequest{IatId: "i", ProjectId: "p"})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok, "must be a gRPC status error, got %T: %v", err, err)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Equal(t, "Errors.DCR.FeatureDisabled", st.Message())
	})
}

// TestIAT_RuntimeFeatureGate_PassesWhenOn pins the symmetric case:
// when both gates are ON, the gate passes (and the call proceeds; here
// it will nil-panic on the command field, which proves the gate
// short-circuit ran first when the flag was off — see comment above).
//
// Use a recover() so the test asserts "we got past the gate" without
// requiring a real Commands instance.
func TestIAT_RuntimeFeatureGate_PassesWhenOn(t *testing.T) {
	s := &Server{dcrYAMLEnabled: true}
	ctx := authz.WithFeatures(context.Background(), feature.Features{DynamicClientRegistration: true})

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected nil-panic past the gate, got nil — gate may have rejected a valid request")
		}
	}()
	_, _ = s.CreateInitialAccessToken(ctx, &admin.CreateInitialAccessTokenRequest{ProjectId: "p"})
}

// TestIAT_YAMLGate_DisabledReturnsUnimplemented covers the cavekit-iat.md
// R6 last AC: when the yaml gate (config.OIDC.DCR.Enabled) is OFF, all
// three RPCs return gRPC UNIMPLEMENTED — the symmetric "not registered"
// semantic from the kit (gRPC has no first-class deregister mechanism;
// UNIMPLEMENTED is what clients see for an unmounted method).
//
// The runtime feature flag is ON in the ctx to prove the yaml gate is
// the FIRST gate checked — yaml-off short-circuits before runtime-flag
// evaluation runs.
func TestIAT_YAMLGate_DisabledReturnsUnimplemented(t *testing.T) {
	s := &Server{dcrYAMLEnabled: false}
	ctx := authz.WithFeatures(context.Background(), feature.Features{DynamicClientRegistration: true})

	cases := []struct {
		name string
		call func() error
	}{
		{
			name: "CreateInitialAccessToken",
			call: func() error {
				_, err := s.CreateInitialAccessToken(ctx, &admin.CreateInitialAccessTokenRequest{ProjectId: "p"})
				return err
			},
		},
		{
			name: "ListInitialAccessTokens",
			call: func() error {
				_, err := s.ListInitialAccessTokens(ctx, &admin.ListInitialAccessTokensRequest{})
				return err
			},
		},
		{
			name: "RevokeInitialAccessToken",
			call: func() error {
				_, err := s.RevokeInitialAccessToken(ctx, &admin.RevokeInitialAccessTokenRequest{IatId: "i", ProjectId: "p"})
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok, "must be a gRPC status error, got %T: %v", err, err)
			assert.Equal(t, codes.Unimplemented, st.Code(),
				"yaml-off must surface as UNIMPLEMENTED (kit R6 last AC)")
		})
	}
}
