package admin

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/query"
	object_pb "github.com/zitadel/zitadel/pkg/grpc/object"

	"github.com/zitadel/zitadel/pkg/grpc/admin"
)

// errIATFeatureDisabled is the typed gRPC error returned when the
// per-instance runtime feature flag DynamicClientRegistration is off.
// The message key Errors.DCR.FeatureDisabled is the i18n bundle key
// the HTTP-bridge maps for human-readable surfacing.
var errIATFeatureDisabled = status.Error(codes.FailedPrecondition, "Errors.DCR.FeatureDisabled")

// errIATYAMLDisabled is returned when the yaml gate
// (config.OIDC.DCR.Enabled) is off — the kit specifies the
// behaviorally-equivalent "not registered" semantics, surfaced as
// gRPC UNIMPLEMENTED so clients see the same code they would for any
// missing method (cavekit-iat.md R6 last AC / T-024).
var errIATYAMLDisabled = status.Error(codes.Unimplemented, "DCR is not enabled in this deployment.")

// IAT admin gRPC handlers — cavekit-iat.md R6 / T-023. Wires the
// proto surface (T-022) through to the IAT commands (T-021/T-017) and
// query helpers (T-020). The runtime feature-gate (T-024) is enforced
// by gateRuntime() at the top of each method; when off the call
// returns FAILED_PRECONDITION with Errors.DCR.FeatureDisabled.

// iatDualGate enforces both halves of the cavekit-iat.md R6 dual-gate:
//
//   - yaml off (config.OIDC.DCR.Enabled=false) → UNIMPLEMENTED.
//     This is the symmetric "not registered" semantic from the kit AC;
//     gRPC has no first-class way to deregister methods on a running
//     server, so we return UNIMPLEMENTED here which clients cannot
//     distinguish from a missing method on the wire.
//   - yaml on, runtime feature flag off → FAILED_PRECONDITION with
//     Errors.DCR.FeatureDisabled. Symmetric to the HTTP handler's 403
//     `feature_disabled` envelope.
//   - both on → nil (proceed with the call).
//
// The gate runs BEFORE the command/query layer is touched.
func (s *Server) iatDualGate(ctx context.Context) error {
	if !s.dcrYAMLEnabled {
		return errIATYAMLDisabled
	}
	if !authz.GetFeatures(ctx).DynamicClientRegistration {
		return errFeatureDisabledIAT(ctx)
	}
	return nil
}

func (s *Server) CreateInitialAccessToken(ctx context.Context, req *admin.CreateInitialAccessTokenRequest) (*admin.CreateInitialAccessTokenResponse, error) {
	if err := s.iatDualGate(ctx); err != nil {
		return nil, err
	}
	plaintext, iatID, err := s.command.CreateInitialAccessToken(
		ctx,
		req.GetProjectId(),
		"", // resource owner — admin RPC; let command resolve from project
		req.GetDescription(),
		int(req.GetMaxUses()),
		req.GetLifetime().AsDuration(),
		req.GetAllowedGrantTypes(),
		req.GetAllowedRedirectUriPatterns(),
	)
	if err != nil {
		return nil, err
	}
	resp := &admin.CreateInitialAccessTokenResponse{
		IatId: iatID,
		Token: plaintext,
		Details: &object_pb.ObjectDetails{
			ResourceOwner: authz.GetCtxData(ctx).OrgID,
		},
	}
	if d := req.GetLifetime().AsDuration(); d > 0 {
		// expires_at is best-effort — the command computes the same
		// instant from time.Now() at push, so the response and the
		// projection differ by sub-millisecond. The client uses this
		// for display only.
		resp.ExpiresAt = timestamppb.New(timestamppb.Now().AsTime().Add(d))
	}
	return resp, nil
}

func (s *Server) ListInitialAccessTokens(ctx context.Context, req *admin.ListInitialAccessTokensRequest) (*admin.ListInitialAccessTokensResponse, error) {
	if err := s.iatDualGate(ctx); err != nil {
		return nil, err
	}
	views, err := s.query.SearchInitialAccessTokens(ctx, req.GetProjectId())
	if err != nil {
		return nil, err
	}
	out := make([]*admin.InitialAccessTokenView, 0, len(views))
	for _, v := range views {
		out = append(out, iatViewToPb(v))
	}
	return &admin.ListInitialAccessTokensResponse{
		Result: out,
	}, nil
}

func (s *Server) RevokeInitialAccessToken(ctx context.Context, req *admin.RevokeInitialAccessTokenRequest) (*admin.RevokeInitialAccessTokenResponse, error) {
	if err := s.iatDualGate(ctx); err != nil {
		return nil, err
	}
	if err := s.command.RevokeInitialAccessToken(ctx, req.GetIatId(), req.GetProjectId(), ""); err != nil {
		return nil, err
	}
	return &admin.RevokeInitialAccessTokenResponse{
		Details: &object_pb.ObjectDetails{
			ResourceOwner: authz.GetCtxData(ctx).OrgID,
		},
	}, nil
}

func iatViewToPb(v *query.InitialAccessToken) *admin.InitialAccessTokenView {
	out := &admin.InitialAccessTokenView{
		Id:                         v.ID,
		ProjectId:                  v.ProjectID,
		MaxUses:                    int32(v.MaxUses),
		UsesConsumed:               int32(v.UsesConsumed),
		Revoked:                    v.Revoked,
		CreatedAt:                  timestamppb.New(v.CreatedAt),
		ChangeDate:                 timestamppb.New(v.ChangeDate),
		AllowedGrantTypes:          []string(v.AllowedGrantTypes),
		AllowedRedirectUriPatterns: []string(v.AllowedRedirectURIPatterns),
	}
	if v.ExpiresAt != nil {
		out.ExpiresAt = timestamppb.New(*v.ExpiresAt)
	}
	return out
}

func errFeatureDisabledIAT(ctx context.Context) error {
	return errIATFeatureDisabled
}
