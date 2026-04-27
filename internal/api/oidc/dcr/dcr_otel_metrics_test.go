package dcr

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/zitadel/backend/v3/instrumentation/metrics"
)

// T-067 — OpenTelemetry metrics for DCR
// (cavekit-console-ui-docs-and-observability.md R8).
//
// Acceptance criteria pinned by this file:
//
//   - AC1 Counter `zitadel.dcr.registrations_total`
//         (labels: result, auth_method, application_type).
//   - AC2 Histogram `zitadel.dcr.request_duration_seconds`.
//   - AC3 Counter `zitadel.dcr.errors_total` (label: code).
//   - AC4 Counter `zitadel.dcr.iat.consumed_total`.
//   - AC5 Counter `zitadel.dcr.iat.exhausted_total`.
//   - AC6 No DCR metric is emitted with the `dcr_*_total`
//         underscore style.
//
// Test plumbing strategy: the global meter is the noop meter under
// `go test` (no exporter is wired), so we cannot inspect emitted
// values. Instead the contract-level pin is two-pronged:
//
//   1. Constants pin: the metric NAME constants in `metrics.go` MUST
//      equal the literal strings the kit demands. Any rename of a
//      metric is a behavior break for downstream Prometheus / OTLP
//      consumers and MUST trigger this test.
//
//   2. Registration pin: after the package init() registers the
//      metrics, `metrics.AddCount` / `AddHistogramMeasurement` calls
//      against the kit-named metrics MUST NOT return the
//      `Errors.Metrics.Counter.NotFound` zerror. The same calls
//      against the legacy `dcr_*_total` underscore-style names
//      MUST return NotFound (R8 AC6).

// ───────────────────────────────────────────────────────────────────────
// AC1-AC5 name pin
// ───────────────────────────────────────────────────────────────────────

func TestT067_R8_AC1to5_MetricNamesMatchKit(t *testing.T) {
	// Map kit AC → metric name constant. The first column is the
	// literal string the kit asserts; the second is the constant the
	// implementation uses. They MUST match by-character.
	cases := []struct {
		ac       string
		kitName  string
		constVal string
	}{
		{"AC1", "zitadel.dcr.registrations_total", MetricRegistrationsTotal},
		{"AC2", "zitadel.dcr.request_duration_seconds", MetricRequestDurationSeconds},
		{"AC3", "zitadel.dcr.errors_total", MetricErrorsTotal},
		{"AC4", "zitadel.dcr.iat.consumed_total", MetricIATConsumedTotal},
		{"AC5", "zitadel.dcr.iat.exhausted_total", MetricIATExhaustedTotal},
	}
	for _, c := range cases {
		t.Run(c.ac, func(t *testing.T) {
			assert.Equal(t, c.kitName, c.constVal,
				"R8 %s: metric name must equal the kit-mandated literal "+
					"(any rename is a downstream-breaking change for Prometheus / OTLP consumers)",
				c.ac)
		})
	}
}

// ───────────────────────────────────────────────────────────────────────
// AC1-AC5 registration pin
// ───────────────────────────────────────────────────────────────────────

func TestT067_R8_RegistrationSucceeds(t *testing.T) {
	// F-001 fix: registration is now lazy-on-first-record (no init()),
	// matching the codebase pattern at
	// internal/api/grpc/server/middleware/metrics_interceptor.go. Call
	// RegisterMetrics explicitly to verify the surface still works in
	// the test binary; production wiring relies on ensureRegistered()
	// being triggered by the first record-call.
	require.NoError(t, RegisterMetrics(),
		"production callers expect RegisterMetrics to be idempotent")
	// Trigger the lazy guard explicitly so subsequent assertions read
	// post-registration state regardless of whether any earlier test
	// in this binary already exercised a record-helper.
	ensureRegistered()

	// The five kit names MUST be registered — sanity-check by calling
	// AddCount / AddHistogramMeasurement and asserting no NotFound.
	ctx := context.Background()

	for _, name := range []string{
		MetricRegistrationsTotal,
		MetricErrorsTotal,
		MetricIATConsumedTotal,
		MetricIATExhaustedTotal,
	} {
		err := metrics.AddCount(ctx, name, 1, nil)
		assert.NoError(t, err,
			"counter %q MUST be registered before observation; AddCount returned %v", name, err)
	}

	err := metrics.AddHistogramMeasurement(ctx, MetricRequestDurationSeconds, 0.012, nil)
	assert.NoError(t, err,
		"histogram %q MUST be registered before observation", MetricRequestDurationSeconds)
}

// ───────────────────────────────────────────────────────────────────────
// AC6 — no underscore-style names registered
// ───────────────────────────────────────────────────────────────────────

func TestT067_R8_AC6_NoUnderscoreStyleMetric(t *testing.T) {
	// The kit explicitly bans the legacy `dcr_*_total` underscore style
	// (R8 AC6). Per metric, observe against the underscore form and
	// require a NotFound — proves no code path is emitting the
	// forbidden naming convention.
	ctx := context.Background()
	bannedNames := []string{
		"dcr_registrations_total",
		"dcr_request_duration_seconds",
		"dcr_errors_total",
		"dcr_iat_consumed_total",
		"dcr_iat_exhausted_total",
	}
	for _, name := range bannedNames {
		t.Run(name, func(t *testing.T) {
			err := metrics.AddCount(ctx, name, 1, nil)
			require.Error(t, err,
				"R8 AC6: underscore-style metric %q MUST NOT be registered "+
					"(allowed style is dotted `zitadel.dcr.*`)", name)
			assert.Contains(t, err.Error(), "NotFound",
				"R8 AC6 sanity: error MUST be the metrics-layer NotFound zerror")
		})
	}

	// Also pin the constant set: every `Metric*` constant defined in
	// this package MUST start with `zitadel.dcr.` (no `dcr_`
	// underscore-prefixed export sneaking in via a future rename).
	for _, name := range []string{
		MetricRegistrationsTotal,
		MetricRequestDurationSeconds,
		MetricErrorsTotal,
		MetricIATConsumedTotal,
		MetricIATExhaustedTotal,
	} {
		assert.True(t, strings.HasPrefix(name, "zitadel.dcr."),
			"R8 AC6: metric name %q MUST use the dotted `zitadel.dcr.*` style", name)
		assert.NotContains(t, name, "dcr_",
			"R8 AC6: metric name %q MUST NOT contain `dcr_` underscore-style fragment", name)
	}
}

// ───────────────────────────────────────────────────────────────────────
// AC1 + AC2 + AC3 — dispatcher integration
// ───────────────────────────────────────────────────────────────────────

// TestT067_R8_AC1_RegistrationsTotal_DispatcherIntegration pins the
// dispatcher emitting registrations_total by exercising the success
// path (201 anonymous mode). Under the noop meter we cannot inspect
// the value, but a successful pass demonstrates the call site does
// not error and is wired through the success branch.
func TestT067_R8_AC1_RegistrationsTotal_DispatcherIntegration(t *testing.T) {
	register := &stubRegister{clientID: "client-metrics"}
	h := newDispatchHandler(t, register.fn(),
		stubAnonConfig{defaultOrgID: "org-1", defaultProject: "proj-1"})

	body := `{
		"client_name": "metrics probe",
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_basic",
		"application_type": "web"
	}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, body))

	require.Equal(t, http.StatusCreated, w.Code,
		"201 happy-path required for registrations_total{result=success}")
	require.Equal(t, 1, register.called,
		"sanity: register hook fired so the success-branch metric line ran")
}

// TestT067_R8_AC3_ErrorsTotal_DispatcherIntegration pins the error
// path emitting errors_total by exercising a 400 invalid_client_metadata
// outcome (malformed JSON).
func TestT067_R8_AC3_ErrorsTotal_DispatcherIntegration(t *testing.T) {
	register := &stubRegister{clientID: "x"}
	h := newDispatchHandler(t, register.fn(),
		stubAnonConfig{defaultOrgID: "o", defaultProject: "p"})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, newJSONPostReq(t, `{not json`))

	require.Equal(t, http.StatusBadRequest, w.Code,
		"400 path required to drive errors_total{code=invalid_client_metadata}")
	assert.Contains(t, w.Body.String(), `"error":"invalid_client_metadata"`)
	assert.Equal(t, 0, register.called)
}

// TestT067_R8_AC4_IATConsumedTotal_DispatcherIntegration pins the
// happy IAT path emits iat.consumed_total by reusing the same end-
// to-end IAT-mode flow as the T-066 span integration test.
func TestT067_R8_AC4_IATConsumedTotal_DispatcherIntegration(t *testing.T) {
	hasher := mustBuildHasher(t)
	dummy, err := BuildAntiEnumDummyHash(hasher)
	require.NoError(t, err)
	encodedHash, err := hasher.Hash("zdiat_id1.random")
	require.NoError(t, err)

	consumeCalls := 0
	deps := RegistrationDeps{
		Queries: stubQueries{row: &QueryIATRow{
			ID: "id1", InstanceID: "test-instance", ResourceOwner: "ro-1",
			ProjectID: "proj-1", TokenHash: encodedHash,
		}},
		Verifier:          bcryptVerifier{Swapper: hasher.(bcryptHasher).Swapper},
		Parser:            stubParser,
		Config:            defaultStubConfig(),
		AnonConfig:        stubAnonConfig{defaultOrgID: "o", defaultProject: "p"},
		SupportedSigAlgs:  []string{"RS256"},
		AntiEnumDummyHash: dummy,
		Register:          (&stubRegister{clientID: "client-iat"}).fn(),
		MaxBodyBytes:      64 * 1024,
		ConsumeIAT: func(_ context.Context, _ *RegistrationContext) error {
			consumeCalls++
			return nil
		},
	}
	h := NewHandler(deps)

	body := `{
		"client_name": "IAT metrics probe",
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_basic",
		"application_type": "web"
	}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer zdiat_id1.random")
	req = req.WithContext(ctxWithFeature(t, true))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code,
		"201 IAT happy-path required for iat.consumed_total")
	require.Equal(t, 1, consumeCalls,
		"sanity: ConsumeIAT fired exactly once on the success path")
}

// TestT067_R8_AC5_IATExhaustedTotal_DispatcherIntegration pins the
// exhausted-slot path. Drives a fake ConsumeIAT that returns the
// kit-described exhausted ClampError, asserts the dispatcher
// short-circuits with 401, and proves the exhausted detection helper
// recognises the wrapped zerror message.
func TestT067_R8_AC5_IATExhaustedTotal_DispatcherIntegration(t *testing.T) {
	hasher := mustBuildHasher(t)
	dummy, err := BuildAntiEnumDummyHash(hasher)
	require.NoError(t, err)
	encodedHash, err := hasher.Hash("zdiat_id1.random")
	require.NoError(t, err)

	// The wrapped zerror text is what `cmd/start/start.go` actually
	// produces in production via `command.ConsumeInitialAccessToken`
	// (zerrors.ThrowInvalidArgument key `Errors.DCR.IAT.Exhausted`).
	exhaustedErr := errors.New("COMMA-IAT09: Errors.DCR.IAT.Exhausted")
	deps := RegistrationDeps{
		Queries: stubQueries{row: &QueryIATRow{
			ID: "id1", InstanceID: "test-instance", ResourceOwner: "ro-1",
			ProjectID: "proj-1", TokenHash: encodedHash,
		}},
		Verifier:          bcryptVerifier{Swapper: hasher.(bcryptHasher).Swapper},
		Parser:            stubParser,
		Config:            defaultStubConfig(),
		AnonConfig:        stubAnonConfig{defaultOrgID: "o", defaultProject: "p"},
		SupportedSigAlgs:  []string{"RS256"},
		AntiEnumDummyHash: dummy,
		Register:          (&stubRegister{clientID: "should-not-be-called"}).fn(),
		MaxBodyBytes:      64 * 1024,
		ConsumeIAT: func(_ context.Context, _ *RegistrationContext) error {
			return &ClampError{
				Status:      http.StatusUnauthorized,
				Code:        ErrCodeInvalidToken,
				Description: MissingOrInvalidAccessTokenDescription,
				Wrapped:     exhaustedErr,
			}
		},
	}
	h := NewHandler(deps)

	body := `{
		"client_name": "exhausted probe",
		"redirect_uris": ["https://example.com/cb"],
		"grant_types": ["authorization_code"],
		"response_types": ["code"],
		"token_endpoint_auth_method": "client_secret_basic",
		"application_type": "web"
	}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer zdiat_id1.random")
	req = req.WithContext(ctxWithFeature(t, true))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code,
		"exhausted IAT MUST collapse to 401 invalid_token at the HTTP layer (anti-enum)")
	assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
}

// TestT067_R8_AC5_IsExhaustedConsumeError_Detection pins the helper
// behavior in isolation — exhausted-key match returns true, every
// other key (Revoked / Expired / generic 401 / nil) returns false.
func TestT067_R8_AC5_IsExhaustedConsumeError_Detection(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil → false", nil, false},
		{"plain non-IAT err → false", errors.New("eventstore push failed"), false},
		{"revoked → false", errors.New("COMMA-IAT07: Errors.DCR.IAT.Revoked"), false},
		{"expired → false", errors.New("COMMA-IAT08: Errors.DCR.IAT.Expired"), false},
		{"exhausted (raw) → true", errors.New("COMMA-IAT09: Errors.DCR.IAT.Exhausted"), true},
		{"exhausted (3rd-attempt) → true", errors.New("COMMA-IAT10: Errors.DCR.IAT.Exhausted"), true},
		{"exhausted wrapped in ClampError → true", &ClampError{
			Code: ErrCodeInvalidToken, Description: MissingOrInvalidAccessTokenDescription,
			Wrapped: errors.New("COMMA-IAT09: Errors.DCR.IAT.Exhausted"),
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, isExhaustedConsumeError(c.err))
		})
	}
}

// TestT067_R8_AC1_ResultLabelMatrix pins the resultFromStatus helper —
// the registrations_total `result` label MUST classify outcomes as
// success / client_error / server_error correctly.
func TestT067_R8_AC1_ResultLabelMatrix(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{0, MetricResultSuccess}, // no WriteHeader → 200 default
		{200, MetricResultSuccess},
		{201, MetricResultSuccess},
		{204, MetricResultSuccess},
		{400, MetricResultClientError},
		{401, MetricResultClientError},
		{403, MetricResultClientError},
		{404, MetricResultClientError},
		{413, MetricResultClientError},
		{415, MetricResultClientError},
		{429, MetricResultClientError},
		{500, MetricResultServerError},
		{502, MetricResultServerError},
		{503, MetricResultServerError},
	}
	for _, c := range cases {
		t.Run(http.StatusText(c.status), func(t *testing.T) {
			assert.Equal(t, c.want, resultFromStatus(c.status))
		})
	}
}

// TestT067_R8_AC1_AuthMethodLabelValues pins the metric-layer
// auth_method constants against the audit-event RegMethod* constants.
// They MUST stay in lock-step so a future relabel of the audit
// dimension doesn't silently re-label the metric.
func TestT067_R8_AC1_AuthMethodLabelValues(t *testing.T) {
	assert.Equal(t, RegMethodAnonymous, MetricAuthMethodAnonymous,
		"metric label value for anonymous mode MUST equal the audit RegMethodAnonymous const")
	assert.Equal(t, RegMethodIAT, MetricAuthMethodIAT,
		"metric label value for IAT mode MUST equal the audit RegMethodIAT const")
}

// TestT067_R8_AC2_RequestDurationDoesNotPanic_ZeroDuration pins that
// recordRequestDuration tolerates a zero or near-zero elapsed time.
// Histograms with a zero observation are valid Prometheus signals
// and MUST NOT panic on the noop meter.
func TestT067_R8_AC2_RequestDurationDoesNotPanic_ZeroDuration(t *testing.T) {
	require.NotPanics(t, func() {
		recordRequestDuration(context.Background(), 0)
		recordRequestDuration(context.Background(), 1*time.Nanosecond)
		recordRequestDuration(context.Background(), 750*time.Millisecond)
	})
}
