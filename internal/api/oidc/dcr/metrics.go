package dcr

import (
	"context"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/zitadel/zitadel/backend/v3/instrumentation/metrics"
)

// errorMessageContains is a cheap substring check that walks the
// error chain via [error.Error] string concatenation. We deliberately
// avoid `errors.As` against `*zerrors.ZitadelError` here because the
// metrics layer must not depend on the zerrors package shape — the
// only contract we rely on is that the i18n key surfaces in the
// wrapped error's textual form.
func errorMessageContains(err error, needle string) bool {
	return strings.Contains(err.Error(), needle)
}

// T-067 — OpenTelemetry metrics under the Zitadel-conventional dotted
// `zitadel.` prefix (cavekit-console-ui-docs-and-observability.md R8).
//
// All five required counters / histogram are emitted via the global
// meter from `backend/v3/instrumentation/metrics`. Names use the
// dotted style consistent with the existing
// `zitadel.active_session_counter` etc. — R8 AC6 explicitly forbids
// the legacy `dcr_*_total` underscore style.
//
// Labels intentionally avoid high-cardinality identifiers: no
// `client_id`, no `iat_id`, no `instance_id`. Only enumerable
// dimensions ship as labels (result class, auth method,
// application_type, RFC 7591 error code).

const (
	// MetricRegistrationsTotal counts every POST /oidc/v1/register
	// outcome. Labels: result (success | client_error | server_error),
	// auth_method (anonymous | iat), application_type (web | native | spa).
	MetricRegistrationsTotal            = "zitadel.dcr.registrations_total"
	MetricRegistrationsTotalDescription = "Total DCR client registration attempts. Labels: result, auth_method, application_type."

	// MetricRequestDurationSeconds is the histogram covering every
	// DCR HTTP handler — POST + GET + PUT + DELETE.
	MetricRequestDurationSeconds            = "zitadel.dcr.request_duration_seconds"
	MetricRequestDurationSecondsDescription = "DCR HTTP request duration in seconds."

	// MetricErrorsTotal increments on every RFC 7591 error envelope
	// emitted by the dispatcher. Label: code (the RFC 7591 error
	// code value — invalid_client_metadata, invalid_token, etc.).
	MetricErrorsTotal            = "zitadel.dcr.errors_total"
	MetricErrorsTotalDescription = "Total DCR errors. Label: code (RFC 7591 error code)."

	// MetricIATConsumedTotal increments on every successful IAT slot
	// reservation. No labels — keep cardinality flat.
	MetricIATConsumedTotal            = "zitadel.dcr.iat.consumed_total"
	MetricIATConsumedTotalDescription = "Total successful IAT slot consumes."

	// MetricIATExhaustedTotal increments when an IAT consume fails
	// because every slot is already consumed (cavekit-iat.md R2 AC5
	// "exhausted" condition).
	MetricIATExhaustedTotal            = "zitadel.dcr.iat.exhausted_total"
	MetricIATExhaustedTotalDescription = "Total IAT exhausted-slot rejections."
)

// Label keys.
const (
	MetricLabelResult          = "result"
	MetricLabelAuthMethod      = "auth_method"
	MetricLabelApplicationType = "application_type"
	MetricLabelCode            = "code"
)

// Result-label values for [MetricRegistrationsTotal].
const (
	MetricResultSuccess     = "success"
	MetricResultClientError = "client_error"
	MetricResultServerError = "server_error"
)

// Auth-method label values mirror [RegMethodAnonymous] / [RegMethodIAT]
// at the metric layer — duplicated as constants so a future relabel
// of the audit field doesn't silently change the metric label.
const (
	MetricAuthMethodAnonymous = RegMethodAnonymous
	MetricAuthMethodIAT       = RegMethodIAT
)

// requestDurationBuckets follows the Prometheus default RED-style
// HTTP histogram so dashboards can use stock SLO panels without
// re-tuning.
var requestDurationBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// RegisterMetrics registers all five DCR metrics on the global meter.
// Idempotent — repeated calls are no-ops at the underlying meter
// wrapper because [metrics.RegisterCounter] / [metrics.RegisterHistogram]
// early-return when the name is already known.
//
// Production callers SHOULD NOT abort on metric-registration failure —
// observability gaps are preferable to a deployment that refuses to
// serve traffic.
//
// MUST NOT be called from package init(). The global meter is captured
// from [otel.GetMeterProvider] inside a [sync.OnceValue] guard; if any
// counter is created before [instrumentation.Setup] installs the real
// provider, the cached counter may permanently dispatch to the noop
// meter (depending on otel-go's instrument-delegation guarantees,
// which we deliberately do not depend on).
//
// Each `record*` helper below calls RegisterMetrics opportunistically
// on its first invocation per process, mirroring the codebase's
// established lazy-register-on-first-use pattern from
// `internal/api/grpc/server/middleware/metrics_interceptor.go`. The
// guard is amortised across the lifetime of the process by
// [registerOnce]; the underlying RegisterCounter / RegisterHistogram
// calls are themselves idempotent so repeated calls are harmless even
// without the guard.
func RegisterMetrics() error {
	if err := metrics.RegisterCounter(MetricRegistrationsTotal, MetricRegistrationsTotalDescription); err != nil {
		return err
	}
	if err := metrics.RegisterHistogram(
		MetricRequestDurationSeconds,
		MetricRequestDurationSecondsDescription,
		"s",
		requestDurationBuckets,
	); err != nil {
		return err
	}
	if err := metrics.RegisterCounter(MetricErrorsTotal, MetricErrorsTotalDescription); err != nil {
		return err
	}
	if err := metrics.RegisterCounter(MetricIATConsumedTotal, MetricIATConsumedTotalDescription); err != nil {
		return err
	}
	if err := metrics.RegisterCounter(MetricIATExhaustedTotal, MetricIATExhaustedTotalDescription); err != nil {
		return err
	}
	return nil
}

// registerOnce amortises [RegisterMetrics] across the process lifetime
// without calling it from init(). The first record-call triggers
// registration; later calls are skipped via [sync.Once].
//
// Defence-in-depth: this is a precondition guard, not a correctness
// guarantee. Even if RegisterMetrics fails (returns a non-nil error),
// the record-helpers still call AddCount / AddHistogramMeasurement —
// those calls go through the metrics package's NotFound error branch
// which we swallow. The metric simply never emits in that case.
var registerOnce sync.Once

func ensureRegistered() {
	registerOnce.Do(func() { _ = RegisterMetrics() })
}

// recordRegistration increments [MetricRegistrationsTotal] with the
// three labels mandated by R8 AC1. Best-effort: any error from the
// metrics layer is swallowed so observability never fails a request.
func recordRegistration(ctx context.Context, result, authMethod, applicationType string) {
	ensureRegistered()
	_ = metrics.AddCount(ctx, MetricRegistrationsTotal, 1, map[string]attribute.Value{
		MetricLabelResult:          attribute.StringValue(result),
		MetricLabelAuthMethod:      attribute.StringValue(authMethod),
		MetricLabelApplicationType: attribute.StringValue(applicationType),
	})
}

// recordRequestDuration records the elapsed time of a DCR HTTP request
// on [MetricRequestDurationSeconds]. No labels — duration is reported
// as a single global series per R8 AC2.
func recordRequestDuration(ctx context.Context, elapsed time.Duration) {
	ensureRegistered()
	_ = metrics.AddHistogramMeasurement(ctx, MetricRequestDurationSeconds, elapsed.Seconds(), nil)
}

// recordError increments [MetricErrorsTotal] with the RFC 7591 error
// code label per R8 AC3. Empty `code` is replaced with `"server_error"`
// so the label cardinality stays bounded by the documented RFC 7591
// + DCR-internal code set.
func recordError(ctx context.Context, code string) {
	ensureRegistered()
	if code == "" {
		code = ErrCodeServerError
	}
	_ = metrics.AddCount(ctx, MetricErrorsTotal, 1, map[string]attribute.Value{
		MetricLabelCode: attribute.StringValue(code),
	})
}

// recordIATConsumed increments [MetricIATConsumedTotal] on every
// successful IAT slot reservation (R8 AC4).
func recordIATConsumed(ctx context.Context) {
	ensureRegistered()
	_ = metrics.AddCount(ctx, MetricIATConsumedTotal, 1, nil)
}

// recordIATExhausted increments [MetricIATExhaustedTotal] when an IAT
// consume returns the exhausted condition (R8 AC5).
func recordIATExhausted(ctx context.Context) {
	ensureRegistered()
	_ = metrics.AddCount(ctx, MetricIATExhaustedTotal, 1, nil)
}

// iatExhaustedMessage is the i18n key the command layer attaches to
// the wrapped zerror for the exhausted-slot condition (see
// `command.ConsumeInitialAccessToken` / cavekit-iat.md R2 AC5/AC7).
// Match by message string is sufficient because the dispatcher
// collapses every IAT consume failure to invalid_token at the HTTP
// layer (anti-enumeration), but we need the original signal to break
// out the "exhausted" counter from the generic errors_total.
const iatExhaustedMessage = "Errors.DCR.IAT.Exhausted"

// isExhaustedConsumeError reports whether the wrapped zerror inside a
// dispatcher [ClampError] indicates the exhausted-slot condition.
// Returns false for any other error shape — projection-lag failures,
// revocations, expirations, generic 401s — so the exhausted counter
// stays a clean signal for ops dashboards.
func isExhaustedConsumeError(err error) bool {
	if err == nil {
		return false
	}
	return errorMessageContains(err, iatExhaustedMessage)
}
