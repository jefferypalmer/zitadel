package dcr

import (
	"context"
	"strings"
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
// Idempotent; safe to call from init() or from a startup wiring hook.
// Returns the first registration error if any, but production callers
// SHOULD NOT abort on metric-registration failure — observability
// gaps are preferable to a deployment that refuses to serve traffic.
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

// init registers the DCR metrics on package load. The global meter
// is the noop meter until the instrumentation package's startup
// hook installs an exporter — in that pre-startup window registration
// still succeeds and the noop counters silently swallow Add calls,
// so this init() is safe in test binaries too.
func init() {
	_ = RegisterMetrics()
}

// recordRegistration increments [MetricRegistrationsTotal] with the
// three labels mandated by R8 AC1. Best-effort: any error from the
// metrics layer is swallowed so observability never fails a request.
func recordRegistration(ctx context.Context, result, authMethod, applicationType string) {
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
	_ = metrics.AddHistogramMeasurement(ctx, MetricRequestDurationSeconds, elapsed.Seconds(), nil)
}

// recordError increments [MetricErrorsTotal] with the RFC 7591 error
// code label per R8 AC3. Empty `code` is replaced with `"server_error"`
// so the label cardinality stays bounded by the documented RFC 7591
// + DCR-internal code set.
func recordError(ctx context.Context, code string) {
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
	_ = metrics.AddCount(ctx, MetricIATConsumedTotal, 1, nil)
}

// recordIATExhausted increments [MetricIATExhaustedTotal] when an IAT
// consume returns the exhausted condition (R8 AC5).
func recordIATExhausted(ctx context.Context) {
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
