---
created: "2026-04-27T17:15:00Z"
last_edited: "2026-04-27T17:15:00Z"
---
# Implementation Tracking: console-ui-docs-and-observability

Build site: context/plans/build-site.md

| Task | Status | Notes |
|------|--------|-------|
| T-066 | DONE | OTel spans `oidc.dcr.{register,read,update,delete,iat.consume}` wired at handler entries via `tracing.NewNamedSpan`. No span attributes added (R7 AC6 satisfied structurally — zero attributes can't carry secrets). 6 tests in `dcr_otel_spans_test.go` pin all 6 R7 ACs through in-memory `tracetest.SpanRecorder` registered as global TracerProvider in `init()` (sync.OnceValue cache means the swap MUST land before first NewNamedSpan call). Also updated the F-200 source-string assertion in `dispatcher_test.go` to match `deps.ConsumeIAT(consumeCtx, regCtx)` (span-scoped child context). Files touched: wire.go, manage_get.go, manage_put.go, manage_delete.go, dcr_otel_spans_test.go (new), dispatcher_test.go (assertion update). |
