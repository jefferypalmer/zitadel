---
created: "2026-04-26T00:00:00Z"
last_edited: "2026-04-26T00:00:00Z"
---
# Implementation Tracking: Initial Access Token (IAT) Domain

Build site: context/plans/build-site.md

| Task | Status | Notes |
|------|--------|-------|
| T-011 | DONE | Three IAT events on the `project` aggregate: `project.initial_access_token.added`, `.consumed`, `.revoked`. Files: `internal/repository/project/initial_access_token.go` + mappers registered in `eventstore.go`. Consumed event declares per-slot UniqueConstraint `iat_uses:<id>:<use_index>` when finite (`finite=true` constructor flag); nil when MaxUses=0. `finite` is NOT serialized (reconstructed from projection at consume time by T-017). 9 subtests green incl. wire-type pin, payload, omitempty optional fields, finite-vs-unbounded constraint matrix, distinct-IAT-distinct-slot collision space. |
