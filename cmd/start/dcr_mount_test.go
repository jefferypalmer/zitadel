package start

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDCRMount_F217_HasInterceptorStack pins the
// cavekit-register-handler.md R1 amendment 2026-04-27 / F-217 — the
// DCR handler AND the AS metadata handler MUST be wrapped with the
// `instanceInterceptor` + `limitingAccessInterceptor` chain before
// being mounted via `apis.RegisterHandlerOnPrefix`.
//
// Pre-fix the handlers were mounted bare:
//
//	apis.RegisterHandlerOnPrefix(dcr.HandlerPrefix, dcr.NewHandler(dcrDeps))
//	apis.RegisterHandlerOnPrefix(as_metadata.HandlerPath, as_metadata.NewHandler(oidcServer.AsMetadata))
//
// Without the instance interceptor, `authz.GetInstance(ctx)` returns
// the empty-instance sentinel; without the rate limiter, an
// unauthenticated, write-amplifying endpoint has no throttle.
//
// This test inspects start.go source rather than booting the runtime:
// the kit AC explicitly accepts source-string inspection.
func TestDCRMount_F217_HasInterceptorStack(t *testing.T) {
	src, err := os.ReadFile("start.go")
	require.NoError(t, err)
	body := string(src)

	// Both wrapped-mount lines MUST exist and MUST contain the
	// interceptor stack + handler factory. The outermost wrap layer
	// differs between mounts:
	//   dcrWrapped — adds middleware.RecoverHandler(dcrWriteRecoverError)
	//                outside instanceInterceptor.Handler per
	//                cavekit-manage-handler.md R9 (T-025) so panics
	//                produce the RFC 7591 JSON envelope instead of the
	//                text/plain FallbackRecoverHandler default.
	//   asMetaWrapped — instanceInterceptor.Handler at the outermost.
	assertWrapped := func(t *testing.T, label, varName, factoryFragment string) {
		t.Helper()
		idx := strings.Index(body, varName+" :=")
		require.NotEqual(t, -1, idx,
			"%s: expected `%s := …` mount-wrap line", label, varName)
		segment := body[idx:]
		end := strings.Index(segment, "\n\t\tapis.RegisterHandlerOnPrefix")
		require.NotEqual(t, -1, end, "%s: missing apis.RegisterHandlerOnPrefix call after wrap", label)
		wrap := segment[:end]
		assert.Contains(t, wrap, "instanceInterceptor.Handler",
			"%s: instanceInterceptor MUST be in the wrap chain — F-217 / R1 AC", label)
		assert.Contains(t, wrap, "limitingAccessInterceptor.Handle",
			"%s: limitingAccessInterceptor MUST be in the wrap chain — F-217 / R1 AC", label)
		assert.Contains(t, wrap, factoryFragment,
			"%s: handler factory %q MUST be the inner-most wrapped value", label, factoryFragment)
	}

	assertWrapped(t, "DCR mount", "dcrWrapped", "dcr.NewHandler(dcrDeps)")
	assertWrapped(t, "AS metadata mount", "asMetaWrapped", "as_metadata.NewHandler(oidcServer.AsMetadata)")

	// Defensive: no bare mount of dcr.NewHandler / as_metadata.NewHandler
	// directly into RegisterHandlerOnPrefix without going through the
	// wrap variable.
	assert.NotContains(t, body,
		"apis.RegisterHandlerOnPrefix(dcr.HandlerPrefix, dcr.NewHandler(",
		"F-217: mounting dcr.NewHandler bare is FORBIDDEN — must be wrapped via dcrWrapped")
	assert.NotContains(t, body,
		"apis.RegisterHandlerOnPrefix(as_metadata.HandlerPath, as_metadata.NewHandler(",
		"F-217: mounting as_metadata.NewHandler bare is FORBIDDEN — must be wrapped via asMetaWrapped")
}
