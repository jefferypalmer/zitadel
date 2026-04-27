package oidc

import (
	"log/slog"
	"context"
	"fmt"
	"strings"

	"github.com/zitadel/zitadel/backend/v3/instrumentation/logging"
)

// Validate runs cavekit-config.md R4 / R5 startup checks for DCR.
//
//   - R4 refuses start when DCR is enabled in anonymous mode with empty
//     DefaultProjectID / DefaultOrgID — returning an error propagates to
//     a non-zero exit from cmd/start/config.go NewConfig, matching the
//     "never serve HTTP 503 from a partially-initialized handler" rule.
//   - R5 emits a WARN log line (non-fatal) when the effective issuer URL
//     has a non-empty path component, naming the .well-known/
//     oauth-authorization-server URL Claude Code will probe against the
//     hostname root.
//
// externalSecure + externalDomain + externalPort together describe the
// configured external URL (matching http_util.BuildHTTP).
func (c DCRConfig) Validate(ctx context.Context, externalSecure bool, externalDomain string, externalPort uint16) error {
	if !c.Enabled {
		return nil
	}

	// cavekit-config.md R1 amendment 2026-04-27 / F-300:
	// ClientSecretExpiresIn MUST be non-negative. A negative duration
	// would advertise a freshly-issued secret as already expired
	// (RFC 7591 §3.2.1 client_secret_expires_at would be in the past).
	if c.ClientSecretExpiresIn < 0 {
		return fmt.Errorf(
			"OIDC.DCR.ClientSecretExpiresIn=%s is invalid: MUST be non-negative. "+
				"0 = no expiry per RFC 7591 §3.2.1; positive durations are accepted. "+
				"See cavekit-config.md R1 / F-300", c.ClientSecretExpiresIn)
	}

	// cavekit-config.md R1 amendment 2026-04-27 / F-204:
	// MaxRequestBodyBytes sentinel semantics. 0 is INVALID — refuse
	// startup rather than silently substitute the package default.
	// To disable the cap entirely, the operator MUST set -1.
	switch {
	case c.MaxRequestBodyBytes == 0:
		return fmt.Errorf(
			"OIDC.DCR.MaxRequestBodyBytes must be > 0 (positive cap) or -1 (no cap). " +
				"0 is forbidden because it silently triggered a 64 KiB default fallback in earlier " +
				"builds, hiding the operator's intent. See cavekit-config.md R1 / F-204")
	case c.MaxRequestBodyBytes < -1:
		return fmt.Errorf(
			"OIDC.DCR.MaxRequestBodyBytes=%d is invalid: only positive integers (enforced cap) "+
				"or -1 (no cap) are accepted. See cavekit-config.md R1 / F-204",
			c.MaxRequestBodyBytes)
	case c.MaxRequestBodyBytes == -1:
		// F-301 startup WARN: -1 disables the per-request cap, but the
		// dcr.AbsoluteMaxBodyBytes ceiling (100 MiB) still applies.
		// Surface the trade-off at boot so an operator who set -1
		// accidentally sees it.
		slog.Warn("OIDC.DCR.MaxRequestBodyBytes=-1: per-request cap disabled. "+
			"Defence-in-depth ceiling dcr.AbsoluteMaxBodyBytes=100 MiB still applies.",
			"field", "OIDC.DCR.MaxRequestBodyBytes",
			"absolute_ceiling_bytes", 100*1024*1024,
			"reference", "cavekit-config.md R1 / F-301")
	}

	if !c.RequireInitialAccessToken {
		var missing []string
		if strings.TrimSpace(c.DefaultProjectID) == "" {
			missing = append(missing, "OIDC.DCR.DefaultProjectID")
		}
		if strings.TrimSpace(c.DefaultOrgID) == "" {
			missing = append(missing, "OIDC.DCR.DefaultOrgID")
		}
		if len(missing) > 0 {
			return fmt.Errorf(
				"DCR is enabled in anonymous mode but required defaults are empty: %s. "+
					"Set OIDC.DCR.RequireInitialAccessToken=true, or populate these keys so "+
					"anonymous /oidc/v1/register requests can be attributed to a project/org",
				strings.Join(missing, ", "),
			)
		}
	}

	// R5: startup WARN when the configured ExternalDomain has a non-empty
	// path component.
	//
	// CAVEAT vs cavekit-config.md R5: Zitadel's ExternalDomain is a
	// hostname, not a URL — the per-request issuer comes from
	// http_util.DomainContext(ctx).Origin() at serving time. A subpath
	// deployment driven by a reverse proxy is therefore not observable
	// from startup config alone, and the kit's "https://example.com/zitadel"
	// example is never a valid ExternalDomain value (BuildHTTP(hostname+path, port)
	// produces malformed output because the :port glues after the path).
	//
	// This check therefore warns only on the one case detectable at startup:
	// an ExternalDomain explicitly misconfigured with a `/`. For proxy-driven
	// subpath deployments the corresponding runtime-level check will land
	// with discovery work (T-029/T-030) where the per-request issuer is
	// available.
	if idx := strings.Index(externalDomain, "/"); idx >= 0 {
		hostOnly := externalDomain[:idx]
		scheme := "https"
		if !externalSecure {
			scheme = "http"
		}
		hostPort := hostOnly
		if externalPort != 0 && !((externalPort == 443 && externalSecure) || (externalPort == 80 && !externalSecure)) {
			hostPort = fmt.Sprintf("%s:%d", hostOnly, externalPort)
		}
		probeURL := fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server", scheme, hostPort)
		logging.Warn(ctx,
			"OIDC.DCR.Enabled=true and ExternalDomain contains a path component. "+
				"RFC 8414 clients (including Claude Code MCP) probe "+
				"`.well-known/oauth-authorization-server` at the hostname ROOT, "+
				"not under a subpath — your deployment will not advertise DCR "+
				"discovery to those clients. See the deployment guide "+
				"(hostname-root requirement) for details.",
			"external_domain", externalDomain,
			"probe_url", probeURL,
		)
	}
	return nil
}
