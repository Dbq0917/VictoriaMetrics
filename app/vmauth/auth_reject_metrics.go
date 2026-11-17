package main

import (
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/VictoriaMetrics/metrics"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/httpserver"
)

// Reasons exposed via the reason label of vmauth_auth_rejected_requests_total.
const (
	authRejectReasonMissingCredentials = "missing_credentials"
	authRejectReasonInvalidCredentials = "invalid_credentials"
)

// authRejectMetricName is the metric exposed for authentication rejections.
//
// It is intentionally separate from the existing vmauth_http_request_errors_total metric,
// so the semantics and names of existing metrics remain unchanged.
const authRejectMetricName = "vmauth_auth_rejected_requests_total"

// authRejectLabels describes a single label combination of vmauth_auth_rejected_requests_total.
type authRejectLabels struct {
	reason  string
	backend string
	tenant  string
}

// authRejectMetricsRegistry keeps one counter per label combination.
//
// The hot path performs an atomic increment on a counter cached in a sync.Map,
// so metric accounting does not add lock contention under high concurrency.
// New label combinations are created only on the slow path.
type authRejectMetricsRegistry struct {
	m sync.Map
}

// authRejectMetricEntry binds a counter to the exact metric name used to register it,
// so it can be unregistered later even if the metric-related flags change in the meantime.
type authRejectMetricEntry struct {
	name    string
	counter *metrics.Counter
}

func (r *authRejectMetricsRegistry) inc(labels authRejectLabels) {
	if entry, ok := r.m.Load(labels); ok {
		entry.(*authRejectMetricEntry).counter.Inc()
		return
	}
	r.getOrCreate(labels).Inc()
}

func (r *authRejectMetricsRegistry) getOrCreate(labels authRejectLabels) *metrics.Counter {
	if entry, ok := r.m.Load(labels); ok {
		return entry.(*authRejectMetricEntry).counter
	}
	name := buildAuthRejectMetricName(labels)
	entry := &authRejectMetricEntry{
		name:    name,
		counter: metrics.GetOrCreateCounter(name),
	}
	actual, _ := r.m.LoadOrStore(labels, entry)
	return actual.(*authRejectMetricEntry).counter
}

// reset removes all the cached counters. It is used only in tests for isolation.
func (r *authRejectMetricsRegistry) reset() {
	r.m.Range(func(key, _ any) bool {
		entry, _ := r.m.Load(key)
		r.m.Delete(key)
		metrics.UnregisterMetric(entry.(*authRejectMetricEntry).name)
		return true
	})
}

// authRejectMetrics is the process-global registry for authentication rejections.
var authRejectMetrics = &authRejectMetricsRegistry{}

// incAuthRejectCounter records an authentication rejection.
//
// It is a no-op when the -authRejectMetrics.enable flag is off, so disabling the feature
// restores the original behavior without restarting the auth flow.
func incAuthRejectCounter(reason string, r *http.Request, ac *AuthConfig) {
	if !*authRejectMetricsEnabled {
		return
	}
	authRejectMetrics.inc(authRejectLabels{
		reason:  reason,
		backend: getAuthRejectBackendLabel(r, ac),
		tenant:  getAuthRejectTenantLabel(r),
	})
}

func buildAuthRejectMetricName(labels authRejectLabels) string {
	labelParts := make([]string, 0, 5)
	labelParts = append(labelParts,
		`reason="`+labels.reason+`"`,
		`backend="`+escapeAuthRejectLabelValue(labels.backend)+`"`,
		`tenant="`+escapeAuthRejectLabelValue(labels.tenant)+`"`,
	)
	if *authRejectMetricsEnvironment != "" {
		labelParts = append(labelParts, `env="`+escapeAuthRejectLabelValue(*authRejectMetricsEnvironment)+`"`)
	}
	return authRejectMetricName + "{" + strings.Join(labelParts, ",") + "}"
}

// escapeAuthRejectLabelValue escapes characters that are not allowed inside
// Prometheus label values and caps the resulting length to bound the series size.
func escapeAuthRejectLabelValue(s string) string {
	maxLen := *authRejectMetricsMaxLabelValueLen
	if maxLen > 0 && len(s) > maxLen {
		runes := []rune(s)
		if len(runes) > maxLen {
			s = string(runes[:maxLen])
		}
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, ch := range s {
		switch ch {
		case '\\', '"', '\n':
			b.WriteByte('\\')
		}
		b.WriteRune(ch)
	}
	return b.String()
}

// getAuthRejectBackendLabel returns the backend label value for the request.
//
// The backend is derived from the route that would serve the request:
// the request host is matched against url_map entries of the unauthorized user.
// If no route matches, the label is set to "unknown".
func getAuthRejectBackendLabel(r *http.Request, ac *AuthConfig) string {
	if !*authRejectMetricsBackendLabel {
		return "disabled"
	}
	if ac == nil || ac.UnauthorizedUser == nil {
		return "unknown"
	}
	u := normalizeURL(r.URL)
	up, _, denied := ac.UnauthorizedUser.getURLPrefixAndHeaders(u, r.Host, r.Header)
	if denied {
		if up = getDeniedURLPrefix(ac.UnauthorizedUser, u, r.Host, r.Header); up == nil {
			return "unknown"
		}
	}
	if up == nil {
		return "unknown"
	}
	return backendLabelFromURLPrefix(up)
}

// getDeniedURLPrefix returns the URLPrefix of the url_map entry, whose deny_paths rule matches the request.
// getURLPrefixAndHeaders returns a nil URLPrefix for denied requests, so the matching entry is located here
// in order to attribute the rejection to the configured backend.
func getDeniedURLPrefix(ui *UserInfo, u *url.URL, host string, h http.Header) *URLPrefix {
	for i := range ui.URLMaps {
		e := &ui.URLMaps[i]
		if !matchAnyRegex(e.SrcHosts, host) {
			continue
		}
		if !matchAnyRegex(e.SrcPaths, u.Path) {
			continue
		}
		if !matchAnyQueryArg(e.SrcQueryArgs, u.Query()) {
			continue
		}
		if !matchAnyHeader(e.SrcHeaders, h) {
			continue
		}
		if matchAnyDenyPath(e.DenyPaths, u.Path) {
			return e.URLPrefix
		}
	}
	return nil
}

// backendLabelFromURLPrefix returns a stable, cardinality-bounded identifier for the backend.
// Only the scheme and host:port of the first configured backend are used, so dynamic IPs
// discovered via -discoverBackendIPs do not inflate the number of series.
func backendLabelFromURLPrefix(up *URLPrefix) string {
	bus := up.busOriginal
	if len(bus) == 0 || bus[0] == nil {
		return "unknown"
	}
	bu := bus[0]
	host := bu.Host
	if host == "" {
		host = bu.Hostname()
	}
	if host == "" {
		return "unknown"
	}
	if bu.Scheme != "" {
		return bu.Scheme + "://" + host
	}
	return host
}

// getAuthRejectTenantLabel extracts the tenant identifier from the request URL.
//
// VictoriaMetrics cluster requests use the /{insert|select|delete}/{tenantID}/{suffix}
// URL format. Requests without a tenant in the path are labeled "unknown".
func getAuthRejectTenantLabel(r *http.Request) string {
	if !*authRejectMetricsTenantLabel {
		return "disabled"
	}
	p, err := httpserver.ParsePath(r.URL.Path)
	if err != nil || p.AuthToken == "" || !isClusterPathPrefix(p.Prefix) {
		return "unknown"
	}
	return p.AuthToken
}

func isClusterPathPrefix(prefix string) bool {
	switch prefix {
	case "insert", "select", "delete":
		return true
	default:
		return false
	}
}
