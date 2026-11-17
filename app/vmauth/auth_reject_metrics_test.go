package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/VictoriaMetrics/metrics"
)

// getAuthRejectCounterValue returns the current value of vmauth_auth_rejected_requests_total
// for the given label combination.
func getAuthRejectCounterValue(t *testing.T, labels authRejectLabels) uint64 {
	t.Helper()
	return authRejectMetrics.getOrCreate(labels).Get()
}

// withAuthRejectMetrics enables the auth rejection metrics with the given flag values
// and restores the previous values when the test finishes.
func withAuthRejectMetrics(t testing.TB, enabled, tenantLabel, backendLabel bool, environment string) {
	t.Helper()

	prevEnabled := *authRejectMetricsEnabled
	prevTenant := *authRejectMetricsTenantLabel
	prevBackend := *authRejectMetricsBackendLabel
	prevEnv := *authRejectMetricsEnvironment

	*authRejectMetricsEnabled = enabled
	*authRejectMetricsTenantLabel = tenantLabel
	*authRejectMetricsBackendLabel = backendLabel
	*authRejectMetricsEnvironment = environment

	authRejectMetrics.reset()

	t.Cleanup(func() {
		*authRejectMetricsEnabled = prevEnabled
		*authRejectMetricsTenantLabel = prevTenant
		*authRejectMetricsBackendLabel = prevBackend
		*authRejectMetricsEnvironment = prevEnv
		authRejectMetrics.reset()
	})
}

func newNoopBackend(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func newRejectTestRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.RequestURI = req.URL.RequestURI()
	return req
}

func countExposedAuthRejectSeries(t *testing.T) int {
	t.Helper()
	var sb strings.Builder
	metrics.WritePrometheus(&sb, false)
	count := 0
	for _, line := range strings.Split(sb.String(), "\n") {
		if strings.HasPrefix(line, authRejectMetricName+"{") {
			count++
		}
	}
	return count
}

func TestAuthRejectMetrics_CountsByCredentialOutcome(t *testing.T) {
	withAuthRejectMetrics(t, true, true, true, "test")

	ts := newNoopBackend(t)
	cfgStr := "users:\n" +
		"- username: \"user-a\"\n" +
		"  password: \"correct-pass\"\n" +
		"  url_prefix: \"" + ts.URL + "/backend\"\n"
	defer setAuthConfig(t, cfgStr)()

	missingLabels := authRejectLabels{
		reason:  authRejectReasonMissingCredentials,
		backend: "unknown",
		tenant:  "0",
	}
	invalidLabels := authRejectLabels{
		reason:  authRejectReasonInvalidCredentials,
		backend: "unknown",
		tenant:  "0",
	}

	missingBefore := getAuthRejectCounterValue(t, missingLabels)
	invalidBefore := getAuthRejectCounterValue(t, invalidLabels)

	// 1. Request without credentials must be counted as missing_credentials.
	reqMissing := newRejectTestRequest(http.MethodGet, "http://example.com/select/0/prometheus/api/v1/query")
	if !requestHandler(&fakeResponseWriter{}, reqMissing) {
		t.Fatalf("requestHandler returned false for request without credentials")
	}
	if got := getAuthRejectCounterValue(t, missingLabels); got != missingBefore+1 {
		t.Fatalf("missing_credentials counter: got %d; want %d", got, missingBefore+1)
	}

	// 2. Request with wrong credentials must be counted as invalid_credentials.
	reqInvalid := newRejectTestRequest(http.MethodGet, "http://example.com/select/0/prometheus/api/v1/query")
	reqInvalid.SetBasicAuth("user-a", "wrong-pass")
	if !requestHandler(&fakeResponseWriter{}, reqInvalid) {
		t.Fatalf("requestHandler returned false for request with invalid credentials")
	}
	if got := getAuthRejectCounterValue(t, invalidLabels); got != invalidBefore+1 {
		t.Fatalf("invalid_credentials counter: got %d; want %d", got, invalidBefore+1)
	}
	if got := getAuthRejectCounterValue(t, missingLabels); got != missingBefore+1 {
		t.Fatalf("missing_credentials counter changed unexpectedly: got %d; want %d", got, missingBefore+1)
	}

	// 3. Request with correct credentials must not move either rejection counter.
	reqValid := newRejectTestRequest(http.MethodGet, "http://example.com/select/0/prometheus/api/v1/query")
	reqValid.SetBasicAuth("user-a", "correct-pass")
	if !requestHandler(&fakeResponseWriter{}, reqValid) {
		t.Fatalf("requestHandler returned false for request with valid credentials")
	}
	if got := getAuthRejectCounterValue(t, missingLabels); got != missingBefore+1 {
		t.Fatalf("missing_credentials counter changed after a valid request: got %d; want %d", got, missingBefore+1)
	}
	if got := getAuthRejectCounterValue(t, invalidLabels); got != invalidBefore+1 {
		t.Fatalf("invalid_credentials counter changed after a valid request: got %d; want %d", got, invalidBefore+1)
	}

	// Every exposed series of the new metric must carry the env label.
	var sb strings.Builder
	metrics.WritePrometheus(&sb, false)
	for _, line := range strings.Split(sb.String(), "\n") {
		if !strings.HasPrefix(line, authRejectMetricName+"{") {
			continue
		}
		if !strings.Contains(line, `env="test"`) {
			t.Fatalf("exposed metric line is missing the env label: %s", line)
		}
	}
}

func TestAuthRejectMetrics_DisabledByDefault(t *testing.T) {
	withAuthRejectMetrics(t, false, true, true, "")

	ts := newNoopBackend(t)
	cfgStr := "users:\n" +
		"- username: \"user-a\"\n" +
		"  password: \"correct-pass\"\n" +
		"  url_prefix: \"" + ts.URL + "/backend\"\n"
	defer setAuthConfig(t, cfgStr)()

	req := newRejectTestRequest(http.MethodGet, "http://example.com/select/0/prometheus/api/v1/query")
	if !requestHandler(&fakeResponseWriter{}, req) {
		t.Fatalf("requestHandler returned false")
	}

	if count := countExposedAuthRejectSeries(t); count != 0 {
		t.Fatalf("metric %s must not be exposed while the feature flag is off; got %d series", authRejectMetricName, count)
	}
}

func TestAuthRejectMetrics_CardinalityDegradation(t *testing.T) {
	withAuthRejectMetrics(t, true, false, false, "")

	ts := newNoopBackend(t)
	cfgStr := "users:\n" +
		"- username: \"user-a\"\n" +
		"  password: \"correct-pass\"\n" +
		"  url_prefix: \"" + ts.URL + "/backend\"\n"
	defer setAuthConfig(t, cfgStr)()

	paths := []string{
		"/select/0/prometheus/api/v1/query",
		"/select/42/prometheus/api/v1/query",
		"/insert/123/5/prometheus/api/v1/write",
		"/totally/different/path",
	}
	for _, path := range paths {
		req := newRejectTestRequest(http.MethodGet, "http://example.com"+path)
		if !requestHandler(&fakeResponseWriter{}, req) {
			t.Fatalf("requestHandler returned false for %q", path)
		}
	}

	// With both split labels disabled, all the rejections collapse into a single series.
	labels := authRejectLabels{
		reason:  authRejectReasonMissingCredentials,
		backend: "disabled",
		tenant:  "disabled",
	}
	if got := getAuthRejectCounterValue(t, labels); got != uint64(len(paths)) {
		t.Fatalf("degraded counter: got %d; want %d", got, len(paths))
	}
	if count := countExposedAuthRejectSeries(t); count != 1 {
		t.Fatalf("expected a single degraded series; got %d", count)
	}
}

func TestAuthRejectMetrics_ConcurrentTotalMatchesRequests(t *testing.T) {
	withAuthRejectMetrics(t, true, true, true, "")

	ts := newNoopBackend(t)
	cfgStr := "users:\n" +
		"- username: \"user-a\"\n" +
		"  password: \"correct-pass\"\n" +
		"  url_prefix: \"" + ts.URL + "/backend\"\n"
	defer setAuthConfig(t, cfgStr)()

	const goroutines = 32
	const requestsPerGoroutine = 200

	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range requestsPerGoroutine {
				req := newRejectTestRequest(http.MethodGet, "http://example.com/select/7/prometheus/api/v1/query")
				if !requestHandler(&fakeResponseWriter{}, req) {
					t.Errorf("requestHandler returned false")
					return
				}
			}
		}()
	}
	wg.Wait()

	labels := authRejectLabels{
		reason:  authRejectReasonMissingCredentials,
		backend: "unknown",
		tenant:  "7",
	}
	want := uint64(goroutines * requestsPerGoroutine)
	if got := getAuthRejectCounterValue(t, labels); got != want {
		t.Fatalf("counter total: got %d; want %d", got, want)
	}
}

func TestAuthRejectMetrics_UnknownTenantAndBackend(t *testing.T) {
	withAuthRejectMetrics(t, true, true, true, "")

	ts := newNoopBackend(t)
	cfgStr := "users:\n" +
		"- username: \"user-a\"\n" +
		"  password: \"correct-pass\"\n" +
		"  url_prefix: \"" + ts.URL + "/backend\"\n"
	defer setAuthConfig(t, cfgStr)()

	req := newRejectTestRequest(http.MethodGet, "http://example.com/no/tenant/path")
	if !requestHandler(&fakeResponseWriter{}, req) {
		t.Fatalf("requestHandler returned false")
	}

	labels := authRejectLabels{
		reason:  authRejectReasonMissingCredentials,
		backend: "unknown",
		tenant:  "unknown",
	}
	if got := getAuthRejectCounterValue(t, labels); got != 1 {
		t.Fatalf("unknown-label counter: got %d; want 1", got)
	}
}

func TestAuthRejectMetrics_BackendLabelFromUnauthorizedRoute(t *testing.T) {
	withAuthRejectMetrics(t, true, true, true, "")

	ts := newNoopBackend(t)
	cfgStr := "users:\n" +
		"- username: \"user-a\"\n" +
		"  password: \"correct-pass\"\n" +
		"  url_prefix: \"" + ts.URL + "/backend\"\n" +
		"unauthorized_user:\n" +
		"  url_map:\n" +
		"  - src_paths:\n" +
		"    - /select/0/prometheus/.*\n" +
		"    deny_paths:\n" +
		"    - /select/0/prometheus/internal.*\n" +
		"    url_prefix: \"" + ts.URL + "/routed\"\n"
	defer setAuthConfig(t, cfgStr)()

	// A request without credentials, which hits a deny_paths rule of unauthorized_user,
	// is rejected with 401 while the matching url_map still identifies the backend.
	reqDenied := newRejectTestRequest(http.MethodGet, "http://example.com/select/0/prometheus/internal/metrics")
	if !requestHandler(&fakeResponseWriter{}, reqDenied) {
		t.Fatalf("requestHandler returned false for denied path")
	}

	labels := authRejectLabels{
		reason:  authRejectReasonMissingCredentials,
		backend: ts.URL,
		tenant:  "0",
	}
	if got := getAuthRejectCounterValue(t, labels); got != 1 {
		t.Fatalf("backend-labeled counter: got %d; want 1", got)
	}
}

func TestBuildAuthRejectMetricName(t *testing.T) {
	withAuthRejectMetrics(t, true, true, true, "prod")

	got := buildAuthRejectMetricName(authRejectLabels{
		reason:  authRejectReasonMissingCredentials,
		backend: "http://host:8428",
		tenant:  "0:0",
	})
	want := `vmauth_auth_rejected_requests_total{reason="missing_credentials",backend="http://host:8428",tenant="0:0",env="prod"}`
	if got != want {
		t.Fatalf("metric name mismatch\ngot:  %s\nwant: %s", got, want)
	}
}
