package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// BenchmarkAuthRejectMetricsInc measures the hot-path cost of recording a rejection
// for an already-registered label combination.
func BenchmarkAuthRejectMetricsInc(b *testing.B) {
	withAuthRejectMetrics(b, true, true, true, "bench")

	labels := authRejectLabels{
		reason:  authRejectReasonMissingCredentials,
		backend: "http://backend:8428",
		tenant:  "0",
	}
	// Pre-create the counter so the benchmark exercises only the hot-path map lookup + atomic add.
	authRejectMetrics.getOrCreate(labels)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			authRejectMetrics.inc(labels)
		}
	})
}

// BenchmarkAuthRejectMetricsDisabled measures the cost when the feature is turned off,
// which must be a single atomic flag read.
func BenchmarkAuthRejectMetricsDisabled(b *testing.B) {
	withAuthRejectMetrics(b, false, true, true, "")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	cfgStr := "users:\n" +
		"- username: \"user-a\"\n" +
		"  password: \"correct-pass\"\n" +
		"  url_prefix: \"" + ts.URL + "/backend\"\n"
	defer setAuthConfig(b, cfgStr)()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/select/0/prometheus/api/v1/query", nil)
	req.RequestURI = req.URL.RequestURI()

	b.ReportAllocs()
	b.ResetTimer()
	var sink atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		w := &fakeResponseWriter{}
		for pb.Next() {
			w.reset()
			requestHandler(w, req)
			sink.Add(1)
		}
	})
}
