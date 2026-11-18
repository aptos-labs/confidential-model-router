package manager

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The scrape sends METRICS_API_KEY every poll. It must reach only the backend
// whose TLS key was attested, as inference does: a WebPKI-valid certificate
// for the right host name is not enough.
func TestMetricsScrapeSendsKeyOnlyToAttestedKey(t *testing.T) {
	old, _ := pollAPIKey.Load().(string)
	defer SetMetricsPollAPIKey(old)
	SetMetricsPollAPIKey("metrics-test")

	auths := make(chan string, 4)
	server := newBackendTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			return
		}
		auths <- r.Header.Get("Authorization")
		fmt.Fprintf(w, "%s 3\n", waitingMetricName)
	}))
	defer server.Close()
	// The fixture makes the server's certificate valid under normal
	// verification, so only the key pin can refuse it.
	trustBackendTLSFixture(t, server)
	host := strings.TrimPrefix(server.URL, "https://")
	fp := testBackendFingerprint(t, server)
	expired := newAttestationState(time.Now().Add(-time.Minute), time.Now().Add(-time.Hour), "test")

	for _, tc := range []struct {
		name        string
		key         string
		attestation *attestationState
		reached     bool
	}{
		{"attested key", fp, nil, true},
		{"other key", "not-the-attested-key", nil, false},
		{"expired attestation", fp, expired, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newEnclaveMetrics(host, "test-model", tc.key, tc.attestation)
			defer m.shutdown()
			m.scrape(t.Context())
			select {
			case got := <-auths:
				if !tc.reached {
					t.Fatal("metrics key sent to a backend that is not attested")
				}
				if got != "Bearer metrics-test" {
					t.Fatalf("Authorization = %q", got)
				}
			default:
				if tc.reached {
					t.Fatal("scrape did not reach the attested backend")
				}
			}
			if counts, _ := m.latestSample(); counts.hasWaiting != tc.reached {
				t.Fatalf("sample recorded = %v, want %v", counts.hasWaiting, tc.reached)
			}
		})
	}
}

func TestMetricsScrapeDoesNotFollowRedirects(t *testing.T) {
	old, _ := pollAPIKey.Load().(string)
	defer SetMetricsPollAPIKey(old)
	SetMetricsPollAPIKey("metrics-test")

	var metrics, elsewhere atomic.Int64
	server := newBackendTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			return
		case "/metrics":
			metrics.Add(1)
		default:
			elsewhere.Add(1)
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	trustBackendTLSFixture(t, server)
	host := strings.TrimPrefix(server.URL, "https://")
	m := newEnclaveMetrics(host, "test-model", testBackendFingerprint(t, server), nil)
	defer m.shutdown()
	m.scrape(t.Context())
	if metrics.Load() != 1 || elsewhere.Load() != 0 {
		t.Fatalf("scrape requests: /metrics=%d, redirect target=%d, want 1 and 0", metrics.Load(), elsewhere.Load())
	}
}
