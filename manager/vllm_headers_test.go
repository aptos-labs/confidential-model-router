package manager

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// clientVLLMHeaders mixes canonical and raw map keys: http.Header.Set
// canonicalizes, but code that writes the map directly does not.
func clientVLLMHeaders(h http.Header) {
	h.Set("X-Vllm-Priority", "-100")
	h["x-vllm-custom"] = []string{"1"}
	h.Set("Endpoint-Load-Metrics-Format", "JSON")
	h["endpoint-load-metrics-format"] = []string{"TEXT", "JSON"}
	h.Set("X-Session-ID", "first-session")
	h["x-session-id"] = []string{"second-session", "third-session"}
	h.Set("X-Data-Parallel-Rank", "1")
	h["x-data-parallel-rank"] = []string{"2", "3"}
	h.Set("Traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
	h["traceparent"] = []string{"00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01"}
	h.Set("Tracestate", "first=value")
	h["tracestate"] = []string{"second=value"}
	h.Set("X-Keep-Me", "kept")
	h.Set("X-Request-Id", "public-invoice-id")
}

func assertNoVLLMHeaders(t *testing.T, got http.Header) {
	t.Helper()
	for name := range got {
		if isVLLMHeader(name) {
			t.Fatalf("backend received client header %s", name)
		}
	}
	if got.Get("X-Keep-Me") != "kept" {
		t.Fatal("unrelated client header dropped")
	}
	if got.Get("X-Request-Id") != "public-invoice-id" {
		t.Fatal("public invoice request ID header changed without a migration")
	}
}

func TestVLLMHeadersNeverReachBackend(t *testing.T) {
	seen := make(chan http.Header, 8)
	upstream := newBackendTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			return
		}
		seen <- r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"test","choices":[]}`)
	}))
	defer upstream.Close()
	trustBackendTLSFixture(t, upstream)
	host := strings.TrimPrefix(upstream.URL, "https://")
	fp := testBackendFingerprint(t, upstream)

	t.Run("proxy", func(t *testing.T) {
		e := &Enclave{host: host, modelName: "other", tlsKeyFP: fp, cb: newCircuitBreaker()}
		e.proxy = newProxy(host, fp, "other", nil, e.cb, nil)
		r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
		clientVLLMHeaders(r.Header)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		assertNoVLLMHeaders(t, <-seen)
		if r.Header.Get("X-Vllm-Priority") != "-100" {
			t.Fatal("inbound request mutated")
		}
	})

	em := &EnclaveManager{models: &sync.Map{}}
	em.models.Store("other", &Model{Enclaves: map[string]*Enclave{host: {host: host, modelName: "other", tlsKeyFP: fp}}})
	for _, jsonPath := range []bool{false, true} {
		name := "internal"
		if jsonPath {
			name = "internal-json"
		}
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			clientVLLMHeaders(headers)
			var resp *http.Response
			var err error
			if jsonPath {
				resp, err = em.DoModelRequestJSON(context.Background(), "other", "/v1/chat/completions", map[string]any{}, headers)
			} else {
				resp, err = em.DoModelRequest(context.Background(), "other", "/v1/chat/completions", []byte("{}"), headers)
			}
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			assertNoVLLMHeaders(t, <-seen)
			if headers.Get("X-Vllm-Priority") != "-100" {
				t.Fatal("caller headers mutated")
			}
		})
	}
}

func TestVLLMLoadHeadersNeverReachNonStreamingClient(t *testing.T) {
	upstream := newBackendTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Endpoint-Load-Metrics"] = []string{"TEXT named_metrics.num_requests_waiting=7"}
		w.Header()["endpoint-load-metrics"] = []string{"JSON duplicate"}
		w.Header().Set("X-Request-Id", "public-invoice-id")
		w.Header().Set("X-Keep-Me", "kept")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"test","choices":[]}`)
	}))
	defer upstream.Close()
	trustBackendTLSFixture(t, upstream)
	host := strings.TrimPrefix(upstream.URL, "https://")
	fp := testBackendFingerprint(t, upstream)
	e := &Enclave{host: host, modelName: "other", tlsKeyFP: fp, cb: newCircuitBreaker()}
	e.proxy = newProxy(host, fp, "other", nil, e.cb, nil)
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if got := w.Result().Header.Values(vllmLoadResponseHeader); len(got) != 0 {
		t.Fatalf("client received engine load headers: %v", got)
	}
	if got := w.Header().Get("X-Request-Id"); got != "public-invoice-id" {
		t.Fatalf("public request ID changed: %q", got)
	}
	if got := w.Header().Get("X-Keep-Me"); got != "kept" {
		t.Fatal("unrelated response header dropped")
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"id":"test","choices":[]}` {
		t.Fatalf("non-streaming body changed: %s", got)
	}
}

func TestWithoutVLLMHeadersKeepsCleanRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Vllm", "not a prefix match")
	r.Header.Set("X-Vllmpriority", "not a prefix match")
	if withoutVLLMHeaders(r) != r {
		t.Fatal("request without X-Vllm-* headers was cloned")
	}
}
