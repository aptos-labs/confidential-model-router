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
	h.Set("X-Keep-Me", "kept")
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

func TestWithoutVLLMHeadersKeepsCleanRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Vllm", "not a prefix match")
	r.Header.Set("X-Vllmpriority", "not a prefix match")
	if withoutVLLMHeaders(r) != r {
		t.Fatal("request without X-Vllm-* headers was cloned")
	}
}
