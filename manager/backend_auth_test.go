package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-model-router/billing"
	"github.com/tinfoilsh/confidential-model-router/config"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	usagereporting "github.com/tinfoilsh/usage-reporting-go"
)

type backendTestProvider struct{ calls int }

func (p *backendTestProvider) Authorization(context.Context) (string, error) {
	p.calls++
	return "Bearer delegated-test", nil
}

func testBackendCredentials(t *testing.T, host string) backendCredentials {
	t.Helper()
	t.Setenv("ROUTER_TEST_BACKEND_AUTH", "backend-test")
	cfg, err := config.FromBytes([]byte(fmt.Sprintf("models:\n  selected:\n    backend_auth_env: ROUTER_TEST_BACKEND_AUTH\n    enclaves: [%q]\n  other:\n    enclaves: [%q]\n", host, host)))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := loadBackendCredentials(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Runtime environment changes cannot rotate or broaden the startup snapshot.
	t.Setenv("ROUTER_TEST_BACKEND_AUTH", "changed-test")
	return credentials
}

func testBackendFingerprint(t *testing.T, server *httptest.Server) string {
	t.Helper()
	resp, err := server.Client().Get(server.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	fp, err := enclave.ConnectionCertFP(*resp.TLS)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func TestBackendAuthStartupFailsClosed(t *testing.T) {
	for _, value := range []string{"", "   ", "bad\r\nvalue"} {
		t.Run(fmt.Sprintf("length-%d", len(value)), func(t *testing.T) {
			t.Setenv("ROUTER_TEST_EMPTY_BACKEND_AUTH", value)
			_, err := NewEnclaveManager([]byte("models:\n  selected:\n    backend_auth_env: ROUTER_TEST_EMPTY_BACKEND_AUTH\n    enclaves: [host1.example]\n"), "https://control.example", "", "", "", "", "", time.Minute, false)
			if err == nil || !strings.Contains(err.Error(), "backend_auth_env") {
				t.Fatalf("expected startup credential validation failure, got %v", err)
			}
			if value != "" && strings.Contains(err.Error(), value) {
				t.Fatal("startup error disclosed credential")
			}
		})
	}
}

func TestBackendAuthProxyBilling(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, model := range []string{"selected", "other"} {
			t.Run(fmt.Sprintf("%s/streaming-%t", model, streaming), func(t *testing.T) {
				auths := make(chan string, 1)
				upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/health" {
						return
					}
					auths <- r.Header.Get("Authorization")
					w.Header().Set("X-Request-Id", "backend-auth-request")
					usage := `{"id":"test","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`
					if streaming {
						w.Header().Set("Content-Type", "text/event-stream")
						fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", usage)
					} else {
						w.Header().Set("Content-Type", "application/json")
						fmt.Fprint(w, usage)
					}
				}))
				defer upstream.Close()
				host := strings.TrimPrefix(upstream.URL, "https://")
				batches := make(chan usagereporting.Batch, 2)
				control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var batch usagereporting.Batch
					if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
						t.Error(err)
					}
					batches <- batch
				}))
				defer control.Close()
				collector := billing.NewCollector(control.URL, "test-reporter", "report-test")
				defer collector.Stop()
				e := &Enclave{host: host, modelName: model, backendAuth: testBackendCredentials(t, host)}
				e.proxy = newProxy(host, testBackendFingerprint(t, upstream), model, collector, newCircuitBreaker(), nil)
				// The attested transport requires a public CA. Keep the auth
				// tripper and point it at the test server's trusted client.
				e.proxy.Transport = &backendAuthTripper{base: upstream.Client().Transport}
				provider := &backendTestProvider{}
				r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}"))
				r.Header.Set("Authorization", "Bearer customer-test")
				r.Header.Set("X-Original-Authorization", "Bearer spoof-test")
				r.Header.Set("X-Tinfoil-Original-API-Key", "spoof-test")
				r = r.WithContext(WithAuthorizationProvider(r.Context(), provider))
				w := httptest.NewRecorder()
				e.ServeHTTP(w, r)
				if w.Code != http.StatusOK {
					t.Fatalf("status: %d: %s", w.Code, w.Body.String())
				}
				want := "Bearer delegated-test"
				if model == "selected" {
					want = "Bearer backend-test"
				}
				if got := <-auths; got != want {
					t.Fatalf("outbound auth mismatch")
				}
				if provider.calls != 1 {
					t.Fatalf("provider calls = %d", provider.calls)
				}
				if r.Header.Get("Authorization") != "Bearer customer-test" {
					t.Fatal("inbound identity mutated")
				}
				collector.Stop()
				select {
				case batch := <-batches:
					if len(batch.Events) != 1 {
						t.Fatalf("events = %d", len(batch.Events))
					}
					event := batch.Events[0]
					if event.APIKey != "customer-test" {
						t.Fatal("billing attributed to rewritten or spoofed credential")
					}
					if event.Attributes["streaming"] != fmt.Sprint(streaming) {
						t.Fatal("streaming attribution mismatch")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("billing event not delivered")
				}
			})
		}
	}
}

func TestBackendAuthInternalModelRequests(t *testing.T) {
	auths := make(chan string, 8)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			return
		}
		auths <- r.Header.Get("Authorization")
		fmt.Fprint(w, "{}")
	}))
	defer upstream.Close()
	host := strings.TrimPrefix(upstream.URL, "https://")
	credentials := testBackendCredentials(t, host)
	em := &EnclaveManager{models: &sync.Map{}, backendAuth: credentials}
	fp := testBackendFingerprint(t, upstream)
	for _, model := range []string{"selected", "other"} {
		e := &Enclave{host: host, modelName: model, tlsKeyFP: fp, backendAuth: credentials}
		em.models.Store(model, &Model{Enclaves: map[string]*Enclave{host: e}})
		for _, jsonPath := range []bool{false, true} {
			provider := &backendTestProvider{}
			ctx := WithAuthorizationProvider(context.Background(), provider)
			headers := http.Header{"Authorization": {"Bearer customer-test"}}
			var err error
			var resp *http.Response
			body := []byte("{}")
			if jsonPath {
				body, err = json.Marshal(map[string]any{})
				if err != nil {
					t.Fatal(err)
				}
			}
			// postToEnclave is the internal dispatch path. The attested client
			// rejects the test certificate, so use the server's own client.
			resp, err = postToEnclave(ctx, upstream.Client(), e, "/v1/chat/completions", body, headers, nil)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			want := "Bearer delegated-test"
			if model == "selected" {
				want = "Bearer backend-test"
			}
			if <-auths != want {
				t.Fatal("internal outbound auth mismatch")
			}
			original, _ := resp.Request.Context().Value(originalIdentityKey{}).(string)
			if original != "Bearer customer-test" || headers.Get("Authorization") != original {
				t.Fatal("internal original identity lost")
			}
			if provider.calls != 1 {
				t.Fatal("existing provider bypassed")
			}
		}
	}
}

func TestBackendAuthOriginScopeAndRedirect(t *testing.T) {
	leaks := make(chan string, 2)
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaks <- r.Header.Get("Authorization") }))
	defer other.Close()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()
	host := strings.TrimPrefix(upstream.URL, "https://")
	credentials := testBackendCredentials(t, host)
	for _, target := range []string{other.URL, "http://" + host} {
		r := httptest.NewRequest(http.MethodPost, target, nil)
		r.Header.Set("Authorization", "Bearer customer-test")
		r = r.WithContext(withBackendCredentials(r.Context(), credentials, "selected"))
		applyBackendAuthorization(r)
		if r.Header.Get("Authorization") != "Bearer customer-test" {
			t.Fatal("credential leaked across origin")
		}
	}
	e := &Enclave{host: host, modelName: "selected", backendAuth: credentials}
	resp, err := postToEnclave(context.Background(), upstream.Client(), e, "/v1/chat/completions", nil, http.Header{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatal("redirect followed")
	}
	select {
	case <-leaks:
		t.Fatal("redirect destination contacted")
	default:
	}
}
