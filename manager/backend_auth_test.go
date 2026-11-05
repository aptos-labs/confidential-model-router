package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-model-router/billing"
	"github.com/tinfoilsh/confidential-model-router/config"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	tinfoilClient "github.com/tinfoilsh/tinfoil-go/verifier/client"
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

func newBackendTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	server.StartTLS()
	return server
}

// trustBackendTLSFixture is only for sequential tests: the pinned transport
// clones http.DefaultTransport on first use. Give that clone a test-only trust
// root, retaining normal certificate/hostname verification and its pin check.
// Never mutate the original transport or install roots outside this test.
func trustBackendTLSFixture(t *testing.T, server *httptest.Server) {
	t.Helper()
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	roots := transport.TLSClientConfig.RootCAs
	if roots == nil {
		roots = x509.NewCertPool()
	} else {
		roots = roots.Clone()
	}
	roots.AddCert(server.Certificate())
	transport.TLSClientConfig.RootCAs = roots
	http.DefaultTransport = transport
	t.Cleanup(func() {
		http.DefaultTransport = original
		transport.CloseIdleConnections()
	})
}

func TestBackendTLSFixtureVerification(t *testing.T) {
	server := newBackendTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	fp := testBackendFingerprint(t, server)
	original := http.DefaultTransport
	for _, name := range []string{"trusted", "wrong-pin", "unknown-ca", "wrong-hostname"} {
		t.Run(name, func(t *testing.T) {
			if name != "unknown-ca" {
				trustBackendTLSFixture(t, server)
			}
			if name == "wrong-hostname" {
				http.DefaultTransport.(*http.Transport).TLSClientConfig.ServerName = "untrusted.example"
			}
			expectedPin := fp
			if name == "wrong-pin" {
				expectedPin = "wrong-pin"
			}
			client := &http.Client{Transport: &tinfoilClient.TLSBoundRoundTripper{ExpectedPublicKey: expectedPin}}
			resp, err := client.Get(server.URL)
			if resp != nil {
				resp.Body.Close()
			}
			switch name {
			case "trusted":
				if err != nil {
					t.Fatal(err)
				}
			case "wrong-pin":
				if !errors.Is(err, tinfoilClient.ErrCertMismatch) {
					t.Fatalf("expected pin mismatch, got %v", err)
				}
			case "unknown-ca":
				var unknownCA x509.UnknownAuthorityError
				if !errors.As(err, &unknownCA) {
					t.Fatalf("expected untrusted certificate rejection, got %v", err)
				}
			case "wrong-hostname":
				var hostnameError x509.HostnameError
				if !errors.As(err, &hostnameError) {
					t.Fatalf("expected hostname rejection, got %v", err)
				}
			}
		})
		if http.DefaultTransport != original {
			t.Fatal("fixture trust changed the default transport after cleanup")
		}
	}
}

func testBackendFingerprint(t *testing.T, server *httptest.Server) string {
	t.Helper()
	resp, err := server.Client().Get(server.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	fp, err := attestation.ConnectionCertFP(*resp.TLS)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func TestBackendAuthStartupFailsClosed(t *testing.T) {
	for _, value := range []string{"", "   ", "bad\r\nvalue"} {
		t.Run(fmt.Sprintf("length-%d", len(value)), func(t *testing.T) {
			t.Setenv("ROUTER_TEST_EMPTY_BACKEND_AUTH", value)
			_, err := NewEnclaveManager([]byte("models:\n  selected:\n    backend_auth_env: ROUTER_TEST_EMPTY_BACKEND_AUTH\n    enclaves: [host1.example]\n"), "https://control.example", "", "", "", "", "", "", time.Minute, false)
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
				upstream := newBackendTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				trustBackendTLSFixture(t, upstream)
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
				e.proxy = newProxy(host, testBackendFingerprint(t, upstream), model, collector, newCircuitBreaker())
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
	upstream := newBackendTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			return
		}
		auths <- r.Header.Get("Authorization")
		fmt.Fprint(w, "{}")
	}))
	defer upstream.Close()
	trustBackendTLSFixture(t, upstream)
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
			var resp *http.Response
			var err error
			if jsonPath {
				resp, err = em.DoModelRequestJSON(ctx, model, "/v1/chat/completions", map[string]any{}, headers)
			} else {
				resp, err = em.DoModelRequest(ctx, model, "/v1/chat/completions", []byte("{}"), headers)
			}
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
	other := newBackendTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaks <- r.Header.Get("Authorization") }))
	defer other.Close()
	upstream := newBackendTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestBackendAuthMetricsCredentialsSeparate(t *testing.T) {
	old, _ := pollAPIKey.Load().(string)
	defer SetMetricsPollAPIKey(old)
	SetMetricsPollAPIKey("metrics-test")
	auths := make(chan string, 1)
	server := newBackendTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths <- r.Header.Get("Authorization")
		fmt.Fprintln(w, "vllm:num_requests_waiting 0")
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	credentials := testBackendCredentials(t, host)
	m := newEnclaveMetrics(host, "selected")
	m.client = server.Client()
	m.scrape(withBackendCredentials(context.Background(), credentials, "selected"))
	if <-auths != "Bearer metrics-test" {
		t.Fatal("metrics credential replaced by inference credential")
	}
}

func TestBackendAuthInvalidTargets(t *testing.T) {
	t.Setenv("ROUTER_TEST_BACKEND_AUTH", "backend-test")
	for _, host := range []string{"", "user@host.example", "host.example/path", "host.example?query", "host.example#fragment"} {
		cfg := &config.Config{Models: map[string]config.Model{"selected": {BackendAuthEnv: "ROUTER_TEST_BACKEND_AUTH", Hostnames: []string{host}}}}
		if _, err := loadBackendCredentials(cfg); err == nil {
			t.Fatalf("accepted invalid target %q", host)
		}
	}
}

func TestBackendAuthSameOriginRedirect(t *testing.T) {
	calls := 0
	server := newBackendTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	e := &Enclave{host: host, modelName: "selected", backendAuth: testBackendCredentials(t, host)}
	client := server.Client()
	resp, err := postToEnclave(context.Background(), client, e, "/v1/chat/completions", nil, http.Header{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || calls != 1 {
		t.Fatal("same-origin redirect followed")
	}
	if client.CheckRedirect != nil {
		t.Fatal("shared client mutated")
	}
}
