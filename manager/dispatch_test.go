// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-11-11.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package manager

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"
)

func attemptRequest(allowRetry bool) (*http.Request, *DispatchAttempt) {
	attempt := &DispatchAttempt{AllowRetry: allowRetry}
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"m"}`))
	return req.WithContext(WithDispatchAttempt(req.Context(), attempt)), attempt
}

func statusBackend(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	})
}

// A backend 503 that arrives before any response byte goes back to the
// handler, not to the client, when the handler allowed a retry.
func TestProxyHandsBackRetryableStatus(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		proxy := setupTestProxy(t, statusBackend(status, "workload proxy is not ready"))
		req, attempt := attemptRequest(true)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		if !attempt.Retry() {
			t.Fatalf("status %d: attempt not handed back", status)
		}
		if want := httpFailureReason(status); attempt.Reason() != want {
			t.Fatalf("status %d: reason = %q, want %q", status, attempt.Reason(), want)
		}
		if rec.Body.Len() != 0 || len(rec.Header()) != 0 || rec.Code != http.StatusOK {
			t.Fatalf("status %d: the client response was touched: code=%d headers=%v body=%q", status, rec.Code, rec.Header(), rec.Body.String())
		}
	}
}

// Without the handler's allowance the backend's own failure reaches the
// client, as before the retry existed.
func TestProxyRelaysFailureWithoutAllowance(t *testing.T) {
	proxy := setupTestProxy(t, statusBackend(http.StatusServiceUnavailable, "not ready"))

	req, attempt := attemptRequest(false)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if attempt.Retry() || rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "not ready" {
		t.Fatalf("allowance off: retry=%v code=%d body=%q", attempt.Retry(), rec.Code, rec.Body.String())
	}

	// A request without an attempt (internal dispatches) behaves the same.
	rec = httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no attempt: code=%d, want 503", rec.Code)
	}
}

// A 500 usually follows the request to the next host, and other statuses
// are answers, not host failures: none of them is handed back.
func TestProxyDoesNotHandBackOtherStatuses(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest, http.StatusTooManyRequests, http.StatusInternalServerError} {
		proxy := setupTestProxy(t, statusBackend(status, "answer"))
		req, attempt := attemptRequest(true)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)
		if attempt.Retry() || rec.Code != status || rec.Body.String() != "answer" {
			t.Fatalf("status %d: retry=%v code=%d body=%q", status, attempt.Retry(), rec.Code, rec.Body.String())
		}
	}
}

// A handed-back failure still counts against the enclave's breaker.
func TestHandedBackFailureFeedsBreaker(t *testing.T) {
	cb := newCircuitBreaker()
	proxy := newProxy("retry-host.test", "", "retry-model", nil, cb)
	backend := httptest.NewServer(statusBackend(http.StatusServiceUnavailable, ""))
	t.Cleanup(backend.Close)
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(backend.URL, "http://")
	}
	proxy.Transport = http.DefaultTransport

	for i := 0; i < cbFailureThreshold; i++ {
		req, attempt := attemptRequest(true)
		proxy.ServeHTTP(httptest.NewRecorder(), req)
		if !attempt.Retry() {
			t.Fatalf("attempt %d not handed back", i)
		}
	}
	if cb.State() != cbOpen {
		t.Fatalf("breaker state = %d, want open after %d handed-back failures", cb.State(), cbFailureThreshold)
	}
}

func TestProxyHandsBackTransportErrors(t *testing.T) {
	proxy := newProxy("transport-host.test", "", "transport-model", nil, newCircuitBreaker())
	refused := &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}

	req, attempt := attemptRequest(true)
	rec := httptest.NewRecorder()
	proxy.ErrorHandler(rec, req, refused)
	if !attempt.Retry() || attempt.Reason() != "connection_refused" || rec.Body.Len() != 0 {
		t.Fatalf("refused: retry=%v reason=%q body=%q", attempt.Retry(), attempt.Reason(), rec.Body.String())
	}

	// Not allowed: the client gets the 502.
	req, attempt = attemptRequest(false)
	rec = httptest.NewRecorder()
	proxy.ErrorHandler(rec, req, refused)
	if attempt.Retry() || rec.Code != http.StatusBadGateway {
		t.Fatalf("refused without allowance: retry=%v code=%d", attempt.Retry(), rec.Code)
	}

	// A timeout is never handed back: the backend may still be working.
	req, attempt = attemptRequest(true)
	rec = httptest.NewRecorder()
	proxy.ErrorHandler(rec, req, context.DeadlineExceeded)
	if attempt.Retry() || rec.Code != http.StatusBadGateway {
		t.Fatalf("timeout: retry=%v code=%d", attempt.Retry(), rec.Code)
	}

	// A client cancellation is never handed back.
	req, attempt = attemptRequest(true)
	proxy.ErrorHandler(httptest.NewRecorder(), req, context.Canceled)
	if attempt.Retry() {
		t.Fatal("cancellation handed back")
	}
}

func TestSelectServingExcluding(t *testing.T) {
	m := newTestModel("a", "b")
	for i := 0; i < 50; i++ {
		got, claim, overloaded, _, _ := m.SelectServingExcluding(nil, nil, nil, map[string]bool{"a": true})
		if got == nil || got.host != "b" || claim != nil || overloaded {
			t.Fatalf("exclude a: got %v claim=%v overloaded=%v", got, claim, overloaded)
		}
	}
	if got, _, _, _, _ := m.SelectServingExcluding(nil, nil, nil, map[string]bool{"a": true, "b": true}); got != nil {
		t.Fatalf("both excluded: got %v, want nil", got)
	}
	// The cache-aware order is honored among the hosts that are left.
	if got, _, _, _, _ := m.SelectServingExcluding([]string{"a", "b"}, nil, nil, map[string]bool{"a": true}); got == nil || got.host != "b" {
		t.Fatalf("order with exclusion: got %v, want b", got)
	}
	// An excluded host with a due recovery probe is not probed by this request.
	for i := 0; i < cbFailureThreshold; i++ {
		m.Enclaves["a"].cb.RecordFailure()
	}
	m.Enclaves["a"].cb.lastFailureNano.Store(time.Now().Add(-cbCooldown - time.Second).UnixNano())
	if got, claim, _, _, _ := m.SelectServingExcluding(nil, nil, nil, map[string]bool{"a": true}); got == nil || got.host != "b" || claim != nil {
		t.Fatalf("excluded host probed: got %v claim=%v", got, claim)
	}
	if got, claim := m.SelectForDispatchPoolsExcluding(nil, nil, nil, map[string]bool{"a": true}); got == nil || got.host != "b" || claim != nil {
		t.Fatalf("dispatch pools: got %v claim=%v", got, claim)
	}
}

func TestHasOtherServingEnclave(t *testing.T) {
	m := newTestModel("a", "b")
	if !m.HasOtherServingEnclave("a", nil, nil, nil) {
		t.Fatal("b is closed: want an alternative for a")
	}
	if m.HasOtherServingEnclave("a", nil, nil, map[string]bool{"b": true}) {
		t.Fatal("b already failed this request: want no alternative")
	}
	for i := 0; i < cbFailureThreshold; i++ {
		m.Enclaves["b"].cb.RecordFailure()
	}
	if m.HasOtherServingEnclave("a", nil, nil, nil) {
		t.Fatal("b is open: want no alternative")
	}
	if newTestModel("a").HasOtherServingEnclave("a", nil, nil, nil) {
		t.Fatal("single enclave: want no alternative")
	}
	// A host outside the caller's reservation pools is not an alternative.
	m = newTestModel("a", "b", "c")
	if m.HasOtherServingEnclave("a", map[string]bool{"a": true}, nil, nil) {
		t.Fatal("b and c are outside the pools: want no alternative")
	}
	if !m.HasOtherServingEnclave("a", map[string]bool{"a": true}, map[string]bool{"c": true}, nil) {
		t.Fatal("c is in the spill pool: want an alternative")
	}
}

func TestPickLeastInflight(t *testing.T) {
	m := newTestModel("a", "b")
	m.leastInflight = true
	m.Enclaves["a"].inflight.Store(9)
	for i := 0; i < 50; i++ {
		if got, _ := m.NextEnclave(nil); got == nil || got.host != "b" {
			t.Fatalf("a is busy: got %v, want b", got)
		}
	}
	// A tie is broken at random.
	m.Enclaves["a"].inflight.Store(0)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		got, _ := m.NextEnclave(nil)
		seen[got.host] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("tie: saw %v, want both hosts", seen)
	}
	// The default stays uniformly random, whatever the load.
	m.leastInflight = false
	m.Enclaves["a"].inflight.Store(9)
	seen = map[string]bool{}
	for i := 0; i < 200; i++ {
		got, _ := m.NextEnclave(nil)
		seen[got.host] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("random: saw %v, want both hosts", seen)
	}
}
