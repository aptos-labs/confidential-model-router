//go:build routertest

// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-11-11.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tinfoilsh/confidential-model-router/manager"
)

const retryTestModel = "retry-chat-fixture"

func retryTestRequest(stream bool) *http.Request {
	body := `{"model":"` + retryTestModel + `","messages":[{"role":"user","content":"hello"}],"stream":false}`
	if stream {
		body = strings.Replace(body, `"stream":false`, `"stream":true`, 1)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer retry-test-only-token")
	return r
}

// A host that is attested but not ready answers 503. The client must get the
// other host's answer, with the full request body replayed.
func TestRouterRetriesOnAnotherEnclave(t *testing.T) {
	oldSalt := *cacheSaltEnabled
	*cacheSaltEnabled = false
	t.Cleanup(func() { *cacheSaltEnabled = oldSalt })

	const reply = `{"choices":[{"message":{"role":"assistant","content":"hello"}}]}`
	var notReadyCalls, readyCalls atomic.Int64
	notReady := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notReadyCalls.Add(1)
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"error":{"message":"Workload proxy is not ready."}}`)
	})
	ready := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readyCalls.Add(1)
		got, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(got), `"content":"hello"`) || !strings.Contains(string(got), retryTestModel) {
			t.Errorf("the replayed body is not the request body: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, reply)
	})
	em, hosts := manager.NewMultiEnclaveRouterTestManager(retryTestModel, []http.Handler{notReady, ready})
	handler := newRouterHandler(em, nil)

	const requests = 40
	for i := 0; i < requests; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, retryTestRequest(i%2 == 1))
		if rec.Code != http.StatusOK || rec.Body.String() != reply {
			t.Fatalf("request %d: status=%d body=%s", i, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Tinfoil-Enclave"); got != hosts[1] {
			t.Fatalf("request %d: served by %q, want %q", i, got, hosts[1])
		}
	}
	if readyCalls.Load() != requests {
		t.Fatalf("ready host calls = %d, want %d", readyCalls.Load(), requests)
	}
	// The failing host gets requests only until its breaker opens.
	if n := notReadyCalls.Load(); n < 1 || n > 3 {
		t.Fatalf("not-ready host calls = %d, want 1 to 3 (the breaker opens after 3)", n)
	}
	if notReadyCalls.Load() == 3 && !em.RouterTestBreakerOpen(retryTestModel, hosts[0]) {
		t.Fatal("the not-ready host's breaker must be open after 3 failures")
	}
}

// With one host there is nowhere to retry: the backend's own answer reaches
// the client, as before.
func TestRouterRelaysFailureOfTheOnlyEnclave(t *testing.T) {
	oldSalt := *cacheSaltEnabled
	*cacheSaltEnabled = false
	t.Cleanup(func() { *cacheSaltEnabled = oldSalt })

	const failure = `{"error":{"message":"Workload proxy is not ready."}}`
	calls := 0
	em, _ := manager.NewMultiEnclaveRouterTestManager(retryTestModel, []http.Handler{
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, failure)
		}),
	})
	rec := httptest.NewRecorder()
	newRouterHandler(em, nil).ServeHTTP(rec, retryTestRequest(false))
	if calls != 1 || rec.Code != http.StatusServiceUnavailable || rec.Body.String() != failure {
		t.Fatalf("calls=%d status=%d body=%s", calls, rec.Code, rec.Body.String())
	}
}

// When every host fails, the last host's own answer reaches the client and
// each host is tried once.
func TestRouterStopsRetryingWhenEveryEnclaveFails(t *testing.T) {
	oldSalt := *cacheSaltEnabled
	*cacheSaltEnabled = false
	t.Cleanup(func() { *cacheSaltEnabled = oldSalt })

	var calls atomic.Int64
	failing := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, name)
		})
	}
	em, _ := manager.NewMultiEnclaveRouterTestManager(retryTestModel, []http.Handler{failing("first"), failing("second")})
	rec := httptest.NewRecorder()
	newRouterHandler(em, nil).ServeHTTP(rec, retryTestRequest(false))
	if calls.Load() != 2 {
		t.Fatalf("backend calls = %d, want 2 (each host once)", calls.Load())
	}
	if rec.Code != http.StatusServiceUnavailable || (rec.Body.String() != "first" && rec.Body.String() != "second") {
		t.Fatalf("status=%d body=%q, want the last host's 503", rec.Code, rec.Body.String())
	}
}

// A 500 is an answer about the request, not about the host: no retry.
func TestRouterDoesNotRetryInternalServerError(t *testing.T) {
	oldSalt := *cacheSaltEnabled
	*cacheSaltEnabled = false
	t.Cleanup(func() { *cacheSaltEnabled = oldSalt })

	var calls atomic.Int64
	broken := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "boom")
	})
	em, _ := manager.NewMultiEnclaveRouterTestManager(retryTestModel, []http.Handler{broken, broken})
	rec := httptest.NewRecorder()
	newRouterHandler(em, nil).ServeHTTP(rec, retryTestRequest(false))
	if calls.Load() != 1 || rec.Code != http.StatusInternalServerError || rec.Body.String() != "boom" {
		t.Fatalf("calls=%d status=%d body=%q", calls.Load(), rec.Code, rec.Body.String())
	}
}
