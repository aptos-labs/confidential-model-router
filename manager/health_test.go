// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-11-11.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package manager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testHealthGate(t *testing.T, status *atomic.Int32) *healthGate {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/health" {
			t.Errorf("health probe changed: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(server.Close)
	return &healthGate{url: server.URL + "/health", client: server.Client(), stop: make(chan struct{})}
}

func openPastCooldown(cb *circuitBreaker) {
	for i := 0; i < cbFailureThreshold; i++ {
		cb.RecordFailure()
	}
	cb.lastFailureNano.Store(time.Now().Add(-cbCooldown - time.Second).UnixNano())
}

func TestHealthGateCheck(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusServiceUnavailable)
	gate := testHealthGate(t, &status)

	if gate.Passing() {
		t.Fatal("a new gate must not pass before its first check")
	}
	if gate.check(context.Background()) || gate.Passing() {
		t.Fatal("503 from the health endpoint must not pass")
	}
	status.Store(http.StatusOK)
	if !gate.check(context.Background()) || !gate.Passing() {
		t.Fatal("200 from the health endpoint must pass")
	}
	status.Store(http.StatusInternalServerError)
	if gate.check(context.Background()) || gate.Passing() {
		t.Fatal("a later failure must drop the pass")
	}

	// An unreachable endpoint does not pass.
	down := &healthGate{url: "http://127.0.0.1:1/health", client: &http.Client{Timeout: time.Second}, stop: make(chan struct{})}
	if down.check(context.Background()) {
		t.Fatal("an unreachable endpoint passed")
	}

	// An enclave without a gate keeps the original behavior.
	var none *healthGate
	if !none.Passing() {
		t.Fatal("nil gate must allow the live probe")
	}
	none.shutdown()
}

// With a gate, no client request is claimed as the recovery probe until the
// health endpoint answered.
func TestHealthGateHoldsLiveProbe(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusServiceUnavailable)
	m := newTestModel("a", "b")
	gate := testHealthGate(t, &status)
	m.Enclaves["a"].health = gate
	openPastCooldown(m.Enclaves["a"].cb)

	gate.check(context.Background())
	for i := 0; i < 50; i++ {
		got, claim := m.NextEnclave(nil)
		if got == nil || got.host != "b" || claim != nil {
			t.Fatalf("gate failing: got %v claim=%v, want b without a probe", got, claim)
		}
	}
	if got, claim, _, _, _ := m.SelectServing([]string{"a", "b"}, nil, nil); got == nil || got.host != "b" || claim != nil {
		t.Fatalf("gate failing, ordered: got %v claim=%v", got, claim)
	}
	if m.Enclaves["a"].cb.State() != cbOpen {
		t.Fatalf("breaker state = %d, want open", m.Enclaves["a"].cb.State())
	}

	status.Store(http.StatusOK)
	gate.check(context.Background())
	got, claim := m.NextEnclave(nil)
	if got == nil || got.host != "a" || claim == nil {
		t.Fatalf("gate passing: got %v claim=%v, want the probe on a", got, claim)
	}
}

// The gate only allows the live probe. It never closes the breaker itself.
func TestHealthGateDoesNotCloseBreaker(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	gate := testHealthGate(t, &status)
	cb := newCircuitBreaker()
	openPastCooldown(cb)
	gate.check(context.Background())
	if cb.State() != cbOpen {
		t.Fatalf("breaker state = %d, want open after a passing health check", cb.State())
	}
}

func TestBreakerStartOpen(t *testing.T) {
	cb := newCircuitBreaker()
	cb.startOpen()
	if cb.State() != cbOpen || cb.Closed() {
		t.Fatalf("state = %d, want open", cb.State())
	}
	if _, ok := cb.ClaimProbe(); !ok {
		t.Fatal("a breaker that starts open must allow a probe at once")
	}
	cb.RecordSuccess()
	if !cb.Closed() {
		t.Fatal("a successful probe must close the breaker")
	}
}

func TestHealthGateShutdownStopsRun(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	gate := testHealthGate(t, &status)
	done := make(chan struct{})
	go func() {
		gate.run(newCircuitBreaker(), "health-model", "health-host.test")
		close(done)
	}()
	gate.shutdown()
	gate.shutdown() // safe to call twice
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop after shutdown")
	}
}

// A config reload that adds, changes or removes health_probe_path reaches the
// enclaves the model already has, not only the ones added later.
func TestSetHealthProbePathReconcilesEnclaves(t *testing.T) {
	m := newTestModel("a", "b")
	openPastCooldown(m.Enclaves["a"].cb)

	m.mu.Lock()
	m.setHealthProbePath("health-model", "/health")
	m.mu.Unlock()
	first := m.Enclaves["a"].health
	if m.healthProbePath != "/health" || first == nil || m.Enclaves["b"].health == nil {
		t.Fatalf("path %q: gates a=%v b=%v, want both set", m.healthProbePath, first, m.Enclaves["b"].health)
	}
	// The fresh gate has not passed: no client request probes the open enclave.
	if got, claim := m.NextEnclave(nil); got == nil || got.host != "b" || claim != nil {
		t.Fatalf("fresh gate: got %v claim=%v, want b without a probe", got, claim)
	}

	// The same path again keeps the gates and their state.
	m.mu.Lock()
	m.setHealthProbePath("health-model", "/health")
	m.mu.Unlock()
	if m.Enclaves["a"].health != first {
		t.Fatal("an unchanged path must keep the gate")
	}

	// Removing the path stops the gates and restores the original live probe.
	m.mu.Lock()
	m.setHealthProbePath("health-model", "")
	m.mu.Unlock()
	if m.Enclaves["a"].health != nil || m.Enclaves["b"].health != nil {
		t.Fatal("a removed path must drop the gates")
	}
	select {
	case <-first.stop:
	default:
		t.Fatal("the replaced gate must be stopped")
	}
	if got, claim := m.NextEnclave(nil); got == nil || got.host != "a" || claim == nil {
		t.Fatalf("no gate: got %v claim=%v, want the live probe on a", got, claim)
	}
}
