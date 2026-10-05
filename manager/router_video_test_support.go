//go:build routertest

// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-09-11.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package manager

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-model-router/config"
	"github.com/tinfoilsh/confidential-model-router/ratelimit"
)

// NewVideoRouterTestManager is only compiled with the routertest tag. It gives
// cross-package handler tests real model selection, enclave serving, and proxy
// response handling without attestation, network calls, or background workers.
// Keep it out of production builds; it intentionally bypasses trust setup.
func NewVideoRouterTestManager(backends map[string]http.Handler, trackerOpts ...ratelimit.Option) *EnclaveManager {
	em := &EnclaveManager{models: &sync.Map{}, requestTracker: ratelimit.NewRequestTracker(trackerOpts...)}
	for name, backend := range backends {
		host := name + ".test.invalid"
		cb := newCircuitBreaker()
		proxy := newProxy(host, "", name, nil, cb)
		proxy.Transport = videoRouterTestTransport{backend: backend}
		em.models.Store(name, &Model{Enclaves: map[string]*Enclave{
			host: {host: host, modelName: name, proxy: proxy, cb: cb},
		}})
	}
	return em
}

// SetVideoRouterTestOverloaded installs a fresh overload sample without starting
// a metrics poller. Call only while setting up the fixture, before serving.
func (e *Enclave) SetVideoRouterTestOverloaded() {
	e.metrics = newEnclaveMetrics(e.host, e.modelName)
	e.metrics.cfg = &config.OverloadConfig{MaxRequestsWaiting: 1, RetryAfterMinutes: 1}
	e.metrics.updateLatest(5, time.Now())
	e.metrics.overloaded.Store(true)
}

type videoRouterTestTransport struct {
	backend http.Handler
}

func (t videoRouterTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	defer r.Body.Close()
	rec := httptest.NewRecorder()
	t.backend.ServeHTTP(rec, r)
	resp := rec.Result()
	resp.Request = r
	return resp, nil
}
