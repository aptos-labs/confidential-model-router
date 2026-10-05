//go:build routertest

// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-09-11.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package manager

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// NewVideoRouterTestManager is only compiled with the routertest tag. It gives
// cross-package handler tests real model selection, enclave serving, and proxy
// response handling without attestation, network calls, or background workers.
// Keep it out of production builds; it intentionally bypasses trust setup.
func NewVideoRouterTestManager(backends map[string]http.Handler) *EnclaveManager {
	em := &EnclaveManager{models: &sync.Map{}}
	for name, backend := range backends {
		host := name + ".test.invalid"
		cb := newCircuitBreaker()
		proxy := newProxy(host, "", name, nil, cb, nil)
		proxy.Transport = videoRouterTestTransport{backend: backend}
		em.models.Store(name, &Model{Enclaves: map[string]*Enclave{
			host: {host: host, modelName: name, proxy: proxy, cb: cb},
		}})
	}
	return em
}

// SetVideoRouterTestOverloaded installs a fresh queue sample without starting
// a metrics poller. The model's Overload policy must trip at this depth.
// Call only while setting up the fixture, before serving.
func (e *Enclave) SetVideoRouterTestOverloaded() {
	e.metrics = newEnclaveMetrics(e.host, e.modelName)
	e.metrics.updateLatest(requestCounts{waiting: 5, hasWaiting: true}, time.Now())
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
