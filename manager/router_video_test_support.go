//go:build routertest

package manager

import (
	"net/http"
	"net/http/httptest"
	"sync"
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
		proxy := newProxy(host, "", name, nil, cb)
		proxy.Transport = videoRouterTestTransport{backend: backend}
		em.models.Store(name, &Model{Enclaves: map[string]*Enclave{
			host: {host: host, modelName: name, proxy: proxy, cb: cb},
		}})
	}
	return em
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
