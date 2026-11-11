//go:build routertest

// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-11-11.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package manager

import (
	"net/http"
	"sync"

	"github.com/tinfoilsh/confidential-model-router/ratelimit"
)

// NewMultiEnclaveRouterTestManager is only compiled with the routertest tag.
// It gives handler tests one model with several enclaves, in the given order,
// with real selection, breakers and proxy response handling and without
// attestation or network calls. It returns the enclave hosts in order.
func NewMultiEnclaveRouterTestManager(model string, backends []http.Handler) (*EnclaveManager, []string) {
	em := &EnclaveManager{models: &sync.Map{}, requestTracker: ratelimit.NewRequestTracker()}
	enclaves := make(map[string]*Enclave, len(backends))
	hosts := make([]string, 0, len(backends))
	for i, backend := range backends {
		host := model + "-" + string(rune('a'+i)) + ".test.invalid"
		cb := newCircuitBreaker()
		proxy := newProxy(host, "", model, nil, cb)
		proxy.Transport = videoRouterTestTransport{backend: backend}
		enclaves[host] = &Enclave{host: host, modelName: model, proxy: proxy, cb: cb}
		hosts = append(hosts, host)
	}
	em.models.Store(model, &Model{Enclaves: enclaves, expectedHosts: len(backends)})
	return em, hosts
}

// RouterTestBreakerOpen reports whether the enclave's breaker left the closed state.
func (em *EnclaveManager) RouterTestBreakerOpen(model, host string) bool {
	m, ok := em.GetModel(model)
	if !ok {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	enclave := m.Enclaves[host]
	return enclave != nil && !enclave.breakerClosed()
}
