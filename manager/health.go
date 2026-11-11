// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-11-11.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package manager

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	tinfoilClient "github.com/tinfoilsh/tinfoil-go/verifier/client"
)

const (
	healthProbeInterval = 5 * time.Second
	healthProbeTimeout  = 5 * time.Second
)

// healthGate keeps live requests away from an enclave whose breaker is not
// closed until the enclave answers its health endpoint with 200. Without it
// the breaker's recovery probe is a client request, and an enclave that is
// attested but still loading its model fails one client request per cooldown.
//
// The gate does not close the breaker itself. A passing health check only
// allows the usual live probe, so an enclave whose health endpoint is
// optimistic still has to serve one real request before it gets traffic.
type healthGate struct {
	url    string
	client *http.Client

	passing atomic.Bool
	stop    chan struct{}
	once    sync.Once
}

func newHealthGate(host, path, publicKeyFP string) *healthGate {
	return &healthGate{
		url: "https://" + host + path,
		client: &http.Client{
			Transport: &tinfoilClient.TLSBoundRoundTripper{ExpectedPublicKey: publicKeyFP},
			Timeout:   healthProbeTimeout,
		},
		stop: make(chan struct{}),
	}
}

// Passing reports whether a live recovery probe is allowed. An enclave
// without a gate keeps the original behavior: always allowed.
func (g *healthGate) Passing() bool { return g == nil || g.passing.Load() }

// check performs one health request and records its result.
func (g *healthGate) check(ctx context.Context) bool {
	ok := false
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.url, nil)
	if err == nil {
		resp, doErr := g.client.Do(req)
		if doErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			ok = resp.StatusCode == http.StatusOK
		}
	}
	g.passing.Store(ok)
	return ok
}

// run probes the enclave while its breaker is not closed. A closed breaker
// needs no probe: live traffic already proves health. The result is dropped
// while the breaker is closed, so a later failure always needs a fresh pass.
func (g *healthGate) run(cb *circuitBreaker, modelName, host string) {
	ticker := time.NewTicker(healthProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-ticker.C:
			if cb.Closed() {
				g.passing.Store(false)
				continue
			}
			result := "fail"
			if g.check(context.Background()) {
				result = "pass"
			}
			HealthProbesTotal.WithLabelValues(modelName, host, result).Inc()
		}
	}
}

func (g *healthGate) shutdown() {
	if g == nil {
		return
	}
	g.once.Do(func() { close(g.stop) })
}
