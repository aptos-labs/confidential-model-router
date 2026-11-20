package manager

import (
	"math/rand/v2"
	"time"

	"github.com/tinfoilsh/confidential-model-router/config"
)

type routingTier int

const (
	tierPreferred routingTier = iota
	tierBusy
	tierUnknown
	tierOverloaded
	tierCount
)

// spillPoliciesLocked keeps shared metrics available even if the shared
// pool's own guard is disabled. The caller must hold m.mu.
func (m *Model) spillPoliciesLocked(host string) []*config.OverloadConfig {
	if !m.sharedHosts[host] {
		return nil
	}
	var policies []*config.OverloadConfig
	for _, policy := range m.policiesByCaller {
		if policy.Enabled() {
			policies = append(policies, policy)
		}
	}
	return policies
}

// localInflight is the caller's own dispatch count for the enclave: an
// exact, immediately-updated signal, unlike the polled counts which are a
// whole sample stale and blind to a burst that arrives inside one poll
// interval. It is per router, so with N replicas the instantaneous cap is
// N × soft_max until the global polled count corrects it.
func (m *enclaveMetrics) tier(policy *config.OverloadConfig, localInflight int64) (routingTier, float64) {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	if !policy.Enabled() {
		return tierPreferred, 0
	}
	counts := m.latestCounts
	unknown := m.latestCollected.IsZero() || time.Since(m.latestCollected) > sampleStalenessLimit ||
		!counts.supports(policy)
	if cap := policy.LocalInflightCap(); cap > 0 && localInflight >= int64(cap) {
		return tierOverloaded, counts.waiting
	}
	if unknown && policy.SoftMaxRequestsRunning > 0 && localInflight >= int64(policy.SoftMaxRequestsRunning) {
		// Preserve the existing unknown-sample spill at the soft limit.
		return tierOverloaded, counts.waiting
	}
	if unknown {
		return tierUnknown, counts.waiting
	}
	// Queued requests count toward the soft max: a host queueing below it
	// is admitting work, not saturated.
	load := max(counts.running+counts.waiting, float64(localInflight))
	trip, clear := policy.Marks()
	marks := queueMarks{trip, clear}
	if trip > 0 && marks.overloaded(counts.waiting, m.queueOverloads[marks]) {
		return tierOverloaded, counts.waiting
	}
	preferred := counts.waiting == 0
	if policy.SoftMaxRequestsRunning > 0 {
		preferred = load < float64(policy.SoftMaxRequestsRunning)
	}
	if preferred {
		return tierPreferred, counts.waiting
	}
	return tierBusy, counts.waiting
}

// SelectServing ranks closed backends by the request's tier, then pool, then
// affinity. Unknown load fails open only after known usable capacity. Due
// recovery probes and the all-breakers-open last resort retain their bypass.
// A non-nil enclave reserves one local in-flight request until ReleaseDispatch.
func (m *Model) SelectServing(order []string, claimProbes bool, primary, spill map[string]bool, policy *config.OverloadConfig) (*Enclave, *ProbeClaim, bool, time.Duration, float64) {
	enclave, claim, overloaded, retryAfter, waiting, _ := m.SelectServingWithCap(order, claimProbes, primary, spill, policy)
	return enclave, claim, overloaded, retryAfter, waiting
}

// SelectServingWithCap also reports whether selection hit the absolute local
// cap before it reserved the rejection. Callers can preserve priority bypass
// for polled queue overload without bypassing the local cap.
func (m *Model) SelectServingWithCap(order []string, claimProbes bool, primary, spill map[string]bool, policy *config.OverloadConfig) (*Enclave, *ProbeClaim, bool, time.Duration, float64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	enclave, claim, overloaded, retryAfter, waiting, localCapReached := m.selectServingLocked(order, claimProbes, primary, spill, policy, "")
	if enclave != nil {
		enclave.inflight.Add(1)
		BackendInflight.WithLabelValues(enclave.modelName, enclave.host).Inc()
	}
	return enclave, claim, overloaded, retryAfter, waiting, localCapReached
}

// SelectRetry excludes recovery probes, unknown load, and overloaded replicas.
func (m *Model) SelectRetry(failedHost string, order []string, primary, spill map[string]bool, policy *config.OverloadConfig) *Enclave {
	m.mu.Lock()
	defer m.mu.Unlock()
	enclave, _, overloaded, _, _, _ := m.selectServingLocked(order, false, primary, spill, policy, failedHost)
	if enclave == nil || overloaded {
		return nil
	}
	enclave.inflight.Add(1)
	BackendInflight.WithLabelValues(enclave.modelName, enclave.host).Inc()
	return enclave
}

func (m *Model) selectServingLocked(order []string, claimProbes bool, primary, spill map[string]bool, policy *config.OverloadConfig, excludedHost string) (*Enclave, *ProbeClaim, bool, time.Duration, float64, bool) {
	pools := []map[string]bool{primary}
	if len(spill) > 0 {
		pools = append(pools, spill)
	}
	var buckets [tierCount][2][]*Enclave
	var degraded []*Enclave
	var probes [2][]*Enclave
	waiting := make(map[*Enclave]float64)
	for pool, allowed := range pools {
		for _, enclave := range m.Enclaves {
			if (excludedHost != "" && enclave.host == excludedHost) || (allowed != nil && !allowed[enclave.host]) || !enclave.attestationValid(time.Now()) {
				continue
			}
			if !enclave.breakerClosed() {
				if excludedHost != "" {
					continue
				}
				probes[pool] = append(probes[pool], enclave)
				degraded = append(degraded, enclave)
				continue
			}
			tier := tierUnknown
			if enclave.metrics != nil {
				tier, waiting[enclave] = enclave.metrics.tier(policy, enclave.inflight.Load())
			}
			if enclave.LocalInflightCapReached(policy) {
				tier = tierOverloaded
			}
			if excludedHost != "" && tier == tierUnknown {
				continue
			}
			buckets[tier][pool] = append(buckets[tier][pool], enclave)
		}
	}
	for tier, byPool := range buckets {
		for pool, candidates := range byPool {
			if routingTier(tier) == tierPreferred && claimProbes {
				for _, enclave := range probes[pool] {
					if claim := enclave.claimProbe(); claim != nil {
						return enclave, claim, false, 0, 0, false
					}
				}
			}
			if len(candidates) == 0 {
				continue
			}
			enclave := m.pickTierLocked(order, candidates)
			if routingTier(tier) == tierOverloaded {
				return enclave, nil, true, policy.RetryAfter(), waiting[enclave], enclave.LocalInflightCapReached(policy)
			}
			if routingTier(tier) == tierUnknown {
				OverloadFailOpenTotal.WithLabelValues(enclave.modelName, enclave.host).Inc()
			}
			return enclave, nil, false, 0, waiting[enclave], false
		}
	}
	if len(degraded) > 0 {
		return degraded[0], nil, false, 0, 0, false
	}
	return nil, nil, false, 0, 0, false
}

func (m *Model) pickTierLocked(order []string, candidates []*Enclave) *Enclave {
	fallback := candidates[rand.IntN(len(candidates))]
	least := fallback
	for _, enclave := range candidates {
		if enclave.inflight.Load() < least.inflight.Load() {
			least = enclave
		}
	}
	for _, host := range order {
		for _, enclave := range candidates {
			if enclave.host != host {
				continue
			}
			if m.CacheRoute != nil && m.CacheRoute.MaxInflightDelta != nil {
				cap := *m.CacheRoute.MaxInflightDelta
				if cap >= 0 && enclave.inflight.Load()-least.inflight.Load() > int64(cap) {
					return least
				}
			}
			return enclave
		}
	}
	return fallback
}
