// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-11-11.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package manager

import (
	"context"
	"errors"
	"net/http"
)

// errRetryElsewhere stops the reverse proxy from relaying a retryable backend
// failure: ModifyResponse returns it, and the ErrorHandler then leaves the
// client response untouched.
var errRetryElsewhere = errors.New("backend failed before any response byte reached the client")

// DispatchAttempt is one public dispatch's retry contract between the handler
// and the per-enclave proxy. The handler sets AllowRetry when it can replay
// the request body and another enclave can serve the request. The proxy then
// keeps a retryable failure away from the client and marks the attempt, so
// the handler dispatches again elsewhere. Nothing has been written to the
// client when Retry reports true.
type DispatchAttempt struct {
	AllowRetry bool

	retry  bool
	reason string
}

// Retry reports whether the proxy handed the request back for another
// enclave. Safe on a nil attempt.
func (a *DispatchAttempt) Retry() bool { return a != nil && a.retry }

// Reason is the failure reason label of the attempt that was handed back.
func (a *DispatchAttempt) Reason() string {
	if a == nil {
		return ""
	}
	return a.reason
}

// handBack marks the attempt for a retry when the handler allowed one.
func (a *DispatchAttempt) handBack(reason string) bool {
	if a == nil || !a.AllowRetry {
		return false
	}
	a.retry = true
	a.reason = reason
	return true
}

type dispatchAttemptKey struct{}

// WithDispatchAttempt attaches the attempt to the context of the one request
// dispatched for it.
func WithDispatchAttempt(ctx context.Context, attempt *DispatchAttempt) context.Context {
	return context.WithValue(ctx, dispatchAttemptKey{}, attempt)
}

func dispatchAttemptFromContext(ctx context.Context) *DispatchAttempt {
	attempt, _ := ctx.Value(dispatchAttemptKey{}).(*DispatchAttempt)
	return attempt
}

// retryableStatus reports whether a backend status means "this host cannot
// serve now" rather than "this request is bad". A 500 is excluded: it usually
// follows the request to the next host.
func retryableStatus(code int) bool {
	switch code {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryableTransportReason reports whether a classifyProxyError reason leaves
// the request safe to send to another enclave: no response header arrived.
// A timeout is excluded, because the backend may still be working on the
// request, and a cancellation is the client's own.
func retryableTransportReason(reason string) bool {
	switch reason {
	case "connection_refused", "connection_reset", "dns_error", "tls_error", "tls_mismatch", "transport_error":
		return true
	}
	return false
}
