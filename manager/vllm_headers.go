package manager

import (
	"net/http"
	"strings"
)

// The router owns vLLM's engine and request-routing controls. In particular,
// X-Vllm-Priority would undo the router's priority injection, and the other
// names select load reporting, sticky sessions, data-parallel ranks, or
// tracing. Match case-insensitively because direct map writes need not use
// canonical names, and delete every value for each matching name.
const vllmHeaderPrefix = "X-Vllm-"

// X-Request-Id and body request_id deliberately stay unchanged. Existing
// public invoices use the echoed ID. Changing that ownership needs a migration.
var vllmControlHeaders = []string{
	"Endpoint-Load-Metrics-Format",
	"X-Session-ID",
	"X-Data-Parallel-Rank",
	"Traceparent",
	"Tracestate",
}

const vllmLoadResponseHeader = "Endpoint-Load-Metrics"

func isVLLMHeader(name string) bool {
	if len(name) >= len(vllmHeaderPrefix) && strings.EqualFold(name[:len(vllmHeaderPrefix)], vllmHeaderPrefix) {
		return true
	}
	for _, blocked := range vllmControlHeaders {
		if strings.EqualFold(name, blocked) {
			return true
		}
	}
	return false
}

// withoutVLLMHeaders returns req itself when it carries no engine-control
// header, else a clone without them; a RoundTripper must not mutate its request.
func withoutVLLMHeaders(req *http.Request) *http.Request {
	found := false
	for name := range req.Header {
		if isVLLMHeader(name) {
			found = true
			break
		}
	}
	if !found {
		return req
	}
	out := req.Clone(req.Context())
	for name := range out.Header {
		if isVLLMHeader(name) {
			delete(out.Header, name)
		}
	}
	return out
}

// vLLM emits this load report on non-streaming responses. No authenticated
// internal hop consumes response load headers today, so remove every value at
// the transport boundary before either the public proxy or a tool client sees it.
// X-Request-Id remains intact for the existing public invoice behavior.
func withoutVLLMLoadHeaders(resp *http.Response) {
	for name := range resp.Header {
		if strings.EqualFold(name, vllmLoadResponseHeader) {
			delete(resp.Header, name)
		}
	}
}
