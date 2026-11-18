package manager

import (
	"net/http"
	"strings"
)

// vllmHeaderPrefix marks request headers that vLLM reads as engine controls.
// vLLM v0.31.0 takes X-Vllm-Priority over the body's priority field, so a
// client value would undo the router's priority injection and rate-limit
// demotion. The router owns these controls: no X-Vllm-* header reaches a
// backend, whichever code path built the request.
const vllmHeaderPrefix = "X-Vllm-"

func isVLLMHeader(name string) bool {
	return len(name) >= len(vllmHeaderPrefix) && strings.EqualFold(name[:len(vllmHeaderPrefix)], vllmHeaderPrefix)
}

// withoutVLLMHeaders returns req itself when it carries no X-Vllm-* header,
// else a clone without them; a RoundTripper must not mutate its request. The
// match ignores case because a header map written directly need not hold
// canonical names.
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
