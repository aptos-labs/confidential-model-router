package main

// vllmInternalFields are vLLM request fields for the serving deployment, not
// for API clients. kv_transfer_params and ec_transfer_params steer disaggregated
// cache transfer, vllm_xargs carries arbitrary engine arguments, and session_id
// selects sticky engine sessions. The router strips them from every JSON body
// it forwards. Body request_id remains client-controlled for compatibility:
// vLLM echoes it through X-Request-Id, which existing public invoices use. Any
// change to request-ID ownership needs a compatible invoice migration first,
// and this value must not become a usage-admission identifier without one.
var vllmInternalFields = []string{"kv_transfer_params", "ec_transfer_params", "vllm_xargs", "session_id"}

func stripVLLMInternalFields(body map[string]any) {
	for _, field := range vllmInternalFields {
		delete(body, field)
	}
}
