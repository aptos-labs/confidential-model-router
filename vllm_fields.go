package main

// vllmInternalFields are vLLM request fields for the serving deployment, not
// for API clients. vLLM v0.31.0 passes all three into the engine's sampling
// extra_args: kv_transfer_params and ec_transfer_params steer disaggregated
// KV and encoder-cache transfer, and vllm_xargs carries arbitrary engine
// arguments. The router strips them from every JSON body it forwards.
var vllmInternalFields = []string{"kv_transfer_params", "ec_transfer_params", "vllm_xargs"}

func stripVLLMInternalFields(body map[string]any) {
	for _, field := range vllmInternalFields {
		delete(body, field)
	}
}
