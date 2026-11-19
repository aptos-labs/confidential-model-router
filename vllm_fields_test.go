package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const vllmInternalFieldsJSON = `"kv_transfer_params":{"prompt_token_ids":[1,2,3]},"ec_transfer_params":{"do_remote_encode":true},"vllm_xargs":{"session_id":"other-session"}`

func TestStripVLLMInternalFields(t *testing.T) {
	body, err := decodeJSONBody([]byte(`{"model":"m",` + vllmInternalFieldsJSON + `,"vllm_other":1}`))
	if err != nil {
		t.Fatal(err)
	}
	stripVLLMInternalFields(body)
	for _, field := range vllmInternalFields {
		if _, ok := body[field]; ok {
			t.Fatalf("%s survived", field)
		}
	}
	if body["model"] != "m" || body["vllm_other"] == nil {
		t.Fatalf("unrelated fields changed: %v", body)
	}
	stripVLLMInternalFields(nil)
}

func TestInputTokensDropVLLMInternalFields(t *testing.T) {
	for path, fields := range map[string]string{
		chatInputTokensPath:      `"messages":[{"role":"user","content":"hi"}]`,
		responsesInputTokensPath: `"input":"hi"`,
	} {
		t.Run(path, func(t *testing.T) {
			var dispatched map[string]any
			dispatch := func(_ context.Context, _, _ string, body []byte, _ http.Header) (*http.Response, error) {
				if err := json.Unmarshal(body, &dispatched); err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"count":1}`))}, nil
			}
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"model":"m",`+fields+`,`+vllmInternalFieldsJSON+`}`))
			rec := httptest.NewRecorder()
			handleInputTokens(rec, req, "secret-key", nil, dispatch)
			if rec.Code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
			}
			for _, field := range vllmInternalFields {
				if _, ok := dispatched[field]; ok {
					t.Fatalf("/tokenize body carries %s", field)
				}
			}
		})
	}
}
