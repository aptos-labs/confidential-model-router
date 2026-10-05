// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-09-11.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package tokencount

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestOmniStreamPreservesModalityAndFinalAudioChunk(t *testing.T) {
	// Real audio frames exceed bufio's default 64 KiB line limit. The last
	// chunk may carry both audio content and finish_reason, not just a stop.
	audio := strings.Repeat("A", 96<<10)
	body := "data: {\"modality\":\"text\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"}}]}\n\n" +
		fmt.Sprintf("data: {\"modality\":\"audio\",\"choices\":[{\"index\":0,\"delta\":{\"content\":%q},\"finish_reason\":\"stop\"}]}\n\n", audio) +
		"data: [DONE]\n\n"
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	stream, _, err := ExtractTokensFromResponseWithHandler(response, "qwen3-omni", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("multimodal SSE changed: got %d bytes, want %d", len(got), len(body))
	}
}
