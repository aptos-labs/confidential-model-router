package billing

import (
	"bytes"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// The billing log line runs at INFO for every request. It must carry no part
// of the API key, while the usage reporter still receives the whole key.
func TestBillingLogOmitsAPIKey(t *testing.T) {
	const apiKey = "sk-abc-1234567890-wxyz"
	var logs bytes.Buffer
	logger := log.StandardLogger()
	out, level := logger.Out, logger.GetLevel()
	logger.SetOutput(&logs)
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() { logger.SetOutput(out); logger.SetLevel(level) })

	c, readBatch := setupCollectorTest(t)
	c.AddEvent(Event{
		Timestamp:        time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC),
		UserID:           "user-1",
		Model:            "glm-5-3",
		PromptTokens:     3,
		CompletionTokens: 2,
		TotalTokens:      5,
		RequestID:        "req-1",
		APIKey:           apiKey,
		CustomerRequests: 1,
	})

	line := logs.String()
	if !strings.Contains(line, "billing_event") || !strings.Contains(line, "req-1") {
		t.Fatalf("billing log line missing: %q", line)
	}
	for _, fragment := range []string{"api_key", "sk-", "wxyz", "1234567890"} {
		if strings.Contains(line, fragment) {
			t.Fatalf("billing log carries %q: %q", fragment, line)
		}
	}
	if got := readBatch().Events[0].APIKey; got != apiKey {
		t.Fatalf("reporter API key = %q, want the full key", got)
	}
}
