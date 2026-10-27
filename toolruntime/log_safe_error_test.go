package toolruntime

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestLogSafeErrorRedactsUpstreamBody(t *testing.T) {
	secret := "PROMPT-CANARY-7f3a"
	err := &upstreamError{statusCode: 400, body: []byte(`{"error":{"message":"bad input: ` + secret + `"}}`)}

	if !strings.Contains(err.Error(), secret) {
		t.Fatalf("Error() should keep the body for client-facing paths")
	}
	got := LogSafeError(err)
	if strings.Contains(got, secret) {
		t.Fatalf("LogSafeError leaked upstream body: %q", got)
	}
	if !strings.Contains(got, "status 400") {
		t.Fatalf("LogSafeError should keep the status code, got %q", got)
	}

	wrapped := fmt.Errorf("tool loop: %w", err)
	if got := LogSafeError(wrapped); strings.Contains(got, secret) {
		t.Fatalf("LogSafeError leaked body through a wrapped error: %q", got)
	}
}

func TestLogSafeErrorPassesThroughOtherErrors(t *testing.T) {
	if got := LogSafeError(errors.New("dial timeout")); got != "dial timeout" {
		t.Fatalf("unexpected: %q", got)
	}
}
