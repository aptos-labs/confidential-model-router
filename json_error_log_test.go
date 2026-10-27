package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestJSONErrorDoesNotLogMessage(t *testing.T) {
	var buf bytes.Buffer
	prev := log.StandardLogger().Out
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	secret := "PROMPT-CANARY-91bc"
	rec := httptest.NewRecorder()
	jsonError(rec, "Invalid request body: invalid character near "+secret, "invalid_request_error", http.StatusBadRequest)

	if strings.Contains(buf.String(), secret) {
		t.Fatalf("jsonError logged request content: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "status=400") {
		t.Fatalf("jsonError should log the status, got %q", buf.String())
	}
	if !strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("client response should still carry the full message")
	}
}
