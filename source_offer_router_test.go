//go:build routertest

// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-10-05.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tinfoilsh/confidential-model-router/manager"
)

func TestHealthCarriesSourceOffer(t *testing.T) {
	withBuildInfo(t, "aptos-"+testCommit, "")
	rec := httptest.NewRecorder()
	// A test manager has never synced, so /health reports "not ready". The
	// source offer must still be present on that response.
	em := manager.NewVideoRouterTestManager(nil)
	newRouterHandler(em, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 for an unsynced manager", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body["license"] != licenseID || body["source"] != sourceRepoURL+"/tree/"+testCommit {
		t.Fatalf("health body lacks the source offer: %v", body)
	}
	if rec.Header().Get(sourceOfferHeader) == "" || rec.Header().Get(licenseHeader) != licenseID {
		t.Fatalf("health response lacks source offer headers: %v", rec.Header())
	}
}
