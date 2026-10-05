// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-10-05.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testCommit = "b8c36d88e332a361f944ec46446f9a57d5d947d3"

func withBuildInfo(t *testing.T, v, src string) {
	t.Helper()
	oldVersion, oldSource := version, sourceURL
	version, sourceURL = v, src
	t.Cleanup(func() { version, sourceURL = oldVersion, oldSource })
}

func TestCorrespondingSourceURL(t *testing.T) {
	tests := []struct {
		name, version, source, want string
	}{
		{"aptos build pins the exact commit", "aptos-" + testCommit, "", sourceRepoURL + "/tree/" + testCommit},
		{"explicit override wins", "aptos-" + testCommit, "https://example.com/src.tar.gz", "https://example.com/src.tar.gz"},
		{"dev build falls back to the repository", "dev", "", sourceRepoURL},
		{"short sha is not trusted as a commit", "aptos-b8c36d8", "", sourceRepoURL},
		{"uppercase sha is not a git commit id", "aptos-B8C36D88E332A361F944EC46446F9A57D5D947D3", "", sourceRepoURL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withBuildInfo(t, tt.version, tt.source)
			if got := correspondingSourceURL(); got != tt.want {
				t.Fatalf("correspondingSourceURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSourceOfferEndpoints(t *testing.T) {
	withBuildInfo(t, "aptos-"+testCommit, "")
	want := sourceRepoURL + "/tree/" + testCommit
	for _, path := range []string{"/", "/source"} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			newRouterHandler(nil, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not JSON: %v", err)
			}
			if body["license"] != licenseID || body["source"] != want ||
				body["version"] != "aptos-"+testCommit || body["notice"] == "" {
				t.Fatalf("unexpected source offer body: %v", body)
			}
			if rec.Header().Get(sourceOfferHeader) != want || rec.Header().Get(licenseHeader) != licenseID {
				t.Fatalf("missing source offer headers: %v", rec.Header())
			}
		})
	}
}

func TestErrorResponsesCarrySourceOffer(t *testing.T) {
	withBuildInfo(t, "aptos-"+testCommit, "")
	rec := httptest.NewRecorder()
	newRouterHandler(nil, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/videos/sync", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if rec.Header().Get(sourceOfferHeader) == "" || rec.Header().Get(licenseHeader) != licenseID {
		t.Fatalf("error response lacks source offer headers: %v", rec.Header())
	}
}
