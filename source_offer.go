// Copyright 2026 Aptos Labs. Added to tinfoilsh/confidential-model-router on 2026-10-05.
// Licensed under the GNU Affero General Public License v3, like the rest of this program.

package main

import (
	"net/http"
	"strings"
)

// correspondingSourceURL returns the location of the Corresponding Source of
// this exact build, which AGPL-3.0 section 13 requires us to offer to every
// user who interacts with the router over the network.
func correspondingSourceURL() string {
	if sourceURL != "" {
		return sourceURL
	}
	if sha, ok := strings.CutPrefix(version, "aptos-"); ok && isFullCommitSHA(sha) {
		return sourceRepoURL + "/tree/" + sha
	}
	return sourceRepoURL
}

// sourceOffer is the body served at "/" and "/source".
func sourceOffer() map[string]any {
	return map[string]any{
		"license": licenseID,
		"source":  correspondingSourceURL(),
		"version": version,
		"notice":  sourceOfferMessage,
	}
}

// setSourceOfferHeaders adds the source offer to a response. Proxied
// responses keep these headers because the reverse proxy adds upstream
// headers to the same header map instead of replacing it.
func setSourceOfferHeaders(h http.Header) {
	h.Set(sourceOfferHeader, correspondingSourceURL())
	h.Set(licenseHeader, licenseID)
}

func isFullCommitSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
