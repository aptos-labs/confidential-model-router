package manager

import (
	"os"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-model-router/config"
)

func TestLiveBackendMatchesPinnedRelease(t *testing.T) {
	if os.Getenv("APTOS_LIVE_ATTESTATION") == "" {
		t.Skip("set APTOS_LIVE_ATTESTATION=1 to verify the production backends")
	}
	verifier := newReleaseVerifier()
	verifier.setPins(
		map[string][]config.ReleasePin{
			legacyTestRepo: {{Tag: "v0.0.18", Digest: legacyTestDigest}},
		},
		[]config.ReleasePin{{Tag: "v0.0.47", Digest: legacyTestHWDigest}},
	)
	original := legacyVerifyTimeout
	legacyVerifyTimeout = 3 * time.Minute
	t.Cleanup(func() { legacyVerifyTimeout = original })

	for _, host := range []string{"host0.inference.aptoslabs.com", "host1.inference.aptoslabs.com"} {
		t.Run(host, func(t *testing.T) {
			verified, err := verifier.verify(host, legacyTestRepo)
			if err != nil {
				t.Fatal(err)
			}
			if verified.CodeTag != "v0.0.18" || verified.ConfigRepo != legacyTestRepo {
				t.Fatalf("accepted %s@%s", verified.ConfigRepo, verified.CodeTag)
			}
			if tlsKey, ok := verified.TLSPublicKeyFP(); !ok || tlsKey == "" {
				t.Fatal("verification has no TLS key")
			}
			if !verified.FreshnessExpiresAt.After(time.Now().Add(legacyVerificationTTL - time.Minute)) {
				t.Fatalf("freshness expires at %s", verified.FreshnessExpiresAt)
			}
		})
	}
}
