package manager

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
	legacyattestation "github.com/tinfoilsh/verifier/attestation"
)

const (
	legacyTestRepo = "aptos-labs/confidential-glm-5-3-prod"
	legacyTestTLS  = "aa"
	legacyTestHPKE = "bb"
)

var (
	legacyTestMRTD  = strings.Repeat("1", 96)
	legacyTestRTMR0 = strings.Repeat("2", 96)
	legacyTestRTMR1 = strings.Repeat("3", 96)
	legacyTestRTMR2 = strings.Repeat("4", 96)
)

type legacyFixture struct {
	verifier      *releaseVerifier
	now           time.Time
	enclave       *legacyattestation.Measurement
	source        *legacyattestation.Measurement
	hardware      []*legacyattestation.HardwareMeasurement
	releaseChecks atomic.Int32
	hardwareReads atomic.Int32
	tag           string
	digest        string
}

func newLegacyFixture() *legacyFixture {
	f := &legacyFixture{
		now: time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC),
		enclave: &legacyattestation.Measurement{
			Type:      legacyattestation.TdxGuestV2,
			Registers: []string{legacyTestMRTD, legacyTestRTMR0, legacyTestRTMR1, legacyTestRTMR2, measurement.RTMR3_ZERO},
		},
		source: &legacyattestation.Measurement{
			Type:      legacyattestation.SnpTdxMultiPlatformV1,
			Registers: []string{strings.Repeat("5", 96), legacyTestRTMR1, legacyTestRTMR2},
		},
		hardware: []*legacyattestation.HardwareMeasurement{
			{ID: "other@x", MRTD: strings.Repeat("9", 96), RTMR0: strings.Repeat("9", 96)},
			{ID: "large_1d_v011@x", MRTD: legacyTestMRTD, RTMR0: legacyTestRTMR0},
		},
		tag:    "v0.0.18",
		digest: "digest-v0.0.18",
	}
	f.verifier = &releaseVerifier{
		sources:  map[string]*legacyattestation.Measurement{},
		hardware: map[string][]*legacyattestation.HardwareMeasurement{},
		now:      func() time.Time { return f.now },
		fetchDocument: func(context.Context, string) (*legacyattestation.Document, error) {
			return &legacyattestation.Document{}, nil
		},
		verifyDocument: func(*legacyattestation.Document) (*legacyattestation.Verification, error) {
			return &legacyattestation.Verification{Measurement: f.enclave, TLSPublicKeyFP: legacyTestTLS, HPKEPublicKey: legacyTestHPKE}, nil
		},
		latestTag:    func(string) (string, error) { return f.tag, nil },
		digestForTag: func(string, string) (string, error) { return f.digest, nil },
		latestDigest: func(string) (string, error) { return "hardware-digest", nil },
		verifyRelease: func(string, string) (*legacyattestation.Measurement, error) {
			f.releaseChecks.Add(1)
			return f.source, nil
		},
		fetchHardware: func(string) ([]*legacyattestation.HardwareMeasurement, error) {
			f.hardwareReads.Add(1)
			return f.hardware, nil
		},
	}
	return f
}

func (f *legacyFixture) verify(t *testing.T) (string, error) {
	t.Helper()
	v, err := f.verifier.verifyWithin(context.Background(), "host.example", legacyTestRepo)
	if err != nil {
		return "", err
	}
	tls, ok := v.TLSPublicKeyFP()
	if !ok {
		t.Fatal("verification has no TLS key")
	}
	return tls, nil
}

func TestLegacyVerificationProducesRouterVerification(t *testing.T) {
	f := newLegacyFixture()
	v, err := f.verifier.verifyWithin(context.Background(), "host.example", legacyTestRepo)
	if err != nil {
		t.Fatal(err)
	}
	if tls, ok := v.TLSPublicKeyFP(); !ok || tls != legacyTestTLS {
		t.Fatalf("TLS key = %q, %v", tls, ok)
	}
	if hpke, ok := v.HPKEPublicKey(); !ok || hpke != legacyTestHPKE {
		t.Fatalf("HPKE key = %q, %v", hpke, ok)
	}
	if v.CodeTag != f.tag || v.ConfigRepo != legacyTestRepo {
		t.Fatalf("tag/repo = %q/%q", v.CodeTag, v.ConfigRepo)
	}
	if v.EnclaveMeasurement.Type != measurement.TdxGuestV2 || v.CodeMeasurement.Type != measurement.SnpTdxMultiPlatformV1 {
		t.Fatalf("measurement types = %s/%s", v.EnclaveMeasurement.Type, v.CodeMeasurement.Type)
	}
	if want := f.now.Add(legacyVerificationTTL); !v.FreshnessExpiresAt.Equal(want) {
		t.Fatalf("expiry = %s, want %s", v.FreshnessExpiresAt, want)
	}
	if v.Metadata.Verifier.Name != legacyVerifierName || !v.Metadata.VerifiedAt.Equal(f.now) {
		t.Fatalf("metadata = %+v", v.Metadata)
	}
}

// The router refreshes when the expiry is inside the renewal window; the local
// bound must leave room for the hourly cadence instead of refreshing on every sync.
func TestLegacyVerificationTTLLeavesRefreshHeadroom(t *testing.T) {
	if legacyVerificationTTL <= attestationRenewalWindow {
		t.Fatalf("TTL %s must exceed renewal window %s", legacyVerificationTTL, attestationRenewalWindow)
	}
}

func TestLegacyVerificationRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*legacyFixture)
		want   string
	}{
		{"rtmr2 differs from release", func(f *legacyFixture) { f.enclave.Registers[3] = strings.Repeat("7", 96) }, "does not match"},
		{"rtmr1 differs from release", func(f *legacyFixture) { f.enclave.Registers[2] = strings.Repeat("7", 96) }, "does not match"},
		{"nonzero rtmr3", func(f *legacyFixture) { f.enclave.Registers[4] = strings.Repeat("7", 96) }, "RTMR3"},
		{"missing rtmr3", func(f *legacyFixture) { f.enclave.Registers = f.enclave.Registers[:4] }, "RTMR3"},
		{"unknown hardware", func(f *legacyFixture) { f.hardware = f.hardware[:1] }, "hardware"},
		{"hardware mrtd only", func(f *legacyFixture) { f.hardware[1].RTMR0 = strings.Repeat("9", 96) }, "hardware"},
		{"release verification fails", func(f *legacyFixture) {
			f.verifier.verifyRelease = func(string, string) (*legacyattestation.Measurement, error) { return nil, errors.New("bad bundle") }
		}, "bad bundle"},
		{"document verification fails", func(f *legacyFixture) {
			f.verifier.verifyDocument = func(*legacyattestation.Document) (*legacyattestation.Verification, error) {
				return nil, errors.New("bad quote")
			}
		}, "bad quote"},
		{"document fetch fails", func(f *legacyFixture) {
			f.verifier.fetchDocument = func(context.Context, string) (*legacyattestation.Document, error) {
				return nil, errors.New("unreachable")
			}
		}, "unreachable"},
		{"no TLS key", func(f *legacyFixture) {
			f.verifier.verifyDocument = func(*legacyattestation.Document) (*legacyattestation.Verification, error) {
				return &legacyattestation.Verification{Measurement: f.enclave}, nil
			}
		}, "TLS key"},
		{"latest release unavailable", func(f *legacyFixture) {
			f.verifier.latestTag = func(string) (string, error) { return "", errors.New("proxy down") }
		}, "proxy down"},
		{"hardware release unavailable", func(f *legacyFixture) {
			f.verifier.latestDigest = func(string) (string, error) { return "", errors.New("hw proxy down") }
		}, "hw proxy down"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLegacyFixture()
			tc.mutate(f)
			if _, err := f.verify(t); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestLegacyVerificationTracksLatestRelease(t *testing.T) {
	f := newLegacyFixture()
	if _, err := f.verify(t); err != nil {
		t.Fatal(err)
	}

	// A newer release with a different measurement stops accepting the old enclave.
	f.tag, f.digest = "v0.0.19", "digest-v0.0.19"
	f.source = &legacyattestation.Measurement{
		Type:      legacyattestation.SnpTdxMultiPlatformV1,
		Registers: []string{strings.Repeat("5", 96), legacyTestRTMR1, strings.Repeat("8", 96)},
	}
	if _, err := f.verify(t); err == nil || !strings.Contains(err.Error(), "v0.0.19") {
		t.Fatalf("old enclave accepted against newer release: %v", err)
	}
}

func TestLegacyVerificationCachesImmutableReleaseData(t *testing.T) {
	f := newLegacyFixture()
	for range 3 {
		if _, err := f.verify(t); err != nil {
			t.Fatal(err)
		}
	}
	if f.releaseChecks.Load() != 1 || f.hardwareReads.Load() != 1 {
		t.Fatalf("release checks = %d, hardware reads = %d; want 1 each", f.releaseChecks.Load(), f.hardwareReads.Load())
	}

	f.tag, f.digest = "v0.0.19", "digest-v0.0.19"
	if _, err := f.verify(t); err != nil {
		t.Fatal(err)
	}
	if f.releaseChecks.Load() != 2 {
		t.Fatalf("a new digest must be verified, release checks = %d", f.releaseChecks.Load())
	}
}

func TestLegacyVerificationSkipsHardwareForSEV(t *testing.T) {
	f := newLegacyFixture()
	f.enclave = &legacyattestation.Measurement{Type: legacyattestation.SevGuestV2, Registers: []string{f.source.Registers[0]}}
	f.hardware = nil
	if _, err := f.verify(t); err != nil {
		t.Fatal(err)
	}
	if f.hardwareReads.Load() != 0 {
		t.Fatal("SEV-SNP verification must not consult TDX hardware measurements")
	}
}

func TestLegacyVerificationHonorsDeadline(t *testing.T) {
	f := newLegacyFixture()
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	f.verifier.fetchDocument = func(ctx context.Context, _ string) (*legacyattestation.Document, error) {
		<-block
		return nil, ctx.Err()
	}
	original := legacyVerifyTimeout
	legacyVerifyTimeout = 50 * time.Millisecond
	t.Cleanup(func() { legacyVerifyTimeout = original })
	if _, err := f.verifier.verify("host.example", legacyTestRepo); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
}
