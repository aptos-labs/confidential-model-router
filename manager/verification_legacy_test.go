package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-model-router/config"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
	legacyattestation "github.com/tinfoilsh/verifier/attestation"
)

const (
	legacyTestRepo     = "aptos-labs/confidential-glm-5-3-prod"
	legacyTestTLS      = "aa"
	legacyTestHPKE     = "bb"
	legacyTestDigest   = "47b4d1472a067966473ecdc0b79d3d92ffb2b9f19b81e92f37171cb961372252"
	legacyTestHWDigest = "d80f92482bfffc1033d2e4b88c0df6e1090e8825d91d43715beb06742ec6a96b"
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
	hwTag         string
	hwDigest      string
	codeBundle    string
	hwBundle      string
	repoClaim     string
	omitCode      bool
	omitHardware  bool
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
		tag:        "v0.0.18",
		digest:     legacyTestDigest,
		hwTag:      "v0.0.47",
		hwDigest:   legacyTestHWDigest,
		codeBundle: `{"marker":"code"}`,
		hwBundle:   `{"marker":"hardware"}`,
		repoClaim:  legacyTestRepo,
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
		fetchV3: func(context.Context, string) ([]byte, error) { return f.attestationV3(), nil },
		verifyCode: func(bundle []byte, repo, tag, digest string) (*legacyattestation.Measurement, error) {
			f.releaseChecks.Add(1)
			if repo != legacyTestRepo || tag != "v0.0.18" || digest != legacyTestDigest || string(bundle) != f.codeBundle {
				return nil, errors.New("unexpected code bundle")
			}
			return f.source, nil
		},
		verifyHardware: func(bundle []byte, repo, tag, digest string) ([]*legacyattestation.HardwareMeasurement, error) {
			f.hardwareReads.Add(1)
			if repo != hardwareMeasurementsRepo || tag != "v0.0.47" || digest != legacyTestHWDigest || string(bundle) != f.hwBundle {
				return nil, errors.New("unexpected hardware bundle")
			}
			return f.hardware, nil
		},
	}
	f.verifier.setPins(
		map[string][]config.ReleasePin{legacyTestRepo: {{Tag: f.tag, Digest: f.digest}}},
		[]config.ReleasePin{{Tag: f.hwTag, Digest: f.hwDigest}},
	)
	return f
}

func (f *legacyFixture) attestationV3() []byte {
	var collateral []any
	if !f.omitCode {
		collateral = append(collateral, legacyReference("code-provenance", sigstoreCodeFormat, f.repoClaim, f.tag, f.digest, f.codeBundle))
	}
	if !f.omitHardware {
		collateral = append(collateral, legacyReference("hardware-measurements", sigstoreHardwareFormat, hardwareMeasurementsRepo, f.hwTag, f.hwDigest, f.hwBundle))
	}
	body, err := json.Marshal(map[string]any{"collateral": collateral})
	if err != nil {
		panic(err)
	}
	return body
}

func legacyReference(id, format, repo, tag, digest, bundle string) map[string]any {
	return map[string]any{
		"id": id, "role": referenceValuesRole, "format": format, "subjects": []string{cpuCollateralSubject},
		"data": map[string]any{"repo": repo, "tag": tag, "digest": digest, "sigstore_bundle": json.RawMessage(bundle)},
	}
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
			f.verifier.verifyCode = func([]byte, string, string, string) (*legacyattestation.Measurement, error) {
				return nil, errors.New("bad bundle")
			}
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
		{"unpinned release", func(f *legacyFixture) {
			f.tag = "v0.0.19"
			f.digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, "not pinned"},
		{"unpinned hardware", func(f *legacyFixture) {
			f.hwTag = "v0.0.48"
			f.hwDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}, "not pinned"},
		{"provenance names another repo", func(f *legacyFixture) { f.repoClaim = "aptos-labs/other" }, "names"},
		{"missing code provenance", func(f *legacyFixture) { f.omitCode = true }, "no code provenance"},
		{"missing hardware provenance", func(f *legacyFixture) { f.omitHardware = true }, "no hardware"},
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

func TestLegacyVerificationRejectsUnpinnedRelease(t *testing.T) {
	f := newLegacyFixture()
	if _, err := f.verify(t); err != nil {
		t.Fatal(err)
	}
	f.tag = "v0.0.19"
	f.digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	f.source = &legacyattestation.Measurement{
		Type:      legacyattestation.SnpTdxMultiPlatformV1,
		Registers: []string{strings.Repeat("5", 96), legacyTestRTMR1, legacyTestRTMR2},
	}
	if _, err := f.verify(t); err == nil || !strings.Contains(err.Error(), "v0.0.19") {
		t.Fatalf("unpinned release accepted: %v", err)
	}
	if f.releaseChecks.Load() != 1 {
		t.Fatalf("unpinned release was sent to sigstore, checks = %d", f.releaseChecks.Load())
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

	f.codeBundle = `{"marker":"replacement"}`
	if _, err := f.verify(t); err != nil {
		t.Fatal(err)
	}
	if f.releaseChecks.Load() != 2 {
		t.Fatalf("a new bundle must be verified, release checks = %d", f.releaseChecks.Load())
	}
}

func TestLegacyVerificationChecksTdxPolicyOnly(t *testing.T) {
	tdx := newLegacyFixture()
	var checked atomic.Int32
	tdx.verifier.checkTdx = func(_ *legacyattestation.Document, v3 []byte) error {
		checked.Add(1)
		if !strings.Contains(string(v3), sigstoreCodeFormat) {
			t.Fatal("TDX policy did not receive the v3 document")
		}
		return nil
	}
	if _, err := tdx.verify(t); err != nil {
		t.Fatal(err)
	}
	if checked.Load() != 1 {
		t.Fatalf("TDX policy checks = %d", checked.Load())
	}

	sev := newLegacyFixture()
	sev.enclave = &legacyattestation.Measurement{Type: legacyattestation.SevGuestV2, Registers: []string{sev.source.Registers[0]}}
	sev.verifier.checkTdx = func(*legacyattestation.Document, []byte) error {
		t.Fatal("SEV verification consulted the TDX policy")
		return nil
	}
	if _, err := sev.verify(t); err != nil {
		t.Fatal(err)
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

func TestBackendPinsAreRequiredToStart(t *testing.T) {
	repos, catalog := defaultReleaseVerifier.pinSnapshot()
	t.Cleanup(func() { defaultReleaseVerifier.setPins(repos, catalog) })

	_, err := NewEnclaveManager([]byte("models:\n  glm:\n    repo: "+legacyTestRepo+"\n    enclaves: [h.example]\n"), "https://control.example", "", "", "", "", "", time.Minute, false)
	if err == nil || !strings.Contains(err.Error(), "no pinned release") {
		t.Fatalf("err = %v, want a missing pin", err)
	}

	body := fmt.Sprintf("hardware_measurements: [v0.0.47@%s]\nmodels:\n  glm:\n    repo: %s\n    releases: [v0.0.18@%s]\n    enclaves: [h.example]\n", legacyTestHWDigest, legacyTestRepo, legacyTestDigest)
	em, err := NewEnclaveManager([]byte(body), "https://control.example", "", "", "", "", "", time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	pins, hardware, err := defaultReleaseVerifier.pinsFor(legacyTestRepo)
	if err != nil || len(pins) != 1 || pins[0].Tag != "v0.0.18" || pins[0].Digest != legacyTestDigest || len(hardware) != 1 {
		t.Fatalf("installed pins = %+v %+v err=%v", pins, hardware, err)
	}
	model, ok := em.GetModel("glm")
	if !ok || len(model.pinnedReleases) != 1 || em.hardwarePins[0] != "v0.0.47@"+legacyTestHWDigest {
		t.Fatalf("model pins = %+v hardware = %+v", model, em.hardwarePins)
	}
}
