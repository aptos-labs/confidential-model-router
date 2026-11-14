package manager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-model-router/config"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
	legacyattestation "github.com/tinfoilsh/verifier/attestation"
	legacysigstore "github.com/tinfoilsh/verifier/sigstore"
)

// Verification of backends uses github.com/tinfoilsh/verifier, the standalone
// verifier. The v3 attestation carries the sigstore-code bundle and the
// hardware-measurements bundle. Each is checked against a tag and digest pinned
// in the router image. GitHub's latest release is not consulted. The V3 SDK
// path is not used because it requires platform and freshness witnesses that
// only Tinfoil's release workflows can sign.
//
// The standalone verifier has no signed freshness witness. FreshnessExpiresAt
// is therefore a router-local bound on how long one successful verification may
// authorize new requests; the refresh cadence in attestationRefreshDue keeps it
// well ahead of that bound while the backend remains reachable.
//
// For TDX, the v3 attestation's captured Intel collateral is replayed as well.
// That checks TCB status, revocation, and the module policy. Its nextUpdate is
// not the freshness deadline above.
const (
	hardwareMeasurementsRepo = "tinfoilsh/hardware-measurements"
	legacyVerificationTTL    = 2 * attestationRenewalWindow
	legacyTrustRootMaxAge    = 24 * time.Hour
	maxAttestationDocBytes   = 8 << 20
	legacyVerifierName       = "github.com/tinfoilsh/verifier"
	legacyVerifierVersion    = "v0.10.11"
)

// Bounds one full verification, including the sigstore trust-root fetch. Var for tests.
var legacyVerifyTimeout = time.Minute

type releaseVerifier struct {
	mu         sync.Mutex
	sigstore   *legacysigstore.Client
	sigstoreAt time.Time
	sources    map[string]*legacyattestation.Measurement
	hardware   map[string][]*legacyattestation.HardwareMeasurement
	repos      map[string][]config.ReleasePin
	catalog    []config.ReleasePin

	now            func() time.Time
	fetchDocument  func(ctx context.Context, host string) (*legacyattestation.Document, error)
	verifyDocument func(*legacyattestation.Document) (*legacyattestation.Verification, error)
	fetchV3        func(ctx context.Context, host string) ([]byte, error)
	verifyCode     func(bundle []byte, repo, tag, digest string) (*legacyattestation.Measurement, error)
	verifyHardware func(bundle []byte, repo, tag, digest string) ([]*legacyattestation.HardwareMeasurement, error)
	checkTdx       func(doc *legacyattestation.Document, v3 []byte) error
}

var defaultReleaseVerifier = newReleaseVerifier()

func newReleaseVerifier() *releaseVerifier {
	r := &releaseVerifier{
		sources:        map[string]*legacyattestation.Measurement{},
		hardware:       map[string][]*legacyattestation.HardwareMeasurement{},
		repos:          map[string][]config.ReleasePin{},
		now:            time.Now,
		fetchDocument:  fetchAttestationDocument,
		verifyDocument: (*legacyattestation.Document).Verify,
		fetchV3:        fetchAttestationV3,
	}
	r.verifyCode = r.verifySigstoreCode
	r.verifyHardware = r.verifySigstoreHardware
	r.checkTdx = r.checkTdxPolicy
	return r
}

func verifyEnclave(host, repo string) (*verify.Verification, error) {
	return defaultReleaseVerifier.verify(host, repo)
}

// verify bounds the whole verification. Sigstore trust-root loading uses the
// default HTTP client without a deadline, so the work runs in a goroutine that
// is abandoned when the deadline passes.
func (r *releaseVerifier) verify(host, repo string) (*verify.Verification, error) {
	ctx, cancel := context.WithTimeout(context.Background(), legacyVerifyTimeout)
	defer cancel()
	type outcome struct {
		verification *verify.Verification
		err          error
	}
	done := make(chan outcome, 1)
	go func() {
		v, err := r.verifyWithin(ctx, host, repo)
		done <- outcome{v, err}
	}()
	select {
	case o := <-done:
		return o.verification, o.err
	case <-ctx.Done():
		return nil, fmt.Errorf("verifying %s: %w", host, ctx.Err())
	}
}

func (r *releaseVerifier) verifyWithin(ctx context.Context, host, repo string) (*verify.Verification, error) {
	doc, err := r.fetchDocument(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation: %w", err)
	}
	codePins, hardwarePins, err := r.pinsFor(repo)
	if err != nil {
		return nil, err
	}
	verified, err := r.verifyDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("verifying attestation document: %w", err)
	}
	if verified.Measurement == nil {
		return nil, errors.New("attestation document carries no measurement")
	}
	if verified.TLSPublicKeyFP == "" {
		return nil, errors.New("verified attestation has no TLS key fingerprint")
	}

	v3, err := r.fetchV3(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("fetching v3 attestation: %w", err)
	}
	code, err := codeReference(v3, repo)
	if err != nil {
		return nil, err
	}
	pin, ok := findReleasePin(codePins, code.tag, code.digest)
	if !ok {
		return nil, fmt.Errorf("release %s@%s is not pinned for %s", code.tag, code.digest, repo)
	}
	source, err := r.cachedCode(code.bundle, repo, pin.Tag, pin.Digest)
	if err != nil {
		return nil, fmt.Errorf("verifying release attestation of %s@%s: %w", repo, pin.Tag, err)
	}
	if err := verified.Measurement.Equals(source); err != nil {
		return nil, fmt.Errorf("enclave does not match %s@%s: %w", repo, pin.Tag, err)
	}
	tag := pin.Tag
	if verified.Measurement.Type == legacyattestation.TdxGuestV2 {
		if r.checkTdx != nil {
			if err := r.checkTdx(doc, v3); err != nil {
				return nil, fmt.Errorf("checking TDX platform policy: %w", err)
			}
		}
		// Release attestations cover RTMR1 and RTMR2 only; a nonzero RTMR3 means
		// the guest extended its measurements at runtime.
		if len(verified.Measurement.Registers) != 5 || verified.Measurement.Registers[4] != measurement.RTMR3_ZERO {
			return nil, errors.New("TDX RTMR3 is not zero")
		}
		catalog, err := hardwareReference(v3)
		if err != nil {
			return nil, err
		}
		hardwarePin, ok := findReleasePin(hardwarePins, catalog.tag, catalog.digest)
		if !ok {
			return nil, fmt.Errorf("hardware measurements %s@%s are not pinned", catalog.tag, catalog.digest)
		}
		hardware, err := r.cachedHardware(catalog.bundle, hardwareMeasurementsRepo, hardwarePin.Tag, hardwarePin.Digest)
		if err != nil {
			return nil, fmt.Errorf("verifying hardware measurements release: %w", err)
		}
		if _, err := legacyattestation.VerifyHardware(hardware, verified.Measurement); err != nil {
			return nil, fmt.Errorf("verifying hardware measurements: %w", err)
		}
	}

	now := r.now()
	material := []document.CryptoMaterialItem{
		{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: verified.TLSPublicKeyFP},
	}
	if verified.HPKEPublicKey != "" {
		material = append(material, document.CryptoMaterialItem{
			ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: verified.HPKEPublicKey,
		})
	}
	return &verify.Verification{
		ConfigRepo:         repo,
		CodeTag:            tag,
		CodeMeasurement:    toMeasurement(source),
		EnclaveMeasurement: toMeasurement(verified.Measurement),
		CryptoMaterial:     material,
		FreshnessExpiresAt: now.Add(legacyVerificationTTL),
		Metadata: verify.VerificationMetadata{
			Verifier:   verify.SoftwareIdentity{Name: legacyVerifierName, Version: legacyVerifierVersion},
			VerifiedAt: now,
		},
	}, nil
}

func toMeasurement(m *legacyattestation.Measurement) *measurement.Measurement {
	return &measurement.Measurement{
		Type:      measurement.PredicateType(m.Type),
		Registers: append([]string(nil), m.Registers...),
	}
}

func (r *releaseVerifier) sigstoreClient() (*legacysigstore.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sigstore != nil && r.now().Sub(r.sigstoreAt) < legacyTrustRootMaxAge {
		return r.sigstore, nil
	}
	client, err := legacysigstore.NewClient()
	if err != nil {
		return nil, fmt.Errorf("loading sigstore trust root: %w", err)
	}
	r.sigstore, r.sigstoreAt = client, r.now()
	return client, nil
}

// cachedCode verifies the bundle carried in the attestation, then remembers
// the result for those exact bytes. A later document that names the same
// digest with a different bundle is verified again.
func (r *releaseVerifier) cachedCode(bundle []byte, repo, tag, digest string) (*legacyattestation.Measurement, error) {
	key := bundleCacheKey(repo, tag, digest, bundle)
	r.mu.Lock()
	cached := r.sources[key]
	r.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
	source, err := r.verifyCode(bundle, repo, tag, digest)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.sources[key] = source
	r.mu.Unlock()
	return source, nil
}

func (r *releaseVerifier) cachedHardware(bundle []byte, repo, tag, digest string) ([]*legacyattestation.HardwareMeasurement, error) {
	key := bundleCacheKey(repo, tag, digest, bundle)
	r.mu.Lock()
	cached := r.hardware[key]
	r.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
	hardware, err := r.verifyHardware(bundle, repo, tag, digest)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.hardware[key] = hardware
	r.mu.Unlock()
	return hardware, nil
}

func bundleCacheKey(repo, tag, digest string, bundle []byte) string {
	sum := sha256.Sum256(bundle)
	return repo + "\x00" + tag + "\x00" + digest + "\x00" + hex.EncodeToString(sum[:])
}

func (r *releaseVerifier) verifySigstoreCode(bundle []byte, repo, tag, digest string) (*legacyattestation.Measurement, error) {
	client, err := r.sigstoreClient()
	if err != nil {
		return nil, err
	}
	return client.VerifyPinnedAttestation(bundle, digest, repo, tag)
}

func (r *releaseVerifier) verifySigstoreHardware(bundle []byte, repo, tag, digest string) ([]*legacyattestation.HardwareMeasurement, error) {
	client, err := r.sigstoreClient()
	if err != nil {
		return nil, err
	}
	return client.VerifyPinnedHardware(bundle, digest, repo, tag)
}

func (r *releaseVerifier) checkTdxPolicy(doc *legacyattestation.Document, v3 []byte) error {
	return verifyCapturedTdxPolicy(doc.Body, v3, r.now())
}

// fetchAttestationDocument disables connection reuse so backends that share an
// address cannot be served over a pooled connection negotiated for another SNI.
func fetchAttestationDocument(ctx context.Context, host string) (*legacyattestation.Document, error) {
	body, err := getAttestation(ctx, url.URL{Scheme: "https", Host: host, Path: "/.well-known/tinfoil-attestation"})
	if err != nil {
		return nil, err
	}
	var doc legacyattestation.Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func getAttestation(ctx context.Context, target url.URL) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport is not an *http.Transport")
	}
	transport = transport.Clone()
	transport.DisableKeepAlives = true
	client := &http.Client{Timeout: enclaveVerifyTimeout, Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAttestationDocBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", target.String(), resp.Status)
	}
	return body, nil
}
