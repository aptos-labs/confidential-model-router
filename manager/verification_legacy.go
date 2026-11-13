package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
	legacyattestation "github.com/tinfoilsh/verifier/attestation"
	legacygithub "github.com/tinfoilsh/verifier/github"
	legacysigstore "github.com/tinfoilsh/verifier/sigstore"
)

// Verification of backends uses github.com/tinfoilsh/verifier, the standalone
// verifier. It authenticates the enclave against the latest GitHub release of
// the model repo (sigstore-attested RTMR1/RTMR2) and, for TDX, against the
// latest tinfoilsh/hardware-measurements release (MRTD/RTMR0). The V3 SDK path
// is not used because it requires platform and freshness witnesses that only
// Tinfoil's release workflows can sign.
//
// The standalone verifier has no signed freshness witness. FreshnessExpiresAt
// is therefore a router-local bound on how long one successful verification may
// authorize new requests; the refresh cadence in attestationRefreshDue keeps it
// well ahead of that bound while upstream sources are reachable.
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

// Bounds one full verification, including GitHub and sigstore fetches. Var for tests.
var legacyVerifyTimeout = time.Minute

type releaseVerifier struct {
	mu         sync.Mutex
	sigstore   *legacysigstore.Client
	sigstoreAt time.Time
	sources    map[string]*legacyattestation.Measurement
	hardware   map[string][]*legacyattestation.HardwareMeasurement

	now            func() time.Time
	fetchDocument  func(ctx context.Context, host string) (*legacyattestation.Document, error)
	verifyDocument func(*legacyattestation.Document) (*legacyattestation.Verification, error)
	latestTag      func(repo string) (string, error)
	digestForTag   func(repo, tag string) (string, error)
	latestDigest   func(repo string) (string, error)
	verifyRelease  func(repo, digest string) (*legacyattestation.Measurement, error)
	fetchHardware  func(digest string) ([]*legacyattestation.HardwareMeasurement, error)
	checkTdx       func(ctx context.Context, host string, doc *legacyattestation.Document) error
}

var defaultReleaseVerifier = newReleaseVerifier()

func newReleaseVerifier() *releaseVerifier {
	r := &releaseVerifier{
		sources:        map[string]*legacyattestation.Measurement{},
		hardware:       map[string][]*legacyattestation.HardwareMeasurement{},
		now:            time.Now,
		fetchDocument:  fetchAttestationDocument,
		verifyDocument: (*legacyattestation.Document).Verify,
		latestTag:      legacygithub.FetchLatestTag,
		digestForTag:   legacygithub.FetchDigest,
		latestDigest:   legacygithub.FetchLatestDigest,
	}
	r.verifyRelease = r.verifySigstoreRelease
	r.fetchHardware = r.fetchSigstoreHardware
	r.checkTdx = r.checkTdxPolicy
	return r
}

func verifyEnclave(host, repo string) (*verify.Verification, error) {
	return defaultReleaseVerifier.verify(host, repo)
}

// verify bounds the whole verification. The standalone verifier's GitHub and
// sigstore helpers use the default HTTP client without deadlines, so the work
// runs in a goroutine that is abandoned when the deadline passes.
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

	tag, source, err := r.latestSource(repo)
	if err != nil {
		return nil, err
	}
	if err := verified.Measurement.Equals(source); err != nil {
		return nil, fmt.Errorf("enclave does not match %s@%s: %w", repo, tag, err)
	}
	if verified.Measurement.Type == legacyattestation.TdxGuestV2 {
		if r.checkTdx != nil {
			if err := r.checkTdx(ctx, host, doc); err != nil {
				return nil, fmt.Errorf("checking TDX platform policy: %w", err)
			}
		}
		// Release attestations cover RTMR1 and RTMR2 only; a nonzero RTMR3 means
		// the guest extended its measurements at runtime.
		if len(verified.Measurement.Registers) != 5 || verified.Measurement.Registers[4] != measurement.RTMR3_ZERO {
			return nil, errors.New("TDX RTMR3 is not zero")
		}
		hardware, err := r.latestHardware()
		if err != nil {
			return nil, err
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

// latestSource returns the sigstore-verified measurement of the repo's latest
// release. Verified measurements are cached by digest because a release's
// attestation is immutable; the latest tag is always re-read.
func (r *releaseVerifier) latestSource(repo string) (string, *legacyattestation.Measurement, error) {
	tag, err := r.latestTag(repo)
	if err != nil {
		return "", nil, fmt.Errorf("fetching latest release of %s: %w", repo, err)
	}
	digest, err := r.digestForTag(repo, tag)
	if err != nil {
		return "", nil, fmt.Errorf("fetching digest of %s@%s: %w", repo, tag, err)
	}
	key := repo + "@" + digest
	r.mu.Lock()
	cached := r.sources[key]
	r.mu.Unlock()
	if cached != nil {
		return tag, cached, nil
	}
	source, err := r.verifyRelease(repo, digest)
	if err != nil {
		return "", nil, fmt.Errorf("verifying release attestation of %s@%s: %w", repo, tag, err)
	}
	r.mu.Lock()
	r.sources[key] = source
	r.mu.Unlock()
	return tag, source, nil
}

func (r *releaseVerifier) latestHardware() ([]*legacyattestation.HardwareMeasurement, error) {
	digest, err := r.latestDigest(hardwareMeasurementsRepo)
	if err != nil {
		return nil, fmt.Errorf("fetching latest hardware measurements: %w", err)
	}
	r.mu.Lock()
	cached := r.hardware[digest]
	r.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
	hardware, err := r.fetchHardware(digest)
	if err != nil {
		return nil, fmt.Errorf("verifying hardware measurements release: %w", err)
	}
	r.mu.Lock()
	r.hardware[digest] = hardware
	r.mu.Unlock()
	return hardware, nil
}

func (r *releaseVerifier) verifySigstoreRelease(repo, digest string) (*legacyattestation.Measurement, error) {
	client, err := r.sigstoreClient()
	if err != nil {
		return nil, err
	}
	bundle, err := legacygithub.FetchAttestationBundle(repo, digest)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation bundle: %w", err)
	}
	return client.VerifyAttestation(bundle, digest, repo)
}

func (r *releaseVerifier) fetchSigstoreHardware(digest string) ([]*legacyattestation.HardwareMeasurement, error) {
	client, err := r.sigstoreClient()
	if err != nil {
		return nil, err
	}
	return client.FetchHardwareMeasurements(hardwareMeasurementsRepo, digest)
}

func (r *releaseVerifier) checkTdxPolicy(ctx context.Context, host string, doc *legacyattestation.Document) error {
	body, err := fetchAttestationV3(ctx, host)
	if err != nil {
		return err
	}
	return verifyCapturedTdxPolicy(doc.Body, body, r.now())
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
