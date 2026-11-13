package sigstore

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/github"
)

const (
	oidcIssuer = "https://token.actions.githubusercontent.com"
)

type Client struct {
	trustRoot *root.TrustedRoot
}

func NewClient() (*Client, error) {
	trustRootJSON, err := FetchTrustRoot()
	if err != nil {
		return nil, fmt.Errorf("fetching trust root: %w", err)
	}

	trustRoot, err := root.NewTrustedRootFromJSON(trustRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing trust root: %w", err)
	}

	return &Client{
		trustRoot: trustRoot,
	}, nil
}

func NewClientFromJSON(trustRootJSON []byte) (*Client, error) {
	trustRoot, err := root.NewTrustedRootFromJSON(trustRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing trust root: %w", err)
	}
	return &Client{trustRoot: trustRoot}, nil
}

// FetchTrustRoot fetches the trust root from the Sigstore TUF repo
func FetchTrustRoot() ([]byte, error) {
	tufOpts := tuf.
		DefaultOptions().
		WithDisableLocalCache()
	//WithFetcher(util.NewFetcher())
	client, err := tuf.New(tufOpts)
	if err != nil {
		return nil, err
	}

	return client.GetTarget("trusted_root.json")
}

func (c *Client) VerifyBundle(bundleJSON []byte, repo, hexDigest string) (*verify.VerificationResult, error) {
	if c.trustRoot == nil {
		return nil, fmt.Errorf("trust root is not set")
	}

	var b bundle.Bundle
	b.Bundle = new(protobundle.Bundle)
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("parsing bundle: %w", err)
	}

	verifier, err := verify.NewSignedEntityVerifier(
		c.trustRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("creating signed entity verifier: %w", err)
	}

	certID, err := verify.NewShortCertificateIdentity(
		oidcIssuer,
		"",
		"",
		// TODO: Can we pin this to latest without fetching the latest release?
		"^https://github.com/"+repo+"/.github/workflows/.*@refs/tags/*",
	)
	if err != nil {
		return nil, fmt.Errorf("creating certificate identity: %w", err)
	}

	digest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("decoding hex digest: %w", err)
	}
	result, err := verifier.Verify(
		&b,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha256", digest),
			verify.WithCertificateIdentity(certID),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying: %w", err)
	}

	return result, nil
}

// VerifyPinnedAttestation authenticates a code bundle that is already in hand.
// repo and tag are the trusted release, and hexDigest is that release's artifact
// digest. The certificate must be a GitHub-hosted build of that tag.
func (c *Client) VerifyPinnedAttestation(bundleJSON []byte, hexDigest, repo, tag string) (*attestation.Measurement, error) {
	if _, err := c.authenticatePinnedBundle(bundleJSON, repo, tag, hexDigest); err != nil {
		return nil, err
	}
	return c.VerifyAttestation(bundleJSON, hexDigest, repo)
}

// VerifyPinnedHardware authenticates a hardware-measurements bundle already in
// hand. It does not contact GitHub.
func (c *Client) VerifyPinnedHardware(bundleJSON []byte, hexDigest, repo, tag string) ([]*attestation.HardwareMeasurement, error) {
	result, err := c.authenticatePinnedBundle(bundleJSON, repo, tag, hexDigest)
	if err != nil {
		return nil, err
	}
	return hardwareMeasurements(result, hexDigest)
}

func (c *Client) authenticatePinnedBundle(bundleJSON []byte, repo, tag, hexDigest string) (*verify.VerificationResult, error) {
	result, err := c.VerifyBundle(bundleJSON, repo, hexDigest)
	if err != nil {
		return nil, fmt.Errorf("verifying bundle: %w", err)
	}
	if err := requirePinnedRelease(result, repo, tag); err != nil {
		return nil, err
	}
	return result, nil
}

// requirePinnedRelease binds the verified certificate to one repository and tag.
// VerifiedIdentity is the caller's policy, not the certificate, so the
// repository and workflow come from the certificate summary. The artifact
// digest is enforced separately, as the Sigstore artifact policy.
func requirePinnedRelease(result *verify.VerificationResult, repo, tag string) error {
	if result == nil || result.Signature == nil || result.Signature.Certificate == nil {
		return fmt.Errorf("bundle has no verified certificate")
	}
	cert := result.Signature.Certificate
	if cert.Issuer != oidcIssuer {
		return fmt.Errorf("bundle issuer is %q, not GitHub Actions", cert.Issuer)
	}
	repositoryURI := "https://github.com/" + repo
	switch {
	case cert.SourceRepositoryURI != "":
		if cert.SourceRepositoryURI != repositoryURI {
			return fmt.Errorf("bundle repository is %s, not %s", cert.SourceRepositoryURI, repositoryURI)
		}
	case cert.GithubWorkflowRepository != "":
		if cert.GithubWorkflowRepository != repo {
			return fmt.Errorf("bundle repository is %s, not %s", cert.GithubWorkflowRepository, repo)
		}
	default:
		return fmt.Errorf("bundle certificate has no repository")
	}
	if cert.RunnerEnvironment != "github-hosted" {
		return fmt.Errorf("bundle runner is %q, not github-hosted", cert.RunnerEnvironment)
	}
	if err := requireWorkflow(cert.SubjectAlternativeName, repositoryURI, repo, tag, "subject"); err != nil {
		return err
	}
	// Some certificates repeat the workflow in the build-signer extension.
	// When it is present it has to name the same tag.
	if cert.BuildSignerURI != "" {
		if err := requireWorkflow(cert.BuildSignerURI, repositoryURI, repo, tag, "workflow"); err != nil {
			return err
		}
	}
	if ref := cert.SourceRepositoryRef; ref != "" && ref != "refs/tags/"+tag {
		return fmt.Errorf("bundle ref %q is not refs/tags/%s", ref, tag)
	}
	if ref := cert.GithubWorkflowRef; ref != "" && ref != "refs/tags/"+tag {
		return fmt.Errorf("bundle ref %q is not refs/tags/%s", ref, tag)
	}
	return nil
}

func requireWorkflow(value, repositoryURI, repo, tag, what string) error {
	prefix := repositoryURI + "/.github/workflows/"
	suffix := "@refs/tags/" + tag
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, suffix) {
		return fmt.Errorf("bundle %s %q is not a tagged build of %s@%s", what, value, repo, tag)
	}
	workflow := strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix)
	if workflow == "" || strings.ContainsAny(workflow, "/@") {
		return fmt.Errorf("bundle %s name %q is not a single workflow file", what, workflow)
	}
	return nil
}

func (c *Client) VerifyAttestation(
	bundleJSON []byte,
	hexDigest, repo string,
) (*attestation.Measurement, error) {
	result, err := c.VerifyBundle(bundleJSON, repo, hexDigest)
	if err != nil {
		return nil, fmt.Errorf("verifying bundle: %w", err)
	}

	predicate := result.Statement.Predicate
	predicateFields := predicate.Fields

	measurementType := attestation.PredicateType(result.Statement.PredicateType)
	switch measurementType {
	case attestation.SevGuestV1:
		return &attestation.Measurement{
			Type:      measurementType,
			Registers: []string{predicateFields["measurement"].GetStringValue()},
		}, nil
	case attestation.SnpTdxMultiPlatformV1:
		tdxMeasurementField, ok := predicateFields["tdx_measurement"]
		if !ok {
			return nil, fmt.Errorf("invalid multiplatform measurement: no tdx measurement")
		}
		if tdxMeasurementField == nil {
			return nil, fmt.Errorf("invalid multiplatform measurement: tdx measurement is nil")
		}
		tdxMeasurement := tdxMeasurementField.GetStructValue()
		if tdxMeasurement == nil {
			return nil, fmt.Errorf("invalid multiplatform measurement: tdx measurement is not a struct")
		}
		rtmrs := tdxMeasurement.GetFields()

		// Validate multiplatform measurement format
		snpMeasurement, ok := predicateFields["snp_measurement"]
		if !ok {
			return nil, fmt.Errorf("invalid multiplatform measurement: no snp measurement")
		}
		if snpMeasurement == nil {
			return nil, fmt.Errorf("invalid multiplatform measurement: snp measurement is nil")
		}

		for _, rtmr := range []string{"rtmr1", "rtmr2"} {
			v, ok := rtmrs[rtmr]
			if !ok {
				return nil, fmt.Errorf("invalid multiplatform measurement: no %s", rtmr)
			}
			if v == nil {
				return nil, fmt.Errorf("invalid multiplatform measurement: %s is nil", rtmr)
			}
		}

		return &attestation.Measurement{
			Type: measurementType,
			Registers: []string{
				predicateFields["snp_measurement"].GetStringValue(),
				rtmrs["rtmr1"].GetStringValue(),
				rtmrs["rtmr2"].GetStringValue(),
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported predicate type: %s", result.Statement.PredicateType)
	}
}

// FetchHardwareMeasurements fetches the MRTD and RTMR0 from a given hardware repo
func (c *Client) FetchHardwareMeasurements(repo, digest string) ([]*attestation.HardwareMeasurement, error) {
	sigstoreBundle, err := github.FetchAttestationBundle(repo, digest)
	if err != nil {
		return nil, err
	}

	bundle, err := c.VerifyBundle(sigstoreBundle, repo, digest)
	if err != nil {
		return nil, err
	}
	return hardwareMeasurements(bundle, digest)
}

func hardwareMeasurements(bundle *verify.VerificationResult, digest string) ([]*attestation.HardwareMeasurement, error) {
	if bundle == nil || bundle.Statement == nil {
		return nil, fmt.Errorf("hardware bundle has no statement")
	}
	predicate := bundle.Statement.Predicate
	predicateType := bundle.Statement.PredicateType

	if attestation.PredicateType(predicateType) != attestation.HardwareMeasurementsV1 {
		return nil, fmt.Errorf("unexpected predicate type: %s", predicateType)
	}

	var measurements []*attestation.HardwareMeasurement
	for k, v := range predicate.Fields {
		structValue := v.GetStructValue()
		if structValue == nil {
			return nil, fmt.Errorf("invalid hardware measurement")
		}

		fields := structValue.Fields

		for _, field := range []string{"mrtd", "rtmr0"} {
			v, ok := fields[field]
			if !ok {
				return nil, fmt.Errorf("invalid hardware measurement: no %s", field)
			}
			if v == nil {
				return nil, fmt.Errorf("invalid hardware measurement: %s is nil", field)
			}
		}

		measurements = append(measurements, &attestation.HardwareMeasurement{
			ID:    fmt.Sprintf("%s@%s", k, digest),
			MRTD:  fields["mrtd"].GetStringValue(),
			RTMR0: fields["rtmr0"].GetStringValue(),
		})
	}
	return measurements, nil
}

// VerifyAttestation verifies the attested measurements of an enclave image
// against a trusted root (Sigstore) and returns the measurement payload contained in the DSSE.
// Deprecated: Use client.VerifyAttestation instead.
func VerifyAttestation(
	trustRootJSON, bundleJSON []byte,
	hexDigest, repo string,
) (*attestation.Measurement, error) {
	trustRoot, err := root.NewTrustedRootFromJSON(trustRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing trust root: %w", err)
	}
	client := &Client{trustRoot: trustRoot}
	return client.VerifyAttestation(bundleJSON, hexDigest, repo)
}

// LatestHardwareMeasurements fetches the latest hardware measurements from GitHub+Sigstore
func (c *Client) LatestHardwareMeasurements() ([]*attestation.HardwareMeasurement, error) {
	const repo = "tinfoilsh/hardware-measurements"
	digest, err := github.FetchLatestDigest(repo)
	if err != nil {
		return nil, err
	}

	return c.FetchHardwareMeasurements(repo, digest)
}
