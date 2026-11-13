package sigstore

import (
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

func pinnedIdentity(repo, tag, workflow string) *verify.VerificationResult {
	uri := "https://github.com/" + repo + "/.github/workflows/" + workflow + "@refs/tags/" + tag
	cert := &certificate.Summary{SubjectAlternativeName: uri}
	cert.Issuer = oidcIssuer
	cert.SourceRepositoryURI = "https://github.com/" + repo
	cert.RunnerEnvironment = "github-hosted"
	cert.BuildSignerURI = uri
	return &verify.VerificationResult{
		Signature: &verify.SignatureVerificationResult{Certificate: cert},
	}
}

func TestRequirePinnedReleaseAcceptsTaggedGitHubBuild(t *testing.T) {
	const repo = "aptos-labs/confidential-glm-5-3-prod"
	result := pinnedIdentity(repo, "v0.0.18", "tinfoil-release-publish.yml")
	if err := requirePinnedRelease(result, repo, "v0.0.18"); err != nil {
		t.Fatal(err)
	}
}

func TestRequirePinnedReleaseRejects(t *testing.T) {
	const repo = "aptos-labs/confidential-glm-5-3-prod"
	cases := []struct {
		name   string
		mutate func(*verify.VerificationResult)
		want   string
	}{
		{"missing certificate", func(result *verify.VerificationResult) { result.Signature = nil }, "no verified"},
		{"other repository", func(result *verify.VerificationResult) {
			result.Signature.Certificate.SourceRepositoryURI = "https://github.com/aptos-labs/other"
		}, "repository"},
		{"repository prefix", func(result *verify.VerificationResult) {
			result.Signature.Certificate.SourceRepositoryURI = "https://github.com/" + repo + "-evil"
		}, "repository"},
		{"self-hosted runner", func(result *verify.VerificationResult) {
			result.Signature.Certificate.RunnerEnvironment = "self-hosted"
		}, "runner"},
		{"other tag", func(result *verify.VerificationResult) {
			result.Signature.Certificate.SubjectAlternativeName = strings.Replace(result.Signature.Certificate.SubjectAlternativeName, "v0.0.18", "v0.0.19", 1)
		}, "subject"},
		{"tag prefix", func(result *verify.VerificationResult) {
			result.Signature.Certificate.SubjectAlternativeName = strings.Replace(result.Signature.Certificate.SubjectAlternativeName, "v0.0.18", "v0.0.180", 1)
		}, "subject"},
		{"nested workflow", func(result *verify.VerificationResult) {
			result.Signature.Certificate.SubjectAlternativeName = "https://github.com/" + repo + "/.github/workflows/dir/build.yml@refs/tags/v0.0.18"
		}, "subject name"},
		{"conflicting signer", func(result *verify.VerificationResult) {
			result.Signature.Certificate.BuildSignerURI = strings.Replace(result.Signature.Certificate.BuildSignerURI, "v0.0.18", "v0.0.19", 1)
		}, "workflow"},
		{"conflicting ref", func(result *verify.VerificationResult) {
			result.Signature.Certificate.SourceRepositoryRef = "refs/tags/v0.0.19"
		}, "ref"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := pinnedIdentity(repo, "v0.0.18", "tinfoil-release-publish.yml")
			tc.mutate(result)
			err := requirePinnedRelease(result, repo, "v0.0.18")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}
