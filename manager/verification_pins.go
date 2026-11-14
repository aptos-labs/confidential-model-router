package manager

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/tinfoilsh/confidential-model-router/config"
)

const (
	sigstoreCodeFormat     = "https://tinfoil.sh/collateral/sigstore-code/v1"
	sigstoreHardwareFormat = "https://inference.aptoslabs.com/collateral/sigstore-hardware-measurements/v1"
	referenceValuesRole    = "reference-values"
)

// applyBackendPins installs the image's approved releases. The runtime config
// is not consulted: a hostname update must not be able to approve a new build.
func applyBackendPins(cfg *config.Config) error {
	repos := make(map[string][]config.ReleasePin)
	for name, model := range cfg.Models {
		if model.Repo == "" {
			continue
		}
		pins, err := config.ParseReleasePins(model.Releases)
		if err != nil {
			return fmt.Errorf("model %s: %w", name, err)
		}
		if len(pins) == 0 {
			return fmt.Errorf("model %s has no pinned release", name)
		}
		if previous, ok := repos[model.Repo]; ok && !sameReleasePins(previous, pins) {
			return fmt.Errorf("model %s pins a different release set for %s", name, model.Repo)
		}
		repos[model.Repo] = pins
	}
	var hardware []config.ReleasePin
	if len(repos) > 0 {
		pins, err := config.ParseReleasePins(cfg.HardwareMeasurements)
		if err != nil {
			return fmt.Errorf("hardware measurements: %w", err)
		}
		if len(pins) == 0 {
			return fmt.Errorf("hardware measurements pin is required")
		}
		hardware = pins
	}
	defaultReleaseVerifier.setPins(repos, hardware)
	return nil
}

func sameReleasePins(left, right []config.ReleasePin) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[config.ReleasePin]int, len(left))
	for _, pin := range left {
		seen[pin]++
	}
	for _, pin := range right {
		seen[pin]--
		if seen[pin] < 0 {
			return false
		}
	}
	return true
}

func sameReleaseList(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a := append([]string(nil), left...)
	b := append([]string(nil), right...)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func (r *releaseVerifier) pinSnapshot() (map[string][]config.ReleasePin, []config.ReleasePin) {
	r.mu.Lock()
	defer r.mu.Unlock()
	repos := make(map[string][]config.ReleasePin, len(r.repos))
	for repo, pins := range r.repos {
		repos[repo] = append([]config.ReleasePin(nil), pins...)
	}
	return repos, append([]config.ReleasePin(nil), r.catalog...)
}

func (r *releaseVerifier) setPins(repos map[string][]config.ReleasePin, hardware []config.ReleasePin) {
	copied := make(map[string][]config.ReleasePin, len(repos))
	for repo, pins := range repos {
		copied[repo] = append([]config.ReleasePin(nil), pins...)
	}
	r.mu.Lock()
	r.repos = copied
	r.catalog = append([]config.ReleasePin(nil), hardware...)
	r.mu.Unlock()
}

func (r *releaseVerifier) pinsFor(repo string) (code, hardware []config.ReleasePin, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	code = append([]config.ReleasePin(nil), r.repos[repo]...)
	hardware = append([]config.ReleasePin(nil), r.catalog...)
	if len(code) == 0 {
		return nil, nil, fmt.Errorf("no pinned release for %s", repo)
	}
	return code, hardware, nil
}

func findReleasePin(pins []config.ReleasePin, tag, digest string) (config.ReleasePin, bool) {
	for _, pin := range pins {
		if pin.Tag == tag && pin.Digest == digest {
			return pin, true
		}
	}
	return config.ReleasePin{}, false
}

type signedReference struct {
	repo   string
	tag    string
	digest string
	bundle []byte
}

type collateralEntry struct {
	ID       string          `json:"id"`
	Role     string          `json:"role"`
	Format   string          `json:"format"`
	Subjects []string        `json:"subjects"`
	Data     json.RawMessage `json:"data"`
}

type collateralDocument struct {
	Collateral []collateralEntry `json:"collateral"`
}

type sigstoreReference struct {
	Repo   string          `json:"repo"`
	Tag    string          `json:"tag"`
	Digest string          `json:"digest"`
	Bundle json.RawMessage `json:"sigstore_bundle"`
}

func codeReference(document []byte, repo string) (signedReference, error) {
	entry, err := oneReference(document, sigstoreCodeFormat, "code provenance")
	if err != nil {
		return signedReference{}, err
	}
	ref, err := decodeReference(entry)
	if err != nil {
		return signedReference{}, fmt.Errorf("code provenance: %w", err)
	}
	if ref.repo != repo {
		return signedReference{}, fmt.Errorf("code provenance names %s, not %s", ref.repo, repo)
	}
	return ref, nil
}

func hardwareReference(document []byte) (signedReference, error) {
	entry, err := oneReference(document, sigstoreHardwareFormat, "hardware measurements")
	if err != nil {
		return signedReference{}, err
	}
	ref, err := decodeReference(entry)
	if err != nil {
		return signedReference{}, fmt.Errorf("hardware measurements: %w", err)
	}
	if ref.repo != hardwareMeasurementsRepo {
		return signedReference{}, fmt.Errorf("hardware measurements publisher is %s, not %s", ref.repo, hardwareMeasurementsRepo)
	}
	return ref, nil
}

func oneReference(document []byte, format, name string) (collateralEntry, error) {
	var parsed collateralDocument
	if err := json.Unmarshal(document, &parsed); err != nil {
		return collateralEntry{}, fmt.Errorf("parsing attestation collateral: %w", err)
	}
	var found *collateralEntry
	seen := make(map[string]bool, len(parsed.Collateral))
	for i := range parsed.Collateral {
		entry := &parsed.Collateral[i]
		if entry.ID == "" {
			return collateralEntry{}, fmt.Errorf("attestation collateral has an empty id")
		}
		if seen[entry.ID] {
			return collateralEntry{}, fmt.Errorf("duplicate collateral id %s", entry.ID)
		}
		seen[entry.ID] = true
		if entry.Format != format {
			continue
		}
		if found != nil {
			return collateralEntry{}, fmt.Errorf("attestation has more than one %s entry", name)
		}
		found = entry
	}
	if found == nil {
		return collateralEntry{}, fmt.Errorf("attestation has no %s", name)
	}
	if found.Role != referenceValuesRole {
		return collateralEntry{}, fmt.Errorf("%s role is %s", name, found.Role)
	}
	if len(found.Subjects) != 1 || found.Subjects[0] != cpuCollateralSubject {
		return collateralEntry{}, fmt.Errorf("%s is not for the cpu", name)
	}
	return *found, nil
}

func decodeReference(entry collateralEntry) (signedReference, error) {
	decoder := json.NewDecoder(bytes.NewReader(entry.Data))
	decoder.DisallowUnknownFields()
	var payload sigstoreReference
	if err := decoder.Decode(&payload); err != nil {
		return signedReference{}, err
	}
	if decoder.More() {
		return signedReference{}, fmt.Errorf("trailing data")
	}
	if payload.Repo == "" || payload.Tag == "" || payload.Digest == "" {
		return signedReference{}, errors.New("missing repo, tag, or digest")
	}
	if len(payload.Bundle) == 0 || bytes.Equal(bytes.TrimSpace(payload.Bundle), []byte("null")) {
		return signedReference{}, errors.New("missing sigstore bundle")
	}
	return signedReference{
		repo:   payload.Repo,
		tag:    payload.Tag,
		digest: payload.Digest,
		bundle: append([]byte(nil), payload.Bundle...),
	}, nil
}
