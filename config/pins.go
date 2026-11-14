package config

import (
	"fmt"
	"strings"
)

// ReleasePin is one approved build: the git tag and the sha256 digest of the
// attested artifact. A router release is required to change either value.
type ReleasePin struct {
	Tag    string
	Digest string
}

func ParseReleasePins(values []string) ([]ReleasePin, error) {
	pins := make([]ReleasePin, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, raw := range values {
		tag, digest, ok := strings.Cut(raw, "@")
		if !ok || !validReleaseTag(tag) || !validReleaseDigest(digest) {
			shown := raw
			if len(shown) > 160 {
				shown = shown[:160] + "..."
			}
			return nil, fmt.Errorf("invalid release pin %q", shown)
		}
		key := tag + "@" + digest
		if seen[key] {
			return nil, fmt.Errorf("duplicate release pin %s@%s", tag, digest)
		}
		seen[key] = true
		pins = append(pins, ReleasePin{Tag: tag, Digest: digest})
	}
	return pins, nil
}

func validReleaseTag(tag string) bool {
	if tag == "" || len(tag) > 128 || strings.HasPrefix(tag, "sha256:") {
		return false
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '+' || c == '-' || c == '/':
		default:
			return false
		}
	}
	return true
}

func validReleaseDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for i := 0; i < len(digest); i++ {
		c := digest[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
