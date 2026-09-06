package artifact

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type ParsedReference struct {
	Repository string
	Digest     string
}

func ParseDigestReference(reference string) (ParsedReference, error) {
	if looksLikeLocalPath(reference) {
		return ParsedReference{}, fmt.Errorf("non-OCI input %q is not supported; expected repository@sha256:<64hex>", reference)
	}
	parts := strings.Split(reference, "@")
	if len(parts) != 2 {
		return ParsedReference{}, fmt.Errorf("non-OCI input %q is not supported; expected repository@sha256:<64hex>", reference)
	}
	repo, digest := parts[0], parts[1]
	if repo == "" || !digestPattern.MatchString(digest) {
		return ParsedReference{}, fmt.Errorf("invalid digest reference: %s", reference)
	}
	return ParsedReference{Repository: repo, Digest: digest}, nil
}

func looksLikeLocalPath(reference string) bool {
	if reference == "" {
		return false
	}
	if strings.HasPrefix(reference, "/") || strings.HasPrefix(reference, "./") || strings.HasPrefix(reference, "../") || strings.HasPrefix(reference, "~") || strings.HasPrefix(reference, "file://") {
		return true
	}
	cleaned := filepath.Clean(reference)
	return cleaned == "." || cleaned == ".."
}
