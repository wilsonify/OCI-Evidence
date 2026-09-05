package artifact

import (
	"fmt"
	"regexp"
	"strings"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type ParsedReference struct {
	Repository string
	Digest     string
}

func ParseDigestReference(reference string) (ParsedReference, error) {
	parts := strings.Split(reference, "@")
	if len(parts) != 2 {
		return ParsedReference{}, fmt.Errorf("reference must be repository@sha256:digest")
	}
	repo, digest := parts[0], parts[1]
	if repo == "" || !digestPattern.MatchString(digest) {
		return ParsedReference{}, fmt.Errorf("invalid digest reference: %s", reference)
	}
	return ParsedReference{Repository: repo, Digest: digest}, nil
}
