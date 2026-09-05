package fuzz

import (
	"testing"

	"github.com/wilsonify/OCI-Evidence/internal/artifact"
)

func FuzzParseDigestReference(f *testing.F) {
	f.Add("repo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	f.Add("repo:tag")
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = artifact.ParseDigestReference(input)
	})
}
