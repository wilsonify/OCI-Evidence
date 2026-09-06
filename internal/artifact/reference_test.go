package artifact

import (
	"strings"
	"testing"
)

func TestParseDigestReferenceRejectsLocalPath(t *testing.T) {
	_, err := ParseDigestReference("./local/path")
	if err == nil {
		t.Fatal("expected local path to be rejected")
	}
	if !strings.Contains(err.Error(), "non-OCI input") {
		t.Fatalf("expected clear non-OCI error, got %v", err)
	}
}

func TestParseDigestReferenceRejectsTagReference(t *testing.T) {
	_, err := ParseDigestReference("registry.example/repo:latest")
	if err == nil {
		t.Fatal("expected tag reference to be rejected")
	}
	if !strings.Contains(err.Error(), "non-OCI input") {
		t.Fatalf("expected clear non-OCI error, got %v", err)
	}
}
