package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

func TestOCIReferrersReturnNotImplemented(t *testing.T) {
	s := NewOCIReferrers()
	if err := s.Attach(context.Background(), "sha256:abc", model.Evidence{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected Attach to return not implemented, got %v", err)
	}
	if _, err := s.Discover(context.Background(), "sha256:abc"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("expected Discover to return not implemented, got %v", err)
	}
}
