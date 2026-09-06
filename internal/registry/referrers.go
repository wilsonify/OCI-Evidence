package registry

import (
	"context"
	"errors"
	"sync"

	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

var ErrNotImplemented = errors.New("oci referrer storage not implemented")

type EvidenceReferrerStore interface {
	Attach(ctx context.Context, subjectDigest string, evidence model.Evidence) error
	Discover(ctx context.Context, subjectDigest string) ([]model.Evidence, error)
}

type InMemoryReferrers struct {
	mu   sync.RWMutex
	data map[string][]model.Evidence
}

func NewInMemoryReferrers() *InMemoryReferrers {
	return &InMemoryReferrers{data: map[string][]model.Evidence{}}
}

func (s *InMemoryReferrers) Attach(_ context.Context, subjectDigest string, evidence model.Evidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[subjectDigest] = append(s.data[subjectDigest], evidence)
	return nil
}

func (s *InMemoryReferrers) Discover(_ context.Context, subjectDigest string) ([]model.Evidence, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := s.data[subjectDigest]
	out := make([]model.Evidence, len(items))
	copy(out, items)
	return out, nil
}

type OCIReferrers struct{}

func NewOCIReferrers() *OCIReferrers { return &OCIReferrers{} }

func (s *OCIReferrers) Attach(_ context.Context, _ string, _ model.Evidence) error {
	return ErrNotImplemented
}
func (s *OCIReferrers) Discover(_ context.Context, _ string) ([]model.Evidence, error) {
	return nil, ErrNotImplemented
}
