package registry

import (
	"context"
	"sync"

	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

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
