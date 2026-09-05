package cache

import (
	"sync"

	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

type EvidenceCache struct {
	mu  sync.RWMutex
	byK map[string]model.Evidence
}

func New() *EvidenceCache { return &EvidenceCache{byK: map[string]model.Evidence{}} }

func (c *EvidenceCache) Get(scanKey string) (model.Evidence, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.byK[scanKey]
	return e, ok
}

func (c *EvidenceCache) Put(e model.Evidence) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byK[e.ScanKey] = e
}
