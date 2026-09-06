package cache

import (
	"sync"
	"time"

	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

type EvidenceCache struct {
	mu         sync.RWMutex
	byK        map[string]model.Evidence
	order      []string
	position   map[string]int
	MaxAge     time.Duration
	MaxEntries int
}

func New() *EvidenceCache {
	return NewWithOptions(24*time.Hour, 1024)
}

func NewWithOptions(maxAge time.Duration, maxEntries int) *EvidenceCache {
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	if maxEntries <= 0 {
		maxEntries = 1024
	}
	return &EvidenceCache{
		byK:        map[string]model.Evidence{},
		order:      []string{},
		position:   map[string]int{},
		MaxAge:     maxAge,
		MaxEntries: maxEntries,
	}
}

func (c *EvidenceCache) Get(scanKey string) (model.Evidence, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.byK[scanKey]
	if !ok {
		return model.Evidence{}, false
	}
	if c.MaxAge > 0 && !e.ProducedAt.IsZero() && time.Since(e.ProducedAt) > c.MaxAge {
		e.Stale = true
	}
	return e, true
}

func (c *EvidenceCache) Put(e model.Evidence) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.MaxAge > 0 && !e.ProducedAt.IsZero() && time.Since(e.ProducedAt) > c.MaxAge {
		e.Stale = true
	}
	if _, exists := c.byK[e.ScanKey]; !exists {
		c.position[e.ScanKey] = len(c.order)
		c.order = append(c.order, e.ScanKey)
	}
	c.byK[e.ScanKey] = e
	if c.MaxEntries > 0 && len(c.byK) > c.MaxEntries {
		for len(c.byK) > c.MaxEntries && len(c.order) > 0 {
			key := c.order[0]
			c.order = c.order[1:]
			delete(c.position, key)
			delete(c.byK, key)
		}
		c.reindexOrder()
	}
}

func (c *EvidenceCache) reindexOrder() {
	for i, key := range c.order {
		c.position[key] = i
	}
}
