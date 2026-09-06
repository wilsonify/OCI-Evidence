package cache

import (
	"testing"
	"time"

	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

func TestEvidenceCacheMarksStaleEntries(t *testing.T) {
	c := NewWithOptions(10*time.Millisecond, 10)
	e := model.Evidence{ScanKey: "scan-1", ProducedAt: time.Now().Add(-1 * time.Hour), Capability: "sbom"}
	c.Put(e)
	got, ok := c.Get("scan-1")
	if !ok {
		t.Fatal("expected cached evidence to be found")
	}

	func TestEvidenceCacheEvictionIsDeterministicFIFO(t *testing.T) {
		c := NewWithOptions(time.Hour, 2)
		c.Put(model.Evidence{ScanKey: "scan-1", ProducedAt: time.Now(), Capability: "sbom"})
		c.Put(model.Evidence{ScanKey: "scan-2", ProducedAt: time.Now(), Capability: "signature"})
		c.Put(model.Evidence{ScanKey: "scan-3", ProducedAt: time.Now(), Capability: "provenance"})

		if _, ok := c.Get("scan-1"); ok {
			t.Fatal("expected oldest key to be evicted first")
		}
		if _, ok := c.Get("scan-2"); !ok {
			t.Fatal("expected second key to remain")
		}
		if _, ok := c.Get("scan-3"); !ok {
			t.Fatal("expected newest key to remain")
		}
	}
	if !got.Stale {
		t.Fatal("expected stale flag to be set for aged evidence")
	}
}
