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
	if !got.Stale {
		t.Fatal("expected stale flag to be set for aged evidence")
	}
}
