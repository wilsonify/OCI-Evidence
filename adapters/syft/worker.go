package syft

import (
	"github.com/wilsonify/OCI-Evidence/internal/workers"
	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

func NewStatic() workers.Worker {
	return workers.StaticWorker{
		ID: model.WorkerIdentity{Name: "syft-grype-adapter", Version: "v0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Supported: map[string]struct{}{
			"sbom":          {},
			"vulnerability": {},
			"signature":     {},
			"provenance":    {},
			"integrity":     {},
		},
		VulnerabilityDB: model.DatabaseIdentity{Name: "grype-db", Version: "v0", Digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"},
	}
}
