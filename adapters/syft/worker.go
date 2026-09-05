package syft

import (
	"context"
	"encoding/json"
	"os/exec"

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

type Worker struct {
	ID        model.WorkerIdentity
	Supported map[string]struct{}
	Database  model.DatabaseIdentity
}

func New() workers.Worker {
	return Worker{
		ID: model.WorkerIdentity{Name: "syft", Version: "v0", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		Supported: map[string]struct{}{
			"sbom": {},
		},
		Database: model.DatabaseIdentity{Name: "syft-db", Version: "unknown", Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
	}
}

func (w Worker) Identity() model.WorkerIdentity { return w.ID }
func (w Worker) Supports(capability string) bool {
	_, ok := w.Supported[capability]
	return ok
}

func (w Worker) Scan(ctx context.Context, subject model.Artifact, req workers.Request) (workers.Result, error) {
	if req.Capability != "sbom" {
		return workers.Result{State: model.StateUnsupported, Payload: map[string]any{"message": "unsupported capability"}}, nil
	}
	out, err := exec.CommandContext(ctx, "syft", "scan", subject.Reference, "-o", "json").CombinedOutput()
	if err != nil {
		return workers.Result{}, err
	}
	var payload any
	if len(out) > 0 {
		if err := json.Unmarshal(out, &payload); err != nil {
			payload = map[string]any{"raw": string(out)}
		}
	}
	return workers.Result{State: model.StatePass, Database: w.Database, Payload: payload}, nil
}
