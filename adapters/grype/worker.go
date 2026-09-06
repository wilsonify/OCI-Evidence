package grype

import (
	"context"
	"encoding/json"
	"os/exec"

	"github.com/wilsonify/OCI-Evidence/internal/workers"
	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

type Worker struct {
	ID        model.WorkerIdentity
	Supported map[string]struct{}
	Database  model.DatabaseIdentity
}

func New() workers.Worker {
	return Worker{
		ID: model.WorkerIdentity{Name: "grype", Version: "v0", Digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"},
		Supported: map[string]struct{}{
			"vulnerability": {},
		},
		Database: model.DatabaseIdentity{Name: "grype-db", Version: "unknown", Digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"},
	}
}

func (w Worker) Identity() model.WorkerIdentity { return w.ID }
func (w Worker) Supports(capability string) bool {
	_, ok := w.Supported[capability]
	return ok
}

func (w Worker) Scan(ctx context.Context, subject model.Artifact, req workers.Request) (workers.Result, error) {
	if req.Capability != "vulnerability" {
		return workers.Result{State: model.StateUnsupported, Payload: map[string]any{"message": "unsupported capability"}}, nil
	}
	out, err := exec.CommandContext(ctx, "grype", subject.Reference, "-o", "json").CombinedOutput()
	if err != nil {
		return workers.Result{}, err
	}
	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		return workers.Result{State: model.StateError, Database: w.Database, Payload: map[string]any{"error": err.Error(), "raw": string(out)}}, nil
	}
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	if matches, ok := payload["matches"].([]any); ok {
		for _, item := range matches {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			sev, _ := m["severity"].(string)
			switch sev {
			case "Critical":
				counts["critical"]++
			case "High":
				counts["high"]++
			case "Medium":
				counts["medium"]++
			case "Low":
				counts["low"]++
			}
		}
	}
	return workers.Result{State: model.StatePass, Database: w.Database, Payload: map[string]any{"critical": counts["critical"], "high": counts["high"], "medium": counts["medium"], "low": counts["low"]}}, nil
}
