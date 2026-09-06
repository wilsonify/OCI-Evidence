package cosign

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
}

func New() workers.Worker {
	return Worker{
		ID: model.WorkerIdentity{Name: "cosign", Version: "v0", Digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333"},
		Supported: map[string]struct{}{
			"signature": {},
		},
	}
}

func (w Worker) Identity() model.WorkerIdentity { return w.ID }
func (w Worker) Supports(capability string) bool {
	_, ok := w.Supported[capability]
	return ok
}

func (w Worker) Scan(ctx context.Context, subject model.Artifact, req workers.Request) (workers.Result, error) {
	if req.Capability != "signature" {
		return workers.Result{State: model.StateUnsupported, Payload: map[string]any{"message": "unsupported capability"}}, nil
	}
	out, err := exec.CommandContext(ctx, "cosign", "verify", subject.Digest, "--insecure-ignore-tlog=false").CombinedOutput()
	if err != nil {
		return workers.Result{}, err
	}
	var payload map[string]any
	if err := json.Unmarshal(out, &payload); err != nil {
		payload = map[string]any{"raw": string(out)}
	}
	return workers.Result{State: model.StatePass, Payload: payload}, nil
}
