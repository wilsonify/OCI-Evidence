package workers

import (
	"context"
	"fmt"

	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

type Request struct {
	Capability          string
	ConfigurationDigest string
}

type Result struct {
	State    model.State
	Database model.DatabaseIdentity
	Payload  any
}

type Worker interface {
	Identity() model.WorkerIdentity
	Supports(capability string) bool
	Scan(ctx context.Context, subject model.Artifact, req Request) (Result, error)
}

type Registry struct {
	workers []Worker
}

func NewRegistry(workers ...Worker) Registry {
	return Registry{workers: workers}
}

func (r Registry) ForCapability(capability string) (Worker, error) {
	for _, w := range r.workers {
		if w.Supports(capability) {
			return w, nil
		}
	}
	return nil, fmt.Errorf("no worker supports capability %q", capability)
}

type VulnerabilitySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
}

type StaticWorker struct {
	ID              model.WorkerIdentity
	Supported       map[string]struct{}
	VulnerabilityDB model.DatabaseIdentity
}

func (s StaticWorker) Identity() model.WorkerIdentity { return s.ID }

func (s StaticWorker) Supports(capability string) bool {
	_, ok := s.Supported[capability]
	return ok
}

func (s StaticWorker) Scan(_ context.Context, _ model.Artifact, req Request) (Result, error) {
	switch req.Capability {
	case "vulnerability":
		return Result{State: model.StatePass, Database: s.VulnerabilityDB, Payload: VulnerabilitySummary{}}, nil
	case "signature", "provenance", "integrity", "sbom":
		return Result{State: model.StatePass, Payload: map[string]any{"message": "validated"}}, nil
	default:
		return Result{State: model.StateUnsupported, Payload: map[string]any{"message": "unsupported"}}, nil
	}
}
