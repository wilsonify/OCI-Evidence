package execution

import (
	"context"
	"time"

	"github.com/wilsonify/OCI-Evidence/internal/workers"
	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

type Executor interface {
	Execute(ctx context.Context, worker workers.Worker, subject model.Artifact, req workers.Request) (workers.Result, error)
}

type LocalExecutor struct {
	Timeout time.Duration
}

func (e LocalExecutor) Execute(ctx context.Context, worker workers.Worker, subject model.Artifact, req workers.Request) (workers.Result, error) {
	t := e.Timeout
	if t <= 0 {
		t = 30 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	return worker.Scan(c, subject, req)
}

type SandboxExecutor struct {
	LocalExecutor
}

func (e SandboxExecutor) Execute(ctx context.Context, worker workers.Worker, subject model.Artifact, req workers.Request) (workers.Result, error) {
	return e.LocalExecutor.Execute(ctx, worker, subject, req)
}
