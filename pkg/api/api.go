package api

import (
	"context"

	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

type Security interface {
	Inspect(ctx context.Context, reference string) (model.Artifact, error)
	Discover(ctx context.Context, reference string) ([]model.Evidence, error)
	Scan(ctx context.Context, reference string, capabilities ...string) ([]model.Evidence, bool, error)
	Evaluate(ctx context.Context, reference string, p Policy) (model.Decision, error)
	Verify(ctx context.Context, reference string, p Policy) (model.VerifyResult, error)
}

type Policy struct {
	RequireSignature   bool `json:"requireSignature"`
	RequireProvenance  bool `json:"requireProvenance"`
	FailOnStale        bool `json:"failOnStale"`
	MaxCriticalVulns   int  `json:"maxCriticalVulns"`
	WarnOnUnsupported  bool `json:"warnOnUnsupported"`
}
