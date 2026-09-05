package api

import (
	"context"
	"encoding/json"
	"os"

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
	RequireSignature  bool `json:"requireSignature"`
	RequireProvenance bool `json:"requireProvenance"`
	FailOnStale       bool `json:"failOnStale"`
	MaxCriticalVulns  int  `json:"maxCriticalVulns"`
	MaxHighVulns      int  `json:"maxHighVulns"`
	WarnOnUnsupported bool `json:"warnOnUnsupported"`
}

func LoadPolicy(path string) (Policy, error) {
	if path == "" {
		return Policy{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return Policy{}, err
	}
	return p, nil
}
