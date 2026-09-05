package policy

import (
	"testing"
	"time"

	"github.com/wilsonify/OCI-Evidence/pkg/api"
	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

func TestEvaluateMaxCriticalAndHigh(t *testing.T) {
	p := api.Policy{MaxCriticalVulns: 0, MaxHighVulns: 1}
	evs := []model.Evidence{{
		Capability: "vulnerability",
		State:      model.StatePass,
		Result: map[string]any{
			"critical": 1,
			"high":     2,
		},
	}}
	decision := Evaluate(p, evs, []string{"vulnerability"})
	if decision.State != model.StateFail {
		t.Fatalf("expected fail state, got %s", decision.State)
	}
	if len(decision.Reasons) == 0 {
		t.Fatal("expected reasons for a failing policy")
	}
}

func TestEvaluateWarnsOnlyBeforeFail(t *testing.T) {
	p := api.Policy{WarnOnUnsupported: true}
	evs := []model.Evidence{
		{Capability: "signature", State: model.StateFail},
		{Capability: "sbom", State: model.StateUnsupported},
	}
	decision := Evaluate(p, evs, []string{"signature", "sbom"})
	if decision.State != model.StateFail {
		t.Fatalf("expected fail state, got %s", decision.State)
	}
	if len(decision.Reasons) != 1 {
		t.Fatalf("expected only fail reasons, got %#v", decision.Reasons)
	}
}

func TestEvaluateStaleAndSignatureRequirements(t *testing.T) {
	p := api.Policy{RequireSignature: true, FailOnStale: true}
	evs := []model.Evidence{{Capability: "signature", State: model.StateStale, ProducedAt: time.Now().Add(-48 * time.Hour)}}
	decision := Evaluate(p, evs, []string{"signature"})
	if decision.State != model.StateFail {
		t.Fatalf("expected fail state for stale signature evidence; got %s", decision.State)
	}
}
