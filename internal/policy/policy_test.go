package policy

import (
	"strings"
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
	if len(decision.Reasons) == 0 {
		t.Fatalf("expected fail reason, got %#v", decision.Reasons)
	}
	last := decision.Reasons[len(decision.Reasons)-1]
	if !strings.Contains(last, "control signature is FAIL") {
		t.Fatalf("expected deterministic fail reason ordering, got %#v", decision.Reasons)
	}
}

func TestEvaluateStaleAndSignatureRequirements(t *testing.T) {
	p := api.Policy{RequireSignature: true, FailOnStale: true}
	evs := []model.Evidence{{Capability: "signature", State: model.StateStale, ProducedAt: time.Now().Add(-48 * time.Hour)}}
	decision := Evaluate(p, evs, []string{"signature"})
	if decision.State != model.StateFail {
		t.Fatalf("expected fail state for stale signature evidence; got %s", decision.State)
	}

	func TestEvaluateAggregatesMultipleVulnerabilityEvidenceRecords(t *testing.T) {
		p := api.Policy{MaxCriticalVulns: 0, MaxHighVulns: 0}
		evs := []model.Evidence{
			{Capability: "vulnerability", State: model.StatePass, ScanKey: "a", Result: map[string]any{"critical": 0, "high": 1}},
			{Capability: "vulnerability", State: model.StatePass, ScanKey: "b", Result: map[string]any{"critical": 1, "high": 0}},
		}
		decision := Evaluate(p, evs, []string{"vulnerability"})
		if decision.State != model.StateFail {
			t.Fatalf("expected fail state, got %s", decision.State)
		}
		if len(decision.Reasons) < 2 {
			t.Fatalf("expected both vulnerability threshold failures, got %#v", decision.Reasons)
		}
	}
}
