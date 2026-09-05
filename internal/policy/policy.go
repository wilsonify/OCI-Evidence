package policy

import (
	"fmt"

	"github.com/wilsonify/OCI-Evidence/pkg/api"
	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

func Evaluate(p api.Policy, evidences []model.Evidence, required []string) model.Decision {
	controls := map[string]model.State{}
	collected := map[string]model.Evidence{}
	for _, e := range evidences {
		controls[e.Capability] = e.State
		collected[e.Capability] = e
	}
	for _, c := range required {
		if _, ok := controls[c]; !ok {
			controls[c] = model.StateUnsupported
		}
	}

	reasons := []string{}
	state := model.StatePass

	setWorst := func(s model.State, reason string) {
		switch s {
		case model.StateFail:
			state = model.StateFail
			reasons = append(reasons, reason)
		case model.StateWarn:
			if state != model.StateFail {
				state = model.StateWarn
			}
			reasons = append(reasons, reason)
		}
	}

	if p.RequireSignature {
		if controls["signature"] != model.StatePass {
			setWorst(model.StateFail, "signature verification is required")
		}
	}
	if p.RequireProvenance && controls["provenance"] != model.StatePass {
		setWorst(model.StateWarn, "provenance verification is required")
	}
	for c, s := range controls {
		if s == model.StateFail || s == model.StateRevoked {
			setWorst(model.StateFail, fmt.Sprintf("control %s is %s", c, s))
		}
		if s == model.StateStale && p.FailOnStale {
			setWorst(model.StateFail, fmt.Sprintf("control %s is STALE", c))
		}
		if s == model.StateUnsupported && p.WarnOnUnsupported {
			setWorst(model.StateWarn, fmt.Sprintf("control %s is UNSUPPORTED", c))
		}
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "all evaluated controls satisfy policy")
	}

	return model.Decision{State: state, Reasons: reasons, Controls: controls, Evidence: collected}
}
