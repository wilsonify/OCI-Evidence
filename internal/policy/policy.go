package policy

import (
	"fmt"
	"reflect"

	"github.com/wilsonify/OCI-Evidence/pkg/api"
	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

func Evaluate(p api.Policy, evidences []model.Evidence, required []string) model.Decision {
	controls := map[string]model.State{}
	collected := map[string]model.Evidence{}
	for _, e := range evidences {
		if s, ok := controls[e.Capability]; !ok || higherPriority(e.State, s) {
			controls[e.Capability] = e.State
		}
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
		if reason == "" {
			return
		}
		switch s {
		case model.StateFail:
			if state != model.StateFail {
				state = model.StateFail
			}
			reasons = append(reasons, reason)
		case model.StateWarn:
			if state == model.StateFail {
				return
			}
			if state != model.StateWarn {
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
	if p.RequireProvenance {
		if controls["provenance"] != model.StatePass {
			setWorst(model.StateFail, "provenance verification is required")
		}
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

	if ev, ok := collected["vulnerability"]; ok {
		crit, high := vulnerabilityCounts(ev)
		if p.MaxCriticalVulns >= 0 && crit > p.MaxCriticalVulns {
			setWorst(model.StateFail, fmt.Sprintf("vulnerability critical count %d exceeds max %d", crit, p.MaxCriticalVulns))
		}
		if p.MaxHighVulns >= 0 && high > p.MaxHighVulns {
			setWorst(model.StateFail, fmt.Sprintf("vulnerability high count %d exceeds max %d", high, p.MaxHighVulns))
		}
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "all evaluated controls satisfy policy")
	}

	return model.Decision{State: state, Reasons: reasons, Controls: controls, Evidence: collected}
}

func higherPriority(newState, currentState model.State) bool {
	priority := map[model.State]int{
		model.StateFail:          8,
		model.StateRevoked:       7,
		model.StateError:         6,
		model.StateStale:         5,
		model.StateWarn:          4,
		model.StatePass:          3,
		model.StateUnknown:       2,
		model.StateUnsupported:   1,
		model.StateNotApplicable: 0,
	}
	return priority[newState] > priority[currentState]
}

func vulnerabilityCounts(e model.Evidence) (int, int) {
	if e.Result == nil {
		return 0, 0
	}
	v, ok := e.Result.(map[string]any)
	if !ok {
		return readCountsFromReflection(e.Result)
	}
	critical := asInt(v["critical"])
	high := asInt(v["high"])
	if critical == 0 && high == 0 {
		return readCountsFromReflection(v)
	}
	return critical, high
}

func readCountsFromReflection(v any) (int, int) {
	val := reflect.ValueOf(v)
	if !val.IsValid() {
		return 0, 0
	}
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return 0, 0
		}
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct && val.Kind() != reflect.Map {
		return 0, 0
	}
	critical := 0
	high := 0
	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			field := val.Type().Field(i)
			name := field.Name
			switch name {
			case "Critical":
				critical = asInt(val.Field(i).Interface())
			case "High":
				high = asInt(val.Field(i).Interface())
			}
		}
		return critical, high
	}
	if field, ok := val.Interface().(map[string]any); ok {
		return asInt(field["critical"]), asInt(field["high"])
	}
	return critical, high
}

func asInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		if x == "" {
			return 0
		}
		var n int
		_, _ = fmt.Sscanf(x, "%d", &n)
		return n
	default:
		return 0
	}
}
