package controller

import (
	"context"
	"errors"
	"time"

	"github.com/wilsonify/OCI-Evidence/internal/artifact"
	"github.com/wilsonify/OCI-Evidence/internal/cache"
	"github.com/wilsonify/OCI-Evidence/internal/classifier"
	"github.com/wilsonify/OCI-Evidence/internal/evidence"
	"github.com/wilsonify/OCI-Evidence/internal/execution"
	"github.com/wilsonify/OCI-Evidence/internal/policy"
	"github.com/wilsonify/OCI-Evidence/internal/registry"
	"github.com/wilsonify/OCI-Evidence/internal/trust"
	"github.com/wilsonify/OCI-Evidence/internal/workers"
	"github.com/wilsonify/OCI-Evidence/pkg/api"
	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

type Service struct {
	Inspector  artifact.Inspector
	Workers    workers.Registry
	Trust      trust.WorkerTrustPolicy
	Executor   execution.Executor
	Cache      *cache.EvidenceCache
	Referrers  registry.EvidenceReferrerStore
	ConfigHash string
}

func (s Service) Inspect(ctx context.Context, reference string) (model.Artifact, error) {
	return s.Inspector.Inspect(ctx, reference)
}

func (s Service) Discover(ctx context.Context, reference string) ([]model.Evidence, error) {
	a, err := s.Inspect(ctx, reference)
	if err != nil {
		return nil, err
	}
	if s.Referrers == nil {
		return nil, errors.New("evidence referrer store is not configured")
	}
	evs, err := s.Referrers.Discover(ctx, a.Digest)
	if err != nil {
		return nil, err
	}
	for i := range evs {
		evs[i] = s.validateEvidence(a, evs[i])
	}
	return evs, nil
}

func (s Service) Scan(ctx context.Context, reference string, requested ...string) ([]model.Evidence, bool, error) {
	a, err := s.Inspect(ctx, reference)
	if err != nil {
		return nil, false, err
	}
	caps := requested
	if len(caps) == 0 {
		caps = classifier.Capabilities(a)
	}

	evidences := []model.Evidence{}
	reusedAny := false

	for _, cap := range caps {
		w, err := s.Workers.ForCapability(cap)
		if err != nil {
			evidences = append(evidences, model.Evidence{
				SchemaVersion:       "ocisec.evidence.v1",
				Capability:          cap,
				Subject:             a,
				State:               model.StateUnsupported,
				ProducedAt:          time.Now().UTC(),
				ConfigurationDigest: s.ConfigHash,
			})
			continue
		}
		id := w.Identity()
		if err := s.Trust.Verify(id.Digest); err != nil {
			evidences = append(evidences, model.Evidence{
				SchemaVersion:       "ocisec.evidence.v1",
				Capability:          cap,
				Subject:             a,
				Worker:              id,
				State:               model.StateRevoked,
				Result:              map[string]any{"error": err.Error()},
				ProducedAt:          time.Now().UTC(),
				ConfigurationDigest: s.ConfigHash,
				Revoked:             true,
			})
			continue
		}

		scanKey := evidence.ScanKey(a.Digest, id.Digest, s.ConfigHash, "", cap)
		if s.Cache != nil {
			if cached, ok := s.Cache.Get(scanKey); ok {
				cached = s.validateEvidence(a, cached)
				s.Cache.Put(cached)
				if cached.State == model.StatePass {
					reusedAny = true
					evidences = append(evidences, cached)
					continue
				}
			}
		}

		res, execErr := s.Executor.Execute(ctx, w, a, workers.Request{Capability: cap, ConfigurationDigest: s.ConfigHash})
		state := res.State
		payload := res.Payload
		if execErr != nil {
			state = model.StateError
			payload = map[string]any{"error": execErr.Error()}
		}
		ev := model.Evidence{
			SchemaVersion:       "ocisec.evidence.v1",
			ScanKey:             scanKey,
			Capability:          cap,
			Subject:             a,
			Worker:              id,
			Database:            res.Database,
			ConfigurationDigest: s.ConfigHash,
			State:               state,
			Result:              payload,
			ProducedAt:          time.Now().UTC(),
		}
		ev = s.validateEvidence(a, ev)
		if s.Cache != nil {
			s.Cache.Put(ev)
		}
		if s.Referrers != nil {
			if err := s.Referrers.Attach(ctx, a.Digest, ev); err != nil {
				return evidences, reusedAny, err
			}
		}
		evidences = append(evidences, ev)
	}
	return evidences, reusedAny, nil
}

func (s Service) Evaluate(ctx context.Context, reference string, p api.Policy) (model.Decision, error) {
	a, err := s.Inspect(ctx, reference)
	if err != nil {
		return model.Decision{}, err
	}
	evs, err := s.Discover(ctx, reference)
	if err != nil {
		return model.Decision{}, err
	}
	if len(evs) == 0 {
		return model.Decision{}, errors.New("no evidence found; run scan first")
	}
	caps := classifier.Capabilities(a)
	return policy.Evaluate(p, evs, caps), nil
}

func (s Service) Verify(ctx context.Context, reference string, p api.Policy) (model.VerifyResult, error) {
	a, err := s.Inspect(ctx, reference)
	if err != nil {
		return model.VerifyResult{}, err
	}
	evs, reused, err := s.Scan(ctx, reference)
	if err != nil {
		return model.VerifyResult{}, err
	}
	for i := range evs {
		evs[i] = s.validateEvidence(a, evs[i])
	}
	decision := policy.Evaluate(p, evs, classifier.Capabilities(a))
	return model.VerifyResult{Artifact: a, Evidence: evs, Decision: decision, ReusedAny: reused}, nil
}

func (s Service) validateEvidence(subject model.Artifact, ev model.Evidence) model.Evidence {
	if ev.Subject.Digest != "" && ev.Subject.Digest != subject.Digest {
		ev.State = model.StateError
		ev.Result = map[string]any{"error": "evidence subject digest does not match artifact digest"}
		return ev
	}
	if ev.Worker.Digest == "" || ev.State == model.StateUnsupported {
		return ev
	}
	if err := s.Trust.Verify(ev.Worker.Digest); err != nil {
		ev.Revoked = true
		ev.State = model.StateRevoked
		ev.Result = map[string]any{"error": err.Error()}
		return ev
	}
	if s.Cache != nil && ev.ProducedAt.IsZero() == false && time.Since(ev.ProducedAt) > s.Cache.MaxAge {
		ev.Stale = true
		if ev.State == model.StatePass {
			ev.State = model.StateStale
		}
	}
	return ev
}

var _ api.Security = Service{}
