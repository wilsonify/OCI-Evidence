package controller

import (
	"context"
	"errors"
	"log"
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
	evs, err := s.Referrers.Discover(ctx, a.Digest)
	if err != nil {
		return nil, err
	}
	for i := range evs {
		if err := s.Trust.Verify(evs[i].Worker.Digest); err != nil {
			evs[i].Revoked = true
			evs[i].State = model.StateRevoked
			evs[i].Result = map[string]any{"error": err.Error()}
		}
		if s.Cache != nil && evs[i].ProducedAt.IsZero() == false && time.Since(evs[i].ProducedAt) > s.Cache.MaxAge {
			evs[i].Stale = true
		}
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
				if err := s.Trust.Verify(cached.Worker.Digest); err != nil {
					cached.Revoked = true
					cached.State = model.StateRevoked
					cached.Result = map[string]any{"error": err.Error()}
					s.Cache.Put(cached)
				} else if !cached.Revoked && !cached.Stale {
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
		if s.Cache != nil {
			s.Cache.Put(ev)
		}
		if s.Referrers != nil {
			if err := s.Referrers.Attach(ctx, a.Digest, ev); err != nil {
				log.Printf("warning: attaching evidence for %s/%s: %v", a.Repository, a.Digest, err)
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
	evs, err := s.Referrers.Discover(ctx, a.Digest)
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
	decision := policy.Evaluate(p, evs, classifier.Capabilities(a))
	return model.VerifyResult{Artifact: a, Evidence: evs, Decision: decision, ReusedAny: reused}, nil
}

var _ api.Security = Service{}
