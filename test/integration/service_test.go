package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wilsonify/OCI-Evidence/internal/artifact"
	"github.com/wilsonify/OCI-Evidence/internal/cache"
	"github.com/wilsonify/OCI-Evidence/internal/controller"
	"github.com/wilsonify/OCI-Evidence/internal/execution"
	"github.com/wilsonify/OCI-Evidence/internal/registry"
	"github.com/wilsonify/OCI-Evidence/internal/trust"
	"github.com/wilsonify/OCI-Evidence/internal/workers"
	"github.com/wilsonify/OCI-Evidence/pkg/api"
	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

const ref = "registry.example/repo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fixedInspector struct{}

func (fixedInspector) Inspect(_ context.Context, reference string) (model.Artifact, error) {
	parsed, err := artifact.ParseDigestReference(reference)
	if err != nil {
		return model.Artifact{}, err
	}
	return model.Artifact{
		Reference:         reference,
		Repository:        parsed.Repository,
		Digest:            parsed.Digest,
		ManifestMediaType: "application/vnd.oci.image.manifest.v1+json",
		Annotations:       map[string]string{},
	}, nil
}

type scriptedWorker struct {
	id         model.WorkerIdentity
	capability string
	result     workers.Result
}

func (w scriptedWorker) Identity() model.WorkerIdentity { return w.id }
func (w scriptedWorker) Supports(capability string) bool {
	return capability == w.capability
}
func (w scriptedWorker) Scan(_ context.Context, _ model.Artifact, req workers.Request) (workers.Result, error) {
	if req.Capability != w.capability {
		return workers.Result{State: model.StateUnsupported}, nil
	}
	return w.result, nil
}

func newService(policy trust.WorkerTrustPolicy, store registry.EvidenceReferrerStore, c *cache.EvidenceCache, ws ...workers.Worker) controller.Service {
	return controller.Service{
		Inspector:  fixedInspector{},
		Workers:    workers.NewRegistry(ws...),
		Trust:      policy,
		Executor:   execution.LocalExecutor{Timeout: time.Second},
		Cache:      c,
		Referrers:  store,
		ConfigHash: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
	}
}

func TestVerifyAndDiscoverAgreeOnRevokedTrust(t *testing.T) {
	workerDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	w := scriptedWorker{
		id:         model.WorkerIdentity{Name: "signature-worker", Version: "v1", Digest: workerDigest},
		capability: "signature",
		result:     workers.Result{State: model.StatePass, Payload: map[string]any{"verified": true}},
	}
	store := registry.NewInMemoryReferrers()
	c := cache.NewWithOptions(time.Hour, 10)
	svc := newService(trust.WorkerTrustPolicy{Allowed: map[string]struct{}{workerDigest: {}}}, store, c, w)
	ctx := context.Background()
	if _, _, err := svc.Scan(ctx, ref, "signature"); err != nil {
		t.Fatal(err)
	}

	svc.Trust.Allowed = map[string]struct{}{}
	discovered, err := svc.Discover(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(discovered) == 0 || discovered[0].State != model.StateRevoked {
		t.Fatalf("expected discover evidence to be revoked, got %#v", discovered)
	}

	verifyResult, err := svc.Verify(ctx, ref, api.Policy{RequireSignature: true})
	if err != nil {
		t.Fatal(err)
	}
	if verifyResult.Decision.State == model.StatePass {
		t.Fatalf("revoked trust must not pass verification: %#v", verifyResult.Decision)
	}
}

func TestStaleEvidenceIsNeverValid(t *testing.T) {
	digest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	store := registry.NewInMemoryReferrers()
	old := model.Evidence{
		SchemaVersion: "ocisec.evidence.v1",
		Capability:    "signature",
		Subject:       model.Artifact{Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Worker:        model.WorkerIdentity{Digest: digest},
		State:         model.StatePass,
		ProducedAt:    time.Now().Add(-2 * time.Hour),
	}
	if err := store.Attach(context.Background(), old.Subject.Digest, old); err != nil {
		t.Fatal(err)
	}
	svc := newService(
		trust.WorkerTrustPolicy{Allowed: map[string]struct{}{digest: {}}},
		store,
		cache.NewWithOptions(time.Minute, 10),
	)
	evs, err := svc.Discover(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].State != model.StateStale {
		t.Fatalf("expected stale evidence state, got %#v", evs)
	}
}

func TestScanFailsWhenPersistenceIsNotImplemented(t *testing.T) {
	digest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	w := scriptedWorker{
		id:         model.WorkerIdentity{Name: "signature-worker", Version: "v1", Digest: digest},
		capability: "signature",
		result:     workers.Result{State: model.StatePass, Payload: map[string]any{"verified": true}},
	}
	svc := newService(
		trust.WorkerTrustPolicy{Allowed: map[string]struct{}{digest: {}}},
		registry.NewOCIReferrers(),
		cache.NewWithOptions(time.Hour, 10),
		w,
	)
	_, _, err := svc.Scan(context.Background(), ref, "signature")
	if !errors.Is(err, registry.ErrNotImplemented) {
		t.Fatalf("expected not implemented persistence error, got %v", err)
	}
}

func TestEndToEndDigestWorkflowPassAndFail(t *testing.T) {
	signDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	vulnDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	signWorker := scriptedWorker{
		id:         model.WorkerIdentity{Name: "signature-worker", Version: "v1", Digest: signDigest},
		capability: "signature",
		result:     workers.Result{State: model.StatePass, Payload: map[string]any{"verified": true}},
	}
	vulnWorker := scriptedWorker{
		id:         model.WorkerIdentity{Name: "vuln-worker", Version: "v1", Digest: vulnDigest},
		capability: "vulnerability",
		result: workers.Result{
			State:   model.StatePass,
			Payload: map[string]any{"critical": 0, "high": 1},
		},
	}
	svc := newService(
		trust.WorkerTrustPolicy{Allowed: map[string]struct{}{signDigest: {}, vulnDigest: {}}},
		registry.NewInMemoryReferrers(),
		cache.NewWithOptions(time.Hour, 10),
		signWorker,
		vulnWorker,
	)

	ctx := context.Background()
	pass, err := svc.Verify(ctx, ref, api.Policy{RequireSignature: true, MaxHighVulns: 1})
	if err != nil {
		t.Fatal(err)
	}
	if pass.Artifact.Digest == "" || pass.Decision.State != model.StatePass {
		t.Fatalf("expected pass result for trusted digest workflow, got %#v", pass.Decision)
	}
	fail, err := svc.Verify(ctx, ref, api.Policy{RequireSignature: true, MaxHighVulns: 0})
	if err != nil {
		t.Fatal(err)
	}
	if fail.Decision.State != model.StateFail {
		t.Fatalf("expected policy fail when vulnerability threshold is exceeded, got %#v", fail.Decision)
	}
}
