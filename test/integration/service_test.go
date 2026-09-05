package integration

import (
	"context"
	"testing"
	"time"

	"github.com/wilsonify/OCI-Evidence/adapters/syft"
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

func newService() controller.Service {
	return controller.Service{
		Inspector: artifact.DigestOnlyInspector{},
		Workers:   workers.NewRegistry(syft.NewStatic()),
		Trust: trust.WorkerTrustPolicy{Allowed: map[string]struct{}{
			"sha256:1111111111111111111111111111111111111111111111111111111111111111": {},
		}},
		Executor:   execution.LocalExecutor{Timeout: time.Second},
		Cache:      cache.New(),
		Referrers:  registry.NewInMemoryReferrers(),
		ConfigHash: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
	}
}

const ref = "registry.example/repo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestVerifyAndReuse(t *testing.T) {
	svc := newService()
	ctx := context.Background()
	p := api.Policy{RequireSignature: true, WarnOnUnsupported: true}

	first, err := svc.Verify(ctx, ref, p)
	if err != nil {
		t.Fatal(err)
	}
	if first.ReusedAny {
		t.Fatal("first verify should not reuse evidence")
	}
	second, err := svc.Verify(ctx, ref, p)
	if err != nil {
		t.Fatal(err)
	}
	if !second.ReusedAny {
		t.Fatal("second verify should reuse evidence")
	}
}

func TestRevokedWorkerFails(t *testing.T) {
	svc := newService()
	svc.Trust.Revoked = map[string]struct{}{
		"sha256:1111111111111111111111111111111111111111111111111111111111111111": {},
	}
	ctx := context.Background()
	evs, reused, err := svc.Scan(ctx, ref, "signature")
	if err != nil {
		t.Fatal(err)
	}
	if reused {
		t.Fatal("revoked evidence cannot be reused")
	}
	if len(evs) != 1 || evs[0].State != model.StateRevoked {
		t.Fatalf("expected revoked state, got %#v", evs)
	}
}
