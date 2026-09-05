package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
)

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	reference := os.Args[2]
	jsonOut := hasFlag("--json")

	svc := controller.Service{
		Inspector: artifact.DigestOnlyInspector{},
		Workers: workers.NewRegistry(
			syft.NewStatic(),
		),
		Trust: trust.WorkerTrustPolicy{Allowed: map[string]struct{}{
			"sha256:1111111111111111111111111111111111111111111111111111111111111111": {},
		}},
		Executor:   execution.LocalExecutor{Timeout: 5 * time.Second},
		Cache:      cache.New(),
		Referrers:  registry.NewInMemoryReferrers(),
		ConfigHash: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
	}

	ctx := context.Background()
	policy := api.Policy{RequireSignature: true, RequireProvenance: false, FailOnStale: true, MaxCriticalVulns: 0, WarnOnUnsupported: true}

	switch cmd {
	case "inspect":
		out(ctx, jsonOut, svc.Inspect(ctx, reference))
	case "discover", "evidence":
		out(ctx, jsonOut, svc.Discover(ctx, reference))
	case "scan":
		e, reused, err := svc.Scan(ctx, reference)
		if err != nil {
			exitErr(err)
		}
		out(ctx, jsonOut, map[string]any{"reused": reused, "evidence": e}, nil)
	case "verify":
		out(ctx, jsonOut, svc.Verify(ctx, reference, policy))
	case "policy":
		out(ctx, jsonOut, svc.Evaluate(ctx, reference, policy))
	default:
		usage()
		os.Exit(2)
	}
}

func hasFlag(flag string) bool {
	for _, a := range os.Args[3:] {
		if a == flag {
			return true
		}
	}
	return false
}

func out(_ context.Context, jsonOut bool, value any, err error) {
	if err != nil {
		exitErr(err)
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(value)
		return
	}
	fmt.Println(renderHuman(value))
}

func renderHuman(value any) string {
	b, _ := json.MarshalIndent(value, "", "  ")
	return string(b)
}

func exitErr(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "error:", err)
	if strings.Contains(err.Error(), "digest") {
		_, _ = fmt.Fprintln(os.Stderr, "hint: use repository@sha256:<64hex>")
	}
	os.Exit(1)
}

func usage() {
	fmt.Println("usage: ocisec <inspect|discover|scan|verify|policy|evidence> <repository@sha256:digest> [--json]")
}
