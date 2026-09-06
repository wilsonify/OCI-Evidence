package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/wilsonify/OCI-Evidence/adapters/cosign"
	"github.com/wilsonify/OCI-Evidence/adapters/grype"
	"github.com/wilsonify/OCI-Evidence/adapters/provenance"
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

func main() {
	if len(os.Args) < 3 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	reference := os.Args[2]

	fs := flag.NewFlagSet("ocisec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "print machine-readable JSON")
	policyPath := fs.String("policy", "", "load policy from JSON file")
	registryPath := fs.String("registry", "", "write output to file")
	if err := fs.Parse(os.Args[3:]); err != nil {
		usage()
		os.Exit(2)
	}

	svc := controller.Service{
		Inspector: artifact.NewRegistryInspector(),
		Workers: workers.NewRegistry(
			syft.New(),
			grype.New(),
			cosign.New(),
			provenance.New(),
		),
		Trust:      trust.WorkerTrustPolicy{Allowed: allowedWorkersFromEnv()},
		Executor:   execution.LocalExecutor{Timeout: 30 * time.Second},
		Cache:      cache.New(),
		Referrers:  registry.NewInMemoryReferrers(),
		ConfigHash: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
	}

	ctx := context.Background()
	policyDef := api.Policy{RequireSignature: true, RequireProvenance: false, FailOnStale: true, MaxCriticalVulns: 0, MaxHighVulns: 0, WarnOnUnsupported: true}
	if *policyPath != "" {
		var err error
		policyDef, err = api.LoadPolicy(*policyPath)
		if err != nil {
			exitErr(err)
		}
	}

	var value any
	var err error
	switch cmd {
	case "inspect":
		value, err = svc.Inspect(ctx, reference)
	case "discover", "evidence":
		value, err = svc.Discover(ctx, reference)
	case "scan":
		e, reused, scanErr := svc.Scan(ctx, reference)
		if scanErr != nil {
			exitErr(scanErr)
		}
		value = map[string]any{"reused": reused, "evidence": e}
	case "verify":
		v, verifyErr := svc.Verify(ctx, reference, policyDef)
		value = v
		err = verifyErr
	case "policy":
		v, policyErr := svc.Evaluate(ctx, reference, policyDef)
		value = v
		err = policyErr
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		exitErr(err)
	}
	if err := out(*jsonOut, *registryPath, value); err != nil {
		exitErr(err)
	}
	os.Exit(exitCodeForValue(value))
}

func out(jsonOut bool, registryPath string, value any) error {
	if registryPath != "" {
		if err := writeOutput(registryPath, value); err != nil {
			return err
		}
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(value)
		return nil
	}
	fmt.Println(renderHuman(value))
	return nil
}

func renderHuman(value any) string {
	b, _ := json.MarshalIndent(value, "", "  ")
	return string(b)
}

func exitErr(err error) {
	if err == nil {
		os.Exit(0)
	}
	_, _ = fmt.Fprintln(os.Stderr, "error:", err)
	if strings.Contains(err.Error(), "digest") {
		_, _ = fmt.Fprintln(os.Stderr, "hint: use repository@sha256:<64hex>")
	}
	os.Exit(1)
}

func writeOutput(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func exitCodeForValue(value any) int {
	switch v := value.(type) {
	case model.VerifyResult:
		if v.Decision.State == model.StatePass {
			return 0
		}
		return 1
	case model.Decision:
		if v.State == model.StatePass {
			return 0
		}
		return 1
	case map[string]any:
		if decision, ok := v["decision"].(model.Decision); ok {
			if decision.State == model.StatePass {
				return 0
			}
			return 1
		}
		if evidence, ok := v["evidence"].([]model.Evidence); ok {
			for _, e := range evidence {
				if e.State == model.StateFail || e.State == model.StateError || e.State == model.StateRevoked || e.State == model.StateStale {
					return 1
				}
			}
		}
		return 0
	case []model.Evidence:
		for _, e := range v {
			if e.State == model.StateFail || e.State == model.StateError || e.State == model.StateRevoked || e.State == model.StateStale {
				return 1
			}
		}
		return 0
	default:
		return 0
	}
}

func usage() {
	fmt.Println("usage: ocisec <inspect|discover|scan|verify|policy|evidence> <repository@sha256:digest> [--json] [--policy <file>] [--registry <file>]")
}

func allowedWorkersFromEnv() map[string]struct{} {
	raw := strings.TrimSpace(os.Getenv("OCIEVIDENCE_ALLOWED_WORKERS"))
	allowed := map[string]struct{}{}
	if raw == "" {
		return allowed
	}
	for _, item := range strings.Split(raw, ",") {
		digest := strings.TrimSpace(item)
		if digest == "" {
			continue
		}
		allowed[digest] = struct{}{}
	}
	return allowed
}
