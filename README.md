# OCI-Evidence

OCI-Evidence is a standalone security control plane for OCI artifacts.

**Trust once. Reuse many times.**

It verifies artifacts by immutable digest, executes untrusted workers through a control boundary, normalizes machine-readable evidence, caches by deterministic scan identity, and evaluates policy without rescanning when inputs are unchanged.

## Vertical slice implemented

- inspect artifact (`repository@sha256:digest`) with registry-backed manifest resolution
- classify capabilities based on manifest metadata
- verify worker digest trust policy and revoke stale or untrusted evidence
- execute worker via isolation abstraction with CLI-backed adapters
- normalize evidence (`ocisec.evidence.v1`)
- compute deterministic scan key
- cache and reuse matching evidence with TTL/staleness checks
- attach/discover evidence through referrer-store abstraction
- evaluate policy independently from scan execution, including critical/high thresholds
- load policy files and write JSON output to a registry file via CLI flags

## Security invariants

- Tags are never security identity.
- Every decision references immutable digest.
- Unsupported is never PASS.
- Worker digest and config digest are part of evidence identity.
- Policy reevaluation does not require rescanning.
- Worker compromise is handled by revocation.

## CLI

```bash
ocisec inspect <repository@sha256:digest>
ocisec discover <repository@sha256:digest>
ocisec scan <repository@sha256:digest>
ocisec verify <repository@sha256:digest>
ocisec policy <repository@sha256:digest>
ocisec evidence <repository@sha256:digest>
```

Use `--json` for machine-readable output, `--policy <file>` to load a policy JSON document, and `--registry <file>` to write the result payload to a file.

## Library usage

Use `internal/controller.Service` through `pkg/api.Security` interface.

Core API methods:

- `Inspect`
- `Discover`
- `Scan`
- `Evaluate`
- `Verify`

## Repository structure

```text
cmd/ocisec
internal/{artifact,classifier,evidence,policy,trust,workers,execution,registry,cache,controller}
pkg/{api,model}
adapters/{syft,grype,trivy,cosign}
policies/examples
docs/
test/{integration,fuzz}
```

See docs for architecture and threat model details.
