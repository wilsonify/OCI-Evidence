# OCI-Evidence

**OCI artifact security verification and evidence management.**

OCI-Evidence is a standalone security control plane for verifying arbitrary OCI artifacts and managing the security evidence associated with them.

It is designed to be independently usable by other repositories and systems as a:

* **CLI** for CI/CD pipelines and local workflows
* **Go library** for applications that need OCI security verification
* **Service** for centralized artifact verification and evidence management

The goal is simple:

> **Trust once. Reuse many times.**

OCI-Evidence does not try to become another vulnerability scanner. Instead, it orchestrates existing security tooling, verifies the tools themselves, produces normalized evidence, binds that evidence to immutable OCI artifact identities, and makes the resulting evidence reusable across systems.

---

## Why OCI-Evidence?

Modern software artifacts rarely consist of a single container image.

OCI registries can contain:

* Container images
* Helm charts
* WebAssembly modules
* SBOMs
* Provenance
* Signatures and attestations
* Security scan results
* Policies
* Arbitrary application artifacts
* Custom OCI artifact types

Security tooling, however, is often implemented independently by each repository.

That leads to duplicated workflows:

```text
project A ── scanner ── policy
project B ── scanner ── policy
project C ── scanner ── policy
project D ── scanner ── policy
```

Each project must decide:

* Which scanner to use
* Which scanner version to trust
* How to acquire the scanner securely
* How to identify the artifact
* How to cache results
* How to interpret scan output
* How to attach evidence
* How to verify signatures
* How to handle stale results
* How to deal with a compromised scanner
* How to reuse results elsewhere

OCI-Evidence provides that common security workflow once.

```text
                    ┌──────────────────────┐
                    │     OCI-Evidence     │
                    │                      │
OCI Artifact ──────►│ Identify             │
                    │ Verify workers       │
                    │ Execute              │
                    │ Normalize evidence   │
                    │ Cache                │
                    │ Evaluate policy      │
                    │ Store evidence       │
                    └──────────┬───────────┘
                               │
                 ┌─────────────┼─────────────┐
                 ▼             ▼             ▼
              CI/CD       Kubernetes      Audit
```

---

## Core principle

### Trust once. Reuse many times.

An artifact is identified by its **immutable digest**, not by its tag.

A security result is valid only when it is explicitly bound to:

```text
artifact digest
+ security worker identity
+ worker version/digest
+ worker configuration
+ vulnerability database identity
+ evidence format/version
```

Once that evidence has been independently verified, other systems can consume it without repeating the entire security workflow.

```text
                    artifact@sha256:ABC
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
          ▼                 ▼                 ▼
        SBOM              Scan             Signature
          │                 │                 │
          ▼                 ▼                 ▼
       evidence          evidence          evidence
          └─────────────────┼─────────────────┘
                            ▼
                       policy decision
                            │
                 ┌──────────┴──────────┐
                 ▼                     ▼
                PASS                  FAIL
```

---

## What OCI-Evidence is

OCI-Evidence is the **security evidence and verification layer** between OCI artifacts and security consumers.

It provides:

### Artifact identification

Inspect OCI manifests, indexes, artifact manifests, media types, artifact types, annotations, and digests.

### Security capability detection

Determine what security controls are applicable to an artifact.

For example:

| Artifact         | Possible controls                             |
| ---------------- | --------------------------------------------- |
| Container image  | SBOM, vulnerabilities, signatures, provenance |
| Helm chart       | dependencies, configuration, signatures       |
| WASM module      | signatures, provenance, WASM analysis         |
| SBOM             | schema validation, dependency analysis        |
| Provenance       | attestation verification                      |
| Signature        | cryptographic verification                    |
| Unknown artifact | integrity, signature, provenance              |

### Trusted security workers

Existing security tools are treated as replaceable workers rather than trusted components of the core system.

Examples include:

* Syft
* Grype
* Trivy
* Cosign
* Notation
* Other scanners and verification tools

OCI-Evidence verifies the exact worker being executed before trusting its output.

### Isolated execution

Artifacts and security workers are treated as untrusted inputs.

Workers should run with:

* Restricted filesystem access
* Resource limits
* Timeouts
* Ephemeral workspaces
* Minimal network access
* No controller credentials
* No cloud credentials
* No unnecessary host privileges

### Evidence normalization

Different tools produce different formats.

OCI-Evidence converts their results into a common evidence model so consumers do not need to understand every scanner's output format.

### Evidence storage

Security evidence can be stored alongside the artifact as OCI referrers.

```text
artifact@sha256:ABC
    │
    ├── sbom@sha256:DEF
    ├── vulnerability-scan@sha256:GHI
    ├── signature@sha256:JKL
    └── provenance@sha256:MNO
```

### Evidence reuse

Before running a worker, OCI-Evidence checks whether equivalent, still-valid evidence already exists.

A matching result can be reused instead of rescanning.

### Policy evaluation

Security evidence is evaluated against policy independently from evidence generation.

Changing policy should not inherently require rescanning an artifact.

```text
existing evidence
       │
       ├── policy A ──► PASS
       ├── policy B ──► WARN
       └── policy C ──► FAIL
```

### Revocation

If a scanner or worker is later discovered to be compromised, its identity can be revoked.

Historical evidence is not silently rewritten or deleted.

Instead:

```text
scanner@sha256:ABC
        │
        ▼
     REVOKED
        │
        ▼
identify evidence produced by ABC
        │
        ▼
invalidate affected decisions
```

---

## What OCI-Evidence is not

OCI-Evidence intentionally does **not** attempt to implement every security capability itself.

It will not build:

* A vulnerability database
* A CVE matching engine
* An SBOM generator
* A container scanner
* A malware scanner
* Cryptographic primitives
* An OCI registry
* A custom signature format
* A custom provenance format
* A giant plugin framework
* A UI in the core project

Instead, OCI-Evidence integrates existing tools behind stable interfaces.

The architecture should make it possible to replace a scanner without replacing the security control plane.

---

## Architecture

```text
                         OCI Registry
                              │
                              ▼
                     ┌─────────────────┐
                     │ Artifact Reader │
                     │      ORAS       │
                     └────────┬────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │ Artifact Identity │
                    │  & Classification │
                    └─────────┬─────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                    ▼                   ▼
             Existing Evidence    Security Workers
                    │                   │
                    │          ┌────────┼────────┐
                    │          ▼        ▼        ▼
                    │        Syft     Grype    Cosign
                    │          │        │        │
                    │          └────────┼────────┘
                    │                   │
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │ Evidence Validator│
                    │ & Normalizer      │
                    └─────────┬─────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │ Evidence Identity │
                    │ & Cache           │
                    └─────────┬─────────┘
                              │
                     ┌────────┴────────┐
                     ▼                 ▼
              Policy Engine      OCI Referrers
                     │                 │
                     ▼                 ▼
                PASS/FAIL        Reusable Evidence
```

---

## Security model

OCI-Evidence uses a deliberately small trust boundary.

```text
                    ROOT OF TRUST
                          │
                          ▼
                  OCI-Evidence Core
                          │
                   verifies identity
                          │
                          ▼
                   Security Worker
                          │
                    analyzes input
                          │
                          ▼
                   OCI Artifact
```

The core does **not** blindly trust:

* Artifact contents
* Scanner binaries
* Scanner containers
* Scanner output
* Vulnerability databases
* External metadata
* Mutable OCI tags

Every external result is treated as untrusted input until validated.

---

## Immutable identity

Tags are convenient references but are not security identities.

This is unsafe:

```text
myimage:latest
```

This is the security identity:

```text
myimage@sha256:abc123...
```

Evidence must always reference the immutable subject digest.

A tag may move from:

```text
latest → sha256:AAA
```

to:

```text
latest → sha256:BBB
```

Evidence for `AAA` must never silently apply to `BBB`.

---

## Evidence identity

Evidence reuse is deterministic.

Conceptually, evidence identity is derived from:

```text
subject digest
+ worker identity
+ worker digest/version
+ worker configuration
+ vulnerability database identity
+ evidence schema version
```

For example:

```text
subject:
  sha256:ABC

worker:
  grype
  sha256:DEF

database:
  grype-db
  sha256:GHI

configuration:
  sha256:JKL
```

A policy change does not necessarily invalidate the underlying evidence.

This allows:

```text
scan once
     │
     ├── development policy
     ├── release policy
     ├── production policy
     └── compliance policy
```

without repeatedly executing expensive scanners.

---

## Evidence lifecycle

```text
DISCOVER
   │
   ▼
IDENTIFY
   │
   ▼
CHECK EXISTING EVIDENCE
   │
   ├──── valid ─────► REUSE
   │
   ▼
VERIFY WORKER
   │
   ▼
EXECUTE IN ISOLATION
   │
   ▼
VALIDATE OUTPUT
   │
   ▼
NORMALIZE
   │
   ▼
BIND TO SUBJECT DIGEST
   │
   ▼
STORE / ATTACH
   │
   ▼
EVALUATE POLICY
   │
   ▼
PASS / WARN / FAIL
```

---

## Result states

OCI-Evidence distinguishes security states rather than collapsing everything into pass/fail.

Possible states include:

* `PASS`
* `FAIL`
* `WARN`
* `NOT_APPLICABLE`
* `UNSUPPORTED`
* `STALE`
* `REVOKED`
* `ERROR`

In particular:

> **UNSUPPORTED is not PASS.**

If OCI-Evidence cannot perform a particular security control, the policy decides what that means.

---

## CLI

The CLI is intended to be useful independently of the library and service.

Examples:

```bash
ocievidence inspect ghcr.io/example/app@sha256:...
```

```bash
ocievidence discover ghcr.io/example/app@sha256:...
```

```bash
ocievidence scan ghcr.io/example/app@sha256:...
```

```bash
ocievidence verify ghcr.io/example/app@sha256:...
```

```bash
ocievidence evidence ghcr.io/example/app@sha256:...
```

```bash
ocievidence policy evaluate \
  ghcr.io/example/app@sha256:... \
  --policy production.yaml
```

Machine-readable output should be available:

```bash
ocievidence verify \
  ghcr.io/example/app@sha256:... \
  --json
```

The CLI should be suitable for use from:

* GitHub Actions
* GitLab CI
* Jenkins
* Tekton
* Argo
* Kubernetes workflows
* Local development
* Release automation

---

## Go library

The library is a first-class interface, not merely an implementation detail of the CLI.

Conceptually:

```go
result, err := security.Verify(ctx, artifact)
```

and:

```go
decision, err := security.Evaluate(ctx, artifact, policy)
```

Consumers should not need to understand:

* ORAS internals
* Scanner-specific output formats
* Evidence storage details
* Worker execution mechanics
* Vulnerability database formats

Those concerns belong behind the OCI-Evidence API.

---

## Service

A service mode can provide centralized verification for organizations with multiple repositories.

```text
                    ┌──────────────┐
GitHub Actions ────►│              │
                    │              │
GitLab CI ─────────►│ OCI-Evidence │
                    │   Service    │
Kubernetes ────────►│              │
                    │              │
Release systems ───►│              │
                    └──────┬───────┘
                           │
                           ▼
                      OCI Registry
```

The service should use the same core library and security model as the CLI.

---

## Designed for arbitrary OCI artifacts

OCI-Evidence should not assume that every artifact is a container image.

Artifact classification should be based on OCI metadata such as:

* Manifest type
* Artifact type
* Media types
* Layer media types
* Annotations
* Referrers
* Subject relationships

Not:

* File extensions
* Repository naming conventions
* Mutable tags

This allows the system to support new OCI artifact types without redesigning the core.

---

## Dependency philosophy

OCI-Evidence should have a small trusted core.

Security tooling should be replaceable.

For example:

```text
                    OCI-Evidence
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
        Syft           Grype          Cosign
          │              │              │
          └──────────────┼──────────────┘
                         │
                    normalized
                      evidence
```

No individual scanner should become a mandatory architectural dependency.

This is particularly important for supply-chain resilience.

A scanner can be compromised.

A scanner can become unmaintained.

A vulnerability database can be corrupted.

A release can be malicious.

OCI-Evidence must remain useful even when an individual worker is replaced or revoked.

---

## Supply-chain security

OCI-Evidence itself must follow the same principles it enforces.

Release artifacts should eventually provide:

* Reproducible builds
* SBOMs
* Signed release artifacts
* Build provenance
* Dependency pinning
* Static analysis
* Vulnerability scanning
* Fuzz testing
* Verified security-tool binaries
* Immutable release references

Security tools used to build or operate OCI-Evidence should never be trusted merely because they came from a well-known project.

The exact artifact being executed matters.

---

## Security invariants

The following invariants are fundamental to the project:

1. **Tags are never security identities.**
2. **Security decisions reference immutable artifact digests.**
3. **Unsupported controls never implicitly pass.**
4. **Scanner identity is part of evidence identity.**
5. **Scanner configuration is part of evidence identity.**
6. **Vulnerability database identity is part of vulnerability evidence identity.**
7. **Policy changes do not inherently require rescanning.**
8. **A compromised scanner can be revoked without replacing the controller.**
9. **Historical evidence is never silently rewritten.**
10. **Untrusted artifacts cannot compromise the controller.**
11. **Untrusted workers cannot compromise the controller.**
12. **Workers receive no unnecessary controller or cloud credentials.**
13. **External worker output is treated as untrusted input.**
14. **Evidence is cryptographically/immutably bound to its subject digest.**
15. **Mutable tags cannot cause evidence for one artifact to apply to another.**
16. **No single scanner is required for the architecture to function.**

---

## Example workflow

A repository wants to release:

```text
ghcr.io/example/payment-service:v1.4.2
```

OCI-Evidence resolves the tag:

```text
v1.4.2
    ↓
sha256:ABC...
```

It then checks for existing evidence.

If valid evidence already exists:

```text
sha256:ABC
    │
    ├── SBOM ───────── valid
    ├── vulnerability ─ valid
    ├── signature ───── valid
    └── provenance ──── valid
```

No scanner needs to run again.

If vulnerability evidence is missing:

```text
artifact
   │
   ▼
verify Grype worker
   │
   ▼
run Grype
   │
   ▼
validate output
   │
   ▼
normalize evidence
   │
   ▼
attach evidence to artifact
```

A production policy can then evaluate the existing evidence.

The same evidence can subsequently be consumed by:

* CI
* CD
* Kubernetes admission
* Release automation
* Security dashboards
* Audit systems
* Compliance workflows

without repeating the scan.

---

## Project status

OCI-Evidence is a greenfield project.

The initial implementation should prioritize one complete vertical slice over breadth:

```text
inspect
  ↓
verify worker
  ↓
scan
  ↓
normalize
  ↓
cache
  ↓
attach evidence
  ↓
evaluate policy
  ↓
reuse
```

Additional artifact types, workers, policy capabilities, and service functionality should build on this foundation.

---

## License

TBD
