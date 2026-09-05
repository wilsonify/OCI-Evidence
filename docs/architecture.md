# OCI-Evidence architecture

OCI-Evidence is a small control plane that uses immutable digest identity and untrusted worker isolation.

## Vertical slice

1. Inspect OCI artifact by digest identity.
2. Classify artifact capabilities.
3. Verify worker trust policy by worker digest.
4. Execute worker through isolated executor abstraction.
5. Normalize worker output into versioned evidence schema.
6. Compute deterministic scan key from immutable inputs.
7. Reuse cached evidence if scan key matches.
8. Attach evidence as referrer-linked records.
9. Evaluate policy from normalized evidence.

## Trust boundaries

- Core controller: trusted root of orchestration and policy semantics.
- Worker binaries/images: untrusted and explicitly verified before use.
- Artifact contents: untrusted input.
- Worker outputs: untrusted input until normalized and validated.
- Registry metadata and tags: untrusted except immutable digest references.

## Extension points

- Inspector implementation can use ORAS-backed registry operations.
- Worker adapters can be replaced without changing core logic.
- Executor backend can move from local process to stronger sandbox backend.
- Policy engine can be swapped for OPA/Rego while preserving evidence schema.
