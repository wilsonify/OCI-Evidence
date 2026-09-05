# Supply-chain security model

OCI-Evidence is security infrastructure and must verify its own build chain.

## Baseline controls

- Pinned module dependencies via `go.mod`/`go.sum`.
- Unit/integration/fuzz tests.
- Static analysis and vulnerability scanning in CI.
- Secret scanning on changed files before commit.
- CodeQL review before finalization.

## Release hardening roadmap

- Reproducible build settings.
- Generated SBOMs for release artifacts.
- Signed binaries and provenance attestations.
- Verified/pinned worker adapter artifacts before trust promotion.
