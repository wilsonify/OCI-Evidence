# Threat model

## In-scope threats

- Malicious OCI artifact payloads.
- Tag mutation causing digest confusion.
- Compromised scanner binaries/images.
- Compromised scanner release channel.
- Malicious or malformed scanner output.
- Compromised vulnerability database updates.
- Replay of stale evidence.
- Malicious registry metadata.
- Compromised CI execution environment.

## Security responses in v1

- Digest-only artifact identity for all decisions.
- Worker digest allowlist and revocation checks.
- Scan key binding to subject digest, worker digest, config digest, and db digest.
- Explicit evidence states (UNSUPPORTED/STALE/REVOKED/ERROR are not PASS).
- Isolated execution abstraction with timeout/resource boundary hook points.
- Evidence persistence separated from policy evaluation to allow policy-only reevaluation.

## Remaining risks in v1

- Local executor is weaker than container/sandbox execution.
- In-memory referrer store is for initial vertical slice, not production durability.
- Signature/provenance verification adapters are placeholders and must be hardened before production use.
