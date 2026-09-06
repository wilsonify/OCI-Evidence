# Worker authoring and security guide

Workers implement capability-based scanning without scanner-specific branching in core logic.

## Requirements

- Expose immutable worker identity (name, version, digest).
- Declare capability support.
- Return structured result and optional database identity.
- Avoid access to controller/cloud credentials.
- Run through executor isolation boundary.

## Promotion workflow

1. Build and publish worker artifact.
2. Verify signatures/provenance out of band.
3. Pin immutable digest in trust policy allowlist.
4. Monitor advisories and revoke compromised digests.

## Revocation

When a worker digest is revoked, existing evidence remains discoverable but must evaluate as revoked/failed by policy.
