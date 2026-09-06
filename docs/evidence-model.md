# Evidence model

Schema version: `ocisec.evidence.v1`

Each record contains:

- `subject.digest` (required immutable identity)
- `capability`
- `worker.{name,version,digest}`
- `database.{name,version,digest}` when applicable
- `configurationDigest`
- `scanKey`
- `state`
- `result`
- `producedAt`
- `revoked` and `stale` markers

## Scan key

`scanKey = sha256(subject_digest + worker_digest + configuration_digest + database_digest + capability)`

Matching scan keys are reusable when evidence is not revoked or stale.

## Evidence states

- PASS
- FAIL
- WARN
- NOT_APPLICABLE
- UNSUPPORTED
- ERROR
- STALE
- REVOKED
- UNKNOWN
