package trust

import "testing"

func TestEmptyAllowlistTrustsNobody(t *testing.T) {
	p := WorkerTrustPolicy{}
	if err := p.Verify("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err == nil {
		t.Fatal("expected empty allowlist to reject worker")
	}
}

func TestNilRevocationMapMeansNoRevocations(t *testing.T) {
	p := WorkerTrustPolicy{
		Allowed: map[string]struct{}{
			"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {},
		},
	}
	if err := p.Verify("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatalf("expected allowlisted worker to verify when revocation map is nil: %v", err)
	}
}

func TestRevokedWorkerRejectedEvenIfAllowlisted(t *testing.T) {
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	p := WorkerTrustPolicy{
		Allowed: map[string]struct{}{digest: {}},
		Revoked: map[string]struct{}{digest: {}},
	}
	if err := p.Verify(digest); err == nil {
		t.Fatal("expected revoked worker to be rejected")
	}
}
