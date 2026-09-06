package trust

import "fmt"

type WorkerTrustPolicy struct {
	Allowed map[string]struct{}
	Revoked map[string]struct{}
}

func (p WorkerTrustPolicy) Verify(digest string) error {
	if _, ok := p.Revoked[digest]; ok {
		return fmt.Errorf("worker digest revoked: %s", digest)
	}
	if len(p.Allowed) == 0 {
		return fmt.Errorf("worker digest not allowlisted: %s", digest)
	}
	if _, ok := p.Allowed[digest]; !ok {
		return fmt.Errorf("worker digest not allowlisted: %s", digest)
	}
	return nil
}
