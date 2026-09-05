package artifact

import (
	"context"

	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

type Inspector interface {
	Inspect(ctx context.Context, reference string) (model.Artifact, error)
}

type DigestOnlyInspector struct{}

func (d DigestOnlyInspector) Inspect(_ context.Context, reference string) (model.Artifact, error) {
	parsed, err := ParseDigestReference(reference)
	if err != nil {
		return model.Artifact{}, err
	}
	return model.Artifact{
		Reference:   reference,
		Repository:  parsed.Repository,
		Digest:      parsed.Digest,
		Annotations: map[string]string{},
	}, nil
}
