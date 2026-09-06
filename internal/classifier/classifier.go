package classifier

import (
	"sort"
	"strings"

	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

func Capabilities(a model.Artifact) []string {
	known := map[string]struct{}{}
	add := func(v string) {
		if _, ok := known[v]; !ok {
			known[v] = struct{}{}
		}
	}

	add("integrity")
	add("signature")
	add("provenance")

	if strings.Contains(a.ManifestMediaType, "image") || strings.Contains(a.ArtifactType, "image") {
		add("sbom")
		add("vulnerability")
	}
	for _, mt := range a.MediaTypes {
		if strings.Contains(mt, "helm") {
			add("helm")
		}
		if strings.Contains(mt, "wasm") {
			add("wasm")
		}
	}

	out := make([]string, 0, len(known))
	for k := range known {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
