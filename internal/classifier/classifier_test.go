package classifier

import (
	"reflect"
	"testing"

	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

func TestCapabilitiesAreDeterministic(t *testing.T) {
	a := model.Artifact{
		ManifestMediaType: "application/vnd.oci.image.manifest.v1+json",
		MediaTypes:        []string{"application/vnd.cncf.helm.config.v1+json", "application/vnd.module.wasm.content.layer.v1+wasm"},
	}
	got := Capabilities(a)
	want := []string{"helm", "integrity", "provenance", "sbom", "signature", "vulnerability", "wasm"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected capability ordering: got %#v want %#v", got, want)
	}
}
