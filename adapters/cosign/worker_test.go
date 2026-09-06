package cosign

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wilsonify/OCI-Evidence/internal/workers"
	"github.com/wilsonify/OCI-Evidence/pkg/model"
)

func TestScanUsesFullOCIReference(t *testing.T) {
	tmp := t.TempDir()
	argsPath := filepath.Join(tmp, "args.txt")
	binPath := filepath.Join(tmp, "cosign")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsPath + "\necho '{}'\n"
	if err := os.WriteFile(binPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+oldPath)

	w, ok := New().(Worker)
	if !ok {
		t.Fatal("expected concrete cosign worker")
	}
	_, err := w.Scan(context.Background(), model.Artifact{
		Reference: "registry.example/repo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, workers.Request{Capability: "signature"})
	if err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) < 3 {
		t.Fatalf("unexpected args list: %q", string(content))
	}
	if lines[0] != "verify" {
		t.Fatalf("expected cosign verify command, got %q", lines[0])
	}
	if lines[1] != "registry.example/repo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("expected full OCI reference argument, got %q", lines[1])
	}
}
