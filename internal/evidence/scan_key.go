package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func ScanKey(subjectDigest, workerDigest, configDigest, dbDigest, capability string) string {
	raw := fmt.Sprintf("subject=%s|worker=%s|config=%s|db=%s|cap=%s", subjectDigest, workerDigest, configDigest, dbDigest, capability)
	sum := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(sum[:])
}
