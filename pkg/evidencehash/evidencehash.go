package evidencehash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// CanonicalSHA256 mirrors CEL evidence hashing semantics exactly:
// json.Marshal(v) bytes hashed with SHA256 hex.
func CanonicalSHA256(v any) (hexHash string, bytes []byte, err error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), b, nil
}

// ComputeBundleHashFromManifest mirrors CEL bundle hash semantics exactly.
func ComputeBundleHashFromManifest(bundleVersion, contractID, packetHash string, artifacts []map[string]any) string {
	var b strings.Builder
	b.WriteString(bundleVersion)
	b.WriteString("\n")
	b.WriteString(contractID)
	b.WriteString("\n")
	b.WriteString(packetHash)
	b.WriteString("\n")
	for _, a := range artifacts {
		b.WriteString(fmt.Sprint(a["artifact_id"]))
		b.WriteString(":")
		b.WriteString(fmt.Sprint(a["sha256"]))
		b.WriteString("\n")
	}
	return HashStringSHA256Hex(b.String())
}

func HashStringSHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
