package canonhash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func SumObject(v any) (string, []byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), b, nil
}
