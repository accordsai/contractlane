package webhooks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

func CanonicalizeHeaders(h http.Header) (canonicalJSON []byte, canonical map[string][]string, err error) {
	canonical = make(map[string][]string, len(h))
	for k, vs := range h {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		values := canonical[key]
		for _, v := range vs {
			values = append(values, strings.TrimSpace(v))
		}
		sort.Strings(values)
		canonical[key] = values
	}

	keys := make([]string, 0, len(canonical))
	for k := range canonical {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, nil, err
		}
		vb, err := json.Marshal(canonical[k])
		if err != nil {
			return nil, nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')

	return b.Bytes(), canonical, nil
}

func ComputeWebhookHashes(method, path string, headersCanonicalJSON []byte, rawBody []byte) (rawBodySHA, headersSHA, requestSHA string) {
	rawBodySHA = hashBytes(rawBody)
	headersSHA = hashBytes(headersCanonicalJSON)

	envelope := make([]byte, 0, len(method)+len(path)+len(headersCanonicalJSON)+len(rawBody)+3)
	envelope = append(envelope, []byte(method)...)
	envelope = append(envelope, '\n')
	envelope = append(envelope, []byte(path)...)
	envelope = append(envelope, '\n')
	envelope = append(envelope, headersCanonicalJSON...)
	envelope = append(envelope, '\n')
	envelope = append(envelope, rawBody...)
	requestSHA = hashBytes(envelope)
	return rawBodySHA, headersSHA, requestSHA
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
