package rfc3161

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	CertReq        bool                  `asn1:"optional"`
}

type Client struct {
	HTTPClient *http.Client
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 3 * time.Second}
	}
	return &Client{HTTPClient: httpClient}
}

func BuildTimeStampRequestFromHashHex(targetHash string, policyOID string) ([]byte, error) {
	hashHex := strings.TrimSpace(targetHash)
	hashHex = strings.TrimPrefix(hashHex, "sha256:")
	digest, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, fmt.Errorf("invalid target hash: %w", err)
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("invalid target hash length: %d", len(digest))
	}
	return BuildTimeStampRequest(digest, policyOID)
}

func BuildTimeStampRequest(digest []byte, policyOID string) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes")
	}
	req := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: algorithmIdentifier{
				Algorithm: oidSHA256,
				Parameters: asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag:   asn1.TagNull,
				},
			},
			HashedMessage: digest,
		},
		CertReq: true,
	}
	if p := strings.TrimSpace(policyOID); p != "" {
		oid, err := parseOID(p)
		if err != nil {
			return nil, err
		}
		req.ReqPolicy = oid
	}
	return asn1.Marshal(req)
}

func (c *Client) RequestTimestampToken(ctx context.Context, tsaURL string, reqDER []byte) (token []byte, contentType string, err error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tsaURL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, "", err
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("Accept", "application/timestamp-reply")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.Header.Get("Content-Type"), fmt.Errorf("tsa_http_status_%d", resp.StatusCode)
	}
	if len(body) == 0 {
		return nil, resp.Header.Get("Content-Type"), fmt.Errorf("tsa_empty_response")
	}
	return body, resp.Header.Get("Content-Type"), nil
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid policy_oid")
	}
	out := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		var n int
		if p == "" {
			return nil, fmt.Errorf("invalid policy_oid")
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return nil, fmt.Errorf("invalid policy_oid")
			}
			n = (n * 10) + int(ch-'0')
		}
		out = append(out, n)
	}
	return out, nil
}
