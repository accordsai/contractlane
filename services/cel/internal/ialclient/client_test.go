package ialclient

import "testing"

func TestClientTypesCompile(t *testing.T) {
	_ = New("http://example.com")
}
