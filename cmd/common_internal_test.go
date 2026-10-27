// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedact(t *testing.T) {
	const bn = "beacon-node-url"

	tests := []struct {
		flag string
		val  string
		want string
	}{
		{bn, "https://user:secret@bn.example.com:5052", "https://user:xxxxx@bn.example.com:5052"},
		{bn, "http://lighthouse:5052", "http://lighthouse:5052"},
		{"loki-addresses", "http://user:secret@loki:3100/loki/api/v1/push", "http://user:xxxxx@loki:3100/loki/api/v1/push"},
		{bn, "https://eth-mainnet.example.com/v2/secret-key", "https://eth-mainnet.example.com/xxxxx"},
		{bn, "https://bn.example.com?apikey=secret", "https://bn.example.com?apikey=xxxxx"},
		{bn, "http://lighthouse:5052/", "http://lighthouse:5052/"},
		{"obol-api-url", "https://api.obol.tech/v1", "https://api.obol.tech/v1"},
		{"obol-api-url", "https://api.obol.tech/v1?key=secret", "https://api.obol.tech/v1?key=xxxxx"},
		{"charon-runtime-dir", "/charon", "/charon"},
		{"log-level", "info", "info"},
		{"some-auth-token", "secret", redacted},
	}
	for _, test := range tests {
		t.Run(test.flag+" "+test.val, func(t *testing.T) {
			require.Equal(t, test.want, redact(test.flag, test.val))
		})
	}
}
