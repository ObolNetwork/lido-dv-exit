// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		flag string
		val  string
		want string
	}{
		{flag: "beacon-node-url", val: "https://user:secret@beacon.example", want: "https://user:xxxxx@beacon.example"},
		{flag: "obol-api-url", val: "https://api.obol.tech/v1", want: "https://api.obol.tech/v1"},
		{flag: "loki-addresses", val: "https://user:secret@loki.example", want: "https://user:xxxxx@loki.example"},
		{flag: "some-auth-token", val: "secret", want: "xxxxx"},
		{flag: "exit-epoch", val: "194048", want: "194048"},
	}

	for _, test := range tests {
		t.Run(test.flag, func(t *testing.T) {
			require.Equal(t, test.want, redact(test.flag, test.val))
		})
	}
}
