// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package util

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidatorPubkeyToBytes(t *testing.T) {
	tests := []struct {
		name    string
		pubkey  string
		want    []byte
		wantErr bool
	}{
		{
			"empty input",
			"",
			nil,
			true,
		},
		{
			"not 48 bytes",
			hex.EncodeToString([]byte{1, 2, 3}),
			nil,
			true,
		},
		{
			"48 bytes 0x-prefixed work",
			"0x" + hex.EncodeToString(bytes.Repeat([]byte{42}, 48)),
			bytes.Repeat([]byte{42}, 48),
			false,
		},
		{
			"48 bytes non-0x-prefixed work",
			hex.EncodeToString(bytes.Repeat([]byte{42}, 48)),
			bytes.Repeat([]byte{42}, 48),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidatorPubkeyToBytes(tt.pubkey)
			if tt.wantErr {
				require.Error(t, err)
				require.Empty(t, got)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSignatureToBytes(t *testing.T) {
	tests := []struct {
		name    string
		pubkey  string
		want    []byte
		wantErr bool
	}{
		{
			"empty input",
			"",
			nil,
			true,
		},
		{
			"not 96",
			hex.EncodeToString([]byte{1, 2, 3}),
			nil,
			true,
		},
		{
			"96 bytes 0x-prefixed work",
			"0x" + hex.EncodeToString(bytes.Repeat([]byte{42}, 96)),
			bytes.Repeat([]byte{42}, 96),
			false,
		},
		{
			"96 bytes non-0x-prefixed work",
			hex.EncodeToString(bytes.Repeat([]byte{42}, 96)),
			bytes.Repeat([]byte{42}, 96),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignatureToBytes(tt.pubkey)
			if tt.wantErr {
				require.Error(t, err)
				require.Empty(t, got)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
