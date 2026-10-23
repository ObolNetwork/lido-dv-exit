// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package util_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ObolNetwork/lido-dv-exit/app/util"
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
			got, err := util.ValidatorPubkeyToBytes(tt.pubkey)
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

func TestForkHashToBytes(t *testing.T) {
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
			"not 4 bytes",
			hex.EncodeToString([]byte{1, 2, 3}),
			nil,
			true,
		},
		{
			"4 bytes 0x-prefixed work",
			"0x" + hex.EncodeToString(bytes.Repeat([]byte{42}, 4)),
			bytes.Repeat([]byte{42}, 4),
			false,
		},
		{
			"4 bytes non-0x-prefixed work",
			hex.EncodeToString(bytes.Repeat([]byte{42}, 4)),
			bytes.Repeat([]byte{42}, 4),
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.ForkHashToBytes(tt.pubkey)
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
