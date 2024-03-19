// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package bnapi_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
)

func TestCapellaFork(t *testing.T) {
	tests := []struct {
		name      string
		forkHash  string
		want      string
		errAssert require.ErrorAssertionFunc
	}{
		{
			"bad fork hash string",
			"bad",
			"",
			require.Error,
		},
		{
			"ok fork hash but nonexistent",
			"0x12345678",
			"",
			require.Error,
		},
		{
			"existing ok fork hash",
			"0x00000000",
			"0x03000000",
			require.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bnapi.CapellaFork(tt.forkHash)
			tt.errAssert(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
