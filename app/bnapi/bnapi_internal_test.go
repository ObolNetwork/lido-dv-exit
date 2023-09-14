package bnapi

import (
	"github.com/obolnetwork/charon/testutil"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func Test_pubkeyValid(t *testing.T) {
	tests := []struct {
		name    string
		pubkey  string
		wantErr string
	}{
		{
			"ok",
			testutil.RandomEth2PubKey(t).String(),
			"",
		},
		{
			"not 98 chars",
			strings.Repeat("a", 97),
			"pubkey too short",
		},
		{
			"pubkey doesn't start with 0x",
			"aa" + testutil.RandomEth2PubKey(t).String()[2:],
			"pubkey prefix is not 0x",
		},
		{
			"bogus hex",
			"0x" + strings.Repeat(",", 96),
			"pubkey not hex encoded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pubkeyValid(tt.pubkey)

			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func Test_validatorStatePath(t *testing.T) {
	okEthPubk := testutil.RandomEth2PubKey(t).String()

	tests := []struct {
		name      string
		sid       StateID
		valPubkey string
		want      string
		wantErr   string
	}{
		{
			"ok",
			StateIDHead,
			okEthPubk,
			"/eth/v1/beacon/states/head/validators/" + okEthPubk,
			"",
		},
		{
			"bad state",
			42,
			okEthPubk,
			"",
			"provided state id is unknown",
		},
		{
			"invalid pubkey",
			StateIDHead,
			okEthPubk[2:],
			"",
			"invalid pubkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validatorStatePath(tt.sid, tt.valPubkey)

			require.Equal(t, tt.want, got)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}
