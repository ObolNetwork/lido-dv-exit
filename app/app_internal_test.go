// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"net/http/httptest"
	"testing"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/testutil"
	"github.com/stretchr/testify/require"

	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
)

func Test_eth2Client(t *testing.T) {
	ongoingVal := testutil.RandomEth2PubKey(t)

	r := bnapi.MockBeaconNode(map[string]eth2v1.Validator{
		ongoingVal.String(): {
			Index:   42,
			Balance: 42,
			Status:  eth2v1.ValidatorStateActiveOngoing,
			Validator: &eth2p0.Validator{
				PublicKey:                  ongoingVal,
				WithdrawalCredentials:      testutil.RandomBytes32(),
				EffectiveBalance:           42,
				Slashed:                    false,
				ActivationEligibilityEpoch: 42,
				ActivationEpoch:            42,
				ExitEpoch:                  42,
				WithdrawableEpoch:          42,
			},
		},
	})

	srv := httptest.NewServer(r)

	defer srv.Close()

	ctx := context.Background()

	client, err := eth2Client(ctx, srv.URL)
	require.NoError(t, err)

	vals, err := client.ValidatorsByPubKey(ctx, bnapi.StateIDFinalized.String(), []eth2p0.BLSPubKey{ongoingVal})
	require.NoError(t, err)

	require.NotEmpty(t, vals)
}
