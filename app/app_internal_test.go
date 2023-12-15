// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/testutil"
	"github.com/stretchr/testify/require"

	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
	ldetestutil "github.com/ObolNetwork/lido-dv-exit/app/util/testutil"
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

	client, err := eth2Client(ctx, srv.URL, 1)
	require.NoError(t, err)

	vals, err := client.Validators(ctx, &eth2api.ValidatorsOpts{
		State:   bnapi.StateIDHead.String(),
		PubKeys: []eth2p0.BLSPubKey{ongoingVal},
	})
	require.NoError(t, err)

	require.NotEmpty(t, vals)
}

func Test_newSlotTicker(t *testing.T) {
	valAmt := 4
	operatorAmt := 4

	lock, _, _ := cluster.NewForT(
		t,
		valAmt,
		operatorAmt,
		operatorAmt,
		0,
		cluster.WithVersion("v1.7.0"),
	)

	srvs := ldetestutil.APIServers(t, lock, false)
	defer srvs.Close()

	clock := clockwork.NewFakeClock()
	tick, err := newSlotTicker(context.Background(), srvs.Eth2Client(t, context.Background()), clock)
	require.NoError(t, err)

	<-tick
	clock.Advance(1 * time.Second)
	<-tick
}
