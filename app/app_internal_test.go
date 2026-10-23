// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/jonboulle/clockwork"
	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/obolapi"
	"github.com/obolnetwork/charon/testutil"
	"github.com/obolnetwork/charon/testutil/beaconmock"
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

	client, err := eth2Client(ctx, srv.URL, nil, 1, 1, [4]byte{0, 0, 0, 0})
	require.NoError(t, err)

	vals, err := client.Validators(ctx, &eth2api.ValidatorsOpts{
		State:   bnapi.StateIDHead.String(),
		PubKeys: []eth2p0.BLSPubKey{ongoingVal},
	})
	require.NoError(t, err)

	require.NotEmpty(t, vals)
}

func Test_newSlotTicker(t *testing.T) {
	mock, err := beaconmock.New(t.Context(), beaconmock.WithSlotDuration(1*time.Second))
	require.NoError(t, err)

	defer func() {
		require.NoError(t, mock.Close())
	}()

	clock := clockwork.NewFakeClock()
	tick, err := newSlotTicker(context.Background(), mock, clock)
	require.NoError(t, err)

	<-tick
	clock.Advance(1 * time.Second)
	<-tick
}

func TestIsLockNotFound(t *testing.T) {
	status := http.StatusNotFound

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"statusCode":404,"message":"cluster lock is not found"}`))
	}))
	defer srv.Close()

	oAPI, err := obolapi.New(srv.URL)
	require.NoError(t, err)

	key, err := k1.GeneratePrivateKey()
	require.NoError(t, err)

	err = postPartialExit(t.Context(), oAPI, make([]byte, 32), 1, key)
	require.Error(t, err)
	require.True(t, isLockNotFound(err))

	status = http.StatusInternalServerError

	err = postPartialExit(t.Context(), oAPI, make([]byte, 32), 1, key)
	require.Error(t, err)
	require.False(t, isLockNotFound(err))

	require.False(t, isLockNotFound(errors.New("other")))
}
