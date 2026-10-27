// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package app

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	eth2api "github.com/attestantio/go-eth2-client/api"
	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/jonboulle/clockwork"
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

func TestWriteExitFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exit.json")

	// Overwriting an exit written by an earlier version also restricts its permissions.
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o755))
	require.NoError(t, writeExitFile(path, []byte("new")))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(exitFileMode), info.Mode().Perm())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("new"), data)
}
