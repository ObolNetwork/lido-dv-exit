// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package testutil

import (
	"context"
	"math/rand"
	"net/http/httptest"
	"testing"
	"time"

	eth2v1 "github.com/attestantio/go-eth2-client/api/v1"
	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/testutil"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
	"github.com/ObolNetwork/lido-dv-exit/app/obolapi"
)

type TestServers struct {
	ObolAPIServer    *httptest.Server
	BeaconNodeServer *httptest.Server
}

func (ts TestServers) Close() error {
	_ = ts.ObolAPIServer.Close
	_ = ts.BeaconNodeServer.Close

	return nil
}

// Eth2Client returns an eth2 client for the given TestServer.
//
//nolint:revive // testing function
func (ts *TestServers) Eth2Client(t *testing.T, ctx context.Context) eth2wrap.Client {
	t.Helper()

	bnHTTPClient, err := eth2http.New(ctx,
		eth2http.WithAddress(ts.BeaconNodeServer.URL),
		eth2http.WithLogLevel(zerolog.InfoLevel),
	)

	require.NoError(t, err)

	bnClient := bnHTTPClient.(*eth2http.Service)

	return eth2wrap.AdaptEth2HTTP(bnClient, 1*time.Second)
}

// APIServers return an instance of TestServer with mocked Obol API and beacon node API from a given lock file.
func APIServers(t *testing.T, lock cluster.Lock, withNonActiveVals bool) TestServers {
	t.Helper()

	oapiHandler, oapiAddLock := obolapi.MockServer(false)
	oapiAddLock(lock)

	oapiServer := httptest.NewServer(oapiHandler)

	mockValidators := map[string]eth2v1.Validator{}

	mightBeInactive := func(withNonActiveVals bool, idx int) eth2v1.ValidatorState {
		if !withNonActiveVals {
			return eth2v1.ValidatorStateActiveOngoing
		}

		if idx%2 == 0 {
			return eth2v1.ValidatorStateActiveOngoing
		}

		return eth2v1.ValidatorStatePendingQueued // return a state which doesn't represent "validator is running"
	}

	for idx, val := range lock.Validators {
		mockValidators[val.PublicKeyHex()] = eth2v1.Validator{
			Index:   eth2p0.ValidatorIndex(rand.Int63()), //nolint:gosec // testing function
			Balance: 42,
			Status:  mightBeInactive(withNonActiveVals, idx),
			Validator: &eth2p0.Validator{
				PublicKey:                  eth2p0.BLSPubKey(val.PubKey),
				WithdrawalCredentials:      testutil.RandomBytes32(),
				EffectiveBalance:           42,
				Slashed:                    false,
				ActivationEligibilityEpoch: 42,
				ActivationEpoch:            42,
				ExitEpoch:                  42,
				WithdrawableEpoch:          42,
			},
		}
	}

	bnapiHandler := bnapi.MockBeaconNode(mockValidators)
	bnapiServer := httptest.NewServer(bnapiHandler)

	return TestServers{
		ObolAPIServer:    oapiServer,
		BeaconNodeServer: bnapiServer,
	}
}
