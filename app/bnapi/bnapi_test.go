package bnapi_test

import (
	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
	"github.com/gorilla/mux"
	"github.com/obolnetwork/charon/testutil"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"testing"
)

func TestName(t *testing.T) {
	ongoingVal := testutil.RandomEth2PubKey(t).String()

	r := mux.NewRouter()

	r.HandleFunc("/eth/v1/beacon/states/{state_id}/validators/{validator_id}", bnapi.MockValidatorAPIForT(
		t,
		map[string]bnapi.ValidatorState{
			ongoingVal: {
				ExecutionOptimistic: false,
				Finalized:           true,
				Data: bnapi.ValidatorStateData{
					Index:  "42",
					Status: "active_ongoing",
				},
			},
		}))

	srv := httptest.NewServer(r)

	defer srv.Close()

	c := bnapi.Client{BeaconNodeURL: srv.URL}

	t.Run("invalid stateID", func(t *testing.T) {
		res, err := c.ValidatorStateForStateID(33, ongoingVal)
		require.ErrorContains(t, err, "provided state id is unknown")
		require.Empty(t, res)
	})

	t.Run("invalid pubkey", func(t *testing.T) {
		res, err := c.ValidatorStateForStateID(bnapi.StateIDHead, "heh")
		require.ErrorContains(t, err, "invalid pubkey")
		require.Empty(t, res)
	})

	t.Run("validator not found", func(t *testing.T) {
		res, err := c.ValidatorStateForStateID(bnapi.StateIDHead, testutil.RandomEth2PubKey(t).String())
		require.ErrorContains(t, err, "Validator not found")
		require.Empty(t, res)
	})

	t.Run("validator found", func(t *testing.T) {
		res, err := c.ValidatorStateForStateID(bnapi.StateIDHead, ongoingVal)
		require.NoError(t, err)
		require.NotEmpty(t, res)
	})
}
