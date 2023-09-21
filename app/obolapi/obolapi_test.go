// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi_test

import (
	"context"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/obolnetwork/charon/app/eth2wrap"
	"github.com/obolnetwork/charon/cluster"
	"github.com/obolnetwork/charon/eth2util/signing"
	"github.com/obolnetwork/charon/tbls"
	"github.com/obolnetwork/charon/tbls/tblsconv"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/ObolNetwork/lido-dv-exit/app/bnapi"
	"github.com/ObolNetwork/lido-dv-exit/app/obolapi"
)

const exitEpoch = phase0.Epoch(162304)

func TestAPIFlow(t *testing.T) {
	kn := 4

	handler, addLockFiles := obolapi.GenerateTestServer(t)
	srv := httptest.NewServer(handler)

	defer srv.Close()

	bnapiHandler := bnapi.MockBeaconNodeForT(t, nil)
	bnapiServer := httptest.NewServer(bnapiHandler)
	defer bnapiServer.Close()
	mockEth2Cl := eth2Client(t, context.Background(), bnapiServer.URL)

	lock, _, shares := cluster.NewForT(
		t,
		1,
		kn,
		kn,
		0,
	)

	addLockFiles(lock)

	exitMsg := phase0.SignedVoluntaryExit{
		Message: &phase0.VoluntaryExit{
			Epoch:          42,
			ValidatorIndex: 42,
		},
		Signature: phase0.BLSSignature{},
	}

	sigRoot, err := exitMsg.Message.HashTreeRoot()
	require.NoError(t, err)

	domain, err := signing.GetDomain(context.Background(), mockEth2Cl, signing.DomainExit, exitEpoch)
	require.NoError(t, err)

	sigData, err := (&phase0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	for idx := 0; idx < len(shares); idx++ {
		var exits []obolapi.ExitBlob

		for idx, shareSet := range shares[idx] {
			signature, err := tbls.Sign(shareSet, sigData[:])
			require.NoError(t, err)

			exitMsg := exitMsg
			exitMsg.Signature = phase0.BLSSignature(signature)

			exits = append(exits, obolapi.ExitBlob{
				PublicKey:         lock.Validators[0].PublicKeyHex(),
				SignedExitMessage: exitMsg,
				ShareIdx:          idx + 1,
			})
		}

		lockHash := "0x" + hex.EncodeToString(lock.LockHash)

		cl := obolapi.Client{ObolAPIUrl: srv.URL}

		// send all the partial exits
		for _, exit := range exits {
			require.NoError(t, cl.PostPartialExit(lockHash, exit))
		}

		// get full exit
		fullExit, err := cl.GetFullExit(lock.Validators[0].PublicKeyHex())
		require.NoError(t, err)

		valPubk, err := lock.Validators[0].PublicKey()
		require.NoError(t, err)

		sig, err := tblsconv.SignatureFromBytes(fullExit.SignedExitMessage.Signature[:])
		require.NoError(t, err)

		// verify that the aggregated signature works
		require.NoError(t, tbls.Verify(valPubk, sigData[:], sig))
	}
}

func eth2Client(t *testing.T, ctx context.Context, bnURL string) eth2wrap.Client {
	t.Helper()

	bnHttpClient, err := http.New(ctx,
		http.WithAddress(bnURL),
		http.WithLogLevel(zerolog.InfoLevel),
	)

	require.NoError(t, err)

	bnClient := bnHttpClient.(*http.Service)
	return eth2wrap.AdaptEth2HTTP(bnClient, 1*time.Second)
}
