// Copyright © 2022-2023 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package obolapi_test

import (
	"context"
	"encoding/hex"
	"net/http/httptest"
	"testing"
	"time"

	eth2http "github.com/attestantio/go-eth2-client/http"
	eth2p0 "github.com/attestantio/go-eth2-client/spec/phase0"
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

const exitEpoch = eth2p0.Epoch(162304)

func TestAPIFlow(t *testing.T) {
	kn := 4

	handler, addLockFiles := obolapi.MockServer()
	srv := httptest.NewServer(handler)

	defer srv.Close()

	bnapiHandler := bnapi.MockBeaconNode(nil)
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

	exitMsg := eth2p0.SignedVoluntaryExit{
		Message: &eth2p0.VoluntaryExit{
			Epoch:          42,
			ValidatorIndex: 42,
		},
		Signature: eth2p0.BLSSignature{},
	}

	sigRoot, err := exitMsg.Message.HashTreeRoot()
	require.NoError(t, err)

	domain, err := signing.GetDomain(context.Background(), mockEth2Cl, signing.DomainExit, exitEpoch)
	require.NoError(t, err)

	sigData, err := (&eth2p0.SigningData{ObjectRoot: sigRoot, Domain: domain}).HashTreeRoot()
	require.NoError(t, err)

	for idx := 0; idx < len(shares); idx++ {
		var exits []obolapi.ExitBlob

		for idx, shareSet := range shares[idx] {
			signature, err := tbls.Sign(shareSet, sigData[:])
			require.NoError(t, err)

			exitMsg := exitMsg
			exitMsg.Signature = eth2p0.BLSSignature(signature)

			exits = append(exits, obolapi.ExitBlob{
				PublicKey:         lock.Validators[0].PublicKeyHex(),
				SignedExitMessage: exitMsg,
				ShareIdx:          idx + 1,
			})
		}

		lockHash := "0x" + hex.EncodeToString(lock.LockHash)

		cl := obolapi.Client{ObolAPIUrl: srv.URL}

		ctx := context.Background()

		// send all the partial exits
		for _, exit := range exits {
			require.NoError(t, cl.PostPartialExit(ctx, lockHash, "token", exit))
		}

		// get full exit
		fullExit, err := cl.GetFullExit(ctx, lock.Validators[0].PublicKeyHex(), "token")
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

	bnHTTPClient, err := eth2http.New(ctx,
		eth2http.WithAddress(bnURL),
		eth2http.WithLogLevel(zerolog.InfoLevel),
	)

	require.NoError(t, err)

	bnClient := bnHTTPClient.(*eth2http.Service)

	return eth2wrap.AdaptEth2HTTP(bnClient, 1*time.Second)
}
